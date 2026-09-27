// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// diskIdleReadsBeforeDelete is how many consecutive reads without changes an entry of the
// kernel accumulation map survives before it is deleted, so entries of devices that stopped
// doing I/O don't fill the map.
const diskIdleReadsBeforeDelete = 60

// errorTypeOther is the semantic conventions fallback for error.type values OBI can't name
const errorTypeOther = "_OTHER"

// cgroupContainersCacheLen matches the size of the disk_cgroup_names eBPF map
const cgroupContainersCacheLen = 1 << 10

func dtlog() *slog.Logger {
	return slog.With("component", "stat.DiskMapTracer")
}

// diskAccumSource abstracts the disk_io_accum eBPF map, for testing
type diskAccumSource interface {
	read() (map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT, error)
	delete(key ebpf.StatsDiskIoKeyT) error
}

type ebpfDiskAccum struct {
	accum *ciliumebpf.Map
}

func (e ebpfDiskAccum) read() (map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT, error) {
	entries := map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{}
	var key ebpf.StatsDiskIoKeyT
	var value ebpf.StatsDiskIoAccumT
	iter := e.accum.Iterate()
	for iter.Next(&key, &value) {
		entries[key] = value
	}
	return entries, iter.Err()
}

func (e ebpfDiskAccum) delete(key ebpf.StatsDiskIoKeyT) error {
	return e.accum.Delete(key)
}

// cgroupNameSource abstracts the disk_cgroup_names eBPF map, for testing
type cgroupNameSource interface {
	name(cgroupID uint64) (string, bool)
}

type ebpfCgroupNames struct {
	names *ciliumebpf.Map
}

func (e ebpfCgroupNames) name(cgroupID uint64) (string, bool) {
	var name ebpf.StatsDiskCgroupNameT
	if err := e.names.Lookup(cgroupID, &name); err != nil {
		return "", false
	}
	return unix.ByteSliceToString(name.Name[:]), true
}

// DiskMapTracer periodically reads the block I/O accumulation map that the kernel fills, and
// forwards what changed since the previous read as ebpf.Stat records.
type DiskMapTracer struct {
	reader   *diskReader
	interval time.Duration
}

// NewDiskMapTracer returns a tracer for the given disk_io_accum and disk_cgroup_names maps.
// latencyBounds are the histogram boundaries, in seconds, that the kernel buckets the latencies
// with. statusIsBlkStatus tells how the kernel reports the completion status (see
// disk_status_code).
func NewDiskMapTracer(
	accum, cgroupNames *ciliumebpf.Map,
	latencyBounds []float64,
	statusIsBlkStatus bool,
	interval time.Duration,
) *DiskMapTracer {
	return &DiskMapTracer{
		reader: newDiskReader(ebpfDiskAccum{accum: accum}, latencyBounds, statusIsBlkStatus,
			&deviceNames{sysRoot: "/sys"}, newCgroupContainers(ebpfCgroupNames{names: cgroupNames})),
		interval: interval,
	}
}

func (m *DiskMapTracer) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if stats := m.reader.readStats(); len(stats) > 0 {
					out.SendCtx(ctx, stats)
				}
			}
		}
	}
}

type diskReader struct {
	log               *slog.Logger
	accum             diskAccumSource
	latencyBounds     []float64
	statusIsBlkStatus bool
	devices           *deviceNames
	containers        *cgroupContainers

	previous  map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT
	idleReads map[ebpf.StatsDiskIoKeyT]int
}

func newDiskReader(
	accum diskAccumSource,
	latencyBounds []float64,
	statusIsBlkStatus bool,
	devices *deviceNames,
	containers *cgroupContainers,
) *diskReader {
	return &diskReader{
		log:               dtlog(),
		accum:             accum,
		latencyBounds:     latencyBounds,
		statusIsBlkStatus: statusIsBlkStatus,
		devices:           devices,
		containers:        containers,
		previous:          map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{},
		idleReads:         map[ebpf.StatsDiskIoKeyT]int{},
	}
}

func (r *diskReader) readStats() []*ebpf.Stat {
	entries, err := r.accum.read()
	if err != nil {
		// a partial read still forwards what it got; the rest is forwarded by the next read
		r.log.Debug("can't read the disk_io_accum map", "error", err)
	}
	var stats []*ebpf.Stat
	for key, current := range entries {
		if stat := r.statFromDelta(key, current); stat != nil {
			stats = append(stats, stat)
			r.idleReads[key] = 0
		} else {
			r.forgetIfIdle(key)
		}
		if _, tracked := r.idleReads[key]; tracked {
			r.previous[key] = current
		}
	}
	if err == nil {
		r.forgetEvicted(entries)
	}
	return stats
}

// statFromDelta returns the requests that completed since the previous read of the key, or nil
func (r *diskReader) statFromDelta(key ebpf.StatsDiskIoKeyT, current ebpf.StatsDiskIoAccumT) *ebpf.Stat {
	previous := r.previous[key]
	// kernel counters only grow; a decrease means the LRU map evicted and re-created the entry
	if current.Bytes < previous.Bytes || anyDecreased(current.LatencyCount[:], previous.LatencyCount[:]) {
		previous = ebpf.StatsDiskIoAccumT{}
	}

	var latency []ebpf.LatencySample
	var operations, timeNs uint64
	// one bucket per boundary, plus the overflow bucket
	for bucket := range len(r.latencyBounds) + 1 {
		count := current.LatencyCount[bucket] - previous.LatencyCount[bucket]
		if count == 0 {
			continue
		}
		sumNs := current.LatencySumNs[bucket] - previous.LatencySumNs[bucket]
		latency = append(latency, latencySample(r.latencyBounds, bucket, count, sumNs))
		operations += count
		timeNs += sumNs
	}
	if operations == 0 {
		return nil
	}
	return &ebpf.Stat{
		Type: ebpf.StatTypeDiskIO,
		DiskIO: &ebpf.DiskIO{
			Device:      r.devices.name(key.Major, key.Minor),
			Direction:   ebpf.DiskIODirectionCode(key.Direction),
			ErrorType:   diskErrorType(key.Status, r.statusIsBlkStatus),
			ContainerID: r.containers.containerID(key.CgroupId),
			Operations:  operations,
			Time:        float64(timeNs) / float64(time.Second),
			Bytes:       current.Bytes - previous.Bytes,
			Latency:     latency,
		},
	}
}

func anyDecreased(current, previous []uint64) bool {
	for i := range current {
		if current[i] < previous[i] {
			return true
		}
	}
	return false
}

func (r *diskReader) forgetIfIdle(key ebpf.StatsDiskIoKeyT) {
	r.idleReads[key]++
	if r.idleReads[key] < diskIdleReadsBeforeDelete {
		return
	}
	if err := r.accum.delete(key); err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		r.log.Debug("can't delete idle disk_io_accum entry", "error", err)
		return
	}
	delete(r.idleReads, key)
	delete(r.previous, key)
}

// forgetEvicted drops what is remembered about entries that the LRU map evicted
func (r *diskReader) forgetEvicted(entries map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT) {
	for key := range r.previous {
		if _, ok := entries[key]; !ok {
			delete(r.previous, key)
			delete(r.idleReads, key)
		}
	}
}

// latencySample summarizes count requests of a kernel histogram bucket as their mean latency.
// The mean is kept inside the bucket boundaries, so exporters with the same or coarser
// boundaries place all the requests in the same bucket the kernel did.
func latencySample(bounds []float64, bucket int, count, sumNs uint64) ebpf.LatencySample {
	seconds := float64(sumNs) / float64(count) / float64(time.Second)
	if bucket < len(bounds) {
		seconds = math.Min(seconds, bounds[bucket])
	}
	if bucket > 0 && seconds <= bounds[bucket-1] {
		seconds = math.Nextafter(bounds[bucket-1], math.Inf(1))
	}
	return ebpf.LatencySample{Seconds: seconds, Count: count}
}

// blkStatusErrno maps the blk_status_t values that are stable across kernel versions to the
// errno the kernel reports for them (blk_errors in block/blk-core.c). Higher values were
// renumbered between kernel versions.
var blkStatusErrno = map[uint8]syscall.Errno{
	1:  unix.EOPNOTSUPP,
	2:  unix.ETIMEDOUT,
	3:  unix.ENOSPC,
	4:  unix.ENOLINK,
	5:  unix.EREMOTEIO,
	6:  unix.EBADE,
	7:  unix.ENODATA,
	8:  unix.EILSEQ,
	9:  unix.ENOMEM,
	10: unix.EIO,
	11: unix.EREMCHG,
	12: unix.EAGAIN,
	13: unix.EBUSY,
}

// diskErrorType names the completion status of a block request after its errno, so it reads
// the same whether the kernel reports errnos or blk_status_t values. Empty on success.
func diskErrorType(status uint8, isBlkStatus bool) string {
	if status == 0 {
		return ""
	}
	errno := syscall.Errno(status)
	if isBlkStatus {
		var ok bool
		if errno, ok = blkStatusErrno[status]; !ok {
			return errorTypeOther
		}
	}
	if name := unix.ErrnoName(errno); name != "" {
		return name
	}
	return errorTypeOther
}

// cgroupContainers resolves the cgroups that block I/O is charged to into the ID of their
// container, from the cgroup names that the kernel recorded.
type cgroupContainers struct {
	names cgroupNameSource
	cache *simplelru.LRU[uint64, string]
}

func newCgroupContainers(names cgroupNameSource) *cgroupContainers {
	// the size is a constant known to be valid
	cache, _ := simplelru.NewLRU[uint64, string](cgroupContainersCacheLen, nil)
	return &cgroupContainers{names: names, cache: cache}
}

// containerID returns the ID of the container of the cgroup, or an empty string if the cgroup
// is not a container, or is unknown
func (c *cgroupContainers) containerID(cgroupID uint64) string {
	if cgroupID == 0 {
		return ""
	}
	if id, ok := c.cache.Get(cgroupID); ok {
		return id
	}
	name, ok := c.names.name(cgroupID)
	if !ok {
		// not cached: the kernel may record the name later
		return ""
	}
	id, _ := container.IDFromCgroupName(name)
	c.cache.Add(cgroupID, id)
	return id
}

// deviceNames resolves block device numbers to their kernel names, e.g. 259:0 to nvme0n1
type deviceNames struct {
	sysRoot string
	cache   map[[2]uint32]string
}

func (d *deviceNames) name(major, minor uint32) string {
	if d.cache == nil {
		d.cache = map[[2]uint32]string{}
	}
	if name, ok := d.cache[[2]uint32{major, minor}]; ok {
		return name
	}
	numbers := fmt.Sprintf("%d:%d", major, minor)
	name := devNameFromUevent(filepath.Join(d.sysRoot, "dev", "block", numbers, "uevent"))
	if name == "" {
		// e.g. hidden NVMe multipath path devices, or a device removed since its last I/O
		name = numbers
	}
	d.cache[[2]uint32{major, minor}] = name
	return name
}

func devNameFromUevent(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if name, ok := strings.CutPrefix(scanner.Text(), "DEVNAME="); ok {
			return name
		}
	}
	return ""
}
