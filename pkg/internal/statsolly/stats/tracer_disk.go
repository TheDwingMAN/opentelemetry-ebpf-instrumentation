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
	"strconv"
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

// accumSource abstracts an eBPF map of cumulative values, for testing
type accumSource[K comparable, V any] interface {
	read() (map[K]V, error)
	delete(key K) error
}

type ebpfAccum[K comparable, V any] struct {
	accum *ciliumebpf.Map
}

func (e ebpfAccum[K, V]) read() (map[K]V, error) {
	entries := map[K]V{}
	var key K
	var value V
	iter := e.accum.Iterate()
	for iter.Next(&key, &value) {
		entries[key] = value
	}
	return entries, iter.Err()
}

func (e ebpfAccum[K, V]) delete(key K) error {
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

// DiskMapTracerConfig tells a DiskMapTracer which kernel maps to read, and how to interpret them
type DiskMapTracerConfig struct {
	// DiskIOAccum and FsSyncAccum are the accumulation maps to read. A nil map is not read.
	DiskIOAccum, FsSyncAccum *ciliumebpf.Map
	// DiskRequests holds the block requests in flight, and DiskBioRequests the bios in flight of
	// the stacked volumes. Nil unless their number is reported.
	DiskRequests, DiskBioRequests *ciliumebpf.Map
	// DiskBioAccum and DiskBioDevices are the accumulation map of the bios of the stacked volumes,
	// and the set of volumes to measure. Nil unless the stacked volumes are measured.
	DiskBioAccum, DiskBioDevices *ciliumebpf.Map
	CgroupNames                  *ciliumebpf.Map
	// DiskLatencyBounds and FsSyncLatencyBounds are the histogram boundaries, in seconds, that
	// the kernel buckets the latencies with
	DiskLatencyBounds, FsSyncLatencyBounds []float64
	// NFSProcedureAccum and NFSIOAccum are the accumulation maps of the NFS client. A nil map is
	// not read.
	NFSProcedureAccum, NFSIOAccum *ciliumebpf.Map
	// NFSLatencyBounds are the histogram boundaries, in seconds, of the NFS RPC latencies
	NFSLatencyBounds []float64
	// DiskStatusIsBlkStatus tells how the kernel reports block request completion statuses
	// (see disk_status_code)
	DiskStatusIsBlkStatus bool
	Interval              time.Duration
}

// DiskMapTracer periodically reads the block I/O and file sync accumulation maps that the kernel
// fills, and forwards what changed since the previous read as ebpf.Stat records.
type DiskMapTracer struct {
	readers []statReader
	// nil unless the requests in flight are reported
	pending *pendingReader
	// nil unless the stacked volumes are measured
	bios     *bioDevices
	interval time.Duration
}

type statReader interface {
	readStats() []*ebpf.Stat
}

func NewDiskMapTracer(cfg *DiskMapTracerConfig) *DiskMapTracer {
	containers := newCgroupContainers(ebpfCgroupNames{names: cfg.CgroupNames})
	devices := &deviceNames{sysRoot: "/sys"}
	var readers []statReader
	if cfg.DiskIOAccum != nil {
		readers = append(readers, newDiskReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: cfg.DiskIOAccum},
			cfg.DiskLatencyBounds, cfg.DiskStatusIsBlkStatus, devices, containers))
	}
	var bios *bioDevices
	if cfg.DiskBioAccum != nil && cfg.DiskBioDevices != nil {
		readers = append(readers, newBioReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: cfg.DiskBioAccum},
			cfg.DiskLatencyBounds, devices, containers))
		bios = newBioDevices("/sys", ebpfDeviceSet{set: cfg.DiskBioDevices})
	}
	var pending *pendingReader
	if cfg.DiskRequests != nil {
		pending = newPendingReader(ebpfRequests{starts: cfg.DiskRequests, bioStarts: cfg.DiskBioRequests}, devices)
	}
	if cfg.FsSyncAccum != nil {
		readers = append(readers, newFsSyncReader(ebpfAccum[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT]{accum: cfg.FsSyncAccum},
			cfg.FsSyncLatencyBounds, containers, newFilesystems()))
	}
	if cfg.NFSProcedureAccum != nil {
		readers = append(readers, newNFSProcedureReader(ebpfAccum[ebpf.StatsNfsProcedureKeyT, ebpf.StatsNfsProcedureAccumT]{accum: cfg.NFSProcedureAccum},
			cfg.NFSLatencyBounds, containers))
	}
	if cfg.NFSIOAccum != nil {
		readers = append(readers, newNFSIOReader(ebpfAccum[ebpf.StatsNfsIoKeyT, uint64]{accum: cfg.NFSIOAccum}, containers))
	}
	return &DiskMapTracer{readers: readers, pending: pending, bios: bios, interval: cfg.Interval}
}

func (m *DiskMapTracer) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for reads := 0; ; reads++ {
			if m.bios != nil && reads%bioDevicesRefreshReads == 0 {
				m.bios.refresh()
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := m.readStats()
				if len(stats) > 0 {
					out.SendCtx(ctx, stats)
				}
			}
		}
	}
}

func (m *DiskMapTracer) readStats() []*ebpf.Stat {
	var stats []*ebpf.Stat
	for _, reader := range m.readers {
		stats = append(stats, reader.readStats()...)
	}
	if m.pending == nil {
		return stats
	}
	for _, stat := range stats {
		if stat.DiskIO != nil {
			m.pending.observe(stat.DiskIO)
		}
	}
	return append(stats, m.pending.readStats()...)
}

// accumReader reads a kernel map of cumulative values and forwards, as stats, what grew since
// the previous read of each entry.
type accumReader[K comparable, V any] struct {
	log   *slog.Logger
	accum accumSource[K, V]
	// toStat returns the stat of what grew between the previous and the current value of the
	// key, or nil if nothing did
	toStat func(key K, current, previous V) *ebpf.Stat

	previous  map[K]V
	idleReads map[K]int
}

func newAccumReader[K comparable, V any](
	mapName string,
	accum accumSource[K, V],
	toStat func(key K, current, previous V) *ebpf.Stat,
) *accumReader[K, V] {
	return &accumReader[K, V]{
		log:       dtlog().With("map", mapName),
		accum:     accum,
		toStat:    toStat,
		previous:  map[K]V{},
		idleReads: map[K]int{},
	}
}

func (r *accumReader[K, V]) readStats() []*ebpf.Stat {
	entries, err := r.accum.read()
	if err != nil {
		// a partial read still forwards what it got; the rest is forwarded by the next read
		r.log.Debug("can't read the accumulation map", "error", err)
	}
	var stats []*ebpf.Stat
	for key, current := range entries {
		if stat := r.toStat(key, current, r.previous[key]); stat != nil {
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

func (r *accumReader[K, V]) forgetIfIdle(key K) {
	r.idleReads[key]++
	if r.idleReads[key] < diskIdleReadsBeforeDelete {
		return
	}
	if err := r.accum.delete(key); err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		r.log.Debug("can't delete idle accumulation map entry", "error", err)
		return
	}
	delete(r.idleReads, key)
	delete(r.previous, key)
}

// forgetEvicted drops what is remembered about entries that the LRU map evicted
func (r *accumReader[K, V]) forgetEvicted(entries map[K]V) {
	for key := range r.previous {
		if _, ok := entries[key]; !ok {
			delete(r.previous, key)
			delete(r.idleReads, key)
		}
	}
}

func newDiskReader(
	accum accumSource[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT],
	latencyBounds []float64,
	statusIsBlkStatus bool,
	devices *deviceNames,
	containers *cgroupContainers,
) *accumReader[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT] {
	d := diskStats{
		latencyBounds:     latencyBounds,
		statusIsBlkStatus: statusIsBlkStatus,
		devices:           devices,
		containers:        containers,
	}
	return newAccumReader("disk_io_accum", accum, d.stat)
}

// newBioReader reads the accumulated bios of the stacked volumes, whose status is always a
// blk_status_t
func newBioReader(
	accum accumSource[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT],
	latencyBounds []float64,
	devices *deviceNames,
	containers *cgroupContainers,
) *accumReader[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT] {
	d := diskStats{
		latencyBounds:     latencyBounds,
		statusIsBlkStatus: true,
		devices:           devices,
		containers:        containers,
	}
	return newAccumReader("disk_bio_accum", accum, d.stat)
}

type diskStats struct {
	latencyBounds     []float64
	statusIsBlkStatus bool
	devices           *deviceNames
	containers        *cgroupContainers
}

// stat returns the block requests that completed since the previous read of the key, or nil
func (d *diskStats) stat(key ebpf.StatsDiskIoKeyT, current, previous ebpf.StatsDiskIoAccumT) *ebpf.Stat {
	// kernel counters only grow; a decrease means the LRU map evicted and re-created the entry
	if current.Bytes < previous.Bytes || anyDecreased(current.LatencyCount[:], previous.LatencyCount[:]) ||
		anyDecreased(current.QueueCount[:], previous.QueueCount[:]) {
		previous = ebpf.StatsDiskIoAccumT{}
	}
	delta := latencyDelta(d.latencyBounds, current.LatencyCount[:], current.LatencySumNs[:],
		previous.LatencyCount[:], previous.LatencySumNs[:])
	if delta.operations == 0 {
		return nil
	}
	queue := latencyDelta(d.latencyBounds, current.QueueCount[:], current.QueueSumNs[:],
		previous.QueueCount[:], previous.QueueSumNs[:])
	return &ebpf.Stat{
		Type: ebpf.StatTypeDiskIO,
		DiskIO: &ebpf.DiskIO{
			Device:      d.devices.name(key.Major, key.Minor),
			Partition:   d.devices.partition(key.Major, key.Minor, key.PartDev, key.Partno),
			Stacked:     d.devices.stacked(key.Major, key.Minor),
			Op:          ebpf.DiskOpCode(key.Op),
			ErrorType:   diskErrorType(key.Status, d.statusIsBlkStatus),
			ContainerID: d.containers.containerID(key.CgroupId),
			Operations:  delta.operations,
			Time:        delta.seconds(),
			Bytes:       current.Bytes - previous.Bytes,
			Latency:     delta.latency,
			Queue:       queue.latency,
		},
	}
}

func newFsSyncReader(
	accum accumSource[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT],
	latencyBounds []float64,
	containers *cgroupContainers,
	filesystems *filesystems,
) *accumReader[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT] {
	f := fsSyncStats{latencyBounds: latencyBounds, containers: containers, filesystems: filesystems}
	return newAccumReader("fs_sync_accum", accum, f.stat)
}

type fsSyncStats struct {
	latencyBounds []float64
	containers    *cgroupContainers
	filesystems   *filesystems
}

// stat returns the file syncs that completed since the previous read of the key, or nil
func (f *fsSyncStats) stat(key ebpf.StatsFsSyncKeyT, current, previous ebpf.StatsFsSyncAccumT) *ebpf.Stat {
	if anyDecreased(current.LatencyCount[:], previous.LatencyCount[:]) {
		previous = ebpf.StatsFsSyncAccumT{}
	}
	delta := latencyDelta(f.latencyBounds, current.LatencyCount[:], current.LatencySumNs[:],
		previous.LatencyCount[:], previous.LatencySumNs[:])
	if delta.operations == 0 {
		return nil
	}
	fs, _ := f.filesystems.lookup(key.S_dev)
	return &ebpf.Stat{
		Type: ebpf.StatTypeFsSync,
		FsSync: &ebpf.FsSync{
			Type:           ebpf.FsSyncTypeCode(key.Type),
			Mountpoint:     fs.mountpoint,
			FilesystemType: fs.fsType,
			// file syncs report errnos on every kernel version
			ErrorType:   diskErrorType(key.Status, false),
			ContainerID: f.containers.containerID(key.CgroupId),
			Latency:     delta.latency,
		},
	}
}

// latencyGrowth is what a kernel latency histogram grew since a previous read
type latencyGrowth struct {
	latency    []ebpf.LatencySample
	operations uint64
	timeNs     uint64
}

func (g latencyGrowth) seconds() float64 {
	return float64(g.timeNs) / float64(time.Second)
}

func latencyDelta(bounds []float64, currentCount, currentSumNs, previousCount, previousSumNs []uint64) latencyGrowth {
	var growth latencyGrowth
	// one bucket per boundary, plus the overflow bucket
	for bucket := range len(bounds) + 1 {
		count := currentCount[bucket] - previousCount[bucket]
		if count == 0 {
			continue
		}
		sumNs := currentSumNs[bucket] - previousSumNs[bucket]
		growth.latency = append(growth.latency, latencySample(bounds, bucket, count, sumNs))
		growth.operations += count
		growth.timeNs += sumNs
	}
	return growth
}

func anyDecreased(current, previous []uint64) bool {
	for i := range current {
		if current[i] < previous[i] {
			return true
		}
	}
	return false
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
	sysRoot    string
	cache      map[[2]uint32]string
	partitions map[partitionKey]string
	stack      map[[2]uint32]bool
}

// stacked tells whether a block device is built on other block devices (see isStacked)
func (d *deviceNames) stacked(major, minor uint32) bool {
	if d.stack == nil {
		d.stack = map[[2]uint32]bool{}
	}
	if stacked, ok := d.stack[[2]uint32{major, minor}]; ok {
		return stacked
	}
	stacked := isStacked(filepath.Join(d.sysRoot, "dev", "block", fmt.Sprintf("%d:%d", major, minor)))
	d.stack[[2]uint32{major, minor}] = stacked
	return stacked
}

type partitionKey struct {
	major, minor, partDev uint32
	partno                uint8
}

// kernelDevMinorBits is the width of the minor number in a kernel-internal dev_t
const kernelDevMinorBits = 20

// partition returns the name of the partition of a disk that block I/O targets, from its kernel
// dev_t (partDev, Linux 5.12+) or, on older kernels, its partition number. Empty for I/O on the
// whole disk, or when the partition can't be found.
func (d *deviceNames) partition(major, minor, partDev uint32, partno uint8) string {
	partMajor, partMinor := partDev>>kernelDevMinorBits, partDev&(1<<kernelDevMinorBits-1)
	if (partDev == 0 && partno == 0) || (partMajor == major && partMinor == minor) {
		return ""
	}
	if d.partitions == nil {
		d.partitions = map[partitionKey]string{}
	}
	key := partitionKey{major: major, minor: minor, partDev: partDev, partno: partno}
	if name, ok := d.partitions[key]; ok {
		return name
	}
	var name string
	if partDev != 0 {
		name = d.name(partMajor, partMinor)
	} else {
		name = d.partitionByNumber(d.name(major, minor), partno)
	}
	d.partitions[key] = name
	return name
}

// partitionByNumber finds the partition of a disk with the given number in sysfs, where each
// partition is a directory of the disk with a "partition" file holding its number
func (d *deviceNames) partitionByNumber(disk string, partno uint8) string {
	numbers, _ := filepath.Glob(filepath.Join(d.sysRoot, "block", disk, "*", "partition"))
	for _, number := range numbers {
		content, err := os.ReadFile(number)
		if err == nil && strings.TrimSpace(string(content)) == strconv.Itoa(int(partno)) {
			return filepath.Base(filepath.Dir(number))
		}
	}
	return ""
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
