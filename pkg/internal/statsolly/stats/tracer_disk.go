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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/prometheus/procfs/blockdevice"
	"golang.org/x/sys/unix"

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

func dtlog() *slog.Logger {
	return slog.With("component", "stat.DiskMapTracer")
}

// errAccumFull tells that an accumulation map was read completely, and is full
var errAccumFull = errors.New("the accumulation map is full")

// accumSource abstracts an eBPF map of cumulative values, for testing
type accumSource[K comparable, V any] interface {
	// read returns the entries of the map, with errAccumFull if it is full
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
	if err := iter.Err(); err != nil {
		return entries, err
	}
	if len(entries) >= int(e.accum.MaxEntries()) {
		return entries, errAccumFull
	}
	return entries, nil
}

func (e ebpfAccum[K, V]) delete(key K) error {
	return e.accum.Delete(key)
}

// DiskMapTracerConfig tells a DiskMapTracer which kernel maps to read, and how to interpret them
type DiskMapTracerConfig struct {
	// DiskIOAccum is the accumulation map to read. A nil map is not read.
	DiskIOAccum *ciliumebpf.Map
	// DiskLatencyBounds are the histogram boundaries, in seconds, that the kernel buckets the
	// latencies with
	DiskLatencyBounds []float64
	// DiskStatusIsBlkStatus tells how the kernel reports block request completion statuses
	// (see disk_status_code)
	DiskStatusIsBlkStatus bool
	Interval              time.Duration
}

// DiskMapTracer periodically reads the block I/O accumulation map that the kernel fills, and
// forwards what changed since the previous read as ebpf.Stat records.
type DiskMapTracer struct {
	readers  []statReader
	interval time.Duration
}

type statReader interface {
	readStats() []*ebpf.Stat
}

func NewDiskMapTracer(cfg *DiskMapTracerConfig) *DiskMapTracer {
	devices := &deviceNames{sysRoot: "/sys", procRoot: "/proc"}
	var readers []statReader
	if cfg.DiskIOAccum != nil {
		readers = append(readers, newDiskReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: cfg.DiskIOAccum},
			cfg.DiskLatencyBounds, cfg.DiskStatusIsBlkStatus, devices))
	}
	return &DiskMapTracer{readers: readers, interval: cfg.Interval}
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
	return stats
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
	// the map was full at the previous read
	full bool
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
	full := errors.Is(err, errAccumFull)
	if full {
		// the kernel doesn't add new keys to a full map: they are dropped until idle ones are
		// deleted
		if !r.full {
			r.log.Warn("the kernel map is full: the I/O of new devices is not measured "+
				"until the entries of idle ones are deleted", "entries", len(entries))
		}
		err = nil
	}
	r.full = full
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

// forgetEvicted drops what is remembered about entries that are no longer in the map
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
) *accumReader[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT] {
	d := diskStats{
		latencyBounds:     latencyBounds,
		statusIsBlkStatus: statusIsBlkStatus,
		devices:           devices,
	}
	return newAccumReader("disk_io_accum", accum, d.stat)
}

type diskStats struct {
	latencyBounds     []float64
	statusIsBlkStatus bool
	devices           *deviceNames
}

// stat returns the block requests that completed since the previous read of the key, or nil
func (d *diskStats) stat(key ebpf.StatsDiskIoKeyT, current, previous ebpf.StatsDiskIoAccumT) *ebpf.Stat {
	// kernel counters only grow; a decrease means the entry was deleted and re-created
	if anyDecreased(current.LatencyCount[:], previous.LatencyCount[:]) ||
		anyDecreased(current.LatencySumNs[:], previous.LatencySumNs[:]) {
		previous = ebpf.StatsDiskIoAccumT{}
	}
	delta := latencyDelta(d.latencyBounds, current.LatencyCount[:], current.LatencySumNs[:],
		previous.LatencyCount[:], previous.LatencySumNs[:])
	if delta.operations == 0 {
		return nil
	}
	return &ebpf.Stat{
		Type: ebpf.StatTypeDiskIO,
		DiskIO: &ebpf.DiskIO{
			Device:     d.devices.name(key.Major, key.Minor),
			VolumeName: d.devices.dmName(key.Major, key.Minor),
			Stacked:    d.devices.stacked(key.Major, key.Minor),
			Op:         ebpf.DiskOpCode(key.Op),
			ErrorType:  diskErrorType(key.Status, d.statusIsBlkStatus),
			Latency:    d.latency(key, delta.latency),
		},
	}
}

// latency returns the latencies that the latency histograms report for the requests of a key.
// The paths of a multipath device report none: the multipath device reports the latency of the
// same I/O, and the histograms of its paths would multiply its series by their number.
func (d *diskStats) latency(key ebpf.StatsDiskIoKeyT, latency []ebpf.LatencySample) []ebpf.LatencySample {
	if d.devices.multipathPathOf(key.Major, key.Minor) == dmMultipathPath {
		return nil
	}
	return latency
}

// latencyGrowth is what a kernel latency histogram grew since a previous read
type latencyGrowth struct {
	latency    []ebpf.LatencySample
	operations uint64
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

// deviceNamesCachePeriod is how long device names are cached: the kernel gives the numbers of
// removed devices to new ones, e.g. the minors of detached NVMe volumes or of loop devices
const deviceNamesCachePeriod = 30 * time.Second

// deviceNames resolves block device numbers to their kernel names, e.g. 259:0 to nvme0n1
type deviceNames struct {
	sysRoot, procRoot string
	// now returns the current time, time.Now if nil
	now      func() time.Time
	cachedAt time.Time

	cache     map[[2]uint32]string
	stack     map[[2]uint32]bool
	diskstats map[[2]uint32]string
	paths     map[[2]uint32]multipathPath
	dmNames   map[[2]uint32]string
}

// expire forgets what is cached once deviceNamesCachePeriod passed since it started caching
func (d *deviceNames) expire() {
	now := time.Now()
	if d.now != nil {
		now = d.now()
	}
	if d.cache != nil && now.Sub(d.cachedAt) < deviceNamesCachePeriod {
		return
	}
	d.cachedAt = now
	d.cache = map[[2]uint32]string{}
	d.stack = map[[2]uint32]bool{}
	d.diskstats = nil
	d.paths = map[[2]uint32]multipathPath{}
	d.dmNames = map[[2]uint32]string{}
}

// stacked tells whether a block device is built on other block devices (see isStacked)
func (d *deviceNames) stacked(major, minor uint32) bool {
	d.expire()
	if stacked, ok := d.stack[[2]uint32{major, minor}]; ok {
		return stacked
	}
	dir := filepath.Join(d.sysRoot, "dev", "block", fmt.Sprintf("%d:%d", major, minor))
	if !exists(dir) {
		// e.g. removed since its last I/O: not cached, the numbers may be given to another device
		return false
	}
	stacked := isStacked(dir)
	d.stack[[2]uint32{major, minor}] = stacked
	return stacked
}

// dmName returns the name of a device mapper device, as /dev/mapper names it, or an empty string
// for the other devices
func (d *deviceNames) dmName(major, minor uint32) string {
	d.expire()
	key := [2]uint32{major, minor}
	if name, ok := d.dmNames[key]; ok {
		return name
	}
	dir := filepath.Join(d.sysRoot, "dev", "block", devNumbers(major, minor))
	if !exists(dir) {
		// e.g. removed since its last I/O: not cached, the numbers may be given to another device
		return ""
	}
	name := deviceMapperName(dir)
	d.dmNames[key] = name
	return name
}

// multipathPath tells which multipath device, if any, a block device is a path of
type multipathPath uint8

const (
	notMultipathPath multipathPath = iota
	// dmMultipathPath is a disk that a measured dm-multipath device holds
	dmMultipathPath
)

// multipathPathOf tells whether a block device is a path of a multipath device that OBI measures
func (d *deviceNames) multipathPathOf(major, minor uint32) multipathPath {
	d.expire()
	key := [2]uint32{major, minor}
	if path, ok := d.paths[key]; ok {
		return path
	}
	dir := filepath.Join(d.sysRoot, "dev", "block", devNumbers(major, minor))
	path := notMultipathPath
	switch {
	case exists(dir):
		if d.heldByDMMultipath(dir) {
			path = dmMultipathPath
		}
	default:
		// e.g. removed since its last I/O: not cached, the numbers may be given to another device
		return notMultipathPath
	}
	d.paths[key] = path
	return path
}

// heldByDMMultipath tells whether the sysfs directory of a block device is a path that a measured
// dm-multipath device holds
func (d *deviceNames) heldByDMMultipath(dir string) bool {
	holders, _ := filepath.Glob(filepath.Join(dir, "holders", "*"))
	return slices.ContainsFunc(holders, func(holder string) bool {
		return isDMMultipath(holder) && isMeasured(holder)
	})
}

// isMeasured tells whether OBI measures the I/O of the block device of a sysfs directory: the
// request-based devices, which issue the requests that the probes measure
func isMeasured(dir string) bool {
	return exists(dir) && !isBioBased(dir)
}

// name returns the name of a block device, or its "major:minor" numbers when neither sysfs nor
// /proc/diskstats names it
func (d *deviceNames) name(major, minor uint32) string {
	if name := d.knownName(major, minor); name != "" {
		return name
	}
	// e.g. a device removed since its last I/O
	return fmt.Sprintf("%d:%d", major, minor)
}

// knownName returns the name of a block device from sysfs or /proc/diskstats, or an empty string.
// Unknown devices are not cached, as their numbers may be given to another device.
func (d *deviceNames) knownName(major, minor uint32) string {
	d.expire()
	if name, ok := d.cache[[2]uint32{major, minor}]; ok {
		return name
	}
	numbers := fmt.Sprintf("%d:%d", major, minor)
	name := devNameFromUevent(filepath.Join(d.sysRoot, "dev", "block", numbers, "uevent"))
	if name == "" {
		// the path devices of NVMe native multipath (nvmeXcYnZ) are hidden: sysfs doesn't link
		// their numbers, but /proc/diskstats lists them
		name = d.diskstatsName(major, minor)
	}
	if name != "" {
		d.cache[[2]uint32{major, minor}] = name
	}
	return name
}

// diskstatsName returns the name that /proc/diskstats lists a block device with, or an empty
// string. It reads /proc/diskstats once per cache period.
func (d *deviceNames) diskstatsName(major, minor uint32) string {
	if d.diskstats == nil {
		d.diskstats = map[[2]uint32]string{}
		diskstats, _ := procDiskstats(d.procRoot, d.sysRoot)
		for _, stat := range diskstats {
			// before Linux 6.1, the kernel lists all the hidden NVMe path devices as 0:0
			if stat.MajorNumber == 0 {
				continue
			}
			d.diskstats[[2]uint32{stat.MajorNumber, stat.MinorNumber}] = stat.DeviceName
		}
	}
	return d.diskstats[[2]uint32{major, minor}]
}

func procDiskstats(procRoot, sysRoot string) ([]blockdevice.Diskstats, error) {
	fs, err := blockdevice.NewFS(procRoot, sysRoot)
	if err != nil {
		return nil, err
	}
	return fs.ProcDiskstats()
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

func devNumbers(major, minor uint32) string {
	return strconv.FormatUint(uint64(major), 10) + ":" + strconv.FormatUint(uint64(minor), 10)
}
