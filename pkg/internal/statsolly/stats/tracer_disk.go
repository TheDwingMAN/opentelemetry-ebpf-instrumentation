// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/prometheus/procfs/blockdevice"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/errtype"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// diskIdleDeleteAfter is how long an entry of the kernel accumulation map survives without changes
// before it is deleted, so entries of devices that stopped doing I/O don't fill the map.
const diskIdleDeleteAfter = time.Minute

// idleReadsBeforeDelete is how many consecutive reads without changes, one every readInterval,
// take diskIdleDeleteAfter, and at least one
func idleReadsBeforeDelete(readInterval time.Duration) int {
	return max(1, int((diskIdleDeleteAfter+readInterval-1)/readInterval))
}

// cgroupContainersCacheLen matches the size of the disk_cgroup_names eBPF map
const cgroupContainersCacheLen = 1 << 13

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
	// lookupAndDelete deletes an entry and returns its last value, or ciliumebpf.ErrNotSupported
	// when the kernel can't do both at once
	lookupAndDelete(key K) (V, error)
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

func (e ebpfAccum[K, V]) lookupAndDelete(key K) (V, error) {
	var last V
	err := e.accum.LookupAndDelete(key, &last)
	// hash maps support it from Linux 5.14: older kernels return ENOTSUPP. Kernels without the
	// command (before 4.20) return EINVAL. OBI supports none, so this only guards eBPF backports
	// that lack it, whose idle entries would never be deleted otherwise.
	if errors.Is(err, unix.EINVAL) {
		return last, fmt.Errorf("%w: %w", ciliumebpf.ErrNotSupported, err)
	}
	return last, err
}

// cgroupNameSource abstracts the disk_cgroup_names eBPF map, for testing
type cgroupNameSource interface {
	name(cgroupID uint64) (cgroupName, bool)
}

// cgroupName is the name of a cgroup and of its parent, as the kernel recorded them
type cgroupName struct {
	name, parent string
}

type ebpfCgroupNames struct {
	names *ciliumebpf.Map
}

func (e ebpfCgroupNames) name(cgroupID uint64) (cgroupName, bool) {
	var name ebpf.StatsDiskCgroupNameT
	if err := e.names.Lookup(cgroupID, &name); err != nil {
		return cgroupName{}, false
	}
	return cgroupName{name: unix.ByteSliceToString(name.Name[:]), parent: unix.ByteSliceToString(name.Parent[:])}, true
}

// DiskMapTracerConfig tells a DiskMapTracer which kernel maps to read, and how to interpret them
type DiskMapTracerConfig struct {
	// DiskIOAccum is the accumulation map to read
	DiskIOAccum *ciliumebpf.Map
	// CgroupNames are the names of the cgroups that the kernel charges the I/O to
	CgroupNames *ciliumebpf.Map
	// DiskStatusIsBlkStatus tells how the kernel reports block request completion statuses
	// (see disk_status_code)
	DiskStatusIsBlkStatus bool
	Interval              time.Duration
}

// DiskMapTracer periodically reads the storage stats that the kernel keeps, and forwards what
// changed since the previous read as ebpf.Stat records.
type DiskMapTracer struct {
	reader   *diskReader
	interval time.Duration
}

func NewDiskMapTracer(cfg *DiskMapTracerConfig) *DiskMapTracer {
	accum := ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: cfg.DiskIOAccum}
	devices := &blockDevices{sysRoot: "/sys", procRoot: "/proc"}
	containers := newCgroupContainers(ebpfCgroupNames{names: cfg.CgroupNames})
	return &DiskMapTracer{
		reader:   newDiskReader(accum, cfg.DiskStatusIsBlkStatus, devices, containers, cfg.Interval),
		interval: cfg.Interval,
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
				stats := m.reader.readStats()
				if len(stats) > 0 {
					out.SendCtx(ctx, stats)
				}
			}
		}
	}
}

// diskReader reads the kernel accumulation map of the disk stats and forwards, as stats, what grew
// since the previous read of each entry.
type diskReader struct {
	log   *slog.Logger
	accum accumSource[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]
	stats diskStats

	previous  map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT
	idleReads map[ebpf.StatsDiskIoKeyT]int
	// idleReadsBeforeDelete is how many reads without changes an entry survives
	idleReadsBeforeDelete int
	// the map was full at the previous read
	full bool
	// the kernel can't look up and delete an entry at once
	noLookupAndDelete bool
}

func newDiskReader(
	accum accumSource[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT],
	statusIsBlkStatus bool,
	devices *blockDevices,
	containers *cgroupContainers,
	readInterval time.Duration,
) *diskReader {
	return &diskReader{
		log:                   dtlog().With("map", "disk_io_accum"),
		accum:                 accum,
		stats:                 diskStats{statusIsBlkStatus: statusIsBlkStatus, devices: devices, containers: containers},
		previous:              map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{},
		idleReads:             map[ebpf.StatsDiskIoKeyT]int{},
		idleReadsBeforeDelete: idleReadsBeforeDelete(readInterval),
	}
}

func (r *diskReader) readStats() []*ebpf.Stat {
	entries, err := r.accum.read()
	full := errors.Is(err, errAccumFull)
	if full {
		// the kernel doesn't add new keys to a full map: they are dropped until idle ones are
		// deleted
		if !r.full {
			r.log.Warn("the kernel map is full: the I/O of new workloads and devices is not measured "+
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
		if stat := r.stats.stat(key, current, r.previous[key]); stat != nil {
			stats = append(stats, stat)
			r.idleReads[key] = 0
			// only what was forwarded is remembered: the kernel adds the bytes and the latency of a
			// request before counting it, and what a read finds of them before the count is
			// forwarded with the request
			r.previous[key] = current
		} else if lastGrowth := r.forgetIfIdle(key); lastGrowth != nil {
			stats = append(stats, lastGrowth)
		}
	}
	if err == nil {
		r.forgetEvicted(entries)
	}
	return stats
}

// forgetIfIdle deletes the entry of a key once it went diskIdleDeleteAfter without a request
// counted. It returns the stat of what the kernel added to the entry since it was last forwarded,
// until its deletion, or nil.
func (r *diskReader) forgetIfIdle(key ebpf.StatsDiskIoKeyT) *ebpf.Stat {
	r.idleReads[key]++
	if r.idleReads[key] < r.idleReadsBeforeDelete {
		return nil
	}
	last, known, err := r.deleteEntry(key)
	if err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		r.log.Debug("can't delete idle accumulation map entry", "error", err)
		return nil
	}
	previous := r.previous[key]
	delete(r.idleReads, key)
	delete(r.previous, key)
	if err != nil || !known {
		return nil
	}
	return r.stats.stat(key, last, previous)
}

// deleteEntry deletes the entry of a key, and returns its last value when the kernel can look it
// up and delete it at once. Otherwise, what the kernel adds to the entry between its read and its
// deletion is lost. Either way, a probe that found the entry before its deletion can still add to
// it after. The hash maps are preallocated, so that is lost, or counted once in the entry, of the
// same key or another, that reuses its element.
func (r *diskReader) deleteEntry(key ebpf.StatsDiskIoKeyT) (last ebpf.StatsDiskIoAccumT, known bool, err error) {
	if !r.noLookupAndDelete {
		last, err = r.accum.lookupAndDelete(key)
		if !errors.Is(err, ciliumebpf.ErrNotSupported) {
			return last, true, err
		}
		r.log.Debug("the kernel can't look up and delete map entries at once: the idle entries are "+
			"deleted without their last value", "error", err)
		r.noLookupAndDelete = true
	}
	return last, false, r.accum.delete(key)
}

// forgetEvicted drops what is remembered about entries that are no longer in the map
func (r *diskReader) forgetEvicted(entries map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT) {
	for key := range r.idleReads {
		if _, ok := entries[key]; !ok {
			delete(r.previous, key)
			delete(r.idleReads, key)
		}
	}
}

type diskStats struct {
	statusIsBlkStatus bool
	devices           *blockDevices
	containers        *cgroupContainers
}

// stat returns the block requests that completed since the previous read of the key, or nil
func (d *diskStats) stat(key ebpf.StatsDiskIoKeyT, current, previous ebpf.StatsDiskIoAccumT) *ebpf.Stat {
	// kernel counters only grow; a decrease means the entry was deleted and re-created
	if anyDecreased(current.LatencyCount[:], previous.LatencyCount[:]) || current.LatencySumNs < previous.LatencySumNs ||
		current.Bytes < previous.Bytes {
		previous = ebpf.StatsDiskIoAccumT{}
	}
	latency, operations := latencyDelta(current, previous)
	if operations == 0 {
		return nil
	}
	device := d.devices.device(key.Major, key.Minor)
	serviceTime := latency.Sum
	// the paths of a multipath device report no latency: the multipath device reports the latency
	// of the same I/O, and the histograms of its paths would multiply its series by their number.
	// They keep their counters, which show a slow or failing path.
	if device.dmMultipathPath {
		latency = nil
	}
	return &ebpf.Stat{
		Type: ebpf.StatTypeDiskIO,
		DiskIO: &ebpf.DiskIO{
			Device:      device.name,
			VolumeName:  device.dmName,
			Stacked:     device.stacked,
			Op:          ebpf.DiskOpCode(key.Op),
			ErrorType:   diskErrorType(key.Status, d.statusIsBlkStatus),
			ContainerID: d.containers.containerID(key.CgroupId),
			Operations:  operations,
			Time:        serviceTime,
			Bytes:       current.Bytes - previous.Bytes,
			Latency:     latency,
		},
	}
}

// latencyDelta returns what a kernel latency histogram counted since a previous read, and how many
// requests that is
func latencyDelta(current, previous ebpf.StatsDiskIoAccumT) (*ebpf.LatencyHistogram, uint64) {
	latency := &ebpf.LatencyHistogram{
		BucketCounts: make([]uint64, len(current.LatencyCount)),
		Sum:          float64(current.LatencySumNs-previous.LatencySumNs) / float64(time.Second),
	}
	var operations uint64
	for bucket := range current.LatencyCount {
		latency.BucketCounts[bucket] = current.LatencyCount[bucket] - previous.LatencyCount[bucket]
		operations += latency.BucketCounts[bucket]
	}
	return latency, operations
}

func anyDecreased(current, previous []uint64) bool {
	for i := range current {
		if current[i] < previous[i] {
			return true
		}
	}
	return false
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
			return errtype.Other
		}
	}
	if name := unix.ErrnoName(errno); name != "" {
		return name
	}
	return errtype.Other
}

// cgroupContainers resolves the cgroups that block I/O is charged to into the ID of their
// container, from the cgroup names that the kernel recorded
type cgroupContainers struct {
	names cgroupNameSource
	cache *simplelru.LRU[uint64, string]
}

func newCgroupContainers(names cgroupNameSource) *cgroupContainers {
	// the size is a constant known to be valid
	cache, _ := simplelru.NewLRU[uint64, string](cgroupContainersCacheLen, nil)
	return &cgroupContainers{names: names, cache: cache}
}

// containerID returns the ID of the container of the cgroup, or an empty string if the cgroup is
// not a container, or is unknown
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
	id, _ := container.IDFromCgroupNames(name.name, name.parent)
	c.cache.Add(cgroupID, id)
	return id
}

// blockDevicesCachePeriod is how long what is known of the block devices is cached: the kernel
// gives the numbers of removed devices to new ones, e.g. the minors of detached NVMe volumes or of
// loop devices
const blockDevicesCachePeriod = 30 * time.Second

// devNum holds the major and minor numbers of a block device
type devNum struct {
	major, minor uint32
}

// blockDevice is what sysfs and /proc/diskstats tell of a block device
type blockDevice struct {
	// name is the kernel name, e.g. nvme0n1, or the "major:minor" numbers when neither sysfs nor
	// /proc/diskstats names the device
	name string
	// dmName is the device mapper name, as /dev/mapper lists it, or empty for other devices
	dmName string
	// stacked tells whether the device is built on other block devices (see isStacked)
	stacked bool
	// dmMultipathPath tells whether the device is a disk that a measured dm-multipath device holds
	dmMultipathPath bool
}

// blockDevices resolves block device numbers to what sysfs and /proc/diskstats tell of the devices
type blockDevices struct {
	sysRoot, procRoot string
	// now returns the current time, time.Now if nil
	now      func() time.Time
	cachedAt time.Time

	cache     map[devNum]blockDevice
	diskstats map[devNum]string
}

// expire forgets what is cached once blockDevicesCachePeriod passed since it started caching
func (d *blockDevices) expire() {
	now := time.Now()
	if d.now != nil {
		now = d.now()
	}
	if d.cache != nil && now.Sub(d.cachedAt) < blockDevicesCachePeriod {
		return
	}
	d.cachedAt = now
	d.cache = map[devNum]blockDevice{}
	d.diskstats = nil
}

// device returns what is known of a block device. Devices without a name are not cached, as
// their numbers may be given to another device.
func (d *blockDevices) device(major, minor uint32) blockDevice {
	d.expire()
	numbers := devNum{major: major, minor: minor}
	if device, ok := d.cache[numbers]; ok {
		return device
	}

	var device blockDevice
	dir := filepath.Join(d.sysRoot, "dev", "block", devNumbers(major, minor))
	if exists(dir) {
		device = blockDevice{
			name:            devNameFromUevent(filepath.Join(dir, "uevent")),
			dmName:          deviceMapperName(dir),
			stacked:         isStacked(dir),
			dmMultipathPath: heldByDMMultipath(dir),
		}
	}
	if device.name == "" {
		// the path devices of NVMe native multipath (nvmeXcYnZ) are hidden: sysfs doesn't link
		// their numbers, but /proc/diskstats lists them
		device.name = d.diskstatsName(numbers)
	}
	if device.name == "" {
		// e.g. a device removed since its last I/O
		device.name = devNumbers(major, minor)
		return device
	}
	d.cache[numbers] = device
	return device
}

// heldByDMMultipath tells whether the sysfs directory of a block device is a path that a measured
// dm-multipath device holds
func heldByDMMultipath(dir string) bool {
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

// diskstatsName returns the name that /proc/diskstats lists a block device with, or an empty
// string. It reads /proc/diskstats once per cache period.
func (d *blockDevices) diskstatsName(numbers devNum) string {
	if d.diskstats == nil {
		d.diskstats = map[devNum]string{}
		diskstats, _ := procDiskstats(d.procRoot, d.sysRoot)
		for _, stat := range diskstats {
			// before Linux 6.1, the kernel lists all the hidden NVMe path devices as 0:0
			if stat.MajorNumber == 0 {
				continue
			}
			d.diskstats[devNum{major: stat.MajorNumber, minor: stat.MinorNumber}] = stat.DeviceName
		}
	}
	return d.diskstats[numbers]
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
