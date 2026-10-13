// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/prometheus/procfs/blockdevice"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/errtype"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// defaultDiskReadInterval is how often the kernel map is read when ebpf.batch_timeout is 0
const defaultDiskReadInterval = time.Second

// diskIdleTime is how long an entry of the kernel map stays unchanged before it is deleted, so that
// the keys without I/O leave room for new ones
const diskIdleTime = time.Minute

// blockDevicesCachePeriod is how long what sysfs tells of the block devices is cached: the kernel
// gives the numbers of removed devices to new ones
const blockDevicesCachePeriod = 30 * time.Second

var timeNow = time.Now

var errAccumFull = errors.New("the accumulation map is full")

func dtlog() *slog.Logger {
	return slog.With("component", "stat.DiskMapTracer")
}

// DiskMapTracer periodically reads the block request durations that the kernel accumulates, and
// forwards what each device and direction gained since the previous read.
type DiskMapTracer struct {
	reader   *diskReader
	interval time.Duration
}

func NewDiskMapTracer(accum, cgroupNames *ciliumebpf.Map, statusIsBlkStatus bool, cfg *config.EBPFTracer) *DiskMapTracer {
	interval := cfg.BatchTimeout
	if interval <= 0 {
		interval = defaultDiskReadInterval
	}
	reader := newDiskReader(ebpfDiskAccum{accum: accum}, &blockDevices{sysRoot: "/sys", procRoot: "/proc"}, interval)
	reader.statusIsBlkStatus = statusIsBlkStatus
	names := func(cgroupID uint64) (string, string, bool) {
		var name ebpf.StatsDiskCgroupNameT
		if err := cgroupNames.Lookup(cgroupID, &name); err != nil {
			return "", "", false
		}
		return unix.ByteSliceToString(name.Name[:]), unix.ByteSliceToString(name.Parent[:]), true
	}
	reader.containers = newCgroupContainers(names, int(cgroupNames.MaxEntries()))
	return &DiskMapTracer{
		reader:   reader,
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

type diskAccum interface {
	// read returns the entries of the map, with errAccumFull when it is full
	read() (map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT, error)
	lookupAndDelete(key ebpf.StatsDiskIoKeyT) (ebpf.StatsDiskIoAccumT, error)
	delete(key ebpf.StatsDiskIoKeyT) error
}

type ebpfDiskAccum struct {
	accum *ciliumebpf.Map
}

func (a ebpfDiskAccum) read() (map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT, error) {
	entries := map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{}
	var key ebpf.StatsDiskIoKeyT
	var value ebpf.StatsDiskIoAccumT
	iter := a.accum.Iterate()
	for iter.Next(&key, &value) {
		entries[key] = value
	}
	if err := iter.Err(); err != nil {
		return entries, err
	}
	if len(entries) >= int(a.accum.MaxEntries()) {
		return entries, errAccumFull
	}
	return entries, nil
}

func (a ebpfDiskAccum) lookupAndDelete(key ebpf.StatsDiskIoKeyT) (ebpf.StatsDiskIoAccumT, error) {
	var last ebpf.StatsDiskIoAccumT
	err := a.accum.LookupAndDelete(&key, &last)
	return last, err
}

func (a ebpfDiskAccum) delete(key ebpf.StatsDiskIoKeyT) error {
	return a.accum.Delete(&key)
}

// diskReader forwards, as stats, what the entries of the kernel map gained since the previous read.
// The kernel only adds to them, and the reader deletes those that stay unchanged for diskIdleTime.
type diskReader struct {
	log        *slog.Logger
	accum      diskAccum
	devices    *blockDevices
	entries    map[ebpf.StatsDiskIoKeyT]diskEntry
	warnedFull bool
	// the statuses of the keys are blk_status_t values instead of errnos
	statusIsBlkStatus bool
	// idleReadsBeforeDelete is how many reads find an entry unchanged before it is deleted
	idleReadsBeforeDelete int
	containers            *cgroupContainers
}

type diskEntry struct {
	previous  ebpf.StatsDiskIoAccumT
	idleReads int
}

func newDiskReader(accum diskAccum, devices *blockDevices, interval time.Duration) *diskReader {
	return &diskReader{
		log:                   dtlog(),
		accum:                 accum,
		devices:               devices,
		entries:               map[ebpf.StatsDiskIoKeyT]diskEntry{},
		idleReadsBeforeDelete: max(1, int((diskIdleTime+interval-1)/interval)),
	}
}

func (r *diskReader) readStats() []*ebpf.Stat {
	entries, err := r.accum.read()
	switch {
	case errors.Is(err, errAccumFull):
		if !r.warnedFull {
			r.warnedFull = true
			r.log.Warn("the disk_io_accum map is full: the I/O of the devices, directions and workloads that it "+
				"doesn't hold is not measured until idle entries are deleted", "entries", len(entries))
		}
	case err != nil:
		// what was read is forwarded, and the rest at the next read
		r.log.Debug("can't read the disk_io_accum map", "error", err)
	}

	var stats []*ebpf.Stat
	for key, current := range entries {
		entry := r.entries[key]
		if current != entry.previous {
			r.entries[key] = diskEntry{previous: current}
			stats = append(stats, r.stat(key, current, entry.previous))
			continue
		}
		entry.idleReads++
		if entry.idleReads < r.idleReadsBeforeDelete {
			r.entries[key] = entry
			continue
		}
		if stat := r.deleteIdle(key, entry); stat != nil {
			stats = append(stats, stat)
		}
	}
	return stats
}

// deleteIdle deletes the entry of a key from the kernel map, and returns what the kernel added to it
// since its last read, if anything. Hash maps can only look up and delete an entry at once from
// Linux 5.14: before, what the kernel adds between the read and the delete is lost. A completion that
// looked the entry up before its deletion adds to the freed element: its request is lost, or counted
// under the key that reuses the element.
func (r *diskReader) deleteIdle(key ebpf.StatsDiskIoKeyT, entry diskEntry) *ebpf.Stat {
	last, err := r.accum.lookupAndDelete(key)
	if err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		last, err = entry.previous, r.accum.delete(key)
	}
	switch {
	case errors.Is(err, ciliumebpf.ErrKeyNotExist):
		delete(r.entries, key)
		return nil
	case err != nil:
		r.log.Debug("can't delete an idle entry of the disk_io_accum map", "error", err)
		r.entries[key] = entry
		return nil
	}
	delete(r.entries, key)
	if last == entry.previous {
		return nil
	}
	return r.stat(key, last, entry.previous)
}

// stat returns the requests that completed on the device and in the direction of a key since the
// previous read
func (r *diskReader) stat(key ebpf.StatsDiskIoKeyT, current, previous ebpf.StatsDiskIoAccumT) *ebpf.Stat {
	device := r.devices.device(key.Major, key.Minor)
	latency := ebpf.LatencyHistogram{
		BucketCounts: make([]uint64, len(current.LatencyCount)),
		Sum:          float64(current.LatencySumNs-previous.LatencySumNs) / float64(time.Second),
	}
	for bucket := range current.LatencyCount {
		latency.BucketCounts[bucket] = current.LatencyCount[bucket] - previous.LatencyCount[bucket]
	}
	return &ebpf.Stat{
		Type: ebpf.StatTypeDiskIO,
		DiskIO: &ebpf.DiskIO{
			Device:     device.name,
			VolumeName: device.volumeName,
			Stacked:    device.stacked,
			Op:         ebpf.DiskOpCode(key.Op),
			Latency:    latency,
			ErrorType:  diskErrorType(key.Status, r.statusIsBlkStatus),
			Bytes:      current.Bytes - previous.Bytes,

			ContainerID:   r.containers.containerID(key.CgroupId),
			MultipathPath: device.dmMultipathPath,
		},
	}
}

// cgroupContainers names the containers of the cgroups that the kernel charges the I/O to, from the
// names of the cgroups and of their parents that the kernel recorded
type cgroupContainers struct {
	names func(cgroupID uint64) (name, parent string, ok bool)
	cache *simplelru.LRU[uint64, string]
}

func newCgroupContainers(names func(uint64) (string, string, bool), size int) *cgroupContainers {
	// the size of a map, which is positive
	cache, _ := simplelru.NewLRU[uint64, string](size, nil)
	return &cgroupContainers{names: names, cache: cache}
}

// containerID returns the ID of the container of a cgroup, or an empty string for none
func (c *cgroupContainers) containerID(cgroupID uint64) string {
	if cgroupID == 0 {
		return ""
	}
	if id, ok := c.cache.Get(cgroupID); ok {
		return id
	}
	name, parent, ok := c.names(cgroupID)
	if !ok {
		// not cached, as the kernel can still record the names
		return ""
	}
	id, _ := container.IDFromCgroupNames(name, parent)
	c.cache.Add(cgroupID, id)
	return id
}

// diskErrorType names the status of failed requests after its errno, so that it reads the same
// whether the kernel reports errnos or blk_status_t values, and is empty on success
func diskErrorType(status uint8, isBlkStatus bool) string {
	if status == 0 {
		return ""
	}
	errno := syscall.Errno(status)
	if isBlkStatus {
		// errno 0, which has no name, if the table doesn't know the status
		errno = blkStatusErrno[status]
	}
	if name := unix.ErrnoName(errno); name != "" {
		return name
	}
	return errtype.Other
}

type devNum struct {
	major, minor uint32
}

type blockDevice struct {
	name       string
	volumeName string
	stacked    bool
	// the histograms of the paths of a dm-multipath device would multiply its series
	dmMultipathPath bool
}

type blockDevices struct {
	sysRoot, procRoot string
	cachedAt          time.Time
	devices           map[devNum]blockDevice
	// diskstats names the devices that /proc/diskstats lists, read once per cache period
	diskstats map[devNum]string
}

// device returns what sysfs tells of a block device. A device that neither sysfs nor
// /proc/diskstats knows, as one removed since its I/O, is named by its "major:minor" numbers, which
// are not cached, as the kernel can give them to a new device.
func (d *blockDevices) device(major, minor uint32) blockDevice {
	if now := timeNow(); now.Sub(d.cachedAt) >= blockDevicesCachePeriod {
		d.cachedAt = now
		d.devices = map[devNum]blockDevice{}
		d.diskstats = nil
	}
	numbers := devNum{major: major, minor: minor}
	if device, ok := d.devices[numbers]; ok {
		return device
	}
	devNumbers := fmt.Sprintf("%d:%d", major, minor)
	dir := filepath.Join(d.sysRoot, "dev", "block", devNumbers)
	device := blockDevice{
		name:            ueventDevName(filepath.Join(dir, "uevent")),
		volumeName:      deviceMapperName(dir),
		stacked:         isStacked(dir),
		dmMultipathPath: heldByDMMultipath(dir),
	}
	if device.name == "" {
		// sysfs doesn't link the hidden path devices of NVMe native multipath (nvmeXcYnZ) from
		// /sys/dev/block, but /proc/diskstats lists them
		device.name = d.diskstatsName(numbers)
	}
	if device.name == "" {
		return blockDevice{name: devNumbers}
	}
	d.devices[numbers] = device
	return device
}

func (d *blockDevices) diskstatsName(numbers devNum) string {
	if d.diskstats == nil {
		d.diskstats = map[devNum]string{}
		for _, stat := range procDiskstats(d.procRoot, d.sysRoot) {
			// before Linux 6.1, the kernel lists all the hidden NVMe paths as 0:0
			if stat.MajorNumber != 0 {
				d.diskstats[devNum{major: stat.MajorNumber, minor: stat.MinorNumber}] = stat.DeviceName
			}
		}
	}
	return d.diskstats[numbers]
}

// procDiskstats returns what it could read of /proc/diskstats
func procDiskstats(procRoot, sysRoot string) []blockdevice.Diskstats {
	fs, err := blockdevice.NewFS(procRoot, sysRoot)
	if err != nil {
		return nil
	}
	diskstats, _ := fs.ProcDiskstats()
	return diskstats
}

func ueventDevName(path string) string {
	uevent, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(uevent)) {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "DEVNAME="); ok {
			return name
		}
	}
	return ""
}
