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

// DiskMapTracer periodically reads the block request, file sync and NFS client RPC durations that the
// kernel accumulates, and forwards what each key gained since the previous read.
type DiskMapTracer struct {
	// the readStats of the accumulation maps that the kernel fills
	readers  []func() []*ebpf.Stat
	interval time.Duration
}

// NewDiskMapTracer reads the accumulation maps that are not nil
func NewDiskMapTracer(diskAccum, fsSyncAccum, nfsProcedureAccum, cgroupNames *ciliumebpf.Map, statusIsBlkStatus bool,
	cfg *config.EBPFTracer,
) *DiskMapTracer {
	interval := cfg.BatchTimeout
	if interval <= 0 {
		interval = defaultDiskReadInterval
	}
	containers := ebpfCgroupContainers(cgroupNames)
	tracer := &DiskMapTracer{interval: interval}
	if diskAccum != nil {
		reader := newDiskReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: diskAccum},
			&blockDevices{sysRoot: "/sys", procRoot: "/proc"}, interval)
		reader.statusIsBlkStatus = statusIsBlkStatus
		reader.containers = containers
		tracer.readers = append(tracer.readers, reader.readStats)
	}
	if fsSyncAccum != nil {
		accum := ebpfAccum[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT]{accum: fsSyncAccum}
		tracer.readers = append(tracer.readers, newFsSyncReader(accum, containers, interval).readStats)
	}
	if nfsProcedureAccum != nil {
		accum := ebpfAccum[ebpf.StatsNfsProcedureKeyT, ebpf.StatsNfsProcedureAccumT]{accum: nfsProcedureAccum}
		tracer.readers = append(tracer.readers, newNFSProcedureReader(accum, interval).readStats)
	}
	return tracer
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
				var stats []*ebpf.Stat
				for _, readStats := range m.readers {
					stats = append(stats, readStats()...)
				}
				if len(stats) > 0 {
					out.SendCtx(ctx, stats)
				}
			}
		}
	}
}

type accumMap[K, V comparable] interface {
	// read returns the entries of the map, with errAccumFull when it is full
	read() (map[K]V, error)
	lookupAndDelete(key K) (V, error)
	delete(key K) error
}

type ebpfAccum[K, V comparable] struct {
	accum *ciliumebpf.Map
}

func (a ebpfAccum[K, V]) read() (map[K]V, error) {
	entries := map[K]V{}
	var key K
	var value V
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

func (a ebpfAccum[K, V]) lookupAndDelete(key K) (V, error) {
	var last V
	err := a.accum.LookupAndDelete(&key, &last)
	return last, err
}

func (a ebpfAccum[K, V]) delete(key K) error {
	return a.accum.Delete(&key)
}

// accumReader forwards, as stats, what the entries of a kernel accumulation map gained since the
// previous read. The kernel only adds to them, and the reader deletes those that stay unchanged for
// diskIdleTime.
type accumReader[K, V comparable] struct {
	log   *slog.Logger
	accum accumMap[K, V]
	// toStat returns the stat of what an entry gained since its previous value
	toStat     func(key K, current, previous V) *ebpf.Stat
	entries    map[K]accumEntry[V]
	warnedFull bool
	// idleReadsBeforeDelete is how many reads find an entry unchanged before it is deleted
	idleReadsBeforeDelete int
}

type accumEntry[V comparable] struct {
	previous  V
	idleReads int
}

func newAccumReader[K, V comparable](mapName string, accum accumMap[K, V], toStat func(K, V, V) *ebpf.Stat,
	interval time.Duration,
) *accumReader[K, V] {
	return &accumReader[K, V]{
		log:                   dtlog().With("map", mapName),
		accum:                 accum,
		toStat:                toStat,
		entries:               map[K]accumEntry[V]{},
		idleReadsBeforeDelete: max(1, int((diskIdleTime+interval-1)/interval)),
	}
}

// diskReader reads the accumulation map of the block requests
type diskReader struct {
	*accumReader[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]
	devices *blockDevices
	// the statuses of the keys are blk_status_t values instead of errnos
	statusIsBlkStatus bool
	containers        *cgroupContainers
}

func newDiskReader(accum accumMap[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT], devices *blockDevices,
	interval time.Duration,
) *diskReader {
	r := &diskReader{devices: devices}
	r.accumReader = newAccumReader(ebpf.StatsMapDiskIoAccum, accum, r.stat, interval)
	return r
}

// newFsSyncReader reads the accumulation map of the file syncs
func newFsSyncReader(accum accumMap[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT], containers *cgroupContainers,
	interval time.Duration,
) *accumReader[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT] {
	return newAccumReader(ebpf.StatsMapFsSyncAccum, accum, func(key ebpf.StatsFsSyncKeyT, current, previous ebpf.StatsFsSyncAccumT) *ebpf.Stat {
		return &ebpf.Stat{
			Type: ebpf.StatTypeFsSync,
			FsSync: &ebpf.FsSync{
				Type: ebpf.FsSyncTypeCode(key.Type),
				// a sync returns an errno, as block_rq_complete before Linux 5.16
				ErrorType:   diskErrorType(key.Status, false),
				ContainerID: containers.containerID(key.CgroupId),
				Latency:     latencyDelta(current.LatencyCount[:], previous.LatencyCount[:], current.LatencySumNs, previous.LatencySumNs),
			},
		}
	}, interval)
}

// nullProcedure names the procedure that the kernel leaves unnamed: the NULL ping that the NFS client
// sends with each new RPC client, which the statistics of the kernel name NULL
const nullProcedure = "NULL"

// newNFSProcedureReader reads the accumulation map of the NFS client RPCs
func newNFSProcedureReader(accum accumMap[ebpf.StatsNfsProcedureKeyT, ebpf.StatsNfsProcedureAccumT], interval time.Duration,
) *accumReader[ebpf.StatsNfsProcedureKeyT, ebpf.StatsNfsProcedureAccumT] {
	log := dtlog()
	return newAccumReader(ebpf.StatsMapNfsProcedureAccum, accum, func(key ebpf.StatsNfsProcedureKeyT, current, previous ebpf.StatsNfsProcedureAccumT) *ebpf.Stat {
		latency := latencyDelta(current.LatencyCount[:], previous.LatencyCount[:], current.LatencySumNs, previous.LatencySumNs)
		errorType := nfsErrorType(key.Status)
		if errorType == errtype.Other {
			log.Debug("NFS RPCs completed with a status without a name", "status", key.Status, "rpcs", latency.Count())
		}
		procedure := unix.ByteSliceToString(key.Procedure[:])
		if procedure == "" {
			procedure = nullProcedure
		}
		return &ebpf.Stat{
			Type: ebpf.StatTypeNFSProcedure,
			NFSProcedure: &ebpf.NFSProcedure{
				Server:    unix.ByteSliceToString(key.Server[:]),
				Procedure: procedure,
				Version:   key.Version,
				ErrorType: errorType,
				Latency:   latency,
			},
		}
	}, interval)
}

func (r *accumReader[K, V]) readStats() []*ebpf.Stat {
	entries, err := r.accum.read()
	switch {
	case errors.Is(err, errAccumFull):
		if !r.warnedFull {
			r.warnedFull = true
			r.log.Warn("a storage accumulation map is full: the operations of the keys that it doesn't hold are "+
				"not measured until idle entries are deleted", "entries", len(entries))
		}
	case err != nil:
		// what was read is forwarded, and the rest at the next read
		r.log.Debug("can't read a storage accumulation map", "error", err)
	}

	var stats []*ebpf.Stat
	for key, current := range entries {
		entry := r.entries[key]
		if current != entry.previous {
			r.entries[key] = accumEntry[V]{previous: current}
			stats = append(stats, r.toStat(key, current, entry.previous))
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
func (r *accumReader[K, V]) deleteIdle(key K, entry accumEntry[V]) *ebpf.Stat {
	last, err := r.accum.lookupAndDelete(key)
	if err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		last, err = entry.previous, r.accum.delete(key)
	}
	switch {
	case errors.Is(err, ciliumebpf.ErrKeyNotExist):
		delete(r.entries, key)
		return nil
	case err != nil:
		r.log.Debug("can't delete an idle entry of a storage accumulation map", "error", err)
		r.entries[key] = entry
		return nil
	}
	delete(r.entries, key)
	if last == entry.previous {
		return nil
	}
	return r.toStat(key, last, entry.previous)
}

// latencyDelta returns what a kernel latency histogram counted since a previous read
func latencyDelta(counts, previousCounts []uint64, sumNs, previousSumNs uint64) ebpf.LatencyHistogram {
	latency := ebpf.LatencyHistogram{
		BucketCounts: make([]uint64, len(counts)),
		Sum:          float64(sumNs-previousSumNs) / float64(time.Second),
	}
	for bucket := range counts {
		latency.BucketCounts[bucket] = counts[bucket] - previousCounts[bucket]
	}
	return latency
}

// stat returns the requests that completed on the device and in the direction of a key since the
// previous read
func (r *diskReader) stat(key ebpf.StatsDiskIoKeyT, current, previous ebpf.StatsDiskIoAccumT) *ebpf.Stat {
	device := r.devices.device(key.Major, key.Minor)
	latency := latencyDelta(current.LatencyCount[:], previous.LatencyCount[:], current.LatencySumNs, previous.LatencySumNs)
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

// cgroupContainers names the containers of the cgroups that the kernel charges the I/O and the syncs
// to, from the names of the cgroups and of their parents that the kernel recorded
type cgroupContainers struct {
	names func(cgroupID uint64) (name, parent string, ok bool)
	cache *simplelru.LRU[uint64, string]
}

// ebpfCgroupContainers names the containers from the names that the kernel records in cgroupNames
func ebpfCgroupContainers(cgroupNames *ciliumebpf.Map) *cgroupContainers {
	names := func(cgroupID uint64) (string, string, bool) {
		var name ebpf.StatsDiskCgroupNameT
		if err := cgroupNames.Lookup(cgroupID, &name); err != nil {
			return "", "", false
		}
		return unix.ByteSliceToString(name.Name[:]), unix.ByteSliceToString(name.Parent[:]), true
	}
	return newCgroupContainers(names, int(cgroupNames.MaxEntries()))
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

// nfsErrorType names the status of failed NFS RPCs after its errno, and is empty on success
func nfsErrorType(status uint16) string {
	if status == 0 {
		return ""
	}
	if name := unix.ErrnoName(syscall.Errno(status)); name != "" {
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
