// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

const (
	loopBackingFileSize = 64 << 20
	directIOBlockSize   = 64 << 10
	directIOBlocks      = 256

	fileSyncs = 20

	// environment of the child processes of TestDiskIOIsChargedPerCgroup and
	// TestDiskBufferedWritesAreChargedToTheirCgroup
	envWriterDevice = "OBI_TEST_DISK_WRITER_DEVICE"
	envWriterBlocks = "OBI_TEST_DISK_WRITER_BLOCKS"
	envWriterFile   = "OBI_TEST_DISK_WRITER_FILE"
)

// allAttributes selects every attribute of every metric, so that the disk probes read the cgroup
// of the I/O
var allAttributes = &attributes.SelectorConfig{
	SelectionCfg: attributes.Selection{"*": attributes.InclusionLists{Include: []string{"*"}}},
}

// TestDiskLatencyIsAccumulatedPerDevice drives a known I/O pattern on a loop device and checks
// that the kernel accumulates exactly one latency sample per completed request, in the buckets of
// the bounds that userspace gives it. The I/O is O_DIRECT and sequential at queue depth 1, so
// the block layer neither caches nor merges it.
func TestDiskLatencyIsAccumulatedPerDevice(t *testing.T) {
	loopDev := attachLoopDevice(t)
	reader := attachDiskReader(t)

	f, err := os.OpenFile(loopDev, os.O_RDWR|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t)
	for i := range directIOBlocks {
		_, err := f.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}
	for i := range directIOBlocks {
		_, err := f.ReadAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}

	deviceName := filepath.Base(loopDev)
	completed := map[ebpf.DiskOpCode]uint64{}
	operations := map[ebpf.DiskOpCode]uint64{}
	transferred := map[ebpf.DiskOpCode]uint64{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != deviceName {
			continue
		}
		assert.Empty(t, stat.DiskIO.ErrorType)
		assert.Positive(t, stat.DiskIO.Latency.Sum)
		assert.InDelta(t, stat.DiskIO.Latency.Sum, stat.DiskIO.Time, 0, "the time is the sum of the histogram")
		// without the bounds, the kernel would put every request above the last one
		assert.Zero(t, stat.DiskIO.Latency.BucketCounts[len(export.DiskLatencyBounds)],
			"no request takes longer than the last bound")
		completed[stat.DiskIO.Op] += requests(stat.DiskIO.Latency)
		operations[stat.DiskIO.Op] += stat.DiskIO.Operations
		transferred[stat.DiskIO.Op] += stat.DiskIO.Bytes
	}
	perDirection := func(value uint64) map[ebpf.DiskOpCode]uint64 {
		return map[ebpf.DiskOpCode]uint64{
			ebpf.CodeDiskOpWrite: value,
			ebpf.CodeDiskOpRead:  value,
		}
	}
	assert.Equal(t, perDirection(directIOBlocks), completed)
	assert.Equal(t, perDirection(directIOBlocks), operations)
	assert.Equal(t, perDirection(directIOBlocks*directIOBlockSize), transferred)
}

// TestDiskRequestsAreTimedFromTheirIssue holds writes of a loop device in the I/O scheduler before
// their issue, and checks that OBI records the issue of each write on its own clock, and that the
// durations leave the wait in the scheduler out, while the kernel's start of a request, which
// /proc/diskstats times from, includes it. The backing file of the loop device is on a frozen
// filesystem, so the writes that the loop driver takes block in it, keeping all its tags, and the
// scheduler holds the other writes until the filesystem is thawed.
func TestDiskRequestsAreTimedFromTheirIssue(t *testing.T) {
	const (
		held = 32
		// a write timed from its start takes longer than it was held, while from its issue it takes
		// the time the loop device needs to serve the writes ahead of it, well within the hold
		hold = time.Second
	)
	devPath, mountPoint := loopDeviceOnExt4(t)
	device := filepath.Base(devPath)
	useScheduler(t, device, "mq-deadline")
	tags, err := strconv.Atoi(readSysFile(t, filepath.Join("/sys/block", device, "mq", "0", "nr_tags")))
	require.NoError(t, err)
	reader := attachDiskReader(t)
	inFlight := openInFlightMap(t, reader)

	thaw := freeze(t, mountPoint)
	before := readKernelDiskStats(t, device)
	submitted := monotonicNow(t)
	written := writeBlocksConcurrently(t, devPath, tags+held)
	waitForWritesInFlight(t, device, tags)
	// the writes past the tags wait in the scheduler, after the kernel started them
	time.Sleep(hold)
	assert.Equal(t, tags, issuesRecordedSince(t, inFlight, devPath, submitted),
		"OBI recorded the issue of each write in flight, on its own clock, and of none of the held ones")
	thaw()
	require.NoError(t, written())
	after := readKernelDiskStatsOnceWritten(t, device, before, tags+held)

	var writes, timedWithinHold uint64
	var sumSeconds float64
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != device || stat.DiskIO.Op != ebpf.CodeDiskOpWrite {
			continue
		}
		writes += requests(stat.DiskIO.Latency)
		timedWithinHold += requestsWithin(stat.DiskIO.Latency, hold.Seconds())
		sumSeconds += stat.DiskIO.Latency.Sum
	}
	require.Equal(t, uint64(tags+held), after.writes-before.writes)
	require.Equal(t, uint64(tags+held), writes)
	// the kernel times each write from its start, so its times include the wait in the scheduler
	leftOut := (after.writeTime - before.writeTime).Seconds() - sumSeconds
	assert.Greater(t, leftOut, 0.9*held*hold.Seconds(), "OBI leaves the wait of the held writes out")
	// the writes in flight wait out the hold, so only the held ones can be timed within it
	assert.Equal(t, uint64(held), timedWithinHold, "the held writes are timed from their issue")
}

// TestDiskRequestsIssuedBeforeTheProbesAreCounted issues writes before the disk probes are attached,
// as when OBI starts while the devices do I/O, and checks that they are counted, timed on the
// kernel's clock from their issue, which OBI didn't record.
func TestDiskRequestsIssuedBeforeTheProbesAreCounted(t *testing.T) {
	const (
		writes = 8
		hold   = time.Second
	)
	devPath, mountPoint := loopDeviceOnExt4(t)
	device := filepath.Base(devPath)
	makeKernelTimeRequests(t, device)

	thaw := freeze(t, mountPoint)
	before := readKernelDiskStats(t, device)
	written := writeBlocksConcurrently(t, devPath, writes)
	waitForWritesInFlight(t, device, writes)
	reader := attachDiskReader(t)
	time.Sleep(hold)
	thaw()
	require.NoError(t, written())
	after := readKernelDiskStatsOnceWritten(t, device, before, writes)

	var counted uint64
	var sumSeconds float64
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != device || stat.DiskIO.Op != ebpf.CodeDiskOpWrite {
			continue
		}
		counted += requests(stat.DiskIO.Latency)
		sumSeconds += stat.DiskIO.Latency.Sum
	}
	require.Equal(t, uint64(writes), after.writes-before.writes)
	assert.Equal(t, uint64(writes), counted)
	assert.GreaterOrEqual(t, sumSeconds, writes*hold.Seconds(),
		"timed from their issue, before the probes were attached")
}

// openInFlightMap opens the map where the disk probes of a reader record the issue of each block
// request: the in-flight map of the program that fills the accumulation map of the reader. The
// tests of other packages may load disk probes at the same time.
func openInFlightMap(t *testing.T, reader *diskReader) *ciliumebpf.Map {
	t.Helper()
	accumInfo, err := reader.accum.(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]).accum.Info()
	require.NoError(t, err)
	accumID, ok := accumInfo.ID()
	require.True(t, ok, "the kernel reports the IDs of the maps")

	for id, err := ciliumebpf.ProgramGetNextID(0); err == nil; id, err = ciliumebpf.ProgramGetNextID(id) {
		program, err := ciliumebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		info, err := program.Info()
		program.Close()
		if err != nil {
			continue
		}
		mapIDs, _ := info.MapIDs()
		if !slices.Contains(mapIDs, accumID) {
			continue
		}
		for _, mapID := range mapIDs {
			m, err := ciliumebpf.NewMapFromID(mapID)
			if err != nil {
				continue
			}
			if info, err := m.Info(); err == nil && info.Name == "disk_rq_start" {
				t.Cleanup(func() { m.Close() })
				return m
			}
			m.Close()
		}
	}
	require.Fail(t, "the disk probes record the issue of each request in disk_rq_start")
	return nil
}

// monotonicNow returns the time of the clock that the probes read, CLOCK_MONOTONIC
func monotonicNow(t *testing.T) uint64 {
	t.Helper()
	var now unix.Timespec
	require.NoError(t, unix.ClockGettime(unix.CLOCK_MONOTONIC, &now))
	return uint64(now.Nano())
}

// issuesRecordedSince returns how many requests of a device have their issue recorded in the
// in-flight map at or after the given time of the probes' clock
func issuesRecordedSince(t *testing.T, inFlight *ciliumebpf.Map, devPath string, sinceNs uint64) int {
	t.Helper()
	var dev unix.Stat_t
	require.NoError(t, unix.Stat(devPath, &dev))
	var (
		key      uint64
		start    ebpf.StatsDiskRqStartT
		recorded int
	)
	entries := inFlight.Iterate()
	for entries.Next(&key, &start) {
		if start.Major == unix.Major(dev.Rdev) && start.Minor == unix.Minor(dev.Rdev) && start.IssuedNs >= sinceNs {
			recorded++
		}
	}
	require.NoError(t, entries.Err())
	return recorded
}

// loopDeviceOnExt4 attaches a loop device to a file of an ext4 filesystem, itself on a loop device,
// and returns the /dev path of the device and the mount point of the filesystem. It skips the test
// without mkfs.ext4.
func loopDeviceOnExt4(t *testing.T) (devPath, mountPoint string) {
	t.Helper()
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("needs mkfs.ext4")
	}
	fsDev := attachLoopDevice(t)
	out, err := exec.Command("mkfs.ext4", "-q", "-F", "-E", "lazy_itable_init=0,lazy_journal_init=0", fsDev).CombinedOutput()
	require.NoError(t, err, "mkfs.ext4: %s", out)
	mountPoint = t.TempDir()
	require.NoError(t, unix.Mount(fsDev, mountPoint, "ext4", 0, ""))
	t.Cleanup(func() { _ = unix.Unmount(mountPoint, 0) })

	backing, err := os.Create(filepath.Join(mountPoint, "disk.img"))
	require.NoError(t, err)
	t.Cleanup(func() { backing.Close() })
	require.NoError(t, backing.Truncate(loopBackingFileSize/2))
	devPath = attachLoopDeviceTo(t, backing)
	return devPath, mountPoint
}

// from include/uapi/linux/fs.h
const (
	fiFreeze = 0xc0045877 // FIFREEZE, _IOWR('X', 119, int)
	fiThaw   = 0xc0045878 // FITHAW, _IOWR('X', 120, int)
)

// freeze freezes a filesystem until the returned function is called, or the test ends: the writes
// to its files block until then
func freeze(t *testing.T, mountPoint string) (thaw func()) {
	t.Helper()
	dir, err := os.Open(mountPoint)
	require.NoError(t, err)
	require.NoError(t, unix.IoctlSetInt(int(dir.Fd()), fiFreeze, 0))
	var once sync.Once
	thaw = func() {
		once.Do(func() {
			require.NoError(t, unix.IoctlSetInt(int(dir.Fd()), fiThaw, 0))
			dir.Close()
		})
	}
	t.Cleanup(thaw)
	return thaw
}

// useScheduler makes a device use an I/O scheduler during the test. It skips the test if the
// device can't use it.
func useScheduler(t *testing.T, device, scheduler string) {
	t.Helper()
	previous, available := queueSchedulers(t, device)
	if !slices.Contains(available, scheduler) {
		t.Skipf("%s is not available", scheduler)
	}
	writeQueueAttribute(t, device, "scheduler", scheduler)
	t.Cleanup(func() { writeQueueAttribute(t, device, "scheduler", previous) })
}

// writeBlocksConcurrently writes the given number of blocks of a device, a block apart so that the
// scheduler can't merge them, each from its own goroutine. It returns a function that waits for
// the writes and returns their errors.
func writeBlocksConcurrently(t *testing.T, devPath string, blocks int) (wait func() error) {
	t.Helper()
	f, err := os.OpenFile(devPath, os.O_WRONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	done := make(chan error, blocks)
	for i := range blocks {
		block := alignedBuffer(t)
		go func() {
			_, err := f.WriteAt(block, int64(2*i*directIOBlockSize))
			done <- err
		}()
	}
	return func() error {
		var errs []error
		for range blocks {
			errs = append(errs, <-done)
		}
		return errors.Join(errs...)
	}
}

// waitForWritesInFlight waits until the given number of writes of a device are issued and not
// completed
func waitForWritesInFlight(t *testing.T, device string, writes int) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		inflight := strings.Fields(readSysFile(t, filepath.Join("/sys/block", device, "inflight")))
		require.Len(ct, inflight, 2)
		assert.Equal(ct, strconv.Itoa(writes), inflight[1])
	}, 10*time.Second, 10*time.Millisecond)
}

func readSysFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.TrimSpace(string(content))
}

// requestsWithin returns how many requests a latency histogram counts in the buckets whose upper
// bound is at most the given seconds
func requestsWithin(latency *ebpf.LatencyHistogram, seconds float64) uint64 {
	var count uint64
	for bucket, bound := range export.DiskLatencyBounds {
		if bound <= seconds {
			count += latency.BucketCounts[bucket]
		}
	}
	return count
}

// requests returns how many requests a latency histogram counts
func requests(latency *ebpf.LatencyHistogram) uint64 {
	var count uint64
	if latency != nil {
		for _, bucketCount := range latency.BucketCounts {
			count += bucketCount
		}
	}
	return count
}

// slowestBound returns the upper bound of the highest bucket of a latency histogram that counts a
// request, +Inf for the overflow bucket: every request took at most that long
func slowestBound(latency *ebpf.LatencyHistogram) float64 {
	slowest := 0.0
	for bucket, count := range latency.BucketCounts {
		switch {
		case count == 0:
		case bucket < len(export.DiskLatencyBounds):
			slowest = export.DiskLatencyBounds[bucket]
		default:
			slowest = math.Inf(1)
		}
	}
	return slowest
}

// TestAccumLookupAndDelete checks that the kernel returns the last value of the accumulation map
// entries that the reader deletes, or that the reader is told that it can't: hash maps support it
// from Linux 5.14
func TestAccumLookupAndDelete(t *testing.T) {
	accumMap, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type: ciliumebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 1,
	})
	require.NoError(t, err)
	defer accumMap.Close()
	accum := ebpfAccum[uint32, uint64]{accum: accumMap}
	require.NoError(t, accumMap.Put(uint32(1), uint64(42)))

	last, err := accum.lookupAndDelete(1)
	if errors.Is(err, ciliumebpf.ErrNotSupported) {
		var value uint64
		require.NoError(t, accumMap.Lookup(uint32(1), &value), "the entry is not deleted")
		t.Skipf("the kernel can't look up and delete hash map entries: %v", err)
	}
	require.NoError(t, err)
	assert.Equal(t, uint64(42), last)
	_, err = accum.lookupAndDelete(1)
	assert.ErrorIs(t, err, ciliumebpf.ErrKeyNotExist, "the entry is deleted")
}

// TestAccumLookupAndDeleteUnsupported checks that the reader is told when the kernel can't look up
// and delete an entry at once, and that the entry is kept. Array maps never support it, so this
// runs the error path that hash maps take before Linux 5.14 on any kernel.
func TestAccumLookupAndDeleteUnsupported(t *testing.T) {
	accumMap, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type: ciliumebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1,
	})
	require.NoError(t, err)
	defer accumMap.Close()
	accum := ebpfAccum[uint32, uint64]{accum: accumMap}
	require.NoError(t, accumMap.Put(uint32(0), uint64(42)))

	_, err = accum.lookupAndDelete(0)
	require.ErrorIs(t, err, ciliumebpf.ErrNotSupported)
	var value uint64
	require.NoError(t, accumMap.Lookup(uint32(0), &value))
	assert.Equal(t, uint64(42), value, "the entry is kept")
}

// TestDiskFileSyncsAreCountedLikeTheKernel syncs the files of an ext4 filesystem. The kernel
// completes the journal writes that have a cache flush before or after them twice, and completes
// the empty flushes of files that didn't change without issuing them: writes must be counted as in
// /proc/diskstats.
func TestDiskFileSyncsAreCountedLikeTheKernel(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("needs mkfs.ext4")
	}
	loopDev := attachLoopDevice(t)
	device := filepath.Base(loopDev)
	out, err := exec.Command("mkfs.ext4", "-q", "-F", "-E", "lazy_itable_init=0,lazy_journal_init=0", loopDev).CombinedOutput()
	require.NoError(t, err, "mkfs.ext4: %s", out)
	mountPoint := t.TempDir()
	require.NoError(t, unix.Mount(loopDev, mountPoint, "ext4", 0, ""))
	t.Cleanup(func() { _ = unix.Unmount(mountPoint, 0) })
	unchanged := filepath.Join(mountPoint, "unchanged")
	syncFile(t, unchanged, []byte("data"))

	reader := attachDiskReader(t)
	before := readKernelDiskStats(t, device)
	for range fileSyncs {
		syncFile(t, unchanged, nil)
		syncFile(t, filepath.Join(mountPoint, "changed"), []byte("data"))
	}

	var writes, operations, written uint64
	var writeTime float64
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != device || stat.DiskIO.Op != ebpf.CodeDiskOpWrite {
			continue
		}
		writes += requests(stat.DiskIO.Latency)
		operations += stat.DiskIO.Operations
		written += stat.DiskIO.Bytes
		writeTime += stat.DiskIO.Time
	}
	// OBI counts a write before the kernel accounts it in /proc/diskstats
	after := readKernelDiskStatsOnceWritten(t, device, before, int(writes))
	assert.Equal(t, after.writes-before.writes, writes)
	assert.Equal(t, writes, operations)
	assert.Equal(t, (after.sectorsWritten-before.sectorsWritten)*kernelSectorSize, written)
	assert.Less(t, writeTime, float64(writes), "each write took less than a second on average")
}

// TestDiskWriteZeroesAreCountedLikeTheKernel zeroes a range of a loop device, which the loop
// driver serves by punching a hole in its backing file: the request that writes the zeroes must be
// counted as one write of the zeroed range, as in /proc/diskstats.
func TestDiskWriteZeroesAreCountedLikeTheKernel(t *testing.T) {
	loopDev := attachLoopDevice(t)
	device := filepath.Base(loopDev)
	reader := attachDiskReader(t)

	disk, err := os.OpenFile(loopDev, os.O_RDWR, 0)
	require.NoError(t, err)
	defer disk.Close()
	const zeroed = 1 << 20
	before := readKernelDiskStats(t, device)
	// unlike BLKZEROOUT, punching a hole in a block device never falls back to writing zero pages
	err = unix.Fallocate(int(disk.Fd()), unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, 0, zeroed)
	if errors.Is(err, unix.EOPNOTSUPP) {
		t.Skip("the loop device doesn't support write-zeroes on this kernel")
	}
	require.NoError(t, err)
	after := readKernelDiskStatsOnceWritten(t, device, before, 1)

	var writes, written uint64
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != device || stat.DiskIO.Op != ebpf.CodeDiskOpWrite {
			continue
		}
		writes += requests(stat.DiskIO.Latency)
		written += stat.DiskIO.Bytes
	}
	require.Equal(t, uint64(1), after.writes-before.writes, "the kernel completes one write-zeroes request")
	assert.Equal(t, uint64(1), writes)
	assert.Equal(t, (after.sectorsWritten-before.sectorsWritten)*kernelSectorSize, written)
}

// TestDiskStartsOfRequestsWithoutIOStatistics checks that OBI doesn't time the requests of a device
// without I/O statistics from a start left by an earlier use. From Linux 6.13, the kernel records
// the start of a request only when it accounts it, so a request reused after queue/iostats is
// turned off keeps the start of its last accounted use. That age would be the latency of the empty
// flushes of the file syncs, which complete without being issued. Without the RQF_IO_STAT check, it
// fails on those kernels; it passes either way on older ones.
func TestDiskStartsOfRequestsWithoutIOStatistics(t *testing.T) {
	const (
		staleAge = 2 * time.Second
		reads    = 64
	)
	for _, scheduler := range []string{"none", "mq-deadline"} {
		t.Run(scheduler, func(t *testing.T) {
			// a request takes the tag last freed on the CPU that allocates it: keep the I/O on one
			// CPU so that it reuses the tags of the accounted requests. The locked thread exits with
			// the subtest, and its CPU affinity with it.
			runtime.LockOSThread()
			var allowed, oneCPU unix.CPUSet
			require.NoError(t, unix.SchedGetaffinity(0, &allowed))
			cpu := 0
			for !allowed.IsSet(cpu) {
				cpu++
			}
			oneCPU.Set(cpu)
			require.NoError(t, unix.SchedSetaffinity(0, &oneCPU))

			loopDev := attachLoopDevice(t)
			device := filepath.Base(loopDev)
			previousScheduler, available := queueSchedulers(t, device)
			if !slices.Contains(available, scheduler) {
				t.Skipf("%s is not available", scheduler)
			}
			previousIOStats := readQueueAttribute(t, device, "iostats")
			t.Cleanup(func() {
				writeQueueAttribute(t, device, "scheduler", previousScheduler)
				writeQueueAttribute(t, device, "iostats", previousIOStats)
			})
			writeQueueAttribute(t, device, "scheduler", scheduler)
			writeQueueAttribute(t, device, "iostats", "1")
			reader := attachDiskReader(t)

			f, err := os.OpenFile(loopDev, os.O_RDWR|unix.O_DIRECT, 0)
			require.NoError(t, err)
			defer f.Close()
			block := alignedBuffer(t)
			readBlocks := func(count int) {
				t.Helper()
				for i := range count {
					_, err := f.ReadAt(block, int64(i%directIOBlocks*directIOBlockSize))
					require.NoError(t, err)
				}
			}
			syncDevice := func() {
				t.Helper()
				for range fileSyncs {
					require.NoError(t, unix.Fsync(int(f.Fd())))
				}
			}

			nrRequests, err := strconv.Atoi(readQueueAttribute(t, device, "nr_requests"))
			require.NoError(t, err)
			readBlocks(4 * nrRequests)
			syncDevice()

			writeQueueAttribute(t, device, "iostats", "0")
			time.Sleep(staleAge)
			reader.readStats()
			before := readKernelDiskStats(t, device)
			readBlocks(reads)
			syncDevice()
			after := readKernelDiskStats(t, device)
			stale := readDiskTimings(reader, device)
			assert.GreaterOrEqual(t, stale.reads, uint64(reads))
			assert.Equal(t, before.reads, after.reads, "the kernel doesn't account the reads")
			assert.Equal(t, before.writes, after.writes, "the kernel doesn't account the flushes")
			assert.Less(t, stale.slowest, staleAge.Seconds(), "no request is timed from an earlier use")

			writeQueueAttribute(t, device, "iostats", "1")
			readBlocks(reads)
			accounted := readDiskTimings(reader, device)
			assert.GreaterOrEqual(t, accounted.reads, uint64(reads))
			assert.Less(t, accounted.slowest, staleAge.Seconds())
		})
	}
}

type diskTimings struct {
	reads uint64
	// the upper bound of the slowest write: a request timed from an earlier use would make it at
	// least as old as that use
	slowest float64
}

func readDiskTimings(reader *diskReader, device string) diskTimings {
	var timings diskTimings
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != device {
			continue
		}
		switch stat.DiskIO.Op {
		case ebpf.CodeDiskOpRead:
			timings.reads += requests(stat.DiskIO.Latency)
		case ebpf.CodeDiskOpWrite:
			timings.slowest = max(timings.slowest, slowestBound(stat.DiskIO.Latency))
		}
	}
	return timings
}

func readQueueAttribute(t *testing.T, device, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("/sys/block", device, "queue", name))
	require.NoError(t, err)
	return strings.TrimSpace(string(content))
}

// queueSchedulers reads the current I/O scheduler of a device and the ones it can use, which
// sysfs lists with the current one in brackets
func queueSchedulers(t *testing.T, device string) (current string, available []string) {
	t.Helper()
	for scheduler := range strings.FieldsSeq(readQueueAttribute(t, device, "scheduler")) {
		if name, ok := strings.CutPrefix(scheduler, "["); ok {
			scheduler = strings.TrimSuffix(name, "]")
			current = scheduler
		}
		available = append(available, scheduler)
	}
	return current, available
}

// makeKernelTimeRequests makes the kernel time the requests of a device: it times those of the
// queues with QUEUE_FLAG_STATS, which writeback throttling sets, whatever queue/iostats says. It
// skips the test if the kernel has no writeback throttling.
func makeKernelTimeRequests(t *testing.T, device string) {
	t.Helper()
	wbtLatency, err := os.ReadFile(filepath.Join("/sys/block", device, "queue", "wbt_lat_usec"))
	if err != nil {
		t.Skipf("no writeback throttling to make the kernel time the requests: %v", err)
	}
	if strings.TrimSpace(string(wbtLatency)) == "0" {
		writeQueueAttribute(t, device, "wbt_lat_usec", "75000")
	}
}

func writeQueueAttribute(t *testing.T, device, name, value string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join("/sys/block", device, "queue", name), []byte(value), 0o644))
}

// kernelSectorSize is the unit of the sectors of /proc/diskstats, whatever the device
const kernelSectorSize = 512

type kernelDiskStats struct {
	reads, writes, sectorsRead, sectorsWritten uint64
	// writeTime adds up the durations of the writes, from the kernel's start of each
	writeTime time.Duration
}

// readKernelDiskStats reads the completed reads and writes of a device in /proc/diskstats
func readKernelDiskStats(t *testing.T, device string) kernelDiskStats {
	t.Helper()
	const (
		readsField          = 3
		sectorsReadField    = 5
		writesField         = 7
		sectorsWrittenField = 9
		writeTimeField      = 10
	)
	content, err := os.ReadFile("/proc/diskstats")
	require.NoError(t, err)
	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)
		if len(fields) <= writeTimeField || fields[2] != device {
			continue
		}
		field := func(i int) uint64 {
			value, err := strconv.ParseUint(fields[i], 10, 64)
			require.NoError(t, err)
			return value
		}
		return kernelDiskStats{
			reads:          field(readsField),
			writes:         field(writesField),
			sectorsRead:    field(sectorsReadField),
			sectorsWritten: field(sectorsWrittenField),
			writeTime:      time.Duration(field(writeTimeField)) * time.Millisecond,
		}
	}
	require.Failf(t, "device not found", "%s is not in /proc/diskstats", device)
	return kernelDiskStats{}
}

// readKernelDiskStatsOnceWritten reads the stats of a device in /proc/diskstats once they count the
// given number of writes since before, or after a timeout. The kernel ends the bios of a request,
// which returns a write to its caller, before it accounts the request in /proc/diskstats.
func readKernelDiskStatsOnceWritten(t *testing.T, device string, before kernelDiskStats, writes int) kernelDiskStats {
	t.Helper()
	after := readKernelDiskStats(t, device)
	for deadline := time.Now().Add(5 * time.Second); after.writes-before.writes < uint64(writes) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		after = readKernelDiskStats(t, device)
	}
	return after
}

// TestDiskPassthroughCommands sends SCSI commands through SG_IO to a disk while it reads and
// writes, as multipath path checkers and smartd do, and checks that the commands are not counted
// and that every read and write is timed from its own issue
func TestDiskPassthroughCommands(t *testing.T) {
	const (
		staleAge = 2 * time.Second
		workers  = 4
		blocks   = 64
	)
	device := scsiDebugDisk(t)
	makeKernelTimeRequests(t, device)
	node := deviceNode(t, device)
	reader := attachDiskReader(t)

	stopCommands := sendTestUnitReady(node, workers)
	require.NoError(t, writeAndReadConcurrently(t, node, workers, blocks))
	require.NoError(t, stopCommands())
	// a command that takes a request whose start is still recorded from a read or a write would be
	// timed from that start: let the starts age so that such a command stands out
	time.Sleep(staleAge)
	stopCommands = sendTestUnitReady(node, workers)
	time.Sleep(staleAge / 4)
	require.NoError(t, stopCommands())

	operations := map[ebpf.DiskOpCode]uint64{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != device {
			continue
		}
		operations[stat.DiskIO.Op] += requests(stat.DiskIO.Latency)
		assert.Less(t, slowestBound(stat.DiskIO.Latency), staleAge.Seconds(), "no %v is timed from an earlier request", stat.DiskIO.Op)
	}
	// not compared with /proc/diskstats: before Linux 5.18 (including RHEL 8), it counts the commands
	// as reads
	assert.Equal(t, map[ebpf.DiskOpCode]uint64{
		ebpf.CodeDiskOpRead:  workers * blocks,
		ebpf.CodeDiskOpWrite: workers * blocks,
	}, operations)
}

// scsiDebugDisk loads scsi_debug with one disk and returns the name of the disk, once udev, if it
// runs, has probed it. It skips the test if scsi_debug can't be loaded or creates no disk.
func scsiDebugDisk(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat("/sys/module/scsi_debug"); err == nil {
		t.Skip("scsi_debug is already loaded, with parameters that this test doesn't control")
	}
	// the sd driver creates the disk. Where it's a module, only udev would load it.
	_ = exec.Command("modprobe", "sd_mod").Run()
	if out, err := exec.Command("modprobe", "scsi_debug", "dev_size_mb=64").CombinedOutput(); err != nil {
		t.Skipf("scsi_debug can't be loaded: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("modprobe", "-r", "scsi_debug").Run() })
	disk := ""
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if disks, _ := filepath.Glob("/sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*/block/*"); len(disks) == 1 {
			disk = filepath.Base(disks[0])
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if disk == "" {
		t.Skip("scsi_debug created no disk: the sd driver isn't loaded")
	}
	lockDisk(t, disk)
	return disk
}

// lockDisk keeps a new disk from udev: udev reads a new disk to probe it, and again whenever it
// changes unless the disk is locked (https://systemd.io/BLOCK_DEVICE_LOCKING/). It waits for the
// probe and keeps the disk locked so that only the test does I/O.
func lockDisk(t *testing.T, disk string) {
	t.Helper()
	_ = exec.Command("udevadm", "settle", "--timeout=10").Run()
	if node, err := os.Open(filepath.Join("/dev", disk)); err == nil {
		t.Cleanup(func() { node.Close() })
		require.NoError(t, unix.Flock(int(node.Fd()), unix.LOCK_EX))
	}
}

// writeAndReadConcurrently writes then reads the given number of different blocks of a device from
// each of the given number of goroutines, and returns their errors
func writeAndReadConcurrently(t *testing.T, device string, workers, blocks int) error {
	t.Helper()
	done := make(chan error, workers)
	for i := range workers {
		block := alignedBuffer(t)
		// a block apart, so that the scheduler can't merge the requests of two goroutines
		offset := int64(i * (blocks + 1) * directIOBlockSize)
		go func() {
			f, err := os.OpenFile(device, os.O_RDWR|unix.O_DIRECT, 0)
			if err != nil {
				done <- err
				return
			}
			defer f.Close()
			for j := range blocks {
				if _, err := f.WriteAt(block, offset+int64(j*directIOBlockSize)); err != nil {
					done <- err
					return
				}
			}
			for j := range blocks {
				if _, err := f.ReadAt(block, offset+int64(j*directIOBlockSize)); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
	}
	var errs []error
	for range workers {
		errs = append(errs, <-done)
	}
	return errors.Join(errs...)
}

// sendTestUnitReady sends SCSI TEST UNIT READY commands to a device from the given number of
// goroutines until the returned function is called, which returns their errors
func sendTestUnitReady(device string, senders int) (stop func() error) {
	stopped := make(chan struct{})
	done := make(chan error, senders)
	for range senders {
		go func() {
			f, err := os.OpenFile(device, os.O_RDONLY, 0)
			if err != nil {
				done <- err
				return
			}
			defer f.Close()
			for {
				select {
				case <-stopped:
					done <- nil
					return
				default:
				}
				if err := testUnitReady(f); err != nil {
					done <- err
					return
				}
			}
		}()
	}
	return func() error {
		close(stopped)
		var errs []error
		for range senders {
			errs = append(errs, <-done)
		}
		return errors.Join(errs...)
	}
}

// from include/scsi/sg.h
const (
	sgIO          = 0x2285
	sgInterfaceID = 'S'
	sgDxferNone   = -1
	sgTimeoutMs   = 10000
)

// sgIOHeader is struct sg_io_hdr of include/scsi/sg.h, for a command without data or sense buffer
type sgIOHeader struct {
	interfaceID    int32
	dxferDirection int32
	cmdLen         uint8
	_              uint8          // mx_sb_len
	_              uint16         // iovec_count
	_              uint32         // dxfer_len
	_              unsafe.Pointer // dxferp
	cmdp           unsafe.Pointer
	_              unsafe.Pointer // sbp
	timeout        uint32
	_              uint32         // flags
	_              int32          // pack_id
	_              unsafe.Pointer // usr_ptr
	_              [4]uint8       // status, masked_status, msg_status, sb_len_wr
	_              [2]uint16      // host_status, driver_status
	_              int32          // resid
	_              uint32         // duration
	_              uint32         // info
}

// testUnitReady sends a SCSI TEST UNIT READY command to a device through SG_IO, which the kernel
// passes through the block layer to the device without reading or writing it
func testUnitReady(f *os.File) error {
	var command [6]byte // TEST UNIT READY: operation code 0, no parameters
	header := sgIOHeader{
		interfaceID:    sgInterfaceID,
		dxferDirection: sgDxferNone,
		cmdLen:         uint8(len(command)),
		cmdp:           unsafe.Pointer(&command[0]),
		timeout:        sgTimeoutMs,
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), sgIO, uintptr(unsafe.Pointer(&header)))
	if errno != 0 {
		return errno
	}
	return nil
}

// syncFile writes data to a file, if any, and syncs it
func syncFile(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
	require.NoError(t, err)
	defer f.Close()
	if data != nil {
		_, err = f.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, f.Sync())
}

// TestDiskMultipathRequestsAreCountedLikeTheKernel writes to and reads from a dm-multipath volume,
// which is request-based: device mapper completes the bytes of each of its requests when the clone
// of the request completes on the path, and ends the request again afterwards, without bytes. Each
// read and write must be counted once, as in /proc/diskstats, on the volume and on its path.
func TestDiskMultipathRequestsAreCountedLikeTheKernel(t *testing.T) {
	const blocks = 32
	loopDev := attachLoopDevice(t)
	path := filepath.Base(loopDev)
	dmName := multipathVolume(t, loopDev)
	if _, err := os.Stat(filepath.Join("/sys/block", dmName, "mq")); err != nil {
		t.Skipf("the multipath volume %s is not request-based on this kernel", dmName)
	}
	lockDisk(t, dmName)
	// a request that ends twice only looks like two requests when the kernel times them
	makeKernelTimeRequests(t, dmName)
	reader := attachDiskReader(t)

	f, err := os.OpenFile(deviceNode(t, dmName), os.O_RDWR|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t)
	before := readKernelDiskStats(t, dmName)
	pathBefore := readKernelDiskStats(t, path)
	for i := range blocks {
		_, err := f.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}
	for i := range blocks {
		_, err := f.ReadAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}
	// device mapper ends a request after its bytes completed, so the kernel can count the last read
	// after it returned
	after := readKernelDiskStats(t, dmName)
	for deadline := time.Now().Add(5 * time.Second); after.reads-before.reads < blocks && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		after = readKernelDiskStats(t, dmName)
	}
	pathAfter := readKernelDiskStats(t, path)

	counted := map[string]kernelDiskStats{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != dmName && stat.DiskIO.Device != path {
			continue
		}
		device := counted[stat.DiskIO.Device]
		switch stat.DiskIO.Op {
		case ebpf.CodeDiskOpRead:
			device.reads += stat.DiskIO.Operations
			device.sectorsRead += stat.DiskIO.Bytes / kernelSectorSize
		case ebpf.CodeDiskOpWrite:
			device.writes += stat.DiskIO.Operations
			device.sectorsWritten += stat.DiskIO.Bytes / kernelSectorSize
		}
		if stat.DiskIO.Device == dmName {
			assert.Equal(t, requests(stat.DiskIO.Latency), stat.DiskIO.Operations)
		}
		counted[stat.DiskIO.Device] = device
	}
	require.Equal(t, uint64(blocks), after.writes-before.writes, "the kernel completes one request per write")
	assert.Equal(t, kernelDiskStatsDelta(before, after), counted[dmName], "the volume")
	assert.Equal(t, kernelDiskStatsDelta(pathBefore, pathAfter), counted[path], "the path keeps its counters")
}

// kernelDiskStatsDelta returns the reads, writes and sectors that /proc/diskstats counted between
// two reads
func kernelDiskStatsDelta(before, after kernelDiskStats) kernelDiskStats {
	return kernelDiskStats{
		reads:          after.reads - before.reads,
		writes:         after.writes - before.writes,
		sectorsRead:    after.sectorsRead - before.sectorsRead,
		sectorsWritten: after.sectorsWritten - before.sectorsWritten,
	}
}

// attachDiskReader loads the disk probes and returns a reader of their accumulation map that already
// forgot the I/O that happened before
func attachDiskReader(t *testing.T) *diskReader {
	t.Helper()
	return attachDiskReaderOf(t, export.FeatureStatsDisk)
}

// attachDiskReaderOf loads the disk probes of the given features and returns a reader of their
// accumulation map that already forgot the I/O that happened before
func attachDiskReaderOf(t *testing.T, features export.Features) *diskReader {
	t.Helper()
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, attributes.UndefinedGroup, allAttributes, ebpf.ProbeReads{})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	require.NotNil(t, fetcher.DiskIOAccumMap(), "the disk probes must be attached on this kernel")

	reader := newDiskReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: fetcher.DiskIOAccumMap()},
		fetcher.DiskStatusIsBlkStatus(), &blockDevices{sysRoot: "/sys"},
		newCgroupContainers(ebpfCgroupNames{names: fetcher.DiskCgroupNamesMap()}), time.Second)
	reader.readStats()
	return reader
}

// multipathVolume creates a dm-multipath volume with a single path, the device, as multipathd does
// for a SAN LUN, and returns its name. It skips the test if dm-multipath can't be loaded.
func multipathVolume(t *testing.T, device string) string {
	t.Helper()
	if out, err := exec.Command("modprobe", "-a", "dm_multipath", "dm_round_robin").CombinedOutput(); err != nil {
		t.Skipf("dm-multipath can't be loaded: %v: %s", err, out)
	}
	return deviceMapperVolume(t, device, fmt.Sprintf("multipath 0 0 1 1 round-robin 0 1 1 %s 1", device))
}

// deviceMapperVolume creates a device mapper volume over a whole device, with the given target and
// its arguments, and returns its name. It skips the test if dmsetup is not installed.
func deviceMapperVolume(t *testing.T, device, target string) string {
	t.Helper()
	dmsetup, err := exec.LookPath("dmsetup")
	if err != nil {
		t.Skip("dmsetup is not installed")
	}
	// the size of the device, in 512-byte sectors
	sectors, err := os.ReadFile(filepath.Join("/sys/class/block", filepath.Base(device), "size"))
	require.NoError(t, err)

	volume := fmt.Sprintf("obi-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	create := exec.Command(dmsetup, "create", volume, "--table",
		fmt.Sprintf("0 %s %s", strings.TrimSpace(string(sectors)), target))
	// without udev, dmsetup creates the device nodes itself
	create.Env = append(os.Environ(), "DM_DISABLE_UDEV=1")
	out, err := create.CombinedOutput()
	require.NoError(t, err, string(out))
	t.Cleanup(func() { _ = exec.Command(dmsetup, "remove", volume).Run() })
	out, err = exec.Command(dmsetup, "info", "-c", "--noheadings", "-o", "blkdevname", volume).Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

// attachLoopDevice attaches a new loop device to a sparse file and returns its /dev path
func attachLoopDevice(t *testing.T) string {
	t.Helper()
	backing, err := os.Create(filepath.Join(t.TempDir(), "disk.img"))
	require.NoError(t, err)
	t.Cleanup(func() { backing.Close() })
	require.NoError(t, backing.Truncate(loopBackingFileSize))
	path := attachLoopDeviceTo(t, backing)
	return path
}

// attachLoopDeviceTo attaches a new loop device to a file and returns its /dev path
func attachLoopDeviceTo(t *testing.T, backing *os.File) string {
	t.Helper()
	control, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	require.NoError(t, err)
	defer control.Close()
	index, err := unix.IoctlRetInt(int(control.Fd()), unix.LOOP_CTL_GET_FREE)
	require.NoError(t, err)

	path := fmt.Sprintf("/dev/loop%d", index)
	loop, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	// udev reads a block device to probe it whenever it changes, unless the device is locked
	// (https://systemd.io/BLOCK_DEVICE_LOCKING/): keep it locked so that only the test does I/O
	require.NoError(t, unix.Flock(int(loop.Fd()), unix.LOCK_EX))
	require.NoError(t, unix.IoctlSetInt(int(loop.Fd()), unix.LOOP_SET_FD, int(backing.Fd())))
	t.Cleanup(func() {
		_ = unix.IoctlSetInt(int(loop.Fd()), unix.LOOP_CLR_FD, 0)
		loop.Close()
	})
	return path
}

// deviceNode creates a node of a block device in a temporary directory, from its numbers in sysfs,
// as /dev isn't populated automatically in every environment
func deviceNode(t *testing.T, name string) string {
	t.Helper()
	numbers, err := os.ReadFile(filepath.Join("/sys/class/block", name, "dev"))
	require.NoError(t, err)
	var major, minor uint32
	_, err = fmt.Sscanf(string(numbers), "%d:%d", &major, &minor)
	require.NoError(t, err)
	node := filepath.Join(t.TempDir(), name)
	require.NoError(t, unix.Mknod(node, unix.S_IFBLK|0o600, int(unix.Mkdev(major, minor))))
	return node
}

// alignedBuffer returns a page-aligned buffer of a direct I/O block, as O_DIRECT requires
func alignedBuffer(t *testing.T) []byte {
	t.Helper()
	buf, err := unix.Mmap(-1, 0, directIOBlockSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Munmap(buf) })
	return buf
}

// TestDiskIOIsChargedPerCgroup writes to the same loop device from processes in container-like
// cgroups, and checks that each container is charged exactly its own I/O
func TestDiskIOIsChargedPerCgroup(t *testing.T) {
	cgroupRoot := ioCgroupRoot(t)
	// a counter alone must load the disk probes, without the histogram
	reader := attachDiskReaderOf(t, export.FeatureStatsDiskOperations)
	loopDev := attachLoopDevice(t)

	writers := map[string]uint64{
		strings.Repeat("a1", 32): 64,
		strings.Repeat("b2", 32): 32,
	}
	for containerID, blocks := range writers {
		cgroup := filepath.Join(cgroupRoot, "docker-"+containerID+".scope")
		runInCgroup(t, cgroup, "TestDiskIOWriterProcess",
			envWriterDevice+"="+loopDev, envWriterBlocks+"="+strconv.FormatUint(blocks, 10))
	}

	// crun runs the processes of a container in a child cgroup of its scope, on cgroup v2 with the
	// systemd driver
	crunContainerID := strings.Repeat("c3", 32)
	scope := filepath.Join(cgroupRoot, "libpod-"+crunContainerID+".scope")
	require.NoError(t, os.Mkdir(scope, 0o755))
	t.Cleanup(func() { _ = os.Remove(scope) })
	if subtreeControl := filepath.Join(scope, "cgroup.subtree_control"); exists(subtreeControl) {
		require.NoError(t, os.WriteFile(subtreeControl, []byte("+io"), 0o644))
	}
	writers[crunContainerID] = 16
	runInCgroup(t, filepath.Join(scope, "container"), "TestDiskIOWriterProcess",
		envWriterDevice+"="+loopDev, envWriterBlocks+"="+strconv.FormatUint(writers[crunContainerID], 10))

	deviceName := filepath.Base(loopDev)
	charged := map[string]uint64{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device == deviceName && stat.DiskIO.Op == ebpf.CodeDiskOpWrite {
			charged[stat.DiskIO.ContainerID] += stat.DiskIO.Operations
		}
	}
	assert.Equal(t, writers, charged)
}

// TestDiskIOWriterProcess is not a test: TestDiskIOIsChargedPerCgroup runs it as a child process
// that writes blocks to a device once its parent has moved it to a cgroup and tells it to start
func TestDiskIOWriterProcess(t *testing.T) {
	device := os.Getenv(envWriterDevice)
	if device == "" {
		t.Skip("only runs as a child process of TestDiskIOIsChargedPerCgroup")
	}
	blocks, err := strconv.Atoi(os.Getenv(envWriterBlocks))
	require.NoError(t, err)
	_, err = bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)

	f, err := os.OpenFile(device, os.O_WRONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t)
	for i := range blocks {
		_, err := f.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}
}

// TestDiskBufferedWritesAreChargedToTheirCgroup writes a file through the page cache from a process
// in a container-like cgroup. The kernel writes the dirty pages back later, from its own threads,
// but on cgroup v2 it charges that I/O to the cgroup that dirtied the pages: the written bytes of
// the device must be charged to the container, but for the journal and metadata of the filesystem.
func TestDiskBufferedWritesAreChargedToTheirCgroup(t *testing.T) {
	const (
		writtenBlocks  = 256
		chargedAtLeast = 0.9
	)
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("needs mkfs.ext4")
	}
	controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil || !slices.Contains(strings.Fields(string(controllers)), "io") ||
		!slices.Contains(strings.Fields(string(controllers)), "memory") {
		t.Skip("the writeback of a cgroup is charged to it with the cgroup v2 io and memory controllers")
	}
	require.NoError(t, os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+io +memory"), 0o644))

	loopDev := attachLoopDevice(t)
	device := filepath.Base(loopDev)
	out, err := exec.Command("mkfs.ext4", "-q", "-F", "-E", "lazy_itable_init=0,lazy_journal_init=0", loopDev).CombinedOutput()
	require.NoError(t, err, "mkfs.ext4: %s", out)
	mountPoint := t.TempDir()
	require.NoError(t, unix.Mount(loopDev, mountPoint, "ext4", 0, ""))
	t.Cleanup(func() { _ = unix.Unmount(mountPoint, 0) })
	reader := attachDiskReaderOf(t, export.FeatureStatsDiskIO)

	containerID := strings.Repeat("d4", 32)
	runInCgroup(t, filepath.Join("/sys/fs/cgroup", "docker-"+containerID+".scope"), "TestDiskBufferedWriterProcess",
		envWriterFile+"="+filepath.Join(mountPoint, "written"), envWriterBlocks+"="+strconv.Itoa(writtenBlocks))

	charged := map[string]uint64{}
	var written uint64
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != device || stat.DiskIO.Op != ebpf.CodeDiskOpWrite {
			continue
		}
		charged[stat.DiskIO.ContainerID] += stat.DiskIO.Bytes
		written += stat.DiskIO.Bytes
	}
	assert.GreaterOrEqual(t, charged[containerID], uint64(writtenBlocks*directIOBlockSize), "the file is charged to the container")
	assert.GreaterOrEqual(t, float64(charged[containerID]), chargedAtLeast*float64(written), "the rest is the filesystem's own I/O")
	delete(charged, containerID)
	delete(charged, "")
	assert.Empty(t, charged, "no other container is charged")
}

// TestDiskBufferedWriterProcess is not a test: TestDiskBufferedWritesAreChargedToTheirCgroup runs
// it as a child process that writes a file through the page cache, then syncs it, once its parent
// has moved it to a cgroup and tells it to start
func TestDiskBufferedWriterProcess(t *testing.T) {
	path := os.Getenv(envWriterFile)
	if path == "" {
		t.Skip("only runs as a child process of TestDiskBufferedWritesAreChargedToTheirCgroup")
	}
	blocks, err := strconv.Atoi(os.Getenv(envWriterBlocks))
	require.NoError(t, err)
	_, err = bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	block := make([]byte, directIOBlockSize)
	for range blocks {
		_, err := f.Write(block)
		require.NoError(t, err)
	}
	require.NoError(t, f.Sync())
}

// ioCgroupRoot returns the root of the cgroup hierarchy of the io (v2) or blkio (v1) controller,
// where the test can create cgroups
func ioCgroupRoot(t *testing.T) string {
	t.Helper()
	if controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		if !slices.Contains(strings.Fields(string(controllers)), "io") {
			t.Skip("the cgroup v2 io controller is not available")
		}
		require.NoError(t, os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+io"), 0o644))
		return "/sys/fs/cgroup"
	}
	if _, err := os.Stat("/sys/fs/cgroup/blkio/cgroup.procs"); err == nil {
		return "/sys/fs/cgroup/blkio"
	}
	t.Skip("no io or blkio cgroup controller")
	return ""
}

// runInCgroup runs a test of this binary as a child process in a new cgroup, and waits for it. The
// child waits for a line on its standard input, which the parent sends once it moved it to the
// cgroup.
func runInCgroup(t *testing.T, cgroup, testName string, env ...string) {
	t.Helper()
	require.NoError(t, os.Mkdir(cgroup, 0o755))
	t.Cleanup(func() { _ = os.Remove(cgroup) })

	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	start, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	require.NoError(t, os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644))
	_, err = start.Write([]byte("start\n"))
	require.NoError(t, err)
	require.NoError(t, cmd.Wait())
}
