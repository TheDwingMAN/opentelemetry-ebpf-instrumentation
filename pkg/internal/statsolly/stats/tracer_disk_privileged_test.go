// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
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
)

// allAttributes selects every attribute of every metric
var allAttributes = &attributes.SelectorConfig{
	SelectionCfg: attributes.Selection{"*": attributes.InclusionLists{Include: []string{"*"}}},
}

// TestDiskLatencyIsAccumulatedPerDevice drives a known I/O pattern on a loop device and checks
// that the kernel accumulates exactly one latency sample per completed request, in the bucket of
// the boundaries that userspace gives it. The I/O is O_DIRECT and sequential at queue depth 1, so
// the block layer neither caches nor merges it.
func TestDiskLatencyIsAccumulatedPerDevice(t *testing.T) {
	// no loop device request completes within the first boundary
	bounds := []float64{0.000001, 0.01, 0.1}
	features := export.FeatureStatsDiskOperationDuration
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, allAttributes,
		ebpf.LatencyHistograms{Disk: bounds})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	require.NotNil(t, fetcher.DiskIOAccumMap(), "the disk probes must be attached on this kernel")

	loopDev := attachLoopDevice(t)
	reader := newDiskReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: fetcher.DiskIOAccumMap()}, bounds,
		fetcher.DiskStatusIsBlkStatus(), &deviceNames{sysRoot: "/sys"})
	reader.readStats() // forget the I/O that happened before this test

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
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != deviceName {
			continue
		}
		assert.Empty(t, stat.DiskIO.ErrorType)
		for _, latency := range stat.DiskIO.Latency {
			assert.Positive(t, latency.Seconds)
			completed[stat.DiskIO.Op] += latency.Count
		}
	}
	perDirection := func(value uint64) map[ebpf.DiskOpCode]uint64 {
		return map[ebpf.DiskOpCode]uint64{
			ebpf.CodeDiskOpWrite: value,
			ebpf.CodeDiskOpRead:  value,
		}
	}
	assert.Equal(t, perDirection(directIOBlocks), completed)

	assertKernelBuckets(t, fetcher.DiskIOAccumMap(), loopDev, bounds)
}

// assertKernelBuckets checks that the kernel accumulated the requests of a device in the buckets of
// the given boundaries: each latency lies in its bucket, so the mean of a bucket does too.
func assertKernelBuckets(t *testing.T, accumMap *ciliumebpf.Map, devPath string, bounds []float64) {
	t.Helper()
	var dev unix.Stat_t
	require.NoError(t, unix.Stat(devPath, &dev))
	entries, err := ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: accumMap}.read()
	require.NoError(t, err)

	boundsNs := make([]uint64, len(bounds))
	for i, bound := range bounds {
		boundsNs[i] = uint64(math.Round(bound * float64(time.Second)))
	}
	var accumulated bool
	for key, accum := range entries {
		if key.Major != unix.Major(dev.Rdev) || key.Minor != unix.Minor(dev.Rdev) {
			continue
		}
		accumulated = true
		assert.Zero(t, accum.LatencyCount[0], "no request completes within %v s", bounds[0])
		for bucket, count := range accum.LatencyCount {
			if count == 0 {
				continue
			}
			require.LessOrEqual(t, bucket, len(bounds), "the kernel only has a bucket per boundary and one above them")
			mean := accum.LatencySumNs[bucket] / count
			if bucket > 0 {
				assert.Greater(t, mean, boundsNs[bucket-1], "the mean of bucket %d is above its lower boundary", bucket)
			}
			if bucket < len(bounds) {
				assert.LessOrEqual(t, mean, boundsNs[bucket], "the mean of bucket %d is within its upper boundary", bucket)
			}
		}
	}
	assert.True(t, accumulated, "the kernel accumulated the requests of %s", devPath)
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
	after := readKernelDiskStats(t, device)

	var writes uint64
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != device || stat.DiskIO.Op != ebpf.CodeDiskOpWrite {
			continue
		}
		for _, latency := range stat.DiskIO.Latency {
			writes += latency.Count
		}
	}
	assert.Equal(t, after.writes-before.writes, writes)
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
	after := readKernelDiskStats(t, device)

	var writes uint64
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != device || stat.DiskIO.Op != ebpf.CodeDiskOpWrite {
			continue
		}
		for _, latency := range stat.DiskIO.Latency {
			writes += latency.Count
		}
	}
	require.Equal(t, uint64(1), after.writes-before.writes, "the kernel completes one write-zeroes request")
	assert.Equal(t, uint64(1), writes)
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
			assert.Less(t, stale.longest, staleAge.Seconds(), "no request is timed from an earlier use")

			writeQueueAttribute(t, device, "iostats", "1")
			readBlocks(reads)
			accounted := readDiskTimings(reader, device)
			assert.GreaterOrEqual(t, accounted.reads, uint64(reads))
			assert.Less(t, accounted.longest, staleAge.Seconds())
		})
	}
}

type diskTimings struct {
	reads uint64
	// the longest of the mean write latencies: a request timed from an earlier use would make it at
	// least as old as that use
	longest float64
}

func readDiskTimings(reader *accumReader[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT], device string) diskTimings {
	var timings diskTimings
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != device {
			continue
		}
		switch stat.DiskIO.Op {
		case ebpf.CodeDiskOpRead:
			for _, latency := range stat.DiskIO.Latency {
				timings.reads += latency.Count
			}
		case ebpf.CodeDiskOpWrite:
			for _, latency := range stat.DiskIO.Latency {
				timings.longest = max(timings.longest, latency.Seconds)
			}
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

type kernelDiskStats struct {
	reads, writes uint64
}

// readKernelDiskStats reads the completed reads and writes of a device in /proc/diskstats
func readKernelDiskStats(t *testing.T, device string) kernelDiskStats {
	t.Helper()
	const (
		readsField  = 3
		writesField = 7
	)
	content, err := os.ReadFile("/proc/diskstats")
	require.NoError(t, err)
	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)
		if len(fields) <= writesField || fields[2] != device {
			continue
		}
		field := func(i int) uint64 {
			value, err := strconv.ParseUint(fields[i], 10, 64)
			require.NoError(t, err)
			return value
		}
		return kernelDiskStats{reads: field(readsField), writes: field(writesField)}
	}
	require.Failf(t, "device not found", "%s is not in /proc/diskstats", device)
	return kernelDiskStats{}
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
		for _, latency := range stat.DiskIO.Latency {
			operations[stat.DiskIO.Op] += latency.Count
			assert.Less(t, latency.Seconds, staleAge.Seconds(), "no %v is timed from an earlier request", stat.DiskIO.Op)
		}
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
// read and write must be counted once, as in /proc/diskstats.
func TestDiskMultipathRequestsAreCountedLikeTheKernel(t *testing.T) {
	const blocks = 32
	dmName := multipathVolume(t, attachLoopDevice(t))
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

	var reads, writes uint64
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != dmName {
			continue
		}
		var requests uint64
		for _, latency := range stat.DiskIO.Latency {
			requests += latency.Count
		}
		switch stat.DiskIO.Op {
		case ebpf.CodeDiskOpRead:
			reads += requests
		case ebpf.CodeDiskOpWrite:
			writes += requests
		}
	}
	require.Equal(t, uint64(blocks), after.writes-before.writes, "the kernel completes one request per write")
	assert.Equal(t, after.reads-before.reads, reads)
	assert.Equal(t, after.writes-before.writes, writes)
}

// attachDiskReader loads the disk probes and returns a reader of their accumulation map that already
// forgot the I/O that happened before
func attachDiskReader(t *testing.T) *accumReader[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT] {
	t.Helper()
	features := export.FeatureStatsDisk
	bounds := []float64{0.001, 0.01, 0.1}
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, allAttributes,
		ebpf.LatencyHistograms{Disk: bounds})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	require.NotNil(t, fetcher.DiskIOAccumMap(), "the disk probes must be attached on this kernel")

	reader := newDiskReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: fetcher.DiskIOAccumMap()}, bounds,
		fetcher.DiskStatusIsBlkStatus(), &deviceNames{sysRoot: "/sys"})
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
	path, _ := attachLoopDeviceTo(t, backing)
	return path
}

// attachLoopDeviceTo attaches a new loop device to a file and returns its /dev path and the
// open device
func attachLoopDeviceTo(t *testing.T, backing *os.File) (string, *os.File) {
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
	return path, loop
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
