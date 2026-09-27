// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

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

	// environment of the child processes of TestDiskIOIsChargedPerCgroup
	envWriterDevice = "OBI_TEST_DISK_WRITER_DEVICE"
	envWriterBlocks = "OBI_TEST_DISK_WRITER_BLOCKS"
	// environment of the child process of TestFsSyncIsChargedPerCgroup
	envSyncerFile = "OBI_TEST_FS_SYNCER_FILE"

	fileSyncs   = 20
	failedSyncs = 3
)

// TestDiskLatencyIsAccumulatedPerDevice drives a known I/O pattern on a loop device and checks
// that the kernel accumulates exactly one latency sample per completed request. The I/O is
// O_DIRECT and sequential at queue depth 1, so the block layer neither caches nor merges it.
func TestDiskLatencyIsAccumulatedPerDevice(t *testing.T) {
	bounds := []float64{0.001, 0.01, 0.1}
	features := export.FeatureStatsDiskOperationDuration
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{},
		ebpf.LatencyHistograms{Disk: bounds})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	require.NotNil(t, fetcher.DiskIOAccumMap(), "the disk probes must be attached on this kernel")

	loopDev := attachLoopDevice(t)
	reader := newDiskReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: fetcher.DiskIOAccumMap()}, bounds,
		fetcher.DiskStatusIsBlkStatus(), &deviceNames{sysRoot: "/sys"},
		newCgroupContainers(ebpfCgroupNames{names: fetcher.DiskCgroupNamesMap()}))
	reader.readStats() // forget the I/O that happened before this test

	f, err := os.OpenFile(loopDev, os.O_RDWR|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t, directIOBlockSize)
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
	queued := map[ebpf.DiskOpCode]uint64{}
	operations := map[ebpf.DiskOpCode]uint64{}
	transferred := map[ebpf.DiskOpCode]uint64{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != deviceName || !stat.DiskIO.Op.IsTransfer() {
			continue
		}
		assert.Empty(t, stat.DiskIO.ErrorType)
		assert.Empty(t, stat.DiskIO.Partition, "the I/O targets the whole device")
		for _, latency := range stat.DiskIO.Latency {
			assert.Positive(t, latency.Seconds)
			completed[stat.DiskIO.Op] += latency.Count
		}
		for _, wait := range stat.DiskIO.Queue {
			queued[stat.DiskIO.Op] += wait.Count
		}
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
	// loop devices keep I/O statistics, so the kernel timestamps the allocation of every request
	assert.Equal(t, perDirection(directIOBlocks), queued, "the wait before issue of every request is known")
}

// TestDiskPartitions checks that I/O on a partition is reported with its partition
func TestDiskPartitions(t *testing.T) {
	loopDev, partitionDev := attachPartitionedLoopDevice(t)
	reader := attachDiskReader(t, export.FeatureStatsDiskOperations)

	const partitionWrites = 16
	partition, err := os.OpenFile(partitionDev, os.O_RDWR|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer partition.Close()
	block := alignedBuffer(t, directIOBlockSize)
	for i := range partitionWrites {
		_, err := partition.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}

	written := map[string]uint64{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device == filepath.Base(loopDev) && stat.DiskIO.Op == ebpf.CodeDiskOpWrite {
			written[stat.DiskIO.Partition] += stat.DiskIO.Operations
		}
	}
	assert.Equal(t, map[string]uint64{filepath.Base(partitionDev): partitionWrites}, written)
}

// TestDiskFlushesAndDiscards checks that flushes and discards are reported apart from reads and
// writes
func TestDiskFlushesAndDiscards(t *testing.T) {
	loopDev := attachLoopDevice(t)
	reader := attachDiskReader(t, export.FeatureStatsDisk)

	disk, err := os.OpenFile(loopDev, os.O_RDWR, 0)
	require.NoError(t, err)
	defer disk.Close()
	const discarded = 1 << 20
	// loop devices support discards only on the kernels and backing filesystems that can punch holes
	discardErr := discard(disk, 0, discarded)
	discardSupported := !errors.Is(discardErr, unix.EOPNOTSUPP)
	if discardSupported {
		require.NoError(t, discardErr)
	}
	// the page cache of the device is written back, then its write back cache flushed
	_, err = disk.WriteAt(alignedBuffer(t, directIOBlockSize), discarded)
	require.NoError(t, err)
	require.NoError(t, disk.Sync())

	var flushes, discards, discardedBytes uint64
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device != filepath.Base(loopDev) {
			continue
		}
		switch stat.DiskIO.Op {
		case ebpf.CodeDiskOpFlush:
			flushes += stat.DiskIO.Operations
			assert.Zero(t, stat.DiskIO.Bytes, "flushes transfer no data")
		case ebpf.CodeDiskOpDiscard:
			discards += stat.DiskIO.Operations
			discardedBytes += stat.DiskIO.Bytes
		}
	}
	assert.Positive(t, flushes, "fsync on a device with a write back cache flushes it")
	if !discardSupported {
		t.Log("the loop device doesn't support discards on this kernel")
		return
	}
	assert.Positive(t, discards)
	assert.Equal(t, uint64(discarded), discardedBytes, "the discarded bytes add up to the discarded range")
}

// TestDiskStackedVolumes writes to a device mapper volume, like an LVM one, and checks that its
// I/O is reported on the volume, as stacked, besides the device below it
func TestDiskStackedVolumes(t *testing.T) {
	dmsetup, err := exec.LookPath("dmsetup")
	if err != nil {
		t.Skip("dmsetup is not installed")
	}
	features := export.FeatureStatsDiskOperations | export.FeatureStatsDiskIO | export.FeatureStatsDiskStackedVolumes
	bounds := []float64{0.001}
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{},
		ebpf.LatencyHistograms{Disk: bounds})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	require.NotNil(t, fetcher.DiskBioAccumMap(), "the bio probes must be attached on this kernel")

	loopDev := attachLoopDevice(t)
	volume := fmt.Sprintf("obi-test-%d", os.Getpid())
	create := exec.Command(dmsetup, "create", volume, "--table",
		fmt.Sprintf("0 %d linear %s 0", loopBackingFileSize/512, loopDev))
	// without udev, dmsetup creates the device nodes itself
	create.Env = append(os.Environ(), "DM_DISABLE_UDEV=1")
	out, err := create.CombinedOutput()
	require.NoError(t, err, string(out))
	t.Cleanup(func() { _ = exec.Command(dmsetup, "remove", volume).Run() })
	out, err = exec.Command(dmsetup, "info", "-c", "--noheadings", "-o", "blkdevname", volume).Output()
	require.NoError(t, err)
	dmName := strings.TrimSpace(string(out))

	devices := &deviceNames{sysRoot: "/sys"}
	containers := newCgroupContainers(ebpfCgroupNames{names: fetcher.DiskCgroupNamesMap()})
	newBioDevices("/sys", ebpfDeviceSet{set: fetcher.DiskBioDevicesMap()}).refresh()
	bios := newBioReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: fetcher.DiskBioAccumMap()},
		bounds, devices, containers)
	bios.readStats()

	const volumeWrites = 32
	f, err := os.OpenFile(deviceNode(t, dmName), os.O_RDWR|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t, directIOBlockSize)
	for i := range volumeWrites {
		_, err := f.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}

	var writes, written uint64
	for _, stat := range bios.readStats() {
		require.Equal(t, dmName, stat.DiskIO.Device, "only the stacked volumes are measured from their bios")
		assert.True(t, stat.DiskIO.Stacked)
		if stat.DiskIO.Op == ebpf.CodeDiskOpWrite {
			writes += stat.DiskIO.Operations
			written += stat.DiskIO.Bytes
		}
	}
	assert.Equal(t, uint64(volumeWrites), writes)
	assert.Equal(t, uint64(volumeWrites*directIOBlockSize), written)
}

// attachDiskReader loads the disk probes of the given features and returns a reader of their
// accumulation map that already forgot the I/O that happened before
func attachDiskReader(t *testing.T, features export.Features) *accumReader[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT] {
	t.Helper()
	bounds := []float64{0.001, 0.01, 0.1}
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{},
		ebpf.LatencyHistograms{Disk: bounds})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	require.NotNil(t, fetcher.DiskIOAccumMap(), "the disk probes must be attached on this kernel")

	reader := newDiskReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: fetcher.DiskIOAccumMap()}, bounds,
		fetcher.DiskStatusIsBlkStatus(), &deviceNames{sysRoot: "/sys"},
		newCgroupContainers(ebpfCgroupNames{names: fetcher.DiskCgroupNamesMap()}))
	reader.readStats()
	return reader
}

// TestDiskPendingRequests keeps requests in flight on a null_blk device that completes them
// slowly, and checks that they are counted.
func TestDiskPendingRequests(t *testing.T) {
	bounds := []float64{0.001}
	features := export.FeatureStatsDiskPendingOperations
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{},
		ebpf.LatencyHistograms{Disk: bounds})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })

	const inFlight = 4
	device := slowNullBlockDevice(t, 500*time.Millisecond)
	pending := newPendingReader(ebpfRequests{starts: fetcher.DiskRequestsMap()}, &deviceNames{sysRoot: "/sys"})

	done := make(chan error, inFlight)
	for i := range inFlight {
		go func() {
			f, err := os.OpenFile(device, os.O_RDONLY|unix.O_DIRECT, 0)
			if err != nil {
				done <- err
				return
			}
			defer f.Close()
			_, err = f.ReadAt(alignedBuffer(t, directIOBlockSize), int64(i*directIOBlockSize))
			done <- err
		}()
	}
	requestsOf := func() map[ebpf.DiskOpCode]int64 {
		requests := map[ebpf.DiskOpCode]int64{}
		for _, stat := range pending.readStats() {
			if stat.DiskPending.Device == filepath.Base(device) {
				requests[stat.DiskPending.Op] = stat.DiskPending.Requests
			}
		}
		return requests
	}
	require.Eventually(t, func() bool {
		return requestsOf()[ebpf.CodeDiskOpRead] == inFlight
	}, 400*time.Millisecond, 10*time.Millisecond, "the reads are in flight while the device serves them")
	for range inFlight {
		require.NoError(t, <-done)
	}
	assert.Equal(t, map[ebpf.DiskOpCode]int64{ebpf.CodeDiskOpRead: 0}, requestsOf(),
		"the device is still reported once its requests complete")
}

// TestDiskIOIsChargedPerCgroup writes to the same loop device from two processes in two
// container-like cgroups, and checks that each container is charged exactly its own I/O.
func TestDiskIOIsChargedPerCgroup(t *testing.T) {
	cgroupRoot := ioCgroupRoot(t)
	// a counter alone must load the disk probes, without the histogram
	features := export.FeatureStatsDiskOperations
	bounds := []float64{0.001}
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{},
		ebpf.LatencyHistograms{Disk: bounds})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })

	loopDev := attachLoopDevice(t)
	reader := newDiskReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: fetcher.DiskIOAccumMap()}, bounds,
		fetcher.DiskStatusIsBlkStatus(), &deviceNames{sysRoot: "/sys"},
		newCgroupContainers(ebpfCgroupNames{names: fetcher.DiskCgroupNamesMap()}))
	reader.readStats() // forget the I/O that happened before this test

	writers := map[string]uint64{
		strings.Repeat("a1", 32): 64,
		strings.Repeat("b2", 32): 32,
	}
	for containerID, blocks := range writers {
		cgroup := filepath.Join(cgroupRoot, "docker-"+containerID+".scope")
		runInCgroup(t, cgroup, "TestDiskIOWriterProcess",
			envWriterDevice+"="+loopDev, envWriterBlocks+"="+strconv.FormatUint(blocks, 10))
	}

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
// that writes blocks to a device once its parent has moved it to a cgroup and tells it to start.
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
	block := alignedBuffer(t, directIOBlockSize)
	for i := range blocks {
		_, err := f.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}
}

// TestFsSyncIsChargedPerCgroup syncs a file, and a pipe, which can't be synced, from a process in
// a container-like cgroup, and checks that the container is charged exactly those syncs.
func TestFsSyncIsChargedPerCgroup(t *testing.T) {
	if _, err := os.Stat("/sys/bus/event_source/devices/kprobe/type"); err != nil {
		t.Skip("the kernel doesn't support kprobes")
	}
	cgroupRoot := ioCgroupRoot(t)
	features := export.FeatureStatsFsSyncDuration
	bounds := []float64{0.001}
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{},
		ebpf.LatencyHistograms{FsSyncDuration: bounds})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })

	reader := newFsSyncReader(ebpfAccum[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT]{accum: fetcher.FsSyncAccumMap()},
		bounds, newCgroupContainers(ebpfCgroupNames{names: fetcher.DiskCgroupNamesMap()}))
	reader.readStats() // forget the syncs that happened before this test

	containerID := strings.Repeat("c3", 32)
	runInCgroup(t, filepath.Join(cgroupRoot, "docker-"+containerID+".scope"), "TestFsSyncProcess",
		envSyncerFile+"="+filepath.Join(t.TempDir(), "synced"))

	syncs := map[string]uint64{}
	for _, stat := range reader.readStats() {
		if stat.FsSync.ContainerID != containerID {
			continue
		}
		for _, latency := range stat.FsSync.Latency {
			syncs[stat.FsSync.ErrorType] += latency.Count
		}
	}
	assert.Equal(t, map[string]uint64{"": fileSyncs, "EINVAL": failedSyncs}, syncs)
}

// TestFsSyncProcess is not a test: TestFsSyncIsChargedPerCgroup runs it as a child process that
// syncs a file and a pipe once its parent has moved it to a cgroup and tells it to start.
func TestFsSyncProcess(t *testing.T) {
	path := os.Getenv(envSyncerFile)
	if path == "" {
		t.Skip("only runs as a child process of TestFsSyncIsChargedPerCgroup")
	}
	_, err := bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)

	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	for range fileSyncs {
		_, err := f.WriteString("synced\n")
		require.NoError(t, err)
		require.NoError(t, f.Sync())
	}

	pipeRead, pipeWrite, err := os.Pipe()
	require.NoError(t, err)
	defer pipeRead.Close()
	defer pipeWrite.Close()
	for range failedSyncs {
		require.ErrorIs(t, unix.Fsync(int(pipeWrite.Fd())), unix.EINVAL)
	}
}

// ioCgroupRoot returns the root of the cgroup hierarchy of the io (v2) or blkio (v1)
// controller, where the test can create cgroups
func ioCgroupRoot(t *testing.T) string {
	t.Helper()
	if controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		if !strings.Contains(string(controllers), "io") {
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

// runInCgroup runs the given test of this binary as a child process in a new cgroup, with the
// given environment
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

// attachPartitionedLoopDevice attaches a new loop device to a sparse file with a DOS partition
// table, and returns the /dev paths of the device and of its first partition
func attachPartitionedLoopDevice(t *testing.T) (string, string) {
	t.Helper()
	const (
		sectorSize     = 512
		firstSector    = 2048
		partitionBytes = 32 << 20
	)
	mbr := make([]byte, sectorSize)
	entry := mbr[446:462]
	entry[4] = 0x83 // Linux
	binary.LittleEndian.PutUint32(entry[8:], firstSector)
	binary.LittleEndian.PutUint32(entry[12:], partitionBytes/sectorSize)
	mbr[510], mbr[511] = 0x55, 0xaa

	backing, err := os.Create(filepath.Join(t.TempDir(), "disk.img"))
	require.NoError(t, err)
	t.Cleanup(func() { backing.Close() })
	require.NoError(t, backing.Truncate(loopBackingFileSize))
	_, err = backing.WriteAt(mbr, 0)
	require.NoError(t, err)

	path, loop := attachLoopDeviceTo(t, backing)
	require.NoError(t, unix.IoctlLoopSetStatus64(int(loop.Fd()), &unix.LoopInfo64{Flags: unix.LO_FLAGS_PARTSCAN}))
	name := filepath.Base(path) + "p1"
	for start := time.Now(); ; time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join("/sys/class/block", name, "dev")); err == nil {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Skip("the kernel doesn't read the partition table (CONFIG_MSDOS_PARTITION may not be set)")
		}
	}

	return path, deviceNode(t, name)
}

// discard discards a range of a block device with the BLKDISCARD ioctl
func discard(f *os.File, offset, length uint64) error {
	span := [2]uint64{offset, length}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKDISCARD, uintptr(unsafe.Pointer(&span)))
	if errno != 0 {
		return errno
	}
	return nil
}

// slowNullBlockDevice creates a null_blk device that completes each request after the given
// delay, and returns its /dev path. It skips the test if null_blk can't be configured.
func slowNullBlockDevice(t *testing.T, delay time.Duration) string {
	t.Helper()
	_ = exec.Command("modprobe", "null_blk", "nr_devices=0").Run()
	dir := filepath.Join("/sys/kernel/config/nullb", fmt.Sprintf("obi-test-%d", os.Getpid()))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Skipf("null_blk can't be configured through configfs: %v", err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(dir, "power"), []byte("0"), 0o644)
		_ = os.Remove(dir)
	})
	for name, value := range map[string]string{
		"irqmode":         "2", // complete requests from a timer
		"completion_nsec": strconv.FormatInt(delay.Nanoseconds(), 10),
		"hw_queue_depth":  "64",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(value), 0o644), name)
	}
	// null_blk names the device nullb<index> on older kernels, and after the configfs directory on
	// newer ones: take the block device that appears when it's powered on
	before, err := os.ReadDir("/sys/class/block")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "power"), []byte("1"), 0o644))
	after, err := os.ReadDir("/sys/class/block")
	require.NoError(t, err)
	existed := map[string]bool{}
	for _, entry := range before {
		existed[entry.Name()] = true
	}
	for _, entry := range after {
		if !existed[entry.Name()] {
			return deviceNode(t, entry.Name())
		}
	}
	require.FailNow(t, "no block device appeared when powering on the null_blk device")
	return ""
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

// alignedBuffer returns a page-aligned buffer, as O_DIRECT requires
func alignedBuffer(t *testing.T, size int) []byte {
	t.Helper()
	buf, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Munmap(buf) })
	return buf
}
