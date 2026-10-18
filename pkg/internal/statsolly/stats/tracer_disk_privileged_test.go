// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"bufio"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/prometheus/procfs/blockdevice"
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

	// how TestDiskWriterProcess writes: "<O_DIRECT> <path> <blocks>"
	envDiskWriter = "OBI_TEST_DISK_WRITER"
)

// TestDiskLatencyIsAccumulatedPerDevice drives O_DIRECT, sequential I/O at queue depth 1 on a loop
// device, which the block layer neither caches nor merges, and checks that the kernel accumulates
// one sample per request, in the buckets of the bounds that userspace gives it.
func TestDiskLatencyIsAccumulatedPerDevice(t *testing.T) {
	devPath := attachLoopDevice(t, t.TempDir())
	reader := attachDiskReader(t, export.FeatureStatsDiskServiceDuration, false)

	f, err := os.OpenFile(devPath, os.O_RDWR|unix.O_DIRECT, 0)
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

	stats := reader.readStats()
	misses := float64(diskProgramMisses(t))
	for _, op := range []ebpf.DiskOpCode{ebpf.CodeDiskOpWrite, ebpf.CodeDiskOpRead} {
		latency := deviceLatency(stats, filepath.Base(devPath), op)
		assert.InDelta(t, directIOBlocks, latency.Count(), misses, "one sample per request of op %d", op)
		assert.InDelta(t, directIOBlocks*directIOBlockSize, deviceBytes(stats, filepath.Base(devPath), op),
			misses*directIOBlockSize, "the bytes of op %d", op)
		assert.Positive(t, latency.Sum)
		// without the bounds, the kernel would put every request above the last one
		assert.Zero(t, latency.BucketCounts[len(export.DiskLatencyBounds)], "no request takes longer than the last bound")
	}
}

// TestDiskRequestsAreTimedFromTheirIssue holds writes of a loop device in the I/O scheduler before
// their issue, and checks that their durations leave that wait out, while the kernel's start of a
// request, which /proc/diskstats times from, includes it. The backing file of the loop device is on
// a frozen filesystem, so the writes that the loop driver takes block in it, keeping all its tags,
// and the scheduler holds the other writes until the filesystem is thawed.
func TestDiskRequestsAreTimedFromTheirIssue(t *testing.T) {
	const (
		held = 32
		// a write timed from its start takes longer than it was held, while from its issue it takes
		// the time the loop device needs to serve the writes ahead of it, well within the hold
		hold = time.Second
	)
	mountPoint, _ := mountExt4(t)
	devPath := attachLoopDevice(t, mountPoint)
	device := filepath.Base(devPath)
	useScheduler(t, device, "mq-deadline")
	tags, err := strconv.Atoi(readSysFile(t, filepath.Join("/sys/block", device, "mq", "0", "nr_tags")))
	require.NoError(t, err)
	reader := attachDiskReader(t, export.FeatureStatsDiskServiceDuration, false)

	thaw := freeze(t, mountPoint)
	before := readKernelDiskStats(t, device)
	written := writeBlocksConcurrently(t, devPath, tags+held)
	waitForWritesInFlight(t, device, tags)
	time.Sleep(hold)
	thaw()
	require.NoError(t, written())
	after := readKernelDiskStatsOnceWritten(t, device, before, tags+held)

	latency := deviceLatency(reader.readStats(), device, ebpf.CodeDiskOpWrite)
	misses := float64(diskProgramMisses(t))
	require.Equal(t, uint64(tags+held), after.writes-before.writes)
	require.InDelta(t, tags+held, latency.Count(), misses)
	leftOut := (after.writeTime - before.writeTime).Seconds() - latency.Sum
	assert.Greater(t, leftOut, 0.9*held*hold.Seconds(), "OBI leaves the wait of the held writes out")
	// the writes in flight wait out the hold, so only the held ones can be timed within it
	assert.InDelta(t, held, requestsWithin(latency, hold.Seconds()), misses, "the held writes are timed from their issue")
}

// TestDiskFailedRequestsAreNamedAfterTheirErrno writes to a loop device whose backing file is on a
// small tmpfs, so that the loop driver fails the writes that don't fit, and checks that OBI names each
// write after the errno that the writer gets, whether the kernel reports errnos or blk_status_t values.
func TestDiskFailedRequestsAreNamedAfterTheirErrno(t *testing.T) {
	const fitting = 16
	tmpfs := t.TempDir()
	require.NoError(t, unix.Mount("tmpfs", tmpfs, "tmpfs", 0, fmt.Sprintf("size=%d", fitting*directIOBlockSize)))
	t.Cleanup(func() { _ = unix.Unmount(tmpfs, unix.MNT_DETACH) })
	devPath := attachLoopDevice(t, tmpfs)
	reader := attachDiskReader(t, export.FeatureStatsDiskServiceDuration, false)

	f, err := os.OpenFile(devPath, os.O_WRONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t)
	// the writes by the name of the errno that they return, empty for none
	written := map[string]uint64{}
	for i := range 2 * fitting {
		var errno unix.Errno
		if _, err := f.WriteAt(block, int64(i*directIOBlockSize)); err != nil {
			require.ErrorAs(t, err, &errno)
		}
		written[unix.ErrnoName(errno)]++
	}
	require.Less(t, written[""], uint64(2*fitting), "the writes that don't fit fail")

	measured := map[string]uint64{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device == filepath.Base(devPath) && stat.DiskIO.Op == ebpf.CodeDiskOpWrite {
			measured[stat.DiskIO.ErrorType] += stat.DiskIO.Latency.Count()
		}
	}
	misses := float64(diskProgramMisses(t))
	assert.ElementsMatch(t, slices.Collect(maps.Keys(written)), slices.Collect(maps.Keys(measured)))
	for errorType, writes := range written {
		assert.InDelta(t, writes, measured[errorType], misses, "writes with error type %q", errorType)
	}
}

// TestDiskIdleEntriesAreDeleted checks that the reader deletes the kernel's entry of a device that
// stays idle, and that the I/O that creates it again is counted from zero
func TestDiskIdleEntriesAreDeleted(t *testing.T) {
	devPath := attachLoopDevice(t, t.TempDir())
	device := filepath.Base(devPath)
	major, minor := deviceNumbers(t, device)
	reader := attachDiskReader(t, export.FeatureStatsDiskServiceDuration, false)
	reader.idleReadsBeforeDelete = 1
	_, err := reader.accum.lookupAndDelete(ebpf.StatsDiskIoKeyT{})
	t.Logf("the kernel looks up and deletes the entries at once: %t (%v)", errors.Is(err, ciliumebpf.ErrKeyNotExist), err)

	f, err := os.OpenFile(devPath, os.O_WRONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t)
	write := func(blocks int) ebpf.LatencyHistogram {
		for i := range blocks {
			_, err := f.WriteAt(block, int64(i*directIOBlockSize))
			require.NoError(t, err)
		}
		return deviceLatency(reader.readStats(), device, ebpf.CodeDiskOpWrite)
	}

	assert.InDelta(t, directIOBlocks, write(directIOBlocks).Count(), float64(diskProgramMisses(t)))
	reader.readStats()
	entries, err := reader.accum.read()
	require.NoError(t, err)
	for key := range entries {
		assert.False(t, key.Major == major && key.Minor == minor, "the entries of the idle device are deleted")
	}
	assert.InDelta(t, directIOBlocks/4, write(directIOBlocks/4).Count(), float64(diskProgramMisses(t)))
}

// TestDiskStackedDevicesInSysfs checks what OBI reads in sysfs of a loop device, and of a device
// mapper volume over it
func TestDiskStackedDevicesInSysfs(t *testing.T) {
	loopPath := attachLoopDevice(t, t.TempDir())
	loop := filepath.Base(loopPath)
	devices := &blockDevices{sysRoot: "/sys"}
	assert.Equal(t, blockDevice{name: loop, stacked: true}, devices.device(deviceNumbers(t, loop)))

	volume, dm := deviceMapperVolume(t, loopPath, "", "linear "+loopPath+" 0")
	assert.Equal(t, blockDevice{name: dm, volumeName: volume, stacked: true}, devices.device(deviceNumbers(t, dm)))
}

// TestDiskMultipathPathsAreMarked writes to a dm-multipath volume over a loop device, its only path,
// as multipathd sets one up over a LUN: the volume and the path report the writes, and the path is
// marked, so that the histogram exporters leave it out
func TestDiskMultipathPathsAreMarked(t *testing.T) {
	if out, err := exec.Command("modprobe", "-a", "dm_multipath", "dm_round_robin").CombinedOutput(); err != nil {
		t.Skipf("needs dm-multipath: %v: %s", err, out)
	}
	loopPath := attachLoopDevice(t, t.TempDir())
	target := "multipath 0 0 1 1 round-robin 0 1 1 " + loopPath + " 1"
	// multipathd takes over a new volume whose UUID is "mpath-" followed by at least one character, and
	// would remove this one, as it blacklists its only path, a loop device: it ignores the bare prefix,
	// which OBI still matches
	volume, dm := deviceMapperVolume(t, loopPath, dmMultipathUUIDPrefix, target)
	if !exists(filepath.Join("/sys/block", dm, "mq")) {
		t.Skipf("the multipath volume %s is not request-based on this kernel", dm)
	}
	reader := attachDiskReader(t, export.FeatureStatsDiskServiceDuration, false)

	f, err := os.OpenFile(deviceNode(t, dm), os.O_WRONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t)
	for i := range directIOBlocks {
		_, err := f.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}

	written := map[string]*ebpf.DiskIO{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Op == ebpf.CodeDiskOpWrite {
			written[stat.DiskIO.Device] = stat.DiskIO
		}
	}
	misses := float64(diskProgramMisses(t))
	require.Contains(t, written, dm)
	assert.Equal(t, volume, written[dm].VolumeName)
	assert.False(t, written[dm].Stacked, "its path doesn't report its histogram")
	assert.False(t, written[dm].MultipathPath)
	assert.InDelta(t, directIOBlocks, written[dm].Latency.Count(), misses)
	path := filepath.Base(loopPath)
	require.Contains(t, written, path)
	assert.True(t, written[path].MultipathPath)
	assert.InDelta(t, directIOBlocks, written[path].Latency.Count(), misses)
}

// TestDiskServiceTimeOfAKnownLatency writes and reads, one request at a time, a null_blk device that
// completes each request a known delay after it receives it: the service time counts that delay for
// each request, and the requests never overlap
func TestDiskServiceTimeOfAKnownLatency(t *testing.T) {
	const (
		delay  = 2 * time.Millisecond
		blocks = 50
	)
	device := slowNullBlockDevice(t, delay)
	reader := attachDiskReader(t, export.FeatureStatsDiskServiceDuration, false)

	f, err := os.OpenFile(device, os.O_RDWR|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t)
	start := time.Now()
	for i := range blocks {
		_, err := f.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
		_, err = f.ReadAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}
	elapsed := time.Since(start)

	var requests uint64
	var serviceTime float64
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device == filepath.Base(device) {
			requests += stat.DiskIO.Latency.Count()
			serviceTime += stat.DiskIO.Latency.Sum
		}
	}
	require.InDelta(t, 2*blocks, requests, float64(diskProgramMisses(t)))
	assert.GreaterOrEqual(t, serviceTime/float64(requests), delay.Seconds(), "the device completes each request after the delay")
	assert.LessOrEqual(t, serviceTime, elapsed.Seconds(), "one request at a time: they never overlap")
}

// TestDiskIOIsChargedPerCgroup writes to a loop device from processes in the cgroups of three
// containers, the third in a child cgroup of its scope, as crun runs them on cgroup v2: each
// container is charged its own writes
func TestDiskIOIsChargedPerCgroup(t *testing.T) {
	root := ioCgroupRoot(t)
	// a counter alone loads the disk probes
	reader := attachDiskReader(t, export.FeatureStatsDiskOperations, true)
	devPath := attachLoopDevice(t, t.TempDir())
	systemd, cgroupfs, crun := strings.Repeat("a1", 32), strings.Repeat("b2", 32), strings.Repeat("c3", 32)
	written := map[string]int{systemd: 64, cgroupfs: 32, crun: 16}
	runInCgroup(t, filepath.Join(root, "docker-"+systemd+".scope"), true, devPath, written[systemd])
	runInCgroup(t, filepath.Join(root, cgroupfs), true, devPath, written[cgroupfs])
	scope := filepath.Join(root, "libpod-"+crun+".scope")
	require.NoError(t, os.Mkdir(scope, 0o755))
	t.Cleanup(func() { _ = os.Remove(scope) })
	if subtreeControl := filepath.Join(scope, "cgroup.subtree_control"); exists(subtreeControl) {
		require.NoError(t, os.WriteFile(subtreeControl, []byte("+io"), 0o644))
	}
	runInCgroup(t, filepath.Join(scope, "container"), true, devPath, written[crun])

	charged := map[string]uint64{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device == filepath.Base(devPath) && stat.DiskIO.Op == ebpf.CodeDiskOpWrite {
			charged[stat.DiskIO.ContainerID] += stat.DiskIO.Latency.Count()
		}
	}
	misses := float64(diskProgramMisses(t))
	require.Len(t, charged, len(written), "%v", charged)
	for containerID, blocks := range written {
		assert.InDelta(t, blocks, charged[containerID], misses, containerID)
	}
}

// TestDiskBufferedWritesAreChargedToTheirCgroup writes a file through the page cache from a process
// in the cgroup of a container. Kernel threads write the pages back, but cgroup v2 charges that I/O
// to the cgroup that dirtied them: only the journal and metadata of the filesystem are charged to
// no container.
func TestDiskBufferedWritesAreChargedToTheirCgroup(t *testing.T) {
	const writtenBlocks = 256
	controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil || !slices.Contains(strings.Fields(string(controllers)), "io") ||
		!slices.Contains(strings.Fields(string(controllers)), "memory") {
		t.Skip("the writeback of a cgroup is charged to it with the cgroup v2 io and memory controllers")
	}
	require.NoError(t, os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+io +memory"), 0o644))
	mountPoint, device := mountExt4(t)
	reader := attachDiskReader(t, export.FeatureStatsDiskIO, true)

	containerID := strings.Repeat("d4", 32)
	runInCgroup(t, filepath.Join("/sys/fs/cgroup", "docker-"+containerID+".scope"), false,
		filepath.Join(mountPoint, "written"), writtenBlocks)

	charged := map[string]uint64{}
	for _, stat := range reader.readStats() {
		if stat.DiskIO.Device == device && stat.DiskIO.Op == ebpf.CodeDiskOpWrite {
			charged[stat.DiskIO.ContainerID] += stat.DiskIO.Bytes
		}
	}
	assert.GreaterOrEqual(t, charged[containerID], uint64(writtenBlocks*directIOBlockSize), "the file is charged to the container")
	assert.GreaterOrEqual(t, float64(charged[containerID]), 0.9*float64(charged[containerID]+charged[""]),
		"the rest is the filesystem's own I/O")
	delete(charged, containerID)
	delete(charged, "")
	assert.Empty(t, charged, "no other container is charged")
}

// TestDiskWriterProcess is not a test: runInCgroup runs it as a child process in a cgroup, where it
// writes blocks to a file, with O_DIRECT or through the page cache, and syncs it
func TestDiskWriterProcess(t *testing.T) {
	var direct bool
	var path string
	var blocks int
	if _, err := fmt.Sscan(os.Getenv(envDiskWriter), &direct, &path, &blocks); err != nil {
		t.Skip("only runs as a child process of runInCgroup")
	}
	// the parent writes a line once it moved the process to the cgroup
	_, err := bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)

	flags, block := os.O_WRONLY|os.O_CREATE, make([]byte, directIOBlockSize)
	if direct {
		flags, block = os.O_WRONLY|unix.O_DIRECT, alignedBuffer(t)
	}
	f, err := os.OpenFile(path, flags, 0o644)
	require.NoError(t, err)
	defer f.Close()
	for i := range blocks {
		_, err := f.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}
	require.NoError(t, f.Sync())
}

// runInCgroup creates a cgroup and runs TestDiskWriterProcess in it, with its arguments
func runInCgroup(t *testing.T, cgroup string, direct bool, path string, blocks int) {
	t.Helper()
	runChildInCgroup(t, cgroup, "TestDiskWriterProcess", fmt.Sprintf("%s=%t %s %d", envDiskWriter, direct, path, blocks))
}

// runChildInCgroup creates a cgroup and runs a test of this binary in it as a child process, with
// an environment variable
func runChildInCgroup(t *testing.T, cgroup, child, env string) {
	t.Helper()
	require.NoError(t, os.Mkdir(cgroup, 0o755))
	t.Cleanup(func() { _ = os.Remove(cgroup) })

	cmd := exec.Command(os.Args[0], "-test.run=^"+child+"$")
	cmd.Env = append(os.Environ(), env)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	start, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	require.NoError(t, os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644))
	_, err = start.Write([]byte("start\n"))
	require.NoError(t, err)
	require.NoError(t, cmd.Wait())
}

// ioCgroupRoot returns the root of the cgroup v2 hierarchy with the io controller enabled for its
// children, or else of the cgroup v1 blkio hierarchy
func ioCgroupRoot(t *testing.T) string {
	t.Helper()
	if controllers, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		if !slices.Contains(strings.Fields(string(controllers)), "io") {
			t.Skip("the cgroup v2 io controller is not available")
		}
		require.NoError(t, os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+io"), 0o644))
		return "/sys/fs/cgroup"
	}
	if !exists("/sys/fs/cgroup/blkio/cgroup.procs") {
		t.Skip("no io or blkio cgroup controller")
	}
	return "/sys/fs/cgroup/blkio"
}

func attachDiskReader(t *testing.T, features export.Features, readsCgroup bool) *diskReader {
	t.Helper()
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{},
		ebpf.CgroupReads{Disk: readsCgroup})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	reader := newDiskReader(ebpfAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]{accum: fetcher.DiskIOAccumMap()},
		&blockDevices{sysRoot: "/sys", procRoot: "/proc"}, defaultDiskReadInterval)
	reader.statusIsBlkStatus = fetcher.DiskStatusIsBlkStatus()
	reader.containers = ebpfCgroupContainers(fetcher.DiskCgroupNamesMap())
	// forget the I/O that happened before
	reader.readStats()
	return reader
}

// diskProgramMisses returns how many runs of the disk programs the kernel skipped as nested on a
// CPU, each of which loses a request
func diskProgramMisses(t *testing.T) uint64 {
	t.Helper()
	return programMisses(t, "obi_stats_raw_tp_block_rq_")
}

// programMisses returns how many runs of the programs whose name starts with prefix the kernel
// skipped as nested on a CPU
func programMisses(t *testing.T, prefix string) uint64 {
	t.Helper()
	var misses uint64
	id, err := ciliumebpf.ProgramGetNextID(0)
	for ; err == nil; id, err = ciliumebpf.ProgramGetNextID(id) {
		program, loadErr := ciliumebpf.NewProgramFromID(id)
		if loadErr != nil {
			continue // unloaded since
		}
		info, infoErr := program.Info()
		stats, statsErr := program.Stats()
		program.Close()
		require.NoError(t, errors.Join(infoErr, statsErr))
		if strings.HasPrefix(info.Name, prefix) {
			misses += stats.RecursionMisses
		}
	}
	require.ErrorIs(t, err, os.ErrNotExist)
	return misses
}

func deviceBytes(stats []*ebpf.Stat, device string, op ebpf.DiskOpCode) uint64 {
	var bytes uint64
	for _, stat := range stats {
		if stat.DiskIO.Device == device && stat.DiskIO.Op == op {
			bytes += stat.DiskIO.Bytes
		}
	}
	return bytes
}

func deviceLatency(stats []*ebpf.Stat, device string, op ebpf.DiskOpCode) ebpf.LatencyHistogram {
	for _, stat := range stats {
		if stat.DiskIO.Device == device && stat.DiskIO.Op == op {
			return stat.DiskIO.Latency
		}
	}
	return ebpf.LatencyHistogram{BucketCounts: make([]uint64, len(export.DiskLatencyBounds)+1)}
}

func requestsWithin(latency ebpf.LatencyHistogram, seconds float64) uint64 {
	var count uint64
	for bucket, bound := range export.DiskLatencyBounds {
		if bound <= seconds {
			count += latency.BucketCounts[bucket]
		}
	}
	return count
}

func attachLoopDevice(t *testing.T, dir string) string {
	t.Helper()
	backing, err := os.Create(filepath.Join(dir, "disk.img"))
	require.NoError(t, err)
	t.Cleanup(func() { backing.Close() })
	require.NoError(t, backing.Truncate(loopBackingFileSize))

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

// deviceMapperVolume creates a device mapper volume over a whole device, with the given UUID (none
// if empty), target and its arguments, and returns its name and its kernel name
func deviceMapperVolume(t *testing.T, devPath, uuid, target string) (volume, name string) {
	t.Helper()
	path, err := exec.LookPath("dmsetup")
	if err != nil {
		t.Skip("needs dmsetup")
	}
	_ = exec.Command("modprobe", "dm_mod").Run()
	if misc, _ := os.ReadFile("/proc/misc"); !strings.Contains(string(misc), "device-mapper") {
		t.Skip("needs device mapper")
	}
	dmsetup := func(args ...string) *exec.Cmd {
		cmd := exec.Command(path, args...)
		// without udev, dmsetup creates and removes the device nodes itself
		cmd.Env = append(os.Environ(), "DM_DISABLE_UDEV=1")
		return cmd
	}
	sectors := readSysFile(t, filepath.Join("/sys/class/block", filepath.Base(devPath), "size"))
	volume = fmt.Sprintf("obi-test-%d", time.Now().UnixNano())
	out, err := dmsetup("create", volume, "--uuid", uuid,
		"--table", fmt.Sprintf("0 %s %s", sectors, target)).CombinedOutput()
	require.NoError(t, err, "%s", out)
	t.Cleanup(func() { _ = dmsetup("remove", "--retry", volume).Run() })
	out, err = dmsetup("info", "-c", "--noheadings", "-o", "blkdevname", volume).Output()
	require.NoError(t, err)
	return volume, strings.TrimSpace(string(out))
}

func deviceNumbers(t *testing.T, name string) (major, minor uint32) {
	t.Helper()
	_, err := fmt.Sscanf(readSysFile(t, filepath.Join("/sys/class/block", name, "dev")), "%d:%d", &major, &minor)
	require.NoError(t, err)
	return major, minor
}

// deviceNode creates a node of a block device in a temporary directory, as /dev isn't populated
// without udev
func deviceNode(t *testing.T, name string) string {
	t.Helper()
	major, minor := deviceNumbers(t, name)
	node := filepath.Join(t.TempDir(), name)
	require.NoError(t, unix.Mknod(node, unix.S_IFBLK|0o600, int(unix.Mkdev(major, minor))))
	return node
}

// slowNullBlockDevice creates a null_blk device that completes each request after the given delay,
// and returns the path of its node. It skips the test if null_blk can't be configured.
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
		"irqmode":         "2", // complete the requests from a timer
		"completion_nsec": strconv.FormatInt(delay.Nanoseconds(), 10),
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
	for _, entry := range after {
		if !slices.ContainsFunc(before, func(existing os.DirEntry) bool { return existing.Name() == entry.Name() }) {
			return deviceNode(t, entry.Name())
		}
	}
	require.FailNow(t, "no block device appeared when powering on the null_blk device")
	return ""
}

// mountExt4 mounts a new ext4 filesystem on a loop device, and returns its mount point and its device
func mountExt4(t *testing.T) (mountPoint, device string) {
	t.Helper()
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("needs mkfs.ext4")
	}
	fsDev := attachLoopDevice(t, t.TempDir())
	out, err := exec.Command("mkfs.ext4", "-q", "-F", "-E", "lazy_itable_init=0,lazy_journal_init=0", fsDev).CombinedOutput()
	require.NoError(t, err, "mkfs.ext4: %s", out)
	mountPoint = t.TempDir()
	require.NoError(t, unix.Mount(fsDev, mountPoint, "ext4", 0, ""))
	t.Cleanup(func() { _ = unix.Unmount(mountPoint, 0) })
	return mountPoint, filepath.Base(fsDev)
}

// from include/uapi/linux/fs.h
const (
	fiFreeze = 0xc0045877 // FIFREEZE, _IOWR('X', 119, int)
	fiThaw   = 0xc0045878 // FITHAW, _IOWR('X', 120, int)
)

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

func useScheduler(t *testing.T, device, scheduler string) {
	t.Helper()
	path := filepath.Join("/sys/block", device, "queue", "scheduler")
	// sysfs lists the schedulers with the current one in brackets
	var current string
	var available []string
	for name := range strings.FieldsSeq(readSysFile(t, path)) {
		if trimmed := strings.Trim(name, "[]"); trimmed != name {
			name, current = trimmed, trimmed
		}
		available = append(available, name)
	}
	if !slices.Contains(available, scheduler) {
		t.Skipf("%s is not available", scheduler)
	}
	require.NoError(t, os.WriteFile(path, []byte(scheduler), 0o644))
	t.Cleanup(func() { _ = os.WriteFile(path, []byte(current), 0o644) })
}

func readSysFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.TrimSpace(string(content))
}

func writeBlocksConcurrently(t *testing.T, devPath string, blocks int) (wait func() error) {
	t.Helper()
	f, err := os.OpenFile(devPath, os.O_WRONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	done := make(chan error, blocks)
	for i := range blocks {
		block := alignedBuffer(t)
		go func() {
			// a block apart, so that the scheduler can't merge them
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

func waitForWritesInFlight(t *testing.T, device string, writes int) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		inflight := strings.Fields(readSysFile(t, filepath.Join("/sys/block", device, "inflight")))
		require.Len(ct, inflight, 2)
		assert.Equal(ct, strconv.Itoa(writes), inflight[1])
	}, 10*time.Second, 10*time.Millisecond)
}

type kernelDiskStats struct {
	writes uint64
	// writeTime adds up the durations of the writes, from the kernel's start of each
	writeTime time.Duration
}

func readKernelDiskStats(t *testing.T, device string) kernelDiskStats {
	t.Helper()
	fs, err := blockdevice.NewFS("/proc", "/sys")
	require.NoError(t, err)
	diskstats, err := fs.ProcDiskstats()
	require.NoError(t, err)
	for _, stats := range diskstats {
		if stats.DeviceName == device {
			return kernelDiskStats{writes: stats.WriteIOs, writeTime: time.Duration(stats.WriteTicks) * time.Millisecond}
		}
	}
	require.Failf(t, "device not found", "%s is not in /proc/diskstats", device)
	return kernelDiskStats{}
}

// readKernelDiskStatsOnceWritten reads the stats of a device in /proc/diskstats once they count the
// given number of writes since before, or after a timeout: the kernel accounts a request after it
// returns its write to the caller.
func readKernelDiskStatsOnceWritten(t *testing.T, device string, before kernelDiskStats, writes int) kernelDiskStats {
	t.Helper()
	after := readKernelDiskStats(t, device)
	for deadline := time.Now().Add(5 * time.Second); after.writes-before.writes < uint64(writes) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		after = readKernelDiskStats(t, device)
	}
	return after
}

func alignedBuffer(t *testing.T) []byte {
	t.Helper()
	buf, err := unix.Mmap(-1, 0, directIOBlockSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Munmap(buf) })
	return buf
}
