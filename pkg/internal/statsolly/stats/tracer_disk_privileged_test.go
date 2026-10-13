// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"errors"
	"fmt"
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
)

// TestDiskLatencyIsAccumulatedPerDevice drives O_DIRECT, sequential I/O at queue depth 1 on a loop
// device, which the block layer neither caches nor merges, and checks that the kernel accumulates
// one sample per request, in the buckets of the bounds that userspace gives it.
func TestDiskLatencyIsAccumulatedPerDevice(t *testing.T) {
	devPath := attachLoopDevice(t, t.TempDir())
	reader := attachDiskReader(t)

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
		assert.InDelta(t, directIOBlocks, requests(latency), misses, "one sample per request of op %d", op)
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
	mountPoint := mountExt4(t)
	devPath := attachLoopDevice(t, mountPoint)
	device := filepath.Base(devPath)
	useScheduler(t, device, "mq-deadline")
	tags, err := strconv.Atoi(readSysFile(t, filepath.Join("/sys/block", device, "mq", "0", "nr_tags")))
	require.NoError(t, err)
	reader := attachDiskReader(t)

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
	require.InDelta(t, tags+held, requests(latency), misses)
	leftOut := (after.writeTime - before.writeTime).Seconds() - latency.Sum
	assert.Greater(t, leftOut, 0.9*held*hold.Seconds(), "OBI leaves the wait of the held writes out")
	// the writes in flight wait out the hold, so only the held ones can be timed within it
	assert.InDelta(t, held, requestsWithin(latency, hold.Seconds()), misses, "the held writes are timed from their issue")
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

// TestDiskMultipathPathsReportNothing writes to a dm-multipath volume over a loop device, its only
// path, as multipathd sets one up over a LUN: the volume reports the writes, and the path, which
// serves the same requests, reports nothing
func TestDiskMultipathPathsReportNothing(t *testing.T) {
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
	reader := attachDiskReader(t)

	f, err := os.OpenFile(deviceNode(t, dm), os.O_WRONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	block := alignedBuffer(t)
	for i := range directIOBlocks {
		_, err := f.WriteAt(block, int64(i*directIOBlockSize))
		require.NoError(t, err)
	}

	var written *ebpf.DiskIO
	for _, stat := range reader.readStats() {
		assert.NotEqual(t, filepath.Base(loopPath), stat.DiskIO.Device, "the path reports nothing")
		if stat.DiskIO.Device == dm && stat.DiskIO.Op == ebpf.CodeDiskOpWrite {
			written = stat.DiskIO
		}
	}
	require.NotNil(t, written)
	assert.Equal(t, volume, written.VolumeName)
	assert.False(t, written.Stacked, "its path reports nothing")
	assert.InDelta(t, directIOBlocks, requests(written.Latency), float64(diskProgramMisses(t)))
}

func attachDiskReader(t *testing.T) *diskReader {
	t.Helper()
	features := export.FeatureStatsDiskServiceDuration
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	reader := NewDiskMapTracer(fetcher.DiskIOAccumMap(), &config.EBPFTracer{}).reader
	// forget the I/O that happened before
	reader.readStats()
	return reader
}

// diskProgramMisses returns how many runs of the disk programs the kernel skipped as nested on a
// CPU, each of which loses a request
func diskProgramMisses(t *testing.T) uint64 {
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
		if strings.HasPrefix(info.Name, "obi_stats_raw_tp_block_rq_") {
			misses += stats.RecursionMisses
		}
	}
	require.ErrorIs(t, err, os.ErrNotExist)
	return misses
}

func deviceLatency(stats []*ebpf.Stat, device string, op ebpf.DiskOpCode) ebpf.LatencyHistogram {
	for _, stat := range stats {
		if stat.DiskIO.Device == device && stat.DiskIO.Op == op {
			return stat.DiskIO.Latency
		}
	}
	return ebpf.LatencyHistogram{BucketCounts: make([]uint64, len(export.DiskLatencyBounds)+1)}
}

func requests(latency ebpf.LatencyHistogram) uint64 {
	var count uint64
	for _, bucketCount := range latency.BucketCounts {
		count += bucketCount
	}
	return count
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

func mountExt4(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("needs mkfs.ext4")
	}
	fsDev := attachLoopDevice(t, t.TempDir())
	out, err := exec.Command("mkfs.ext4", "-q", "-F", "-E", "lazy_itable_init=0,lazy_journal_init=0", fsDev).CombinedOutput()
	require.NoError(t, err, "mkfs.ext4: %s", out)
	mountPoint := t.TempDir()
	require.NoError(t, unix.Mount(fsDev, mountPoint, "ext4", 0, ""))
	t.Cleanup(func() { _ = unix.Unmount(mountPoint, 0) })
	return mountPoint
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
