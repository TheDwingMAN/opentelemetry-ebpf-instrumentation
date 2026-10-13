// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

const (
	// how TestFsSyncerProcess syncs: "types <dir>" or "device <path> <syncs>"
	envFsSyncer = "OBI_TEST_FS_SYNCER"

	// the O_DSYNC and O_SYNC writes of the "types" syncer
	dsyncWrites = 3
	syncWrites  = 2
)

// attachFsSyncReader loads the file sync probes and returns a reader of their accumulation map that
// forgot the syncs before. It skips the test where the kernel can't attach them.
func attachFsSyncReader(t *testing.T, readsCgroup bool) (*accumReader[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT], *ebpf.StatsFetcher) {
	t.Helper()
	features := export.FeatureStatsFsSyncDuration
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{},
		ebpf.CgroupReads{FsSync: readsCgroup})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	if fetcher.FsSyncAccumMap() == nil {
		t.Skip("the file sync probes can't be attached on this kernel")
	}
	reader := newFsSyncReader(ebpfAccum[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT]{accum: fetcher.FsSyncAccumMap()},
		ebpfCgroupContainers(fetcher.DiskCgroupNamesMap()), defaultDiskReadInterval)
	reader.readStats()
	return reader, fetcher
}

// syncsOf returns the syncs of a container that a reader reads, by type, and error type if any
func syncsOf(reader *accumReader[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT], containerID string) map[string]uint64 {
	syncType, _ := ebpf.StatStringGetters(attr.FsSyncType)
	syncs := map[string]uint64{}
	for _, stat := range reader.readStats() {
		if stat.FsSync.ContainerID != containerID {
			continue
		}
		key := syncType(stat)
		if stat.FsSync.ErrorType != "" {
			key += "/" + stat.FsSync.ErrorType
		}
		syncs[key] += stat.FsSync.Latency.Count()
	}
	return syncs
}

// TestFsSyncTypesAreCountedOnce syncs in every way from a process in a container's cgroup, on ext4,
// and checks that the container is charged each sync once, with its type. The calls that sync
// nothing are not syncs: sync_file_range(2) without waiting, and the syncs of a pipe (EINVAL, ESPIPE)
// and of an invalid file descriptor (EBADF). ext4 syncs the O_SYNC and O_DSYNC writes: tmpfs doesn't.
func TestFsSyncTypesAreCountedOnce(t *testing.T) {
	cgroupRoot := ioCgroupRoot(t)
	mountPoint, _ := mountExt4(t)
	reader, _ := attachFsSyncReader(t, true)

	containerID := strings.Repeat("e5", 32)
	runSyncerInCgroup(t, filepath.Join(cgroupRoot, "docker-"+containerID+".scope"), "types "+mountPoint)

	assert.Equal(t, map[string]uint64{
		// fsync(2), and the O_SYNC writes
		"fsync": 1 + syncWrites,
		// fdatasync(2) twice, the O_DSYNC writes and msync(2)
		"fdatasync":       2 + dsyncWrites + 1,
		"sync_file_range": 1,
		"syncfs":          1,
		"sync":            1,
	}, syncsOf(reader, containerID))
}

// When no attribute needs it, the probes don't read the cgroup of the syncs, and still measure them
func TestFsSyncWithoutCgroups(t *testing.T) {
	const syncs = 5
	reader, _ := attachFsSyncReader(t, false)
	f, err := os.Create(filepath.Join(t.TempDir(), "synced"))
	require.NoError(t, err)
	defer f.Close()
	for range syncs {
		_, err := f.WriteString("synced")
		require.NoError(t, err)
		require.NoError(t, f.Sync())
	}

	var fsyncs uint64
	for _, stat := range reader.readStats() {
		assert.Empty(t, stat.FsSync.ContainerID, "the probes don't read the cgroup")
		if stat.FsSync.Type == ebpf.CodeFsSyncFsync && stat.FsSync.ErrorType == "" {
			fsyncs += stat.FsSync.Latency.Count()
		}
	}
	assert.GreaterOrEqual(t, fsyncs, uint64(syncs), "other processes may sync files too")
}

// fexitTimesFsync tells whether OBI times fsync(2) with an fexit program on this kernel, which,
// unlike a kretprobe, has no limit of calls in progress at once
func fexitTimesFsync(t *testing.T) bool {
	t.Helper()
	kernel, err := btf.LoadKernelSpec()
	require.NoError(t, err)
	var trampoline *btf.Struct
	var fsync *btf.Func
	return kernel.TypeByName("bpf_tramp_image", &trampoline) == nil &&
		kernel.TypeByName(kprobe.SyscallPrefix()+"sys_fsync", &fsync) == nil
}

// TestFsSyncConcurrentSyncsDuringAStall syncs a device that takes a second to complete each request,
// as during a storage stall, from many threads at once: where fexit programs time them, every sync
// is counted, but those whose program the kernel skipped as nested
func TestFsSyncConcurrentSyncsDuringAStall(t *testing.T) {
	const concurrentSyncs = 64
	cgroupRoot := ioCgroupRoot(t)
	device := slowNullBlockDevice(t, time.Second, nil)
	reader, _ := attachFsSyncReader(t, true)

	containerID := strings.Repeat("a7", 32)
	start := time.Now()
	runSyncerInCgroup(t, filepath.Join(cgroupRoot, "docker-"+containerID+".scope"),
		fmt.Sprintf("device %s %d", device, concurrentSyncs))
	elapsed := time.Since(start)

	syncs := syncsOf(reader, containerID)
	fexit := fexitTimesFsync(t)
	t.Logf("%d of %d concurrent fsyncs counted in %s (fexit: %t)", syncs["fsync"], concurrentSyncs, elapsed, fexit)
	require.GreaterOrEqual(t, elapsed, time.Second, "the device must stall the syncs")
	assert.Equal(t, map[string]uint64{"fsync": syncs["fsync"]}, syncs)
	if !fexit {
		assert.LessOrEqual(t, syncs["fsync"], uint64(concurrentSyncs))
		assert.Positive(t, syncs["fsync"])
		return
	}
	// fentry and fexit
	misses := programMisses(t, "obi_stats_fe")
	assert.InDelta(t, concurrentSyncs, syncs["fsync"], float64(misses), "the kernel skipped %d runs", misses)
	assert.LessOrEqual(t, syncs["fsync"], uint64(concurrentSyncs))
}

// TestFsSyncDetachWhileSyncing closes the file sync probes while threads sleep in fsync(2) on a
// stalled device: the threads return, and the kernel reports no error. Before Linux 5.12 (and
// 5.10.28), detaching an fexit program from a function that tasks sleep in made them return into
// freed memory: OBI uses kprobes there.
func TestFsSyncDetachWhileSyncing(t *testing.T) {
	const blockedSyncs = 32
	device := slowNullBlockDevice(t, 3*time.Second, nil)
	_, fetcher := attachFsSyncReader(t, false)
	errorsBefore := kernelErrorLines(t)

	synced := make(chan error, 1)
	go func() { synced <- syncDeviceAtOnce(device, blockedSyncs) }()
	// the threads write their pages, then sleep in fsync until the device completes the writes
	time.Sleep(time.Second)
	require.NoError(t, fetcher.Close())

	select {
	case err := <-synced:
		require.NoError(t, err)
	case <-time.After(time.Minute):
		require.FailNow(t, "the syncs never returned")
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "synced"))
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, f.Sync(), "the kernel still syncs files")
	assert.Equal(t, errorsBefore, kernelErrorLines(t), "the kernel reported an error")
}

// TestFsSyncerProcess is not a test: runSyncerInCgroup runs it as a child process in a cgroup
func TestFsSyncerProcess(t *testing.T) {
	var mode, path string
	var syncs int
	if n, _ := fmt.Sscan(os.Getenv(envFsSyncer), &mode, &path, &syncs); n < 2 {
		t.Skip("only runs as a child process of runSyncerInCgroup")
	}
	// the parent writes a line once it moved the process to the cgroup
	_, err := bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)
	if mode == "device" {
		require.NoError(t, syncDeviceAtOnce(path, syncs))
		return
	}
	syncInEveryWay(t, path)
}

// runSyncerInCgroup creates a cgroup and runs TestFsSyncerProcess in it
func runSyncerInCgroup(t *testing.T, cgroup, syncer string) {
	t.Helper()
	runChildInCgroup(t, cgroup, "TestFsSyncerProcess", envFsSyncer+"="+syncer)
}

// syncInEveryWay syncs a file of a directory in every way, then syncs a pipe, which fails with
// EINVAL (ESPIPE for sync_file_range(2)), and an invalid file descriptor, which fails with EBADF
func syncInEveryWay(t *testing.T, dir string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, "synced"))
	require.NoError(t, err)
	defer f.Close()
	_, err = f.WriteString("synced")
	require.NoError(t, err)
	fd := int(f.Fd())
	require.NoError(t, unix.Fsync(fd))
	require.NoError(t, unix.Fdatasync(fd))
	require.NoError(t, unix.Fdatasync(fd))
	// a hint that doesn't wait for the writeback is not a sync
	require.NoError(t, unix.SyncFileRange(fd, 0, 0, unix.SYNC_FILE_RANGE_WRITE))
	waitAndWrite := unix.SYNC_FILE_RANGE_WAIT_BEFORE | unix.SYNC_FILE_RANGE_WRITE | unix.SYNC_FILE_RANGE_WAIT_AFTER
	require.NoError(t, unix.SyncFileRange(fd, 0, 0, waitAndWrite))
	require.NoError(t, unix.Syncfs(fd))
	unix.Sync()

	for flag, writes := range map[int]int{unix.O_DSYNC: dsyncWrites, unix.O_SYNC: syncWrites} {
		synced, err := os.OpenFile(filepath.Join(dir, "written-"+strconv.Itoa(flag)), os.O_CREATE|os.O_WRONLY|flag, 0o644)
		require.NoError(t, err)
		for range writes {
			_, err := synced.WriteString("synced")
			require.NoError(t, err)
		}
		require.NoError(t, synced.Close())
	}

	mapped, err := unix.Mmap(fd, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	require.NoError(t, err)
	mapped[0] = 'S'
	require.NoError(t, unix.Msync(mapped, unix.MS_SYNC))
	require.NoError(t, unix.Munmap(mapped))

	pipeRead, pipeWrite, err := os.Pipe()
	require.NoError(t, err)
	defer pipeRead.Close()
	defer pipeWrite.Close()
	require.ErrorIs(t, unix.Fsync(int(pipeWrite.Fd())), unix.EINVAL)
	require.ErrorIs(t, unix.Fdatasync(int(pipeWrite.Fd())), unix.EINVAL)
	require.ErrorIs(t, unix.SyncFileRange(int(pipeWrite.Fd()), 0, 0, waitAndWrite), unix.ESPIPE)
	require.ErrorIs(t, unix.Fsync(-1), unix.EBADF)
}

// syncDeviceAtOnce writes a page of a block device from each of the given number of threads, then
// syncs the device from all of them at once
func syncDeviceAtOnce(device string, syncs int) error {
	f, err := os.OpenFile(device, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	page := make([]byte, os.Getpagesize())
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, syncs)
	for i := range syncs {
		wg.Go(func() {
			if _, errs[i] = f.WriteAt(page, int64(i*len(page))); errs[i] != nil {
				return
			}
			<-start
			errs[i] = f.Sync()
		})
	}
	close(start)
	wg.Wait()
	return errors.Join(errs...)
}

// kernelErrors are the kernel log lines of a BUG, an oops or a WARNING
var kernelErrors = regexp.MustCompile(`BUG:|Oops|general protection|unable to handle|WARNING:|Call Trace`)

// kernelErrorLines returns the lines of the kernel log that report an error. It reads /dev/kmsg
// with read(2): the Go runtime would wait for more records on its non-blocking descriptor.
func kernelErrorLines(t *testing.T) []string {
	t.Helper()
	kmsg, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("can't read the kernel log: %v", err)
	}
	defer unix.Close(kmsg)
	var lines []string
	record := make([]byte, 8192)
	for {
		n, err := unix.Read(kmsg, record)
		switch {
		case errors.Is(err, unix.EAGAIN):
			return lines
		case errors.Is(err, unix.EPIPE):
			// the oldest records were overwritten since the last read
			continue
		}
		require.NoError(t, err)
		if line := string(record[:n]); kernelErrors.MatchString(line) {
			lines = append(lines, line)
		}
	}
}
