// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

const (
	// environment of the child processes of the file sync tests
	envSyncerDir   = "OBI_TEST_FS_SYNCER_DIR"
	envSyncerSyncs = "OBI_TEST_FS_SYNCER_SYNCS"

	// the syncs of a pipe, which fail with EINVAL (ESPIPE for sync_file_range(2)), and of an
	// invalid file descriptor, which fail with EBADF: none syncs anything
	notSyncs = 3
	// the O_DSYNC and O_SYNC writes of TestFsSyncTypesProcess
	dsyncWrites = 3
	syncWrites  = 2
)

// attachFsSyncReader loads the file sync probes and returns a reader of their accumulation map that
// already forgot the syncs that happened before. It skips the test where the kernel can't attach
// them.
func attachFsSyncReader(t *testing.T, selection *attributes.SelectorConfig) *fsSyncReader {
	t.Helper()
	reader, _ := attachFsSyncFetcher(t, selection)
	return reader
}

func attachFsSyncFetcher(t *testing.T, selection *attributes.SelectorConfig) (*fsSyncReader, *ebpf.StatsFetcher) {
	t.Helper()
	features := export.FeatureStatsFsSyncDuration
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, attributes.UndefinedGroup, selection, ebpf.ProbeReads{})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	if fetcher.FsSyncAccumMap() == nil {
		t.Skipf("the file sync probes can't be attached on this kernel: %v", fetcher.DisabledStorageFeatures())
	}

	reader := newFsSyncReader(ebpfAccum[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT]{accum: fetcher.FsSyncAccumMap()},
		newCgroupContainers(ebpfCgroupNames{names: fetcher.DiskCgroupNamesMap()}), time.Second)
	reader.readStats()
	return reader, fetcher
}

// syncsOf returns the syncs of a container, by type, that a reader reads: the operations of its
// stats, which must be the count of their histogram
func syncsOf(t *testing.T, reader *fsSyncReader, containerID string) map[string]uint64 {
	t.Helper()
	syncs := map[string]uint64{}
	for _, stat := range reader.readStats() {
		if stat.FsSync.ContainerID != containerID {
			continue
		}
		assert.Equal(t, requests(stat.FsSync.Latency), stat.FsSync.Operations, "the operations are the count of the histogram")
		key := fsSyncTypeOf(stat.FsSync.Type)
		if stat.FsSync.ErrorType != "" {
			key += "/" + stat.FsSync.ErrorType
		}
		syncs[key] += stat.FsSync.Operations
	}
	return syncs
}

func fsSyncTypeOf(code ebpf.FsSyncTypeCode) string {
	return map[ebpf.FsSyncTypeCode]string{
		ebpf.CodeFsSyncFsync: "fsync", ebpf.CodeFsSyncFdatasync: "fdatasync", ebpf.CodeFsSyncSync: "sync",
		ebpf.CodeFsSyncSyncfs: "syncfs", ebpf.CodeFsSyncSyncFileRange: "sync_file_range",
	}[code]
}

// TestFsSyncTypesAreCountedOnce runs every kind of sync from a process in a container-like cgroup,
// on ext4, and checks that the container is charged each sync once, with its type. The calls that
// sync nothing, sync_file_range(2) without waiting and the syncs of a pipe or of an invalid file
// descriptor, are not syncs. The filesystem syncs the O_SYNC and O_DSYNC writes: tmpfs doesn't.
func TestFsSyncTypesAreCountedOnce(t *testing.T) {
	cgroupRoot := ioCgroupRoot(t)
	mountPoint := ext4OnLoopDevice(t)
	reader := attachFsSyncReader(t, allAttributes)

	containerID := strings.Repeat("e5", 32)
	runInCgroup(t, filepath.Join(cgroupRoot, "docker-"+containerID+".scope"), "TestFsSyncTypesProcess",
		envSyncerDir+"="+mountPoint)

	assert.Equal(t, map[string]uint64{
		// fsync(2), and the O_SYNC writes
		"fsync": 1 + syncWrites,
		// fdatasync(2) twice, the O_DSYNC writes and msync(2)
		"fdatasync":       2 + dsyncWrites + 1,
		"sync_file_range": 1,
		"syncfs":          1,
		"sync":            1,
	}, syncsOf(t, reader, containerID))
}

// TestFsSyncTypesProcess is not a test: TestFsSyncTypesAreCountedOnce runs it as a child process
// that syncs in every way once its parent has moved it to a cgroup and tells it to start
func TestFsSyncTypesProcess(t *testing.T) {
	dir := os.Getenv(envSyncerDir)
	if dir == "" {
		t.Skip("only runs as a child process of TestFsSyncTypesAreCountedOnce")
	}
	_, err := bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)

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
	require.NoError(t, unix.SyncFileRange(fd, 0, 0,
		unix.SYNC_FILE_RANGE_WAIT_BEFORE|unix.SYNC_FILE_RANGE_WRITE|unix.SYNC_FILE_RANGE_WAIT_AFTER))
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

	syncNothing(t)
}

// syncNothing syncs a pipe, which fails with EINVAL (ESPIPE for sync_file_range(2)), and an invalid
// file descriptor, which fails with EBADF
func syncNothing(t *testing.T) {
	t.Helper()
	pipeRead, pipeWrite, err := os.Pipe()
	require.NoError(t, err)
	defer pipeRead.Close()
	defer pipeWrite.Close()
	for range notSyncs {
		require.ErrorIs(t, unix.Fsync(int(pipeWrite.Fd())), unix.EINVAL)
		require.ErrorIs(t, unix.Fdatasync(int(pipeWrite.Fd())), unix.EINVAL)
		require.ErrorIs(t, unix.SyncFileRange(int(pipeWrite.Fd()), 0, 0,
			unix.SYNC_FILE_RANGE_WAIT_BEFORE|unix.SYNC_FILE_RANGE_WRITE|unix.SYNC_FILE_RANGE_WAIT_AFTER), unix.ESPIPE)
		require.ErrorIs(t, unix.Fsync(-1), unix.EBADF)
	}
}

// A loop device serves the cache flushes of its filesystem by syncing its backing file from a
// kernel thread: the syncs of an ext4 filesystem over a loop device are counted for the container
// that syncs, and again, without a container, for the loop device
func TestFsSyncOfALoopDeviceIsCountedForTheLoopDeviceToo(t *testing.T) {
	cgroupRoot := ioCgroupRoot(t)
	mountPoint := ext4OnLoopDevice(t)
	reader := attachFsSyncReader(t, allAttributes)

	containerID := strings.Repeat("b8", 32)
	runInCgroup(t, filepath.Join(cgroupRoot, "docker-"+containerID+".scope"), "TestFsSyncFilesProcess",
		envSyncerDir+"="+mountPoint, envSyncerSyncs+"=1")

	var containerSyncs, kernelSyncs uint64
	for _, stat := range reader.readStats() {
		if stat.FsSync.Type != ebpf.CodeFsSyncFsync || stat.FsSync.ErrorType != "" {
			continue
		}
		switch stat.FsSync.ContainerID {
		case containerID:
			containerSyncs += stat.FsSync.Operations
		case "":
			kernelSyncs += stat.FsSync.Operations
		}
	}
	assert.Equal(t, uint64(1), containerSyncs)
	// the threads of the host may sync too
	assert.Positive(t, kernelSyncs, "the loop device syncs its backing file")
}

// When no attribute of the metric needs it, the probes don't read the cgroup of the syncs, and
// still measure them
func TestFsSyncWithoutCgroups(t *testing.T) {
	cgroupRoot := ioCgroupRoot(t)
	reader := attachFsSyncReader(t, &attributes.SelectorConfig{})

	runInCgroup(t, filepath.Join(cgroupRoot, "docker-"+strings.Repeat("f6", 32)+".scope"), "TestFsSyncFilesProcess",
		envSyncerDir+"="+t.TempDir(), envSyncerSyncs+"="+strconv.Itoa(fileSyncs))

	var fsyncs uint64
	for _, stat := range reader.readStats() {
		assert.Empty(t, stat.FsSync.ContainerID, "the probes don't read the cgroup")
		if stat.FsSync.Type == ebpf.CodeFsSyncFsync && stat.FsSync.ErrorType == "" {
			fsyncs += stat.FsSync.Operations
		}
	}
	assert.GreaterOrEqual(t, fsyncs, uint64(fileSyncs), "other processes may sync files too")
}

// TestFsSyncFilesProcess is not a test: the file sync tests run it as a child process that syncs
// files from its own threads, all at once, and a pipe, once its parent has moved it to a cgroup and
// tells it to start
func TestFsSyncFilesProcess(t *testing.T) {
	dir := os.Getenv(envSyncerDir)
	if dir == "" {
		t.Skip("only runs as a child process of the file sync tests")
	}
	files, err := strconv.Atoi(os.Getenv(envSyncerSyncs))
	require.NoError(t, err)
	_, err = bufio.NewReader(os.Stdin).ReadString('\n')
	require.NoError(t, err)

	require.NoError(t, syncFilesAtOnce(dir, files))
	syncNothing(t)
}

// syncFilesAtOnce writes the given number of files of a directory, then syncs them all at once,
// each from its own thread
func syncFilesAtOnce(dir string, files int) error {
	written := make([]*os.File, files)
	for i := range written {
		f, err := os.Create(filepath.Join(dir, "synced-"+strconv.Itoa(i)))
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.WriteString("synced"); err != nil {
			return err
		}
		written[i] = f
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, files)
	for i, f := range written {
		wg.Go(func() {
			<-start
			errs[i] = f.Sync()
		})
	}
	close(start)
	wg.Wait()
	return errors.Join(errs...)
}

// stalledFilesystem mounts an ext4 filesystem, without a journal, on a null_blk device that
// completes each request after the given delay, and returns its mount point
func stalledFilesystem(t *testing.T, delay time.Duration) string {
	t.Helper()
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("needs mkfs.ext4")
	}
	device := nullBlockDevice(t, delay, map[string]string{"memory_backed": "1", "size": "64"})
	out, err := exec.Command("mkfs.ext4", "-q", "-F", "-O", "^has_journal", "-E", "nodiscard", device).CombinedOutput()
	require.NoError(t, err, "mkfs.ext4: %s", out)
	mountPoint := t.TempDir()
	require.NoError(t, unix.Mount(device, mountPoint, "ext4", 0, ""))
	t.Cleanup(func() { _ = unix.Unmount(mountPoint, 0) })
	return mountPoint
}

// fexitTimesFsync tells whether OBI times fsync(2) with an fexit program on this kernel, as the
// kernel BTF tells: unlike a kretprobe, an fexit program has no limit of calls in progress at once
func fexitTimesFsync(t *testing.T) bool {
	t.Helper()
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return false
	}
	var trampoline *btf.Struct
	var fsync *btf.Func
	return kernel.TypeByName("bpf_tramp_image", &trampoline) == nil &&
		kernel.TypeByName(kprobe.SyscallPrefix()+"sys_fsync", &fsync) == nil
}

// TestFsSyncConcurrentSyncsDuringAStall syncs many files at once, each from its own thread, on a
// device that takes a second to complete each request, as during a storage stall: where fexit
// programs time them, every sync is counted, but those whose probes the kernel skipped
func TestFsSyncConcurrentSyncsDuringAStall(t *testing.T) {
	const concurrentSyncs = 64
	cgroupRoot := ioCgroupRoot(t)
	mountPoint := stalledFilesystem(t, time.Second)
	reader := attachFsSyncReader(t, allAttributes)

	containerID := strings.Repeat("a7", 32)
	start := time.Now()
	runInCgroup(t, filepath.Join(cgroupRoot, "docker-"+containerID+".scope"), "TestFsSyncFilesProcess",
		envSyncerDir+"="+mountPoint, envSyncerSyncs+"="+strconv.Itoa(concurrentSyncs))
	elapsed := time.Since(start)

	syncs := syncsOf(t, reader, containerID)
	t.Logf("%d of %d concurrent fsyncs counted in %s (fexit: %t)", syncs["fsync"], concurrentSyncs, elapsed, fexitTimesFsync(t))
	require.GreaterOrEqual(t, elapsed, time.Second, "the device must stall the syncs")
	if !fexitTimesFsync(t) {
		assert.LessOrEqual(t, syncs["fsync"], uint64(concurrentSyncs))
		assert.Positive(t, syncs["fsync"])
		return
	}

	skipped := tracingRecursionMisses(t, reader)
	if skipped == 0 {
		assert.Equal(t, map[string]uint64{"fsync": concurrentSyncs}, syncs)
		return
	}
	t.Logf("the kernel skipped %d runs of the fentry and fexit programs", skipped)
	counted := syncs["fsync"]
	assert.Equal(t, map[string]uint64{"fsync": counted}, syncs)
	assert.GreaterOrEqual(t, counted, concurrentSyncs-min(skipped, concurrentSyncs))
	assert.LessOrEqual(t, counted, uint64(concurrentSyncs))
}

// tracingRecursionMisses returns the runs of the fentry and fexit programs of a reader's probes
// that the kernel skipped because the program was already running on that CPU. On a kernel that
// preempts kernel code, as x86 Linux 7.0 and later do by default, a task preempted in a program
// makes the other tasks of its CPU skip it until the task resumes. The tests of other packages may load
// file sync probes at the same time.
func tracingRecursionMisses(t *testing.T, reader *fsSyncReader) uint64 {
	t.Helper()
	accumInfo, err := reader.accum.(ebpfAccum[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT]).accum.Info()
	require.NoError(t, err)
	accumID, ok := accumInfo.ID()
	require.True(t, ok, "the kernel reports the IDs of the maps")

	type tracingProgram struct {
		mapIDs []ciliumebpf.MapID
		misses uint64
	}
	var programs []tracingProgram
	for id, err := ciliumebpf.ProgramGetNextID(0); err == nil; id, err = ciliumebpf.ProgramGetNextID(id) {
		program, err := ciliumebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		info, infoErr := program.Info()
		stats, statsErr := program.Stats()
		program.Close()
		if infoErr != nil || statsErr != nil || info.Type != ciliumebpf.Tracing {
			continue
		}
		mapIDs, _ := info.MapIDs()
		programs = append(programs, tracingProgram{mapIDs: mapIDs, misses: stats.RecursionMisses})
	}

	// the fexit programs fill the accumulation map, and share the map of the syncs in progress
	// with the fentry programs
	var probeMaps []ciliumebpf.MapID
	for _, program := range programs {
		if slices.Contains(program.mapIDs, accumID) {
			probeMaps = program.mapIDs
			break
		}
	}
	require.NotEmpty(t, probeMaps, "the fexit programs fill the accumulation map of the reader")
	startID := slices.IndexFunc(probeMaps, func(id ciliumebpf.MapID) bool {
		m, err := ciliumebpf.NewMapFromID(id)
		if err != nil {
			return false
		}
		defer m.Close()
		info, err := m.Info()
		return err == nil && info.Name == "fs_sync_start"
	})
	require.NotEqual(t, -1, startID, "the fexit programs read the syncs in progress from fs_sync_start")

	var misses uint64
	for _, program := range programs {
		if slices.Contains(program.mapIDs, probeMaps[startID]) {
			misses += program.misses
		}
	}
	return misses
}

// kernelErrors are the kernel log lines of a BUG, an oops or a WARNING
var kernelErrors = regexp.MustCompile(`BUG:|Oops|general protection|unable to handle|WARNING:|Call Trace`)

// kernelErrorLines returns the lines of the kernel log that report an error. It reads /dev/kmsg
// with read(2) directly: the Go runtime would wait for more records on its non-blocking descriptor.
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
		if errors.Is(err, unix.EAGAIN) {
			return lines
		}
		if errors.Is(err, unix.EPIPE) {
			// the oldest records were overwritten since the last read
			continue
		}
		require.NoError(t, err)
		if line := string(record[:n]); kernelErrors.MatchString(line) {
			lines = append(lines, line)
		}
	}
}

// TestFsSyncDetachWhileSyncing closes the file sync probes while threads sleep in fsync(2) on a
// stalled device: the threads return, and the kernel reports no error. Before Linux 5.12 (and
// 5.10.28), detaching an fexit program from a function that tasks sleep in made them return into
// freed memory: OBI uses kprobes there.
func TestFsSyncDetachWhileSyncing(t *testing.T) {
	const blockedSyncs = 32
	mountPoint := stalledFilesystem(t, 3*time.Second)
	_, fetcher := attachFsSyncFetcher(t, &attributes.SelectorConfig{})
	errorsBefore := kernelErrorLines(t)

	synced := make(chan error, 1)
	go func() { synced <- syncFilesAtOnce(mountPoint, blockedSyncs) }()
	// the threads write their files, then sleep in fsync until the device completes their writes
	time.Sleep(time.Second)
	require.NoError(t, fetcher.Close())

	select {
	case err := <-synced:
		require.NoError(t, err)
	case <-time.After(time.Minute):
		require.FailNow(t, "the syncs never returned")
	}
	require.NoError(t, syncFilesAtOnce(t.TempDir(), 1), "the kernel still syncs files")
	assert.Equal(t, errorsBefore, kernelErrorLines(t), "the kernel reported an error")
}
