// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
)

const (
	fsAccumWrites     = 50
	fsAccumWriteBytes = 4096
)

// The explicit layout of the default filesystem buckets, in nanoseconds.
var fsAccumBoundsNs = []uint64{
	100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000, 25_000_000,
	50_000_000, 100_000_000, 250_000_000, 500_000_000, 1_000_000_000, 2_500_000_000, 5_000_000_000,
}

// newAggregatingFsAttacher is newTestFsAttacher with kernel aggregation in
// the explicit layout, planning every filesystem on fentry/fexit or on
// kprobes.
func newAggregatingFsAttacher(tb testing.TB, fentry bool) (*fsAttacher, map[string]*ebpf.Map) {
	return newAggregatingFsAttacherWithSync(tb, fentry, false)
}

// newAggregatingFsAttacherWithSync is newAggregatingFsAttacher with the
// sync syscall set (storage_fs_sync, step 14) attached too, for the sync
// benchmarks and privileged tests that need it.
func newAggregatingFsAttacherWithSync(tb testing.TB, fentry, syncEnabled bool) (*fsAttacher, map[string]*ebpf.Map) {
	tb.Helper()
	if os.Geteuid() != 0 {
		tb.Skip("needs root to load eBPF programs and mount filesystems")
	}
	agg := FsAggregation{Enabled: true, BoundsNs: fsAccumBoundsNs}
	cfg := &config.EBPFTracer{}
	sharedMaps := map[string]*ebpf.Map{}
	a, err := newKernelFsAttacher(slog.Default(), cfg, statsConstants(cfg, blockLoadPlan{}, agg), agg,
		sharedMaps, &sync.Mutex{}, syncEnabled)
	require.NoError(tb, err)
	tb.Cleanup(func() {
		close(a.stopped) // run() is never started: the test drives refresh
		assert.NoError(tb, a.Close())
	})
	require.NotNil(tb, a.accum)
	a.plan = func(targets []fsTarget) []fsAttachPlan {
		plans := planFsTargets(targets)
		for i := range plans {
			plans[i].UseFentry = plans[i].UseFentry && fentry
		}
		return plans
	}
	return a, sharedMaps
}

// fsAccumCount is what fs_io_accum counted for one operation of one volume,
// summed over the keys that match.
type fsAccumCount struct {
	ops, bytes uint64
	keys       int
	cgroups    map[uint64]bool
	tgids      map[uint32]bool
}

func readFsAccum(t *testing.T, m *ebpf.Map, dev uint32, op FsOpCode, match func(FsIoFsIoAccumKey) bool) fsAccumCount {
	t.Helper()
	c := fsAccumCount{cgroups: map[uint64]bool{}, tgids: map[uint32]bool{}}
	var (
		key FsIoFsIoAccumKey
		val FsIoFsIoAccumVal
	)
	it := m.Iterate()
	for it.Next(&key, &val) {
		if key.S_dev != dev || FsOpCode(key.Op) != op || key.Err != 0 || !match(key) {
			continue
		}
		c.keys++
		for _, n := range val.Bkt {
			c.ops += uint64(n)
		}
		c.bytes += val.Bytes
		c.cgroups[key.Cgid] = true
		c.tgids[val.SampleTgid] = true
	}
	require.NoError(t, it.Err())
	return c
}

// writeN writes n blocks to a new file in dir, one write(2) each, then
// fsyncs it once.
func writeN(dir string, n int) error {
	f, err := os.Create(filepath.Join(dir, fmt.Sprintf("obi-accum-%d", os.Getpid())))
	if err != nil {
		return err
	}
	defer f.Close()
	block := make([]byte, fsAccumWriteBytes)
	for i := range n {
		if _, err := unix.Pwrite(int(f.Fd()), block, int64(i*fsAccumWriteBytes)); err != nil {
			return err
		}
	}
	return f.Sync()
}

// Every write and the fsync on an ext4 volume are counted exactly once in the
// kernel map, with their bytes, under the calling process's cgroup and PID
// namespace, whichever map holds the start: task storage (fentry/fexit), the
// hash map (fentry/fexit on a kernel without task storage) or the hash map
// (kprobes). No start is left behind.
func TestFsAggregationCountsEveryOperation(t *testing.T) {
	selfNs, err := os.Readlink("/proc/self/ns/pid")
	require.NoError(t, err)
	cgid, cgroupV2 := selfCgroupID()

	for _, tc := range []struct {
		name        string
		fentry      bool
		taskStorage bool
	}{
		{"fentry, task storage", true, true},
		{"fentry, hash map", true, false},
		{"kprobe, hash map", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.taskStorage {
				old := haveTaskStorage
				haveTaskStorage = func() bool { return false }
				t.Cleanup(func() { haveTaskStorage = old })
			}
			a, sharedMaps := newAggregatingFsAttacher(t, tc.fentry)
			vol := newFsVolume(t, "ext4", 1)
			a.refresh()
			require.Contains(t, a.attached, fsPlanKey{Fs: CodeFsExt4})
			if a.hashStarts[fsPlanKey{Fs: CodeFsExt4}] == tc.taskStorage {
				t.Skipf("ext4 attached with its starts in the other map (fentry fell back to kprobes: %v)",
					a.noFentry[fsPlanKey{Fs: CodeFsExt4}])
			}

			require.NoError(t, writeN(vol.mountPoint, fsAccumWrites))

			mine := func(k FsIoFsIoAccumKey) bool {
				return fmt.Sprintf("pid:[%d]", k.PidNs) == selfNs
			}
			writes := readFsAccum(t, a.accum, vol.dev, CodeFsOpWrite, mine)
			assert.Equal(t, uint64(fsAccumWrites), writes.ops)
			assert.Equal(t, uint64(fsAccumWrites*fsAccumWriteBytes), writes.bytes)
			assert.Equal(t, 1, writes.keys, "one process: one key")
			assertSampleTgid(t, os.Getpid(), writes.tgids)
			if cgroupV2 {
				assert.Equal(t, map[uint64]bool{cgid: true}, writes.cgroups)
			}
			syncs := readFsAccum(t, a.accum, vol.dev, CodeFsOpFsync, mine)
			assert.Equal(t, uint64(1), syncs.ops)
			assert.Zero(t, syncs.bytes)

			var (
				id    uint64
				start FsIoFsStartVal
				left  int
			)
			it := sharedMaps[FsIoMapFsStart].Iterate()
			for it.Next(&id, &start) {
				if uint32(id>>32) == uint32(os.Getpid()) {
					left++
				}
			}
			require.NoError(t, it.Err())
			assert.Zero(t, left, "no start left in fs_start")
		})
	}
}

// Writes from a child process in a cgroup of the test's own land on that
// cgroup's key, not on the test's: the key is the writer's cgroup, whatever
// process counted it. The cgroup is created under the test's cgroup, and no
// controller is enabled anywhere.
func TestFsAggregationKeysByCgroup(t *testing.T) {
	self, cgroupV2 := selfCgroupID()
	if !cgroupV2 {
		t.Skip("cgroup v2 only: on v1 every key's cgroup is the root")
	}
	a, _ := newAggregatingFsAttacher(t, true)
	vol := newFsVolume(t, "ext4", 1)
	a.refresh()
	require.Contains(t, a.attached, fsPlanKey{Fs: CodeFsExt4})

	cgroup, cgid := newTestCgroup(t)
	child := runInCgroup(t, cgroup, "TestFsAggregationWriterProcess", "OBI_FS_ACCUM_DIR="+vol.mountPoint)

	inChild := readFsAccum(t, a.accum, vol.dev, CodeFsOpWrite, func(k FsIoFsIoAccumKey) bool { return k.Cgid == cgid })
	assert.Equal(t, uint64(fsAccumWrites), inChild.ops)
	assert.Equal(t, uint64(fsAccumWrites*fsAccumWriteBytes), inChild.bytes)
	assertSampleTgid(t, child, inChild.tgids)

	inSelf := readFsAccum(t, a.accum, vol.dev, CodeFsOpWrite, func(k FsIoFsIoAccumKey) bool { return k.Cgid == self })
	assert.Zero(t, inSelf.ops, "nothing counted under the test's own cgroup")
}

// TestFsAggregationWriterProcess is the child of TestFsAggregationKeysByCgroup:
// it waits until its parent has moved it into the test cgroup, then writes.
func TestFsAggregationWriterProcess(t *testing.T) {
	dir := os.Getenv("OBI_FS_ACCUM_DIR")
	if dir == "" {
		t.Skip("run by TestFsAggregationKeysByCgroup")
	}
	_, err := bufio.NewReader(os.Stdin).ReadByte()
	require.NoError(t, err)
	require.NoError(t, writeN(dir, fsAccumWrites))
}

// initPIDNamespace is the inode of the host's PID namespace
// (PROC_PID_INIT_INO), the same on every kernel.
const initPIDNamespace = "pid:[4026531836]"

// assertSampleTgid checks that one process counted into the keys: pid, when
// the test sees host PIDs, as OBI does with hostPID.
func assertSampleTgid(t *testing.T, pid int, tgids map[uint32]bool) {
	t.Helper()
	if ns, err := os.Readlink("/proc/self/ns/pid"); err == nil && ns == initPIDNamespace {
		assert.Equal(t, map[uint32]bool{uint32(pid): true}, tgids)
		return
	}
	assert.Len(t, tgids, 1, "the programs record host PIDs, which this PID namespace does not show")
}

// selfCgroupID returns the cgroup v2 id of the test process: the inode of its
// cgroup directory.
func selfCgroupID() (uint64, bool) {
	dir, ok := selfCgroupDir()
	if !ok {
		return 0, false
	}
	return dirInode(dir)
}

func selfCgroupDir() (string, bool) {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return "", false
	}
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", false
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join("/sys/fs/cgroup", path), true
		}
	}
	return "", false
}

func dirInode(dir string) (uint64, bool) {
	info, err := os.Stat(dir)
	if err != nil {
		return 0, false
	}
	return info.Sys().(*syscall.Stat_t).Ino, true
}

// newTestCgroup creates a child of the test's own cgroup and returns its
// path and id; it is removed when the test ends.
func newTestCgroup(t *testing.T) (string, uint64) {
	t.Helper()
	parent, ok := selfCgroupDir()
	require.True(t, ok)
	dir := filepath.Join(parent, fmt.Sprintf("obi-fs-accum-%d", os.Getpid()))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Skipf("cannot create a cgroup under the test's own: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	id, ok := dirInode(dir)
	require.True(t, ok)
	return dir, id
}

// runInCgroup re-executes the test binary to run only test name, moves it
// into cgroup before it does anything, lets it run and waits for it. It
// returns the child's PID.
func runInCgroup(t *testing.T, cgroup, name string, env ...string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), env...)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid

	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Skipf("cannot move a process into the test cgroup: %v", err)
	}
	_, err = stdin.Write([]byte{1})
	require.NoError(t, err)
	require.NoError(t, stdin.Close())
	require.NoError(t, cmd.Wait(), "child: %s", out.String())
	require.NotContains(t, out.String(), "SKIP", "the child ran")
	return pid
}

// The cost of the filesystem programs in AGG mode on the write path: a
// buffered 4 KiB pwrite(2) into the page cache of an ext4 volume, without
// programs and with them, for each start map. The difference from "no
// programs" is the kernel cost per operation: both programs, their
// trampolines or kprobes, the start map and the add into fs_io_accum.
// "parallel" runs one writer per CPU, all counting into one key: the worst
// case for the atomics on the shared map's value.
func BenchmarkFsAggregationWrite(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("needs root to load eBPF programs and mount filesystems")
	}
	for _, mode := range []struct {
		name                        string
		attach, fentry, taskStorage bool
	}{
		{"no programs", false, false, false},
		{"fentry, task storage", true, true, true},
		{"fentry, hash map", true, true, false},
		{"kprobe, hash map", true, false, false},
	} {
		b.Run(mode.name, func(b *testing.B) {
			if !mode.taskStorage {
				old := haveTaskStorage
				haveTaskStorage = func() bool { return false }
				b.Cleanup(func() { haveTaskStorage = old })
			}
			var a *fsAttacher
			if mode.attach {
				a, _ = newAggregatingFsAttacher(b, mode.fentry)
			}
			vol := newFsVolume(b, "ext4", 1)
			if a != nil {
				a.refresh()
				require.Contains(b, a.attached, fsPlanKey{Fs: CodeFsExt4})
				if a.hashStarts[fsPlanKey{Fs: CodeFsExt4}] == mode.taskStorage {
					b.Skip("ext4 attached with its starts in the other map")
				}
			}
			block := make([]byte, fsAccumWriteBytes)
			newFile := func(b *testing.B) int {
				f, err := os.CreateTemp(vol.mountPoint, "bench-*")
				require.NoError(b, err)
				b.Cleanup(func() { f.Close() })
				return int(f.Fd())
			}

			b.Run("serial", func(b *testing.B) {
				fd := newFile(b)
				for b.Loop() {
					if _, err := unix.Pwrite(fd, block, 0); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("parallel", func(b *testing.B) {
				fds := make(chan int, runtime.GOMAXPROCS(0))
				for range cap(fds) {
					fds <- newFile(b)
				}
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					fd := <-fds
					for pb.Next() {
						if _, err := unix.Pwrite(fd, block, 0); err != nil {
							b.Error(err)
							return
						}
					}
				})
			})
		})
	}
}
