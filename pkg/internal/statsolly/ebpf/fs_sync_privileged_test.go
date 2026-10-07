// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"os"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// syncEvents counts the fs_io ring buffer events per (superblock, filesystem,
// operation): TestFsSyncTypesAndFilesystems needs the operation split that
// statEvents (fs_privileged_test.go) does not track.
type syncEvents struct {
	mu sync.Mutex
	n  map[uint32]map[FsTypeCode]map[FsOpCode]int
}

func collectSyncEvents(t *testing.T, reader *ringbuf.Reader) *syncEvents {
	t.Helper()
	events := &syncEvents{n: map[uint32]map[FsTypeCode]map[FsOpCode]int{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var record ringbuf.Record
		for {
			if err := reader.ReadInto(&record); err != nil {
				return
			}
			events.add(record.RawSample)
		}
	}()
	t.Cleanup(func() {
		reader.Close()
		<-done
	})
	return events
}

func (e *syncEvents) add(sample []byte) {
	if len(sample) == 0 || StatType(sample[0]) != StatTypeFsIo || len(sample) < int(unsafe.Sizeof(StatsFsIo{})) {
		return
	}
	event := (*StatsFsIo)(unsafe.Pointer(&sample[0]))
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.n[event.SDev] == nil {
		e.n[event.SDev] = map[FsTypeCode]map[FsOpCode]int{}
	}
	if e.n[event.SDev][FsTypeCode(event.Fs)] == nil {
		e.n[event.SDev][FsTypeCode(event.Fs)] = map[FsOpCode]int{}
	}
	e.n[event.SDev][FsTypeCode(event.Fs)][FsOpCode(event.Op)]++
}

func (e *syncEvents) count(dev uint32, fs FsTypeCode, op FsOpCode) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.n[dev][fs][op]
}

func (e *syncEvents) waitFor(t *testing.T, dev uint32, fs FsTypeCode, op FsOpCode, want int) {
	t.Helper()
	assert.Eventually(t, func() bool {
		return e.count(dev, fs, op) >= want
	}, eventTimeout, 50*time.Millisecond,
		"no %s %s event for superblock %#x (got %d, want >= %d)", fsTypeStr(fs), fsOpStr(op), dev, e.count(dev, fs, op), want)
}

// TestFsSyncTypesAndFilesystems is the step 14 shape of v2's test of the
// same name (fs-sync.md step 14): every sync call, once, on a test mount.
// Unlike v2 (tmpfs), the filesystem is an ext4 loop registered in
// fs_dev_filter (our PV filter drops tmpfs, by design, 2.4): overlay/tmpfs
// get their own assertion below instead.
func TestFsSyncTypesAndFilesystems(t *testing.T) {
	t.Run("fentry", func(t *testing.T) { testFsSyncTypesAndFilesystems(t, false) })
	// The kprobe/kretprobe fallback (the arm64 path while fentry there is
	// UNVERIFIED): same events, read through the CO-RE kprobe walk.
	t.Run("kprobe", func(t *testing.T) { testFsSyncTypesAndFilesystems(t, true) })
}

func testFsSyncTypesAndFilesystems(t *testing.T, kprobes bool) {
	if kprobes {
		orig := planFsSyncFn
		planFsSyncFn = func() fsSyncPlan { return orig().demoteToKprobe() }
		t.Cleanup(func() { planFsSyncFn = orig })
	}
	sharedMaps := map[string]*ebpf.Map{}
	a := newTestFsAttacherWithSync(t, sharedMaps, true)
	require.NotNil(t, a.syncCloser, "the sync syscall set attached")
	reader, err := ringbuf.NewReader(sharedMaps[FsIoMapStatsEvents])
	require.NoError(t, err)
	events := collectSyncEvents(t, reader)

	vol := newFsVolume(t, "ext4", 1)
	a.refresh() // populates fs_dev_filter with vol.dev

	f, err := os.CreateTemp(vol.mountPoint, "obi-sync-*")
	require.NoError(t, err)
	defer f.Close()
	fd := int(f.Fd())
	_, err = f.Write(make([]byte, 4096))
	require.NoError(t, err)

	// sync(2): no file, so no fs type and no device (2.4); every thread on
	// the node shares one counter, so this only asserts it fires at least
	// once, not that it is scoped to this volume.
	before := events.count(0, CodeFsUnknown, CodeFsOpSync)
	unix.Sync()
	events.waitFor(t, 0, CodeFsUnknown, CodeFsOpSync, before+1)

	// syncfs(2): classified from the open file's own superblock.
	require.NoError(t, unix.Syncfs(fd))
	events.waitFor(t, vol.dev, CodeFsExt4, CodeFsOpSyncfs, 1)

	// sync_file_range(2), waiting: recorded.
	require.NoError(t, unix.SyncFileRange(fd, 0, 4096,
		unix.SYNC_FILE_RANGE_WAIT_BEFORE|unix.SYNC_FILE_RANGE_WRITE|unix.SYNC_FILE_RANGE_WAIT_AFTER))
	events.waitFor(t, vol.dev, CodeFsExt4, CodeFsOpSyncFileRange, 1)

	// sync_file_range(2), a pure write hint: not recorded (D7). There is no
	// event to wait for, so this gives the kernel one scheduling window to
	// prove the point, then checks the count did not move.
	require.NoError(t, unix.SyncFileRange(fd, 0, 4096, unix.SYNC_FILE_RANGE_WRITE))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, events.count(vol.dev, CodeFsExt4, CodeFsOpSyncFileRange),
		"a pure SYNC_FILE_RANGE_WRITE hint must not be recorded")
}

// TestFsSyncSkipsUntrackedFilesystems: syncfs(2) on tmpfs and overlay, which
// our per-filesystem probes never track either, must emit nothing (not even
// an fs_type_unknown event): fs_type_from_sb resolves tmpfs to fs_type_unknown,
// and fs_probe_entry_generic drops it before a start is even recorded,
// unlike the per-filesystem fs_dev_filter check, which only gates ext4/xfs/
// btrfs (the v2 review's Q4: an untracked filesystem must never build an
// unbounded, unfiltered key).
func TestFsSyncSkipsUntrackedFilesystems(t *testing.T) {
	sharedMaps := map[string]*ebpf.Map{}
	a := newTestFsAttacherWithSync(t, sharedMaps, true)
	require.NotNil(t, a.syncCloser)
	reader, err := ringbuf.NewReader(sharedMaps[FsIoMapStatsEvents])
	require.NoError(t, err)
	events := collectSyncEvents(t, reader)

	dir := t.TempDir()
	require.NoError(t, unix.Mount("tmpfs", dir, "tmpfs", 0, ""))
	t.Cleanup(func() { _ = unix.Unmount(dir, 0) })

	f, err := os.CreateTemp(dir, "obi-tmpfs-*")
	require.NoError(t, err)
	defer f.Close()

	before := events.count(0, CodeFsUnknown, CodeFsOpSyncfs)
	require.NoError(t, unix.Syncfs(int(f.Fd())))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, before, events.count(0, CodeFsUnknown, CodeFsOpSyncfs), "tmpfs syncfs must emit nothing")
}

// BenchmarkFsSyncAggregation is BenchmarkFsAggregationWrite (fs_accum_privileged_test.go)
// for the step 14 syscalls, in AGG mode: syncfs(2) and waiting
// sync_file_range(2) calls on an ext4 loop volume, without the sync
// programs attached and with them (whichever of fentry or kprobe this
// kernel plans, reported in the sub-test name). The difference from "no
// programs" is the kernel cost our syscall-wrapper probes add: the
// trampoline or kprobe/kretprobe pair, current_file(fd), the fs_dev_filter
// lookup and the add into fs_io_accum.
func BenchmarkFsSyncAggregation(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("needs root to load eBPF programs and mount filesystems")
	}
	for _, attach := range []bool{false, true} {
		name := "no programs"
		if attach {
			name = "attached"
		}
		b.Run(name, func(b *testing.B) {
			var a *fsAttacher
			if attach {
				a, _ = newAggregatingFsAttacherWithSync(b, true, true)
				require.NotNil(b, a.syncCloser)
			}
			vol := newFsVolume(b, "ext4", 1)
			if a != nil {
				a.refresh()
			}

			b.Run("syncfs", func(b *testing.B) {
				f, err := os.CreateTemp(vol.mountPoint, "bench-syncfs-*")
				require.NoError(b, err)
				b.Cleanup(func() { f.Close() })
				fd := int(f.Fd())
				for b.Loop() {
					if err := unix.Syncfs(fd); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("sync_file_range", func(b *testing.B) {
				f, err := os.CreateTemp(vol.mountPoint, "bench-sfr-*")
				require.NoError(b, err)
				b.Cleanup(func() { f.Close() })
				fd := int(f.Fd())
				require.NoError(b, unix.Ftruncate(fd, 4096))
				for b.Loop() {
					if err := unix.SyncFileRange(fd, 0, 4096,
						unix.SYNC_FILE_RANGE_WAIT_BEFORE|unix.SYNC_FILE_RANGE_WRITE|unix.SYNC_FILE_RANGE_WAIT_AFTER); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// TestFsSyncUmountEmitsNoSyncfs: umount(2) flushes the filesystem through
// sync_filesystem inside the kernel, never through the syncfs(2) wrapper,
// so it must not show up as a syncfs operation (the reason to attach at the
// wrapper and not at ->sync_fs, 2.4).
func TestFsSyncUmountEmitsNoSyncfs(t *testing.T) {
	sharedMaps := map[string]*ebpf.Map{}
	a := newTestFsAttacherWithSync(t, sharedMaps, true)
	require.NotNil(t, a.syncCloser)
	reader, err := ringbuf.NewReader(sharedMaps[FsIoMapStatsEvents])
	require.NoError(t, err)
	events := collectSyncEvents(t, reader)

	vol := newFsVolume(t, "ext4", 1)
	a.refresh()
	f, err := os.CreateTemp(vol.mountPoint, "obi-umount-*")
	require.NoError(t, err)
	_, err = f.Write(make([]byte, 4096))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	vol.unmount(t)
	time.Sleep(100 * time.Millisecond)
	assert.Zero(t, events.count(vol.dev, CodeFsExt4, CodeFsOpSyncfs), "umount is not a syncfs call")
}

// TestFsSyncAggregation is TestFsSyncTypesAndFilesystems in AGG mode: the
// kernel counts each sync call into fs_io_accum under the keys the per-event
// path would emit (the volume of an open file for syncfs and a waiting
// sync_file_range, dev 0 and unknown filesystem for sync(2)), and the
// attacher knows the sync probes keep starts in fs_start so it sweeps them.
func TestFsSyncAggregation(t *testing.T) {
	for _, kprobes := range []bool{false, true} {
		name := "fentry"
		if kprobes {
			name = "kprobe"
		}
		t.Run(name, func(t *testing.T) {
			if kprobes {
				orig := planFsSyncFn
				planFsSyncFn = func() fsSyncPlan { return orig().demoteToKprobe() }
				t.Cleanup(func() { planFsSyncFn = orig })
			}
			a, _ := newAggregatingFsAttacherWithSync(t, true, true)
			require.NotNil(t, a.syncCloser, "the sync syscall set attached")
			assert.True(t, a.syncHashStarts, "sync(2) keeps its start in fs_start")

			vol := newFsVolume(t, "ext4", 1)
			a.refresh()
			f, err := os.CreateTemp(vol.mountPoint, "obi-sync-agg-*")
			require.NoError(t, err)
			defer f.Close()
			fd := int(f.Fd())
			_, err = f.Write(make([]byte, 4096))
			require.NoError(t, err)

			any := func(FsIoFsIoAccumKey) bool { return true }
			unix.Sync()
			assert.GreaterOrEqual(t, readFsAccum(t, a.accum, 0, CodeFsOpSync, any).ops, uint64(1))

			require.NoError(t, unix.Syncfs(fd))
			assert.Equal(t, uint64(1), readFsAccum(t, a.accum, vol.dev, CodeFsOpSyncfs, any).ops)

			require.NoError(t, unix.SyncFileRange(fd, 0, 4096,
				unix.SYNC_FILE_RANGE_WAIT_BEFORE|unix.SYNC_FILE_RANGE_WRITE|unix.SYNC_FILE_RANGE_WAIT_AFTER))
			require.NoError(t, unix.SyncFileRange(fd, 0, 4096, unix.SYNC_FILE_RANGE_WRITE)) // a hint: not counted
			assert.Equal(t, uint64(1), readFsAccum(t, a.accum, vol.dev, CodeFsOpSyncFileRange, any).ops)
		})
	}
}
