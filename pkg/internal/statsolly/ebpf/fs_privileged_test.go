// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
)

const (
	// Large enough for mkfs.xfs, the most demanding of the three; the backing
	// file is sparse.
	fsVolumeBytes = 320 << 20
	fsWriteBytes  = 64 << 10
	eventTimeout  = 10 * time.Second
)

// A filesystem whose programs the kernel rejects -- here btrfs, planned
// against a function that does not exist, so its fentry load and then its
// kprobe attach fail -- is disabled on its own. The block programs, loaded
// before, and ext4, attached in the same pass, keep reporting.
func TestFailingFilesystemKeepsBlockAndOtherFilesystems(t *testing.T) {
	fetcher, reader := attachBlockPrograms(t, export.FeatureStorageBlock)
	events := collectStatEvents(t, reader)

	vol := newFsVolume(t, "ext4", 1)
	sharedMaps := map[string]*ebpf.Map{
		FsIoMapStatsEvents: fetcher.StatsEventsMap(),
		FsIoMapDebugEvents: fetcher.DebugEventsMap(),
	}
	a := newTestFsAttacher(t, sharedMaps)

	scan := a.localPVs
	a.localPVs = func() (map[FsTypeCode]bool, error) {
		withPV, err := scan()
		if withPV != nil {
			withPV[CodeFsBtrfs] = true
		}
		return withPV, err
	}
	a.plan = func(targets []fsTarget) []fsAttachPlan {
		plans := planFsTargets(targets)
		for i := range plans {
			if plans[i].Fs == CodeFsBtrfs {
				plans[i].ReadSym = "obi_no_such_function"
			}
		}
		return plans
	}

	a.refresh()
	require.Contains(t, a.attached, CodeFsExt4)
	assert.NotContains(t, a.attached, CodeFsBtrfs)
	assert.Equal(t, 1, a.failures[CodeFsBtrfs], "btrfs failed with fentry and with kprobes")
	assert.True(t, a.noFentry[CodeFsBtrfs], "btrfs was retried with kprobes")

	writeAndSync(t, vol.mountPoint)
	events.waitFs(t, vol.dev, CodeFsExt4)
	events.waitBlock(t, vol.disk.kernelDev)
}

// ext4, xfs and btrfs attach only while a kubelet volume of their type is
// mounted, including one mounted after startup, and detach once it has been
// gone for fsDetachAfter refreshes.
func TestLocalFilesystemsAttachOnlyWithAVolume(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs and mount filesystems")
	}
	sharedMaps := map[string]*ebpf.Map{}
	a := newTestFsAttacher(t, sharedMaps)
	reader, err := ringbuf.NewReader(sharedMaps[FsIoMapStatsEvents])
	require.NoError(t, err)
	events := collectStatEvents(t, reader)

	// Startup: the node's own filesystems hold no kubelet volume.
	a.refresh()
	assertLocalAttached(t, a)

	ext4 := newFsVolume(t, "ext4", 1)
	a.refresh()
	assertLocalAttached(t, a, CodeFsExt4)
	writeAndSync(t, ext4.mountPoint)
	events.waitFs(t, ext4.dev, CodeFsExt4)

	want := []FsTypeCode{CodeFsExt4}
	for i, fs := range []string{"btrfs", "xfs"} {
		vol := newFsVolumeIfSupported(t, fs, i+2)
		if vol == nil {
			continue
		}
		a.refresh()
		want = append(want, localFilesystems[fs])
		assertLocalAttached(t, a, want...)
		writeAndSync(t, vol.mountPoint)
		events.waitFs(t, vol.dev, localFilesystems[fs])
	}

	ext4.unmount(t)
	a.refresh()
	assertLocalAttached(t, a, want...) // detached only after fsDetachAfter refreshes
	a.refresh()
	assertLocalAttached(t, a, want[1:]...)
	var allowed uint8
	assert.ErrorIs(t, sharedMaps[FsIoMapFsDevFilter].Lookup(ext4.dev, &allowed), ebpf.ErrKeyNotExist,
		"the unmounted volume left the allowlist")
}

func newTestFsAttacher(t *testing.T, sharedMaps map[string]*ebpf.Map) *fsAttacher {
	t.Helper()

	cfg := &config.EBPFTracer{}
	a, err := newKernelFsAttacher(slog.Default(), cfg, statsConstants(cfg, blockLoadPlan{}), sharedMaps, &sync.Mutex{})
	require.NoError(t, err)
	t.Cleanup(func() {
		close(a.stopped) // run() is never started: the test drives refresh
		assert.NoError(t, a.Close())
	})
	return a
}

func assertLocalAttached(t *testing.T, a *fsAttacher, want ...FsTypeCode) {
	t.Helper()
	var got []FsTypeCode
	for fs := range a.attached {
		if isLocalFs(fs) {
			got = append(got, fs)
		}
	}
	assert.ElementsMatch(t, want, got)
}

type fsVolume struct {
	disk       *testDisk
	mountPoint string
	// dev is the superblock's dev_t, as the programs report it.
	dev     uint32
	mounted bool
}

// newFsVolumeIfSupported is newFsVolume, or nil when this kernel or image
// cannot make one of fstype. A filesystem module is never loaded for a test.
func newFsVolumeIfSupported(t *testing.T, fstype string, n int) *fsVolume {
	t.Helper()
	if !filesystemRegistered(t, fstype) {
		t.Logf("%s is not registered with this kernel; not covered", fstype)
		return nil
	}
	if _, err := exec.LookPath("mkfs." + fstype); err != nil {
		t.Logf("no mkfs.%s; %s not covered", fstype, fstype)
		return nil
	}
	return newFsVolume(t, fstype, n)
}

// newFsVolume makes a filesystem on a fresh loop device and mounts it where
// the kubelet mounts a CSI volume, for pod UID number n.
func newFsVolume(t *testing.T, fstype string, n int) *fsVolume {
	t.Helper()
	if !filesystemRegistered(t, fstype) {
		t.Skipf("%s is not registered with this kernel", fstype)
	}
	mkfs, err := exec.LookPath("mkfs." + fstype)
	if err != nil {
		t.Skipf("no mkfs.%s", fstype)
	}

	disk := newLoopDevice(t, fsVolumeBytes)
	force := map[string]string{"ext4": "-F", "xfs": "-f", "btrfs": "-f"}[fstype]
	out, err := exec.Command(mkfs, "-q", force, disk.path).CombinedOutput()
	require.NoError(t, err, "mkfs.%s: %s", fstype, out)

	pod := filepath.Join("/var/lib/kubelet/pods", fmt.Sprintf("0b1f5e0a-0000-4000-8000-%012d", n))
	mountPoint := filepath.Join(pod, "volumes/kubernetes.io~csi", "pv-"+fstype, "mount")
	require.NoError(t, os.MkdirAll(mountPoint, 0o755))
	t.Cleanup(func() { os.RemoveAll(pod) })
	require.NoError(t, unix.Mount(disk.path, mountPoint, fstype, 0, ""))

	vol := &fsVolume{disk: disk, mountPoint: mountPoint, mounted: true}
	t.Cleanup(func() { vol.unmount(t) })
	vol.dev = superblockDev(t, mountPoint)
	return vol
}

func (v *fsVolume) unmount(t *testing.T) {
	t.Helper()
	if !v.mounted {
		return
	}
	require.NoError(t, unix.Unmount(v.mountPoint, 0))
	v.mounted = false
}

// superblockDev reads the superblock dev_t of the mount at mountPoint from
// the mount table, as the allowlist does: for btrfs it is an anonymous device,
// not the loop device.
func superblockDev(t *testing.T, mountPoint string) uint32 {
	t.Helper()
	mounts, err := mountsFrom(selfMountInfoPath)
	require.NoError(t, err)
	for _, m := range mounts {
		if m.MountPoint == mountPoint {
			dev, ok := parseDevT(m.MajorMinorVer)
			require.True(t, ok)
			return dev
		}
	}
	require.FailNow(t, "mount not in the mount table", mountPoint)
	return 0
}

func filesystemRegistered(t *testing.T, fstype string) bool {
	t.Helper()
	raw, err := os.ReadFile("/proc/filesystems")
	require.NoError(t, err)
	for line := range strings.SplitSeq(string(raw), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[len(fields)-1] == fstype {
			return true
		}
	}
	return false
}

// writeAndSync writes a file in dir and fsyncs it.
func writeAndSync(t *testing.T, dir string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, "obi-test"))
	require.NoError(t, err)
	defer f.Close()
	_, err = f.Write(make([]byte, fsWriteBytes))
	require.NoError(t, err)
	require.NoError(t, f.Sync())
}

// statEvents counts the filesystem events per superblock and filesystem, and
// the block events per device, read from the stats ring buffer.
type statEvents struct {
	mu    sync.Mutex
	fs    map[uint32]map[FsTypeCode]int
	block map[uint32]int
}

func collectStatEvents(t *testing.T, reader *ringbuf.Reader) *statEvents {
	t.Helper()

	events := &statEvents{fs: map[uint32]map[FsTypeCode]int{}, block: map[uint32]int{}}
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

func (e *statEvents) add(sample []byte) {
	if len(sample) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	switch StatType(sample[0]) {
	case StatTypeFsIo:
		if len(sample) < int(unsafe.Sizeof(StatsFsIo{})) {
			return
		}
		event := (*StatsFsIo)(unsafe.Pointer(&sample[0]))
		if e.fs[event.SDev] == nil {
			e.fs[event.SDev] = map[FsTypeCode]int{}
		}
		e.fs[event.SDev][FsTypeCode(event.Fs)]++
	case StatTypeBlockIo:
		if len(sample) < int(unsafe.Sizeof(StatsBlockIo{})) {
			return
		}
		e.block[(*StatsBlockIo)(unsafe.Pointer(&sample[0])).Dev]++
	}
}

func (e *statEvents) waitFs(t *testing.T, dev uint32, fs FsTypeCode) {
	t.Helper()
	assert.Eventually(t, func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.fs[dev][fs] > 0
	}, eventTimeout, 50*time.Millisecond, "no %s event for the volume's superblock %#x", fsTypeStr(fs), dev)
}

func (e *statEvents) waitBlock(t *testing.T, dev uint32) {
	t.Helper()
	assert.Eventually(t, func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.block[dev] > 0
	}, eventTimeout, 50*time.Millisecond, "no block event for device %#x", dev)
}
