// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// blockStackFixture builds a fake /sys/dev/block plus device-tree layout for
// block_stack tests. Every device's own sysfs directory lives under
// <sysDir>/devtree/<name>; the top-level /sys/dev/block/<major:minor> entry
// is a relative symlink into it, as the real kernel lays it out.
type blockStackFixture struct {
	t      *testing.T
	sysDir string
}

func newBlockStackFixture(t *testing.T) *blockStackFixture {
	t.Helper()
	sysDir := t.TempDir()
	withSysBlockDir(t, sysDir)
	resetBlockStackCache(t)
	return &blockStackFixture{t: t, sysDir: sysDir}
}

func (f *blockStackFixture) devDir(name string) string {
	return filepath.Join(f.sysDir, "devtree", name)
}

// link creates <name>'s own sysfs directory (with its "dev" file) and points
// /sys/dev/block/<majMin> at it.
func (f *blockStackFixture) link(majMin, name string) string {
	f.t.Helper()
	dir := f.devDir(name)
	require.NoError(f.t, os.MkdirAll(dir, 0o755))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "dev"), []byte(majMin+"\n"), 0o644))
	require.NoError(f.t, os.Symlink(filepath.Join("devtree", name), filepath.Join(f.sysDir, majMin)))
	return dir
}

// disk registers a plain whole disk: not stacked, no slaves.
func (f *blockStackFixture) disk(majMin, name string) {
	f.link(majMin, name)
}

// dm registers a device-mapper device (covers software RAID's md/ the same
// way: both are exercised through slaves/) with the given, already
// registered, slave device names. This is also how a request-based
// dm-multipath device is modeled: its slaves are the SCSI paths.
func (f *blockStackFixture) dm(majMin, name string, slaves ...string) {
	dir := f.link(majMin, name)
	require.NoError(f.t, os.Mkdir(filepath.Join(dir, "dm"), 0o755))
	f.deviceLinks(filepath.Join(dir, "slaves"), slaves)
}

func (f *blockStackFixture) md(majMin, name string, slaves ...string) {
	dir := f.link(majMin, name)
	require.NoError(f.t, os.Mkdir(filepath.Join(dir, "md"), 0o755))
	f.deviceLinks(filepath.Join(dir, "slaves"), slaves)
}

// stackedViaSlaves registers a device that is stacked only because it lists
// a non-empty slaves/ directory, with no dm/, md/ or loop/ of its own: the
// bcache and drbd case (v2 isStacked), which has no dedicated marker
// directory the way dm/md/loop do.
func (f *blockStackFixture) stackedViaSlaves(majMin, name string, slaves ...string) {
	dir := f.link(majMin, name)
	f.deviceLinks(filepath.Join(dir, "slaves"), slaves)
}

// multipathHead registers an NVMe native-multipath head with the given,
// already registered, path device names.
func (f *blockStackFixture) multipathHead(majMin, name string, paths ...string) {
	dir := f.link(majMin, name)
	f.deviceLinks(filepath.Join(dir, "multipath"), paths)
}

// deviceLinks symlinks each of names into linksDir, at its real fixture
// directory: matches how dm/md's slaves/ and an NVMe head's multipath/ hold
// symlinks to other devices' sysfs directories.
func (f *blockStackFixture) deviceLinks(linksDir string, names []string) {
	require.NoError(f.t, os.MkdirAll(linksDir, 0o755))
	for _, n := range names {
		require.NoError(f.t, os.Symlink(f.devDir(n), filepath.Join(linksDir, n)))
	}
}

// loop registers a loop device backed by backingFile, a host-absolute path.
func (f *blockStackFixture) loop(majMin, name, backingFile string) {
	dir := f.link(majMin, name)
	loopDir := filepath.Join(dir, "loop")
	require.NoError(f.t, os.MkdirAll(loopDir, 0o755))
	require.NoError(f.t, os.WriteFile(filepath.Join(loopDir, "backing_file"), []byte(backingFile+"\n"), 0o644))
}

// partition registers name as a partition of the already registered parent,
// nested under its directory as real sysfs lays partitions out.
func (f *blockStackFixture) partition(majMin, parent, name string) {
	dir := filepath.Join(f.devDir(parent), name)
	require.NoError(f.t, os.MkdirAll(dir, 0o755))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "dev"), []byte(majMin+"\n"), 0o644))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "partition"), []byte("1\n"), 0o644))
	require.NoError(f.t, os.Symlink(filepath.Join("devtree", parent, name), filepath.Join(f.sysDir, majMin)))
}

// dangling registers a /sys/dev/block entry whose target directory is never
// created, as happens transiently while a device is torn down.
func (f *blockStackFixture) dangling(majMin, name string) {
	f.t.Helper()
	require.NoError(f.t, os.Symlink(filepath.Join("devtree", name), filepath.Join(f.sysDir, majMin)))
}

func TestBlockStackPlainDiskIsPhysical(t *testing.T) {
	f := newBlockStackFixture(t)
	f.disk("252:16", "vdb")

	info := blockStack(devT(252, 16))
	assert.False(t, info.stacked)
	assert.False(t, info.isPartition)
	assert.Equal(t, []string{"vdb"}, info.physical)
}

// TestBlockStackDmThinChain covers the step 8 fixture: a dm-thin chain
// (dm-4 -> dm-2 -> dm-0,dm-1 -> vdb) where every leg of the fan-in resolves
// to the same one physical device.
func TestBlockStackDmThinChain(t *testing.T) {
	f := newBlockStackFixture(t)
	f.disk("252:16", "vdb")
	f.dm("253:0", "dm-0", "vdb")
	f.dm("253:1", "dm-1", "vdb")
	f.dm("253:2", "dm-2", "dm-0", "dm-1")
	f.dm("253:4", "dm-4", "dm-2")

	top := blockStack(devT(253, 4))
	assert.True(t, top.stacked)
	assert.Equal(t, []string{"vdb"}, top.physical, "the fan-in through dm-0 and dm-1 must dedup to one physical device")

	mid := blockStack(devT(253, 2))
	assert.True(t, mid.stacked)
	assert.Equal(t, []string{"vdb"}, mid.physical)
}

func TestBlockStackMd(t *testing.T) {
	f := newBlockStackFixture(t)
	f.disk("8:0", "sda")
	f.disk("8:16", "sdb")
	f.md("9:0", "md0", "sda", "sdb")

	info := blockStack(devT(9, 0))
	assert.True(t, info.stacked)
	assert.Equal(t, []string{"sda", "sdb"}, info.physical)
}

// TestBlockStackRequestBasedMultipathViaSlaves covers a request-based
// dm-multipath device: it is a dm/ device (unlike bio-based dm/md, K19/2.2
// notwithstanding), and its physical paths are reached the same way, through
// slaves/.
func TestBlockStackRequestBasedMultipathViaSlaves(t *testing.T) {
	f := newBlockStackFixture(t)
	f.disk("8:0", "sda")
	f.disk("8:16", "sdb")
	f.dm("253:10", "mpatha", "sda", "sdb")

	info := blockStack(devT(253, 10))
	assert.True(t, info.stacked)
	assert.Equal(t, []string{"sda", "sdb"}, info.physical)
}

// TestBlockStackViaNonEmptySlaves covers a bcache-like device: stacked
// because sysfs lists a non-empty slaves/, even though it has no dm/, md/ or
// loop/ directory of its own (spec 1.2, step 8; v2 isStacked).
func TestBlockStackViaNonEmptySlaves(t *testing.T) {
	f := newBlockStackFixture(t)
	f.disk("8:0", "sda")
	f.stackedViaSlaves("252:0", "bcache0", "sda")

	info := blockStack(devT(252, 0))
	assert.True(t, info.stacked)
	assert.Equal(t, []string{"sda"}, info.physical)
}

// TestBlockStackNVMeMultipathHead covers K5: the head is stacked, its paths
// (hidden from /sys/dev/block on some kernels, but present in the fixture)
// are physical.
func TestBlockStackNVMeMultipathHead(t *testing.T) {
	f := newBlockStackFixture(t)
	f.disk("259:1", "nvme0c0n1")
	f.disk("259:2", "nvme0c1n1")
	f.multipathHead("259:0", "nvme0n1", "nvme0c0n1", "nvme0c1n1")

	info := blockStack(devT(259, 0))
	assert.True(t, info.stacked)
	assert.Equal(t, []string{"nvme0c0n1", "nvme0c1n1"}, info.physical)
}

// TestBlockStackLoop resolves a loop device's backing file through the host
// root (/proc/1/root) to the disk it lives on. The backing file's real
// dev_t is whatever the test filesystem happens to report, so the fixture
// registers a plain disk under that dev_t rather than a fixed one.
func TestBlockStackLoop(t *testing.T) {
	f := newBlockStackFixture(t)
	procDir := t.TempDir()
	withProcRoot(t, procDir)

	backingRel := "/var/lib/loop-backing/disk.img"
	hostPath := filepath.Join(procDir, "1", "root", backingRel)
	require.NoError(t, os.MkdirAll(filepath.Dir(hostPath), 0o755))
	require.NoError(t, os.WriteFile(hostPath, []byte("x"), 0o644))

	var st unix.Stat_t
	require.NoError(t, unix.Stat(hostPath, &st))
	backingDev := unix.Major(st.Dev)<<devMinorBits | unix.Minor(st.Dev)

	f.disk(fmtDev(backingDev), "backingdisk")
	f.loop("7:0", "loop0", backingRel)

	info := blockStack(devT(7, 0))
	assert.True(t, info.stacked)
	assert.Equal(t, []string{"backingdisk"}, info.physical)
}

// TestBlockStackLoopUnresolvableBackingFile covers a missing or
// host-unreadable backing file: physical stays nil (omitted), never a
// fabricated value.
func TestBlockStackLoopUnresolvableBackingFile(t *testing.T) {
	f := newBlockStackFixture(t)
	withProcRoot(t, t.TempDir())
	f.loop("7:1", "loop1", "/no/such/backing/file")

	info := blockStack(devT(7, 1))
	assert.True(t, info.stacked)
	assert.Nil(t, info.physical)
}

// TestBlockStackPartitionInheritsParent covers both a partition of a
// physical disk and a partition of a stacked device: it always takes its
// parent's stacked and physical values, never claiming itself as physical.
func TestBlockStackPartitionInheritsParent(t *testing.T) {
	f := newBlockStackFixture(t)
	f.disk("252:16", "vdb")
	f.partition("252:17", "vdb", "vdb1")
	f.dm("253:0", "dm-0", "vdb")
	f.partition("253:1", "dm-0", "dm-0p1")

	physicalPart := blockStack(devT(252, 17))
	assert.False(t, physicalPart.stacked)
	assert.True(t, physicalPart.isPartition)
	assert.Equal(t, "vdb", physicalPart.parent)
	assert.Equal(t, []string{"vdb"}, physicalPart.physical)

	stackedPart := blockStack(devT(253, 1))
	assert.True(t, stackedPart.stacked)
	assert.True(t, stackedPart.isPartition)
	assert.Equal(t, "dm-0", stackedPart.parent)
	assert.Equal(t, []string{"vdb"}, stackedPart.physical)
}

// TestBlockStackDanglingLink covers a /sys/dev/block entry whose target
// directory does not exist (a device mid-teardown): it is named from the
// link text and, unable to inspect a directory that is not there, defaults
// to physical rather than claiming a stacked device it cannot walk.
func TestBlockStackDanglingLink(t *testing.T) {
	f := newBlockStackFixture(t)
	f.dangling("8:99", "ghost")

	info := blockStack(devT(8, 99))
	assert.False(t, info.stacked)
	assert.Equal(t, []string{"ghost"}, info.physical)
}

// TestBlockStackUnresolvableDevice covers a dev_t with no /sys/dev/block
// entry at all: unlike a dangling link, nothing is known about it, so
// physical is nil (omitted), not a guess.
func TestBlockStackUnresolvableDevice(t *testing.T) {
	newBlockStackFixture(t)

	info := blockStack(devT(199, 0))
	assert.False(t, info.stacked)
	assert.Nil(t, info.physical)
}

// TestBlockStackPhysicalInvariant asserts the step 8 invariant across every
// stacked fixture above: every device a physical walk names must itself
// resolve to stacked == false.
func TestBlockStackPhysicalInvariant(t *testing.T) {
	f := newBlockStackFixture(t)
	f.disk("252:16", "vdb")
	f.dm("253:0", "dm-0", "vdb")
	f.dm("253:1", "dm-1", "vdb")
	f.dm("253:2", "dm-2", "dm-0", "dm-1")
	f.disk("8:0", "sda")
	f.disk("8:16", "sdb")
	f.md("9:0", "md0", "sda", "sdb")
	f.disk("259:1", "nvme0c0n1")
	f.disk("259:2", "nvme0c1n1")
	f.multipathHead("259:0", "nvme0n1", "nvme0c0n1", "nvme0c1n1")
	f.stackedViaSlaves("252:0", "bcache0", "vdb")

	byName := map[string]uint32{
		"vdb": devT(252, 16), "dm-0": devT(253, 0), "dm-1": devT(253, 1),
		"dm-2": devT(253, 2), "sda": devT(8, 0), "sdb": devT(8, 16),
		"md0": devT(9, 0), "nvme0c0n1": devT(259, 1), "nvme0c1n1": devT(259, 2),
		"nvme0n1": devT(259, 0), "bcache0": devT(252, 0),
	}
	for name, dev := range byName {
		for _, physName := range blockStack(dev).physical {
			physDev, ok := byName[physName]
			require.True(t, ok, "%s named an unregistered physical device %q", name, physName)
			assert.False(t, blockStack(physDev).stacked, "%s named %q as physical, but %q is itself stacked", name, physName, physName)
		}
	}
}

// TestBlockStackCapsPhysicalDeviceCount asserts the obi.disk.physical_device
// contract this cache feeds (step 10): sorted, deduped and capped at 8.
func TestBlockStackCapsPhysicalDeviceCount(t *testing.T) {
	f := newBlockStackFixture(t)
	names := make([]string, 0, 10)
	for i := range 10 {
		name := "sd" + string(rune('a'+i))
		f.disk(fmtDev(devT(8, uint32(i*16))), name)
		names = append(names, name)
	}
	f.dm("253:0", "dm-0", names...)

	info := blockStack(devT(253, 0))
	assert.True(t, info.stacked)
	assert.Len(t, info.physical, maxPhysicalDevices)
	assert.Equal(t, []string{"sda", "sdb", "sdc", "sdd", "sde", "sdf", "sdg", "sdh"}, info.physical)
}

// TestBlockStackCacheFollowsMinorReuse mirrors
// TestDeviceNameCacheFollowsMinorReuse: a cached device model must not
// survive its minor being reused for a different kind of device.
func TestBlockStackCacheFollowsMinorReuse(t *testing.T) {
	f := newBlockStackFixture(t)
	f.disk("252:16", "vdb")
	f.dm("253:4", "dm-4", "vdb")

	assert.True(t, blockStack(devT(253, 4)).stacked)

	require.NoError(t, os.Remove(filepath.Join(f.sysDir, "253:4")))
	f.disk("253:4", "reused")

	info := blockStack(devT(253, 4))
	assert.False(t, info.stacked)
	assert.Equal(t, []string{"reused"}, info.physical)
}

// devT builds the kernel dev_t encoding (major<<20 | minor) a test fixture's
// major:minor pair maps to.
func devT(major, minor uint32) uint32 {
	return major<<devMinorBits | minor
}

// resetBlockStackCache clears the device-model cache for the duration of a
// test, the block_stack.go counterpart of resetDevNameCache.
func resetBlockStackCache(t *testing.T) {
	t.Helper()
	devInfoMu.Lock()
	devInfoCache = map[uint32]cachedDevInfo{}
	devInfoMu.Unlock()
	t.Cleanup(func() {
		devInfoMu.Lock()
		devInfoCache = map[uint32]cachedDevInfo{}
		devInfoMu.Unlock()
	})
}
