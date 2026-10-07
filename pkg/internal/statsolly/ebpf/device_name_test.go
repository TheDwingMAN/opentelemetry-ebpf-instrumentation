// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceName(t *testing.T) {
	dir := t.TempDir()
	// A real /sys/dev/block/<major>:<minor> is a symlink into the device tree
	// whose basename is the device node name.
	require.NoError(t, os.Symlink("../../devices/pci0000:00/block/sdb", filepath.Join(dir, "8:16")))
	withSysBlockDir(t, dir)

	// dev_t for major 8, minor 16 is (8<<20)|16 == 0x800010.
	assert.Equal(t, "sdb", deviceName(0x800010))
	// Cached lookups return the same resolved name.
	assert.Equal(t, "sdb", deviceName(0x800010))
	// An unresolvable device falls back to "<major>:<minor>".
	assert.Equal(t, "9:0", deviceName(9<<20))
}

// TestDeviceNameCacheFollowsMinorReuse asserts that a cached name is dropped
// once its sysfs symlink no longer agrees with it: dm/md minors are reused,
// so a cache keyed only by dev_t forever would keep naming a new device after
// its predecessor.
func TestDeviceNameCacheFollowsMinorReuse(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "253:4")
	require.NoError(t, os.Symlink("../../devices/virtual/block/dm-4", link))
	withSysBlockDir(t, dir)

	assert.Equal(t, "dm-4", deviceName(253<<20|4))

	// The minor is reused for an unrelated device: the symlink now points
	// elsewhere, so the stale "dm-4" must not be returned.
	require.NoError(t, os.Remove(link))
	require.NoError(t, os.Symlink("../../devices/virtual/block/dm-9", link))
	assert.Equal(t, "dm-9", deviceName(253<<20|4))

	// The device disappears entirely: the fallback form is returned, not the
	// last resolved name.
	require.NoError(t, os.Remove(link))
	assert.Equal(t, "253:4", deviceName(253<<20|4))
}

// TestDeviceNameForFS covers the system.device rule for filesystems (S5,
// step 10): major 0 (an anonymous superblock: nfs, cifs, ceph, fuse, or a
// btrfs volume spanning more than one device) and a sysfs miss both give ""
// -- never deviceName's "<major>:<minor>" fallback.
func TestDeviceNameForFS(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Symlink("../../devices/pci0000:00/block/vdb", filepath.Join(dir, "252:16")))
	withSysBlockDir(t, dir)

	assert.Equal(t, "vdb", deviceNameForFS(252<<20|16))
	assert.Empty(t, deviceNameForFS(0), "major 0: anonymous superblock")
	assert.Empty(t, deviceNameForFS(9<<20), "no sysfs entry: never the M:m fallback")
}

// withSysBlockDir points the resolver at a fixture directory and clears the
// name cache for the duration of a test.
func withSysBlockDir(t *testing.T, dir string) {
	t.Helper()
	old := sysBlockDir
	sysBlockDir = dir
	resetDevNameCache()
	t.Cleanup(func() {
		sysBlockDir = old
		resetDevNameCache()
	})
}

func resetDevNameCache() {
	devNameMu.Lock()
	devNameCache = map[uint32]namedDev{}
	devNameMu.Unlock()
}
