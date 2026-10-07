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

// A block-backed filesystem resolves system.device straight from its
// superblock's dev_t, and obi.disk.physical_device from the block-stack walk
// behind it (step 10).
func TestFSJoinDeviceBlockBacked(t *testing.T) {
	f := newBlockStackFixture(t)
	f.disk("252:16", "vdb")

	device, physical := FSJoinDevice(devT(252, 16), "/dev/vdb")
	assert.Equal(t, "vdb", device)
	assert.Equal(t, "vdb", physical)
}

// Every network filesystem's superblock is anonymous (major 0) and its
// source is not a host path, so neither fs join device label resolves (S5,
// D4): the mount's server.address carries its identity instead.
func TestFSJoinDeviceNetworkFilesystemsResolveNothing(t *testing.T) {
	withProcRoot(t, t.TempDir())

	for _, tc := range []struct {
		name   string
		source string
	}{
		{"nfs", "10.0.0.5:/export/pvc-x"},
		{"cifs", "//fileserver/share"},
		{"ceph", "10.0.0.1,10.0.0.2,10.0.0.3:/"},
		{"fuse", "s3fs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			device, physical := FSJoinDevice(0, tc.source)
			assert.Empty(t, device)
			assert.Empty(t, physical)
		})
	}
}

// A btrfs volume spanning more than one device reports major 0, like a
// network filesystem, but is still block-backed: the mount source names a
// real host block device to fall back to.
func TestFSJoinDeviceBtrfsMultiDeviceViaSource(t *testing.T) {
	f := newBlockStackFixture(t)
	procDir := t.TempDir()
	withProcRoot(t, procDir)

	const source = "/dev/mapper/vg-lv"
	hostPath := filepath.Join(procDir, "1", "root", source)
	require.NoError(t, os.MkdirAll(filepath.Dir(hostPath), 0o755))
	require.NoError(t, os.WriteFile(hostPath, []byte("x"), 0o644))

	// hostStat is stubbed rather than really stat-ing hostPath: source is a
	// block special file, so the dev_t it represents is st_rdev, not st_dev
	// (st_dev there is devtmpfs's own device, major 0 on every real host --
	// stubbed here too, to prove statHostPathDevT does not fall back to it).
	backingDev := devT(253, 7)
	old := hostStat
	hostStat = func(path string, st *unix.Stat_t) error {
		require.Equal(t, hostPath, path)
		st.Mode = unix.S_IFBLK
		st.Dev = unix.Mkdev(0, 7)
		st.Rdev = unix.Mkdev(253, 7)
		return nil
	}
	t.Cleanup(func() { hostStat = old })

	f.disk(fmtDev(backingDev), "dm-7")

	device, physical := FSJoinDevice(0, source)
	assert.Equal(t, "dm-7", device)
	assert.Equal(t, "dm-7", physical)
}

// A source that resolves through neither sysfs nor the host root (a stale
// dm target, or simply gone) omits both labels rather than guessing.
func TestFSJoinDeviceUnresolvableSourceOmitsBoth(t *testing.T) {
	withProcRoot(t, t.TempDir())

	device, physical := FSJoinDevice(0, "/dev/mapper/does-not-exist")
	assert.Empty(t, device)
	assert.Empty(t, physical)
}

// dev 0 (major 0, minor 0) is major 0's anonymous-superblock case, covered
// directly rather than only through a filesystem type: whatever the caller's
// reason for a zero dev_t, no fallback "0:0" name ever appears.
func TestFSJoinDeviceDevZeroOmitsSystemDevice(t *testing.T) {
	withProcRoot(t, t.TempDir())

	device, physical := FSJoinDevice(0, "")
	assert.Empty(t, device)
	assert.Empty(t, physical)
}

// A regular file's st_rdev is always zero; the device it lives on is named by
// st_dev alone (the loop backing-file case). A block special file's st_dev
// names devtmpfs, not the device the node represents -- st_rdev does (the
// mount-source fallback case). statHostPathDevT must pick the field that
// matches which one path is.
func TestStatHostPathDevTUsesRdevOnlyForBlockSpecialFiles(t *testing.T) {
	withProcRoot(t, t.TempDir())
	old := hostStat
	t.Cleanup(func() { hostStat = old })

	for _, tc := range []struct {
		name string
		mode uint32
		dev  uint64
		rdev uint64
		want uint32
	}{
		{"regular file uses st_dev", unix.S_IFREG, unix.Mkdev(8, 1), unix.Mkdev(253, 9), devT(8, 1)},
		{"block special file uses st_rdev", unix.S_IFBLK, unix.Mkdev(0, 7), unix.Mkdev(259, 0), devT(259, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hostStat = func(_ string, st *unix.Stat_t) error {
				st.Mode, st.Dev, st.Rdev = tc.mode, tc.dev, tc.rdev
				return nil
			}

			dev, ok := statHostPathDevT("/dev/whatever")
			require.True(t, ok)
			assert.Equal(t, tc.want, dev)
		})
	}
}
