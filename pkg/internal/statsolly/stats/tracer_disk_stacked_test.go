// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDeviceSet map[uint32]bool

func (f fakeDeviceSet) devices() ([]uint32, error) {
	var devices []uint32
	for dev := range f {
		devices = append(devices, dev)
	}
	return devices, nil
}

func (f fakeDeviceSet) add(dev uint32) error {
	f[dev] = true
	return nil
}

func (f fakeDeviceSet) remove(dev uint32) error {
	delete(f, dev)
	return nil
}

// fakeBlockDevice creates the sysfs directory of a block device under /block, with its dev file
// and the given subdirectories and slaves
func fakeBlockDevice(t *testing.T, root, name, numbers string, subdirs []string, slaves ...string) {
	t.Helper()
	dir := filepath.Join(root, "block", name)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "slaves"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dev"), []byte(numbers+"\n"), 0o644))
	for _, sub := range subdirs {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
	}
	for _, slave := range slaves {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "slaves", slave), 0o755))
	}
	// /dev/block/<maj:min> links to the device directory
	require.NoError(t, os.MkdirAll(filepath.Join(root, "dev", "block"), 0o755))
	require.NoError(t, os.Symlink(dir, filepath.Join(root, "dev", "block", numbers)))
}

// fakeScheduler writes the I/O scheduler file of a fake block device, as the kernel shows it
func fakeScheduler(t *testing.T, root, name, scheduler string) {
	t.Helper()
	dir := filepath.Join(root, "block", name, "queue")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "scheduler"), []byte(scheduler+"\n"), 0o644))
}

func fakeHostDevices(t *testing.T) string {
	root := t.TempDir()
	fakeBlockDevice(t, root, "nvme0n1", "259:0", []string{"mq"})
	fakeScheduler(t, root, "nvme0n1", "[none] mq-deadline kyber")
	fakeBlockDevice(t, root, "loop0", "7:0", []string{"mq", "loop"})
	fakeBlockDevice(t, root, "dm-0", "252:0", []string{"dm"}, "nvme0n1p2")        // LVM
	fakeBlockDevice(t, root, "dm-1", "252:1", []string{"dm", "mq"}, "sdb", "sdc") // multipath
	fakeBlockDevice(t, root, "md0", "9:0", []string{"md"}, "sdd", "sde")          // RAID
	fakeScheduler(t, root, "md0", "none")
	fakeBlockDevice(t, root, "sdb", "8:16", []string{"mq"})
	// a request-based disk of a kernel without blk-mq for it, like RHEL 8 with scsi_mod.use_blk_mq=0
	fakeBlockDevice(t, root, "sdf", "8:80", nil)
	fakeScheduler(t, root, "sdf", "noop deadline [cfq]")
	// bio-based drivers: a PowerFlex volume, a compressed RAM disk, an NVMe multipath head, DRBD
	fakeBlockDevice(t, root, "scinia", "251:0", nil)
	fakeScheduler(t, root, "scinia", "none")
	fakeBlockDevice(t, root, "zram0", "250:0", nil) // recent kernels show no scheduler of bio-based devices
	fakeBlockDevice(t, root, "nvme1n1", "259:5", nil)
	fakeScheduler(t, root, "nvme1n1", "none")
	fakeBlockDevice(t, root, "drbd1000", "147:1000", nil)
	fakeScheduler(t, root, "drbd1000", "none")
	return root
}

func TestStackedDevices(t *testing.T) {
	root := fakeHostDevices(t)
	names := &deviceNames{sysRoot: root, procRoot: root}
	assert.False(t, names.stacked(259, 0), "a disk")
	assert.False(t, names.stacked(8, 16), "a path of a multipath device")
	assert.True(t, names.stacked(7, 0), "a loop device")
	assert.True(t, names.stacked(252, 0), "an LVM volume")
	assert.True(t, names.stacked(252, 1), "a multipath device")
	assert.True(t, names.stacked(9, 0), "an md RAID volume")
	assert.False(t, names.stacked(8, 99), "an unknown device")
	assert.False(t, names.stacked(251, 0), "a PowerFlex volume: its I/O goes to the network")
	assert.False(t, names.stacked(250, 0), "a compressed RAM disk")
	assert.True(t, names.stacked(259, 5), "an NVMe multipath head, over hidden path devices")
	assert.True(t, names.stacked(147, 1000), "a DRBD device, over its backing device")
	assert.False(t, names.stacked(8, 80), "a request-based disk without blk-mq")
}

func TestBioDevicesTracksTheBioBasedStackedVolumes(t *testing.T) {
	root := fakeHostDevices(t)
	set := fakeDeviceSet{kernelDev(253, 7): true} // a volume that was removed
	bios := newBioDevices(root, set)

	bios.refresh()
	devices, _ := set.devices()
	slices.Sort(devices)
	assert.Equal(t, []uint32{
		kernelDev(9, 0), kernelDev(147, 1000), kernelDev(250, 0), kernelDev(251, 0), kernelDev(252, 0), kernelDev(259, 5),
	}, devices, "the bio-based devices, not the request-based ones (blk-mq or not), nor the removed volume")
}
