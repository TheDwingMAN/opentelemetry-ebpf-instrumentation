// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// fakeSysDevice creates the sysfs directory of a block device, under /devices like the kernel
// does, with /dev/block/<maj:min> linking to it, and /block/<name> for the devices that are not
// partitions. Partitions are subdirectories of their disk, and slaves link to the directories of
// the devices below.
func fakeSysDevice(t *testing.T, root, path, numbers string, slaves ...string) {
	t.Helper()
	dir := filepath.Join(root, "devices", path)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	name := filepath.Base(path)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "uevent"), []byte("DEVNAME="+name+"\n"), 0o644))
	if filepath.Base(filepath.Dir(path)) != "block" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "partition"), []byte("1\n"), 0o644))
	} else {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "block"), 0o755))
		require.NoError(t, os.Symlink(dir, filepath.Join(root, "block", name)))
	}
	for _, slave := range slaves {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "slaves"), 0o755))
		require.NoError(t, os.Symlink(filepath.Join(root, "devices", slave), filepath.Join(dir, "slaves", filepath.Base(slave))))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(root, "dev", "block"), 0o755))
	require.NoError(t, os.Symlink(dir, filepath.Join(root, "dev", "block", numbers)))
}

func fakeVolumeHost(t *testing.T) string {
	root := t.TempDir()
	fakeSysDevice(t, root, "pci/block/sda", "8:0")
	fakeSysDevice(t, root, "pci/block/sda/sda1", "8:1")
	fakeSysDevice(t, root, "pci/block/sdb", "8:16")
	fakeSysDevice(t, root, "pci/block/sdb/sdb1", "8:17")
	fakeSysDevice(t, root, "pci/block/nvme0n1", "259:0")
	// an LVM volume over partitions of two disks
	fakeSysDevice(t, root, "virtual/block/dm-0", "252:0", "pci/block/sda/sda1", "pci/block/sdb/sdb1")
	// loop devices on files of the host, whose devices are in fakeHostPaths
	fakeLoopDevice(t, root, "loop0", "7:0", "/var/lib/images/on-disk.img")
	fakeLoopDevice(t, root, "loop1", "7:1", "/mnt/data/on-partition.img")
	fakeLoopDevice(t, root, "loop2", "7:2", "/srv/on-lvm.img")
	fakeLoopDevice(t, root, "loop3", "7:3", "/var/lib/images/deleted.img (deleted)")
	fakeLoopDevice(t, root, "loop4", "7:4", "/run/on-tmpfs.img")
	fakeLoopDevice(t, root, "loop5", "7:5", "/in-a-container.img")
	// an LVM volume over a loop device
	fakeSysDevice(t, root, "virtual/block/dm-1", "252:1", "virtual/block/loop0")
	// a multipath device over two paths, and an LVM volume over it
	fakeSysDevice(t, root, "pci/block/sdc", "8:32")
	fakeSysDevice(t, root, "pci/block/sdd", "8:48")
	fakeMultipathVolume(t, root, "dm-2", "252:2", "mpatha", "pci/block/sdc", "pci/block/sdd")
	fakeSysDevice(t, root, "virtual/block/dm-3", "252:3", "virtual/block/dm-2")
	return root
}

// fakeLoopDevice creates the sysfs directory of a loop device on a file of the host
func fakeLoopDevice(t *testing.T, root, name, numbers, backingFile string) {
	t.Helper()
	path := filepath.Join("virtual", "block", name)
	fakeSysDevice(t, root, path, numbers)
	dir := filepath.Join(root, "devices", path, "loop")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "backing_file"), []byte(backingFile+"\n"), 0o644))
}

// fakeHostPaths are the devices of the paths of the fake host
var fakeHostPaths = map[string][2]uint32{
	"/var/local-path-provisioner/pvc-local": {259, 0},
	"/var/lib/images/on-disk.img":           {259, 0},
	"/mnt/data/on-partition.img":            {8, 1},
	"/srv/on-lvm.img":                       {252, 0},
	// a new file took the path of the deleted file of loop3
	"/var/lib/images/deleted.img": {259, 0},
	// tmpfs, which is on no block device
	"/run/on-tmpfs.img": {0, 45},
}

// fakeHostDeviceOf returns the device of a path of the fake host
func fakeHostDeviceOf(path string) (major, minor uint32, err error) {
	if device, ok := fakeHostPaths[path]; ok {
		return device[0], device[1], nil
	}
	return 0, 0, errors.New("no such path")
}

// fakeDMVolume creates the sysfs directory of a device mapper volume over slaves, with its name
func fakeDMVolume(t *testing.T, root, name, numbers, dmName string, slaves ...string) {
	t.Helper()
	path := filepath.Join("virtual", "block", name)
	fakeSysDevice(t, root, path, numbers, slaves...)
	dir := filepath.Join(root, "devices", path, "dm")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "name"), []byte(dmName+"\n"), 0o644))
}

// fakeMultipathVolume creates the sysfs directory of a dm-multipath device over its paths, with
// its name and the UUID that multipathd gives it. It is request-based, as multipathd creates them
// by default.
func fakeMultipathVolume(t *testing.T, root, name, numbers, dmName string, paths ...string) {
	t.Helper()
	fakeBioMultipathVolume(t, root, name, numbers, dmName, paths...)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "devices", "virtual", "block", name, "mq"), 0o755))
}

// fakeBioMultipathVolume creates the sysfs directory of a dm-multipath device of queue_mode bio,
// which is bio-based
func fakeBioMultipathVolume(t *testing.T, root, name, numbers, dmName string, paths ...string) {
	t.Helper()
	fakeDMVolume(t, root, name, numbers, dmName, paths...)
	uuid := filepath.Join(root, "devices", "virtual", "block", name, "dm", "uuid")
	require.NoError(t, os.WriteFile(uuid, []byte("mpath-3600a098038303053453f463045727a51\n"), 0o644))
}

// fakeMDVolume creates the sysfs directory of an md RAID volume over slaves
func fakeMDVolume(t *testing.T, root, name, numbers string, slaves ...string) {
	t.Helper()
	path := filepath.Join("virtual", "block", name)
	fakeSysDevice(t, root, path, numbers, slaves...)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "devices", path, "md"), 0o755))
}

// fakeStackedHost creates the sysfs of a host with stacked volumes, whose loop devices are on the
// files of fakeHostPaths
func fakeStackedHost(t *testing.T) string {
	root := t.TempDir()
	fakeSysDevice(t, root, "pci/block/nvme0n1", "259:0")
	fakeSysDevice(t, root, "pci/block/vdb", "253:16")
	fakeSysDevice(t, root, "pci/block/vdc", "253:32")
	fakeSysDevice(t, root, "pci/block/vdc/vdc1", "253:33")
	fakeSysDevice(t, root, "pci/block/vdd", "253:48")
	fakeSysDevice(t, root, "pci/block/vde", "253:64")
	// two LVM volumes over a whole disk
	fakeDMVolume(t, root, "dm-0", "252:0", "vg0-lv0", "pci/block/vdb")
	fakeDMVolume(t, root, "dm-1", "252:1", "vg0-lv1", "pci/block/vdb")
	// an LVM volume over a partition, and a dm-crypt volume over it
	fakeDMVolume(t, root, "dm-2", "252:2", "vg1-lv0", "pci/block/vdc/vdc1")
	fakeDMVolume(t, root, "dm-3", "252:3", "luks-data", "virtual/block/dm-2")
	// an md RAID1 volume over two disks
	fakeMDVolume(t, root, "md0", "9:0", "pci/block/vdd", "pci/block/vde")
	// a multipath device over two paths, and an LVM volume over it
	fakeSysDevice(t, root, "pci/block/vdf", "253:80")
	fakeSysDevice(t, root, "pci/block/vdg", "253:96")
	fakeMultipathVolume(t, root, "dm-4", "252:4", "mpatha", "pci/block/vdf", "pci/block/vdg")
	fakeDMVolume(t, root, "dm-5", "252:5", "vg2-lv0", "virtual/block/dm-4")
	fakeLoopDevice(t, root, "loop0", "7:0", "/var/lib/images/on-disk.img")
	fakeLoopDevice(t, root, "loop1", "7:1", "/run/on-tmpfs.img")
	// an unbound loop device, which has no loop directory
	fakeSysDevice(t, root, "virtual/block/loop2", "7:2")
	return root
}

// volumeValues returns the value of each volume disk of the stats
func volumeValues(t *testing.T, stats []*ebpf.Stat) map[ebpf.DiskVolume]int64 {
	t.Helper()
	values := map[ebpf.DiskVolume]int64{}
	for _, stat := range stats {
		require.Equal(t, ebpf.StatTypeDiskVolume, stat.Type)
		volume := *stat.DiskVolume
		volume.Value = 0
		values[volume] = stat.DiskVolume.Value
	}
	return values
}

func TestDiskVolumesTracer(t *testing.T) {
	root := fakeStackedHost(t)
	tracer := NewDiskVolumesTracer(false)
	tracer.stack = &deviceStack{sysRoot: root, deviceOf: fakeHostDeviceOf}

	removedLV := ebpf.DiskVolume{Volume: "dm-1", Name: "vg0-lv1", Device: "vdb"}
	volumes := map[ebpf.DiskVolume]int64{
		{Volume: "dm-0", Name: "vg0-lv0", Device: "vdb"}: 1,
		removedLV: 1,
		// an LVM volume over a partition is on the whole disk
		{Volume: "dm-2", Name: "vg1-lv0", Device: "vdc"}: 1,
		// a volume over another one is on the disks of the bottom one
		{Volume: "dm-3", Name: "luks-data", Device: "vdc"}: 1,
		// an md RAID1 volume is on both disks, and has no device mapper name
		{Volume: "md0", Device: "vdd"}: 1,
		{Volume: "md0", Device: "vde"}: 1,
		// a multipath device is on its paths, and a volume over it is on it, which reports the I/O
		// of the paths
		{Volume: "dm-4", Name: "mpatha", Device: "vdf"}:   1,
		{Volume: "dm-4", Name: "mpatha", Device: "vdg"}:   1,
		{Volume: "dm-5", Name: "vg2-lv0", Device: "dm-4"}: 1,
		// a loop device is on the disk of its file
		{Volume: "loop0", Device: "nvme0n1"}: 1,
	}
	assert.Equal(t, volumes, volumeValues(t, tracer.readStats()),
		"neither the disks, nor a loop device on tmpfs, nor an unbound loop device")

	require.NoError(t, os.Remove(filepath.Join(root, "block", "dm-1")))
	gone := maps.Clone(volumes)
	gone[removedLV] = 0
	assert.Equal(t, gone, volumeValues(t, tracer.readStats()), "a removed volume is reported once more, as gone")
	delete(gone, removedLV)
	assert.Equal(t, gone, volumeValues(t, tracer.readStats()), "only once")

	// a failed listing of the block devices doesn't report the volumes as gone
	tracer.stack.sysRoot = filepath.Join(root, "missing")
	assert.Empty(t, tracer.readStats())
	tracer.stack.sysRoot = root
	assert.Equal(t, gone, volumeValues(t, tracer.readStats()))
}

// A dm-multipath device of queue_mode bio is bio-based: OBI measures it only with
// stats_disk_bio_devices. Without it, the volumes over it are on its paths, which report their I/O.
// The multipath device is on its paths either way.
func TestDiskVolumesOverBioBasedMultipathDevices(t *testing.T) {
	root := t.TempDir()
	fakeSysDevice(t, root, "pci/block/sda", "8:0")
	fakeSysDevice(t, root, "pci/block/sdb", "8:16")
	fakeBioMultipathVolume(t, root, "dm-0", "252:0", "mpatha", "pci/block/sda", "pci/block/sdb")
	fakeDMVolume(t, root, "dm-1", "252:1", "vg0-lv0", "virtual/block/dm-0")
	multipath := map[ebpf.DiskVolume]int64{
		{Volume: "dm-0", Name: "mpatha", Device: "sda"}: 1,
		{Volume: "dm-0", Name: "mpatha", Device: "sdb"}: 1,
	}
	for _, tc := range []struct {
		name        string
		bioMeasured bool
		lvDisks     []string
	}{
		{name: "measured", bioMeasured: true, lvDisks: []string{"dm-0"}},
		{name: "not measured", bioMeasured: false, lvDisks: []string{"sda", "sdb"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tracer := NewDiskVolumesTracer(tc.bioMeasured)
			tracer.stack.sysRoot = root
			volumes := maps.Clone(multipath)
			for _, disk := range tc.lvDisks {
				volumes[ebpf.DiskVolume{Volume: "dm-1", Name: "vg0-lv0", Device: disk}] = 1
			}
			assert.Equal(t, volumes, volumeValues(t, tracer.readStats()))
		})
	}
}

func TestPhysicalDisks(t *testing.T) {
	stack := &deviceStack{sysRoot: fakeVolumeHost(t), deviceOf: fakeHostDeviceOf}
	disks := func(numbers string) []string {
		return stack.physicalDisks(filepath.Join(stack.sysRoot, "dev", "block", numbers), maxDeviceStackDepth)
	}
	assert.Equal(t, []string{"sda"}, disks("8:0"), "a disk")
	assert.Equal(t, []string{"sda"}, disks("8:1"), "a partition")
	assert.ElementsMatch(t, []string{"sda", "sdb"}, disks("252:0"), "an LVM volume over two disks")
	assert.Empty(t, disks("9:9"), "an unknown device")

	assert.Equal(t, []string{"nvme0n1"}, disks("7:0"), "a loop device on a file on a disk")
	assert.Equal(t, []string{"sda"}, disks("7:1"), "a loop device on a file on a partition")
	assert.ElementsMatch(t, []string{"sda", "sdb"}, disks("7:2"), "a loop device on a file on an LVM volume")
	assert.Equal(t, []string{"nvme0n1"}, disks("252:1"), "an LVM volume over a loop device")
	assert.Equal(t, []string{"dm-2"}, disks("252:2"), "a multipath device, which reports the I/O of its paths")
	assert.Equal(t, []string{"dm-2"}, disks("252:3"), "an LVM volume over a multipath device")
	assert.Equal(t, []string{"loop3"}, disks("7:3"), "a loop device on a deleted file")
	assert.Equal(t, []string{"loop4"}, disks("7:4"), "a loop device on a filesystem on no block device")
	assert.Equal(t, []string{"loop5"}, disks("7:5"), "a loop device on a file that isn't on the host")
}
