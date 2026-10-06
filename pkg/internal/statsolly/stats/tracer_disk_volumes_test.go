// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// fakeDMVolume creates the sysfs directory of a device mapper volume over slaves, with its name
func fakeDMVolume(t *testing.T, root, name, numbers, dmName string, slaves ...string) {
	t.Helper()
	path := filepath.Join("virtual", "block", name)
	fakeSysDevice(t, root, path, numbers, slaves...)
	dir := filepath.Join(root, "devices", path, "dm")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "name"), []byte(dmName+"\n"), 0o644))
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
	tracer := NewDiskVolumesTracer()
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
