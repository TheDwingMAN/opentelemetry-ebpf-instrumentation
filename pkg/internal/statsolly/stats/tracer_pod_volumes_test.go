// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

type fakePodVolumes struct {
	pods []*informer.ObjectMeta
	pvs  map[string]*informer.ObjectMeta
}

func (f *fakePodVolumes) PodsWithVolumeClaims(nodeName string) []*informer.ObjectMeta {
	var pods []*informer.ObjectMeta
	for _, pod := range f.pods {
		if pod.Pod.NodeName == nodeName {
			pods = append(pods, pod)
		}
	}
	return pods
}

func (f *fakePodVolumes) PersistentVolumeByClaim(namespace, claimName string) *informer.ObjectMeta {
	return f.pvs[namespace+"/"+claimName]
}

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

func testPod(name, uid string, claims ...*informer.VolumeClaim) *informer.ObjectMeta {
	return &informer.ObjectMeta{
		Name: name, Namespace: "default", Kind: "Pod",
		Pod: &informer.PodInfo{
			Uid:          uid,
			NodeName:     "node-1",
			Owners:       []*informer.Owner{{Name: "db", Kind: "StatefulSet"}},
			VolumeClaims: claims,
		},
	}
}

func testPV(name, claim, localPath string) *informer.ObjectMeta {
	return &informer.ObjectMeta{
		Name: name, Kind: "PersistentVolume",
		PersistentVolume: &informer.PersistentVolumeInfo{ClaimNamespace: "default", ClaimName: claim, LocalPath: localPath},
	}
}

func newTestPodVolumesTracer(t *testing.T, store *fakePodVolumes, mounts []*procfs.MountInfo) *PodVolumesTracer {
	tracer := NewPodVolumesTracer(store, "node-1", false)
	root := fakeVolumeHost(t)
	tracer.devices = &deviceNames{sysRoot: root, procRoot: root}
	tracer.stack = &deviceStack{sysRoot: root, deviceOf: fakeHostDeviceOf}
	tracer.mounts = func() ([]*procfs.MountInfo, error) { return mounts, nil }
	return tracer
}

func TestPodVolumesTracer(t *testing.T) {
	store := &fakePodVolumes{
		pods: []*informer.ObjectMeta{
			testPod("db-0", "uid-0", &informer.VolumeClaim{VolumeName: "data", ClaimName: "data-db-0"}),
			testPod("db-1", "uid-1", &informer.VolumeClaim{VolumeName: "data", ClaimName: "data-db-1"}),
			testPod("pending", "uid-2", &informer.VolumeClaim{VolumeName: "data", ClaimName: "unbound"}),
		},
		pvs: map[string]*informer.ObjectMeta{
			"default/data-db-0": testPV("pvc-csi", "data-db-0", ""),
			"default/data-db-1": testPV("pvc-local", "data-db-1", "/var/local-path-provisioner/pvc-local"),
		},
	}
	mounts := []*procfs.MountInfo{
		{MajorMinorVer: "252:0", MountPoint: "/var/lib/kubelet/pods/uid-0/volumes/kubernetes.io~csi/pvc-csi/mount"},
		{MajorMinorVer: "0:52", MountPoint: "/var/lib/kubelet/pods/uid-0/volumes/kubernetes.io~empty-dir/tmp"},
	}
	tracer := newTestPodVolumesTracer(t, store, mounts)

	stats := tracer.readStats()
	var volumes []ebpf.PodVolume
	for _, stat := range stats {
		assert.Equal(t, ebpf.StatTypePodVolume, stat.Type)
		assert.Equal(t, int64(1), stat.PodVolume.Value)
		assert.Equal(t, stat.PodVolume.PodName, stat.CommonAttrs.Metadata[attr.K8sPodName])
		assert.Equal(t, "db", stat.CommonAttrs.Metadata[attr.K8sOwnerName])
		assert.Equal(t, "StatefulSet", stat.CommonAttrs.Metadata[attr.K8sKind])
		volume := *stat.PodVolume
		volume.Value = 0
		volumes = append(volumes, volume)
	}
	common := ebpf.PodVolume{Namespace: "default", OwnerName: "db", OwnerKind: "StatefulSet", VolumeName: "data"}
	withDisk := func(pod, claim, pv, mounted, disk string) ebpf.PodVolume {
		v := common
		v.PodName, v.ClaimName, v.PersistentVolume, v.MountedDevice, v.Device = pod, claim, pv, mounted, disk
		return v
	}
	assert.ElementsMatch(t, []ebpf.PodVolume{
		// a CSI volume on an LVM volume over two disks
		withDisk("db-0", "data-db-0", "pvc-csi", "dm-0", "sda"),
		withDisk("db-0", "data-db-0", "pvc-csi", "dm-0", "sdb"),
		// a hostPath volume, which the kubelet doesn't mount
		withDisk("db-1", "data-db-1", "pvc-local", "nvme0n1", "nvme0n1"),
	}, volumes, "unbound claims have no device")

	// db-1 is gone: its volume is reported once more, as no longer mounted
	store.pods = store.pods[:1]
	stats = tracer.readStats()
	require.Len(t, stats, 3)
	var gone []*ebpf.Stat
	for _, stat := range stats {
		if stat.PodVolume.Value == 0 {
			gone = append(gone, stat)
		}
	}
	require.Len(t, gone, 1)
	assert.Equal(t, "db-1", gone[0].PodVolume.PodName)
	assert.Equal(t, "db", gone[0].CommonAttrs.Metadata[attr.K8sOwnerName], "with the labels of the series it ends")

	assert.Len(t, tracer.readStats(), 2, "only once")

	// a failed read of the mount table doesn't report the volumes as gone
	tracer.mounts = func() ([]*procfs.MountInfo, error) { return nil, errors.New("can't read") }
	assert.Empty(t, tracer.readStats())
	tracer.mounts = func() ([]*procfs.MountInfo, error) { return mounts, nil }
	stats = tracer.readStats()
	require.Len(t, stats, 2)
	for _, stat := range stats {
		assert.Equal(t, int64(1), stat.PodVolume.Value)
	}
}

func TestPodVolumesTracerWarnsOnceWithoutKubeletMounts(t *testing.T) {
	var logs bytes.Buffer
	defaultLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(defaultLogger) })

	podWithClaim := testPod("db-0", "uid-0", &informer.VolumeClaim{VolumeName: "data", ClaimName: "data-db-0"})
	store := &fakePodVolumes{pvs: map[string]*informer.ObjectMeta{
		"default/data-db-0": testPV("pvc-csi", "data-db-0", ""),
	}}
	hostMounts := []*procfs.MountInfo{{MajorMinorVer: "253:0", MountPoint: "/"}}
	kubeletMounts := []*procfs.MountInfo{
		{MajorMinorVer: "253:0", MountPoint: "/"},
		{MajorMinorVer: "252:0", MountPoint: "/var/lib/kubelet/pods/uid-0/volumes/kubernetes.io~csi/pvc-csi/mount"},
	}
	tracer := newTestPodVolumesTracer(t, store, hostMounts)

	// the steps follow each other, as the tracer remembers whether it warned
	steps := []struct {
		name          string
		podsWithClaim bool
		mounts        []*procfs.MountInfo
		warnings      int
	}{
		{name: "no pods with claims: nothing to tell", mounts: hostMounts, warnings: 0},
		{name: "pods with claims and no mount of the kubelet", podsWithClaim: true, mounts: hostMounts, warnings: 1},
		{name: "once", podsWithClaim: true, mounts: hostMounts, warnings: 1},
		{name: "no pods with claims again", mounts: hostMounts, warnings: 1},
		{name: "not again when the mounts were never visible in between", podsWithClaim: true, mounts: hostMounts, warnings: 1},
		{name: "the mounts of the kubelet are visible", podsWithClaim: true, mounts: kubeletMounts, warnings: 1},
		{name: "again once they were visible in between", podsWithClaim: true, mounts: hostMounts, warnings: 2},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			store.pods = nil
			if step.podsWithClaim {
				store.pods = []*informer.ObjectMeta{podWithClaim}
			}
			tracer.mounts = func() ([]*procfs.MountInfo, error) { return step.mounts, nil }
			tracer.readStats()
			assert.Equal(t, step.warnings, strings.Count(logs.String(), "no volume mount of the kubelet is visible"))
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

func TestVolumeMountDevice(t *testing.T) {
	mounts := []*procfs.MountInfo{
		{MajorMinorVer: "8:1", MountPoint: "/var/lib/kubelet/pods/uid-0/volumes/kubernetes.io~local-volume/pv-local"},
		{MajorMinorVer: "252:0", MountPoint: "/var/lib/k0s/kubelet/pods/uid-1/volumes/kubernetes.io~csi/pv-csi/mount"},
		{MajorMinorVer: "8:2", MountPoint: "/var/lib/kubelet/pods/uid-1/volumes/kubernetes.io~csi/pv-other/mount"},
	}
	major, minor, ok := volumeMountDevice(mounts, "uid-0", "pv-local")
	require.True(t, ok)
	assert.Equal(t, [2]uint32{8, 1}, [2]uint32{major, minor})

	major, minor, ok = volumeMountDevice(mounts, "uid-1", "pv-csi")
	require.True(t, ok, "under any kubelet root directory")
	assert.Equal(t, [2]uint32{252, 0}, [2]uint32{major, minor})

	_, _, ok = volumeMountDevice(mounts, "uid-0", "pv-csi")
	assert.False(t, ok, "the volume of another pod")
}
