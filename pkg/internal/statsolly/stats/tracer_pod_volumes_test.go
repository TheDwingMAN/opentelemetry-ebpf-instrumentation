// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"errors"
	"os"
	"path/filepath"
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
// does, with /dev/block/<maj:min> linking to it. Partitions are subdirectories of their disk, and
// slaves link to the directories of the devices below.
func fakeSysDevice(t *testing.T, root, path, numbers string, slaves ...string) {
	t.Helper()
	dir := filepath.Join(root, "devices", path)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	name := filepath.Base(path)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "uevent"), []byte("DEVNAME="+name+"\n"), 0o644))
	if filepath.Base(filepath.Dir(path)) != "block" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "partition"), []byte("1\n"), 0o644))
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
	return root
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
	tracer := NewPodVolumesTracer(store, "node-1")
	tracer.devices = &deviceNames{sysRoot: fakeVolumeHost(t)}
	tracer.mounts = func() ([]*procfs.MountInfo, error) { return mounts, nil }
	tracer.deviceOf = func(path string) (uint32, uint32, error) {
		if path == "/var/local-path-provisioner/pvc-local" {
			return 259, 0, nil
		}
		return 0, 0, errors.New("no such path")
	}
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
}

func TestPhysicalDisks(t *testing.T) {
	root := fakeVolumeHost(t)
	disks := func(numbers string) []string {
		return physicalDisks(filepath.Join(root, "dev", "block", numbers), maxDeviceStackDepth)
	}
	assert.Equal(t, []string{"sda"}, disks("8:0"), "a disk")
	assert.Equal(t, []string{"sda"}, disks("8:1"), "a partition")
	assert.ElementsMatch(t, []string{"sda", "sdb"}, disks("252:0"), "an LVM volume over two disks")
	assert.Empty(t, disks("9:9"), "an unknown device")
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
