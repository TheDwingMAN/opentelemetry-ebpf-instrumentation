// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"bytes"
	"errors"
	"log/slog"
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
