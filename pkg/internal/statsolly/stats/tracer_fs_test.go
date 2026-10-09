// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fakeFilesystems(mounts ...*procfs.MountInfo) *filesystems {
	now := time.Now()
	return &filesystems{
		mounts: func() ([]*procfs.MountInfo, error) { return mounts, nil },
		now:    func() time.Time { return now },
	}
}

func TestFilesystemsResolveTheMountOfADevice(t *testing.T) {
	fs := fakeFilesystems(
		&procfs.MountInfo{MajorMinorVer: "259:1", Root: "/", MountPoint: "/", FSType: "ext4"},
		// a bind mount of a directory of the same filesystem
		&procfs.MountInfo{MajorMinorVer: "259:1", Root: "/var/lib/data", MountPoint: "/d", FSType: "ext4"},
		// the same filesystem mounted twice
		&procfs.MountInfo{MajorMinorVer: "253:0", Root: "/", MountPoint: "/var/lib/kubelet/pods/1/volumes/x", FSType: "xfs"},
		&procfs.MountInfo{MajorMinorVer: "253:0", Root: "/", MountPoint: "/data", FSType: "xfs"},
	)

	root, ok := fs.lookup(kernelDev(259, 1))
	assert.True(t, ok)
	assert.Equal(t, filesystem{mountpoint: "/", fsType: "ext4"}, root, "the mount of the root of the filesystem")

	data, ok := fs.lookup(kernelDev(253, 0))
	assert.True(t, ok)
	assert.Equal(t, filesystem{mountpoint: "/data", fsType: "xfs"}, data, "the shortest mountpoint")

	_, ok = fs.lookup(0)
	assert.False(t, ok, "sync(2) has no filesystem")
	_, ok = fs.lookup(kernelDev(8, 1))
	assert.False(t, ok, "an unmounted filesystem")
}

func TestFilesystemsLeaveOutTheMountsOfPodsAndContainers(t *testing.T) {
	const pod = "/var/lib/kubelet/pods/0f3d2a6e-8c1b-4f6e-9d4a-2b7c5e1f9a30"
	// longer than the mount of the volume in the pod
	hostMount := "/mnt/local-storage/" + strings.Repeat("d", 100)
	// longer than the mount of the CSI volume in the pod
	csiStaging := "/var/lib/kubelet/plugins/kubernetes.io/csi/ebs.csi.aws.com/" +
		"4f2c1d3b6a5e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a8/globalmount"
	fs := fakeFilesystems(
		// a local PersistentVolume, mounted on the host and in a pod
		&procfs.MountInfo{MajorMinorVer: "8:16", Root: "/", MountPoint: pod + "/volumes/kubernetes.io~local-volume/pv-1", FSType: "xfs"},
		&procfs.MountInfo{MajorMinorVer: "8:16", Root: "/", MountPoint: hostMount, FSType: "xfs"},
		// a CSI volume, staged by the kubelet and published in a pod
		&procfs.MountInfo{MajorMinorVer: "253:4", Root: "/", FSType: "ext4", MountPoint: csiStaging},
		&procfs.MountInfo{
			MajorMinorVer: "253:4", Root: "/", FSType: "ext4",
			MountPoint: pod + "/volumes/kubernetes.io~csi/pvc-6b1e0c2d-3f4a-4b5c-8d9e-0f1a2b3c4d5e/mount",
		},
		&procfs.MountInfo{
			MajorMinorVer: "253:4", Root: "/data", FSType: "ext4",
			MountPoint: pod + "/volume-subpaths/data/app/0",
		},
		// a CSI volume that its driver doesn't stage, only mounted in a pod
		&procfs.MountInfo{
			MajorMinorVer: "0:61", Root: "/", FSType: "nfs4",
			MountPoint: pod + "/volumes/kubernetes.io~csi/pvc-2a7d9e4b-1c3f-4e5a-9b8d-7f6e5d4c3b2a/mount",
		},
		// the root filesystems of containers of CRI-O and containerd
		&procfs.MountInfo{
			MajorMinorVer: "0:312", Root: "/", FSType: "overlay",
			MountPoint: "/var/lib/containers/storage/overlay/8c7e1b0a9f2d3e4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c/merged",
		},
		&procfs.MountInfo{
			MajorMinorVer: "0:313", Root: "/", FSType: "overlay",
			MountPoint: "/run/containerd/io.containerd.runtime.v2.task/k8s.io/2d4f6b8a0c1e3d5f7a9b1c3e5d7f9a0b2c4e6d8f0a1b3c5e7d9f1a2b4c6e8d0f/rootfs",
		},
	)

	local, ok := fs.lookup(kernelDev(8, 16))
	assert.True(t, ok)
	assert.Equal(t, filesystem{mountpoint: hostMount, fsType: "xfs"}, local,
		"the mount of the host, although the mount in the pod is shorter")

	csi, ok := fs.lookup(kernelDev(253, 4))
	assert.True(t, ok)
	assert.Equal(t, filesystem{mountpoint: csiStaging, fsType: "ext4"}, csi,
		"the staging directory of the CSI volume, a path per volume, although the mount in the pod is shorter")

	for _, dev := range []uint32{kernelDev(0, 61), kernelDev(0, 312), kernelDev(0, 313)} {
		fsys, ok := fs.lookup(dev)
		assert.True(t, ok)
		assert.Empty(t, fsys.mountpoint, "only mounted for pods or containers: a mountpoint per pod or container")
		assert.NotEmpty(t, fsys.fsType, "the type is the same for every pod or container")
	}
}

func TestFilesystemsRereadTheMountTablePeriodically(t *testing.T) {
	var reads int
	var mounts []*procfs.MountInfo
	now := time.Now()
	fs := &filesystems{
		mounts: func() ([]*procfs.MountInfo, error) { reads++; return mounts, nil },
		now:    func() time.Time { return now },
	}
	_, ok := fs.lookup(kernelDev(8, 1))
	assert.False(t, ok)

	mounts = []*procfs.MountInfo{{MajorMinorVer: "8:1", Root: "/", MountPoint: "/mnt", FSType: "ext4"}}
	_, ok = fs.lookup(kernelDev(8, 1))
	assert.False(t, ok, "not read again right away")
	assert.Equal(t, 1, reads)

	now = now.Add(filesystemsRefreshPeriod)
	mounted, ok := fs.lookup(kernelDev(8, 1))
	assert.True(t, ok, "read again once the period passed")
	assert.Equal(t, "/mnt", mounted.mountpoint)

	// the filesystem was unmounted, and its device number given to another one
	mounts = []*procfs.MountInfo{{MajorMinorVer: "8:1", Root: "/", MountPoint: "/other", FSType: "xfs"}}
	mounted, _ = fs.lookup(kernelDev(8, 1))
	assert.Equal(t, "/mnt", mounted.mountpoint, "not read again right away")
	now = now.Add(filesystemsRefreshPeriod)
	mounted, _ = fs.lookup(kernelDev(8, 1))
	assert.Equal(t, filesystem{mountpoint: "/other", fsType: "xfs"}, mounted, "read again once the period passed, even for known devices")
	assert.Equal(t, 3, reads)
}

const (
	hostVolumeMount      = "/var/lib/kubelet/pods/uid-0/volumes/kubernetes.io~csi/pvc-host/mount"
	kubensVolumeMount    = "/var/lib/kubelet/pods/uid-1/volumes/kubernetes.io~csi/pvc-kubens/mount"
	containerVolumeMount = "/var/lib/kubelet/pods/uid-2/volumes/kubernetes.io~csi/pvc-container/mount"
)

// fakeNamespace returns the file of a namespace of a fake procfs root, which the ns links of its
// processes point to, like the kernel's nsfs files
func fakeNamespace(t *testing.T, procRoot, name string) string {
	t.Helper()
	dir := filepath.Join(procRoot, "namespaces")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, nil, 0o644))
	return path
}

// fakeProcess creates /proc/<pid> of a fake procfs root, with a mount table of the mount points
// and a mount namespace
func fakeProcess(t *testing.T, procRoot string, pid int, namespace string, mountPoints ...string) {
	t.Helper()
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "ns"), 0o755))
	var table strings.Builder
	for i, mountPoint := range mountPoints {
		fmt.Fprintf(&table, "%d 1 253:%d / %s rw,relatime - xfs /dev/vda1 rw\n", i+20, i, mountPoint)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mountinfo"), []byte(table.String()), 0o644))
	require.NoError(t, os.Symlink(fakeNamespace(t, procRoot, namespace), filepath.Join(dir, "ns", "mnt")))
}

// fakeKubensPin pins the "kubens" mount namespace at /run/kubens/mnt in the root of the host of a
// fake procfs root
func fakeKubensPin(t *testing.T, procRoot string) {
	t.Helper()
	pin := filepath.Join(procRoot, strconv.Itoa(hostInitPID), "root", kubensMount)
	require.NoError(t, os.MkdirAll(filepath.Dir(pin), 0o755))
	require.NoError(t, os.Symlink(fakeNamespace(t, procRoot, "kubens"), pin))
}

func TestReadHostMounts(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, procRoot string)
		want  []string
	}{{
		name: "the table of the host when it has the mounts of the kubelet",
		setup: func(t *testing.T, procRoot string) {
			fakeProcess(t, procRoot, hostInitPID, "host", "/", hostVolumeMount)
			fakeKubensPin(t, procRoot)
			fakeProcess(t, procRoot, 901, "kubens", "/", kubensVolumeMount)
		},
		want: []string{"/", hostVolumeMount},
	}, {
		name: "the table of the namespace that kubens pins",
		setup: func(t *testing.T, procRoot string) {
			fakeProcess(t, procRoot, hostInitPID, "host", "/")
			fakeKubensPin(t, procRoot)
			fakeProcess(t, procRoot, 812, "kubens", "/", kubensVolumeMount)
			fakeProcess(t, procRoot, 901, "kubens", "/", kubensVolumeMount)
			fakeProcess(t, procRoot, 4000, "container", "/", containerVolumeMount)
		},
		want: []string{"/", kubensVolumeMount},
	}, {
		name: "the table of another process of the namespace while the kubelet restarts",
		setup: func(t *testing.T, procRoot string) {
			fakeProcess(t, procRoot, hostInitPID, "host", "/")
			fakeKubensPin(t, procRoot)
			fakeProcess(t, procRoot, 812, "kubens", "/", kubensVolumeMount)
		},
		want: []string{"/", kubensVolumeMount},
	}, {
		name: "the table of the next process of the namespace when one can't be read",
		setup: func(t *testing.T, procRoot string) {
			fakeProcess(t, procRoot, hostInitPID, "host", "/")
			fakeKubensPin(t, procRoot)
			// the processes come in the order of the directory, which is ascending on /proc only: the
			// readable one is created between unreadable ones, for it not to be listed first in creation
			// order or its reverse (tmpfs), and to be unlikely to be in hash order (ext4)
			const readable = 900
			for _, pid := range []int{810, 811, readable, 901, 902} {
				fakeProcess(t, procRoot, pid, "kubens", "/", kubensVolumeMount)
				if pid != readable {
					require.NoError(t, os.Remove(filepath.Join(procRoot, strconv.Itoa(pid), "mountinfo")))
				}
			}
		},
		want: []string{"/", kubensVolumeMount},
	}, {
		name: "the table of the host when no mount namespace is pinned",
		setup: func(t *testing.T, procRoot string) {
			fakeProcess(t, procRoot, hostInitPID, "host", "/")
			fakeProcess(t, procRoot, 901, "private", "/", kubensVolumeMount)
		},
		want: []string{"/"},
	}, {
		name: "the table of the host when no process is in the pinned namespace",
		setup: func(t *testing.T, procRoot string) {
			fakeProcess(t, procRoot, hostInitPID, "host", "/")
			fakeKubensPin(t, procRoot)
			fakeProcess(t, procRoot, 4000, "container", "/", kubensVolumeMount)
		},
		want: []string{"/"},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			procRoot := t.TempDir()
			tt.setup(t, procRoot)

			mounts, err := readHostMounts(procRoot)
			require.NoError(t, err)
			var mountPoints []string
			for _, mount := range mounts {
				mountPoints = append(mountPoints, mount.MountPoint)
			}
			assert.Equal(t, tt.want, mountPoints)
		})
	}
}

func TestReadHostMountsWithoutTheHostInit(t *testing.T) {
	_, err := readHostMounts(t.TempDir())
	assert.Error(t, err, "an error, for the tracers to keep their previous mount table")
}
