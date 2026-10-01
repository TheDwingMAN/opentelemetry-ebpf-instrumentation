// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"testing"
	"time"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
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
