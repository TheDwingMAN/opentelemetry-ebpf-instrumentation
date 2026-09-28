// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"fmt"
	"time"

	"github.com/prometheus/procfs"
)

// filesystemsRefreshPeriod is the minimum time between two reads of the mount table
const filesystemsRefreshPeriod = 30 * time.Second

type filesystem struct {
	mountpoint string
	fsType     string
}

// filesystems resolves the device numbers of filesystems into where they are mounted and their
// type, from the mount table of the host (that of PID 1, when OBI shares the host PID namespace)
type filesystems struct {
	mounts      func() ([]*procfs.MountInfo, error)
	now         func() time.Time
	byDev       map[uint32]filesystem
	lastRefresh time.Time
}

func newFilesystems() *filesystems {
	return &filesystems{
		mounts: func() ([]*procfs.MountInfo, error) { return procfs.GetProcMounts(1) },
		now:    time.Now,
	}
}

// lookup returns the filesystem of a kernel dev_t. It reads the mount table again when it doesn't
// know the device, at most once per filesystemsRefreshPeriod.
func (f *filesystems) lookup(sDev uint32) (filesystem, bool) {
	if sDev == 0 {
		return filesystem{}, false
	}
	if fs, ok := f.byDev[sDev]; ok {
		return fs, true
	}
	if !f.lastRefresh.IsZero() && f.now().Sub(f.lastRefresh) < filesystemsRefreshPeriod {
		return filesystem{}, false
	}
	f.refresh()
	fs, ok := f.byDev[sDev]
	return fs, ok
}

func (f *filesystems) refresh() {
	f.lastRefresh = f.now()
	mounts, err := f.mounts()
	if err != nil {
		dtlog().Debug("can't read the mount table", "error", err)
		return
	}
	byDev := map[uint32]filesystem{}
	chosen := map[uint32]*procfs.MountInfo{}
	for _, mount := range mounts {
		var major, minor uint32
		if _, err := fmt.Sscanf(mount.MajorMinorVer, "%d:%d", &major, &minor); err != nil {
			continue
		}
		dev := major<<kernelDevMinorBits | minor
		if current, ok := chosen[dev]; ok && !preferredMount(mount, current) {
			continue
		}
		chosen[dev] = mount
		byDev[dev] = filesystem{mountpoint: mount.MountPoint, fsType: mount.FSType}
	}
	f.byDev = byDev
}

// preferredMount picks, among the mounts of the same filesystem, those of its root directory over
// bind mounts of its subdirectories, then the shortest mountpoint
func preferredMount(candidate, current *procfs.MountInfo) bool {
	if (candidate.Root == "/") != (current.Root == "/") {
		return candidate.Root == "/"
	}
	return len(candidate.MountPoint) < len(current.MountPoint)
}
