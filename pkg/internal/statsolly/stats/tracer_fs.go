// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/prometheus/procfs"
)

// filesystemsRefreshPeriod is the time between two reads of the mount table. It is read again
// periodically even when it knows every device, as the kernel gives the numbers of unmounted
// filesystems to new ones, e.g. the overlay filesystems of containers.
const filesystemsRefreshPeriod = 30 * time.Second

// hostInitPID is the PID of the init process of the host, when OBI shares its PID namespace
const hostInitPID = 1

// kubensMount is where OpenShift's kubens.service pins the mount namespace of the kubelet and
// CRI-O, in the root of the host
const kubensMount = "run/kubens/mnt"

// kubeletVolumeMount matches the mount points of the volumes of the pods:
// <kubelet root>/pods/<pod UID>/volumes/
var kubeletVolumeMount = regexp.MustCompile(`/pods/[^/]+/volumes/`)

// workloadMount matches the mount points that the kubelet and the container runtimes create for
// each pod or container: the volumes of the pods (<kubelet root>/pods/<pod UID>/volumes/ and
// volume-subpaths/), and the root filesystems of the containers (.../overlay/<id>/merged,
// .../overlay2/<id>/merged and .../io.containerd.runtime.v2.task/<namespace>/<id>/rootfs). The
// staging directory of a CSI volume (.../globalmount) is not one of them: the kubelet mounts it
// once per volume on the node, at a path that doesn't change with the pods.
var workloadMount = regexp.MustCompile(
	`/pods/[^/]+/volume(s|-subpaths)/|/overlay2?/[^/]+/merged$|/io\.containerd\.runtime\.v2\.task/[^/]+/[^/]+/rootfs$`)

type filesystem struct {
	mountpoint string
	fsType     string
}

// filesystems resolves the device numbers of filesystems into where they are mounted and their
// type, from the mount table of the host (that of PID 1, when OBI shares the host PID namespace),
// or of the kubelet's mount namespace
type filesystems struct {
	mounts      func() ([]*procfs.MountInfo, error)
	now         func() time.Time
	byDev       map[uint32]filesystem
	lastRefresh time.Time
}

func newFilesystems() *filesystems {
	return &filesystems{
		mounts: func() ([]*procfs.MountInfo, error) { return readHostMounts(procfs.DefaultMountPoint) },
		now:    time.Now,
	}
}

// readHostMounts reads the mount table that has the volumes that the kubelet mounts for the pods:
// that of the host (PID 1), or, when the kubelet runs in a mount namespace of its own, like with
// OpenShift's mount namespace encapsulation, that of a process in that namespace, whose mounts the
// host doesn't see
func readHostMounts(procRoot string) ([]*procfs.MountInfo, error) {
	fs, err := procfs.NewFS(procRoot)
	if err != nil {
		return nil, err
	}
	mounts, err := fs.GetProcMounts(hostInitPID)
	if err != nil || hasKubeletVolumeMount(mounts) {
		return mounts, err
	}
	if kubeletMounts, ok := kubensMounts(fs, procRoot); ok {
		return kubeletMounts, nil
	}
	return mounts, nil
}

func hasKubeletVolumeMount(mounts []*procfs.MountInfo) bool {
	return slices.ContainsFunc(mounts, func(m *procfs.MountInfo) bool {
		return kubeletVolumeMount.MatchString(m.MountPoint)
	})
}

// kubensMounts reads the mount table of a process in the mount namespace that kubens pins. The
// process is found by the namespace and not as the kubelet, which the namespace outlives when it
// restarts.
func kubensMounts(fs procfs.FS, procRoot string) ([]*procfs.MountInfo, bool) {
	pinned, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(hostInitPID), "root", kubensMount))
	if err != nil {
		return nil, false
	}
	procs, err := fs.AllProcs()
	if err != nil {
		return nil, false
	}
	for _, proc := range procs {
		namespace, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(proc.PID), "ns", "mnt"))
		if err != nil || !os.SameFile(pinned, namespace) {
			continue
		}
		if mounts, err := proc.MountInfo(); err == nil {
			return mounts, true
		}
	}
	return nil, false
}

// lookup returns the filesystem of a kernel dev_t, from a mount table read at most
// filesystemsRefreshPeriod ago
func (f *filesystems) lookup(sDev uint32) (filesystem, bool) {
	if sDev == 0 {
		return filesystem{}, false
	}
	if f.lastRefresh.IsZero() || f.now().Sub(f.lastRefresh) >= filesystemsRefreshPeriod {
		f.refresh()
	}
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
		byDev[dev] = filesystem{mountpoint: mountpointOf(mount), fsType: mount.FSType}
	}
	f.byDev = byDev
}

// preferredMount picks, among the mounts of the same filesystem, the mounts of the host over those
// of the pods and containers, then those of its root directory over bind mounts of its
// subdirectories, then the shortest mountpoint
func preferredMount(candidate, current *procfs.MountInfo) bool {
	if workloadMount.MatchString(candidate.MountPoint) != workloadMount.MatchString(current.MountPoint) {
		return !workloadMount.MatchString(candidate.MountPoint)
	}
	if (candidate.Root == "/") != (current.Root == "/") {
		return candidate.Root == "/"
	}
	return len(candidate.MountPoint) < len(current.MountPoint)
}

// mountpointOf returns the mountpoint that a mount gives the filesystem, none for the mounts of
// the pods and containers: their paths change with each pod or container
func mountpointOf(mount *procfs.MountInfo) string {
	if workloadMount.MatchString(mount.MountPoint) {
		return ""
	}
	return mount.MountPoint
}
