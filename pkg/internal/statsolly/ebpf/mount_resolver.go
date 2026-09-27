// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/procfs"
)

// mountInfoPath is the mountinfo file to scan, in the format documented by
// proc(5). It defaults to this process's real view of the mount namespace;
// tests point it at a fixture.
var mountInfoPath = "/proc/self/mountinfo"

// kubeletVolumeRe extracts the pod UID, volume plugin, and volume name from a
// kubelet volume mount point, e.g.
// ".../pods/<uid>/volumes/kubernetes.io~<type>/<name>". CSI mounts add a
// trailing "/mount" segment; the third group stops at the next "/" so it
// captures "<name>", never "mount".
var kubeletVolumeRe = regexp.MustCompile(`/pods/([0-9a-f-]{36})/volumes/kubernetes\.io~([^/]+)/([^/]+)`)

// MountInfo describes the Kubernetes volume backing a mounted filesystem.
type MountInfo struct {
	PodUID     string
	PVName     string
	VolumeType string
	Server     string
}

// maxCachedMounts bounds mountCache so a node churning through many transient
// NFS/CSI mounts cannot grow it without limit.
const maxCachedMounts = 4096

// mountCacheTTL bounds how long a resolution is trusted before it is treated
// as a miss and re-resolved. dev_t is a kernel-assigned anonymous superblock
// number that gets reused once a mount is torn down, so an entry cached
// forever could attribute a new pod/volume's I/O to whatever pod/volume
// previously held that dev_t.
const mountCacheTTL = time.Minute

// mountCacheNegativeTTL bounds how long a device that did not resolve to a
// kubelet volume mount is served from cache before scanForMount is retried.
// Every non-PV mount (nfs/cifs/ceph/fuse mounts that aren't kubelet volumes,
// or any other filesystem event whose device never resolves) is a negative
// resolution, and without caching it, resolveMount would re-parse
// /proc/self/mountinfo on every such event.
const mountCacheNegativeTTL = 15 * time.Second

type mountCacheEntry struct {
	info       MountInfo
	found      bool
	resolvedAt time.Time
}

var (
	mountMu    sync.RWMutex
	mountCache = map[uint32]mountCacheEntry{}
	mountOrder []uint32 // insertion order, oldest first, for FIFO eviction
)

// resolveMount maps a filesystem superblock device number (s_dev, as reported
// by eBPF) to the Kubernetes volume it belongs to.
func resolveMount(sDev uint32) (MountInfo, bool) {
	mountMu.RLock()
	entry, ok := mountCache[sDev]
	mountMu.RUnlock()
	if ok {
		ttl := mountCacheTTL
		if !entry.found {
			ttl = mountCacheNegativeTTL
		}
		if time.Since(entry.resolvedAt) < ttl {
			return entry.info, entry.found
		}
	}

	info, found := scanForMount(sDev)

	mountMu.Lock()
	if _, exists := mountCache[sDev]; !exists {
		if len(mountCache) >= maxCachedMounts {
			// Evict the oldest entry rather than the whole cache, so filling
			// the cache doesn't force every other cached device to be
			// rescanned on its next lookup too.
			oldest := mountOrder[0]
			mountOrder = mountOrder[1:]
			delete(mountCache, oldest)
		}
		mountOrder = append(mountOrder, sDev)
	}
	mountCache[sDev] = mountCacheEntry{info: info, found: found, resolvedAt: time.Now()}
	mountMu.Unlock()

	return info, found
}

// scanForMount reads mountInfoPath looking for the mount whose superblock
// device number is sDev, and parses it as a kubelet volume mount.
func scanForMount(sDev uint32) (MountInfo, bool) {
	mounts, err := scanMounts()
	if err != nil {
		return MountInfo{}, false
	}

	target := fmtDev(sDev)

	for _, m := range mounts {
		if m.MajorMinorVer != target {
			continue
		}

		if info, ok := parseKubeletMount(m.MountPoint, m.Source); ok {
			return info, true
		}
	}

	return MountInfo{}, false
}

// scanMounts parses mountInfoPath via procfs. procfs.FS.GetMounts always
// reads "<root>/self/mountinfo", so the FS root is mountInfoPath with those
// last two path elements stripped back off.
func scanMounts() ([]*procfs.MountInfo, error) {
	root := filepath.Dir(filepath.Dir(mountInfoPath))

	fs, err := procfs.NewFS(root)
	if err != nil {
		return nil, err
	}

	return fs.GetMounts()
}

// parseKubeletMount extracts Kubernetes volume identity from a mount point
// and its source, e.g. "10.96.84.126:/export/pvc-b3befffd".
func parseKubeletMount(mountPoint, source string) (MountInfo, bool) {
	match := kubeletVolumeRe.FindStringSubmatch(mountPoint)
	if match == nil {
		return MountInfo{}, false
	}

	return MountInfo{
		PodUID:     match[1],
		VolumeType: match[2],
		PVName:     match[3],
		Server:     mountServer(source),
	}, true
}

// mountServer returns the part of a mount source before its first ":", or
// the whole source when it has none.
func mountServer(source string) string {
	if idx := strings.IndexByte(source, ':'); idx >= 0 {
		return source[:idx]
	}
	return source
}

// WarnIfNoKubeletVolumeMounts scans the current mount table once and warns if
// no mount point looks like a kubelet volume mount. This is the operator-facing
// signal for the most common storage-metrics misconfiguration: the container
// not having /var/lib/kubelet mounted with mountPropagation: HostToContainer,
// which silently prevents persistent volume attribution from ever working.
func WarnIfNoKubeletVolumeMounts(log *slog.Logger) {
	mounts, err := scanMounts()
	if err != nil {
		log.Warn("cannot scan mounts for kubelet volumes; persistent volume attribution will be unavailable", "error", err)
		return
	}

	for _, m := range mounts {
		if kubeletVolumeRe.MatchString(m.MountPoint) {
			return
		}
	}

	log.Warn("no kubelet volume mounts visible; persistent volume attribution needs /var/lib/kubelet mounted with mountPropagation: HostToContainer")
}
