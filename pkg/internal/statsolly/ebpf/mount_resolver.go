// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
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
// previously held that dev_t. invalidateMountCache exists for immediate,
// event-driven invalidation, but nothing currently calls it outside tests, so
// the TTL is what actually bounds staleness in production.
const mountCacheTTL = time.Minute

type mountCacheEntry struct {
	info       MountInfo
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
	if ok && time.Since(entry.resolvedAt) < mountCacheTTL {
		return entry.info, true
	}

	info, ok := scanForMount(sDev)
	if !ok {
		return MountInfo{}, false
	}

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
	mountCache[sDev] = mountCacheEntry{info: info, resolvedAt: time.Now()}
	mountMu.Unlock()

	return info, true
}

// invalidateMountCache drops all cached dev_t -> MountInfo resolutions.
//
// Unlike a block device's cache, this one must not be permanent: NFS and CSI
// mounts appear and disappear with pod lifecycle, so a stale entry would keep
// attributing I/O to a deleted pod's volume. Callers are expected to
// invalidate as mount state changes; this only exposes the primitive. The
// mountCacheTTL above provides a fallback bound when nothing does.
func invalidateMountCache() {
	mountMu.Lock()
	mountCache = map[uint32]mountCacheEntry{}
	mountOrder = nil
	mountMu.Unlock()
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
