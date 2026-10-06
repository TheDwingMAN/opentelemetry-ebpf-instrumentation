// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/procfs"
)

// mountInfoPath is the mountinfo file to scan, in the format documented by
// proc(5). It defaults to the host's init process rather than this one.
//
// The kubelet's volume mounts live in the host mount namespace. Reading them
// from this process would require bind-mounting /var/lib/kubelet into the
// container with mountPropagation: HostToContainer, which is intrusive for a
// DaemonSet to ask for. With hostPID -- already required for attributing I/O
// to a pod -- the host's init is visible, and its mount table lists those
// mounts. Only the paths are parsed, never opened, so visibility is enough.
//
// Tests point this at a fixture.
var mountInfoPath = hostMountInfoPath

const (
	hostMountInfoPath = "/proc/1/mountinfo"
	selfMountInfoPath = "/proc/self/mountinfo"
)

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
	// Shared is set when more than one pod has this superblock mounted, as
	// happens with a ReadWriteMany volume. PodUID is then one of several and
	// must not be used to attribute I/O; the volume itself is still certain.
	Shared bool
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

	mountWatchOnce sync.Once
)

// invalidateMountCache drops every cached resolution, so the next lookup of
// each device rescans the mount table.
func invalidateMountCache() {
	mountMu.Lock()
	defer mountMu.Unlock()
	clear(mountCache)
	mountOrder = nil
}

// resolveMount maps a filesystem superblock device number (s_dev, as reported
// by eBPF) to the Kubernetes volume it belongs to.
func resolveMount(sDev uint32) (MountInfo, bool) {
	// Shared decides whether a mount may name a pod, and a second pod can
	// mount the volume at any moment. The TTLs alone would let a cached
	// single-owner entry name the wrong pod for up to a minute after that, so
	// any change to the mount table drops the cache instead.
	mountWatchOnce.Do(func() { watchMountTable(invalidateMountCache, mountInfoPath, selfMountInfoPath) })

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

	// Every pod mounting a shared volume has its own kubelet mount of the
	// same superblock, so keep scanning after the first hit: the volume is
	// the same for all of them, but the pod is only known if there is one.
	var found MountInfo
	var ok bool
	for _, m := range mounts {
		if m.MajorMinorVer != target {
			continue
		}

		info, parsed := parseKubeletMount(m.MountPoint, m.Source)
		if !parsed {
			continue
		}
		if !ok {
			found, ok = info, true
			continue
		}
		if info.PodUID != found.PodUID {
			found.Shared = true
		}
	}

	return found, ok
}

// scanMounts parses mountInfoPath via procfs. procfs.FS.GetMounts always
// reads "<root>/self/mountinfo", so the FS root is mountInfoPath with those
// last two path elements stripped back off.
func scanMounts() ([]*procfs.MountInfo, error) {
	mounts, err := mountsFrom(mountInfoPath)
	if err != nil {
		if mountInfoPath != hostMountInfoPath {
			return nil, err
		}
		// Without hostPID there is no host init to read, so fall back to this
		// process's own table. Attribution then only covers volumes actually
		// mounted into this container.
		return mountsFrom(selfMountInfoPath)
	}

	if hasKubeletVolumeMount(mounts) {
		return mounts, nil
	}

	// OpenShift's mount namespace encapsulation (kubens.service) runs the
	// kubelet and CRI-O in a mount namespace of their own, so their volume
	// mounts never appear in init's table. The kubelet's own table has them.
	if kubeletTable, ok := kubeletNamespaceMounts(); ok {
		return kubeletTable, nil
	}
	return mounts, nil
}

func hasKubeletVolumeMount(mounts []*procfs.MountInfo) bool {
	for _, m := range mounts {
		if kubeletVolumeRe.MatchString(m.MountPoint) {
			return true
		}
	}
	return false
}

// procRoot is where the kubelet process is looked up. Tests point it at a
// fixture.
var procRoot = "/proc"

// kubeletSearchInterval bounds how often /proc is walked for a kubelet in a
// mount namespace other than init's. On most nodes there is none, and the
// mount table is rescanned on every cache miss.
const kubeletSearchInterval = 30 * time.Second

var (
	kubeletMu sync.Mutex
	// kubeletNS is the mount namespace, as its ns/mnt link reads, of a
	// kubelet running outside init's; kubeletPID is a process in it.
	kubeletNS         string
	kubeletPID        string
	kubeletSearchedAt time.Time
	kubeletWatchOnce  sync.Once
)

// kubeletNamespaceMounts returns the kubelet's mount table when the kubelet
// runs in a mount namespace other than init's.
func kubeletNamespaceMounts() ([]*procfs.MountInfo, bool) {
	kubeletMu.Lock()
	defer kubeletMu.Unlock()

	if kubeletNS != "" {
		// The namespace outlives the kubelet: while it restarts, CRI-O and
		// every conmon are still in it, with the same table. So follow the
		// namespace, not the process, and never wait for the next search.
		if !inMountNamespace(procRoot, kubeletPID, kubeletNS) {
			kubeletPID = findInMountNamespace(procRoot, kubeletNS)
		}
		if kubeletPID != "" {
			if mounts, err := mountsFrom(mountInfoOf(kubeletPID)); err == nil {
				return mounts, true
			}
		}
		kubeletNS, kubeletPID = "", ""
	}

	if time.Since(kubeletSearchedAt) < kubeletSearchInterval {
		return nil, false
	}
	kubeletSearchedAt = time.Now()

	pid, ns, ok := findKubelet(procRoot)
	if !ok {
		return nil, false
	}
	if mounts, err := mountsFrom(mountInfoOf(pid)); err != nil || !hasKubeletVolumeMount(mounts) {
		return nil, false
	}
	// The watch on init's table does not see this namespace. An open
	// mountinfo holds its namespace, so one watch outlives any kubelet. It
	// only reports changes after it opens, so the table is read after it.
	kubeletWatchOnce.Do(func() { watchMountTable(invalidateMountCache, mountInfoOf(pid)) })
	mounts, err := mountsFrom(mountInfoOf(pid))
	if err != nil {
		return nil, false
	}
	kubeletNS, kubeletPID = ns, pid
	return mounts, true
}

func mountInfoOf(pid string) string { return filepath.Join(procRoot, pid, "mountinfo") }

// findKubelet returns the PID and mount namespace of the node's kubelet when
// that namespace differs from init's. The node's kubelet shares init's PID
// namespace; a kubelet inside a container (kind, a nested cluster in a CI
// pod) does not, and is skipped.
func findKubelet(root string) (pid, mntNS string, ok bool) {
	initMnt, err1 := os.Readlink(filepath.Join(root, "1", "ns", "mnt"))
	initPid, err2 := os.Readlink(filepath.Join(root, "1", "ns", "pid"))
	if err1 != nil || err2 != nil {
		return "", "", false
	}
	for _, p := range procPIDs(root) {
		comm, err := os.ReadFile(filepath.Join(root, p, "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "kubelet" {
			continue
		}
		mnt, err := os.Readlink(filepath.Join(root, p, "ns", "mnt"))
		if err != nil || mnt == initMnt {
			continue
		}
		if pidNS, err := os.Readlink(filepath.Join(root, p, "ns", "pid")); err != nil || pidNS != initPid {
			continue
		}
		return p, mnt, true
	}
	return "", "", false
}

// findInMountNamespace returns any process in mount namespace ns.
func findInMountNamespace(root, ns string) string {
	for _, p := range procPIDs(root) {
		if inMountNamespace(root, p, ns) {
			return p
		}
	}
	return ""
}

func inMountNamespace(root, pid, ns string) bool {
	if pid == "" {
		return false
	}
	link, err := os.Readlink(filepath.Join(root, pid, "ns", "mnt"))
	return err == nil && link == ns
}

func procPIDs(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	pids := make([]string, 0, len(entries))
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, e.Name())
		}
	}
	return pids
}

// mountsFrom parses a mountinfo file addressed as <root>/<pid|self>/mountinfo,
// which is the shape both the real procfs and the test fixtures take.
func mountsFrom(path string) ([]*procfs.MountInfo, error) {
	root := filepath.Dir(filepath.Dir(path))

	fs, err := procfs.NewFS(root)
	if err != nil {
		return nil, err
	}

	owner := filepath.Base(filepath.Dir(path))
	if owner == "self" {
		return fs.GetMounts()
	}

	pid, err := strconv.Atoi(owner)
	if err != nil {
		return nil, fmt.Errorf("unexpected mountinfo path %q: %w", path, err)
	}

	proc, err := fs.Proc(pid)
	if err != nil {
		return nil, err
	}

	return proc.MountInfo()
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
	if server, _, ok := strings.Cut(source, ":"); ok {
		return server
	}
	return source
}

// WarnIfNoKubeletVolumeMounts scans the current mount table once and warns if
// no mount point looks like a kubelet volume mount. This is the operator-facing
// signal for the most common storage-metrics misconfiguration: the container
// not running with hostPID, so neither the host's nor the kubelet's mount
// table can be read, which silently prevents persistent volume attribution
// from ever working.
func WarnIfNoKubeletVolumeMounts(log *slog.Logger) {
	mounts, err := scanMounts()
	if err != nil {
		log.Warn("cannot scan mounts for kubelet volumes; persistent volume attribution will be unavailable", "error", err)
		return
	}

	if hasKubeletVolumeMount(mounts) {
		return
	}

	log.Warn("no kubelet volume mounts visible; persistent volume attribution needs hostPID so the host's and the kubelet's mount tables can be read")
}
