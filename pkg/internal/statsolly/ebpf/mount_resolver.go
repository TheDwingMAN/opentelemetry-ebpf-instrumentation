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
	PodUID string
	// PVName is empty when several volumes share the superblock and the
	// device cannot tell them apart.
	PVName     string
	VolumeType string
	Server     string
	// Shared is set when more than one pod has this superblock mounted, as
	// happens with a ReadWriteMany volume. PodUID is then one of several and
	// must not be used to attribute I/O; the volume itself is still certain.
	Shared bool
}

// MountKey identifies the mount a filesystem operation went through: the
// device of its superblock, and the inode of the mount's root directory.
// Several volumes can share a superblock (NFS subdirectories of one export);
// each is mounted at its own root, which tells them apart.
type MountKey struct {
	Dev     uint32
	RootIno uint64
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
	info  MountInfo
	found bool
	// pending is set when the volume could not be named yet because the
	// root inode of a mount was still being looked up.
	pending    bool
	resolvedAt time.Time
}

var (
	mountMu    sync.RWMutex
	mountCache = map[MountKey]mountCacheEntry{}
	mountOrder []MountKey // insertion order, oldest first, for FIFO eviction

	mountWatchOnce sync.Once
	mountWatch     = mountTableWatch{known: map[string]mountSet{}}
)

// invalidateMountCache drops every cached resolution, so the next lookup of
// each device rescans the mount table.
func invalidateMountCache() {
	mountMu.Lock()
	clear(mountCache)
	mountOrder = nil
	mountMu.Unlock()
	forgetRootInodes(nil)
}

// dropMountsWhere drops the cached resolutions drop selects.
func dropMountsWhere(drop func(MountKey, mountCacheEntry) bool) {
	mountMu.Lock()
	defer mountMu.Unlock()

	kept := mountOrder[:0]
	for _, key := range mountOrder {
		if drop(key, mountCache[key]) {
			delete(mountCache, key)
			continue
		}
		kept = append(kept, key)
	}
	mountOrder = kept
}

// dropPendingMounts drops the resolutions that were waiting for a root inode.
func dropPendingMounts() {
	dropMountsWhere(func(_ MountKey, e mountCacheEntry) bool { return e.pending })
}

// resolveMount maps the mount a filesystem operation went through (its
// superblock device and mount root inode, as reported by eBPF) to the
// Kubernetes volume it belongs to.
func resolveMount(key MountKey) (MountInfo, bool) {
	// Shared decides whether a mount may name a pod, and a second pod can
	// mount the volume at any moment. The TTLs alone would let a cached
	// single-owner entry name the wrong pod for up to a minute after that, so
	// a change to the mount table drops the resolutions of the devices whose
	// mounts it touched.
	mountWatchOnce.Do(func() { watchMountTable(mountWatch.changed, mountInfoPath, selfMountInfoPath) })

	mountMu.RLock()
	entry, ok := mountCache[key]
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

	learned := rootInodesLearned.Load()
	info, found, pending := scanForMount(key)

	mountMu.Lock()
	if _, exists := mountCache[key]; !exists {
		if len(mountCache) >= maxCachedMounts {
			// Evict the oldest entry rather than the whole cache, so filling
			// the cache doesn't force every other cached device to be
			// rescanned on its next lookup too.
			oldest := mountOrder[0]
			mountOrder = mountOrder[1:]
			delete(mountCache, oldest)
		}
		mountOrder = append(mountOrder, key)
	}
	mountCache[key] = mountCacheEntry{info: info, found: found, pending: pending, resolvedAt: time.Now()}
	mountMu.Unlock()

	// A lookup that finished during the scan dropped the pending entries
	// before this one was stored.
	if pending && rootInodesLearned.Load() != learned {
		dropPendingMounts()
	}

	return info, found
}

// scanForMount reads the mount table looking for the kubelet volume mounts
// whose superblock device is key.Dev, and picks the volume key belongs to.
// pending reports that the volume could not be named yet because the root
// inode of one of the candidate mounts is still being looked up.
func scanForMount(key MountKey) (info MountInfo, found, pending bool) {
	mounts, root, err := scanMountTable()
	if err != nil {
		return MountInfo{}, false, false
	}

	target := fmtDev(key.Dev)

	type candidate struct {
		info       MountInfo
		mountPoint string
	}
	var cands []candidate
	for _, m := range mounts {
		if m.MajorMinorVer != target {
			continue
		}
		if info, parsed := parseKubeletMount(m.MountPoint, m.Source); parsed {
			cands = append(cands, candidate{info: info, mountPoint: m.MountPoint})
		}
	}
	if len(cands) == 0 {
		return MountInfo{}, false, false
	}

	// merge folds the candidates of one volume into one answer. Every pod
	// mounting a shared volume has its own kubelet mount of it, so the
	// volume is the same for all of them, but the pod is only known if
	// there is one.
	merge := func(cs []candidate) MountInfo {
		found := cs[0].info
		for _, c := range cs[1:] {
			if c.info.PodUID != found.PodUID {
				found.Shared = true
			}
			if c.info.PVName != found.PVName {
				found.PVName = ""
			}
		}
		return found
	}

	byDev := merge(cands)
	// A root inode of 0 is no inode: the probe could not read it.
	if byDev.PVName != "" || key.RootIno == 0 {
		return byDev, true, false
	}

	// Different volumes share a superblock too: NFS shares one per server
	// export, so every PV a subdirectory provisioner (csi-driver-nfs,
	// nfs-subdir-external-provisioner) or a set of static PVs carves out of
	// one export has the same device. Each is mounted at its own directory,
	// so the root of the mount the I/O went through names the volume. When
	// that cannot be told, the volume is left unnamed rather than guessed.
	var matched []candidate
	for _, c := range cands {
		ino, ok, lookingUp := mountRootInode(filepath.Join(root, c.mountPoint))
		pending = pending || lookingUp
		if ok && ino == key.RootIno {
			matched = append(matched, c)
		}
	}
	if len(matched) > 0 {
		if byRoot := merge(matched); byRoot.PVName != "" {
			return byRoot, true, false
		}
	}
	return byDev, true, pending
}

// mountSet is a mount table as a set, for comparing two reads of it.
type mountSet map[mountIdentity]struct{}

// mountIdentity is what tells one mount from another in a mount table.
type mountIdentity struct {
	id         int
	majMin     string
	root       string
	mountPoint string
	source     string
}

// mountTableWatch remembers each watched mount table as last read, so that a
// change drops only the resolutions of the devices whose mounts it added or
// removed. A node starting and stopping pods changes its mount table all the
// time (every pod mounts its secrets and service account token), and
// dropping every resolution on each change would have every mount of every
// pod rescan the table on its next event.
type mountTableWatch struct {
	mu sync.Mutex
	// known holds the last read of each table. A nil set means the last read
	// failed, so the next change cannot be told apart and drops everything.
	known map[string]mountSet
}

// changed reads the table at path again and drops the resolutions its change
// affected. The first read of a table, when its watch starts, only records it.
func (w *mountTableWatch) changed(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	var now mountSet
	if mounts, err := mountsFrom(path); err == nil {
		now = mountSetOf(mounts)
	}
	before, seen := w.known[path]
	w.known[path] = now
	if !seen {
		return
	}
	if before == nil || now == nil {
		invalidateMountCache()
		return
	}

	devs := map[uint32]struct{}{}
	var points []string
	for _, diff := range [2][2]mountSet{{before, now}, {now, before}} {
		for m := range diff[0] {
			if _, ok := diff[1][m]; ok {
				continue
			}
			if dev, ok := parseDev(m.majMin); ok {
				devs[dev] = struct{}{}
			}
			points = append(points, filepath.Join(rootOf(path), m.mountPoint))
		}
	}
	if len(points) == 0 {
		return
	}
	dropMountsWhere(func(key MountKey, _ mountCacheEntry) bool {
		_, changed := devs[key.Dev]
		return changed
	})
	forgetRootInodes(points)
}

func mountSetOf(mounts []*procfs.MountInfo) mountSet {
	set := make(mountSet, len(mounts))
	for _, m := range mounts {
		set[mountIdentity{
			id: m.MountID, majMin: m.MajorMinorVer, root: m.Root, mountPoint: m.MountPoint, source: m.Source,
		}] = struct{}{}
	}
	return set
}

// parseDev parses a "<major>:<minor>" device number, the inverse of fmtDev.
func parseDev(majMin string) (uint32, bool) {
	majStr, minStr, ok := strings.Cut(majMin, ":")
	if !ok {
		return 0, false
	}
	major, err1 := strconv.ParseUint(majStr, 10, 32)
	minor, err2 := strconv.ParseUint(minStr, 10, 32)
	if err1 != nil || err2 != nil || major >= 1<<(32-devMinorBits) || minor > devMinorMask {
		return 0, false
	}
	return uint32(major<<devMinorBits | minor), true
}

// scanMounts parses mountInfoPath via procfs. procfs.FS.GetMounts always
// reads "<root>/self/mountinfo", so the FS root is mountInfoPath with those
// last two path elements stripped back off.
func scanMounts() ([]*procfs.MountInfo, error) {
	mounts, _, err := scanMountTable()
	return mounts, err
}

// scanMountTable is scanMounts, also returning the root directory the
// table's mount points are relative to: "<proc>/<pid>/root" of the process
// whose table it is.
func scanMountTable() ([]*procfs.MountInfo, string, error) {
	mounts, err := mountsFrom(mountInfoPath)
	if err != nil {
		if mountInfoPath != hostMountInfoPath {
			return nil, "", err
		}
		// Without hostPID there is no host init to read, so fall back to this
		// process's own table. Attribution then only covers volumes actually
		// mounted into this container.
		mounts, err = mountsFrom(selfMountInfoPath)
		return mounts, rootOf(selfMountInfoPath), err
	}

	if hasKubeletVolumeMount(mounts) {
		return mounts, rootOf(mountInfoPath), nil
	}

	// OpenShift's mount namespace encapsulation (kubens.service) runs the
	// kubelet and CRI-O in a mount namespace of their own, so their volume
	// mounts never appear in init's table. The kubelet's own table has them.
	if kubeletTable, path, ok := kubeletNamespaceMounts(); ok {
		return kubeletTable, rootOf(path), nil
	}
	return mounts, rootOf(mountInfoPath), nil
}

// rootOf returns "<proc>/<pid>/root" for "<proc>/<pid>/mountinfo": the
// directory through which that process's mount points can be reached.
func rootOf(mountInfo string) string {
	return filepath.Join(filepath.Dir(mountInfo), "root")
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
func kubeletNamespaceMounts() ([]*procfs.MountInfo, string, bool) {
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
				return mounts, mountInfoOf(kubeletPID), true
			}
		}
		kubeletNS, kubeletPID = "", ""
	}

	if time.Since(kubeletSearchedAt) < kubeletSearchInterval {
		return nil, "", false
	}
	kubeletSearchedAt = time.Now()

	pid, ns, ok := findKubelet(procRoot)
	if !ok {
		return nil, "", false
	}
	if mounts, err := mountsFrom(mountInfoOf(pid)); err != nil || !hasKubeletVolumeMount(mounts) {
		return nil, "", false
	}
	// The watch on init's table does not see this namespace. An open
	// mountinfo holds its namespace, so one watch outlives any kubelet. It
	// only reports changes after it opens, so the table is read after it.
	kubeletWatchOnce.Do(func() { watchMountTable(mountWatch.changed, mountInfoOf(pid)) })
	mounts, err := mountsFrom(mountInfoOf(pid))
	if err != nil {
		return nil, "", false
	}
	kubeletNS, kubeletPID = ns, pid
	return mounts, mountInfoOf(pid), true
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
