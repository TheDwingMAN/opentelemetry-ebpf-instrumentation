// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
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
	// Addr is the fs join label server.address (step 10): the addr= super
	// option the kernel reports for nfs and cifs mounts, netip-normalized to
	// match the NFS RPC side's formatting (2.5), falling back to the mount
	// source's host when the kernel gives no addr=; "" for ceph (several
	// monitors, ambiguous) and local filesystems.
	Addr string
	// Source is the mount's device or export path as mountinfo reports it
	// (e.g. "/dev/mapper/vg-lv", "10.0.0.5:/export/pvc-x"). It plays no part
	// in pod/PV attribution; FSJoinDevice uses it only as the system.device
	// fallback of a filesystem whose superblock has no sysfs entry of its
	// own (btrfs, step 10).
	Source string
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
	// mountTableGen moves each time a mount table change drops resolutions,
	// so a resolution read from the table before the change is not stored
	// after it.
	mountTableGen uint64

	// mountScan is scanForMount; tests wrap it.
	mountScan = scanForMount

	mountWatchOnce sync.Once
	mountWatch     = newMountTableWatch()
)

func mrlog() *slog.Logger {
	return slog.With("component", "ebpf.MountResolver")
}

// invalidateMountCache drops every cached resolution, so the next lookup of
// each device rescans the mount table.
func invalidateMountCache() {
	mountMu.Lock()
	clear(mountCache)
	mountOrder = nil
	mountTableGen++
	mountMu.Unlock()
	forgetRootInodes(nil)
}

// dropMountsWhere drops the cached resolutions drop selects.
func dropMountsWhere(drop func(MountKey, mountCacheEntry) bool) {
	mountMu.Lock()
	defer mountMu.Unlock()
	dropMountsWhereLocked(drop)
}

// dropChangedMounts drops the cached resolutions of devs, whose mounts a
// mount table change added or removed.
func dropChangedMounts(devs map[uint32]struct{}) {
	mountMu.Lock()
	defer mountMu.Unlock()
	mountTableGen++
	dropMountsWhereLocked(func(key MountKey, _ mountCacheEntry) bool {
		_, changed := devs[key.Dev]
		return changed
	})
}

// dropMountsWhereLocked is dropMountsWhere with mountMu held.
func dropMountsWhereLocked(drop func(MountKey, mountCacheEntry) bool) {
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
	gen := mountTableGen
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
	info, found, pending := mountScan(key)

	mountMu.Lock()
	if mountTableGen != gen {
		// A mount table change dropped resolutions while this one was read,
		// maybe this device's: the table read may be the one from before the
		// change. It serves this event only, and the next reads the table
		// again.
		mountMu.Unlock()
		return info, found
	}
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
		if info, parsed := parseKubeletMount(m); parsed {
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
		ino, ok, lookingUp := mountRootInode(root, c.mountPoint)
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
	// namespaces holds the mount namespace of the process each table belongs
	// to, as its ns/mnt link read when the table was first read.
	namespaces map[string]string
}

func newMountTableWatch() mountTableWatch {
	return mountTableWatch{known: map[string]mountSet{}, namespaces: map[string]string{}}
}

// changed reads again the table the watch identifies by key, through the
// file the watch holds open, and drops the resolutions its change affected.
// The first read of a table, when its watch starts, records it. Every read
// starts looking up the root inodes the mounts it adds will need.
//
// The table is never read again by path. An open mountinfo keeps the mount
// namespace and root it was opened in after its process exits, while the
// path does not: once the process is gone it names no table, or, with the
// PID reused, another process's.
func (w *mountTableWatch) changed(key string, table io.ReadSeeker) {
	w.mu.Lock()
	defer w.mu.Unlock()

	now, err := readMountSet(table)
	if err != nil {
		mrlog().Debug("can't read a watched mount table", "table", key, "error", err)
	}
	before, seen := w.known[key]
	w.known[key] = now
	if !seen {
		w.namespaces[key] = mountNamespaceOf(key)
		w.prewarmRootInodes(key, now, now)
		return
	}
	if before == nil || now == nil {
		invalidateMountCache()
		w.prewarmRootInodes(key, now, now)
		return
	}

	devs := map[uint32]struct{}{}
	var mountPoints []string
	added := mountSet{}
	for i, diff := range [2][2]mountSet{{now, before}, {before, now}} {
		for m := range diff[0] {
			if _, ok := diff[1][m]; ok {
				continue
			}
			if dev, ok := parseDev(m.majMin); ok {
				devs[dev] = struct{}{}
			}
			mountPoints = append(mountPoints, m.mountPoint)
			if i == 0 {
				added[m] = struct{}{}
			}
		}
	}
	if len(mountPoints) == 0 {
		return
	}
	dropChangedMounts(devs)
	forgetRootInodes(mountPoints)
	w.prewarmRootInodes(key, now, added)
}

// prewarmRootInodes starts looking up the root inode of every volume mount in
// table on a superblock that added touched and that holds more than one
// volume, as NFS subdirectory PVs of one export do. Only the mount root tells
// those volumes apart, and a pod's first I/O comes right after its mount:
// looked up then, the inode would come too late for it, and those events
// would go out without the volume. The lookups are mountRootInode's own, so
// this never waits for the filesystem.
//
// They go through the root of the process whose table this is, and only
// while that process is in the mount namespace the table was first read in:
// once it exits, its PID may name a process that sees other mounts there.
func (w *mountTableWatch) prewarmRootInodes(key string, table, added mountSet) {
	mountPoints := sharedSuperblockMounts(table, added)
	if len(mountPoints) == 0 {
		return
	}
	if ns := w.namespaces[key]; ns == "" || mountNamespaceOf(key) != ns {
		return
	}
	root := rootOf(key)
	for _, mp := range mountPoints {
		mountRootInode(root, mp)
	}
}

// sharedSuperblockMounts returns the mount points of the kubelet volume
// mounts in table whose device holds more than one volume, on the devices of
// the kubelet volume mounts in added. Several pods mounting one volume share
// its superblock too, but the device names that volume without a root inode.
func sharedSuperblockMounts(table, added mountSet) []string {
	touched := map[string]struct{}{}
	for m := range added {
		if kubeletVolumeRe.MatchString(m.mountPoint) {
			touched[m.majMin] = struct{}{}
		}
	}
	if len(touched) == 0 {
		return nil
	}

	mountPoints := map[string][]string{}
	volumes := map[string]map[string]struct{}{}
	for m := range table {
		if _, ok := touched[m.majMin]; !ok {
			continue
		}
		_, _, pvName, ok := kubeletVolumeMatch(m.mountPoint)
		if !ok {
			continue
		}
		mountPoints[m.majMin] = append(mountPoints[m.majMin], m.mountPoint)
		if volumes[m.majMin] == nil {
			volumes[m.majMin] = map[string]struct{}{}
		}
		volumes[m.majMin][pvName] = struct{}{}
	}

	var shared []string
	for dev, mps := range mountPoints {
		if len(volumes[dev]) > 1 {
			shared = append(shared, mps...)
		}
	}
	return shared
}

// mountNamespaceOf reads the mount namespace of the process whose mountinfo
// is at path, or "" when it cannot be read.
func mountNamespaceOf(mountInfo string) string {
	ns, err := os.Readlink(filepath.Join(filepath.Dir(mountInfo), "ns", "mnt"))
	if err != nil {
		return ""
	}
	return ns
}

// readMountSet reads a mountinfo file, in the format documented by proc(5),
// from its start. Only what tells one mount from another is parsed.
func readMountSet(table io.ReadSeeker) (mountSet, error) {
	if _, err := table.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(table)
	if err != nil {
		return nil, err
	}
	set := mountSet{}
	for line := range strings.Lines(string(data)) {
		fields := strings.Split(strings.TrimSuffix(line, "\n"), " ")
		n := len(fields)
		if n < 10 || fields[n-4] != "-" {
			return nil, fmt.Errorf("malformed mountinfo line %q", line)
		}
		id, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, fmt.Errorf("malformed mount ID in %q: %w", line, err)
		}
		set[mountIdentity{
			id: id, majMin: fields[2], root: fields[3], mountPoint: fields[4], source: fields[n-2],
		}] = struct{}{}
	}
	return set, nil
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

// parseKubeletMount extracts Kubernetes volume identity from a mount point,
// and the fs join labels (step 10) from the rest of m.
func parseKubeletMount(m *procfs.MountInfo) (MountInfo, bool) {
	podUID, volumeType, pvName, ok := kubeletVolumeMatch(m.MountPoint)
	if !ok {
		return MountInfo{}, false
	}

	return MountInfo{
		PodUID:     podUID,
		VolumeType: volumeType,
		PVName:     pvName,
		Addr:       mountServerAddress(m.FSType, m.SuperOptions, m.Source),
		Source:     m.Source,
	}, true
}

// kubeletVolumeMatch extracts the pod UID, volume plugin, and volume name
// from a kubelet volume mount point, or ok=false when mountPoint is not one.
func kubeletVolumeMatch(mountPoint string) (podUID, volumeType, pvName string, ok bool) {
	match := kubeletVolumeRe.FindStringSubmatch(mountPoint)
	if match == nil {
		return "", "", "", false
	}
	return match[1], match[2], match[3], true
}

// mountServerAddress returns the fs join label server.address (step 10) for
// a mount: the addr= super option the kernel prints for nfs and cifs mounts,
// netip-normalized (v4-mapped unmapped) to match the NFS RPC side's
// formatting (2.5). It falls back to the mount source's host only when the
// kernel gives no addr=, and is "" for ceph -- several monitors, ambiguous --
// and every local filesystem (D4).
func mountServerAddress(fsType string, superOptions map[string]string, source string) string {
	switch fsType {
	case "nfs", "nfs4", "cifs", "smb3":
	default:
		return ""
	}

	if raw, ok := superOptions["addr"]; ok && raw != "" {
		if ip, err := netip.ParseAddr(raw); err == nil {
			return ip.Unmap().String()
		}
		return raw
	}
	return sourceHost(source)
}

// sourceHost extracts the server host from a mount source when the kernel
// gives no addr= option: "host:/export" (nfs) or "//host/share" (cifs).
// Bracketed IPv6 sources ("[::1]:/export") and multi-monitor ceph sources
// ("mon1,mon2:/path") are left to addr=; this fallback only needs to cover
// the common single-host case addr= itself covers on every kernel this
// project supports.
func sourceHost(source string) string {
	if share, ok := strings.CutPrefix(source, "//"); ok {
		host, _, _ := strings.Cut(share, "/")
		return host
	}
	host, _, _ := strings.Cut(source, ":")
	return host
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
