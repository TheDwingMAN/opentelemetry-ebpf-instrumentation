// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	// maxContainerMounts bounds the paths a MountpointResolver remembers.
	maxContainerMounts = 4096
	// containerMountTTL bounds how long a path is trusted: a container can
	// mount a volume somewhere else, and dev_t numbers are reused.
	containerMountTTL = time.Minute
	// containerMountMissTTL is how long "no such mount" or "no live process"
	// is trusted. It is short because both are usually a moment's state: the
	// volume is mounted a little after the first I/O, or a sibling process
	// is about to appear.
	containerMountMissTTL = 15 * time.Second
	// containerMountPendingTTL is how long a path waiting for a root inode
	// is left unanswered before the resolver is asked again.
	containerMountPendingTTL = time.Second
	// maxContainerMountPIDs bounds the processes of a PID namespace listed
	// when the one that did the I/O is gone.
	maxContainerMountPIDs = 8
	// maxContainerMountLookups bounds the root inode lookups in flight, and
	// the stats that never returned. A stat can hang on a dead NFS server,
	// and the goroutine with it; the lookup that waited for it gives up after
	// containerMountLookupTimeout, so a hang costs one of these until the
	// stat returns, not the resolver.
	maxContainerMountLookups = 16
	// containerMountLookupTimeout is how long a lookup waits for the stats of
	// the candidate mounts before settling for the shortest path.
	containerMountLookupTimeout = 5 * time.Second
	// mountTableTTL is how long a parsed mount table, and the live processes
	// of a PID namespace, are reused across keys: a container with several
	// volumes would otherwise parse the same table once per volume.
	mountTableTTL = 5 * time.Second
	// maxCachedMountTables bounds the processes whose mount tables are kept.
	maxCachedMountTables = 256
)

type containerMountKey struct {
	pidNs uint32
	// scope separates the containers that share a PID namespace
	// (shareProcessNamespace) but not a mount namespace.
	scope string
	mount MountKey
}

type containerMountEntry struct {
	path  string
	until time.Time
}

// MountpointResolver finds where the container of a process sees a volume,
// for obi.fs.container.mountpoint. The path is read from the process's own
// mount table, so it is the one the application uses, not the kubelet's.
//
// It does nothing until asked, and is only asked when the attribute is
// selected. Methods are safe for concurrent use.
type MountpointResolver struct {
	procRoot string
	now      func() time.Time
	// pidsIn lists the live processes of a PID namespace; tests replace it.
	pidsIn func(pidNs uint32) []uint32
	// inode reads the inode of a mount's root; tests replace it.
	inode func(path string) (uint64, error)

	// lookupTimeout is how long a root inode lookup waits for the stats.
	lookupTimeout time.Duration

	cache *expirable.LRU[containerMountKey, containerMountEntry]
	// tables holds the mount points of each device in the mount table of a
	// process, and nsPIDs the live processes of a PID namespace (nil when
	// none): the work behind a key is shared by the keys of one container.
	tables *expirable.LRU[uint32, map[string][]string]
	nsPIDs *expirable.LRU[uint32, []uint32]

	mu       sync.Mutex
	inflight map[containerMountKey]struct{}
	// stuck counts the stats started and not yet returned.
	stuck int
}

// NewMountpointResolver returns a resolver reading the live /proc.
func NewMountpointResolver() *MountpointResolver {
	r := &MountpointResolver{
		procRoot: procRoot,
		now:      time.Now,
		inode:    rootInodeStat,
		cache:    expirable.NewLRU[containerMountKey, containerMountEntry](maxContainerMounts, nil, containerMountTTL),
		tables:   expirable.NewLRU[uint32, map[string][]string](maxCachedMountTables, nil, mountTableTTL),
		nsPIDs:   expirable.NewLRU[uint32, []uint32](maxCachedMountTables, nil, containerMountMissTTL),

		lookupTimeout: containerMountLookupTimeout,
		inflight:      map[containerMountKey]struct{}{},
	}
	r.pidsIn = r.pidsInNamespace
	return r
}

// ContainerPath returns the mount point, in the mount namespace of process
// pid, of the mount the I/O went through; "" when there is none or it is not
// known yet. scope is the container's name, "" when unknown.
//
// Several mounts of one device (a volume mounted with and without a subPath)
// are told apart by the inode of the mount's root, which a lookup in the
// background reads; until it returns the answer is "". Without one, the
// shortest mount point wins.
func (r *MountpointResolver) ContainerPath(pidNs, pid uint32, scope string, mount MountKey) string {
	key := containerMountKey{pidNs: pidNs, scope: scope, mount: mount}
	now := r.now()
	if e, ok := r.cache.Get(key); ok && now.Before(e.until) {
		return e.path
	}

	cands, livePID, ok := r.mountsOfDevice(pidNs, pid, mount.Dev)
	switch {
	case !ok, len(cands) == 0:
		r.cache.Add(key, containerMountEntry{until: now.Add(containerMountMissTTL)})
		return ""
	case len(cands) == 1 || mount.RootIno == 0:
		path := cands[0]
		r.cache.Add(key, containerMountEntry{path: path, until: now.Add(containerMountTTL)})
		return path
	}

	r.cache.Add(key, containerMountEntry{until: now.Add(containerMountPendingTTL)})
	r.startRootLookup(key, livePID, cands)
	return ""
}

// mountsOfDevice returns the mount points, shortest first, of the mounts of
// device dev in the mount table of pid, or of another process of its PID
// namespace when pid is gone. ok is false when no process could be read.
func (r *MountpointResolver) mountsOfDevice(pidNs, pid, dev uint32) (points []string, livePID uint32, ok bool) {
	if pid != 0 {
		if points, ok := r.readMountsOfDevice(pid, dev); ok {
			return points, pid, true
		}
	}
	if pidNs == 0 {
		return nil, 0, false
	}
	for _, other := range r.livePIDs(pidNs) {
		if other == pid {
			continue
		}
		if points, ok := r.readMountsOfDevice(other, dev); ok {
			return points, other, true
		}
	}
	return nil, 0, false
}

// livePIDs lists the processes of PID namespace ns, remembering the answer,
// an empty one included: a dead namespace would otherwise be searched for in
// all of /proc by each of its keys.
func (r *MountpointResolver) livePIDs(ns uint32) []uint32 {
	if pids, ok := r.nsPIDs.Get(ns); ok {
		return pids
	}
	pids := r.pidsIn(ns)
	r.nsPIDs.Add(ns, pids)
	return pids
}

func (r *MountpointResolver) readMountsOfDevice(pid, dev uint32) ([]string, bool) {
	if table, ok := r.tables.Get(pid); ok {
		return table[fmtDev(dev)], true
	}
	mounts, err := mountsFrom(filepath.Join(r.procRoot, strconv.FormatUint(uint64(pid), 10), "mountinfo"))
	if err != nil {
		return nil, false
	}
	table := map[string][]string{}
	for _, m := range mounts {
		if p := unescapeMountInfo(m.MountPoint); !slices.Contains(table[m.MajorMinorVer], p) {
			table[m.MajorMinorVer] = append(table[m.MajorMinorVer], p)
		}
	}
	for _, points := range table {
		slices.SortFunc(points, func(a, b string) int {
			if len(a) != len(b) {
				return len(a) - len(b)
			}
			return strings.Compare(a, b)
		})
	}
	r.tables.Add(pid, table)
	return table[fmtDev(dev)], true
}

// startRootLookup reads, off the caller's goroutine, the root inode of each
// of the mounts cands and stores the shortest one that is key's mount.
func (r *MountpointResolver) startRootLookup(key containerMountKey, pid uint32, cands []string) {
	r.mu.Lock()
	_, running := r.inflight[key]
	if running || r.stuck >= maxContainerMountLookups {
		r.mu.Unlock()
		return
	}
	r.inflight[key] = struct{}{}
	r.mu.Unlock()

	go func() {
		path := r.matchRoot(pid, key.mount.RootIno, cands)
		r.cache.Add(key, containerMountEntry{path: path, until: r.now().Add(containerMountTTL)})

		r.mu.Lock()
		delete(r.inflight, key)
		r.mu.Unlock()
	}()
}

// matchRoot returns the shortest of cands whose root inode is ino. The stats
// run in a goroutine the caller stops waiting for after lookupTimeout, and
// then gets the shortest path; the goroutine ends when its stat does.
func (r *MountpointResolver) matchRoot(pid uint32, ino uint64, cands []string) string {
	root := filepath.Join(r.procRoot, strconv.FormatUint(uint64(pid), 10), "root")
	found := make(chan string, 1)
	r.mu.Lock()
	r.stuck++
	r.mu.Unlock()
	go func() {
		defer func() {
			r.mu.Lock()
			r.stuck--
			r.mu.Unlock()
		}()
		for _, c := range cands {
			if got, err := r.inode(filepath.Join(root, c)); err == nil && got == ino {
				found <- c
				return
			}
		}
		found <- cands[0]
	}()
	timer := time.NewTimer(r.lookupTimeout)
	defer timer.Stop()
	select {
	case path := <-found:
		return path
	case <-timer.C:
		return cands[0]
	}
}

// pidsInNamespace lists the live processes of PID namespace ns through the
// pid links of /proc. It is only run for a process that is gone.
func (r *MountpointResolver) pidsInNamespace(ns uint32) []uint32 {
	entries, err := os.ReadDir(r.procRoot)
	if err != nil {
		return nil
	}
	want := "pid:[" + strconv.FormatUint(uint64(ns), 10) + "]"
	var pids []uint32
	for _, e := range entries {
		n, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		if link, err := os.Readlink(filepath.Join(r.procRoot, e.Name(), "ns", "pid")); err == nil && link == want {
			pids = append(pids, uint32(n))
			if len(pids) >= maxContainerMountPIDs {
				break
			}
		}
	}
	return pids
}
