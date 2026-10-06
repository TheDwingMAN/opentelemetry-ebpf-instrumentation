// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
)

// Defaults of a CgroupIndex.
const (
	// DefaultCgroupScanInterval is the period of the background scan.
	DefaultCgroupScanInterval = 30 * time.Second
	// DefaultCgroupRescanInterval rate-limits the background scans that a
	// lookup of an unknown cgroup id asks for.
	DefaultCgroupRescanInterval = time.Second
	// DefaultCgroupTombstoneTTL is how long a removed cgroup keeps its pod.
	// Its id keeps showing up on new I/O after removal (writeback of the
	// files it owned, charged to its writeback domain: S0-d saw it 9 s after
	// removal), so this covers dirty_expire and that lag with margin.
	DefaultCgroupTombstoneTTL = 10 * time.Minute
)

// rootCgroupID is the id of the cgroup v2 root, which holds kernel threads
// (the issuers of most writeback, S0-d): no pod. Id 0 is no cgroup at all.
const rootCgroupID = 1

// The cgroup v2 hierarchy, as seen from the host or, when OBI's /sys is not
// the host's, through PID 1's root.
var defaultCgroupRoots = []string{"/sys/fs/cgroup", "/proc/1/root/sys/fs/cgroup"}

// The kubelet's top-level cgroups: systemd and cgroupfs drivers.
var kubepodsDirs = []string{"kubepods.slice", "kubepods"}

// Path components, anchored: the index maps every level under kubepods and
// assumes no depth.
var (
	// kubepods-pod<uid>.slice (Guaranteed), kubepods-<qos>-pod<uid>.slice;
	// the systemd driver writes the UID's dashes as underscores. Static
	// pods have 32-hex UIDs.
	systemdPodPattern = regexp.MustCompile(`^kubepods(?:-besteffort|-burstable)?-pod([0-9a-f_]{36}|[0-9a-f]{32})\.slice$`)
	// pod<uid>, under kubepods/<qos>/ or kubepods/.
	cgroupfsPodPattern = regexp.MustCompile(`^pod([0-9a-f-]{36}|[0-9a-f]{32})$`)
	// A container scope of CRI-O, containerd or cri-dockerd (systemd
	// driver). Its descendants, such as CRI-O's /container leaf that holds
	// the container's processes, belong to the same container.
	systemdContainerPattern = regexp.MustCompile(`^(?:crio|cri-containerd|docker)-([0-9a-f]{64})\.scope$`)
	// A container under a cgroupfs pod.
	cgroupfsContainerPattern = regexp.MustCompile(`^(?:crio-)?([0-9a-f]{64})$`)
	// CRI-O's conmon (the container's log writer and runtime shim) and the
	// pod sandbox (crio-<id> without .scope, systemd driver): pod only.
	podOnlyPattern = regexp.MustCompile(`^crio-conmon-[0-9a-f]{64}\.scope$|^crio-[0-9a-f]{64}$`)
)

// CgroupIdentity is what the path of a cgroup says about the I/O charged to
// it: the pod, and the container when the cgroup is a container's. Pod
// slices, conmon scopes and sandboxes have a pod only; QoS slices,
// kubepods itself and everything outside kubepods have neither.
type CgroupIdentity struct {
	PodUID      string
	ContainerID string
}

// scope is the identity a directory passes down to its children.
type scope struct {
	CgroupIdentity
	// inKubepods is set under the kubelet's top-level cgroup: outside, no
	// directory names a pod.
	inKubepods bool
	podOnly    bool
	cgroupfs   bool
}

// child returns the identity of directory name under s.
func (s scope) child(name string) scope {
	switch {
	case !s.inKubepods:
		return s
	case s.PodUID == "":
		if m := systemdPodPattern.FindStringSubmatch(name); m != nil {
			return scope{CgroupIdentity: CgroupIdentity{PodUID: strings.ReplaceAll(m[1], "_", "-")}, inKubepods: true}
		}
		if m := cgroupfsPodPattern.FindStringSubmatch(name); m != nil {
			return scope{CgroupIdentity: CgroupIdentity{PodUID: m[1]}, inKubepods: true, cgroupfs: true}
		}
		return s
	case s.ContainerID != "" || s.podOnly:
		return s
	case !s.cgroupfs && podOnlyPattern.MatchString(name):
		s.podOnly = true
		return s
	}
	pattern := systemdContainerPattern
	if s.cgroupfs {
		pattern = cgroupfsContainerPattern
	}
	if m := pattern.FindStringSubmatch(name); m != nil {
		s.ContainerID = m[1]
		return s
	}
	// Anything else under a pod belongs to the pod only.
	s.podOnly = true
	return s
}

type cgroupEntry struct {
	CgroupIdentity
	// removed is when a scan first missed the cgroup; zero while it lives.
	removed time.Time
}

// CgroupIndex maps cgroup v2 ids to the pod and container their path names.
// A cgroup's id is the inode of its directory, the value of
// bpf_get_current_cgroup_id() and of a blkcg's kn->id (S0-d), so no file is
// opened to read it. Removed cgroups are kept as tombstones for TombstoneTTL.
//
// Only Run and Scan walk the hierarchy: Lookup never does, so the families
// that call it while their lock holds up scrapes are never slowed down by a
// walk. An id Lookup does not know asks Run for a rescan and is answered
// again once a scan that started after the question completed.
//
// The index walks the whole hierarchy of the first root that has the
// kubelet's cgroup, so ids outside it (system.slice, user sessions) are
// known to have no pod without a rescan. A node with no kubelet cgroup has no
// pod anywhere: its scans complete with every id known to have none, and a
// kubelet cgroup that appears later is found by the next scan.
//
// It is safe for concurrent use.
type CgroupIndex struct {
	roots          []string
	scanInterval   time.Duration
	rescanInterval time.Duration
	tombstoneTTL   time.Duration
	clock          func() time.Time
	log            *slog.Logger
	// walk returns the identity of every cgroup; a field for tests.
	walk func() (map[uint64]CgroupIdentity, error)
	// rescan asks Run for a scan; it holds at most one request.
	rescan chan struct{}

	// scanMu serializes scans; mu guards the fields below.
	scanMu sync.Mutex
	mu     sync.RWMutex
	ids    map[uint64]*cgroupEntry
	// asked holds, for an unknown id, when it was first looked up and how
	// many scans had started then. Once a scan that started later has not
	// found it, the cgroup lived only between two scans: its I/O has no pod.
	asked      map[uint64]askedID
	lastRescan time.Time
	// started counts the scans begun; scans is the number of the last one
	// completed (scans run one at a time).
	started int
	scans   int
	// noKubepods is set while the last scan found no kubelet cgroup.
	noKubepods bool
}

type askedID struct {
	at    time.Time
	scans int
}

// CgroupIndexOption changes a default of a CgroupIndex.
type CgroupIndexOption func(*CgroupIndex)

// WithCgroupRoots sets the cgroup v2 mounts the index tries, in order.
func WithCgroupRoots(roots ...string) CgroupIndexOption {
	return func(x *CgroupIndex) { x.roots = roots }
}

// WithCgroupClock sets the clock of tombstones and rescans.
func WithCgroupClock(clock func() time.Time) CgroupIndexOption {
	return func(x *CgroupIndex) { x.clock = clock }
}

// NewCgroupIndex returns an empty index; Run fills it and keeps it current.
func NewCgroupIndex(opts ...CgroupIndexOption) *CgroupIndex {
	x := &CgroupIndex{
		roots:          defaultCgroupRoots,
		scanInterval:   DefaultCgroupScanInterval,
		rescanInterval: DefaultCgroupRescanInterval,
		tombstoneTTL:   DefaultCgroupTombstoneTTL,
		clock:          time.Now,
		log:            slog.With("component", "statagg.CgroupIndex"),
		rescan:         make(chan struct{}, 1),
		ids:            map[uint64]*cgroupEntry{},
		asked:          map[uint64]askedID{},
	}
	x.walk = x.walkRoots
	for _, opt := range opts {
		opt(x)
	}
	return x
}

// Run scans the cgroup hierarchy now, every scan interval, and when a lookup
// of an unknown id asks for it, until ctx is done. Without Run, an unknown
// id stays unknown (final=false).
func (x *CgroupIndex) Run(ctx context.Context) {
	ticker := time.NewTicker(x.scanInterval)
	defer ticker.Stop()
	for {
		if err := x.Scan(); err != nil {
			x.log.Debug("can't scan the cgroup hierarchy", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-x.rescan:
		}
	}
}

// Lookup returns what the index knows of cgroup id: the identity of a live
// cgroup, or of a removed one while its tombstone lasts. It never walks the
// hierarchy. An id the index does not know asks Run for a rescan, at most
// one per rescan interval, and final is false until a scan that started
// after the first lookup completes: an id that scan did not find has,
// finally, no pod. Ids 0 and 1 (the root cgroup) have no pod.
func (x *CgroupIndex) Lookup(id uint64) (identity CgroupIdentity, final bool) {
	if id <= rootCgroupID {
		return CgroupIdentity{}, true
	}
	x.mu.RLock()
	e, known := x.ids[id]
	asked, wasAsked := x.asked[id]
	scans := x.scans
	x.mu.RUnlock()
	switch {
	case known:
		return e.CgroupIdentity, true
	case wasAsked && scans > asked.scans:
		return CgroupIdentity{}, true
	}

	x.mu.Lock()
	defer x.mu.Unlock()
	// A scan may have completed since the read lock.
	if e, known := x.ids[id]; known {
		return e.CgroupIdentity, true
	}
	now := x.clock()
	if asked, wasAsked := x.asked[id]; !wasAsked {
		x.asked[id] = askedID{at: now, scans: x.started}
	} else if x.scans > asked.scans {
		return CgroupIdentity{}, true
	}
	if now.Sub(x.lastRescan) >= x.rescanInterval {
		x.lastRescan = now
		select {
		case x.rescan <- struct{}{}:
		default: // a rescan is pending already
		}
	}
	return CgroupIdentity{}, false
}

// Tombstoned reports whether id is a removed cgroup of a pod whose tombstone
// lasts: a kernel key of that cgroup must not be deleted yet, or the next I/O
// charged to it would create the key again with no labels.
func (x *CgroupIndex) Tombstoned(id uint64) bool {
	x.mu.RLock()
	defer x.mu.RUnlock()
	e, ok := x.ids[id]
	return ok && !e.removed.IsZero() && e.PodUID != ""
}

// Scan walks the cgroup hierarchy and updates the index: new cgroups are
// added, missing ones become tombstones, and tombstones and unknown ids
// older than the tombstone TTL are forgotten. Run calls it; it blocks for
// the whole walk.
func (x *CgroupIndex) Scan() error {
	x.scanMu.Lock()
	defer x.scanMu.Unlock()

	x.mu.Lock()
	x.started++
	seq := x.started
	x.mu.Unlock()

	start := x.clock()
	found, err := x.walk()
	if err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()
	for id, e := range x.ids {
		if _, alive := found[id]; alive {
			continue
		}
		switch {
		case e.removed.IsZero():
			e.removed = start
		case start.Sub(e.removed) >= x.tombstoneTTL:
			delete(x.ids, id)
		}
	}
	for id, identity := range found {
		x.ids[id] = &cgroupEntry{CgroupIdentity: identity}
		delete(x.asked, id)
	}
	for id, asked := range x.asked {
		if start.Sub(asked.at) >= x.tombstoneTTL {
			delete(x.asked, id)
		}
	}
	x.scans = seq
	return nil
}

// walkRoots returns the identity of every directory of the first cgroup
// root that has the kubelet's cgroup, keyed by inode: everything outside the
// kubelet's cgroup has no pod. With no kubelet cgroup under any root, every
// directory of the first root that exists has no pod, and with no root at
// all the result is empty: either way the scan is complete.
func (x *CgroupIndex) walkRoots() (map[uint64]CgroupIdentity, error) {
	root, top := x.kubepodsRoot()
	x.logNoKubepods(root, top)
	found := map[uint64]CgroupIdentity{}
	if root == "" {
		return found, nil
	}
	info, err := os.Stat(root)
	if err != nil {
		// Unmounted since kubepodsRoot: nothing to walk.
		return found, nil
	}
	kubepods := ""
	if top != "" {
		kubepods = filepath.Join(root, top)
	}
	if err := walkCgroup(root, info, scope{}, kubepods, found); err != nil {
		return nil, err
	}
	return found, nil
}

// kubepodsRoot returns the first root with a kubelet cgroup and that
// cgroup's name, or else the first root that is a directory and "".
func (x *CgroupIndex) kubepodsRoot() (root, top string) {
	for _, r := range x.roots {
		for _, t := range kubepodsDirs {
			if isDir(filepath.Join(r, t)) {
				return r, t
			}
		}
	}
	for _, r := range x.roots {
		if isDir(r) {
			return r, ""
		}
	}
	return "", ""
}

func (x *CgroupIndex) logNoKubepods(root, top string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	missing := top == ""
	if missing && !x.noKubepods {
		x.log.Debug("no kubepods cgroup: no cgroup has a pod until the kubelet creates it", "roots", x.roots, "walked", root)
	}
	x.noKubepods = missing
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// walkCgroup records dir and its descendants in found; kubepods is the path
// of the kubelet's cgroup, from which on directory names identify pods.
func walkCgroup(dir string, info fs.FileInfo, s scope, kubepods string, found map[uint64]CgroupIdentity) error {
	ino, ok := dirIno(info)
	if !ok {
		return errors.New("cgroup directory inodes are not available on this platform")
	}
	if !s.inKubepods && kubepods != "" && dir == kubepods {
		s = scope{inKubepods: true}
	}
	found[ino] = s.CgroupIdentity

	entries, err := os.ReadDir(dir)
	if err != nil {
		// Removed while walking: a later scan tombstones it.
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		childInfo, err := e.Info()
		if err != nil {
			continue
		}
		if err := walkCgroup(filepath.Join(dir, e.Name()), childInfo, s.child(e.Name()), kubepods, found); err != nil {
			return err
		}
	}
	return nil
}

// PodStore is what ResolvePod needs of the Kubernetes metadata store.
type PodStore interface {
	PodContainerByContainerID(containerID string) (*ikube.CachedObjMeta, string)
	PodByUID(uid string) *ikube.CachedObjMeta
}

// ResolvePod returns the pod and container name of a cgroup identity. The
// store learns a container's ID only once the pod status reports it, after
// its first I/O, so a container not known yet resolves to its pod by UID, as
// the PID decorator does.
func ResolvePod(store PodStore, id CgroupIdentity) (*ikube.CachedObjMeta, string) {
	if id.ContainerID != "" {
		if meta, name := store.PodContainerByContainerID(id.ContainerID); meta != nil {
			return meta, name
		}
	}
	if id.PodUID == "" {
		return nil, ""
	}
	return store.PodByUID(id.PodUID), ""
}
