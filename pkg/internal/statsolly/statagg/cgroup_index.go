// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"context"
	"errors"
	"fmt"
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
	// DefaultCgroupRescanInterval rate-limits the scans that a lookup of an
	// unknown cgroup id triggers.
	DefaultCgroupRescanInterval = time.Second
	// DefaultCgroupTombstoneTTL is how long a removed cgroup keeps its pod.
	// Its id keeps showing up on new I/O after removal (writeback of the
	// files it owned, charged to its writeback domain: S0-d saw it 9 s after
	// removal), so this covers dirty_expire and that lag with margin.
	DefaultCgroupTombstoneTTL = 10 * time.Minute
)

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
	podOnly  bool
	cgroupfs bool
}

// child returns the identity of directory name under s.
func (s scope) child(name string) scope {
	switch {
	case s.PodUID == "":
		if m := systemdPodPattern.FindStringSubmatch(name); m != nil {
			return scope{CgroupIdentity: CgroupIdentity{PodUID: strings.ReplaceAll(m[1], "_", "-")}}
		}
		if m := cgroupfsPodPattern.FindStringSubmatch(name); m != nil {
			return scope{CgroupIdentity: CgroupIdentity{PodUID: m[1]}, cgroupfs: true}
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
// It is safe for concurrent use.
type CgroupIndex struct {
	roots          []string
	scanInterval   time.Duration
	rescanInterval time.Duration
	tombstoneTTL   time.Duration
	clock          func() time.Time
	log            *slog.Logger

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

// NewCgroupIndex returns an empty index; Scan or Run fill it.
func NewCgroupIndex(opts ...CgroupIndexOption) *CgroupIndex {
	x := &CgroupIndex{
		roots:          defaultCgroupRoots,
		scanInterval:   DefaultCgroupScanInterval,
		rescanInterval: DefaultCgroupRescanInterval,
		tombstoneTTL:   DefaultCgroupTombstoneTTL,
		clock:          time.Now,
		log:            slog.With("component", "statagg.CgroupIndex"),
		ids:            map[uint64]*cgroupEntry{},
		asked:          map[uint64]askedID{},
	}
	for _, opt := range opts {
		opt(x)
	}
	return x
}

// Run scans the cgroup hierarchy now and every scan interval until ctx is
// done.
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
		}
	}
}

// Lookup returns what the index knows of cgroup id: the identity of a live
// cgroup, or of a removed one while its tombstone lasts. An id the index
// does not know triggers a rescan, at most one per rescan interval. final is
// false when the answer may still change: the id is unknown and no scan has
// looked for it yet. An id that a scan made after the first lookup did not
// find has, finally, no pod.
func (x *CgroupIndex) Lookup(id uint64) (identity CgroupIdentity, final bool) {
	if identity, known, final := x.lookup(id); known || final {
		return identity, final
	}
	x.mu.Lock()
	now := x.clock()
	rescan := now.Sub(x.lastRescan) >= x.rescanInterval
	if rescan {
		x.lastRescan = now
	}
	x.mu.Unlock()
	if !rescan {
		return CgroupIdentity{}, false
	}
	if err := x.Scan(); err != nil {
		x.log.Debug("can't rescan the cgroup hierarchy", "error", err)
		return CgroupIdentity{}, false
	}
	identity, _, final = x.lookup(id)
	return identity, final
}

func (x *CgroupIndex) lookup(id uint64) (identity CgroupIdentity, known, final bool) {
	x.mu.RLock()
	e, ok := x.ids[id]
	asked, wasAsked := x.asked[id]
	scans := x.scans
	x.mu.RUnlock()
	if ok {
		return e.CgroupIdentity, true, true
	}
	if wasAsked {
		return CgroupIdentity{}, false, scans > asked.scans
	}
	x.mu.Lock()
	if _, ok := x.asked[id]; !ok {
		x.asked[id] = askedID{at: x.clock(), scans: x.started}
	}
	x.mu.Unlock()
	return CgroupIdentity{}, false, false
}

// Tombstoned reports whether id is a removed cgroup whose tombstone lasts: a
// kernel key of that cgroup must not be deleted yet, or the next I/O charged
// to it would create the key again with no labels.
func (x *CgroupIndex) Tombstoned(id uint64) bool {
	x.mu.RLock()
	defer x.mu.RUnlock()
	e, ok := x.ids[id]
	return ok && !e.removed.IsZero()
}

// Scan walks every level of the kubelet's cgroups and updates the index:
// new cgroups are added, missing ones become tombstones, and tombstones and
// unknown ids older than the tombstone TTL are forgotten.
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

// walk returns the identity of every directory under the kubelet's
// top-level cgroup, keyed by inode.
func (x *CgroupIndex) walk() (map[uint64]CgroupIdentity, error) {
	for _, root := range x.roots {
		for _, top := range kubepodsDirs {
			dir := filepath.Join(root, top)
			info, err := os.Stat(dir)
			if err != nil || !info.IsDir() {
				continue
			}
			found := map[uint64]CgroupIdentity{}
			if err := walkCgroup(dir, info, scope{}, found); err != nil {
				return nil, err
			}
			return found, nil
		}
	}
	return nil, fmt.Errorf("no kubepods cgroup under %v", x.roots)
}

func walkCgroup(dir string, info fs.FileInfo, s scope, found map[uint64]CgroupIdentity) error {
	ino, ok := dirIno(info)
	if !ok {
		return errors.New("cgroup directory inodes are not available on this platform")
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
		if err := walkCgroup(filepath.Join(dir, e.Name()), childInfo, s.child(e.Name()), found); err != nil {
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
