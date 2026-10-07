// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// maxCachedRootInodes bounds rootInodes; the cache is simply dropped when full.
const maxCachedRootInodes = 4096

// rootInodeStat reads the inode of a mount point. Tests replace it.
var rootInodeStat = statRootInode

var (
	// maxRootInodeLookups bounds the lookups whose read has not returned,
	// forgotten ones included. A read that hangs (a hard NFS mount of a
	// server that is gone) holds its goroutine until it returns, which may
	// be never; past this many, no more are started, and the mounts they
	// were for stay unnamed until a lookup returns.
	maxRootInodeLookups = 64
	// rootInodeSlowAfter is how long a lookup runs before it is logged.
	rootInodeSlowAfter = 30 * time.Second
	// rootInodeWarnEvery is how often a mount point, or the limit on
	// lookups, is logged at most.
	rootInodeWarnEvery = 10 * time.Minute
)

// rootInodeLookup is a lookup that has not returned.
type rootInodeLookup struct {
	// forgotten is set when the mount point's inode is forgotten while the
	// lookup runs: what it returns may be the root of a mount that is gone.
	forgotten bool
}

// noLookupSlot is the key under which rootInodeWarnedAt logs that the limit on
// lookups was reached; no mount point is empty.
const noLookupSlot = ""

var (
	rootInodeMu sync.Mutex
	// rootInodes holds the inode of each mount point's root, by mount point
	// as its mount table lists it. The mount table names the mount point;
	// no one process does, since a table outlives any process read through.
	rootInodes = map[string]uint64{}
	// rootInodeBusy holds the lookup running for each mount point, so a mount
	// that blocks is not asked again and no second goroutine piles up.
	rootInodeBusy = map[string]*rootInodeLookup{}
	// rootInodeRunning counts the lookups whose read has not returned,
	// including those of forgotten mount points, no longer in rootInodeBusy.
	rootInodeRunning int
	// rootInodeWarnedAt is when each mount point was last logged as slow.
	rootInodeWarnedAt = map[string]time.Time{}

	// rootInodesLearned counts the lookups that found an inode. A mount
	// resolved while a lookup it needed was in flight is resolved again once
	// this moves.
	rootInodesLearned atomic.Uint64
)

// mountRootInode returns the inode of the root of the filesystem mounted at
// mountPoint, reached through root, the "<proc>/<pid>/root" of a live process
// whose mount table lists it.
//
// It never waits for the filesystem. On a miss it starts the lookup in the
// background and reports it pending; once the inode is known, every mount
// resolution that was waiting for one is dropped, so the next event of those
// mounts resolves them again, this time with the inode.
func mountRootInode(root, mountPoint string) (ino uint64, ok, pending bool) {
	rootInodeMu.Lock()
	defer rootInodeMu.Unlock()

	if ino, ok := rootInodes[mountPoint]; ok {
		return ino, true, false
	}
	if rootInodeBusy[mountPoint] != nil {
		return 0, false, true
	}
	if rootInodeRunning >= maxRootInodeLookups {
		if warnRootInodeLocked(noLookupSlot) {
			mrlog().Warn("too many mount root lookups are not returning;"+
				" volumes on a shared NFS superblock stay unnamed until they do",
				"lookups", rootInodeRunning, "mountPoint", mountPoint)
		}
		return 0, false, true
	}
	l := &rootInodeLookup{}
	rootInodeBusy[mountPoint] = l
	rootInodeRunning++
	go lookUpRootInode(filepath.Join(root, mountPoint), mountPoint, l)
	return 0, false, true
}

func lookUpRootInode(path, mountPoint string, l *rootInodeLookup) {
	slow := time.AfterFunc(rootInodeSlowAfter, func() { warnSlowRootInode(mountPoint, l) })
	ino, err := rootInodeStat(path)
	slow.Stop()

	rootInodeMu.Lock()
	rootInodeRunning--
	if rootInodeBusy[mountPoint] == l {
		delete(rootInodeBusy, mountPoint)
	}
	if err == nil && !l.forgotten {
		if len(rootInodes) >= maxCachedRootInodes {
			clear(rootInodes)
		}
		rootInodes[mountPoint] = ino
	}
	rootInodeMu.Unlock()

	// A failed lookup leaves the waiting resolutions as they are until their
	// TTL: resolving them again now would only start the same lookup again.
	// One whose inode was forgotten meanwhile has them resolve again, which
	// looks the inode up anew.
	if err == nil {
		rootInodesLearned.Add(1)
		dropPendingMounts()
	}
}

// warnSlowRootInode logs a lookup that has not returned after
// rootInodeSlowAfter. The volume on that mount stays unnamed meanwhile.
func warnSlowRootInode(mountPoint string, l *rootInodeLookup) {
	rootInodeMu.Lock()
	warn := !l.forgotten && warnRootInodeLocked(mountPoint)
	rootInodeMu.Unlock()
	if warn {
		mrlog().Warn("the root of a mount is not answering; the volume mounted there stays unnamed"+
			" on a shared NFS superblock until it does", "mountPoint", mountPoint, "after", rootInodeSlowAfter)
	}
}

// warnRootInodeLocked reports whether key is due to be logged, and records
// that it is. rootInodeMu must be held.
func warnRootInodeLocked(key string) bool {
	now := time.Now()
	if last, ok := rootInodeWarnedAt[key]; ok && now.Sub(last) < rootInodeWarnEvery {
		return false
	}
	if len(rootInodeWarnedAt) >= maxCachedRootInodes {
		clear(rootInodeWarnedAt)
	}
	rootInodeWarnedAt[key] = now
	return true
}

// forgetRootInodes drops the cached root inodes of mountPoints, or every one
// when mountPoints is nil, and has the lookups of those mount points still
// running discard what they return. A lookup of any other mount point is left
// to finish. Mount points are reused only after a mount table change, which
// is when this runs.
func forgetRootInodes(mountPoints []string) {
	rootInodeMu.Lock()
	defer rootInodeMu.Unlock()

	if mountPoints == nil {
		clear(rootInodes)
		for mp, l := range rootInodeBusy {
			l.forgotten = true
			delete(rootInodeBusy, mp)
		}
		return
	}
	for _, mp := range mountPoints {
		delete(rootInodes, mp)
		if l := rootInodeBusy[mp]; l != nil {
			// A new mount at this mount point gets a lookup of its own.
			l.forgotten = true
			delete(rootInodeBusy, mp)
		}
	}
}
