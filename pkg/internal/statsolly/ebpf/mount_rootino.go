// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"sync"
	"sync/atomic"
)

// maxCachedRootInodes bounds rootInodes; the cache is simply dropped when full.
const maxCachedRootInodes = 4096

// rootInodeStat reads the inode of a mount point. Tests replace it.
var rootInodeStat = statRootInode

var (
	rootInodeMu sync.Mutex
	rootInodes  = map[string]uint64{}
	// rootInodeBusy holds paths whose lookup has not returned, so a mount
	// that blocks is not asked again, and no second goroutine piles up.
	rootInodeBusy = map[string]bool{}
	// rootInodeGen changes whenever cached inodes are forgotten, so a lookup
	// that started before cannot store the inode of a mount that is gone.
	rootInodeGen uint64

	// rootInodesLearned counts the lookups that found an inode. A mount
	// resolved while a lookup it needed was in flight is resolved again once
	// this moves.
	rootInodesLearned atomic.Uint64
)

// mountRootInode returns the inode of the directory at path, a mount point,
// as seen through the mount: the root of the filesystem mounted there.
//
// It never waits for the filesystem. On a miss it starts the lookup in the
// background and reports it pending; once the inode is known, every mount
// resolution that was waiting for one is dropped, so the next event of those
// mounts resolves them again, this time with the inode.
func mountRootInode(path string) (ino uint64, ok, pending bool) {
	rootInodeMu.Lock()
	defer rootInodeMu.Unlock()

	if ino, ok := rootInodes[path]; ok {
		return ino, true, false
	}
	if !rootInodeBusy[path] {
		rootInodeBusy[path] = true
		go lookUpRootInode(path, rootInodeGen)
	}
	return 0, false, true
}

func lookUpRootInode(path string, gen uint64) {
	ino, err := rootInodeStat(path)

	rootInodeMu.Lock()
	delete(rootInodeBusy, path)
	if err == nil && gen == rootInodeGen {
		if len(rootInodes) >= maxCachedRootInodes {
			clear(rootInodes)
		}
		rootInodes[path] = ino
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

// forgetRootInodes drops the cached root inodes of paths, or every one when
// paths is nil. Mount points are reused only after a mount table change,
// which is when this runs.
func forgetRootInodes(paths []string) {
	rootInodeMu.Lock()
	defer rootInodeMu.Unlock()

	rootInodeGen++
	if paths == nil {
		clear(rootInodes)
		return
	}
	for _, p := range paths {
		delete(rootInodes, p)
	}
}
