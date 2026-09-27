// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"sync"
	"time"
)

// rootInodeTimeout bounds how long resolving a mount's root inode may take.
// The lookup asks for cached attributes only, so it should never reach the
// server; the bound is there in case a dead NFS server blocks it anyway.
const rootInodeTimeout = time.Second

// maxCachedRootInodes bounds rootInodes; the cache is simply dropped when full.
const maxCachedRootInodes = 4096

var (
	rootInodeMu sync.Mutex
	rootInodes  = map[string]uint64{}
	// rootInodeBusy holds paths whose lookup has not returned, so a mount
	// that blocks is not asked again, and no second goroutine piles up.
	rootInodeBusy = map[string]bool{}
)

// mountRootInode returns the inode of the directory at path, a mount point,
// as seen through the mount: the root of the filesystem mounted there.
func mountRootInode(path string) (uint64, bool) {
	rootInodeMu.Lock()
	if ino, ok := rootInodes[path]; ok {
		rootInodeMu.Unlock()
		return ino, true
	}
	if rootInodeBusy[path] {
		rootInodeMu.Unlock()
		return 0, false
	}
	rootInodeBusy[path] = true
	rootInodeMu.Unlock()

	done := make(chan uint64, 1)
	go func() {
		ino, err := statRootInode(path)
		rootInodeMu.Lock()
		delete(rootInodeBusy, path)
		if err == nil {
			if len(rootInodes) >= maxCachedRootInodes {
				clear(rootInodes)
			}
			rootInodes[path] = ino
		}
		rootInodeMu.Unlock()
		if err != nil {
			ino = 0
		}
		done <- ino
	}()

	select {
	case ino := <-done:
		return ino, ino != 0
	case <-time.After(rootInodeTimeout):
		return 0, false
	}
}

// forgetRootInodes drops every cached root inode. Mount points are reused
// only after a mount table change, which is when this runs.
func forgetRootInodes() {
	rootInodeMu.Lock()
	defer rootInodeMu.Unlock()
	clear(rootInodes)
}
