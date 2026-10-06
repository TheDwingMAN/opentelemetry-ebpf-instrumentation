// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// benchSharedSuperblock writes a mount table where two volumes share one NFS
// superblock, so resolving either needs the root inode of each mount.
func benchSharedSuperblock(b *testing.B) {
	b.Helper()
	dir := filepath.Join(b.TempDir(), "1")
	require.NoError(b, os.MkdirAll(dir, 0o755))
	const (
		mpA = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-aaaa"
		mpB = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-bbbb"
	)
	table := "36 35 0:77 /a " + mpA + " rw - nfs4 10.0.0.1:/export/a rw\n" +
		"37 35 0:77 /b " + mpB + " rw - nfs4 10.0.0.1:/export/b rw\n"
	require.NoError(b, os.WriteFile(filepath.Join(dir, "mountinfo"), []byte(table), 0o644))
	old := mountInfoPath
	mountInfoPath = filepath.Join(dir, "mountinfo")
	b.Cleanup(func() {
		mountInfoPath = old
		resetMountCache()
	})
	resetMountCache()
}

// BenchmarkResolveMount_CacheHit is the per-event cost of the mount lookup
// once a mount is resolved.
func BenchmarkResolveMount_CacheHit(b *testing.B) {
	benchSharedSuperblock(b)
	key := MountKey{Dev: 77, RootIno: 12345}
	resolveMount(key)
	b.ReportAllocs()
	for b.Loop() {
		resolveMount(key)
	}
}

// BenchmarkResolveMount_SlowRootInode is the time the decorator spends in the
// first lookup of a mount on a shared superblock when reading the mount
// roots' inodes takes 20 ms (a slow or unreachable network filesystem).
func BenchmarkResolveMount_SlowRootInode(b *testing.B) {
	benchSharedSuperblock(b)
	old := rootInodeStat
	rootInodeStat = func(string) (uint64, error) {
		time.Sleep(20 * time.Millisecond)
		return 0, os.ErrNotExist
	}
	// Every iteration forgets the lookups the one before started, which are
	// still sleeping: lift their limit, so each iteration starts its own.
	oldMax := maxRootInodeLookups
	maxRootInodeLookups = math.MaxInt
	b.Cleanup(func() {
		rootInodeStat = old
		maxRootInodeLookups = oldMax
	})

	key := MountKey{Dev: 77, RootIno: 12345}
	for b.Loop() {
		resetMountCache()
		resolveMount(key)
	}
}
