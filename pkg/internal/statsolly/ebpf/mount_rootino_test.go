// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rootMpA = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-aaaa"
	rootMpB = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-bbbb"
	rootMpC = "/var/lib/kubelet/pods/0ae4568c-d532-43ff-88c2-d16d7512e97b/volumes/kubernetes.io~nfs/pvc-cccc"
)

// blockingRootInodeStat has root inode lookups wait until released, and
// counts them. The inode is the mount point's length.
func blockingRootInodeStat(t *testing.T) (release func(), started *atomic.Int32) {
	t.Helper()
	// Lookups a test before this one left running would count against the
	// limit.
	require.Eventually(t, func() bool { return rootInodeLookupsRunning() == 0 }, 5*time.Second, time.Millisecond)
	gate := make(chan struct{})
	started = &atomic.Int32{}
	withRootInodeStat(t, func(path string) (uint64, error) {
		started.Add(1)
		<-gate
		return uint64(len(path)), nil
	})
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	// Registered after withRootInodeStat's cleanup, so it runs first.
	t.Cleanup(func() {
		release()
		require.Eventually(t, func() bool { return rootInodeLookupsRunning() == 0 }, 5*time.Second, time.Millisecond)
	})
	return release, started
}

func rootInodeLookupsRunning() int {
	rootInodeMu.Lock()
	defer rootInodeMu.Unlock()
	return rootInodeRunning
}

// syncBuffer is a log sink the lookups' goroutines can write to while the
// test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

// A mount table change forgets the root inodes of the mount points it added
// or removed. A lookup of another mount point, still running, must keep what
// it finds: pods starting elsewhere on the node would otherwise keep a slow
// mount's volume unnamed.
func TestForgetRootInodesKeepsOtherLookups(t *testing.T) {
	release, started := blockingRootInodeStat(t)
	const root = "/proc/1/root"

	_, _, pending := mountRootInode(root, rootMpA)
	require.True(t, pending)
	mountRootInode(root, rootMpB)
	require.Eventually(t, func() bool { return started.Load() == 2 }, 5*time.Second, time.Millisecond)

	forgetRootInodes([]string{rootMpB})
	release()
	require.Eventually(t, func() bool { return rootInodeLookupsRunning() == 0 }, 5*time.Second, time.Millisecond)

	assert.True(t, rootInodeCached(rootMpA), "an unrelated change must not discard this lookup")
	assert.False(t, rootInodeCached(rootMpB), "the lookup of a forgotten mount point may be of a mount that is gone")

	ino, ok, _ := mountRootInode(root, rootMpA)
	require.True(t, ok)
	assert.Equal(t, uint64(len(root+rootMpA)), ino)
}

// A mount point forgotten while its lookup hangs gets a new lookup: the mount
// there now may be a new one, on a server that answers.
func TestForgetRootInodesStartsANewLookup(t *testing.T) {
	_, started := blockingRootInodeStat(t)

	mountRootInode("/proc/1/root", rootMpA)
	mountRootInode("/proc/1/root", rootMpA)
	require.Eventually(t, func() bool { return started.Load() == 1 }, 5*time.Second, time.Millisecond)

	forgetRootInodes([]string{rootMpA})
	mountRootInode("/proc/1/root", rootMpA)
	require.Eventually(t, func() bool { return started.Load() == 2 }, 5*time.Second, time.Millisecond)
	assert.Equal(t, 2, rootInodeLookupsRunning())
}

// Lookups that never return (a hard NFS mount of a server that is gone) each
// hold a goroutine. Past maxRootInodeLookups no more are started, and that is
// logged.
func TestRootInodeLookupsAreBounded(t *testing.T) {
	logs := captureLog(t)
	old := maxRootInodeLookups
	maxRootInodeLookups = 2
	t.Cleanup(func() { maxRootInodeLookups = old })
	release, started := blockingRootInodeStat(t)
	const root = "/proc/1/root"

	mountRootInode(root, rootMpA)
	mountRootInode(root, rootMpB)
	// Forgetting a mount point does not free its goroutine.
	forgetRootInodes([]string{rootMpB})
	_, ok, pending := mountRootInode(root, rootMpC)
	mountRootInode(root, rootMpC)

	assert.False(t, ok)
	assert.True(t, pending, "the volume is not known yet")
	require.Eventually(t, func() bool { return started.Load() == 2 }, 5*time.Second, time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(2), started.Load(), "no lookup past the limit")
	assert.Equal(t, 1, strings.Count(logs.String(), "too many mount root lookups"), "logged once")

	release()
	require.Eventually(t, func() bool { return rootInodeLookupsRunning() == 0 }, 5*time.Second, time.Millisecond)
	require.Eventually(t, func() bool {
		_, ok, _ := mountRootInode(root, rootMpC)
		return ok
	}, 5*time.Second, time.Millisecond)
}

// A lookup that has not returned after rootInodeSlowAfter is logged, naming
// the mount point, and at most once per rootInodeWarnEvery for it.
func TestSlowRootInodeLookupIsLogged(t *testing.T) {
	logs := captureLog(t)
	old := rootInodeSlowAfter
	rootInodeSlowAfter = 10 * time.Millisecond
	t.Cleanup(func() { rootInodeSlowAfter = old })
	_, started := blockingRootInodeStat(t)

	mountRootInode("/proc/1/root", rootMpA)
	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "mountPoint="+rootMpA)
	}, 5*time.Second, time.Millisecond)
	assert.Contains(t, logs.String(), "level=WARN")

	// The mount is replaced and its new lookup hangs too: not logged again
	// so soon.
	forgetRootInodes([]string{rootMpA})
	mountRootInode("/proc/1/root", rootMpA)
	require.Eventually(t, func() bool { return started.Load() == 2 }, 5*time.Second, time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 1, strings.Count(logs.String(), "mountPoint="+rootMpA))
	assert.NotContains(t, logs.String(), "mountPoint="+rootMpB)
}

// A lookup that returns in time is not logged.
func TestFastRootInodeLookupIsNotLogged(t *testing.T) {
	logs := captureLog(t)
	old := rootInodeSlowAfter
	rootInodeSlowAfter = 50 * time.Millisecond
	t.Cleanup(func() { rootInodeSlowAfter = old })
	withRootInodeStat(t, func(string) (uint64, error) { return 7, nil })

	require.Eventually(t, func() bool {
		_, ok, _ := mountRootInode("/proc/1/root", rootMpA)
		return ok
	}, 5*time.Second, time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, logs.String())
}
