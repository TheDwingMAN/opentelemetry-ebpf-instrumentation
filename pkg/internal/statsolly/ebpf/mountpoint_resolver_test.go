// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// containerProc writes the mountinfo of a process of a container under root.
func containerProc(t *testing.T, root string, pid int, mountinfo ...string) {
	t.Helper()

	dir := filepath.Join(root, strconv.Itoa(pid))
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mountinfo"), []byte(strings.Join(mountinfo, "\n")+"\n"), 0o644))
}

func containerMount(id, dev, mountPoint string) string {
	return id + " 22 0:" + dev + " / " + mountPoint + " rw,relatime - nfs4 10.0.0.1:/export rw"
}

type clock struct {
	mu sync.Mutex
	t  time.Time
	// onAdvance forgets what the resolver caches by wall time.
	onAdvance func()
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
	if c.onAdvance != nil {
		c.onAdvance()
	}
}

func newTestMountpointResolver(root string) (*MountpointResolver, *clock) {
	c := &clock{t: time.Now()}
	r := NewMountpointResolver()
	r.procRoot = root
	r.now = c.now
	r.pidsIn = func(uint32) []uint32 { return nil }
	c.onAdvance = func() { r.tables.Purge(); r.nsPIDs.Purge() }
	return r, c
}

func TestContainerPathIsWhereTheProcessMountsTheVolume(t *testing.T) {
	root := t.TempDir()
	containerProc(t, root, 100,
		"21 1 0:5 / / rw - overlay overlay rw",
		containerMount("22", "77", "/data"),
	)
	r, _ := newTestMountpointResolver(root)

	assert.Equal(t, "/data", r.ContainerPath(1, 100, "app", MountKey{Dev: 77}))
	assert.Empty(t, r.ContainerPath(1, 100, "app", MountKey{Dev: 78}), "a device the container does not mount")
}

// A volume mounted with and without a subPath is two mounts of one device;
// the root inode of the mount the I/O went through tells which, and with no
// match the shortest path wins.
func TestContainerPathTellsMountsOfOneDeviceApartByRootInode(t *testing.T) {
	root := t.TempDir()
	containerProc(t, root, 100,
		containerMount("22", "77", "/data"),
		containerMount("23", "77", "/srv/long/path"),
		containerMount("24", "77", "/other"),
	)
	r, _ := newTestMountpointResolver(root)
	inodes := map[string]uint64{"/data": 10, "/srv/long/path": 20, "/other": 30}
	r.inode = func(path string) (uint64, error) {
		rel, err := filepath.Rel(filepath.Join(root, "100", "root"), path)
		require.NoError(t, err)
		ino, ok := inodes["/"+rel]
		if !ok {
			return 0, os.ErrNotExist
		}
		return ino, nil
	}

	key := MountKey{Dev: 77, RootIno: 20}
	assert.Empty(t, r.ContainerPath(1, 100, "app", key), "the lookup runs in the background")
	require.Eventually(t, func() bool { return r.ContainerPath(1, 100, "app", key) != "" }, 5*time.Second, time.Millisecond)
	assert.Equal(t, "/srv/long/path", r.ContainerPath(1, 100, "app", key))

	noMatch := MountKey{Dev: 77, RootIno: 99}
	require.Eventually(t, func() bool { return r.ContainerPath(1, 100, "app", noMatch) != "" }, 5*time.Second, time.Millisecond)
	assert.Equal(t, "/data", r.ContainerPath(1, 100, "app", noMatch), "the shortest mount point when none matches")

	// No inode known, as for a mount the probe could not read: no lookup.
	assert.Equal(t, "/data", r.ContainerPath(1, 100, "app", MountKey{Dev: 77}))
}

// The process that did the I/O is gone: another process of its PID namespace
// has the same mounts.
func TestContainerPathFallsBackToAnotherProcessOfTheNamespace(t *testing.T) {
	root := t.TempDir()
	containerProc(t, root, 200, containerMount("22", "77", "/data"))
	r, _ := newTestMountpointResolver(root)
	var asked []uint32
	r.pidsIn = func(ns uint32) []uint32 {
		asked = append(asked, ns)
		return []uint32{100, 150, 200}
	}

	assert.Equal(t, "/data", r.ContainerPath(4026, 100, "app", MountKey{Dev: 77}))
	assert.Equal(t, []uint32{4026}, asked)

	assert.Equal(t, "/data", r.ContainerPath(4026, 100, "app", MountKey{Dev: 77}))
	assert.Len(t, asked, 1, "served from the cache")
}

func TestContainerPathWithNoLiveProcessIsEmptyAndRetried(t *testing.T) {
	root := t.TempDir()
	r, c := newTestMountpointResolver(root)

	assert.Empty(t, r.ContainerPath(4026, 100, "app", MountKey{Dev: 77}))

	containerProc(t, root, 100, containerMount("22", "77", "/data"))
	assert.Empty(t, r.ContainerPath(4026, 100, "app", MountKey{Dev: 77}), "a miss is remembered for a moment")

	c.advance(containerMountMissTTL + time.Second)
	assert.Equal(t, "/data", r.ContainerPath(4026, 100, "app", MountKey{Dev: 77}))
}

func TestContainerPathIsCachedUntilItsTTL(t *testing.T) {
	root := t.TempDir()
	containerProc(t, root, 100, containerMount("22", "77", "/data"))
	r, c := newTestMountpointResolver(root)
	key := MountKey{Dev: 77}

	require.Equal(t, "/data", r.ContainerPath(1, 100, "app", key))

	containerProc(t, root, 100, containerMount("22", "77", "/moved"))
	assert.Equal(t, "/data", r.ContainerPath(1, 100, "app", key))

	c.advance(containerMountTTL + time.Second)
	assert.Equal(t, "/moved", r.ContainerPath(1, 100, "app", key))
}

// Containers sharing a PID namespace do not share their mounts.
func TestContainerPathKeepsContainersOfOnePIDNamespaceApart(t *testing.T) {
	root := t.TempDir()
	containerProc(t, root, 100, containerMount("22", "77", "/data"))
	containerProc(t, root, 101, containerMount("22", "77", "/mnt/vol"))
	r, _ := newTestMountpointResolver(root)

	assert.Equal(t, "/data", r.ContainerPath(1, 100, "app", MountKey{Dev: 77}))
	assert.Equal(t, "/mnt/vol", r.ContainerPath(1, 101, "sidecar", MountKey{Dev: 77}))
}

func TestContainerPathUnescapesTheMountPoint(t *testing.T) {
	root := t.TempDir()
	containerProc(t, root, 100, containerMount("22", "77", `/my\040data`))
	r, _ := newTestMountpointResolver(root)

	assert.Equal(t, "/my data", r.ContainerPath(1, 100, "app", MountKey{Dev: 77}))
}

// A stat that hangs (a dead NFS server) does not hold the resolver: the
// lookup gives up with the shortest path, and the next keys are served.
func TestContainerPathSurvivesHungRootInodeLookups(t *testing.T) {
	root := t.TempDir()
	containerProc(t, root, 100,
		containerMount("22", "77", "/data"),
		containerMount("23", "77", "/srv/long/path"),
	)
	r, c := newTestMountpointResolver(root)
	r.lookupTimeout = 20 * time.Millisecond
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	r.inode = func(string) (uint64, error) { <-release; return 0, nil }

	// More hung keys than there are lookup slots.
	for i := range 2 * maxContainerMountLookups {
		key := MountKey{Dev: 77, RootIno: uint64(100 + i)}
		assert.Empty(t, r.ContainerPath(1, 100, "app"+strconv.Itoa(i%4), key))
		c.advance(containerMountPendingTTL + time.Millisecond)
		require.Eventually(t, func() bool {
			r.mu.Lock()
			defer r.mu.Unlock()
			return len(r.inflight) == 0
		}, 2*time.Second, time.Millisecond)
	}
	// Every hung key was answered with the shortest path, once it timed out.
	assert.Equal(t, "/data", r.ContainerPath(1, 100, "app0", MountKey{Dev: 77, RootIno: 100}))
}

// The mount table of a process is parsed once for all the volumes of its
// container, and a dead namespace is listed once for all of its keys.
func TestContainerPathSharesTheWorkOfKeysOfOneContainer(t *testing.T) {
	root := t.TempDir()
	containerProc(t, root, 200, containerMount("22", "77", "/a"), containerMount("23", "78", "/b"))
	r, c := newTestMountpointResolver(root)
	listed := 0
	r.pidsIn = func(uint32) []uint32 { listed++; return []uint32{200} }

	assert.Equal(t, "/a", r.ContainerPath(4026, 100, "app", MountKey{Dev: 77}))
	assert.Equal(t, "/b", r.ContainerPath(4026, 100, "app", MountKey{Dev: 78}))
	assert.Equal(t, 1, listed, "one listing of the namespace for both volumes")

	// A namespace with no process is remembered too.
	dead := 0
	r.pidsIn = func(uint32) []uint32 { dead++; return nil }
	for dev := uint32(80); dev < 85; dev++ {
		assert.Empty(t, r.ContainerPath(5000, 100, "app", MountKey{Dev: dev}))
	}
	assert.Equal(t, 1, dead)

	c.advance(containerMountMissTTL + time.Second)
	assert.Empty(t, r.ContainerPath(5000, 100, "app", MountKey{Dev: 80}))
	assert.Equal(t, 2, dead, "asked again after the TTL")
}

func TestPidsInNamespaceReadsThePIDLinks(t *testing.T) {
	root := t.TempDir()
	for pid, ns := range map[string]string{"10": "pid:[4026]", "11": "pid:[4027]", "12": "pid:[4026]"} {
		dir := filepath.Join(root, pid, "ns")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.Symlink(ns, filepath.Join(dir, "pid")))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(root, "self"), 0o755))
	r := NewMountpointResolver()
	r.procRoot = root

	assert.ElementsMatch(t, []uint32{10, 12}, r.pidsInNamespace(4026))
}

// BenchmarkContainerPathCached is the cost of the answer once it is known,
// which is what every stat after the first of a container pays.
func BenchmarkContainerPathCached(b *testing.B) {
	root := b.TempDir()
	dir := filepath.Join(root, "100")
	require.NoError(b, os.MkdirAll(dir, 0o755))
	require.NoError(b, os.WriteFile(filepath.Join(dir, "mountinfo"), []byte(containerMount("22", "77", "/data")+"\n"), 0o644))
	r := NewMountpointResolver()
	r.procRoot = root
	key := MountKey{Dev: 77, RootIno: 5}
	require.Equal(b, "/data", r.ContainerPath(4026, 100, "app", key))

	b.ReportAllocs()
	for b.Loop() {
		r.ContainerPath(4026, 100, "app", key)
	}
}

// BenchmarkContainerPathMiss is the cost of the first stat of a container
// and mount: one read of the process's mount table.
func BenchmarkContainerPathMiss(b *testing.B) {
	root := b.TempDir()
	dir := filepath.Join(root, "100")
	require.NoError(b, os.MkdirAll(dir, 0o755))
	lines := []string{"21 1 0:5 / / rw - overlay overlay rw", containerMount("22", "77", "/data")}
	for i := range 60 {
		lines = append(lines, containerMount(strconv.Itoa(30+i), strconv.Itoa(100+i), "/secrets/s"+strconv.Itoa(i)))
	}
	require.NoError(b, os.WriteFile(filepath.Join(dir, "mountinfo"), []byte(strings.Join(lines, "\n")+"\n"), 0o644))
	r := NewMountpointResolver()
	r.procRoot = root

	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		r.ContainerPath(4026, 100, "app", MountKey{Dev: 77, RootIno: uint64(i)})
	}
}
