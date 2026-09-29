// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nfsFixtureLine = `2827 1806 0:574 / /var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-b3befffd-ae0d-4fa0-8cef-4949329d8c3f rw,relatime shared:1625 - nfs4 10.96.84.126:/export/pvc-b3befffd rw,vers=4.1`

func TestResolveMountNFS(t *testing.T) {
	withMountInfo(t, nfsFixtureLine)

	info, ok := resolveMount(MountKey{Dev: 574})
	require.True(t, ok)
	assert.Equal(t, MountInfo{
		PodUID:     "55293f39-c745-4578-accb-f3e5cfc7b303",
		PVName:     "pvc-b3befffd-ae0d-4fa0-8cef-4949329d8c3f",
		VolumeType: "nfs",
		Server:     "10.96.84.126",
	}, info)
}

func TestResolveMountUnknownDevice(t *testing.T) {
	withMountInfo(t, nfsFixtureLine)

	_, ok := resolveMount(MountKey{Dev: 99<<20 | 1})
	assert.False(t, ok)
}

func TestResolveMountCSITrailingMountSegment(t *testing.T) {
	const csiLine = `123 1 0:900 / /var/lib/kubelet/pods/11111111-2222-3333-4444-555555555555/volumes/kubernetes.io~csi/pvc-abc/mount rw,relatime shared:99 - ext4 10.0.0.5:/export/pvc-abc rw`
	withMountInfo(t, csiLine)

	info, ok := resolveMount(MountKey{Dev: 900})
	require.True(t, ok)
	assert.Equal(t, "pvc-abc", info.PVName)
	assert.Equal(t, "csi", info.VolumeType)
}

func TestResolveMountSourceWithoutColon(t *testing.T) {
	const line = `77 1 0:41 / /var/lib/kubelet/pods/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/volumes/kubernetes.io~csi/pvc-noserver/mount rw,relatime shared:5 - ext4 /dev/sdb1 rw`
	withMountInfo(t, line)

	info, ok := resolveMount(MountKey{Dev: 41})
	require.True(t, ok)
	assert.Equal(t, "/dev/sdb1", info.Server)
}

func TestResolveMountCacheInvalidation(t *testing.T) {
	withMountInfo(t, nfsFixtureLine)

	_, ok := resolveMount(MountKey{Dev: 574})
	require.True(t, ok, "expected the fixture mount to resolve")

	// Pod/volume torn down: rewrite the fixture without that mount, but leave
	// the cache alone first to prove the cached entry is actually served
	// (not silently rescanned every call).
	const unrelatedLine = `50 1 0:20 / /run/user/1000 rw,nosuid,nodev,relatime shared:30 - tmpfs tmpfs rw,size=100k`
	require.NoError(t, os.WriteFile(mountInfoPath, []byte(unrelatedLine+"\n"), 0o644))

	_, ok = resolveMount(MountKey{Dev: 574})
	assert.True(t, ok, "expected a stale cache hit before invalidation")

	resetMountCache()

	_, ok = resolveMount(MountKey{Dev: 574})
	assert.False(t, ok, "expected no match after invalidation once the mount is gone")
}

func TestResolveMountNegativeCache(t *testing.T) {
	const unrelatedLine = `50 1 0:20 / /run/user/1000 rw,nosuid,nodev,relatime shared:30 - tmpfs tmpfs rw,size=100k`
	withMountInfo(t, unrelatedLine)

	_, ok := resolveMount(MountKey{Dev: 574})
	require.False(t, ok, "expected no match for a device with no kubelet volume mount")

	// The device now has a matching kubelet volume mount, but the negative
	// cache entry should still be served until mountCacheNegativeTTL elapses,
	// proving the miss isn't rescanned on every call.
	require.NoError(t, os.WriteFile(mountInfoPath, []byte(nfsFixtureLine+"\n"), 0o644))

	_, ok = resolveMount(MountKey{Dev: 574})
	assert.False(t, ok, "expected the negative cache entry to be served before its TTL elapses")
}

func TestWarnIfNoKubeletVolumeMounts_NoMatch(t *testing.T) {
	const unrelatedLine = `50 1 0:20 / /run/user/1000 rw,nosuid,nodev,relatime shared:30 - tmpfs tmpfs rw,size=100k`
	withMountInfo(t, unrelatedLine)

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	WarnIfNoKubeletVolumeMounts(log)

	assert.Contains(t, buf.String(), "no kubelet volume mounts visible")
}

func TestWarnIfNoKubeletVolumeMounts_Match(t *testing.T) {
	withMountInfo(t, nfsFixtureLine)

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	WarnIfNoKubeletVolumeMounts(log)

	assert.Empty(t, buf.String(), "expected no warning when a kubelet volume mount is present")
}

func TestWarnIfNoKubeletVolumeMounts_ScanError(t *testing.T) {
	old := mountInfoPath
	// No self/mountinfo file under this temp root, so scanMounts fails,
	// exercising the scan-error path rather than the no-match path.
	mountInfoPath = filepath.Join(t.TempDir(), "self", "mountinfo")
	resetMountCache()
	t.Cleanup(func() {
		mountInfoPath = old
		resetMountCache()
	})

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	WarnIfNoKubeletVolumeMounts(log)

	assert.Contains(t, buf.String(), "cannot scan mounts for kubelet volumes")
	assert.NotContains(t, buf.String(), "no kubelet volume mounts visible")
}

// withMountInfo points mountInfoPath at a fixture file containing the given
// mountinfo line(s) and clears the mount cache for the duration of a test.
func withMountInfo(t *testing.T, lines ...string) {
	t.Helper()

	dir := t.TempDir()
	// procfs.FS.GetMounts always reads "<root>/self/mountinfo", so the
	// fixture must live at that path under the temp root.
	selfDir := filepath.Join(dir, "self")
	require.NoError(t, os.MkdirAll(selfDir, 0o755))

	path := filepath.Join(selfDir, "mountinfo")
	content := strings.Join(lines, "\n") + "\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	old := mountInfoPath
	mountInfoPath = path
	resetMountCache()
	t.Cleanup(func() {
		mountInfoPath = old
		resetMountCache()
	})
	withProcRoot(t, t.TempDir())
}

// withProcRoot points the kubelet lookup at root and forgets any kubelet
// found before, so no test sees the machine's real /proc.
func withProcRoot(t *testing.T, root string) {
	t.Helper()

	reset := func() {
		kubeletMu.Lock()
		kubeletNS, kubeletPID = "", ""
		kubeletSearchedAt = time.Time{}
		kubeletMu.Unlock()
	}
	old := procRoot
	procRoot = root
	reset()
	t.Cleanup(func() {
		procRoot = old
		reset()
	})
}

// fakeProc writes a process under root: its comm, its mount and PID
// namespace links and its mountinfo.
func fakeProc(t *testing.T, root, pid, comm, mntNS, pidNS string, mountinfo ...string) {
	t.Helper()

	dir := filepath.Join(root, pid)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "ns"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644))
	require.NoError(t, os.Symlink(mntNS, filepath.Join(dir, "ns", "mnt")))
	require.NoError(t, os.Symlink(pidNS, filepath.Join(dir, "ns", "pid")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mountinfo"), []byte(strings.Join(mountinfo, "\n")+"\n"), 0o644))
}

const (
	kubeletNFSLine = "36 35 0:32 / /var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-kubens rw,relatime shared:1 - nfs 10.0.0.1:/export rw"
	rootLine       = "22 1 253:0 / / rw,relatime shared:1 - xfs /dev/vda1 rw"
	hostMnt        = "mnt:[4026531841]"
	kubensMnt      = "mnt:[4026532500]"
	hostPidNS      = "pid:[4026531836]"
)

// kubensNode writes a node with mount namespace encapsulation: init in the
// host namespace, CRI-O and the kubelet in kubens's, and returns its root.
func kubensNode(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	fakeProc(t, root, "1", "systemd", hostMnt, hostPidNS, rootLine)
	fakeProc(t, root, "812", "crio", kubensMnt, hostPidNS, kubeletNFSLine)
	fakeProc(t, root, "901", "kubelet", kubensMnt, hostPidNS, kubeletNFSLine)
	withProcRoot(t, root)
	old := mountInfoPath
	mountInfoPath = filepath.Join(root, "1", "mountinfo")
	t.Cleanup(func() { mountInfoPath = old })
	return root
}

// With OpenShift's mount namespace encapsulation the kubelet's volume mounts
// are missing from init's table; they are read from the kubelet's own.
func TestScanMountsReadsKubeletNamespace(t *testing.T) {
	kubensNode(t)

	info, ok, _ := scanForMount(MountKey{Dev: 32})

	require.True(t, ok)
	assert.Equal(t, "pvc-kubens", info.PVName)
}

// While the kubelet restarts its volume mounts stay in the namespace, and
// CRI-O is still there to read them from: attribution must not lapse.
func TestScanMountsFollowsNamespaceAcrossKubeletRestart(t *testing.T) {
	root := kubensNode(t)
	_, ok, _ := scanForMount(MountKey{Dev: 32})
	require.True(t, ok)

	require.NoError(t, os.RemoveAll(filepath.Join(root, "901")))

	info, ok, _ := scanForMount(MountKey{Dev: 32})
	require.True(t, ok, "the namespace is still readable through CRI-O")
	assert.Equal(t, "pvc-kubens", info.PVName)
}

// A kubelet sharing init's mount namespace has nothing init's table lacks.
func TestFindKubeletIgnoresInitMountNamespace(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, "1", "systemd", hostMnt, hostPidNS)
	fakeProc(t, root, "901", "kubelet", hostMnt, hostPidNS)

	_, _, ok := findKubelet(root)

	assert.False(t, ok)
}

// A kubelet inside a container (kind, a nested cluster in a CI pod) runs in
// a PID namespace of its own, and must not be taken for the node's.
func TestFindKubeletSkipsContainerizedKubelet(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, "1", "systemd", hostMnt, hostPidNS)
	fakeProc(t, root, "10234", "kubelet", "mnt:[4026533000]", "pid:[4026533001]")
	fakeProc(t, root, "4312", "kubelet", kubensMnt, hostPidNS)
	fakeProc(t, root, "77", "kubelet-helper", kubensMnt, hostPidNS)

	pid, ns, ok := findKubelet(root)

	require.True(t, ok)
	assert.Equal(t, "4312", pid)
	assert.Equal(t, kubensMnt, ns)
}

// resetMountCache clears the mount cache. Nothing in production needs this
// (mountCacheTTL / mountCacheNegativeTTL bound staleness there); tests use it
// to isolate cache state between cases.
func resetMountCache() {
	mountMu.Lock()
	mountCache = map[MountKey]mountCacheEntry{}
	mountOrder = nil
	mountMu.Unlock()
	forgetRootInodes(nil)
	rootInodeMu.Lock()
	clear(rootInodeWarnedAt)
	rootInodeMu.Unlock()
}

// The kubelet's mounts live in the host mount namespace, which hostPID makes
// readable through the host init's mountinfo. Reading it from there is what
// removes the need to bind-mount /var/lib/kubelet into the container.
func TestScanMountsReadsHostInitTable(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "1"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "1", "mountinfo"),
		[]byte("36 35 0:32 / /var/lib/kubelet/pods/"+"55293f39-c745-4578-accb-f3e5cfc7b303"+
			"/volumes/kubernetes.io~nfs/pvc-host rw,relatime shared:1 - nfs 10.0.0.1:/export rw\n"), 0o644))

	old := mountInfoPath
	mountInfoPath = filepath.Join(dir, "1", "mountinfo")
	t.Cleanup(func() { mountInfoPath = old })

	mounts, err := scanMounts()

	require.NoError(t, err)
	require.Len(t, mounts, 1)
	info, ok := parseKubeletMount(mounts[0].MountPoint, mounts[0].Source)
	require.True(t, ok)
	assert.Equal(t, "pvc-host", info.PVName)
}

// Without hostPID there is no host init to read. Rather than losing every
// volume label, fall back to this process's own mount table.
func TestScanMountsFallsBackToSelf(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "self"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "self", "mountinfo"), []byte(""), 0o644))

	old := mountInfoPath
	mountInfoPath = filepath.Join(dir, "self", "mountinfo")
	t.Cleanup(func() { mountInfoPath = old })
	withProcRoot(t, t.TempDir())

	_, err := scanMounts()

	assert.NoError(t, err, "a self-addressed path must still be readable")
}

// A ReadWriteMany volume is mounted once per pod, and every mount reports the
// same superblock. The volume is certain; the pod is not, and the resolver
// must say so rather than hand back whichever pod mounted first.
func TestScanForMountMarksSharedSuperblock(t *testing.T) {
	withMountInfo(t,
		"36 35 0:32 / /var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-shared rw,relatime shared:1 - nfs 10.0.0.1:/export rw",
		"36 35 0:32 / /var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-shared rw,relatime shared:1 - nfs 10.0.0.1:/export rw",
	)

	info, ok, _ := scanForMount(MountKey{Dev: 32})

	require.True(t, ok)
	assert.Equal(t, "pvc-shared", info.PVName, "the volume is the same for every mount")
	assert.True(t, info.Shared, "two pods on one superblock must be reported as shared")
}

// The same pod mounting a volume twice, or one mount seen twice, is not
// sharing: only a second distinct pod makes attribution ambiguous.
func TestScanForMountSinglePodIsNotShared(t *testing.T) {
	withMountInfo(t,
		"36 35 0:32 / /var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-shared rw,relatime shared:1 - nfs 10.0.0.1:/export rw",
		"37 35 0:32 / /var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-shared rw,relatime shared:1 - nfs 10.0.0.1:/export rw",
	)

	info, ok, _ := scanForMount(MountKey{Dev: 32})

	require.True(t, ok)
	assert.False(t, info.Shared)
	assert.Equal(t, "pvc-shared", info.PVName)
}

// A subdirectory provisioner carves several PVs out of one NFS export, and
// NFS gives them all the export's superblock. The device cannot say which PV
// the I/O went to, so no PV is named rather than the first one found.
func TestScanForMountDistinctVolumesOnOneSuperblock(t *testing.T) {
	withMountInfo(t,
		"36 35 0:77 /pvc-aaaa /var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~csi/pvc-aaaa/mount rw,relatime shared:1 - nfs4 10.0.0.1:/export/pvc-aaaa rw",
		"37 35 0:77 /pvc-bbbb /var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~csi/pvc-bbbb/mount rw,relatime shared:1 - nfs4 10.0.0.1:/export/pvc-bbbb rw",
	)

	info, ok, _ := scanForMount(MountKey{Dev: 77})

	require.True(t, ok, "the device is still a kubelet volume")
	assert.Empty(t, info.PVName)
	assert.False(t, info.Shared, "one pod mounts both, so the pod is still certain")
}

// A second pod mounting a volume flips Shared, which decides whether the
// mount may name a pod at all; the watcher drops the cache on such a change
// and the next lookup must see the second mount rather than the TTL.
func TestInvalidateMountCacheSeesNewSharer(t *testing.T) {
	const first = "36 35 0:32 / /var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-shared rw,relatime shared:1 - nfs 10.0.0.1:/export rw"
	const second = "37 35 0:32 / /var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-shared rw,relatime shared:1 - nfs 10.0.0.1:/export rw"
	withMountInfo(t, first)

	info, ok := resolveMount(MountKey{Dev: 32})
	require.True(t, ok)
	require.False(t, info.Shared)

	require.NoError(t, os.WriteFile(mountInfoPath, []byte(first+"\n"+second+"\n"), 0o644))

	info, _ = resolveMount(MountKey{Dev: 32})
	assert.False(t, info.Shared, "still served from cache until the table is known to have changed")

	invalidateMountCache()

	info, ok = resolveMount(MountKey{Dev: 32})
	require.True(t, ok)
	assert.True(t, info.Shared)
}

// withRootDir creates the directory a mount point is reached through, under
// the fixture table's "<proc>/<pid>/root", and returns its inode, already
// looked up as the first event of that mount would have.
func withRootDir(t *testing.T, mountPoint string) uint64 {
	t.Helper()

	dir := filepath.Join(rootOf(mountInfoPath), mountPoint)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	return knownRootInode(t, mountPoint)
}

// knownRootInode looks up the root inode of a fixture mount point and waits
// until the cache has it.
func knownRootInode(t *testing.T, mountPoint string) uint64 {
	t.Helper()

	var ino uint64
	require.Eventually(t, func() bool {
		var ok bool
		ino, ok, _ = mountRootInode(rootOf(mountInfoPath), mountPoint)
		return ok
	}, 5*time.Second, time.Millisecond)
	return ino
}

// Static PVs, or a subdirectory provisioner, carve several volumes out of one
// NFS export, and NFS gives them one superblock. The root of the mount the
// I/O went through tells which volume it was.
func TestScanForMountTellsVolumesApartByMountRoot(t *testing.T) {
	const (
		mpA = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-aaaa"
		mpB = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~csi/pvc-bbbb/mount"
	)
	withMountInfo(t,
		"36 35 0:77 /export/pvc-aaaa "+mpA+" rw,relatime shared:1 - nfs4 10.0.0.1:/export/pvc-aaaa rw",
		"37 35 0:77 /export/pvc-bbbb "+mpB+" rw,relatime shared:1 - nfs4 10.0.0.1:/export/pvc-bbbb rw",
	)
	inoA := withRootDir(t, mpA)
	inoB := withRootDir(t, mpB)

	info, ok, _ := scanForMount(MountKey{Dev: 77, RootIno: inoB})
	require.True(t, ok)
	assert.Equal(t, "pvc-bbbb", info.PVName)
	assert.Equal(t, "e6db4197-793a-4924-8d17-2b71dbad18bb", info.PodUID)
	assert.False(t, info.Shared, "only one pod mounts pvc-bbbb")

	info, ok, _ = scanForMount(MountKey{Dev: 77, RootIno: inoA})
	require.True(t, ok)
	assert.Equal(t, "pvc-aaaa", info.PVName)
}

// Two pods on one of those volumes: the volume is certain, the pod is not.
func TestScanForMountSharedVolumeOnSharedSuperblock(t *testing.T) {
	const (
		mpA1 = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-aaaa"
		mpA2 = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-aaaa"
		mpB  = "/var/lib/kubelet/pods/0ae4568c-d532-43ff-88c2-d16d7512e97b/volumes/kubernetes.io~nfs/pvc-bbbb"
	)
	withMountInfo(t,
		"36 35 0:77 /export/a "+mpA1+" rw - nfs4 10.0.0.1:/export/a rw",
		"37 35 0:77 /export/a "+mpA2+" rw - nfs4 10.0.0.1:/export/a rw",
		"38 35 0:77 /export/b "+mpB+" rw - nfs4 10.0.0.1:/export/b rw",
	)
	// Both pods' mounts of pvc-aaaa have the same root; the fixture uses one
	// directory for them by linking the second to the first.
	inoA := withRootDir(t, mpA1)
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(rootOf(mountInfoPath), mpA2)), 0o755))
	require.NoError(t, os.Symlink(filepath.Join(rootOf(mountInfoPath), mpA1), filepath.Join(rootOf(mountInfoPath), mpA2)))
	knownRootInode(t, mpA2)
	withRootDir(t, mpB)

	info, ok, _ := scanForMount(MountKey{Dev: 77, RootIno: inoA})
	require.True(t, ok)
	assert.Equal(t, "pvc-aaaa", info.PVName)
	assert.True(t, info.Shared)
}

// A root inode that matches no mount (a subPath mount, or a lookup that
// failed) leaves the volume unnamed rather than guessed.
func TestScanForMountUnknownMountRootLeavesVolumeUnnamed(t *testing.T) {
	const (
		mpA = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-aaaa"
		mpB = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-bbbb"
	)
	withMountInfo(t,
		"36 35 0:77 /a "+mpA+" rw - nfs4 10.0.0.1:/export/a rw",
		"37 35 0:77 /b "+mpB+" rw - nfs4 10.0.0.1:/export/b rw",
	)
	withRootDir(t, mpA)
	// pvc-bbbb's mount point does not exist in the fixture: its lookup fails.

	info, ok, _ := scanForMount(MountKey{Dev: 77, RootIno: 1})
	require.True(t, ok, "the device is still a kubelet volume")
	assert.Empty(t, info.PVName)
	assert.False(t, info.Shared)
}

// Resolutions are cached per mount, not per device: two volumes on one
// superblock must not share a cache entry.
func TestResolveMountCachesPerMountRoot(t *testing.T) {
	const (
		mpA = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-aaaa"
		mpB = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-bbbb"
	)
	withMountInfo(t,
		"36 35 0:77 /a "+mpA+" rw - nfs4 10.0.0.1:/export/a rw",
		"37 35 0:77 /b "+mpB+" rw - nfs4 10.0.0.1:/export/b rw",
	)
	inoA := withRootDir(t, mpA)
	inoB := withRootDir(t, mpB)

	a, _ := resolveMount(MountKey{Dev: 77, RootIno: inoA})
	b, _ := resolveMount(MountKey{Dev: 77, RootIno: inoB})
	assert.Equal(t, "pvc-aaaa", a.PVName)
	assert.Equal(t, "pvc-bbbb", b.PVName)
}

// Naming a volume on a shared superblock needs the root inode of each of its
// mounts, and on a network filesystem that lookup can hang. The decorator
// must not wait for it: the first events of the mount go out without the
// volume name, and the mount is resolved again once the inode is known.
func TestResolveMountNeverWaitsForRootInode(t *testing.T) {
	const (
		mpA        = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-aaaa"
		mpB        = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-bbbb"
		inoA, inoB = uint64(1001), uint64(1002)
	)
	withMountInfo(t,
		"36 35 0:77 /a "+mpA+" rw - nfs4 10.0.0.1:/export/a rw",
		"37 35 0:77 /b "+mpB+" rw - nfs4 10.0.0.1:/export/b rw",
	)
	release := make(chan struct{})
	withRootInodeStat(t, func(path string) (uint64, error) {
		<-release
		if strings.HasSuffix(path, mpA) {
			return inoA, nil
		}
		return inoB, nil
	})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	start := time.Now()
	info, ok := resolveMount(MountKey{Dev: 77, RootIno: inoB})
	assert.Less(t, time.Since(start), 500*time.Millisecond, "the lookup must not wait for the root inodes")
	require.True(t, ok, "the device is a kubelet volume")
	assert.Empty(t, info.PVName, "the volume is unknown until the root inodes are")

	info, _ = resolveMount(MountKey{Dev: 77, RootIno: inoB})
	assert.Empty(t, info.PVName, "a pending resolution is served from cache while the lookup runs")

	close(release)
	assert.Eventually(t, func() bool {
		info, _ := resolveMount(MountKey{Dev: 77, RootIno: inoB})
		return info.PVName == "pvc-bbbb"
	}, 5*time.Second, time.Millisecond)
}

// A root inode lookup that fails leaves the volume unnamed until the entry's
// TTL, rather than having every event rescan the table and stat again.
func TestResolveMountFailedRootInodeStaysCached(t *testing.T) {
	const mpA = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-aaaa"
	const mpB = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-bbbb"
	withMountInfo(t,
		"36 35 0:77 /a "+mpA+" rw - nfs4 10.0.0.1:/export/a rw",
		"37 35 0:77 /b "+mpB+" rw - nfs4 10.0.0.1:/export/b rw",
	)
	var stats atomic.Int32
	withRootInodeStat(t, func(string) (uint64, error) {
		stats.Add(1)
		return 0, os.ErrNotExist
	})

	resolveMount(MountKey{Dev: 77, RootIno: 5})
	require.Eventually(t, func() bool { return stats.Load() == 2 }, 5*time.Second, time.Millisecond)
	for range 10 {
		resolveMount(MountKey{Dev: 77, RootIno: 5})
	}
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(2), stats.Load(), "one lookup per mount point, not one per event")
}

// withRootInodeStat replaces how root inodes are read, and starts from an
// empty cache.
func withRootInodeStat(t *testing.T, stat func(string) (uint64, error)) {
	t.Helper()
	old := rootInodeStat
	rootInodeStat = stat
	resetMountCache()
	t.Cleanup(func() {
		rootInodeStat = old
		resetMountCache()
	})
}

// A mount table change drops only the resolutions of the devices whose mounts
// it added or removed, and the root inodes of those mount points. Every other
// mount keeps its resolution: pods starting elsewhere on the node must not
// make each volume rescan the table.
func TestMountTableWatchDropsOnlyChangedDevices(t *testing.T) {
	const (
		mpX = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-x"
		mpY = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-y"
	)
	lineX := "36 35 0:32 / " + mpX + " rw - nfs4 10.0.0.1:/x rw"
	lineY := "37 35 0:41 / " + mpY + " rw - nfs4 10.0.0.1:/y rw"
	unrelated := "50 1 0:20 / /run/user/1000 rw - tmpfs tmpfs rw"
	withMountInfo(t, lineX, lineY)
	withRootDir(t, mpX)
	withRootDir(t, mpY)

	w := newMountTableWatch()
	table := openTable(t, mountInfoPath)
	w.changed(mountInfoPath, table)
	_, ok := resolveMount(MountKey{Dev: 32})
	require.True(t, ok)
	_, ok = resolveMount(MountKey{Dev: 41})
	require.True(t, ok)

	// A pod unrelated to either volume starts: nothing is dropped.
	require.NoError(t, os.WriteFile(mountInfoPath, []byte(lineX+"\n"+lineY+"\n"+unrelated+"\n"), 0o644))
	w.changed(mountInfoPath, table)
	assert.True(t, mountCached(MountKey{Dev: 32}))
	assert.True(t, mountCached(MountKey{Dev: 41}))

	// The pod on pvc-y goes away: only its device is resolved again.
	require.NoError(t, os.WriteFile(mountInfoPath, []byte(lineX+"\n"+unrelated+"\n"), 0o644))
	w.changed(mountInfoPath, table)
	assert.True(t, mountCached(MountKey{Dev: 32}))
	assert.False(t, mountCached(MountKey{Dev: 41}))
	assert.True(t, rootInodeCached(mpX))
	assert.False(t, rootInodeCached(mpY))

	_, ok = resolveMount(MountKey{Dev: 41})
	assert.False(t, ok, "the gone volume no longer resolves")
}

// The first read of a table only records it; a table that cannot be read
// again drops every resolution, since what changed cannot be told.
func TestMountTableWatchUnreadableTableDropsAll(t *testing.T) {
	const mpX = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-x"
	withMountInfo(t, "36 35 0:32 / "+mpX+" rw - nfs4 10.0.0.1:/x rw")

	w := newMountTableWatch()
	_, ok := resolveMount(MountKey{Dev: 32})
	require.True(t, ok)
	w.changed(mountInfoPath, openTable(t, mountInfoPath))
	assert.True(t, mountCached(MountKey{Dev: 32}), "the first read only records the table")

	w.changed(mountInfoPath, unreadableTable{})
	assert.False(t, mountCached(MountKey{Dev: 32}))
}

func TestParseDevInvertsFmtDev(t *testing.T) {
	for _, dev := range []uint32{0, 32, 253<<devMinorBits | 4, 259<<devMinorBits | devMinorMask, 4095 << devMinorBits} {
		got, ok := parseDev(fmtDev(dev))
		assert.True(t, ok)
		assert.Equal(t, dev, got)
	}
	for _, bad := range []string{"", "8", "8:x", "4096:0", "0:1048576"} {
		_, ok := parseDev(bad)
		assert.False(t, ok, bad)
	}
}

func mountCached(key MountKey) bool {
	mountMu.RLock()
	defer mountMu.RUnlock()
	_, ok := mountCache[key]
	return ok
}

func rootInodeCached(mountPoint string) bool {
	rootInodeMu.Lock()
	defer rootInodeMu.Unlock()
	_, ok := rootInodes[mountPoint]
	return ok
}

// openTable opens a fixture mount table the way a watch holds it open.
func openTable(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

// unreadableTable is a mount table whose read fails.
type unreadableTable struct{}

func (unreadableTable) Read([]byte) (int, error)       { return 0, os.ErrClosed }
func (unreadableTable) Seek(int64, int) (int64, error) { return 0, os.ErrClosed }

// The watch reads a table through the file it holds open, never by its path
// again: once the process it was opened for exits, the path names no table,
// or, with the PID reused, another process's. Here the path comes to hold a
// table without the volume while the watched namespace still has it.
func TestMountTableWatchNeverReadsThePathAgain(t *testing.T) {
	const mpX = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-x"
	lineX := "36 35 0:32 / " + mpX + " rw - nfs4 10.0.0.1:/x rw"
	withMountInfo(t, rootLine, lineX)

	w := newMountTableWatch()
	table := openTable(t, mountInfoPath)
	w.changed(mountInfoPath, table)
	_, ok := resolveMount(MountKey{Dev: 32})
	require.True(t, ok)

	// The PID is reused: its path is another process's table now.
	reused := filepath.Join(t.TempDir(), "mountinfo")
	require.NoError(t, os.WriteFile(reused, []byte(rootLine+"\n"), 0o644))
	require.NoError(t, os.Rename(reused, mountInfoPath))

	w.changed(mountInfoPath, table)
	assert.True(t, mountCached(MountKey{Dev: 32}), "the watched table did not change")
}

// With OpenShift's mount namespace encapsulation the kubelet's table is
// watched through the kubelet's mountinfo. After the kubelet restarts its PID
// can belong to any process; a second pod mounting the volume must still
// make it shared, rather than the first pod being charged for its I/O until
// the resolution's TTL.
func TestKubeletNamespaceWatchSurvivesPIDReuse(t *testing.T) {
	const sharer = "37 35 0:32 / /var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-kubens rw,relatime shared:1 - nfs 10.0.0.1:/export rw"
	root := kubensNode(t)
	resetMountCache()
	t.Cleanup(resetMountCache)

	info, ok := resolveMount(MountKey{Dev: 32})
	require.True(t, ok)
	require.Equal(t, "pvc-kubens", info.PVName)
	require.False(t, info.Shared)

	w := newMountTableWatch()
	kubeletTable := filepath.Join(root, "901", "mountinfo")
	table := openTable(t, kubeletTable)
	w.changed(kubeletTable, table)

	// A second pod mounts the volume: the namespace's table, which the open
	// file and CRI-O both show, gains its mount.
	nsTable := []byte(kubeletNFSLine + "\n" + sharer + "\n")
	require.NoError(t, os.WriteFile(kubeletTable, nsTable, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "812", "mountinfo"), nsTable, 0o644))
	// The kubelet restarts, and its old PID goes to a process in another
	// mount namespace whose table is the one from before.
	require.NoError(t, os.RemoveAll(filepath.Join(root, "901")))
	fakeProc(t, root, "901", "sleep", "mnt:[4026533999]", hostPidNS, kubeletNFSLine)

	w.changed(kubeletTable, table)

	info, ok = resolveMount(MountKey{Dev: 32})
	require.True(t, ok)
	assert.Equal(t, "pvc-kubens", info.PVName)
	assert.True(t, info.Shared, "the second pod's mount must be seen through the namespace, not the reused PID")
}

// A mount table change that lands between reading the table and storing the
// resolution must not leave the resolution read before it cached: the watch
// has already dropped the device, and nothing would drop it again.
func TestResolveMountDoesNotStoreAcrossTableChange(t *testing.T) {
	const first = "36 35 0:32 / /var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-shared rw,relatime shared:1 - nfs 10.0.0.1:/export rw"
	const second = "37 35 0:32 / /var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-shared rw,relatime shared:1 - nfs 10.0.0.1:/export rw"
	withMountInfo(t, first)
	w := newMountTableWatch()
	table := openTable(t, mountInfoPath)
	w.changed(mountInfoPath, table)

	scan := mountScan
	t.Cleanup(func() { mountScan = scan })
	mountScan = func(key MountKey) (MountInfo, bool, bool) {
		info, found, pending := scan(key)
		// A second pod mounts the volume, and the watch sees it, before
		// the resolution read from the table without it is stored.
		require.NoError(t, os.WriteFile(mountInfoPath, []byte(first+"\n"+second+"\n"), 0o644))
		w.changed(mountInfoPath, table)
		return info, found, pending
	}

	info, ok := resolveMount(MountKey{Dev: 32})
	require.True(t, ok)
	assert.False(t, info.Shared, "the event was read from the table before the change")
	mountScan = scan

	assert.False(t, mountCached(MountKey{Dev: 32}), "a resolution read before a change is not stored after it")
	info, _ = resolveMount(MountKey{Dev: 32})
	assert.True(t, info.Shared)
}

func TestReadMountSetRejectsMalformedTable(t *testing.T) {
	_, err := readMountSet(strings.NewReader("36 35 0:32 / /mnt rw\n"))
	require.Error(t, err)

	set, err := readMountSet(strings.NewReader(nfsFixtureLine + "\n" + rootLine + "\n"))
	require.NoError(t, err)
	assert.Contains(t, set, mountIdentity{
		id: 2827, majMin: "0:574", root: "/",
		mountPoint: "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-b3befffd-ae0d-4fa0-8cef-4949329d8c3f",
		source:     "10.96.84.126:/export/pvc-b3befffd",
	})
	assert.Len(t, set, 2)
}

// withMountNamespace gives the fixture table's process a mount namespace, so
// the watch can tell it is still the process the table was read from.
func withMountNamespace(t *testing.T) {
	t.Helper()
	nsDir := filepath.Join(filepath.Dir(mountInfoPath), "ns")
	require.NoError(t, os.MkdirAll(nsDir, 0o755))
	require.NoError(t, os.Symlink(hostMnt, filepath.Join(nsDir, "mnt")))
}

// withRootInodesByMountPoint has root inode lookups answer inodes[mountPoint],
// and waits for every lookup to return before the test ends.
func withRootInodesByMountPoint(t *testing.T, inodes map[string]uint64) {
	t.Helper()
	withRootInodeStat(t, func(path string) (uint64, error) {
		for mp, ino := range inodes {
			if strings.HasSuffix(path, mp) {
				return ino, nil
			}
		}
		return 0, os.ErrNotExist
	})
	t.Cleanup(func() {
		require.Eventually(t, func() bool { return rootInodeLookupsRunning() == 0 }, 5*time.Second, time.Millisecond)
	})
}

// rootInodeKnownOrLooking reports whether the root inode of mountPoint is
// cached or being looked up.
func rootInodeKnownOrLooking(mountPoint string) bool {
	rootInodeMu.Lock()
	defer rootInodeMu.Unlock()
	_, known := rootInodes[mountPoint]
	return known || rootInodeBusy[mountPoint] != nil
}

// A second PV carved out of an NFS export another PV on the node already
// uses shares its superblock, so only its mount root names it. The watch
// starts looking that root up as soon as it sees the mount, not on the pod's
// first I/O, which would otherwise be exported without the volume.
func TestMountTableWatchPrewarmsSecondVolumeOnSuperblock(t *testing.T) {
	const (
		mpA        = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-aaaa"
		mpB        = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~csi/pvc-bbbb/mount"
		mpC        = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-cccc"
		inoA, inoB = uint64(1001), uint64(1002)
	)
	lineA := "36 35 0:77 /export/a " + mpA + " rw - nfs4 10.0.0.1:/export/a rw"
	lineB := "37 35 0:77 /export/b " + mpB + " rw - nfs4 10.0.0.1:/export/b rw"
	lineC := "38 35 0:32 / " + mpC + " rw - nfs4 10.0.0.2:/export rw"
	withMountInfo(t, lineA)
	withMountNamespace(t)
	withRootInodesByMountPoint(t, map[string]uint64{mpA: inoA, mpB: inoB, mpC: 3})

	w := newMountTableWatch()
	table := openTable(t, mountInfoPath)
	w.changed(mountInfoPath, table)
	info, _ := resolveMount(MountKey{Dev: 77, RootIno: inoA})
	require.Equal(t, "pvc-aaaa", info.PVName, "the device alone names a volume it does not share")
	assert.False(t, rootInodeKnownOrLooking(mpA), "no root is needed while the superblock holds one volume")

	require.NoError(t, os.WriteFile(mountInfoPath, []byte(lineA+"\n"+lineB+"\n"+lineC+"\n"), 0o644))
	w.changed(mountInfoPath, table)

	assert.True(t, rootInodeKnownOrLooking(mpB), "the new volume's root is looked up with the change")
	assert.True(t, rootInodeKnownOrLooking(mpA), "the volume that now shares its superblock needs its root too")
	assert.False(t, rootInodeKnownOrLooking(mpC), "a superblock with one volume needs no root")

	require.Eventually(t, func() bool { return rootInodeCached(mpA) && rootInodeCached(mpB) }, 5*time.Second, time.Millisecond)
	info, ok := resolveMount(MountKey{Dev: 77, RootIno: inoB})
	require.True(t, ok)
	assert.Equal(t, "pvc-bbbb", info.PVName, "the first event of the new volume is named")
}

// When the watch starts, the mounts already on a superblock holding several
// volumes have their roots looked up. A superblock with one volume, even if
// several pods mount it, needs none.
func TestMountTableWatchPrewarmsSharedSuperblocksAtStart(t *testing.T) {
	const (
		mpA   = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-aaaa"
		mpB   = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-bbbb"
		mpC   = "/var/lib/kubelet/pods/0ae4568c-d532-43ff-88c2-d16d7512e97b/volumes/kubernetes.io~nfs/pvc-cccc"
		mpRW1 = "/var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-rwx"
		mpRW2 = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-rwx"
	)
	withMountInfo(t,
		rootLine,
		"36 35 0:77 /a "+mpA+" rw - nfs4 10.0.0.1:/export/a rw",
		"37 35 0:77 /b "+mpB+" rw - nfs4 10.0.0.1:/export/b rw",
		"38 35 0:32 / "+mpC+" rw - nfs4 10.0.0.2:/export rw",
		"39 35 0:41 / "+mpRW1+" rw - nfs4 10.0.0.3:/rwx rw",
		"40 35 0:41 / "+mpRW2+" rw - nfs4 10.0.0.3:/rwx rw",
	)
	withMountNamespace(t)
	withRootInodesByMountPoint(t, map[string]uint64{mpA: 1, mpB: 2, mpC: 3, mpRW1: 4, mpRW2: 4})

	w := newMountTableWatch()
	w.changed(mountInfoPath, openTable(t, mountInfoPath))

	assert.True(t, rootInodeKnownOrLooking(mpA))
	assert.True(t, rootInodeKnownOrLooking(mpB))
	assert.False(t, rootInodeKnownOrLooking(mpC))
	assert.False(t, rootInodeKnownOrLooking(mpRW1))
	assert.False(t, rootInodeKnownOrLooking(mpRW2))
}

// The kubelet's table is watched through the kubelet's mountinfo, and roots
// are looked up through its "<proc>/<pid>/root". Once the kubelet exits and
// its PID goes to a process in another mount namespace, that root shows other
// mounts, so the watch looks nothing up through it.
func TestMountTableWatchPrewarmsOnlyThroughTheTablesNamespace(t *testing.T) {
	const (
		mp2 = "/var/lib/kubelet/pods/e6db4197-793a-4924-8d17-2b71dbad18bb/volumes/kubernetes.io~nfs/pvc-second"
		mp3 = "/var/lib/kubelet/pods/0ae4568c-d532-43ff-88c2-d16d7512e97b/volumes/kubernetes.io~nfs/pvc-third"
	)
	line2 := "37 35 0:32 /second " + mp2 + " rw,relatime shared:1 - nfs 10.0.0.1:/export/second rw"
	line3 := "38 35 0:32 /third " + mp3 + " rw,relatime shared:1 - nfs 10.0.0.1:/export/third rw"
	root := kubensNode(t)
	withRootInodesByMountPoint(t, map[string]uint64{mp2: 2, mp3: 3})

	w := newMountTableWatch()
	kubeletTable := filepath.Join(root, "901", "mountinfo")
	table := openTable(t, kubeletTable)
	w.changed(kubeletTable, table)

	require.NoError(t, os.WriteFile(kubeletTable, []byte(kubeletNFSLine+"\n"+line2+"\n"), 0o644))
	w.changed(kubeletTable, table)
	require.True(t, rootInodeKnownOrLooking(mp2), "the kubelet is still there to look roots up through")

	require.NoError(t, os.WriteFile(kubeletTable, []byte(kubeletNFSLine+"\n"+line2+"\n"+line3+"\n"), 0o644))
	require.NoError(t, os.Remove(filepath.Join(root, "901", "ns", "mnt")))
	require.NoError(t, os.Symlink("mnt:[4026533999]", filepath.Join(root, "901", "ns", "mnt")))
	w.changed(kubeletTable, table)
	assert.False(t, rootInodeKnownOrLooking(mp3), "the PID is another namespace's now")
}
