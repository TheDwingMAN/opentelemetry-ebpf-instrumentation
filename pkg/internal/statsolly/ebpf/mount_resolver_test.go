// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nfsFixtureLine = `2827 1806 0:574 / /var/lib/kubelet/pods/55293f39-c745-4578-accb-f3e5cfc7b303/volumes/kubernetes.io~nfs/pvc-b3befffd-ae0d-4fa0-8cef-4949329d8c3f rw,relatime shared:1625 - nfs4 10.96.84.126:/export/pvc-b3befffd rw,vers=4.1`

func TestResolveMountNFS(t *testing.T) {
	withMountInfo(t, nfsFixtureLine)

	info, ok := resolveMount(574)
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

	_, ok := resolveMount(99<<20 | 1)
	assert.False(t, ok)
}

func TestResolveMountCSITrailingMountSegment(t *testing.T) {
	const csiLine = `123 1 0:900 / /var/lib/kubelet/pods/11111111-2222-3333-4444-555555555555/volumes/kubernetes.io~csi/pvc-abc/mount rw,relatime shared:99 - ext4 10.0.0.5:/export/pvc-abc rw`
	withMountInfo(t, csiLine)

	info, ok := resolveMount(900)
	require.True(t, ok)
	assert.Equal(t, "pvc-abc", info.PVName)
	assert.Equal(t, "csi", info.VolumeType)
}

func TestResolveMountSourceWithoutColon(t *testing.T) {
	const line = `77 1 0:41 / /var/lib/kubelet/pods/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/volumes/kubernetes.io~csi/pvc-noserver/mount rw,relatime shared:5 - ext4 /dev/sdb1 rw`
	withMountInfo(t, line)

	info, ok := resolveMount(41)
	require.True(t, ok)
	assert.Equal(t, "/dev/sdb1", info.Server)
}

func TestResolveMountCacheInvalidation(t *testing.T) {
	withMountInfo(t, nfsFixtureLine)

	_, ok := resolveMount(574)
	require.True(t, ok, "expected the fixture mount to resolve")

	// Pod/volume torn down: rewrite the fixture without that mount, but leave
	// the cache alone first to prove the cached entry is actually served
	// (not silently rescanned every call).
	const unrelatedLine = `50 1 0:20 / /run/user/1000 rw,nosuid,nodev,relatime shared:30 - tmpfs tmpfs rw,size=100k`
	require.NoError(t, os.WriteFile(mountInfoPath, []byte(unrelatedLine+"\n"), 0o644))

	_, ok = resolveMount(574)
	assert.True(t, ok, "expected a stale cache hit before invalidation")

	resetMountCache()

	_, ok = resolveMount(574)
	assert.False(t, ok, "expected no match after invalidation once the mount is gone")
}

func TestResolveMountNegativeCache(t *testing.T) {
	const unrelatedLine = `50 1 0:20 / /run/user/1000 rw,nosuid,nodev,relatime shared:30 - tmpfs tmpfs rw,size=100k`
	withMountInfo(t, unrelatedLine)

	_, ok := resolveMount(574)
	require.False(t, ok, "expected no match for a device with no kubelet volume mount")

	// The device now has a matching kubelet volume mount, but the negative
	// cache entry should still be served until mountCacheNegativeTTL elapses,
	// proving the miss isn't rescanned on every call.
	require.NoError(t, os.WriteFile(mountInfoPath, []byte(nfsFixtureLine+"\n"), 0o644))

	_, ok = resolveMount(574)
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
}

// resetMountCache clears the mount cache. Nothing in production needs this
// (mountCacheTTL / mountCacheNegativeTTL bound staleness there); tests use it
// to isolate cache state between cases.
func resetMountCache() {
	mountMu.Lock()
	mountCache = map[uint32]mountCacheEntry{}
	mountOrder = nil
	mountMu.Unlock()
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

	_, err := scanMounts()

	assert.NoError(t, err, "a self-addressed path must still be readable")
}
