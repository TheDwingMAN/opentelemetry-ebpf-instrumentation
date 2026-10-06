// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"os"
	"path/filepath"
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

	invalidateMountCache()

	_, ok = resolveMount(574)
	assert.False(t, ok, "expected no match after invalidation once the mount is gone")
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
	content := ""
	for _, line := range lines {
		content += line + "\n"
	}
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	old := mountInfoPath
	mountInfoPath = path
	invalidateMountCache()
	t.Cleanup(func() {
		mountInfoPath = old
		invalidateMountCache()
	})
}
