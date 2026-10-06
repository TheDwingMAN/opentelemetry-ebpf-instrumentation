// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	hostPodA = "55293f39-c745-4578-accb-f3e5cfc7b303"
	hostPodB = "e6db4197-793a-4924-8d17-2b71dbad18bb"
	kubelet  = "/var/lib/kubelet/pods/"
)

func nfsMount(id, dev, root, mountPoint string) string {
	return id + " 35 0:" + dev + " " + root + " " + mountPoint + " rw,relatime shared:1 - nfs4 10.0.0.1:/export rw"
}

// The host path is the kubelet's mount of the volume for the pod, with the
// CSI staging mount and the binds the kubelet makes elsewhere (a subPath, the
// container's own mount) left out: only the pods/<uid>/volumes path names it.
func TestHostPathIsTheKubeletMountNotAStagingOrBindMount(t *testing.T) {
	publish := kubelet + hostPodA + "/volumes/kubernetes.io~csi/pvc-abc/mount"
	withMountInfo(t,
		"30 1 0:90 / /var/lib/kubelet/plugins/kubernetes.io/csi/pv/pvc-abc/globalmount rw - ext4 /dev/sdb rw",
		"31 1 0:90 / "+publish+" rw - ext4 /dev/sdb rw",
		"32 1 0:90 /sub "+kubelet+hostPodA+"/volume-subpaths/pvc-abc/app/0 rw - ext4 /dev/sdb rw",
		"33 1 0:90 / /mnt/data rw - ext4 /dev/sdb rw",
	)

	info, ok := resolveMount(MountKey{Dev: 90})

	require.True(t, ok)
	assert.Equal(t, publish, info.HostPath)
	assert.Equal(t, publish, info.HostPathFor(hostPodA))
	assert.False(t, info.Shared)
}

// A ReadWriteMany volume has a kubelet mount per pod. Each pod gets its own
// path, never the first one in the table, and a pod without a mount gets
// none.
func TestHostPathOfASharedVolumeIsPerPod(t *testing.T) {
	mpA := kubelet + hostPodA + "/volumes/kubernetes.io~nfs/pvc-rwx"
	mpB := kubelet + hostPodB + "/volumes/kubernetes.io~nfs/pvc-rwx"
	withMountInfo(t, nfsMount("36", "32", "/", mpA), nfsMount("37", "32", "/", mpB))

	info, ok := resolveMount(MountKey{Dev: 32})

	require.True(t, ok)
	require.True(t, info.Shared)
	assert.Empty(t, info.HostPath, "a shared volume has no single path")
	assert.Equal(t, mpA, info.HostPathFor(hostPodA))
	assert.Equal(t, mpB, info.HostPathFor(hostPodB))
	assert.Empty(t, info.HostPathFor("00000000-0000-0000-0000-000000000000"))
	assert.Empty(t, info.HostPathFor(""))
}

// Several PVs a provisioner carves out of one export share a superblock and
// differ by the root of their mount: each has its own host path.
func TestHostPathOfSubdirectoryVolumesFollowsTheMountRoot(t *testing.T) {
	mpA := kubelet + hostPodA + "/volumes/kubernetes.io~nfs/pvc-aaaa"
	mpB := kubelet + hostPodB + "/volumes/kubernetes.io~csi/pvc-bbbb/mount"
	withMountInfo(t, nfsMount("36", "77", "/export/pvc-aaaa", mpA), nfsMount("37", "77", "/export/pvc-bbbb", mpB))
	inoA := withRootDir(t, mpA)
	inoB := withRootDir(t, mpB)

	infoA, _, _ := scanForMount(MountKey{Dev: 77, RootIno: inoA})
	infoB, _, _ := scanForMount(MountKey{Dev: 77, RootIno: inoB})

	assert.Equal(t, mpA, infoA.HostPath)
	assert.Equal(t, mpB, infoB.HostPath)

	unknown, ok, _ := scanForMount(MountKey{Dev: 77, RootIno: 1})
	require.True(t, ok)
	assert.Empty(t, unknown.PVName)
	assert.Empty(t, unknown.HostPath, "no volume named, no path guessed")
}

// One pod mounting a volume twice gets the same answer whatever the order of
// the table: the shortest path, ties broken by the path.
func TestHostPathOfAVolumeMountedTwiceDoesNotDependOnTableOrder(t *testing.T) {
	short := kubelet + hostPodA + "/volumes/kubernetes.io~nfs/pvc-x"
	long := kubelet + hostPodA + "/volumes/kubernetes.io~nfs/pvc-x/mount"
	for _, lines := range [][]string{
		{nfsMount("36", "32", "/", long), nfsMount("37", "32", "/", short)},
		{nfsMount("37", "32", "/", short), nfsMount("36", "32", "/", long)},
	} {
		withMountInfo(t, lines...)
		info, ok, _ := scanForMount(MountKey{Dev: 32})
		require.True(t, ok)
		assert.Equal(t, short, info.HostPath)
	}
}

// A dev number is reused once a mount is gone: after the table changes, the
// device names the new volume's path, not the old one's.
func TestHostPathOfAReusedDeviceFollowsTheNewMount(t *testing.T) {
	old := kubelet + hostPodA + "/volumes/kubernetes.io~nfs/pvc-old"
	renewed := kubelet + hostPodB + "/volumes/kubernetes.io~nfs/pvc-new"
	withMountInfo(t, nfsMount("36", "32", "/", old))

	info, ok := resolveMount(MountKey{Dev: 32})
	require.True(t, ok)
	require.Equal(t, old, info.HostPath)

	require.NoError(t, os.WriteFile(mountInfoPath, []byte(nfsMount("40", "32", "/", renewed)+"\n"), 0o644))
	invalidateMountCache()

	info, ok = resolveMount(MountKey{Dev: 32})
	require.True(t, ok)
	assert.Equal(t, "pvc-new", info.PVName)
	assert.Equal(t, renewed, info.HostPath)
}

// mountinfo writes a space in a path as \040; the label is the real path.
func TestHostPathIsUnescaped(t *testing.T) {
	withMountInfo(t, nfsMount("36", "32", "/", kubelet+hostPodA+`/volumes/kubernetes.io~nfs/pvc\040x`))

	info, ok := resolveMount(MountKey{Dev: 32})

	require.True(t, ok)
	assert.Equal(t, kubelet+hostPodA+"/volumes/kubernetes.io~nfs/pvc x", info.HostPath)
}

func TestUnescapeMountInfo(t *testing.T) {
	for in, want := range map[string]string{
		"/plain":         "/plain",
		`/a\040b`:        "/a b",
		`/tab\011x`:      "/tab\tx",
		`/back\134slash`: `/back\slash`,
		`/trailing\04`:   `/trailing\04`,
		`/not\xyz`:       `/not\xyz`,
		`\040`:           " ",
	} {
		assert.Equal(t, want, unescapeMountInfo(in), in)
	}
}
