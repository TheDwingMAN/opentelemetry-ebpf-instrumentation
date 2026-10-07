// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestFsIoGetters(t *testing.T) {
	s := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Fs: uint8(CodeFsNFS), Op: uint8(CodeFsOpWrite)}}

	fsGetter, ok := StatGetters(attr.FsType)
	assert.True(t, ok)
	assert.Equal(t, "nfs", fsGetter(s).Value.Emit())

	opGetter, ok := StatGetters(attr.FsOperation)
	assert.True(t, ok)
	assert.Equal(t, "write", opGetter(s).Value.Emit())
}

func TestFsIoGetters_Fsync(t *testing.T) {
	s := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Fs: uint8(CodeFsNFS), Op: uint8(CodeFsOpFsync)}}

	opGetter, ok := StatGetters(attr.FsOperation)
	assert.True(t, ok)
	assert.Equal(t, "fsync", opGetter(s).Value.Emit())
}

// A code with no name gives "", which omits the attribute: never a made-up
// "unknown" filesystem, and never a read for an operation this build does not
// know.
func TestFsIoGetters_UnnamedCodes(t *testing.T) {
	fsGetter, ok := StatGetters(attr.FsType)
	assert.True(t, ok)
	opGetter, ok := StatGetters(attr.FsOperation)
	assert.True(t, ok)

	assert.Empty(t, fsGetter(&Stat{}).Value.AsString())
	assert.Empty(t, opGetter(&Stat{}).Value.AsString())

	unknown := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Fs: uint8(CodeFsUnknown), Op: 200}}
	assert.Empty(t, fsGetter(unknown).Value.AsString())
	assert.Empty(t, opGetter(unknown).Value.AsString())
}

// The volume attributes come from the mount the PID decorator resolved, one
// value shared by every stat of that mount.
func TestFsIoGetters_MountAttrs(t *testing.T) {
	mount := &MountAttrs{PVName: "pvc-1", PVCName: "data", StorageClass: "fast", PVCNamespace: "ns"}
	onVolume := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Mount: mount}}
	noVolume := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{}}

	for name, want := range map[attr.Name]string{
		attr.K8sPersistentVolumeName:      "pvc-1",
		attr.K8sPersistentVolumeClaimName: "data",
		attr.K8sStorageClassName:          "fast",
	} {
		getter, ok := StatGetters(name)
		assert.True(t, ok)
		assert.Equal(t, want, getter(onVolume).Value.AsString(), name)
		assert.Empty(t, getter(noVolume).Value.AsString(), name)
		assert.Empty(t, getter(&Stat{}).Value.AsString(), name)
	}
}

// The fs join labels of step 10 (system.device, obi.disk.physical_device,
// server.address) come from the mount the PID decorator resolved, exactly
// like the PV/PVC/storage-class attributes, and are "" when there is none.
func TestFsIoGetters_JoinLabels(t *testing.T) {
	// system.device also has a block-metrics case (TestBlockIoGetters);
	// deviceName(0) falls back to "<major>:<minor>" for a stat carrying
	// neither block nor filesystem I/O, unlike the other two, which are
	// mount-only attributes with no such fallback.
	withSysBlockDir(t, t.TempDir())

	mount := &MountAttrs{SystemDevice: "vdb", PhysicalDevice: "vdb", ServerAddress: "10.0.0.5"}
	onVolume := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Mount: mount}}
	noVolume := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{}}

	for name, want := range map[attr.Name]string{
		attr.DiskDevice:         "vdb",
		attr.DiskPhysicalDevice: "vdb",
		attr.ServerAddr:         "10.0.0.5",
	} {
		getter, ok := StatGetters(name)
		require.True(t, ok)
		assert.Equal(t, want, getter(onVolume).Value.AsString(), name)
		assert.Empty(t, getter(noVolume).Value.AsString(), name)
	}
}

// k8s.node.name is the agent's node, set once and read by every stat.
func TestNodeNameGetter(t *testing.T) {
	t.Cleanup(func() { nodeName.Store(nil) })

	SetNodeName("worker-1")
	getter, ok := StatGetters(attr.K8sNodeName)
	assert.True(t, ok)
	assert.Equal(t, "worker-1", getter(&Stat{}).Value.AsString())
	assert.Equal(t, "worker-1", getter(&Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{}}).Value.AsString())

	nodeName.Store(nil)
	getter, _ = StatGetters(attr.K8sNodeName)
	assert.Empty(t, getter(&Stat{}).Value.AsString())
}

// TestFsIoErrorTypeGetter covers the platform-independent paths: no error,
// and a stat that carries no filesystem I/O event. The errno-name-on-error
// path is platform-specific (errnoName only resolves names on unix); see
// stat_getters_fs_unix_test.go.
func TestFsIoErrorTypeGetter(t *testing.T) {
	errGetter, ok := StatGetters(attr.ErrorType)
	assert.True(t, ok)

	noError := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Error: 0}}
	assert.Empty(t, errGetter(noError).Value.Emit())

	notFsIo := &Stat{Type: StatTypeTCPRtt, TCPRtt: &TCPRtt{}}
	assert.Empty(t, errGetter(notFsIo).Value.Emit())
}

// fsync(2) and fdatasync(2) reach the filesystem through the same operation
// and are told apart only by the kernel's datasync argument, which the entry
// probe turns into a distinct operation code. Reporting both as "fsync" would
// hide that a database is flushing data only.
func TestFsOpStrSeparatesFdatasync(t *testing.T) {
	getter, ok := StatGetters(attr.FsOperation)
	assert.True(t, ok)

	for _, tc := range []struct {
		op   FsOpCode
		want string
	}{
		{CodeFsOpRead, "read"},
		{CodeFsOpWrite, "write"},
		{CodeFsOpFsync, "fsync"},
		{CodeFsOpFdatasync, "fdatasync"},
		{CodeFsOpSync, "sync"},
		{CodeFsOpSyncfs, "syncfs"},
		{CodeFsOpSyncFileRange, "sync_file_range"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			s := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Fs: uint8(CodeFsNFS), Op: uint8(tc.op)}}
			assert.Equal(t, tc.want, getter(s).Value.AsString())
		})
	}
}

// The mount paths are left out, not set to "", when the stat has none: a
// stat on no kubelet volume, a sync(2), a path that is not known.
func TestFsIoGetters_MountPaths(t *testing.T) {
	mount := &MountAttrs{PVName: "pvc-1", HostPath: "/var/lib/kubelet/pods/u/volumes/kubernetes.io~csi/pvc-1/mount", ContainerPath: "/data"}
	onVolume := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Mount: mount}}
	hostOnly := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Mount: &MountAttrs{PVName: "pvc-1", HostPath: "/h"}}}
	noVolume := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{}}

	host, ok := StatGetters(attr.FsMountpoint)
	assert.True(t, ok)
	container, ok := StatGetters(attr.FsContainerMountpoint)
	assert.True(t, ok)

	assert.Equal(t, mount.HostPath, host(onVolume).Value.AsString())
	assert.Equal(t, "/data", container(onVolume).Value.AsString())
	assert.Equal(t, "/h", host(hostOnly).Value.AsString())
	assert.False(t, container(hostOnly).Valid(), "no container path known")
	assert.False(t, host(noVolume).Valid())
	assert.False(t, container(noVolume).Valid())
	assert.False(t, host(&Stat{}).Valid())

	str, ok := StatStringGetters(attr.FsMountpoint)
	assert.True(t, ok)
	assert.Empty(t, str(noVolume), "an empty Prometheus label")
}
