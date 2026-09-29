// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

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
	} {
		t.Run(tc.want, func(t *testing.T) {
			s := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Fs: uint8(CodeFsNFS), Op: uint8(tc.op)}}
			assert.Equal(t, tc.want, getter(s).Value.AsString())
		})
	}
}
