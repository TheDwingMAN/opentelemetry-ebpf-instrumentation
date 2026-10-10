// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
)

func TestStatGetters_DiskIO(t *testing.T) {
	failedWrite := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{
		Device:    "nvme0n1",
		Op:        CodeDiskOpWrite,
		ErrorType: "EIO",
	}}
	okRead := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{
		Device: "vda",
		Op:     CodeDiskOpRead,
	}}

	device, ok := StatGetters(attr.SystemDevice)
	require.True(t, ok)
	assert.Equal(t, "nvme0n1", device(failedWrite).Value.AsString())

	direction, ok := StatGetters(attr.DiskIODirection)
	require.True(t, ok)
	assert.Equal(t, "write", direction(failedWrite).Value.AsString())
	assert.Equal(t, "read", direction(okRead).Value.AsString())

	errorType, ok := StatGetters(attr.ErrorType)
	require.True(t, ok)
	assert.Equal(t, "EIO", errorType(failedWrite).Value.AsString())
	// error.type only applies to failed requests: omitted instead of emitted empty
	assert.False(t, errorType(okRead).Valid())

	errorTypeString, ok := StatStringGetters(attr.ErrorType)
	require.True(t, ok)
	assert.Empty(t, errorTypeString(okRead))
}

func TestStatGetters_DeviceMapperNameOfBlockIO(t *testing.T) {
	volumeName, ok := StatGetters(attr.DiskVolumeName)
	require.True(t, ok)
	multipathIO := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "dm-1", VolumeName: "mpatha"}}
	assert.Equal(t, "mpatha", volumeName(multipathIO).Value.AsString())
	assert.False(t, volumeName(&Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "sda"}}).Valid(),
		"omitted for the devices that are not device mapper devices")
}

func TestStatGetters_NFSProcedure(t *testing.T) {
	failed := &Stat{Type: StatTypeNFSProcedure, NFSProcedure: &NFSProcedure{
		Server: "10.0.0.5", Procedure: "GETATTR", Version: 4, ErrorType: "ESTALE",
	}}
	succeeded := &Stat{Type: StatTypeNFSProcedure, NFSProcedure: &NFSProcedure{Server: "10.0.0.5", Procedure: "READ", Version: 3}}

	server, ok := StatGetters(attr.ServerAddr)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.5", server(failed).Value.AsString())

	procedure, ok := StatGetters(attr.OncRPCProcedureName)
	require.True(t, ok)
	assert.Equal(t, "GETATTR", procedure(failed).Value.AsString())

	version, ok := StatGetters(attr.OncRPCVersion)
	require.True(t, ok)
	assert.Equal(t, int64(3), version(succeeded).Value.AsInt64())
	versionString, ok := StatStringGetters(attr.OncRPCVersion)
	require.True(t, ok)
	assert.Equal(t, "4", versionString(failed))

	errorType, ok := StatGetters(attr.ErrorType)
	require.True(t, ok)
	assert.Equal(t, "ESTALE", errorType(failed).Value.AsString())
	assert.False(t, errorType(succeeded).Valid())
}

func TestStatGetters_NFSIO(t *testing.T) {
	read := &Stat{Type: StatTypeNFSIO, NFSIO: &NFSIO{Server: "fd00::5", Direction: uint8(CodeDirectionReceive)}}
	write := &Stat{Type: StatTypeNFSIO, NFSIO: &NFSIO{Server: "fd00::5", Direction: uint8(CodeDirectionTransmit)}}

	direction, ok := StatGetters(attr.NetworkIoDirection)
	require.True(t, ok)
	assert.Equal(t, "receive", direction(read).Value.AsString())
	assert.Equal(t, "transmit", direction(write).Value.AsString())

	server, ok := StatGetters(attr.ServerAddr)
	require.True(t, ok)
	assert.Equal(t, "fd00::5", server(write).Value.AsString())

	procedure, ok := StatGetters(attr.OncRPCProcedureName)
	require.True(t, ok)
	assert.False(t, procedure(write).Valid(), "transferred bytes have no procedure")
}

func TestStatContainerID(t *testing.T) {
	assert.Equal(t, "aaaa", (&Stat{DiskIO: &DiskIO{ContainerID: "aaaa"}}).ContainerID())
	assert.Equal(t, "bbbb", (&Stat{FsSync: &FsSync{ContainerID: "bbbb"}}).ContainerID())
	assert.Empty(t, (&Stat{TCPRetransmit: true}).ContainerID())
}

func TestStatGetters_FsSync(t *testing.T) {
	failedSync := &Stat{Type: StatTypeFsSync, FsSync: &FsSync{Type: CodeFsSyncFdatasync, ErrorType: "EIO", ContainerID: "0123abcd"}}
	okSync := &Stat{Type: StatTypeFsSync, FsSync: &FsSync{Type: CodeFsSyncSync}}

	syncType, ok := StatGetters(attr.FsSyncType)
	require.True(t, ok)
	assert.Equal(t, "fdatasync", syncType(failedSync).Value.AsString())
	assert.Equal(t, "sync", syncType(okSync).Value.AsString())
	assert.False(t, syncType(&Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{}}).Valid(), "the block I/O has no sync type")

	errorType, ok := StatGetters(attr.ErrorType)
	require.True(t, ok)
	assert.Equal(t, "EIO", errorType(failedSync).Value.AsString())
	assert.False(t, errorType(okSync).Valid(), "omitted for the successful syncs")

	containerID, ok := StatGetters(attr.ContainerID)
	require.True(t, ok)
	assert.Equal(t, "0123abcd", containerID(failedSync).Value.AsString())
	assert.False(t, containerID(okSync).Valid())

	// the attributes of the block I/O are omitted
	device, ok := StatGetters(attr.SystemDevice)
	require.True(t, ok)
	assert.False(t, device(okSync).Valid())
}

func TestFsSyncTypeStr(t *testing.T) {
	for code, name := range map[FsSyncTypeCode]string{
		CodeFsSyncFsync: "fsync", CodeFsSyncFdatasync: "fdatasync", CodeFsSyncSync: "sync",
		CodeFsSyncSyncfs: "syncfs", CodeFsSyncSyncFileRange: "sync_file_range", 0: "unknown",
	} {
		assert.Equal(t, name, fsSyncTypeStr(code))
	}
}

func TestStatGetters_DiskIOContainer(t *testing.T) {
	inContainer := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{ContainerID: "0123abcd"}}
	onHost := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{}}

	containerID, ok := StatGetters(attr.ContainerID)
	require.True(t, ok)
	assert.Equal(t, "0123abcd", containerID(inContainer).Value.AsString())
	assert.False(t, containerID(onHost).Valid(), "omitted for I/O charged to no container")
}

// The Kubernetes metadata of the I/O charged to no pod, or of a node whose cluster name is unknown,
// is omitted from the storage stats instead of being exported empty
func TestStatGetters_StorageOmitsUnknownKubernetesMetadata(t *testing.T) {
	inPod := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{}, CommonAttrs: pipe.CommonAttrs{Metadata: map[attr.Name]string{
		attr.K8sNamespaceName: "storage",
	}}}
	podLess := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{}}
	podLessSync := &Stat{Type: StatTypeFsSync, FsSync: &FsSync{}}

	namespace, ok := StatGetters(attr.K8sNamespaceName)
	require.True(t, ok)
	assert.Equal(t, "storage", namespace(inPod).Value.AsString())
	assert.False(t, namespace(podLess).Valid())
	assert.False(t, namespace(podLessSync).Valid())
}

// The TCP stats keep exporting the Kubernetes metadata that they don't know, as before
func TestStatGetters_TCPKeepsEmptyClusterName(t *testing.T) {
	clusterName, ok := StatGetters(attr.K8sClusterName)
	require.True(t, ok)
	value := clusterName(&Stat{Type: StatTypeTCPRtt, TCPRtt: &TCPRtt{}})
	assert.True(t, value.Valid())
	assert.Empty(t, value.Value.AsString())
}
