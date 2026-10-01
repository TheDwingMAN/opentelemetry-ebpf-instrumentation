// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
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

func TestStatGetters_DiskPartition(t *testing.T) {
	onPartition := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "nvme0n1", Partition: "nvme0n1p2"}}
	onDisk := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "nvme0n1"}}

	partition, ok := StatGetters(attr.DiskPartition)
	require.True(t, ok)
	assert.Equal(t, "nvme0n1p2", partition(onPartition).Value.AsString())
	assert.False(t, partition(onDisk).Valid(), "omitted for I/O on the whole disk")
}

func TestStatGetters_DiskOperationsWithoutDirection(t *testing.T) {
	flush := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "sda", Op: CodeDiskOpFlush}}
	discard := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "sda", Op: CodeDiskOpDiscard}}

	direction, ok := StatGetters(attr.DiskIODirection)
	require.True(t, ok)
	assert.False(t, direction(flush).Valid(), "flushes neither read nor write")
	assert.False(t, direction(discard).Valid(), "discards neither read nor write")
}

func TestStatGetters_DiskPending(t *testing.T) {
	pending := &Stat{Type: StatTypeDiskPending, DiskPending: &DiskPending{Device: "sdb", Op: CodeDiskOpRead, Requests: 3}}

	device, ok := StatGetters(attr.SystemDevice)
	require.True(t, ok)
	assert.Equal(t, "sdb", device(pending).Value.AsString())

	direction, ok := StatGetters(attr.DiskIODirection)
	require.True(t, ok)
	assert.Equal(t, "read", direction(pending).Value.AsString())
}

func TestStatGetters_FsSync(t *testing.T) {
	failed := &Stat{Type: StatTypeFsSync, FsSync: &FsSync{ErrorType: "EIO", ContainerID: "0123abcd"}}
	succeeded := &Stat{Type: StatTypeFsSync, FsSync: &FsSync{}}

	errorType, ok := StatGetters(attr.ErrorType)
	require.True(t, ok)
	assert.Equal(t, "EIO", errorType(failed).Value.AsString())
	assert.False(t, errorType(succeeded).Valid())

	containerID, ok := StatGetters(attr.ContainerID)
	require.True(t, ok)
	assert.Equal(t, "0123abcd", containerID(failed).Value.AsString())
	assert.False(t, containerID(succeeded).Valid())
}

func TestStatGetters_NFSProcedure(t *testing.T) {
	failed := &Stat{Type: StatTypeNFSProcedure, NFSProcedure: &NFSProcedure{
		Server: "10.0.0.5", Procedure: "GETATTR", Version: 4, ErrorType: "ESTALE", ContainerID: "0123abcd",
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

	containerID, ok := StatGetters(attr.ContainerID)
	require.True(t, ok)
	assert.Equal(t, "0123abcd", containerID(failed).Value.AsString())
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

func TestStatGetters_PodVolume(t *testing.T) {
	volume := &Stat{Type: StatTypePodVolume, PodVolume: &PodVolume{
		VolumeName: "data", ClaimName: "data-db-0", PersistentVolume: "pvc-5d1c",
		MountedDevice: "dm-0", Device: "sda", Value: 1,
	}}
	for name, expected := range map[attr.Name]string{
		attr.K8sVolumeName:                "data",
		attr.K8sVolumeType:                "persistentVolumeClaim",
		attr.K8sPersistentVolumeClaimName: "data-db-0",
		attr.K8sPersistentVolumeName:      "pvc-5d1c",
		attr.DiskVolumeDevice:             "dm-0",
		attr.SystemDevice:                 "sda",
	} {
		getter, ok := StatGetters(name)
		require.True(t, ok)
		assert.Equal(t, expected, getter(volume).Value.AsString(), name)
	}

	volumeName, ok := StatGetters(attr.K8sVolumeName)
	require.True(t, ok)
	assert.False(t, volumeName(&Stat{DiskIO: &DiskIO{Device: "sda"}}).Valid(), "block I/O has no volume")
}

func TestStatContainerID(t *testing.T) {
	assert.Equal(t, "aaaa", (&Stat{DiskIO: &DiskIO{ContainerID: "aaaa"}}).ContainerID())
	assert.Equal(t, "bbbb", (&Stat{FsSync: &FsSync{ContainerID: "bbbb"}}).ContainerID(),
		"file syncs are charged to containers too")
	assert.Equal(t, "cccc", (&Stat{NFSProcedure: &NFSProcedure{ContainerID: "cccc"}}).ContainerID())
	assert.Equal(t, "dddd", (&Stat{NFSIO: &NFSIO{ContainerID: "dddd"}}).ContainerID())
	assert.Empty(t, (&Stat{TCPRetransmit: true}).ContainerID())
}

func TestStatGetters_DiskIOContainer(t *testing.T) {
	inContainer := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{ContainerID: "0123abcd"}}
	onHost := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{}}

	containerID, ok := StatGetters(attr.ContainerID)
	require.True(t, ok)
	assert.Equal(t, "0123abcd", containerID(inContainer).Value.AsString())
	assert.False(t, containerID(onHost).Valid(), "omitted for I/O charged to no container")
}
