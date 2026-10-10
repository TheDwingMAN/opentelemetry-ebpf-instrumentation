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

func TestStatGetters_DeviceMapperNameOfBlockIO(t *testing.T) {
	volumeName, ok := StatGetters(attr.DiskVolumeName)
	require.True(t, ok)
	multipathIO := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "dm-1", VolumeName: "mpatha"}}
	assert.Equal(t, "mpatha", volumeName(multipathIO).Value.AsString())
	assert.False(t, volumeName(&Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "sda"}}).Valid(),
		"omitted for the devices that are not device mapper devices")
}
