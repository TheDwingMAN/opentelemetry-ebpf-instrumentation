// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// TestNFSRPCNetworkIoDirectionGetter covers the direction mapping
// StatNFSClientIO's two series rely on: whichever of them is projecting a
// stat sets NFSRPC.Direction right before its attributes are read, since
// the kernel key the direction comes from counts both of them together.
func TestNFSRPCNetworkIoDirectionGetter(t *testing.T) {
	getter, ok := StatGetters(attr.NetworkIoDirection)
	assert.True(t, ok)

	transmit := &Stat{Type: StatTypeNFSRPC, NFSRPC: &NFSRPC{Direction: uint8(CodeDirectionTransmit)}}
	assert.Equal(t, "transmit", getter(transmit).Value.Emit())

	receive := &Stat{Type: StatTypeNFSRPC, NFSRPC: &NFSRPC{Direction: uint8(CodeDirectionReceive)}}
	assert.Equal(t, "receive", getter(receive).Value.Emit())

	// A stat with no NFSRPC falls through like one with no TCPIo: the zero
	// value, which maps to neither direction, rather than a crash.
	assert.Empty(t, getter(&Stat{}).Value.Emit())
}
