// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// The wire structs are maintained by hand against their C counterparts in
// bpf/statsolly/types.h. A round-trip decode test cannot catch a mirror that is
// consistently wrong in both directions, so assert the byte layout directly.
func TestStatsBlockIoLayout(t *testing.T) {
	var s StatsBlockIo
	assert.Equal(t, uintptr(40), unsafe.Sizeof(s), "sizeof block_io_t")
	assert.Equal(t, uintptr(0), unsafe.Offsetof(s.Flags))
	assert.Equal(t, uintptr(1), unsafe.Offsetof(s.Op))
	assert.Equal(t, uintptr(4), unsafe.Offsetof(s.Dev))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(s.LatencyNs))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(s.QueueNs))
	assert.Equal(t, uintptr(24), unsafe.Offsetof(s.Bytes))
	assert.Equal(t, uintptr(32), unsafe.Offsetof(s.Error))
	assert.Equal(t, uintptr(36), unsafe.Offsetof(s.Inflight))
}

func TestStatsFsIoLayout(t *testing.T) {
	var s StatsFsIo
	assert.Equal(t, uintptr(32), unsafe.Sizeof(s), "sizeof fs_io_t")
	assert.Equal(t, uintptr(0), unsafe.Offsetof(s.Flags))
	assert.Equal(t, uintptr(1), unsafe.Offsetof(s.Fs))
	assert.Equal(t, uintptr(2), unsafe.Offsetof(s.Op))
	assert.Equal(t, uintptr(4), unsafe.Offsetof(s.SDev))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(s.HostPID))
	assert.Equal(t, uintptr(12), unsafe.Offsetof(s.PidNs))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(s.LatencyNs))
	assert.Equal(t, uintptr(24), unsafe.Offsetof(s.Bytes))
}

// The C discriminator values in bpf/statsolly/types.h must match these iota
// positions; a mismatch surfaces only at runtime as "unknown stats event".
func TestStatTypeDiscriminators(t *testing.T) {
	assert.Equal(t, StatType(1), StatTypeTCPRtt)
	assert.Equal(t, StatType(5), StatTypeBlockIo)
	assert.Equal(t, StatType(6), StatTypeFsIo)
}
