// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func TestReadFsIoIntoStat(t *testing.T) {
	ev := ebpf.StatsFsIo{
		Flags:     6,
		Fs:        uint8(ebpf.CodeFsNFS),
		Op:        uint8(ebpf.CodeFsOpWrite),
		SDev:      574,
		HostPID:   4242,
		PidNs:     4026531836,
		LatencyNs: 1_500_000,
		Bytes:     65536,
	}
	raw := (*[unsafe.Sizeof(ev)]byte)(unsafe.Pointer(&ev))[:]

	stat, err := handleStatEvent(&ringbuf.Record{RawSample: raw})
	require.NoError(t, err)
	require.NotNil(t, stat.FsIo)
	assert.Equal(t, ebpf.StatTypeFsIo, stat.Type)
	assert.Equal(t, uint8(ebpf.CodeFsNFS), stat.FsIo.Fs)
	assert.Equal(t, uint8(ebpf.CodeFsOpWrite), stat.FsIo.Op)
	assert.Equal(t, uint32(574), stat.FsIo.SDev)
	assert.Equal(t, uint32(4242), stat.FsIo.HostPID)
	assert.Equal(t, uint32(4026531836), stat.FsIo.PidNs)
	assert.Equal(t, uint64(1_500_000), stat.FsIo.LatencyNs)
	assert.Equal(t, uint64(65536), stat.FsIo.Bytes)
}
