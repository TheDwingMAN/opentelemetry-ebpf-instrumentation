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

func TestReadBlockIoIntoStat(t *testing.T) {
	ev := ebpf.StatsBlockIo{
		Flags:     uint8(ebpf.StatTypeBlockIo),
		Op:        uint8(ebpf.CodeDirectionWrite),
		Dev:       0x800010,
		LatencyNs: 1_500_000,
		QueueNs:   250_000,
		Bytes:     4096,
		Error:     -2,
		Inflight:  3,
	}
	raw := (*[unsafe.Sizeof(ev)]byte)(unsafe.Pointer(&ev))[:]

	stat, err := readBlockIoIntoStat(&ringbuf.Record{RawSample: raw})
	require.NoError(t, err)
	require.NotNil(t, stat.BlockIo)
	assert.Equal(t, ebpf.StatTypeBlockIo, stat.Type)
	assert.Equal(t, uint32(0x800010), stat.BlockIo.Dev)
	assert.Equal(t, uint8(ebpf.CodeDirectionWrite), stat.BlockIo.Op)
	assert.Equal(t, uint64(1_500_000), stat.BlockIo.LatencyNs)
	assert.Equal(t, uint64(250_000), stat.BlockIo.QueueNs)
	assert.Equal(t, uint64(4096), stat.BlockIo.Bytes)
	assert.Equal(t, int32(-2), stat.BlockIo.Error)
	assert.Equal(t, uint32(3), stat.BlockIo.Inflight)
}
