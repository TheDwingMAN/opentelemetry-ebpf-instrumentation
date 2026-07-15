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
	ev := ebpf.StatsBlockIo{Flags: 5, Op: ebpf.BlockOpWrite, Dev: 0x800010, LatencyNs: 1_500_000, Bytes: 4096}
	raw := (*[unsafe.Sizeof(ev)]byte)(unsafe.Pointer(&ev))[:]

	stat, err := readBlockIoIntoStat(&ringbuf.Record{RawSample: raw})
	require.NoError(t, err)
	require.NotNil(t, stat.BlockIo)
	assert.Equal(t, ebpf.StatTypeBlockIo, stat.Type)
	assert.Equal(t, uint32(0x800010), stat.BlockIo.Dev)
	assert.Equal(t, ebpf.BlockOpWrite, stat.BlockIo.Op)
	assert.Equal(t, uint64(1_500_000), stat.BlockIo.LatencyNs)
	assert.Equal(t, uint64(4096), stat.BlockIo.Bytes)
}
