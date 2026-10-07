// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stataggtest // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"

import (
	"encoding/binary"
	"sort"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

// Block's key {u32 dev; u8 op; u8 pad[3]; s32 err} and value {u64 bytes;
// u64 svc_sum_ns; u64 q_sum_ns; u32 svc_bkt[n]; u32 q_bkt[n]}.
const (
	blockKeySize = 12
	keyOpOffset  = 4
	keyErrOffset = 8

	wordBytes   = 0
	wordSvcSum  = 1
	wordQSum    = 2
	blockWords  = 3
	counterSize = 8
	bucketSize  = 4
)

// Block is a block-like kernel aggregation map for tests: in one map, what
// the step 6 blk_agg and blk_q_agg maps count for each device, request kind
// and errno, with the per-event exporters' conditions for each disk metric.
type Block struct {
	Map      *MemMap
	Layout   *statagg.Layout
	Family   *statagg.Family
	Registry *statagg.Registry
	cpus     int
}

// NewBlock returns a Block whose histograms use layout, on cpus CPUs, whose
// keys go through decorate (nil keeps them all).
func NewBlock(layout *statagg.Layout, cpus int, decorate func(*ebpf.Stat) bool) (*Block, error) {
	buckets := layout.Buckets()
	m := NewMemMap(blockKeySize, blockWords*counterSize+2*buckets*bucketSize, cpus)
	readWrite := func(s *ebpf.Stat) bool { return s.BlockIo.IsReadWrite() }
	svc := func(name attributes.Name, sel func(*ebpf.Stat) bool) *statagg.Metric {
		return &statagg.Metric{
			Name: name, Kind: statagg.KindHistogram, Select: sel,
			SumWord: wordSvcSum, BucketWord: blockWords, Layout: layout,
		}
	}
	bytes := func(d statagg.Delta) uint64 { return d.Counter(wordBytes) }

	f, err := statagg.NewFamily(statagg.Config{
		Name:     "test_blk_agg",
		Source:   m,
		Layout:   statagg.ValueLayout{Counters: blockWords, Buckets: 2 * buckets},
		Stat:     blockStat,
		Decorate: decorate,
		Metrics: []*statagg.Metric{
			svc(attributes.StatDiskOperationDuration, readWrite),
			{Name: attributes.StatDiskIO, Kind: statagg.KindCounter, Select: readWrite, Value: bytes},
			{
				Name: attributes.StatDiskQueueDuration, Kind: statagg.KindHistogram, Select: readWrite,
				SumWord: wordQSum, BucketWord: blockWords + buckets, Layout: layout,
			},
			{
				Name: attributes.StatDiskOperationErrors, Kind: statagg.KindCounter,
				Select: func(s *ebpf.Stat) bool { return s.BlockIo.IsReadWrite() && s.BlockIo.Error != 0 },
				Value:  func(d statagg.Delta) uint64 { return d.Sum(blockWords, buckets) },
			},
			svc(attributes.StatDiskFlushDuration, func(s *ebpf.Stat) bool { return s.BlockIo.IsFlush() }),
			svc(attributes.StatDiskDiscardDuration, func(s *ebpf.Stat) bool { return s.BlockIo.IsDiscard() }),
			{
				Name: attributes.StatDiskDiscardIO, Kind: statagg.KindCounter,
				Select: func(s *ebpf.Stat) bool { return s.BlockIo.IsDiscard() && s.BlockIo.Error == 0 },
				Value:  bytes,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	reg, err := statagg.NewRegistry(f)
	if err != nil {
		return nil, err
	}
	return &Block{Map: m, Layout: layout, Family: f, Registry: reg, cpus: cpus}, nil
}

func blockKey(b *ebpf.BlockIo) []byte {
	k := make([]byte, blockKeySize)
	binary.NativeEndian.PutUint32(k, b.Dev)
	k[keyOpOffset] = b.Op
	binary.NativeEndian.PutUint32(k[keyErrOffset:], uint32(b.Error))
	return k
}

func blockStat(key, _ []byte) (*ebpf.Stat, bool) {
	return &ebpf.Stat{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{
		Dev:   binary.NativeEndian.Uint32(key),
		Op:    key[keyOpOffset],
		Error: int32(binary.NativeEndian.Uint32(key[keyErrOffset:])),
	}}, true
}

// Record counts a completed block request, given as the per-event path's
// stat, the way the kernel program would, on CPU cpu. Queue time is
// recorded only when the request has one.
func (b *Block) Record(s *ebpf.Stat, cpu int) {
	io := s.BlockIo
	key := blockKey(io)
	buckets := b.Layout.Buckets()
	b.Map.AddU64(key, cpu%b.cpus, wordBytes*counterSize, io.Bytes)
	b.Map.AddU64(key, cpu%b.cpus, wordSvcSum*counterSize, io.LatencyNs)
	b.Map.AddU32(key, cpu%b.cpus, blockWords*counterSize+b.idx(io.LatencyNs)*bucketSize, 1)
	if io.QueueNs == 0 || !io.IsReadWrite() {
		return
	}
	b.Map.AddU64(key, cpu%b.cpus, wordQSum*counterSize, io.QueueNs)
	b.Map.AddU32(key, cpu%b.cpus, blockWords*counterSize+(buckets+b.idx(io.QueueNs))*bucketSize, 1)
}

func (b *Block) idx(v uint64) int { return searchBounds(b.Layout.BoundsNs, v) }

// searchBounds is bpf/statsolly/hist.h's search: the index of the first
// bound >= v, or len(bounds).
func searchBounds(bounds []uint64, v uint64) int {
	return sort.Search(len(bounds), func(i int) bool { return v <= bounds[i] })
}
