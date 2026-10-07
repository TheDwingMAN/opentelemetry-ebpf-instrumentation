// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"encoding/binary"
	"strconv"
	"testing"
	"time"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

// putPendingValue writes value's issue_ns, dev and kind fields at the
// offsets Snapshot reads (pendingValueIssueNs, pendingValueDev,
// pendingValueKind), as the kernel's blk_rq_inflight value would hold them.
func putPendingValue(value []byte, dev uint32, kind uint8, issueNs uint64) {
	binary.NativeEndian.PutUint64(value[pendingValueIssueNs:], issueNs)
	binary.NativeEndian.PutUint32(value[pendingValueDev:], dev)
	value[pendingValueKind] = kind
}

// pendingGateSizes are the step 11 "First task" gate (spec section 2.1): a
// userspace batch snapshot of the request-keyed in-flight map must cost at
// most 5 ms of CPU per poll at its largest size (blockInflightEntries,
// stats_tracer.go, caps at 64Ki); if it does not, the per-CPU counter
// fallback must be built instead. 1Ki is the floor blockInflightEntries
// sizes to, and what the spec's own perf matrix asks to record alongside
// 64Ki.
var pendingGateSizes = []int{1 << 10, 1 << 16}

// fixedSource is a statagg.Source over a fixed, unsorted slice of entries,
// built once outside the timed loop: no allocation and no ordering on
// ForEach, which is what a real cebpf.Map's BatchLookup gives (its batch
// buffers are likewise allocated once by NewMapSource and reused every
// poll). stataggtest.MemMap, used by the rest of this package's benchmarks,
// sorts its keys on every walk and allocates a new key slice doing it
// (see blk_agg_bench_test.go's own disclaimer); BenchmarkPendingReader_Snapshot
// below uses this instead, specifically because the step 11 gate is a
// decision (keep the snapshot, or fall back to per-CPU counters) that a
// sort's artificial cost must not tip.
type fixedSource struct {
	keys, values [][]byte
}

func newFixedPendingSource(entries int) *fixedSource {
	kinds := []ebpf.BlockOpCode{ebpf.CodeBlockRead, ebpf.CodeBlockWrite, ebpf.CodeBlockFlush, ebpf.CodeBlockDiscard}
	s := &fixedSource{keys: make([][]byte, entries), values: make([][]byte, entries)}
	for i := range entries {
		key := make([]byte, 8)
		// A distinct key per entry, as the struct request pointer the real
		// map is keyed by would be.
		for b := range key {
			key[b] = byte(i >> (8 * b))
		}
		value := make([]byte, pendingValueSize)
		putPendingValue(value, uint32(i%16), uint8(kinds[i%len(kinds)]), 0)
		s.keys[i], s.values[i] = key, value
	}
	return s
}

func (s *fixedSource) KeySize() int     { return 8 }
func (s *fixedSource) ValueStride() int { return pendingValueSize }
func (s *fixedSource) CPUs() int        { return 1 }

func (s *fixedSource) ForEach(fn func(key, values []byte)) error {
	for i := range s.keys {
		fn(s.keys[i], s.values[i])
	}
	return nil
}

func (s *fixedSource) LookupAndDelete([]byte, []byte) (bool, error) { return false, nil }

// BenchmarkPendingReader_Snapshot is the step 11 "First task" gate: the
// userspace cost of one batch snapshot, at the sizes the spec's perf matrix
// asks for. Run it with -benchtime (its allocations dwarf the loop
// overhead, so a handful of iterations already gives a stable ns/op).
func BenchmarkPendingReader_Snapshot(b *testing.B) {
	for _, entries := range pendingGateSizes {
		b.Run(strconv.Itoa(entries), func(b *testing.B) {
			src := newFixedPendingSource(entries)
			r := newPendingReader(func() time.Duration { return 0 }, time.Now, src)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := r.Snapshot(pendingTestTTL); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// The same snapshot when every device has gone idle past the TTL: the
// common case between bursts, where Snapshot only has its own (now empty)
// active map to walk, not the in-flight one.
func BenchmarkPendingReader_SnapshotAllIdle(b *testing.B) {
	src := newFixedPendingSource(1 << 16)
	r := newPendingReader(func() time.Duration { return 0 }, time.Now, src)
	if _, err := r.Snapshot(pendingTestTTL); err != nil {
		b.Fatal(err)
	}
	// Every request completed: the in-flight map is empty, but every key is
	// still active (reported as 0) until the TTL passes.
	r.sources = []statagg.Source{&fixedSource{}}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := r.Snapshot(pendingTestTTL); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPendingReader_SnapshotSortedDouble is the same gate on
// stataggtest.MemMap, for comparison: its per-walk sort and key
// re-allocation (see blk_agg_bench_test.go) make it a far pricier double
// than a real batch lookup, so it is kept only to show the difference
// rather than to decide the gate.
func BenchmarkPendingReader_SnapshotSortedDouble(b *testing.B) {
	for _, entries := range pendingGateSizes {
		b.Run(strconv.Itoa(entries), func(b *testing.B) {
			kinds := []ebpf.BlockOpCode{ebpf.CodeBlockRead, ebpf.CodeBlockWrite, ebpf.CodeBlockFlush, ebpf.CodeBlockDiscard}
			pm := newPendingMap()
			for i := range entries {
				dev := uint32(i % 16)
				kind := kinds[i%len(kinds)]
				pm.put(dev, uint8(kind), 0)
			}
			r := newPendingReader(func() time.Duration { return 0 }, time.Now, pm.m)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := r.Snapshot(pendingTestTTL); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
