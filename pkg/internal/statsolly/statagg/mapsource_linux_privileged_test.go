// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package statagg

import (
	"encoding/binary"
	"strconv"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blkAggValue has the shape of the step 6 blk_agg value: 148 bytes, which a
// per-CPU map strides at 152.
type blkAggValue struct {
	Bytes uint64
	SumNs uint64
	Bkt   [33]uint32
}

const blkAggValueSize = 148

func newTestMap(t *testing.T, typ cebpf.MapType, entries uint32) *cebpf.Map {
	t.Helper()
	m, err := cebpf.NewMap(&cebpf.MapSpec{Type: typ, KeySize: testKeySize, ValueSize: blkAggValueSize, MaxEntries: entries})
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

func mapKey(i uint32) []byte {
	k := make([]byte, testKeySize)
	binary.NativeEndian.PutUint32(k, i)
	return k
}

func TestMapSource_PerCPUHash(t *testing.T) {
	m := newTestMap(t, cebpf.PerCPUHash, 256)
	src, err := NewMapSource(m)
	require.NoError(t, err)
	cpus := src.CPUs()
	require.Equal(t, 152, src.ValueStride())
	r, err := NewReader(src, ValueLayout{Counters: 2, Buckets: 33})
	require.NoError(t, err)

	vals := make([]blkAggValue, cpus)
	vals[0].Bytes, vals[0].Bkt[2] = 10, 1
	vals[cpus-1].Bytes, vals[cpus-1].SumNs, vals[cpus-1].Bkt[2] = 5, 700, 3
	require.NoError(t, m.Put(mapKey(1), vals))

	var deltas []Delta
	visit := func(_ *kernelKey, d Delta, _ []byte) { deltas = append(deltas, append(Delta(nil), d...)) }
	require.NoError(t, r.Poll(time.Now(), visit))
	require.Len(t, deltas, 1)
	assert.Equal(t, uint64(15), deltas[0].Counter(0))
	assert.Equal(t, uint64(700), deltas[0].Counter(1))
	assert.Equal(t, uint64(4), deltas[0][2+2])

	// The kernel counts more, then the key is deleted with its last values.
	vals[0].Bytes, vals[0].Bkt[2] = 30, 2
	require.NoError(t, m.Put(mapKey(1), vals))
	deltas = nil
	require.NoError(t, r.Delete(r.keys[string(mapKey(1))], visit))
	require.Len(t, deltas, 1)
	assert.Equal(t, uint64(20), deltas[0].Counter(0))
	assert.Equal(t, uint64(1), deltas[0][2+2])
	var v []blkAggValue
	assert.ErrorIs(t, m.Lookup(mapKey(1), &v), cebpf.ErrKeyNotExist)
}

func TestMapSource_ManyBatches(t *testing.T) {
	// A batch of one key is smaller than the hash buckets that hold two:
	// the walk restarts with larger batches, returning keys again.
	for name, batch := range map[string]int{"batches": minBatchKeys, "restarts": 1} {
		for _, typ := range []cebpf.MapType{cebpf.PerCPUHash, cebpf.Hash} {
			t.Run(name+"/"+typ.String(), func(t *testing.T) {
				testManyBatches(t, typ, batch)
			})
		}
	}
}

func testManyBatches(t *testing.T, typ cebpf.MapType, batch int) {
	t.Helper()
	m := newTestMap(t, typ, 512)
	src, err := NewMapSource(m)
	require.NoError(t, err)
	src.resize(batch)
	r, err := NewReader(src, ValueLayout{Counters: 2, Buckets: 33})
	require.NoError(t, err)

	const keys = 300
	for i := range uint32(keys) {
		if typ == cebpf.Hash {
			require.NoError(t, m.Put(mapKey(i), blkAggValue{Bytes: uint64(i) + 1}))
			continue
		}
		vals := make([]blkAggValue, src.CPUs())
		vals[0].Bytes = uint64(i) + 1
		require.NoError(t, m.Put(mapKey(i), vals))
	}

	var total uint64
	seen := map[string]int{}
	require.NoError(t, r.Poll(time.Now(), func(k *kernelKey, d Delta, _ []byte) {
		seen[k.key]++
		total += d.Counter(0)
	}))
	assert.Len(t, seen, keys)
	for _, n := range seen {
		require.Equal(t, 1, n, "every key visited once")
	}
	assert.Equal(t, uint64(keys*(keys+1)/2), total)
	if batch == 1 {
		assert.Greater(t, src.batch, 1, "the walk restarted")
	}
}

func TestMapSource_DeleteMissingKey(t *testing.T) {
	m := newTestMap(t, cebpf.Hash, 8)
	src, err := NewMapSource(m)
	require.NoError(t, err)
	found, err := src.LookupAndDelete(mapKey(9), make([]byte, src.ValueStride()))
	require.NoError(t, err)
	assert.False(t, found)
}

func TestMapSource_RejectsLRUMaps(t *testing.T) {
	for _, typ := range []cebpf.MapType{cebpf.LRUHash, cebpf.LRUCPUHash} {
		_, err := NewMapSource(newTestMap(t, typ, 8))
		assert.Error(t, err, typ)
	}
}

// NewSnapshotSource is the path a snapshot caller (PendingReader, over the
// classic-tracepoint fallback's LRU_HASH-keyed blk_rq_inflight_sector) must
// use instead of NewMapSource, which TestMapSource_RejectsLRUMaps checks
// rejects these same map types.
func TestMapSource_SnapshotSourceAcceptsLRUHash(t *testing.T) {
	m := newTestMap(t, cebpf.LRUHash, 8)
	require.NoError(t, m.Put(mapKey(1), blkAggValue{Bytes: 42}))

	src, err := NewSnapshotSource(m)
	require.NoError(t, err)

	var seen int
	require.NoError(t, src.ForEach(func(_, values []byte) {
		seen++
		assert.Equal(t, uint64(42), binary.NativeEndian.Uint64(values))
	}))
	assert.Equal(t, 1, seen)
}

func TestMapSource_SnapshotSourceAcceptsLRUCPUHash(t *testing.T) {
	m := newTestMap(t, cebpf.LRUCPUHash, 8)
	src, err := NewSnapshotSource(m)
	require.NoError(t, err)
	vals := make([]blkAggValue, src.CPUs())
	vals[0].Bytes = 7
	require.NoError(t, m.Put(mapKey(1), vals))

	var seen int
	require.NoError(t, src.ForEach(func(_, _ []byte) { seen++ }))
	assert.Equal(t, 1, seen)
}

// A poll of a real blk_agg-shaped per-CPU map where every key changed on
// every CPU: the batch lookup syscalls and the per-CPU sums. 184 keys is
// what the block plan sizes for 6 disks and 4 kinds of request, with room for
// errnos and later disks.
func BenchmarkMapSource_BlkAgg(b *testing.B) {
	for _, keys := range []uint32{64, 184} {
		b.Run(strconv.Itoa(int(keys)), func(b *testing.B) {
			m, err := cebpf.NewMap(&cebpf.MapSpec{
				Type: cebpf.PerCPUHash, KeySize: testKeySize, ValueSize: blkAggValueSize, MaxEntries: keys,
			})
			require.NoError(b, err)
			b.Cleanup(func() { m.Close() })
			src, err := NewMapSource(m)
			require.NoError(b, err)
			r, err := NewReader(src, ValueLayout{Counters: 2, Buckets: 33, Monotonic: true})
			require.NoError(b, err)

			vals := make([]blkAggValue, src.CPUs())
			put := func(n uint64) {
				for cpu := range vals {
					vals[cpu].Bytes, vals[cpu].SumNs, vals[cpu].Bkt[cpu%33] = 4096*n, 200_000*n, uint32(n)
				}
				for i := range keys {
					require.NoError(b, m.Put(mapKey(i), vals))
				}
			}
			visited := 0
			visit := func(*kernelKey, Delta, []byte) { visited++ }
			put(1)
			require.NoError(b, r.Poll(time.Now(), visit))
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				b.StopTimer()
				put(uint64(i + 2))
				visited = 0
				b.StartTimer()
				if err := r.Poll(time.Now(), visit); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			require.Equal(b, int(keys), visited)
			b.ReportMetric(float64(src.CPUs()), "cpus")
		})
	}
}
