// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package statagg

import (
	"encoding/binary"
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
	for _, typ := range []cebpf.MapType{cebpf.PerCPUHash, cebpf.Hash} {
		t.Run(typ.String(), func(t *testing.T) {
			m := newTestMap(t, typ, 512)
			src, err := NewMapSource(m)
			require.NoError(t, err)
			src.resize(minBatchKeys)
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
			seen := map[string]bool{}
			require.NoError(t, r.Poll(time.Now(), func(k *kernelKey, d Delta, _ []byte) {
				seen[k.key] = true
				total += d.Counter(0)
			}))
			assert.Len(t, seen, keys)
			assert.Equal(t, uint64(keys*(keys+1)/2), total)
		})
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
