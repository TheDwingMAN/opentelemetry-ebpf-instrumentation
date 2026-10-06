// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Two u64 counters and three u32 buckets, 4 bytes of padding.
var readerLayout = ValueLayout{Counters: 2, Buckets: 3}

const readerStride = 32

type visited struct {
	key   string
	delta []uint64
}

func pollAll(t *testing.T, r *Reader) []visited {
	t.Helper()
	return pollAt(t, r, time.Now())
}

func pollAt(t *testing.T, r *Reader, now time.Time) []visited {
	t.Helper()
	var out []visited
	require.NoError(t, r.Poll(now, func(k *kernelKey, d Delta, _ []byte) {
		out = append(out, visited{key: k.key, delta: append([]uint64(nil), d...)})
	}))
	return out
}

func TestReader_SumsCPUsAndReportsOnlyChanges(t *testing.T) {
	m := newFakeMap(4, readerStride, 4)
	r, err := NewReader(m, readerLayout)
	require.NoError(t, err)

	k := []byte("key1")
	m.addU64(k, 0, 0, 100)
	m.addU64(k, 3, 0, 50)
	m.addU64(k, 2, 1, 7)
	m.addU32(k, 1, 2, 3)
	m.addU32(k, 3, 2, 4)

	got := pollAll(t, r)
	require.Len(t, got, 1)
	assert.Equal(t, []uint64{150, 7, 0, 0, 7}, got[0].delta)

	first := r.keys["key1"].changed
	assert.Empty(t, pollAt(t, r, first.Add(time.Second)), "an unchanged key is not visited")
	assert.Equal(t, first, r.keys["key1"].changed)

	m.addU32(k, 0, 0, 1)
	got = pollAt(t, r, first.Add(2*time.Second))
	require.Len(t, got, 1)
	assert.Equal(t, []uint64{0, 0, 1, 0, 0}, got[0].delta)
	assert.Equal(t, first.Add(2*time.Second), r.keys["key1"].changed)
}

func TestReader_BucketDeltasAreWrapSafe(t *testing.T) {
	m := newFakeMap(4, readerStride, 2)
	r, err := NewReader(m, readerLayout)
	require.NoError(t, err)
	k := []byte("wrap")

	// CPU 0's copy of bucket 1 close to 2^32.
	m.addU32(k, 0, 1, math.MaxUint32-9)
	m.addU32(k, 1, 1, 3)
	got := pollAll(t, r)
	require.Len(t, got, 1)
	assert.Equal(t, uint64(math.MaxUint32-6), got[0].delta[3])

	// It wraps before the next poll, and so does the total of both CPUs.
	m.addU32(k, 0, 1, 15)
	m.addU32(k, 1, 1, 8)
	got = pollAll(t, r)
	require.Len(t, got, 1)
	assert.Equal(t, uint64(23), got[0].delta[3], "a copy and the total wrapped; the delta is still exact")

	// Both copies wrap many times over polls: every delta stays exact.
	var total uint64
	for range 40 {
		m.addU32(k, 0, 1, 1<<30)
		m.addU32(k, 1, 1, 1<<30+1)
		got = pollAll(t, r)
		require.Len(t, got, 1)
		total += got[0].delta[3]
	}
	assert.Equal(t, uint64(40*(1<<31+1)), total)
}

// The Reader keeps one total per word and key, whatever the number of CPUs.
func TestReader_StateDoesNotGrowWithCPUs(t *testing.T) {
	for _, cpus := range []int{1, 128} {
		m := newFakeMap(4, readerStride, cpus)
		r, err := NewReader(m, readerLayout)
		require.NoError(t, err)
		for cpu := range cpus {
			m.addU64([]byte("key1"), cpu, 0, 1)
			m.addU32([]byte("key1"), cpu, 2, 1)
		}
		got := pollAll(t, r)
		require.Len(t, got, 1)
		assert.Equal(t, []uint64{uint64(cpus), 0, 0, 0, uint64(cpus)}, got[0].delta)
		assert.Len(t, r.keys["key1"].prev, readerLayout.size())
	}
}

func TestReader_SignedCountersCancelAcrossCPUs(t *testing.T) {
	m := newFakeMap(4, readerStride, 2)
	r, err := NewReader(m, readerLayout)
	require.NoError(t, err)
	k := []byte("pend")

	// +3 issued on CPU 0, -2 completed on CPU 1 (two's complement).
	m.addU64(k, 0, 0, 3)
	m.addU64(k, 1, 0, uint64(math.MaxUint64-1))
	got := pollAll(t, r)
	require.Len(t, got, 1)
	assert.Equal(t, int64(1), int64(got[0].delta[0]))

	m.addU64(k, 1, 0, math.MaxUint64) // one more completion
	got = pollAll(t, r)
	require.Len(t, got, 1)
	assert.Equal(t, int64(-1), int64(got[0].delta[0]))
}

func TestReader_DeleteKeepsTheFinalDelta(t *testing.T) {
	m := newFakeMap(4, readerStride, 2)
	r, err := NewReader(m, readerLayout)
	require.NoError(t, err)
	k := []byte("gone")
	m.addU64(k, 0, 0, 10)
	pollAll(t, r)

	// Counted between the last poll and the deletion.
	m.addU64(k, 1, 0, 5)
	var final []uint64
	require.NoError(t, r.Delete(r.keys["gone"], func(_ *kernelKey, d Delta, _ []byte) {
		final = append([]uint64(nil), d...)
	}))
	assert.Equal(t, []uint64{5, 0, 0, 0, 0}, final)
	assert.Empty(t, m.entries, "the key left the kernel map")
	assert.Empty(t, r.keys, "and the reader")

	// The kernel creates the key again from zero: all of it is new.
	m.addU64(k, 0, 0, 2)
	got := pollAll(t, r)
	require.Len(t, got, 1)
	assert.Equal(t, uint64(2), got[0].delta[0])
}

func TestReader_ForgetsKeysThatLeftTheMap(t *testing.T) {
	m := newFakeMap(4, readerStride, 1)
	r, err := NewReader(m, readerLayout)
	require.NoError(t, err)
	m.addU64([]byte("a"), 0, 0, 1)
	pollAll(t, r)
	require.Contains(t, r.keys, "a")

	delete(m.entries, "a")
	pollAll(t, r)
	assert.NotContains(t, r.keys, "a")
}

func TestReader_LayoutMustFitTheValue(t *testing.T) {
	_, err := NewReader(newFakeMap(4, 16, 1), ValueLayout{Counters: 2, Buckets: 1})
	require.Error(t, err)
}

// restartingMap returns its keys twice per walk, as MapSource does when a
// batch lookup restarts with a larger batch, counting more in between.
type restartingMap struct {
	*fakeMap
	between func()
}

func (m restartingMap) ForEach(fn func(key, values []byte)) error {
	if err := m.fakeMap.ForEach(fn); err != nil {
		return err
	}
	m.between()
	return m.fakeMap.ForEach(fn)
}

func TestReader_KeysReturnedTwiceAreReadOnce(t *testing.T) {
	fm := newFakeMap(4, readerStride, 2)
	k := []byte("dup1")
	fm.addU64(k, 0, 0, 10)
	m := restartingMap{fakeMap: fm, between: func() { fm.addU64(k, 1, 0, 5) }}
	r, err := NewReader(m, readerLayout)
	require.NoError(t, err)

	start := time.Now()
	got := pollAt(t, r, start)
	require.Len(t, got, 1, "visited once per poll")
	assert.Equal(t, uint64(10), got[0].delta[0])

	m.between = func() {}
	got = pollAt(t, r, start.Add(time.Second))
	require.Len(t, got, 1)
	assert.Equal(t, uint64(5), got[0].delta[0], "what it counted during the walk comes with the next poll")
	assert.Equal(t, start.Add(time.Second), r.keys["dup1"].changed)
}