// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg

import (
	"math"
	"math/rand/v2"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
)

// kernelIdx is what bpf/statsolly/hist.h computes: the first bound >= v, or
// the overflow bucket.
func kernelIdx(boundsNs []uint64, v uint64) int {
	return sort.Search(len(boundsNs), func(i int) bool { return v <= boundsNs[i] })
}

// sdkIdx is what the OTel SDK and the Prometheus client compute for an
// explicit bucket histogram: the first bound >= the observed seconds.
func sdkIdx(bounds []float64, v uint64) int {
	return sort.SearchFloat64s(bounds, time.Duration(v).Seconds())
}

func TestBoundNs_IsTheExactSecondsComparison(t *testing.T) {
	rnd := rand.New(rand.NewPCG(1, 2))
	check := func(b float64) {
		n, err := BoundNs(b)
		require.NoError(t, err)
		assert.LessOrEqual(t, time.Duration(n).Seconds(), b, "bound %v -> %d", b, n)
		if n < math.MaxInt64 {
			assert.Greater(t, time.Duration(n+1).Seconds(), b, "bound %v -> %d is not the largest", b, n)
		}
	}
	for _, b := range export.DefaultBuckets.DurationHistogram {
		check(b)
	}
	for _, b := range export.DefaultBuckets.StatDiskOperationDurationHistogram {
		check(b)
	}
	for range 20000 {
		// Uniform over 1ns..1000s in log space, plus exact nanosecond
		// multiples and values just off them.
		b := math.Pow(10, -9+rnd.Float64()*12)
		check(b)
		ns := float64(int64(b*1e9)) / 1e9
		check(ns)
		check(math.Nextafter(ns, math.Inf(1)))
		check(math.Nextafter(ns, 0))
	}
	check(0)
	check(time.Duration(math.MaxInt64).Seconds())
	check(math.MaxFloat64)
}

func TestBoundNs_RejectsNegative(t *testing.T) {
	_, err := BoundNs(-0.001)
	require.Error(t, err)
	_, err = BoundNs(math.NaN())
	require.Error(t, err)
}

func TestExplicitLayout_KernelBucketEqualsSDKBucket(t *testing.T) {
	bounds := export.DefaultBuckets.StatDiskOperationDurationHistogram
	l, err := NewExplicitLayout(bounds)
	require.NoError(t, err)

	rnd := rand.New(rand.NewPCG(3, 4))
	probe := func(v uint64) {
		assert.Equal(t, sdkIdx(bounds, v), kernelIdx(l.BoundsNs, v), "value %d ns", v)
	}
	for _, ns := range l.BoundsNs {
		probe(ns)
		probe(ns + 1)
		if ns > 0 {
			probe(ns - 1)
		}
	}
	for range 100000 {
		probe(uint64(math.Pow(10, rnd.Float64()*11)))
	}
	probe(0)
	probe(math.MaxInt64)
}

func TestExplicitLayout_UnionFoldsBackExactly(t *testing.T) {
	otelBounds := []float64{0.001, 0.01, 0.1, 1}
	promBounds := []float64{0.0005, 0.001, 0.005, 0.1, 2.5}
	l, err := NewExplicitLayout(otelBounds, promBounds)
	require.NoError(t, err)
	assert.Equal(t, []float64{0.0005, 0.001, 0.005, 0.01, 0.1, 1, 2.5}, l.Bounds)

	rnd := rand.New(rand.NewPCG(5, 6))
	for _, exporter := range [][]float64{otelBounds, promBounds} {
		fold, err := l.Fold(exporter)
		require.NoError(t, err)
		require.Len(t, fold, l.Buckets())
		for range 50000 {
			v := uint64(math.Pow(10, 3+rnd.Float64()*7))
			assert.Equal(t, sdkIdx(exporter, v), fold[kernelIdx(l.BoundsNs, v)], "value %d ns", v)
		}
		for _, ns := range l.BoundsNs {
			assert.Equal(t, sdkIdx(exporter, ns), fold[kernelIdx(l.BoundsNs, ns)])
			assert.Equal(t, sdkIdx(exporter, ns+1), fold[kernelIdx(l.BoundsNs, ns+1)])
		}
	}
}

func TestExplicitLayout_Limits(t *testing.T) {
	many := make([]float64, MaxExplicitBounds+1)
	for i := range many {
		many[i] = float64(i+1) / 1000
	}
	_, err := NewExplicitLayout(many[:MaxExplicitBounds])
	require.NoError(t, err)
	_, err = NewExplicitLayout(many)
	require.ErrorIs(t, err, ErrTooManyBounds)
	// 16 + 17 distinct bounds: each fits, their union does not.
	_, err = NewExplicitLayout(many[:16], many[16:])
	require.ErrorIs(t, err, ErrTooManyBounds)

	_, err = NewExplicitLayout([]float64{0.1, math.Inf(1)})
	require.Error(t, err)
	_, err = NewExplicitLayout([]float64{-1})
	require.Error(t, err)
}

func TestExplicitLayout_FoldRejectsForeignBounds(t *testing.T) {
	l, err := NewExplicitLayout([]float64{0.1, 1})
	require.NoError(t, err)
	_, err = l.Fold([]float64{0.5})
	require.Error(t, err)
	_, err = l.Fold([]float64{1, 0.1})
	require.Error(t, err)

	fold, err := l.Fold(nil)
	require.NoError(t, err)
	assert.Equal(t, []int{0, 0, 0}, fold, "no bounds: everything is the one overflow bucket")
}

func TestKernelBounds_Padded(t *testing.T) {
	l, err := NewExplicitLayout([]float64{0, 0.5})
	require.NoError(t, err)
	kb := l.KernelBounds()
	require.Len(t, kb, MaxExplicitBounds)
	assert.Equal(t, uint64(0), kb[0])
	assert.Equal(t, uint64(500_000_000), kb[1])
	for _, b := range kb[2:] {
		assert.Equal(t, uint64(math.MaxUint64), b)
	}

	e, err := NewExponentialLayout(DefaultExponentialScale)
	require.NoError(t, err)
	assert.Len(t, e.KernelBounds(), MaxExponentialBounds)
}

func TestExponentialLayout(t *testing.T) {
	l, err := NewExponentialLayout(DefaultExponentialScale)
	require.NoError(t, err)
	// 1us..100s at scale 2: indexes -80..27, plus the zero bound.
	assert.Equal(t, int32(-80), l.FirstIndex)
	assert.Len(t, l.Bounds, 109)
	assert.Equal(t, 0.0, l.Bounds[0])
	assert.LessOrEqual(t, l.Bounds[1], 1e-6)
	assert.GreaterOrEqual(t, l.Bounds[len(l.Bounds)-1], 100.0)
	assert.True(t, sort.Float64sAreSorted(l.Bounds))

	_, err = NewExponentialLayout(3)
	require.ErrorIs(t, err, ErrTooManyBounds, "scale 3 needs more than 128 bounds over 1us..100s")
	_, err = NewExponentialLayout(-2)
	require.NoError(t, err)
}

// Every kernel bucket of an exponential layout is the OpenTelemetry bucket
// (base^k, base^(k+1)] of its index, for values inside the covered range.
func TestExponentialLayout_IndexMatchesTheBase2Buckets(t *testing.T) {
	for _, scale := range []int32{-1, 0, 1, 2} {
		l, err := NewExponentialLayout(scale)
		require.NoError(t, err)
		base := math.Exp2(math.Exp2(-float64(scale)))

		k, zero := l.ExponentialIndex(kernelIdx(l.BoundsNs, 0))
		assert.True(t, zero, "0 is the zero count")
		assert.Zero(t, k)

		rnd := rand.New(rand.NewPCG(7, uint64(scale+10)))
		for range 20000 {
			v := uint64(math.Pow(10, 3+rnd.Float64()*8)) // 1us..100s
			k, zero := l.ExponentialIndex(kernelIdx(l.BoundsNs, v))
			require.False(t, zero)
			secs := time.Duration(v).Seconds()
			lower, upper := math.Pow(base, float64(k)), math.Pow(base, float64(k+1))
			// Boundaries are rounded to whole nanoseconds.
			assert.True(t, secs > lower-1e-9 && secs <= upper+1e-9,
				"scale %d: %v s in bucket %d (%v, %v]", scale, secs, k, lower, upper)
		}
	}
}
