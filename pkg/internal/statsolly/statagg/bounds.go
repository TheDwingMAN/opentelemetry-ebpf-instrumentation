// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package statagg reads the statistics that eBPF programs aggregate in kernel
// maps and exports them as OpenTelemetry and Prometheus metrics, with the same
// series, attributes and bucket counts the per-event stats exporters produce
// for the same events.
package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"go.opentelemetry.io/obi/pkg/export"
)

// These mirror bpf/statsolly/hist.h.
const (
	// MaxExplicitBounds is k_stat_hist_max_bounds: explicit kernel histograms
	// hold at most this many bounds, plus the overflow bucket.
	MaxExplicitBounds = 32
	// MaxExponentialBounds is k_stat_hist_exp_max_bounds.
	MaxExponentialBounds = 128
)

// Exponential kernel histograms cover this range of durations with the base-2
// exponential boundaries of their scale. Values below the lowest boundary
// share its bucket (0 keeps a bucket of its own), values above the highest
// share the overflow bucket.
//
// MaxExponentialScale is the finest scale: 2, whose buckets are twice as wide
// as those of schema 3, what the Prometheus client picks for per-event native
// histograms with the default bucket_factor of 1.1, and far coarser than the
// OTel SDK's adaptive scale (up to 20). Scale 3 would need about 215 bounds
// over the range.
const (
	DefaultExponentialScale int32 = 2
	MaxExponentialScale     int32 = 2
	exponentialLowest             = time.Microsecond
	exponentialHighest            = 100 * time.Second
)

// ErrTooManyBounds is returned when a histogram needs more bounds than the
// kernel layout holds; such a family keeps the per-event path.
var ErrTooManyBounds = errors.New("too many histogram bounds for a kernel histogram")

// BoundNs returns the largest n for which time.Duration(n).Seconds() <= b,
// capped at math.MaxInt64 ns. The per-event exporters compare
// time.Duration(ns).Seconds() with their bounds, upper-inclusive, and
// Seconds() never decreases as n grows, so "ns <= BoundNs(b)" in the kernel is
// the same test, bit for bit. A negative or NaN b has no such n.
func BoundNs(b float64) (uint64, error) {
	if math.IsNaN(b) || b < 0 {
		return 0, fmt.Errorf("histogram bound %v: no duration is below it", b)
	}
	if time.Duration(math.MaxInt64).Seconds() <= b {
		return math.MaxInt64, nil
	}
	// Binary search for the last n in [0, MaxInt64) whose Seconds() <= b;
	// n = 0 always qualifies.
	lo, hi := uint64(0), uint64(math.MaxInt64)
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		if time.Duration(mid).Seconds() <= b {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo, nil
}

// LayoutKind tells explicit from exponential kernel histograms.
type LayoutKind uint8

const (
	LayoutExplicit LayoutKind = iota
	LayoutExponential
)

// Layout is the bucket layout of a kernel histogram: the bounds the kernel
// compares values with, in seconds and in nanoseconds. Bucket i of the kernel
// counts values v with BoundsNs[i-1] < v <= BoundsNs[i]; bucket len(BoundsNs)
// counts the values above every bound.
type Layout struct {
	Kind     LayoutKind
	Bounds   []float64
	BoundsNs []uint64

	// Scale and FirstIndex describe an exponential layout, whose Bounds[0]
	// is 0 (its bucket is the zero count) and whose Bounds[i] for i >= 1 is
	// the base-2 exponential boundary of index FirstIndex+i-1 at Scale.
	Scale      int32
	FirstIndex int32
}

// NewExplicitLayout returns the explicit layout that serves every exporter
// whose bounds are among sets: their sorted union. It fails when the union
// has more than MaxExplicitBounds bounds, or a bound that is not a finite
// non-negative number of seconds.
func NewExplicitLayout(sets ...[]float64) (*Layout, error) {
	bounds := export.UnionBounds(sets...)
	if len(bounds) > MaxExplicitBounds {
		return nil, fmt.Errorf("%w: %d bounds, at most %d", ErrTooManyBounds, len(bounds), MaxExplicitBounds)
	}
	boundsNs, err := boundsToNs(bounds)
	if err != nil {
		return nil, err
	}
	return &Layout{Kind: LayoutExplicit, Bounds: bounds, BoundsNs: boundsNs}, nil
}

// NewExponentialLayout returns the exponential layout at scale, at most
// MaxExponentialScale, over the kernel's fixed duration range.
func NewExponentialLayout(scale int32) (*Layout, error) {
	if scale > MaxExponentialScale {
		return nil, fmt.Errorf("%w: exponential scale %d, at most %d", ErrTooManyBounds, scale, MaxExponentialScale)
	}
	first, expBounds := export.Base2ExponentialBounds(scale,
		exponentialLowest.Seconds(), exponentialHighest.Seconds())
	bounds := append([]float64{0}, expBounds...)
	if len(bounds) > MaxExponentialBounds {
		return nil, fmt.Errorf("%w: scale %d needs %d bounds, at most %d",
			ErrTooManyBounds, scale, len(bounds), MaxExponentialBounds)
	}
	boundsNs, err := boundsToNs(bounds)
	if err != nil {
		return nil, err
	}
	return &Layout{
		Kind:       LayoutExponential,
		Bounds:     bounds,
		BoundsNs:   boundsNs,
		Scale:      scale,
		FirstIndex: first,
	}, nil
}

// HistogramChoice is what selects the kernel layout of a family's
// histograms.
type HistogramChoice struct {
	// OTelExponential is set when the OTel exporter's histogram_aggregation
	// is base2_exponential_bucket_histogram.
	OTelExponential bool
	// OptIn is the user's explicit request for exponential kernel
	// histograms, e.g. to get Prometheus native histograms.
	OptIn bool
}

// Exponential reports whether the kernel counts in the exponential layout.
// Prometheus native histograms being configured (native_histogram
// .bucket_factor, which is set by default) never selects it: in the explicit
// layout, the Prometheus exporter emits classic buckets only, and a user who
// wants native histograms from kernel aggregation opts into exponential.
func (c HistogramChoice) Exponential() bool { return c.OTelExponential || c.OptIn }

// NewLayout returns the kernel layout c selects: exponential at
// DefaultExponentialScale, or explicit over the union of the exporters'
// bound sets.
func (c HistogramChoice) NewLayout(sets ...[]float64) (*Layout, error) {
	if c.Exponential() {
		return NewExponentialLayout(DefaultExponentialScale)
	}
	return NewExplicitLayout(sets...)
}

func boundsToNs(bounds []float64) ([]uint64, error) {
	boundsNs := make([]uint64, len(bounds))
	for i, b := range bounds {
		if math.IsInf(b, 0) {
			return nil, fmt.Errorf("histogram bound %v: must be finite", b)
		}
		ns, err := BoundNs(b)
		if err != nil {
			return nil, err
		}
		boundsNs[i] = ns
	}
	return boundsNs, nil
}

// Buckets is the number of kernel buckets, the overflow bucket included.
func (l *Layout) Buckets() int { return len(l.BoundsNs) + 1 }

// KernelBounds returns the bound array the eBPF program is loaded with: the
// bounds in nanoseconds, padded with math.MaxUint64 to the size of the
// layout's array.
func (l *Layout) KernelBounds() []uint64 {
	size := MaxExplicitBounds
	if l.Kind == LayoutExponential {
		size = MaxExponentialBounds
	}
	padded := make([]uint64, size)
	copy(padded, l.BoundsNs)
	for i := len(l.BoundsNs); i < size; i++ {
		padded[i] = math.MaxUint64
	}
	return padded
}

// Fold maps each kernel bucket of an explicit layout to the bucket of an
// exporter whose bounds are among the layout's: kernel bucket i lies whole in
// exporter bucket Fold(bounds)[i], the one of the first exporter bound >=
// Bounds[i], or the exporter's overflow bucket.
func (l *Layout) Fold(bounds []float64) ([]int, error) {
	if l.Kind != LayoutExplicit {
		return nil, errors.New("only explicit layouts fold into explicit bounds")
	}
	if !slices.IsSorted(bounds) {
		return nil, fmt.Errorf("histogram bounds %v are not sorted", bounds)
	}
	for _, b := range bounds {
		if _, ok := slices.BinarySearch(l.Bounds, b); !ok {
			return nil, fmt.Errorf("histogram bound %v is not in the kernel layout %v", b, l.Bounds)
		}
	}
	fold := make([]int, l.Buckets())
	for i, b := range l.Bounds {
		fold[i], _ = slices.BinarySearch(bounds, b)
	}
	fold[len(l.Bounds)] = len(bounds)
	return fold, nil
}

// ExponentialIndex returns the base-2 exponential bucket index at l.Scale of
// kernel bucket i of an exponential layout, in the OpenTelemetry convention
// (index k counts values in (base^k, base^(k+1)]), or zero=true for the zero
// bucket. The Prometheus native histogram key of the same bucket is k+1.
func (l *Layout) ExponentialIndex(i int) (k int32, zero bool) {
	if i == 0 {
		return 0, true
	}
	return l.FirstIndex + int32(i) - 2, false
}
