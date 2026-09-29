// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package parity

import (
	"math"
	"math/rand/v2"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
)

const cpus = 4

var blockFeatures = export.FeatureStorageBlockDuration | export.FeatureStorageBlockIo |
	export.FeatureStorageBlockQueue | export.FeatureStorageBlockErrors |
	export.FeatureStorageBlockFlush | export.FeatureStorageBlockDiscard

// blockEvents is a deterministic stream of block completions on two disks:
// every kind, some failures, latencies from 1us to 10s, and values exactly
// on and next to each bound. avoid, when set, keeps latencies at least 2 ns
// away from its bounds: exponential boundaries are rounded to whole
// nanoseconds, so a value within 1 ns of one may land a bucket off.
func blockEvents(n int, bounds []uint64, avoid bool) []*ebpf.Stat {
	rnd := rand.New(rand.NewPCG(11, 12))
	devs := []uint32{252<<20 | 0, 252<<20 | 16}
	kinds := []ebpf.BlockOpCode{ebpf.CodeBlockRead, ebpf.CodeBlockWrite, ebpf.CodeBlockFlush, ebpf.CodeBlockDiscard}
	latency := func() uint64 {
		for {
			v := uint64(math.Pow(10, 3+rnd.Float64()*7))
			if !avoid || !nearBound(bounds, v) {
				return v
			}
		}
	}
	var events []*ebpf.Stat
	for i := range n {
		op := kinds[rnd.IntN(len(kinds))]
		var errno int32
		if rnd.IntN(10) == 0 {
			errno = []int32{-5, -61, -110}[rnd.IntN(3)]
		}
		var queue uint64
		if rnd.IntN(3) > 0 {
			queue = latency()
		}
		lat := latency()
		if !avoid && i < 2*len(bounds) {
			// On a bound, then one above it.
			lat = bounds[i/2] + uint64(i%2)
		}
		events = append(events, &ebpf.Stat{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{
			Dev: devs[rnd.IntN(len(devs))], Op: uint8(op), Error: errno,
			Bytes: uint64(rnd.IntN(64)+1) * 4096, LatencyNs: lat, QueueNs: queue,
		}})
	}
	return events
}

func nearBound(bounds []uint64, v uint64) bool {
	i := sort.Search(len(bounds), func(i int) bool { return bounds[i] >= v })
	for _, j := range []int{i - 1, i} {
		if j >= 0 && j < len(bounds) {
			d := int64(bounds[j]) - int64(v)
			if d >= -2 && d <= 2 {
				return true
			}
		}
	}
	return false
}

func blockKernel(t *testing.T, layout *statagg.Layout) func(decorate func(*ebpf.Stat) bool) Kernel {
	return func(decorate func(*ebpf.Stat) bool) Kernel {
		b, err := stataggtest.NewBlock(layout, cpus, decorate)
		require.NoError(t, err)
		n := 0
		return Kernel{
			Registry: b.Registry,
			Families: []*statagg.Family{b.Family},
			Record: func(s *ebpf.Stat) {
				b.Record(s, n)
				n++
			},
		}
	}
}

func TestParity_ExplicitBuckets(t *testing.T) {
	otelBuckets := export.DefaultBuckets
	promBuckets := export.DefaultBuckets
	// The exporters' bounds differ: the kernel counts in their union.
	promBuckets.StatDiskOperationDurationHistogram = []float64{0.0005, 0.001, 0.003, 0.01, 0.1, 1}
	layout, err := statagg.NewExplicitLayout(otelBuckets.StatDiskOperationDurationHistogram, promBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)

	Run(t, Setup{Features: blockFeatures, OTelBuckets: otelBuckets, PromBuckets: promBuckets},
		blockEvents(3000, layout.BoundsNs, false), blockKernel(t, layout))
}

func TestParity_ExponentialBuckets(t *testing.T) {
	layout, err := statagg.NewExponentialLayout(statagg.DefaultExponentialScale)
	require.NoError(t, err)
	Run(t, Setup{
		Features:    blockFeatures,
		OTelBuckets: export.DefaultBuckets,
		PromBuckets: export.DefaultBuckets,
		Exponential: true,
	}, blockEvents(3000, layout.BoundsNs, true), blockKernel(t, layout))
}

func TestParity_FiltersDropTheSameSeries(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)
	for name, filters := range map[string]filter.AttributeFamilyConfig{
		"direction": {"disk.io.direction": filter.MatchDefinition{Match: "read"}},
		"error":     {"error.type": filter.MatchDefinition{NotMatch: "ETIMEDOUT"}},
	} {
		t.Run(name, func(t *testing.T) {
			Run(t, Setup{
				Features:    blockFeatures,
				Filters:     filters,
				OTelBuckets: export.DefaultBuckets,
				PromBuckets: export.DefaultBuckets,
			}, blockEvents(1000, layout.BoundsNs, false), blockKernel(t, layout))
		})
	}
}

// With error.type selected on operation.duration, the failed and successful
// requests of a disk are separate series in both paths.
func TestParity_AttributeSelection(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)
	Run(t, Setup{
		Features: blockFeatures,
		Selection: attributes.Selection{
			attributes.StatDiskOperationDuration.Section: attributes.InclusionLists{Include: []string{"*"}},
			attributes.StatDiskIO.Section:                attributes.InclusionLists{Exclude: []string{"disk.io.direction"}},
		},
		OTelBuckets: export.DefaultBuckets,
		PromBuckets: export.DefaultBuckets,
	}, blockEvents(1000, layout.BoundsNs, false), blockKernel(t, layout))
}
