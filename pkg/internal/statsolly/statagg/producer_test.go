// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func TestProducer_Cumulative(t *testing.T) {
	tf := newTestFamily(t, 2, diskBounds, nil)
	p := tf.otelProducer(t, cumulative, 0)
	k := blkKey(devA, ebpf.CodeBlockWrite, 0)
	record(tf.m, tf.layout, k, 0, 10, 200_000)
	first := produce(t, p)

	tf.clock.Advance(time.Second)
	record(tf.m, tf.layout, k, 1, 10, 200_000)
	second := produce(t, p)

	io := second["test.io"].Data.(metricdata.Sum[int64])
	assert.Equal(t, metricdata.CumulativeTemporality, io.Temporality)
	assert.True(t, io.IsMonotonic)
	require.Len(t, io.DataPoints, 1)
	assert.Equal(t, int64(20), io.DataPoints[0].Value)
	assert.Equal(t, first["test.io"].Data.(metricdata.Sum[int64]).DataPoints[0].StartTime, io.DataPoints[0].StartTime,
		"a cumulative series keeps its start")

	dur := histPoint(t, second["test.duration"], devOp(devA, ebpf.CodeBlockWrite)...)
	assert.Equal(t, uint64(2), dur.Count)
	_, minSet := dur.Min.Value()
	_, maxSet := dur.Max.Value()
	assert.False(t, minSet || maxSet, "the kernel tracks no min/max")

	// Nothing new: a cumulative exporter keeps sending the series.
	tf.clock.Advance(time.Second)
	third := produce(t, p)
	assert.Equal(t, int64(20), sumValue(t, third["test.io"], devOp(devA, ebpf.CodeBlockWrite)...))
}

func TestProducer_Delta(t *testing.T) {
	tf := newTestFamily(t, 2, diskBounds, nil)
	p := tf.otelProducer(t, delta, 0)
	ka := blkKey(devA, ebpf.CodeBlockWrite, 0)
	kb := blkKey(devB, ebpf.CodeBlockWrite, 0)
	record(tf.m, tf.layout, ka, 0, 10, 200_000)
	record(tf.m, tf.layout, kb, 0, 1, 200_000)
	t0 := tf.clock.Now()
	first := produce(t, p)
	assert.Equal(t, metricdata.DeltaTemporality, first["test.io"].Data.(metricdata.Sum[int64]).Temporality)
	assert.Equal(t, int64(10), sumValue(t, first["test.io"], devOp(devA, ebpf.CodeBlockWrite)...))

	tf.clock.Advance(time.Second)
	record(tf.m, tf.layout, ka, 1, 5, 3_000_000)
	second := produce(t, p)
	io := second["test.io"].Data.(metricdata.Sum[int64])
	require.Len(t, io.DataPoints, 1, "a delta export leaves out series that counted nothing")
	assert.Equal(t, int64(5), io.DataPoints[0].Value)
	assert.Equal(t, t0, io.DataPoints[0].StartTime, "a delta starts at the previous export")

	dur := histPoint(t, second["test.duration"], devOp(devA, ebpf.CodeBlockWrite)...)
	assert.Equal(t, uint64(1), dur.Count)
	assert.Equal(t, uint64(1), dur.BucketCounts[5])
	assert.InDelta(t, 0.003, dur.Sum, 1e-12)

	tf.clock.Advance(time.Second)
	assert.Empty(t, produce(t, p), "no change, no data")
}

func TestProducer_TemporalityPerInstrumentKind(t *testing.T) {
	tf := newTestFamily(t, 1, diskBounds, nil)
	asked := map[sdkmetric.InstrumentKind]bool{}
	p := tf.otelProducer(t, func(k sdkmetric.InstrumentKind) metricdata.Temporality {
		asked[k] = true
		if k == sdkmetric.InstrumentKindHistogram {
			return metricdata.DeltaTemporality
		}
		return metricdata.CumulativeTemporality
	}, 0)
	record(tf.m, tf.layout, blkKey(devA, ebpf.CodeBlockRead, 0), 0, 1, 1)
	got := produce(t, p)
	assert.Equal(t, metricdata.DeltaTemporality, got["test.duration"].Data.(metricdata.Histogram[float64]).Temporality)
	assert.Equal(t, metricdata.CumulativeTemporality, got["test.io"].Data.(metricdata.Sum[int64]).Temporality)
	assert.True(t, asked[sdkmetric.InstrumentKindCounter])
}

func TestProducer_Exponential(t *testing.T) {
	l, err := NewExponentialLayout(DefaultExponentialScale)
	require.NoError(t, err)
	tf := newTestFamilyLayout(t, 2, l, nil)
	p := tf.otelProducer(t, cumulative, 0)
	k := blkKey(devA, ebpf.CodeBlockRead, 0)
	record(tf.m, tf.layout, k, 0, 1, 0)         // zero bucket
	record(tf.m, tf.layout, k, 0, 1, 1_000_000) // 1ms = 2^-9.97: index -40 at scale 2
	record(tf.m, tf.layout, k, 1, 1, 1_000_000)
	record(tf.m, tf.layout, k, 1, 1, 4_000_000) // 4ms: index -32

	got := produce(t, p)
	eh := got["test.duration"].Data.(metricdata.ExponentialHistogram[float64])
	require.Len(t, eh.DataPoints, 1)
	dp := eh.DataPoints[0]
	assert.Equal(t, int32(2), dp.Scale)
	assert.Equal(t, uint64(4), dp.Count)
	assert.Equal(t, uint64(1), dp.ZeroCount)
	assert.InDelta(t, 0.006, dp.Sum, 1e-12)
	// 2^(-40/4) = 0.000977 < 1ms <= 2^(-39/4): OTel index -40.
	assert.Equal(t, int32(-40), dp.PositiveBucket.Offset)
	require.Len(t, dp.PositiveBucket.Counts, 9, "indexes -40..-32")
	assert.Equal(t, uint64(2), dp.PositiveBucket.Counts[0])
	assert.Equal(t, uint64(1), dp.PositiveBucket.Counts[8])
	var n uint64
	for _, c := range dp.PositiveBucket.Counts {
		n += c
	}
	assert.Equal(t, dp.Count, n+dp.ZeroCount, "count == sum(buckets)")
}

func TestProducer_AddValidates(t *testing.T) {
	tf := newTestFamily(t, 1, diskBounds, nil)
	p := NewProducer(tf.reg, "test", cumulative, 0)
	proj, _ := devOpLabels(false)
	require.Error(t, p.Add(testDuration, OTelMetric{Bounds: []float64{0.3}, Project: proj}),
		"exporter bounds must be among the kernel's")
	require.Error(t, p.Add(testUnknown, OTelMetric{Project: proj}))
	require.Error(t, NewProducer(nil, "test", cumulative, 0).Add(testIO, OTelMetric{Project: proj}))
}

var testUnknown = attributes.Name{Section: "test.unknown", OTEL: "test.unknown", Prom: "test_unknown_total"}
