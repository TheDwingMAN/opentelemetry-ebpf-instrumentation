// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	metricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// a fixed clock, which the returned function moves forward
func fixedClock(t *testing.T) func(time.Duration) {
	now := time.Unix(1_000_000, 0)
	previousClock := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = previousClock })
	return func(d time.Duration) { now = now.Add(d) }
}

func diskStat(device string) *ebpf.Stat {
	return &ebpf.Stat{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{Device: device, Op: ebpf.CodeDiskOpRead}}
}

// latency is the histogram of the requests of each bucket, whose latencies add up to sum
func latency(sum float64, bucketCounts ...uint64) *ebpf.LatencyHistogram {
	return &ebpf.LatencyHistogram{BucketCounts: bucketCounts, Sum: sum}
}

var deviceAttribute = []attributes.Field[*ebpf.Stat, attribute.KeyValue]{{
	ExposedName: "system.device",
	Get:         func(s *ebpf.Stat) attribute.KeyValue { return attribute.String("system.device", s.DiskIO.Device) },
}}

func produceHistograms(t *testing.T, p *kernelHistogramProducer) []metricdata.HistogramDataPoint[float64] {
	scopes, err := p.Produce(t.Context())
	require.NoError(t, err)
	if len(scopes) == 0 {
		return nil
	}
	require.Len(t, scopes, 1)
	assert.Equal(t, statScopeName, scopes[0].Scope.Name)
	require.Len(t, scopes[0].Metrics, 1)
	metric := scopes[0].Metrics[0]
	assert.Equal(t, attributes.StatDiskServiceDuration.OTEL, metric.Name)
	assert.Equal(t, "s", metric.Unit)
	histogram, ok := metric.Data.(metricdata.Histogram[float64])
	require.True(t, ok)
	return histogram.DataPoints
}

func TestKernelHistogramProducerAddsTheRequestsOfEachBucketAtOnce(t *testing.T) {
	fixedClock(t)
	p := newKernelHistogramProducer(metricdata.CumulativeTemporality, time.Hour)
	h := p.histogram(attributes.StatDiskServiceDuration, []float64{0.001, 0.01}, deviceAttribute)

	p.record(h, diskStat("sda"), latency(0.0005*3+0.001*2+0.5*1000, 5, 0, 1000))
	p.record(h, diskStat("sda"), latency(0.005*4, 0, 4, 0))

	points := produceHistograms(t, p)
	require.Len(t, points, 1)
	assert.Equal(t, uint64(1009), points[0].Count)
	assert.InDelta(t, 0.0005*3+0.001*2+0.5*1000+0.005*4, points[0].Sum, 1e-9)
	assert.Equal(t, []float64{0.001, 0.01}, points[0].Bounds)
	assert.Equal(t, []uint64{5, 4, 1000}, points[0].BucketCounts)
	device, _ := points[0].Attributes.Value("system.device")
	assert.Equal(t, "sda", device.AsString())
}

func TestKernelHistogramProducerTemporality(t *testing.T) {
	advance := fixedClock(t)
	for _, tc := range []struct {
		temporality metricdata.Temporality
		second      []uint64
		// how long after the first record the second data point starts
		secondStart time.Duration
	}{
		{metricdata.CumulativeTemporality, []uint64{3, 0}, 0},
		{metricdata.DeltaTemporality, []uint64{1, 0}, time.Minute},
	} {
		start := timeNow()
		p := newKernelHistogramProducer(tc.temporality, time.Hour)
		h := p.histogram(attributes.StatDiskServiceDuration, []float64{0.001}, deviceAttribute)
		p.record(h, diskStat("sda"), latency(0.001, 2, 0))
		advance(time.Minute)
		require.Len(t, produceHistograms(t, p), 1)

		p.record(h, diskStat("sda"), latency(0.0005, 1, 0))
		advance(time.Minute)
		points := produceHistograms(t, p)
		require.Len(t, points, 1)
		assert.Equal(t, tc.second, points[0].BucketCounts, "%v", tc.temporality)
		assert.Equal(t, start.Add(tc.secondStart), points[0].StartTime, "%v", tc.temporality)

		advance(time.Minute)
		if tc.temporality == metricdata.DeltaTemporality {
			assert.Empty(t, produceHistograms(t, p), "no request since the previous export")
		} else {
			assert.Len(t, produceHistograms(t, p), 1)
		}
	}
}

func TestKernelHistogramProducerDropsTheSeriesNotUpdatedDuringTheTTL(t *testing.T) {
	advance := fixedClock(t)
	p := newKernelHistogramProducer(metricdata.CumulativeTemporality, time.Minute)
	h := p.histogram(attributes.StatDiskServiceDuration, []float64{0.001}, deviceAttribute)
	p.record(h, diskStat("sda"), latency(0.0005, 1, 0))
	p.record(h, diskStat("sdb"), latency(0.0005, 1, 0))
	require.Len(t, produceHistograms(t, p), 2)

	advance(2 * time.Minute)
	p.record(h, diskStat("sdb"), latency(0.0005, 1, 0))
	points := produceHistograms(t, p)
	require.Len(t, points, 1)
	device, _ := points[0].Attributes.Value("system.device")
	assert.Equal(t, "sdb", device.AsString())
	assert.Equal(t, uint64(2), points[0].Count)
}
