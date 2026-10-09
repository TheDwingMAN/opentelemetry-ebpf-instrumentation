// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"slices"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	metricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// kernelHistogramProducer emits the latency histograms that the kernel accumulates, such as the
// durations of the block requests or of the file syncs, as pre-aggregated histograms. An SDK
// Float64Histogram can't add the requests of a kernel bucket at once, and recording each of them
// would cost as much as the I/O rate, so, like bpfProbeLatencyProducer, this implements the SDK
// Producer interface and emits explicit bounds and bucket counts. Series that aren't updated during
// the TTL are dropped.
type kernelHistogramProducer struct {
	temporality metricdata.Temporality
	ttl         time.Duration
	// clock is read from timeNow when the producer is created, as the expirers do, so that the
	// periodic collection doesn't read the package variable
	clock func() time.Time
	// mu guards the counts of the series of the histograms
	mu         sync.Mutex
	histograms []*kernelHistogram
}

// kernelHistogram is a histogram metric, and its series
type kernelHistogram struct {
	name   attributes.Name
	bounds []float64
	attrs  []attributes.Field[*ebpf.Stat, attribute.KeyValue]
	series *expire.ExpiryMap[*kernelHistogramSeries]
}

type kernelHistogramSeries struct {
	attrs attribute.Set
	// start is when the counts started to be accumulated: when the series was created, or the
	// previous export with delta temporality
	start time.Time
	count uint64
	sum   float64
	// buckets counts the requests of each bucket: one per bound, then the overflow bucket
	buckets []uint64
}

func newKernelHistogramProducer(temporality metricdata.Temporality, ttl time.Duration) *kernelHistogramProducer {
	return &kernelHistogramProducer{temporality: temporality, ttl: ttl, clock: timeNow}
}

// histogram adds a histogram metric with the given bucket bounds and attributes
func (p *kernelHistogramProducer) histogram(
	name attributes.Name,
	bounds []float64,
	attrs []attributes.Field[*ebpf.Stat, attribute.KeyValue],
) *kernelHistogram {
	h := &kernelHistogram{
		name:   name,
		bounds: bounds,
		attrs:  attrs,
		series: expire.NewExpiryMap[*kernelHistogramSeries](p.clock, p.ttl),
	}
	p.mu.Lock()
	p.histograms = append(p.histograms, h)
	p.mu.Unlock()
	return h
}

// record adds the requests of the kernel buckets of a stat to its series of a histogram, whose
// bounds are those of the kernel buckets
func (p *kernelHistogramProducer) record(h *kernelHistogram, stat *ebpf.Stat, latency *ebpf.LatencyHistogram) {
	if h == nil || latency == nil {
		return
	}
	attrs, values := attributeSet(h.attrs, stat)
	series := h.series.GetOrCreate(values, func() *kernelHistogramSeries {
		return &kernelHistogramSeries{attrs: attrs, start: p.clock(), buckets: make([]uint64, len(h.bounds)+1)}
	})

	p.mu.Lock()
	defer p.mu.Unlock()
	for bucket, count := range latency.BucketCounts {
		series.buckets[bucket] += count
		series.count += count
	}
	series.sum += latency.Sum
}

func (p *kernelHistogramProducer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.clock()
	var metrics []metricdata.Metrics
	for _, h := range p.histograms {
		h.series.DeleteExpired()
		dataPoints := h.dataPoints(now, p.temporality)
		if len(dataPoints) == 0 {
			continue
		}
		metrics = append(metrics, metricdata.Metrics{
			Name: h.name.OTEL,
			Unit: h.name.Unit,
			Data: metricdata.Histogram[float64]{
				Temporality: p.temporality,
				DataPoints:  dataPoints,
			},
		})
	}
	if len(metrics) == 0 {
		return nil, nil
	}
	return []metricdata.ScopeMetrics{{
		Scope:   instrumentation.Scope{Name: statScopeName},
		Metrics: metrics,
	}}, nil
}

// dataPoints returns the data points of the series. With delta temporality, they count the
// requests since the previous export, and the series without any are left out.
func (h *kernelHistogram) dataPoints(now time.Time, temporality metricdata.Temporality) []metricdata.HistogramDataPoint[float64] {
	delta := temporality == metricdata.DeltaTemporality
	var dataPoints []metricdata.HistogramDataPoint[float64]
	for _, series := range h.series.All() {
		if delta && series.count == 0 {
			continue
		}
		dataPoints = append(dataPoints, metricdata.HistogramDataPoint[float64]{
			Attributes:   series.attrs,
			StartTime:    series.start,
			Time:         now,
			Count:        series.count,
			Sum:          series.sum,
			Bounds:       slices.Clone(h.bounds),
			BucketCounts: slices.Clone(series.buckets),
		})
		if delta {
			series.start = now
			series.count = 0
			series.sum = 0
			clear(series.buckets)
		}
	}
	return dataPoints
}
