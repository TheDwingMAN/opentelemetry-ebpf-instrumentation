// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// kernelHistogramVec exposes a latency histogram that the kernel accumulates, such as the
// durations of the block requests, as classic histograms. A client
// histogram can't add the requests of a kernel bucket at once, and observing each of them would
// cost as much as the I/O rate, so the series are kept here and exposed as const histograms, like
// the eBPF probe latencies. Series that aren't updated during the TTL are dropped.
type kernelHistogramVec struct {
	desc   *prometheus.Desc
	bounds []float64
	series *expire.ExpiryMap[*kernelHistogramSeries]
	// mu guards the counts of the series
	mu sync.Mutex
}

type kernelHistogramSeries struct {
	labels []string
	count  uint64
	sum    float64
	// buckets counts the requests of each bucket: one per bound, then the overflow bucket
	buckets []uint64
}

func newKernelHistogramVec(name, help string, bounds []float64, labelNames []string, ttl time.Duration) *kernelHistogramVec {
	return &kernelHistogramVec{
		desc:   prometheus.NewDesc(name, help, labelNames, nil),
		bounds: bounds,
		series: expire.NewExpiryMap[*kernelHistogramSeries](timeNow, ttl),
	}
}

// observe adds the requests of the kernel buckets to the series of the label values. The bounds of
// the histogram are those of the kernel buckets.
func (v *kernelHistogramVec) observe(labelValues []string, latency *ebpf.LatencyHistogram) {
	if latency == nil {
		return
	}
	series := v.series.GetOrCreate(labelValues, func() *kernelHistogramSeries {
		return &kernelHistogramSeries{labels: labelValues, buckets: make([]uint64, len(v.bounds)+1)}
	})

	v.mu.Lock()
	defer v.mu.Unlock()
	for bucket, count := range latency.BucketCounts {
		series.buckets[bucket] += count
		series.count += count
	}
	series.sum += latency.Sum
}

func (v *kernelHistogramVec) Describe(descs chan<- *prometheus.Desc) {
	descs <- v.desc
}

func (v *kernelHistogramVec) Collect(metrics chan<- prometheus.Metric) {
	v.series.DeleteExpired()
	for _, histogram := range v.snapshot() {
		metrics <- histogram
	}
}

func (v *kernelHistogramVec) snapshot() []prometheus.Metric {
	v.mu.Lock()
	defer v.mu.Unlock()
	all := v.series.All()
	histograms := make([]prometheus.Metric, 0, len(all))
	for _, series := range all {
		cumulative := make(map[float64]uint64, len(v.bounds))
		var count uint64
		for i, bound := range v.bounds {
			count += series.buckets[i]
			cumulative[bound] = count
		}
		histograms = append(histograms,
			prometheus.MustNewConstHistogram(v.desc, series.count, series.sum, cumulative, series.labels...))
	}
	return histograms
}
