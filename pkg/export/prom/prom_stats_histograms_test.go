// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func gatherHistograms(t *testing.T, vec *kernelHistogramVec) []*dto.Metric {
	registry := prometheus.NewPedanticRegistry()
	require.NoError(t, registry.Register(vec))
	families, err := registry.Gather()
	require.NoError(t, err)
	if len(families) == 0 {
		return nil
	}
	return families[0].GetMetric()
}

func TestKernelHistogramVecAddsTheRequestsOfEachBucketAtOnce(t *testing.T) {
	vec := newKernelHistogramVec("latency_seconds", "help", []float64{0.001, 0.01}, []string{"device"}, time.Hour)
	vec.observe([]string{"sda"}, []ebpf.LatencySample{
		{Seconds: 0.0005, Count: 3},
		{Seconds: 0.001, Count: 2}, // on a bound: in its bucket
		{Seconds: 0.5, Count: 1000},
	})
	vec.observe([]string{"sda"}, []ebpf.LatencySample{{Seconds: 0.005, Count: 4}})
	vec.observe([]string{"sda"}, nil)

	metrics := gatherHistograms(t, vec)
	require.Len(t, metrics, 1)
	histogram := metrics[0].GetHistogram()
	assert.Equal(t, uint64(1009), histogram.GetSampleCount())
	assert.InDelta(t, 0.0005*3+0.001*2+0.5*1000+0.005*4, histogram.GetSampleSum(), 1e-9)
	require.Len(t, histogram.GetBucket(), 2)
	assert.Equal(t, uint64(5), histogram.GetBucket()[0].GetCumulativeCount())
	assert.Equal(t, uint64(9), histogram.GetBucket()[1].GetCumulativeCount())
	assert.Equal(t, "sda", metrics[0].GetLabel()[0].GetValue())
}

func TestKernelHistogramVecDropsTheSeriesNotUpdatedDuringTheTTL(t *testing.T) {
	now := time.Now()
	previousClock := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = previousClock })

	vec := newKernelHistogramVec("latency_seconds", "help", []float64{0.001}, []string{"device"}, time.Minute)
	vec.observe([]string{"sda"}, []ebpf.LatencySample{{Seconds: 0.0005, Count: 1}})
	vec.observe([]string{"sdb"}, []ebpf.LatencySample{{Seconds: 0.0005, Count: 1}})
	require.Len(t, gatherHistograms(t, vec), 2)

	now = now.Add(2 * time.Minute)
	vec.observe([]string{"sdb"}, []ebpf.LatencySample{{Seconds: 0.0005, Count: 1}})
	metrics := gatherHistograms(t, vec)
	require.Len(t, metrics, 1)
	assert.Equal(t, "sdb", metrics[0].GetLabel()[0].GetValue())
	assert.Equal(t, uint64(2), metrics[0].GetHistogram().GetSampleCount())
}
