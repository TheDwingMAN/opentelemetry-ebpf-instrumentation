// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestLatencyHistogramsOfTheEnabledExportersAndFeatures(t *testing.T) {
	custom := []float64{0.0003, 0.003, 0.03, 0.3, 0.7, 2, 3, 7}
	cfg := &obi.Config{
		// the Prometheus exporter is disabled: its default buckets don't count
		Prometheus: prom.PrometheusConfig{Buckets: export.DefaultBuckets},
		OTELMetrics: otelcfg.MetricsConfig{
			MetricsEndpoint: "http://collector:4318",
			Buckets:         export.DefaultBuckets,
		},
		Metrics: perapp.GlobalMetricsConfig{Features: export.FeatureStatsDiskOperationDuration},
	}
	cfg.OTELMetrics.Buckets.StatDiskOperationDurationHistogram = custom

	histograms, approximated := latencyHistograms(cfg)
	assert.Equal(t, custom, histograms.Disk, "only the histograms of the enabled features")
	assert.Empty(t, approximated)

	cfg.Prometheus.Port = 9400
	histograms, approximated = latencyHistograms(cfg)
	assert.Len(t, histograms.Disk, len(custom)+len(export.DefaultBuckets.StatDiskOperationDurationHistogram),
		"the union of the boundaries of both exporters, as many as the kernel keeps")
	assert.IsIncreasing(t, histograms.Disk)
	assert.Empty(t, approximated)
}

// Buckets that the kernel can't keep approximate their histograms, and don't stop the agent
func TestLatencyHistogramsTheKernelCantKeep(t *testing.T) {
	bounds := func(first, step float64) []float64 {
		b := make([]float64, 16)
		for i := range b {
			b[i] = first + float64(i)*step
		}
		return b
	}
	cfg := &obi.Config{
		Prometheus: prom.PrometheusConfig{Port: 9400, Buckets: export.DefaultBuckets},
		OTELMetrics: otelcfg.MetricsConfig{
			MetricsEndpoint: "http://collector:4318",
			Buckets:         export.DefaultBuckets,
		},
		Metrics: perapp.GlobalMetricsConfig{Features: export.FeatureStatsDiskOperationDuration},
	}
	cfg.Prometheus.Buckets.StatDiskOperationDurationHistogram = bounds(0.001, 0.001)
	cfg.OTELMetrics.Buckets.StatDiskOperationDurationHistogram = bounds(0.0015, 0.001)

	histograms, approximated := latencyHistograms(cfg)
	assert.Len(t, histograms.Disk, 24, "the 32 bounds of both exporters, spread over the kernel buckets")
	assert.IsIncreasing(t, histograms.Disk)
	require.Len(t, approximated, 1)
	assert.Contains(t, approximated[0], "stat_disk_operation_duration_histogram")
}
