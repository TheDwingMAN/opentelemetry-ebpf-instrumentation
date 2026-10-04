// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestLatencyHistogramsOfTheEnabledExportersAndFeatures(t *testing.T) {
	custom := []float64{0.0003, 0.0007, 0.003, 0.007, 0.03, 0.07, 0.3, 0.7, 3}
	cfg := &obi.Config{
		// the Prometheus exporter is disabled: its default buckets don't count
		Prometheus: prom.PrometheusConfig{Buckets: export.DefaultBuckets},
		OTELMetrics: otelcfg.MetricsConfig{
			MetricsEndpoint: "http://collector:4318",
			Buckets:         export.DefaultBuckets,
		},
		Metrics: perapp.GlobalMetricsConfig{Features: export.FeatureStatsDiskOperationDuration | export.FeatureStatsFsSyncDuration},
	}
	cfg.OTELMetrics.Buckets.StatDiskOperationDurationHistogram = custom

	histograms := latencyHistograms(cfg)
	assert.Equal(t, custom, histograms.Disk, "only the histograms of the enabled features")
	assert.Equal(t, export.DefaultBuckets.StatFsSyncDurationHistogram, histograms.FsSyncDuration)
	assert.Empty(t, histograms.NFS)

	cfg.Prometheus.Port = 9400
	histograms = latencyHistograms(cfg)
	assert.Len(t, histograms.Disk, len(custom)+len(export.DefaultBuckets.StatDiskOperationDurationHistogram),
		"the union of the boundaries of both exporters")
	assert.IsIncreasing(t, histograms.Disk)
}
