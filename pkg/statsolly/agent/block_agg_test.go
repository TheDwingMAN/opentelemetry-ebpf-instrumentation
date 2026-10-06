// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/obi"
)

// manyBounds is more than half of the bounds a kernel histogram holds, so
// that two such sets together do not fit.
const manyBounds = 20

// seconds returns manyBounds distinct bounds: first, 2*first, 3*first...
func seconds(first float64) []float64 {
	out := make([]float64, manyBounds)
	for i := range out {
		out[i] = first * float64(i+1)
	}
	return out
}

func blockAggConfig(features export.Features, otelOn, promOn bool) *obi.Config {
	cfg := obi.DefaultConfig
	cfg.Metrics.Features = features
	if otelOn {
		cfg.OTELMetrics.MetricsEndpoint = "http://collector:4318"
	}
	if promOn {
		cfg.Prometheus.Port = 9400
	}
	return &cfg
}

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestBlockAggregation_PerEventCases(t *testing.T) {
	for name, cfg := range map[string]func() *obi.Config{
		"block metrics off": func() *obi.Config {
			return blockAggConfig(export.FeatureStatsTCPRtt, true, true)
		},
		"disabled by the user": func() *obi.Config {
			cfg := blockAggConfig(export.FeatureStorageBlock, true, true)
			cfg.EBPF.StorageAggregation.Disabled = true
			return cfg
		},
		"queue depth is per event": func() *obi.Config {
			return blockAggConfig(export.FeatureStorageBlock|export.FeatureStorageBlockQueueDepth, true, true)
		},
		"print_stats prints every event": func() *obi.Config {
			cfg := blockAggConfig(export.FeatureStorageBlock, true, true)
			cfg.Stats.Print = true
			return cfg
		},
		"too many bounds": func() *obi.Config {
			cfg := blockAggConfig(export.FeatureStorageBlock, true, true)
			cfg.OTELMetrics.Buckets.StatDiskOperationDurationHistogram = seconds(0.001)
			cfg.Prometheus.Buckets.StatDiskOperationDurationHistogram = seconds(0.0015)
			return cfg
		},
	} {
		t.Run(name, func(t *testing.T) {
			agg, layout := blockAggregation(cfg(), quietLog)
			assert.Nil(t, agg)
			assert.Nil(t, layout)
		})
	}
}

func TestBlockAggregation_ExplicitUnionOfTheEnabledExporters(t *testing.T) {
	otelBounds, promBounds := seconds(0.001), seconds(0.0015)
	union, err := statagg.NewExplicitLayout(otelBounds[:10], promBounds[:10])
	require.NoError(t, err)

	cfg := blockAggConfig(export.FeatureStorageBlock, true, true)
	cfg.OTELMetrics.Buckets.StatDiskOperationDurationHistogram = otelBounds[:10]
	cfg.Prometheus.Buckets.StatDiskOperationDurationHistogram = promBounds[:10]
	cfg.EBPF.StorageAggregation.BlockMapsBudgetBytes = 1 << 20
	agg, layout := blockAggregation(cfg, quietLog)
	require.NotNil(t, agg)
	assert.Equal(t, union.Bounds, layout.Bounds, "the kernel counts in the union of both exporters' bounds")
	assert.False(t, agg.Exponential)
	assert.Equal(t, layout.KernelBounds(), agg.BoundsNs)
	assert.Equal(t, uint64(1<<20), agg.BudgetBytes)

	// With 40 bounds between them the union does not fit, unless only one
	// exporter is enabled: a disabled exporter's buckets never count.
	for name, otelOn := range map[string]bool{"OTel only": true, "Prometheus only": false} {
		t.Run(name, func(t *testing.T) {
			cfg := blockAggConfig(export.FeatureStorageBlock, otelOn, !otelOn)
			cfg.OTELMetrics.Buckets.StatDiskOperationDurationHistogram = otelBounds
			cfg.Prometheus.Buckets.StatDiskOperationDurationHistogram = promBounds
			agg, layout := blockAggregation(cfg, quietLog)
			require.NotNil(t, agg)
			want := promBounds
			if otelOn {
				want = otelBounds
			}
			assert.Equal(t, want, layout.Bounds)
		})
	}
}

// Only the enabled block histograms feed the union.
func TestBlockHistogramBounds_EnabledHistogramsOnly(t *testing.T) {
	b := &export.Buckets{StatDiskOperationDurationHistogram: []float64{1, 2}}
	assert.Empty(t, blockHistogramBounds(export.FeatureStorageBlockIo|export.FeatureStorageBlockErrors, b),
		"no histogram, no bounds")
	assert.Len(t, blockHistogramBounds(export.FeatureStorageBlockFlush, b), 1)
	assert.Len(t, blockHistogramBounds(export.FeatureStorageBlock, b), 4)
}

func TestBlockAggregation_ExponentialLayout(t *testing.T) {
	t.Run("OTel exponential aggregation", func(t *testing.T) {
		cfg := blockAggConfig(export.FeatureStorageBlock, true, true)
		cfg.OTELMetrics.HistogramAggregation = otelcfg.HistogramAggregationExponential
		agg, layout := blockAggregation(cfg, quietLog)
		require.NotNil(t, agg)
		assert.True(t, agg.Exponential)
		assert.Equal(t, statagg.LayoutExponential, layout.Kind)
		assert.Len(t, agg.BoundsNs, statagg.MaxExponentialBounds)
	})
	t.Run("OTel exponential aggregation with the OTel exporter off", func(t *testing.T) {
		cfg := blockAggConfig(export.FeatureStorageBlock, false, true)
		cfg.OTELMetrics.HistogramAggregation = otelcfg.HistogramAggregationExponential
		agg, layout := blockAggregation(cfg, quietLog)
		require.NotNil(t, agg)
		assert.False(t, agg.Exponential, "only an enabled exporter's aggregation counts")
		assert.Equal(t, statagg.LayoutExplicit, layout.Kind)
	})
	t.Run("opt-in", func(t *testing.T) {
		cfg := blockAggConfig(export.FeatureStorageBlock, false, true)
		cfg.EBPF.StorageAggregation.ExponentialHistograms = true
		agg, _ := blockAggregation(cfg, quietLog)
		require.NotNil(t, agg)
		assert.True(t, agg.Exponential)
	})
	t.Run("opt-in beats too many explicit bounds", func(t *testing.T) {
		cfg := blockAggConfig(export.FeatureStorageBlock, true, true)
		cfg.OTELMetrics.Buckets.StatDiskOperationDurationHistogram = seconds(0.001)
		cfg.Prometheus.Buckets.StatDiskOperationDurationHistogram = seconds(0.0015)
		cfg.EBPF.StorageAggregation.ExponentialHistograms = true
		agg, _ := blockAggregation(cfg, quietLog)
		require.NotNil(t, agg)
		assert.True(t, agg.Exponential)
	})
}

func TestBlockAggregation_DefaultBudget(t *testing.T) {
	agg, _ := blockAggregation(blockAggConfig(export.FeatureStorageBlock, true, true), quietLog)
	require.NotNil(t, agg)
	assert.Equal(t, uint64(8<<20), agg.BudgetBytes)
}

// Without a fetcher that loaded the aggregation maps (the per-event mode, or
// tests), the pipeline has no block families.
func TestNewBlockFamilies_NoFetcher(t *testing.T) {
	s := &Stats{cfg: blockAggConfig(export.FeatureStorageBlock, true, true)}
	_, s.blockLayout = blockAggregation(s.cfg, quietLog)
	families, err := s.newBlockFamilies(t.Context())
	require.NoError(t, err)
	assert.Empty(t, families)
}
