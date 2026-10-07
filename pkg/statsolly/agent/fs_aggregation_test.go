// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fsConfig enables the filesystem metrics and both exporters, with the
// default buckets.
func fsConfig() *obi.Config {
	return &obi.Config{
		Metrics: perapp.GlobalMetricsConfig{Features: export.FeatureStorageFS},
		OTELMetrics: otelcfg.MetricsConfig{
			MetricsEndpoint: "http://localhost:4318", Buckets: export.DefaultBuckets,
			HistogramAggregation: otelcfg.HistogramAggregationExplicit,
		},
		Prometheus: prom.PrometheusConfig{Port: 9090, Buckets: export.DefaultBuckets},
	}
}

// The filesystem programs aggregate in the kernel unless the configuration
// asks for events or no kernel histogram fits the exporters' buckets. The
// layout serves the exporters that export the filesystem histogram, and is
// exponential when OTLP exports exponential histograms or the user asks.
func TestFsAggregation(t *testing.T) {
	fsBounds := export.DefaultBuckets.StatFsOperationDurationHistogram
	for _, tc := range []struct {
		name        string
		cfg         func(*obi.Config)
		enabled     bool
		exponential bool
		bounds      int
	}{
		{name: "default", enabled: true, bounds: len(fsBounds)},
		{name: "exporters' bounds differ: their union", cfg: func(c *obi.Config) {
			c.Prometheus.Buckets.StatFsOperationDurationHistogram = []float64{0.0003, 7}
		}, enabled: true, bounds: len(fsBounds) + 2},
		{name: "a disabled exporter's bounds do not count", cfg: func(c *obi.Config) {
			c.Prometheus.Port = 0
			c.Prometheus.Buckets.StatFsOperationDurationHistogram = make([]float64, 40)
		}, enabled: true, bounds: len(fsBounds)},
		{name: "a disabled histogram's bounds do not count", cfg: func(c *obi.Config) {
			c.Metrics.Features = export.FeatureStorageFSIo | export.FeatureStorageFSErrors
			c.Prometheus.Buckets.StatFsOperationDurationHistogram = make([]float64, 40)
		}, enabled: true, bounds: 0},
		{name: "union beyond 32 bounds: per event", cfg: func(c *obi.Config) {
			for i := range 20 {
				c.Prometheus.Buckets.StatFsOperationDurationHistogram = append(
					c.Prometheus.Buckets.StatFsOperationDurationHistogram, float64(i+1)*0.0137)
			}
		}},
		{name: "OTLP exponential histograms", cfg: func(c *obi.Config) {
			c.OTELMetrics.HistogramAggregation = otelcfg.HistogramAggregationExponential
		}, enabled: true, exponential: true},
		{name: "exponential by choice", cfg: func(c *obi.Config) {
			c.EBPF.StorageAggregation.ExponentialHistograms = true
		}, enabled: true, exponential: true},
		{name: "per event by choice", cfg: func(c *obi.Config) { c.EBPF.StorageAggregation.Disabled = true }},
		{name: "printed stats", cfg: func(c *obi.Config) { c.Stats.Print = true }},
		{name: "no filesystem metrics", cfg: func(c *obi.Config) { c.Metrics.Features = export.FeatureStorageBlock }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fsConfig()
			if tc.cfg != nil {
				tc.cfg(cfg)
			}
			agg, layout := fsAggregation(cfg, discardLog())
			assert.Equal(t, tc.enabled, agg.Enabled)
			if !tc.enabled {
				assert.Nil(t, layout)
				return
			}
			require.NotNil(t, layout)
			assert.Equal(t, tc.exponential, agg.Exponential)
			assert.Equal(t, layout.KernelBounds(), agg.BoundsNs)
			if !tc.exponential {
				assert.Len(t, layout.Bounds, tc.bounds)
			}
		})
	}
}

// On a cgroup v1 host the filesystem keys are decorated through the PID
// path, not the cgroup index, which is never built.
func TestBuildAggregationCgroupVersion(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		old := cgroupV2
		cgroupV2 = func() bool { return v2 }
		t.Cleanup(func() { cgroupV2 = old })

		cfg := fsConfig()
		_, layout := fsAggregation(cfg, discardLog())
		s := &Stats{cfg: cfg, ctxInfo: &global.ContextInfo{}, agentIP: net.ParseIP("1.2.3.4")}
		s.fsAccum, s.fsLayout = stataggtest.NewMemMap(32, 152, 1), layout

		registry, err := s.buildAggregation(t.Context())
		require.NoError(t, err)
		require.NotNil(t, registry)
		assert.Len(t, s.families, 1)
		assert.Equal(t, v2, s.cgroups != nil, "cgroup v2: %v", v2)
	}

	s := &Stats{cfg: fsConfig(), ctxInfo: &global.ContextInfo{}}
	registry, err := s.buildAggregation(t.Context())
	require.NoError(t, err)
	assert.Nil(t, registry, "per event: no aggregation")
}

// With kernel aggregation, the pipeline exports the filesystem metrics from
// the kernel map: what the map counts reaches the Prometheus endpoint.
func TestPipelineExportsAggregatedFsMetrics(t *testing.T) {
	old, oldV2 := newRingBufTracer, cgroupV2
	t.Cleanup(func() { newRingBufTracer, cgroupV2 = old, oldV2 })
	newRingBufTracer = func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
		return func(ctx context.Context) {
			<-ctx.Done()
			out.Close()
		}
	}
	cgroupV2 = func() bool { return false }

	registry := prometheus.NewRegistry()
	promServer := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry}))
	t.Cleanup(promServer.Close)

	cfg := fsConfig()
	cfg.OTELMetrics = otelcfg.MetricsConfig{}
	cfg.Prometheus = prom.PrometheusConfig{Registry: registry, Path: "/metrics", TTL: time.Hour, Buckets: export.DefaultBuckets}
	agg, layout := fsAggregation(cfg, discardLog())
	require.True(t, agg.Enabled)

	m := stataggtest.NewMemMap(32, 152, 1)
	s := &Stats{
		agentIP:  net.ParseIP("1.2.3.4"),
		ctxInfo:  &global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		cfg:      cfg,
		fsAccum:  m,
		fsLayout: layout,
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runner, err := s.buildPipeline(ctx)
	require.NoError(t, err)
	runner.Start(ctx)
	s.runAggregation(ctx)

	// A write of 4096 bytes by a process of cgroup 7 on an xfs volume, as
	// fs_aggregate counts it.
	key := make([]byte, 32)
	binary.NativeEndian.PutUint64(key, 7)
	binary.NativeEndian.PutUint32(key[16:], 253<<20|4)
	key[24], key[25] = uint8(ebpf.CodeFsXFS), uint8(ebpf.CodeFsOpWrite)
	m.AddU64(key, 0, 0, 20_000)
	m.AddU64(key, 0, 8, 4096)
	m.AddU32(key, 0, 16, 1) // 20us: the first bucket, up to 100us
	m.SetU32(key, 0, 148, 4242)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		metrics, err := promtest.Scrape(promServer.URL + "/metrics")
		require.NoError(ct, err)
		var found bool
		for _, sm := range metrics {
			if sm.Name == "obi_stat_fs_io_bytes_total" {
				found = true
				assert.InDelta(ct, 4096.0, sm.Value, 0)
				assert.Equal(ct, "write", sm.Labels["fs_operation"])
				assert.Equal(ct, "xfs", sm.Labels["system_filesystem_type"])
			}
		}
		assert.True(ct, found, "obi_stat_fs_io_bytes_total")
	}, timeout, 100*time.Millisecond)
}
