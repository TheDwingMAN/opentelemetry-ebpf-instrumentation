// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	otelmetric "go.opentelemetry.io/obi/pkg/export/otel/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

var defaultStatRttInstrument = otelmetric.Instrument{
	Name:  attributes.StatTCPRtt.OTEL,
	Scope: instrumentation.Scope{Name: statScopeName},
}

var defaultExpCfg = otelcfg.ExponentialHistogramConfig{MaxSize: 64, MaxScale: 12}

func TestStatHistogramView_ExponentialUsesConfiguredMaxSizeAndScale(t *testing.T) {
	buckets := []float64{0.001, 0.010, 0.100, 1.0}
	view := statHistogramView(attributes.StatTCPRtt.OTEL, buckets, true, defaultExpCfg)

	stream, ok := view(defaultStatRttInstrument)
	require.True(t, ok)

	aggregation, ok := stream.Aggregation.(sdkmetric.AggregationBase2ExponentialHistogram)
	require.True(t, ok)
	assert.Equal(t, int32(64), aggregation.MaxSize)
	assert.Equal(t, int32(12), aggregation.MaxScale)
}

func TestStatHistogramView_ExplicitUsesBuckets(t *testing.T) {
	buckets := []float64{0.001, 0.010, 0.100, 1.0}
	view := statHistogramView(attributes.StatTCPRtt.OTEL, buckets, false, otelcfg.ExponentialHistogramConfig{})

	stream, ok := view(defaultStatRttInstrument)
	require.True(t, ok)

	aggregation, ok := stream.Aggregation.(sdkmetric.AggregationExplicitBucketHistogram)
	require.True(t, ok)
	assert.Equal(t, buckets, aggregation.Boundaries)
}

func TestStatMetricsExporter_DiskMetrics(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	stats := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	cfg := &otelcfg.MetricsConfig{
		Interval:        50 * time.Millisecond,
		CommonEndpoint:  otlp.ServerEndpoint,
		MetricsProtocol: otelcfg.ProtocolHTTPProtobuf,
		TTL:             3 * time.Minute,
	}
	otelExporter, err := StatMetricsExporterProvider(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		&StatMetricsConfig{
			Metrics: cfg,
			SelectorCfg: &attributes.SelectorConfig{
				SelectionCfg: attributes.Selection{
					attributes.StatDiskOperationDuration.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
					attributes.StatDiskIO.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
				},
			},
			CommonCfg: &perapp.GlobalMetricsConfig{Features: export.FeatureStorageBlock},
		}, stats)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives a block I/O stat
	stats.Send([]*ebpf.Stat{
		{
			Type: ebpf.StatTypeBlockIo,
			BlockIo: &ebpf.BlockIo{
				Dev:       0x800010,
				Op:        ebpf.BlockOpWrite,
				LatencyNs: 2_000_000,
				Bytes:     4096,
			},
		},
	})

	// THEN that one event produces both disk metrics: the latency histogram
	// and the bytes counter.
	//
	// Both are exported independently, so the order they reach the collector is
	// not deterministic and we cannot assert on "the next record". Drain
	// whatever has arrived on each tick and keep the first record seen per
	// metric name -- first-seen is also the value we want under either
	// temporality, since a delta counter reports 0 on subsequent intervals.
	seen := map[string]collector.MetricRecord{}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for drained := false; !drained; {
			select {
			case rec := <-otlp.Records():
				if _, ok := seen[rec.Name]; !ok {
					seen[rec.Name] = rec
				}
			default:
				drained = true
			}
		}
		assert.Contains(ct, seen, "obi.stat.disk.operation.duration")
		assert.Contains(ct, seen, "obi.stat.disk.io")
	}, timeout, 100*time.Millisecond)

	// Both metrics carry the same device/direction attributes, decoded from
	// dev 0x800010 (major 8, minor 16) and BlockOpWrite.
	diskAttrs := map[string]string{
		"system.device":     "8:16",
		"disk.io.direction": "write",
	}

	latency := seen["obi.stat.disk.operation.duration"]
	assert.Equal(t, diskAttrs, latency.Attributes)
	assert.InEpsilon(t, 0.002, latency.FloatVal, 0.0001)
	assert.Equal(t, 1, latency.Count)

	ioBytes := seen["obi.stat.disk.io"]
	assert.Equal(t, diskAttrs, ioBytes.Attributes)
	assert.Equal(t, int64(4096), ioBytes.IntVal)
}
