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

// The disk counters split the requests and their time by outcome, so that a request that timed out
// doesn't change the mean of the successful ones. Failed requests transferred no bytes.
func TestStatMetricsExporter_DiskCountersSplitByError(t *testing.T) {
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
	exporter, err := StatMetricsExporterProvider(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		&StatMetricsConfig{
			Metrics:     cfg,
			SelectorCfg: &attributes.SelectorConfig{SelectionCfg: attributes.Selection{}},
			CommonCfg: &perapp.GlobalMetricsConfig{
				Features: export.FeatureStatsDiskIO | export.FeatureStatsDiskOperations | export.FeatureStatsDiskServiceTime,
			},
		}, stats)(ctx)
	require.NoError(t, err)

	go exporter(ctx)

	// 1,000 writes of 0.1 ms and 4 KiB, and one that timed out after 30 s
	stats.Send([]*ebpf.Stat{
		{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{
			Device: "vda", Op: ebpf.CodeDiskOpWrite, Operations: 1000, Time: 0.1, Bytes: 1000 * 4096,
		}},
		{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{
			Device: "vda", Op: ebpf.CodeDiskOpWrite, ErrorType: "ETIMEDOUT", Operations: 1, Time: 30,
		}},
	})

	// the last exported value of each series of the counters, by its error.type
	bytes, operations, serviceTime := map[string]int64{}, map[string]int64{}, map[string]float64{}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for drained := false; !drained; {
			select {
			case record := <-otlp.Records():
				errorType, failed := record.Attributes["error.type"]
				if !failed {
					errorType = "none"
				}
				switch record.Name {
				case attributes.StatDiskIO.OTEL:
					bytes[errorType] = record.IntVal
				case attributes.StatDiskOperations.OTEL:
					operations[errorType] = record.IntVal
				case attributes.StatDiskServiceTime.OTEL:
					serviceTime[errorType] = record.FloatVal
				}
			default:
				drained = true
			}
		}
		assert.Equal(ct, map[string]int64{"none": 1000 * 4096}, bytes)
		assert.Equal(ct, map[string]int64{"none": 1000, "ETIMEDOUT": 1}, operations)
		// the mean service time of the successful writes stays 0.1 ms
		assert.Equal(ct, map[string]float64{"none": 0.1, "ETIMEDOUT": 30}, serviceTime)
	}, timeout, 100*time.Millisecond)
}
