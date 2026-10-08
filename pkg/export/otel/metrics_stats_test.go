// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	otelmetric "go.opentelemetry.io/obi/pkg/export/otel/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
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

func TestStatMetricsExporter_StorageOmitsUnknownKubernetesMetadata(t *testing.T) {
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
		&global.ContextInfo{
			OTELMetricsExporter:   &otelcfg.MetricsExporterInstancer{Cfg: cfg},
			MetricAttributeGroups: attributes.GroupKubernetes,
		},
		&StatMetricsConfig{
			Metrics:     cfg,
			SelectorCfg: &attributes.SelectorConfig{SelectionCfg: attributes.Selection{}},
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStatsDiskIO},
		}, stats)(ctx)
	require.NoError(t, err)

	go exporter(ctx)

	write := func(metadata map[attr.Name]string) *ebpf.Stat {
		return &ebpf.Stat{
			Type:        ebpf.StatTypeDiskIO,
			DiskIO:      &ebpf.DiskIO{Device: "vda", Op: ebpf.CodeDiskOpWrite, Operations: 1, Bytes: 4096},
			CommonAttrs: pipe.CommonAttrs{Metadata: metadata},
		}
	}
	stats.Send([]*ebpf.Stat{
		write(map[attr.Name]string{attr.K8sClusterName: "c", attr.K8sNamespaceName: "ns", attr.K8sOwnerName: "db"}),
		// charged to no pod
		write(map[attr.Name]string{attr.K8sClusterName: "c"}),
	})

	device := map[string]string{"system.device": "vda", "obi.disk.stacked": "false", "disk.io.direction": "write"}
	want := []map[string]string{
		{"k8s.cluster.name": "c", "k8s.namespace.name": "ns", "k8s.owner.name": "db"},
		{"k8s.cluster.name": "c"},
	}
	for _, attrs := range want {
		maps.Copy(attrs, device)
	}

	var got []map[string]string
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		got = appendNewSeries(got, otlp.Records(), attributes.StatDiskIO.OTEL)
		assert.ElementsMatch(ct, want, got)
	}, timeout, 100*time.Millisecond)
}

func TestStatMetricsExporter_DiskQueueTime(t *testing.T) {
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
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStatsDiskQueueTime},
		}, stats)(ctx)
	require.NoError(t, err)

	go exporter(ctx)

	request := func(op ebpf.DiskOpCode, queueTime float64) *ebpf.Stat {
		return &ebpf.Stat{
			Type:   ebpf.StatTypeDiskIO,
			DiskIO: &ebpf.DiskIO{Device: "vda", Op: op, Operations: 1, QueueTime: queueTime},
		}
	}
	// the kernel also adds up the wait of the flushes, which are neither reads nor writes
	stats.Send([]*ebpf.Stat{
		request(ebpf.CodeDiskOpWrite, 0.25), request(ebpf.CodeDiskOpWrite, 0.5), request(ebpf.CodeDiskOpFlush, 1),
	})

	// the last exported value of each direction
	queueTime := map[string]float64{}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for drained := false; !drained; {
			select {
			case record := <-otlp.Records():
				if record.Name == attributes.StatDiskQueueTime.OTEL {
					assert.Equal(ct, attributes.StatDiskQueueTime.Unit, record.Unit)
					queueTime[record.Attributes["disk.io.direction"]] = record.FloatVal
				}
			default:
				drained = true
			}
		}
		assert.Equal(ct, map[string]float64{"write": 0.75}, queueTime)
	}, timeout, 100*time.Millisecond)
}

// appendNewSeries appends the attributes of the series of the named metric that the
// records received so far add to series. Each export repeats the series it holds.
func appendNewSeries(series []map[string]string, inCh <-chan collector.MetricRecord, name string) []map[string]string {
	for {
		select {
		case record := <-inCh:
			if record.Name == name && !slices.ContainsFunc(series, func(attrs map[string]string) bool {
				return maps.Equal(attrs, record.Attributes)
			}) {
				series = append(series, record.Attributes)
			}
		default:
			return series
		}
	}
}
