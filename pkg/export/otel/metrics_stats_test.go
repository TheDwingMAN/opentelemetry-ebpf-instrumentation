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

	"go.opentelemetry.io/collector/pdata/pmetric"
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

// The cache flushes are only recorded in their own histogram, per device and outcome: the metrics of
// the reads and writes don't count them
func TestStatMetricsExporter_FlushesOnlyInTheirHistogram(t *testing.T) {
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
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStatsDisk},
		}, stats)(ctx)
	require.NoError(t, err)

	go exporter(ctx)

	// 2 writes of 4 KiB that took 1 ms each, 3 flushes that took 10 ms each, and one that failed
	stats.Send([]*ebpf.Stat{
		{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{
			Device: "vda", Op: ebpf.CodeDiskOpWrite, Operations: 2, Time: 0.002, Bytes: 2 * 4096, Latency: latency(0.002, 2),
		}},
		{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{
			Device: "vda", Op: ebpf.CodeDiskOpFlush, Operations: 3, Time: 0.03, Latency: latency(0.03, 0, 3),
		}},
		{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{
			Device: "vda", Op: ebpf.CodeDiskOpFlush, ErrorType: "EIO", Operations: 1, Time: 0.5, Latency: latency(0.5, 0, 0, 1),
		}},
	})

	// the last exported value of each series of each metric, by its error.type and direction: the
	// count of a histogram, the value of a counter
	values := map[string]map[string]float64{}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for drained := false; !drained; {
			select {
			case record := <-otlp.Records():
				series := record.Attributes["error.type"] + "/" + record.Attributes["disk.io.direction"]
				if values[record.Name] == nil {
					values[record.Name] = map[string]float64{}
				}
				switch record.Type {
				case pmetric.MetricTypeHistogram:
					values[record.Name][series] = float64(record.Count)
				default:
					values[record.Name][series] = float64(record.IntVal) + record.FloatVal
				}
			default:
				drained = true
			}
		}
		assert.Equal(ct, map[string]map[string]float64{
			attributes.StatDiskServiceDuration.OTEL: {"/write": 2},
			attributes.StatDiskOperations.OTEL:      {"/write": 2},
			attributes.StatDiskServiceTime.OTEL:     {"/write": 0.002},
			attributes.StatDiskIO.OTEL:              {"/write": 2 * 4096},
			attributes.StatDiskFlushDuration.OTEL:   {"/": 3, "EIO/": 1},
		}, values)
	}, timeout, 100*time.Millisecond)
}

// Over OTLP, the disk stats omit the Kubernetes metadata of the I/O charged to no pod instead of
// exporting it empty
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

// appendNewSeries appends to series the attributes of the records of a metric that it lacks
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
