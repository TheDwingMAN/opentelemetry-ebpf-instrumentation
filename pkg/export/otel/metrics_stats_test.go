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

// The disk counters split the requests and their time by outcome, as the histogram does, and count
// the requests of the paths of dm-multipath devices, which the histogram leaves out
func TestStatMetricsExporter_DiskCounters(t *testing.T) {
	stats, records := startStatExporter(t, export.FeatureStatsDisk, attributes.UndefinedGroup)
	succeeded, failed, path := diskStat("vda"), diskStat("vda"), diskStat("sdb")
	succeeded.DiskIO.Latency, succeeded.DiskIO.Bytes = *latency(0.0002, 2), 2*4096
	failed.DiskIO.Latency, failed.DiskIO.ErrorType = *latency(30, 0, 1), "ETIMEDOUT"
	path.DiskIO.Latency, path.DiskIO.Bytes, path.DiskIO.MultipathPath = *latency(0.0003, 3), 3*4096, true
	stats.Send([]*ebpf.Stat{succeeded, failed, path})

	// the last value of each series by metric, device and error type: the sum of the histograms
	got := map[string]float64{}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		receive(records, func(record collector.MetricRecord) {
			got[record.Name+" "+record.Attributes["system.device"]+" "+record.Attributes["error.type"]] =
				record.FloatVal + float64(record.IntVal)
		})
		assert.Equal(ct, map[string]float64{
			"obi.stat.disk.service.duration vda ":          0.0002,
			"obi.stat.disk.service.duration vda ETIMEDOUT": 30,
			"obi.stat.disk.operations vda ":                2,
			"obi.stat.disk.operations vda ETIMEDOUT":       1,
			"obi.stat.disk.operations sdb ":                3,
			"obi.stat.disk.service_time vda ":              0.0002,
			"obi.stat.disk.service_time vda ETIMEDOUT":     30,
			"obi.stat.disk.service_time sdb ":              0.0003,
			"obi.stat.disk.io vda ":                        2 * 4096,
			"obi.stat.disk.io sdb ":                        3 * 4096,
		}, got)
	}, timeout, 100*time.Millisecond)
}

// Over OTLP, the disk stats leave out the Kubernetes metadata of the I/O charged to no pod, instead
// of exporting it empty
func TestStatMetricsExporter_DiskStatsOmitAbsentKubernetesMetadata(t *testing.T) {
	stats, records := startStatExporter(t, export.FeatureStatsDiskOperations, attributes.GroupKubernetes)
	inPod, outOfPods := diskStat("vda"), diskStat("vda")
	inPod.DiskIO.Latency, outOfPods.DiskIO.Latency = *latency(0.001, 1), *latency(0.001, 1)
	inPod.CommonAttrs.Metadata = map[attr.Name]string{
		attr.K8sClusterName: "c", attr.K8sNamespaceName: "ns", attr.K8sOwnerName: "db", attr.K8sKind: "StatefulSet",
	}
	outOfPods.CommonAttrs.Metadata = map[attr.Name]string{attr.K8sClusterName: "c"}
	stats.Send([]*ebpf.Stat{inPod, outOfPods})

	want := []map[string]string{
		{"system.device": "vda", "obi.disk.stacked": "false", "disk.io.direction": "read", "k8s.cluster.name": "c"},
		{
			"system.device": "vda", "obi.disk.stacked": "false", "disk.io.direction": "read", "k8s.cluster.name": "c",
			"k8s.namespace.name": "ns", "k8s.owner.name": "db", "k8s.kind": "StatefulSet",
		},
	}
	var got []map[string]string
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		receive(records, func(record collector.MetricRecord) {
			if record.Name == attributes.StatDiskOperations.OTEL &&
				!slices.ContainsFunc(got, func(attrs map[string]string) bool { return maps.Equal(attrs, record.Attributes) }) {
				got = append(got, record.Attributes)
			}
		})
		assert.ElementsMatch(ct, want, got)
	}, timeout, 100*time.Millisecond)
}

// startStatExporter starts an OTLP stats exporter of the given features, with the default
// attributes, which exports to a test collector
func startStatExporter(t *testing.T, features export.Features, groups attributes.AttrGroups,
) (*msg.Queue[[]*ebpf.Stat], <-chan collector.MetricRecord) {
	t.Cleanup(otelcfg.RestoreEnvAfterExecution())
	otlp, err := collector.Start(t.Context())
	require.NoError(t, err)
	stats := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	cfg := &otelcfg.MetricsConfig{
		Interval:        50 * time.Millisecond,
		CommonEndpoint:  otlp.ServerEndpoint,
		MetricsProtocol: otelcfg.ProtocolHTTPProtobuf,
		TTL:             time.Hour,
	}
	exporter, err := StatMetricsExporterProvider(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}, MetricAttributeGroups: groups},
		&StatMetricsConfig{
			Metrics:     cfg,
			SelectorCfg: &attributes.SelectorConfig{},
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: features},
		}, stats)(t.Context())
	require.NoError(t, err)
	go exporter(t.Context())
	return stats, otlp.Records()
}

// receive calls f with each record that the collector received so far
func receive(records <-chan collector.MetricRecord, f func(collector.MetricRecord)) {
	for {
		select {
		case record := <-records:
			f(record)
		default:
			return
		}
	}
}
