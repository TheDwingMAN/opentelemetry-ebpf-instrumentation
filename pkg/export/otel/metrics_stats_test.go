// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	otelmetric "go.opentelemetry.io/obi/pkg/export/otel/metric"
	metric2 "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
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
				Op:        uint8(ebpf.CodeDirectionWrite),
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
	// dev 0x800010 (major 8, minor 16) and a write.
	diskAttrs := map[string]string{
		"system.device": "8:16", "obi.disk.stacked": "false",
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

// TestStatMetricsExporter_DiskQueueAndErrorMetrics covers the three metrics
// added on top of the base duration/io pair: queue wait, queue depth and
// operation errors. Only storage_block_queue, storage_block_queue_depth and
// storage_block_errors are enabled (not duration/io), which doubles as a
// gating test: the base disk metrics must not appear when their own feature
// bit is off.
func TestStatMetricsExporter_DiskQueueAndErrorMetrics(t *testing.T) {
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
					attributes.StatDiskQueueDuration.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
					attributes.StatDiskQueueDepth.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
					attributes.StatDiskOperationErrors.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
				},
			},
			CommonCfg: &perapp.GlobalMetricsConfig{Features: export.FeatureStorageBlockQueue | export.FeatureStorageBlockQueueDepth | export.FeatureStorageBlockErrors},
		}, stats)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives a failed block I/O completion with queue wait and
	// in-flight information
	stats.Send([]*ebpf.Stat{
		{
			Type: ebpf.StatTypeBlockIo,
			BlockIo: &ebpf.BlockIo{
				Dev:       0x800010,
				Op:        uint8(ebpf.CodeDirectionWrite),
				LatencyNs: 2_000_000,
				QueueNs:   500_000,
				Bytes:     4096,
				Error:     -int32(unix.ENOSPC),
				Inflight:  3,
			},
		},
	})

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
		assert.Contains(ct, seen, "obi.stat.disk.queue.duration")
		assert.Contains(ct, seen, "obi.stat.disk.queue.depth")
		assert.Contains(ct, seen, "obi.stat.disk.operation.errors")
	}, timeout, 100*time.Millisecond)

	// Gating: storage_block_duration/storage_block_io are off, so neither of
	// the base disk metrics should have been exported.
	assert.NotContains(t, seen, "obi.stat.disk.operation.duration")
	assert.NotContains(t, seen, "obi.stat.disk.io")

	diskAttrs := map[string]string{
		"system.device": "8:16", "obi.disk.stacked": "false",
		"disk.io.direction": "write",
	}

	queueDuration := seen["obi.stat.disk.queue.duration"]
	assert.Equal(t, diskAttrs, queueDuration.Attributes)
	assert.InEpsilon(t, 0.0005, queueDuration.FloatVal, 0.0001)
	assert.Equal(t, 1, queueDuration.Count)

	queueDepth := seen["obi.stat.disk.queue.depth"]
	assert.Equal(t, map[string]string{"system.device": "8:16", "obi.disk.stacked": "false"}, queueDepth.Attributes)
	assert.InEpsilon(t, 3.0, queueDepth.FloatVal, 0.0001)
	assert.Equal(t, 1, queueDepth.Count)

	opErrors := seen["obi.stat.disk.operation.errors"]
	assert.Equal(t, map[string]string{
		"system.device": "8:16", "obi.disk.stacked": "false",
		"disk.io.direction": "write",
		"error.type":        "ENOSPC",
	}, opErrors.Attributes)
	assert.Equal(t, int64(1), opErrors.IntVal)
}

// TestStatMetricsExporter_DiskQueueDurationSkipsZeroQueueNs covers the A9
// ruling: QueueNs == 0 means no block_rq_insert record matched this
// completion (e.g. blk-mq issued it directly), so the queue duration
// histogram must not observe it, while the operation duration histogram --
// which doesn't depend on QueueNs -- still does.
func TestStatMetricsExporter_DiskQueueDurationSkipsZeroQueueNs(t *testing.T) {
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
					attributes.StatDiskQueueDuration.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
				},
			},
			CommonCfg: &perapp.GlobalMetricsConfig{Features: export.FeatureStorageBlockDuration | export.FeatureStorageBlockQueue},
		}, stats)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives a block I/O completion whose request bypassed
	// block_rq_insert (QueueNs == 0)
	stats.Send([]*ebpf.Stat{
		{
			Type: ebpf.StatTypeBlockIo,
			BlockIo: &ebpf.BlockIo{
				Dev:       0x800010,
				Op:        uint8(ebpf.CodeDirectionWrite),
				LatencyNs: 2_000_000,
				QueueNs:   0,
				Bytes:     4096,
			},
		},
	})

	// THEN the operation duration histogram observes it.
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
	}, timeout, 100*time.Millisecond)

	// AND the queue duration histogram never does.
	assert.NotContains(t, seen, "obi.stat.disk.queue.duration", "queue duration must not be observed for QueueNs == 0")

	// AND storage_block_queue no longer brings the deprecated queue depth.
	assert.NotContains(t, seen, "obi.stat.disk.queue.depth", "queue depth needs storage_block_queue_depth")
}

// A healthy completion must not create an error series: the errors counter is
// gated on Error != 0, and an always-present zero-valued series would make
// "any disk errors on this node?" impossible to answer with a simple presence
// check.
func TestStatMetricsExporter_DiskOperationErrorsSkipsZeroError(t *testing.T) {
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
					attributes.StatDiskOperationErrors.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
				},
			},
			CommonCfg: &perapp.GlobalMetricsConfig{Features: export.FeatureStorageBlockDuration | export.FeatureStorageBlockErrors},
		}, stats)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives a block I/O completion that succeeded
	stats.Send([]*ebpf.Stat{
		{
			Type: ebpf.StatTypeBlockIo,
			BlockIo: &ebpf.BlockIo{
				Dev:       0x800010,
				Op:        uint8(ebpf.CodeDirectionWrite),
				LatencyNs: 2_000_000,
				Bytes:     4096,
				Error:     0,
			},
		},
	})

	// THEN the operation duration histogram observes it.
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
	}, timeout, 100*time.Millisecond)

	// AND the errors counter never does.
	assert.NotContains(t, seen, "obi.stat.disk.operation.errors", "errors counter must not be recorded for Error == 0")
}

// Every stat histogram gets a View, so its buckets are the configured ones
// rather than the SDK defaults.
func TestStatHistogramsHaveViews(t *testing.T) {
	buckets := export.DefaultBuckets
	views := map[string][]float64{}
	for _, h := range statHistograms(&buckets) {
		views[h.name.OTEL] = h.buckets
	}
	for _, m := range attributes.StatMetrics {
		if m.Type != attributes.InstrumentHistogram {
			continue
		}
		assert.NotEmpty(t, views[m.OTEL], "no View for the %s histogram", m.OTEL)
	}
	assert.Equal(t, buckets.StatDiskOperationDurationHistogram, views[attributes.StatDiskFlushDuration.OTEL])
	assert.Equal(t, buckets.StatDiskOperationDurationHistogram, views[attributes.StatDiskDiscardDuration.OTEL])
}

// Flushes and discards have metrics of their own: no direction, error.type
// only when they fail, and none of them reaches the read/write metrics.
func TestStatMetricsExporter_DiskFlushAndDiscard(t *testing.T) {
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
			Metrics:     cfg,
			SelectorCfg: &attributes.SelectorConfig{},
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStorageBlock},
		}, stats)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	blockStat := func(op ebpf.BlockOpCode, bytes uint64, errno int32) *ebpf.Stat {
		return &ebpf.Stat{
			Type: ebpf.StatTypeBlockIo,
			BlockIo: &ebpf.BlockIo{
				Dev:       0x800010,
				Op:        uint8(op),
				LatencyNs: 3_000_000,
				QueueNs:   500_000,
				Bytes:     bytes,
				Error:     errno,
			},
		}
	}
	// WHEN it receives a successful flush and a failed discard
	stats.Send([]*ebpf.Stat{
		blockStat(ebpf.CodeBlockFlush, 0, 0),
		blockStat(ebpf.CodeBlockDiscard, 1<<20, -int32(unix.EIO)),
	})

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
		assert.Contains(ct, seen, "obi.stat.disk.flush.duration")
		assert.Contains(ct, seen, "obi.stat.disk.discard.duration")
	}, timeout, 100*time.Millisecond)

	// THEN a successful flush has no error.type at all, not an empty one
	flush := seen["obi.stat.disk.flush.duration"]
	assert.Equal(t, map[string]string{"system.device": "8:16", "obi.disk.stacked": "false"}, flush.Attributes)
	assert.Equal(t, "s", flush.Unit)
	assert.InEpsilon(t, 0.003, flush.FloatVal, 0.0001)
	assert.Equal(t, 1, flush.Count)

	// AND a failed discard carries its errno
	discard := seen["obi.stat.disk.discard.duration"]
	assert.Equal(t, map[string]string{"system.device": "8:16", "obi.disk.stacked": "false", "error.type": "EIO"}, discard.Attributes)
	assert.Equal(t, 1, discard.Count)

	// AND neither reached the read/write metrics
	for _, name := range []string{
		"obi.stat.disk.operation.duration",
		"obi.stat.disk.io",
		"obi.stat.disk.queue.duration",
		"obi.stat.disk.operation.errors",
	} {
		assert.NotContains(t, seen, name)
	}
}

// A failed discard released nothing: only the successful one adds bytes.
func TestStatMetricsExporter_FailedDiscardReleasesNoBytes(t *testing.T) {
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
			Metrics:     cfg,
			SelectorCfg: &attributes.SelectorConfig{},
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStorageBlockDiscard},
		}, stats)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	discardStat := func(bytes uint64, errno int32) *ebpf.Stat {
		return &ebpf.Stat{
			Type: ebpf.StatTypeBlockIo,
			BlockIo: &ebpf.BlockIo{
				Dev:       0x800010,
				Op:        uint8(ebpf.CodeBlockDiscard),
				LatencyNs: 3_000_000,
				Bytes:     bytes,
				Error:     errno,
			},
		}
	}
	// WHEN it receives a failed 1 MiB discard, then a successful 4 KiB one
	stats.Send([]*ebpf.Stat{
		discardStat(1<<20, -int32(unix.EIO)),
		discardStat(4096, 0),
	})

	// THEN the bytes counter settles on the successful discard alone: had the
	// failed one counted, it could never read 4096.
	latest := map[string]collector.MetricRecord{}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for drained := false; !drained; {
			select {
			case rec := <-otlp.Records():
				latest[rec.Name+"/"+rec.Attributes["error.type"]] = rec
			default:
				drained = true
			}
		}
		discardBytes, ok := latest["obi.stat.disk.discard.io/"]
		require.True(ct, ok, "discard bytes not exported yet")
		assert.Equal(ct, map[string]string{"system.device": "8:16", "obi.disk.stacked": "false"}, discardBytes.Attributes)
		assert.Equal(ct, "By", discardBytes.Unit)
		assert.Equal(ct, int64(4096), discardBytes.IntVal)

		// AND both discards are timed, the failed one with its errno
		assert.Equal(ct, 1, latest["obi.stat.disk.discard.duration/EIO"].Count)
		assert.Equal(ct, 1, latest["obi.stat.disk.discard.duration/"].Count)
	}, timeout, 100*time.Millisecond)
}

// The storage Expirers leave out attributes whose value is "", and a record
// that omits one attribute never shares a series with one that omits
// another: an omitted attribute keeps its place in the series key.
func TestStorageExpirerOmitsEmptyStrings(t *testing.T) {
	provider := otelmetric.NewMeterProvider(otelmetric.WithReader(otelmetric.NewManualReader()))
	counter, err := provider.Meter(statScopeName).Int64Counter("test")
	require.NoError(t, err)

	getter := func(name attr.Name, value func(*ebpf.Stat) string) attributes.Field[*ebpf.Stat, attribute.KeyValue] {
		return attributes.Field[*ebpf.Stat, attribute.KeyValue]{
			ExposedName: string(name),
			Get:         func(s *ebpf.Stat) attribute.KeyValue { return attribute.String(string(name), value(s)) },
		}
	}
	getters := []attributes.Field[*ebpf.Stat, attribute.KeyValue]{
		getter(attr.K8sPodName, func(s *ebpf.Stat) string { return s.CommonAttrs.Metadata[attr.K8sPodName] }),
		getter(attr.K8sNamespaceName, func(s *ebpf.Stat) string { return s.CommonAttrs.Metadata[attr.K8sNamespaceName] }),
	}
	ex := newStorageExpirer[metric2.Int64Counter, int64](t.Context(), counter, getters, timeNow, time.Hour)

	withMeta := func(m map[attr.Name]string) *ebpf.Stat { return &ebpf.Stat{CommonAttrs: pipe.CommonAttrs{Metadata: m}} }
	_, podOnly := ex.ForRecord(withMeta(map[attr.Name]string{attr.K8sPodName: "x"}))
	_, nsOnly := ex.ForRecord(withMeta(map[attr.Name]string{attr.K8sNamespaceName: "x"}))
	_, none := ex.ForRecord(withMeta(nil))

	assert.Equal(t, attribute.NewSet(attribute.String("k8s.pod.name", "x")), podOnly)
	assert.Equal(t, attribute.NewSet(attribute.String("k8s.namespace.name", "x")), nsOnly)
	assert.Equal(t, 0, none.Len())
}

// The stats resource names the host by host.id only. It is shared with the
// TCP stat metrics, so an attribute added to it would change their series
// wherever a collector turns resource attributes into labels; host.name from
// the container's hostname would also be the OBI pod's name, not the node's.
func TestStatsResourceHasNoHostName(t *testing.T) {
	attrs := getFilteredStatsResourceAttrs("host-id-1", attributes.Selection{})
	assert.Contains(t, attrs, semconv.HostID("host-id-1"))
	for _, kv := range attrs {
		assert.NotEqual(t, semconv.HostNameKey, kv.Key)
	}
}
