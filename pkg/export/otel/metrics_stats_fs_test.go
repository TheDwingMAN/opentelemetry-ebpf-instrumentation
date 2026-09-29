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

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestStatMetricsExporter_FsMetrics(t *testing.T) {
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
					attributes.StatFsOperationDuration.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
					attributes.StatFsIO.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
				},
			},
			CommonCfg: &perapp.GlobalMetricsConfig{Features: export.FeatureStorageFS},
		}, stats)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives a filesystem I/O stat
	stats.Send([]*ebpf.Stat{
		{
			Type: ebpf.StatTypeFsIo,
			FsIo: &ebpf.FsIo{
				Fs:        uint8(ebpf.CodeFsNFS),
				Op:        uint8(ebpf.CodeFsOpWrite),
				LatencyNs: 2_000_000,
				Bytes:     65536,
			},
		},
	})

	// THEN that one event produces both fs metrics: the latency histogram
	// and the bytes counter.
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
		assert.Contains(ct, seen, "obi.stat.fs.operation.duration")
		assert.Contains(ct, seen, "obi.stat.fs.io")
	}, timeout, 100*time.Millisecond)

	// Both metrics carry the same filesystem type/operation attributes
	fsAttrs := map[string]string{
		"system.filesystem.type": "nfs",
		"fs.operation":           "write",
	}

	latency := seen["obi.stat.fs.operation.duration"]
	assert.Equal(t, fsAttrs, latency.Attributes)
	assert.InEpsilon(t, 0.002, latency.FloatVal, 0.0001)
	assert.Equal(t, 1, latency.Count)

	ioBytes := seen["obi.stat.fs.io"]
	assert.Equal(t, fsAttrs, ioBytes.Attributes)
	assert.Equal(t, int64(65536), ioBytes.IntVal)
}

// TestStatMetricsExporter_FsIOBytesSkipsZeroBytes covers an fsync completion,
// which carries LatencyNs but no Bytes: the duration histogram must still be
// exported, but the bytes counter must never appear for that event.
func TestStatMetricsExporter_FsIOBytesSkipsZeroBytes(t *testing.T) {
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
					attributes.StatFsOperationDuration.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
					attributes.StatFsIO.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
				},
			},
			CommonCfg: &perapp.GlobalMetricsConfig{Features: export.FeatureStorageFS},
		}, stats)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives a successful fsync completion (Bytes == 0)
	stats.Send([]*ebpf.Stat{
		{
			Type: ebpf.StatTypeFsIo,
			FsIo: &ebpf.FsIo{
				Fs:        uint8(ebpf.CodeFsNFS),
				Op:        uint8(ebpf.CodeFsOpFsync),
				LatencyNs: 1_000_000,
				Bytes:     0,
			},
		},
	})

	// THEN the latency histogram is exported...
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
		assert.Contains(ct, seen, "obi.stat.fs.operation.duration")
	}, timeout, 100*time.Millisecond)

	latency := seen["obi.stat.fs.operation.duration"]
	assert.Equal(t, map[string]string{
		"system.filesystem.type": "nfs",
		"fs.operation":           "fsync",
	}, latency.Attributes)

	// ...but the bytes counter never appears for a zero-byte completion.
	assert.NotContains(t, seen, "obi.stat.fs.io")
}

// TestStatMetricsExporter_FsOperationErrors covers the error counter added on
// top of the base duration/io pair. Only storage_fs_errors is enabled (not
// duration/io), which doubles as a gating test: the base fs metrics must not
// appear when their own feature bit is off.
func TestStatMetricsExporter_FsOperationErrors(t *testing.T) {
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
					attributes.StatFsOperationErrors.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
				},
			},
			CommonCfg: &perapp.GlobalMetricsConfig{Features: export.FeatureStorageFSErrors},
		}, stats)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives a failed filesystem I/O completion
	stats.Send([]*ebpf.Stat{
		{
			Type: ebpf.StatTypeFsIo,
			FsIo: &ebpf.FsIo{
				Fs:    uint8(ebpf.CodeFsNFS),
				Op:    uint8(ebpf.CodeFsOpWrite),
				Error: -116, // -ESTALE
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
		assert.Contains(ct, seen, "obi.stat.fs.operation.errors")
	}, timeout, 100*time.Millisecond)

	// Gating: storage_fs_duration/storage_fs_io are off, so neither of the
	// base fs metrics should have been exported.
	assert.NotContains(t, seen, "obi.stat.fs.operation.duration")
	assert.NotContains(t, seen, "obi.stat.fs.io")

	opErrors := seen["obi.stat.fs.operation.errors"]
	assert.Equal(t, map[string]string{
		"system.filesystem.type": "nfs",
		"fs.operation":           "write",
		"error.type":             "ESTALE",
	}, opErrors.Attributes)
	assert.Equal(t, int64(1), opErrors.IntVal)
}

// The filesystem counterpart of TestStatMetricsExporter_DiskOperationErrorsSkipsZeroError:
// a successful read or write must not create an error series.
func TestStatMetricsExporter_FsOperationErrorsSkipsZeroError(t *testing.T) {
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
					attributes.StatFsOperationDuration.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
					attributes.StatFsOperationErrors.Section: attributes.InclusionLists{
						Include: []string{"*"},
					},
				},
			},
			CommonCfg: &perapp.GlobalMetricsConfig{Features: export.FeatureStorageFSDuration | export.FeatureStorageFSErrors},
		}, stats)(ctx)
	require.NoError(t, err)

	go otelExporter(ctx)

	// WHEN it receives a filesystem I/O completion that succeeded
	stats.Send([]*ebpf.Stat{
		{
			Type: ebpf.StatTypeFsIo,
			FsIo: &ebpf.FsIo{
				Fs:        uint8(ebpf.CodeFsNFS),
				Op:        uint8(ebpf.CodeFsOpWrite),
				LatencyNs: 1_000_000,
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
		assert.Contains(ct, seen, "obi.stat.fs.operation.duration")
	}, timeout, 100*time.Millisecond)

	// AND the errors counter never does.
	assert.NotContains(t, seen, "obi.stat.fs.operation.errors", "errors counter must not be recorded for Error == 0")
}

// A storage attribute that does not apply is left out of the OTLP data point
// rather than sent as "": a process in no pod has no k8s.pod.name, I/O on no
// volume no k8s.persistentvolume.name, and an unknown filesystem no
// system.filesystem.type. With a pod and a volume, all of them are there, the
// volume ones read from the mount the stat went through.
func TestStatMetricsExporter_FsOmitsEmptyAttributes(t *testing.T) {
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
		&global.ContextInfo{
			OTELMetricsExporter:   &otelcfg.MetricsExporterInstancer{Cfg: cfg},
			MetricAttributeGroups: attributes.GroupKubernetes,
		},
		&StatMetricsConfig{
			Metrics:     cfg,
			SelectorCfg: &attributes.SelectorConfig{SelectionCfg: attributes.Selection{}},
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStorageFSIo},
		}, stats)(ctx)
	require.NoError(t, err)
	go otelExporter(ctx)

	onVolume := &ebpf.Stat{
		Type: ebpf.StatTypeFsIo,
		FsIo: &ebpf.FsIo{
			Fs: uint8(ebpf.CodeFsXFS), Op: uint8(ebpf.CodeFsOpWrite), Bytes: 4096,
			Mount: &ebpf.MountAttrs{PVName: "pvc-1", PVCName: "data", StorageClass: "fast", PVCNamespace: "ns"},
		},
		CommonAttrs: pipe.CommonAttrs{Metadata: map[attr.Name]string{
			attr.K8sPodName: "writer", attr.K8sNamespaceName: "ns", attr.K8sContainerName: "io",
		}},
	}
	noVolume := &ebpf.Stat{
		Type: ebpf.StatTypeFsIo,
		FsIo: &ebpf.FsIo{Fs: uint8(ebpf.CodeFsUnknown), Op: uint8(ebpf.CodeFsOpRead), Bytes: 512},
	}
	stats.Send([]*ebpf.Stat{onVolume, noVolume})

	want := []map[string]string{
		{
			"system.filesystem.type":         "xfs",
			"fs.operation":                   "write",
			"k8s.pod.name":                   "writer",
			"k8s.namespace.name":             "ns",
			"k8s.container.name":             "io",
			"k8s.persistentvolume.name":      "pvc-1",
			"k8s.persistentvolumeclaim.name": "data",
			"k8s.storageclass.name":          "fast",
		},
		{"fs.operation": "read"},
	}
	var got []map[string]string
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for drained := false; !drained; {
			select {
			case rec := <-otlp.Records():
				if rec.Name == "obi.stat.fs.io" && !slices.ContainsFunc(got, func(a map[string]string) bool { return maps.Equal(a, rec.Attributes) }) {
					got = append(got, rec.Attributes)
				}
			default:
				drained = true
			}
		}
		assert.ElementsMatch(ct, want, got)
	}, timeout, 100*time.Millisecond)
}
