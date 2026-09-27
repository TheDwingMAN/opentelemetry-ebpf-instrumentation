// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// newFsStatsReporter builds a stats reporter wired to an isolated registry
// with only the storage_fs feature enabled.
func newFsStatsReporter(t *testing.T, registry *prometheus.Registry) *statMetricsReporter {
	t.Helper()
	return newStatsReporterWithFeatures(t, registry, export.FeatureStorageFS)
}

// fsIoStat is one completed filesystem request: 64 KiB written to NFS
// taking 2ms.
func fsIoStat() *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeFsIo,
		FsIo: &ebpf.FsIo{
			Fs:        uint8(ebpf.CodeFsNFS),
			Op:        uint8(ebpf.CodeFsOpWrite),
			LatencyNs: 2_000_000,
			Bytes:     65536,
		},
	}
}

// fsIoErrorStat is a failed filesystem completion on the same fs
// type/operation as fsIoStat, with a non-zero error (-ESTALE).
func fsIoErrorStat() *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeFsIo,
		FsIo: &ebpf.FsIo{
			Fs:    uint8(ebpf.CodeFsNFS),
			Op:    uint8(ebpf.CodeFsOpWrite),
			Error: -116, // -ESTALE
		},
	}
}

// TestStatsReporterRecordsFsMetrics asserts that a single filesystem I/O event
// feeds both fs metric families -- the latency histogram and the bytes
// counter -- with the fs type and operation labels decoded from the raw stat.
func TestStatsReporterRecordsFsMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newFsStatsReporter(t, registry)

	reporter.observeFsOpDuration(fsIoStat())
	reporter.observeFsIOBytes(fsIoStat())

	fsLabels := map[string]string{
		"system_filesystem_type": "nfs",
		"fs_operation":           "write",
	}

	latency := gatheredMetric(t, registry, "obi_stat_fs_operation_duration_seconds", fsLabels)
	require.NotNil(t, latency, "latency histogram not registered or not observed")
	assert.Equal(t, uint64(1), latency.GetHistogram().GetSampleCount())
	assert.InEpsilon(t, 0.002, latency.GetHistogram().GetSampleSum(), 0.0001)

	ioBytes := gatheredMetric(t, registry, "obi_stat_fs_io_bytes_total", fsLabels)
	require.NotNil(t, ioBytes, "bytes counter not registered or not observed")
	assert.InEpsilon(t, 65536.0, ioBytes.GetCounter().GetValue(), 0)
}

// TestStatsReporterFsMetricsNotRegisteredWithoutFeature asserts the fs
// families are not registered at all when storage_fs is off, so enabling only
// TCP stats does not silently emit empty fs series.
func TestStatsReporterFsMetricsNotRegisteredWithoutFeature(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter, err := newStatsReporter(
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&StatsPrometheusConfig{
			Config:      &PrometheusConfig{Registry: registry, TTL: time.Minute},
			SelectorCfg: &attributes.SelectorConfig{},
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStatsTCPRtt},
		},
		msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)

	assert.Nil(t, reporter.fsOpDuration)
	assert.Nil(t, reporter.fsIOBytes)
	assert.Nil(t, reporter.fsOpErrors)

	// Observing is a no-op rather than a nil-pointer panic.
	reporter.observeFsOpDuration(fsIoStat())
	reporter.observeFsIOBytes(fsIoStat())
	reporter.observeFsOpErrors(fsIoErrorStat())

	families, err := registry.Gather()
	require.NoError(t, err)
	for _, f := range families {
		assert.NotContains(t, f.GetName(), "fs_io")
		assert.NotContains(t, f.GetName(), "fs_operation")
	}
}

// TestStatsReporterRecordsFsOperationErrors asserts the error counter only
// increments for a failed filesystem completion, keyed by the errno name, and
// a successful completion (Error == 0) leaves it untouched.
func TestStatsReporterRecordsFsOperationErrors(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newStatsReporterWithFeatures(t, registry, export.FeatureStorageFSErrors)

	reporter.observeFsOpErrors(fsIoStat()) // Error == 0: must not count
	reporter.observeFsOpErrors(fsIoErrorStat())

	opErrors := gatheredMetric(t, registry, "obi_stat_fs_operation_errors_total", map[string]string{
		"system_filesystem_type": "nfs",
		"fs_operation":           "write",
		"error_type":             "ESTALE",
	})
	require.NotNil(t, opErrors, "errors counter not registered or not observed")
	assert.InEpsilon(t, 1.0, opErrors.GetCounter().GetValue(), 0)
}

// TestStatsReporterFsFeatureGating asserts each fs metric is independently
// selectable, mirroring TestStatsReporterDiskQueueAndErrorsFeatureGating for
// the disk errors counter.
func TestStatsReporterFsFeatureGating(t *testing.T) {
	for _, tc := range []struct {
		name        string
		features    export.Features
		wantLatency bool
		wantErrors  bool
	}{
		{"umbrella enables both", export.FeatureStorageFS, true, true},
		{"duration only", export.FeatureStorageFSDuration, true, false},
		{"errors only", export.FeatureStorageFSErrors, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			reporter := newStatsReporterWithFeatures(t, registry, tc.features)

			reporter.observeFsOpDuration(fsIoStat())
			reporter.observeFsOpErrors(fsIoErrorStat())

			fsLabels := map[string]string{
				"system_filesystem_type": "nfs",
				"fs_operation":           "write",
			}
			latency := gatheredMetric(t, registry, "obi_stat_fs_operation_duration_seconds", fsLabels)

			opErrors := gatheredMetric(t, registry, "obi_stat_fs_operation_errors_total", map[string]string{
				"system_filesystem_type": "nfs",
				"fs_operation":           "write",
				"error_type":             "ESTALE",
			})

			assert.Equal(t, tc.wantLatency, latency != nil, "latency histogram presence")
			assert.Equal(t, tc.wantErrors, opErrors != nil, "errors counter presence")
		})
	}
}
