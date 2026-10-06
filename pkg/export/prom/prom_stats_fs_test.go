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

// TestStatsReporterRecordsFsMetrics asserts that a single filesystem I/O event
// feeds both fs metric families -- the latency histogram and the bytes
// counter -- with the fs type and operation labels decoded from the raw stat.
func TestStatsReporterRecordsFsMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newFsStatsReporter(t, registry)

	reporter.observeFsOpDuration(fsIoStat())
	reporter.observeFsIOBytes(fsIoStat())

	fsLabels := map[string]string{
		"fs_type":      "nfs",
		"fs_operation": "write",
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

	// Observing is a no-op rather than a nil-pointer panic.
	reporter.observeFsOpDuration(fsIoStat())
	reporter.observeFsIOBytes(fsIoStat())

	families, err := registry.Gather()
	require.NoError(t, err)
	for _, f := range families {
		assert.NotContains(t, f.GetName(), "fs_io")
		assert.NotContains(t, f.GetName(), "fs_operation")
	}
}
