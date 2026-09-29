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

// newDiskStatsReporter builds a stats reporter wired to an isolated registry
// with only the storage_block feature enabled.
func newDiskStatsReporter(t *testing.T, registry *prometheus.Registry) *statMetricsReporter {
	t.Helper()
	return newStatsReporterWithFeatures(t, registry, export.FeatureStorageBlock)
}

func newStatsReporterWithFeatures(
	t *testing.T, registry *prometheus.Registry, features export.Features,
) *statMetricsReporter {
	t.Helper()

	reporter, err := newStatsReporter(
		&global.ContextInfo{Prometheus: &connector.PrometheusManager{}},
		&StatsPrometheusConfig{
			Config:      &PrometheusConfig{Registry: registry, TTL: time.Minute},
			SelectorCfg: &attributes.SelectorConfig{},
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: features},
		},
		msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(1)),
	)
	require.NoError(t, err)
	return reporter
}

// blockIoStat is one completed block request: 4 KiB written to major 8 / minor 16
// taking 2ms, after 0.5ms queued, with 3 other requests left in flight.
func blockIoStat() *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeBlockIo,
		BlockIo: &ebpf.BlockIo{
			Dev:       0x800010,
			Op:        uint8(ebpf.CodeDirectionWrite),
			LatencyNs: 2_000_000,
			QueueNs:   500_000,
			Bytes:     4096,
			Inflight:  3,
		},
	}
}

// blockIoErrorStat is a failed block completion on the same device/direction
// as blockIoStat, with a non-zero error (-ENOSPC).
func blockIoErrorStat() *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeBlockIo,
		BlockIo: &ebpf.BlockIo{
			Dev:   0x800010,
			Op:    uint8(ebpf.CodeDirectionWrite),
			Error: -28, // -ENOSPC
		},
	}
}

// TestStatsReporterRecordsDiskMetrics asserts that a single block I/O event
// feeds both disk metric families -- the latency histogram and the bytes
// counter -- with the device and direction labels decoded from the raw stat.
func TestStatsReporterRecordsDiskMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newDiskStatsReporter(t, registry)

	reporter.observeDiskOpDuration(blockIoStat())
	reporter.observeDiskIOBytes(blockIoStat())

	diskLabels := map[string]string{
		"system_device":     "8:16",
		"disk_io_direction": "write",
	}

	latency := gatheredMetric(t, registry, "obi_stat_disk_operation_duration_seconds", diskLabels)
	require.NotNil(t, latency, "latency histogram not registered or not observed")
	assert.Equal(t, uint64(1), latency.GetHistogram().GetSampleCount())
	assert.InEpsilon(t, 0.002, latency.GetHistogram().GetSampleSum(), 0.0001)

	ioBytes := gatheredMetric(t, registry, "obi_stat_disk_io_bytes_total", diskLabels)
	require.NotNil(t, ioBytes, "bytes counter not registered or not observed")
	assert.InEpsilon(t, 4096.0, ioBytes.GetCounter().GetValue(), 0)
}

// TestStatsReporterDiskBytesAccumulates asserts the bytes metric is a counter
// that sums across requests rather than overwriting -- the property that makes
// it usable as a throughput metric via rate().
func TestStatsReporterDiskBytesAccumulates(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newDiskStatsReporter(t, registry)

	for range 3 {
		reporter.observeDiskIOBytes(blockIoStat())
	}

	ioBytes := gatheredMetric(t, registry, "obi_stat_disk_io_bytes_total", map[string]string{
		"system_device":     "8:16",
		"disk_io_direction": "write",
	})
	require.NotNil(t, ioBytes)
	assert.InEpsilon(t, 12288.0, ioBytes.GetCounter().GetValue(), 0)
}

// TestStatsReporterDiskFeatureGating asserts each disk metric is independently
// selectable. Both derive from the same block tracepoints, so it would be easy
// to gate them on a single flag; users who only want one should not pay the
// cardinality of the other.
func TestStatsReporterDiskFeatureGating(t *testing.T) {
	for _, tc := range []struct {
		name        string
		features    export.Features
		wantLatency bool
		wantBytes   bool
	}{
		{"umbrella enables both", export.FeatureStorageBlock, true, true},
		{"latency only", export.FeatureStorageBlockDuration, true, false},
		{"bytes only", export.FeatureStorageBlockIo, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			reporter := newStatsReporterWithFeatures(t, registry, tc.features)

			reporter.observeDiskOpDuration(blockIoStat())
			reporter.observeDiskIOBytes(blockIoStat())

			diskLabels := map[string]string{
				"system_device":     "8:16",
				"disk_io_direction": "write",
			}

			latency := gatheredMetric(t, registry, "obi_stat_disk_operation_duration_seconds", diskLabels)
			ioBytes := gatheredMetric(t, registry, "obi_stat_disk_io_bytes_total", diskLabels)

			assert.Equal(t, tc.wantLatency, latency != nil, "latency histogram presence")
			assert.Equal(t, tc.wantBytes, ioBytes != nil, "bytes counter presence")
		})
	}
}

// TestStatsReporterSkipsDiskMetricsWithoutFeature asserts the disk families are
// not registered at all when storage_block is off, so enabling only TCP stats
// does not silently emit empty disk series.
func TestStatsReporterSkipsDiskMetricsWithoutFeature(t *testing.T) {
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

	assert.Nil(t, reporter.diskOpDuration)
	assert.Nil(t, reporter.diskIOBytes)
	assert.Nil(t, reporter.diskQueueDuration)
	assert.Nil(t, reporter.diskQueueDepth)
	assert.Nil(t, reporter.diskOpErrors)

	// Observing is a no-op rather than a nil-pointer panic.
	reporter.observeDiskOpDuration(blockIoStat())
	reporter.observeDiskIOBytes(blockIoStat())
	reporter.observeDiskQueueDuration(blockIoStat())
	reporter.observeDiskQueueDepth(blockIoStat())
	reporter.observeDiskOpErrors(blockIoErrorStat())

	families, err := registry.Gather()
	require.NoError(t, err)
	for _, f := range families {
		assert.NotContains(t, f.GetName(), "disk")
	}
}

// TestStatsReporterRecordsDiskQueueMetrics asserts a single block I/O event
// feeds both queue metrics -- queue wait and queue depth -- with the same
// device/direction (queue wait) or device-only (queue depth) labels as the
// base disk metrics.
func TestStatsReporterRecordsDiskQueueMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newStatsReporterWithFeatures(t, registry, export.FeatureStorageBlockQueue)

	reporter.observeDiskQueueDuration(blockIoStat())
	reporter.observeDiskQueueDepth(blockIoStat())

	queueDuration := gatheredMetric(t, registry, "obi_stat_disk_queue_duration_seconds", map[string]string{
		"system_device":     "8:16",
		"disk_io_direction": "write",
	})
	require.NotNil(t, queueDuration, "queue duration histogram not registered or not observed")
	assert.Equal(t, uint64(1), queueDuration.GetHistogram().GetSampleCount())
	assert.InEpsilon(t, 0.0005, queueDuration.GetHistogram().GetSampleSum(), 0.0001)

	queueDepth := gatheredMetric(t, registry, "obi_stat_disk_queue_depth", map[string]string{
		"system_device": "8:16",
	})
	require.NotNil(t, queueDepth, "queue depth histogram not registered or not observed")
	assert.Equal(t, uint64(1), queueDepth.GetHistogram().GetSampleCount())
	assert.InEpsilon(t, 3.0, queueDepth.GetHistogram().GetSampleSum(), 0.0001)
}

// TestStatsReporterRecordsDiskOperationErrors asserts the error counter only
// increments for a failed completion, keyed by the errno name, and a
// successful completion (Error == 0) leaves it untouched.
func TestStatsReporterRecordsDiskOperationErrors(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newStatsReporterWithFeatures(t, registry, export.FeatureStorageBlockErrors)

	reporter.observeDiskOpErrors(blockIoStat()) // Error == 0: must not count
	reporter.observeDiskOpErrors(blockIoErrorStat())

	opErrors := gatheredMetric(t, registry, "obi_stat_disk_operation_errors_total", map[string]string{
		"system_device":     "8:16",
		"disk_io_direction": "write",
		"error_type":        "ENOSPC",
	})
	require.NotNil(t, opErrors, "errors counter not registered or not observed")
	assert.InEpsilon(t, 1.0, opErrors.GetCounter().GetValue(), 0)
}

// TestStatsReporterDiskQueueAndErrorsFeatureGating asserts the queue metrics
// and the errors counter are each independently selectable, mirroring
// TestStatsReporterDiskFeatureGating for the base duration/io pair.
func TestStatsReporterDiskQueueAndErrorsFeatureGating(t *testing.T) {
	for _, tc := range []struct {
		name       string
		features   export.Features
		wantQueue  bool
		wantErrors bool
	}{
		{"umbrella enables both", export.FeatureStorageBlock, true, true},
		{"queue only", export.FeatureStorageBlockQueue, true, false},
		{"errors only", export.FeatureStorageBlockErrors, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			reporter := newStatsReporterWithFeatures(t, registry, tc.features)

			reporter.observeDiskQueueDuration(blockIoStat())
			reporter.observeDiskOpErrors(blockIoErrorStat())

			queueDuration := gatheredMetric(t, registry, "obi_stat_disk_queue_duration_seconds", map[string]string{
				"system_device":     "8:16",
				"disk_io_direction": "write",
			})
			opErrors := gatheredMetric(t, registry, "obi_stat_disk_operation_errors_total", map[string]string{
				"system_device":     "8:16",
				"disk_io_direction": "write",
				"error_type":        "ENOSPC",
			})

			assert.Equal(t, tc.wantQueue, queueDuration != nil, "queue duration histogram presence")
			assert.Equal(t, tc.wantErrors, opErrors != nil, "errors counter presence")
		})
	}
}
