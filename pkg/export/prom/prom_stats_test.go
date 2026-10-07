// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

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
			Error: -int32(unix.ENOSPC),
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
		"system_device": "8:16", "obi_disk_stacked": "false",
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
		"system_device": "8:16", "obi_disk_stacked": "false",
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
				"system_device": "8:16", "obi_disk_stacked": "false",
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
	reporter := newStatsReporterWithFeatures(t, registry, export.FeatureStorageBlockQueue|export.FeatureStorageBlockQueueDepth)

	reporter.observeDiskQueueDuration(blockIoStat())
	reporter.observeDiskQueueDepth(blockIoStat())

	queueDuration := gatheredMetric(t, registry, "obi_stat_disk_queue_duration_seconds", map[string]string{
		"system_device": "8:16", "obi_disk_stacked": "false",
		"disk_io_direction": "write",
	})
	require.NotNil(t, queueDuration, "queue duration histogram not registered or not observed")
	assert.Equal(t, uint64(1), queueDuration.GetHistogram().GetSampleCount())
	assert.InEpsilon(t, 0.0005, queueDuration.GetHistogram().GetSampleSum(), 0.0001)

	queueDepth := gatheredMetric(t, registry, "obi_stat_disk_queue_depth", map[string]string{
		"system_device": "8:16", "obi_disk_stacked": "false",
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
		"system_device": "8:16", "obi_disk_stacked": "false",
		"disk_io_direction": "write",
		"error_type":        "ENOSPC",
	})
	require.NotNil(t, opErrors, "errors counter not registered or not observed")
	assert.InEpsilon(t, 1.0, opErrors.GetCounter().GetValue(), 0)
}

// blockIoNoQueueStat is a block completion whose request has no valid
// accounting start (e.g. queue/iostats=0): QueueNs is 0, so there is
// no queue wait for the queue duration histogram to observe, while the other
// disk metrics observe normally.
func blockIoNoQueueStat() *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeBlockIo,
		BlockIo: &ebpf.BlockIo{
			Dev:       0x800010,
			Op:        uint8(ebpf.CodeDirectionWrite),
			LatencyNs: 2_000_000,
			QueueNs:   0,
			Bytes:     4096,
		},
	}
}

// TestStatsReporterSkipsQueueDurationForZeroQueueNs asserts the A9 ruling:
// QueueNs == 0 means no valid accounting start matched this completion (e.g.
// blk-mq issued it directly), so the queue duration histogram must not
// observe it, while the operation duration histogram -- which doesn't depend
// on QueueNs -- still does.
func TestStatsReporterSkipsQueueDurationForZeroQueueNs(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newStatsReporterWithFeatures(t, registry, export.FeatureStorageBlockDuration|export.FeatureStorageBlockQueue)

	reporter.observeDiskOpDuration(blockIoNoQueueStat())
	reporter.observeDiskQueueDuration(blockIoNoQueueStat())

	diskLabels := map[string]string{
		"system_device": "8:16", "obi_disk_stacked": "false",
		"disk_io_direction": "write",
	}

	latency := gatheredMetric(t, registry, "obi_stat_disk_operation_duration_seconds", diskLabels)
	require.NotNil(t, latency, "operation duration must still be observed")
	assert.Equal(t, uint64(1), latency.GetHistogram().GetSampleCount())

	queueDuration := gatheredMetric(t, registry, "obi_stat_disk_queue_duration_seconds", diskLabels)
	assert.Nil(t, queueDuration, "queue duration must not be observed for QueueNs == 0")
}

// TestStatsReporterDiskQueueAndErrorsFeatureGating asserts the queue metrics
// and the errors counter are each independently selectable, mirroring
// TestStatsReporterDiskFeatureGating for the base duration/io pair.
func TestStatsReporterDiskQueueAndErrorsFeatureGating(t *testing.T) {
	for _, tc := range []struct {
		name       string
		features   export.Features
		wantQueue  bool
		wantDepth  bool
		wantErrors bool
	}{
		{"umbrella enables queue and errors, not the deprecated depth", export.FeatureStorageBlock, true, false, true},
		{"queue only", export.FeatureStorageBlockQueue, true, false, false},
		{"depth only", export.FeatureStorageBlockQueueDepth, false, true, false},
		{"errors only", export.FeatureStorageBlockErrors, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			reporter := newStatsReporterWithFeatures(t, registry, tc.features)

			reporter.observeDiskQueueDuration(blockIoStat())
			reporter.observeDiskQueueDepth(blockIoStat())
			reporter.observeDiskOpErrors(blockIoErrorStat())

			queueDuration := gatheredMetric(t, registry, "obi_stat_disk_queue_duration_seconds", map[string]string{
				"system_device": "8:16", "obi_disk_stacked": "false",
				"disk_io_direction": "write",
			})
			opErrors := gatheredMetric(t, registry, "obi_stat_disk_operation_errors_total", map[string]string{
				"system_device": "8:16", "obi_disk_stacked": "false",
				"disk_io_direction": "write",
				"error_type":        "ENOSPC",
			})

			queueDepth := gatheredMetric(t, registry, "obi_stat_disk_queue_depth", map[string]string{
				"system_device": "8:16", "obi_disk_stacked": "false",
			})

			assert.Equal(t, tc.wantQueue, queueDuration != nil, "queue duration histogram presence")
			assert.Equal(t, tc.wantDepth, queueDepth != nil, "queue depth histogram presence")
			assert.Equal(t, tc.wantErrors, opErrors != nil, "errors counter presence")
		})
	}
}

// blockIoKindStat is a completed block request of the given kind on major 8 /
// minor 16, taking 3ms.
func blockIoKindStat(op ebpf.BlockOpCode, bytes uint64, errno int32) *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeBlockIo,
		BlockIo: &ebpf.BlockIo{
			Dev:       0x800010,
			Op:        uint8(op),
			LatencyNs: 3_000_000,
			QueueNs:   500_000,
			Bytes:     bytes,
			Error:     errno,
			Inflight:  2,
		},
	}
}

// Flushes and discards have metrics of their own, without a direction, and
// error.type only when they fail.
func TestStatsReporterRecordsDiskFlushAndDiscard(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newDiskStatsReporter(t, registry)

	reporter.observeDiskFlushDuration(blockIoKindStat(ebpf.CodeBlockFlush, 0, 0))
	reporter.observeDiskFlushDuration(blockIoKindStat(ebpf.CodeBlockFlush, 0, -int32(unix.EIO)))
	reporter.observeDiskDiscard(blockIoKindStat(ebpf.CodeBlockDiscard, 1<<20, 0))
	reporter.observeDiskDiscard(blockIoKindStat(ebpf.CodeBlockDiscard, 1<<20, 0))

	ok := map[string]string{"system_device": "8:16", "obi_disk_stacked": "false", "error_type": ""}
	failed := map[string]string{"system_device": "8:16", "obi_disk_stacked": "false", "error_type": "EIO"}

	flush := gatheredMetric(t, registry, "obi_stat_disk_flush_duration_seconds", ok)
	require.NotNil(t, flush, "flush histogram not registered or not observed")
	assert.Equal(t, uint64(1), flush.GetHistogram().GetSampleCount())
	assert.InEpsilon(t, 0.003, flush.GetHistogram().GetSampleSum(), 0.0001)

	reporter.observeDiskOpDuration(blockIoStat())
	opDuration := gatheredMetric(t, registry, "obi_stat_disk_operation_duration_seconds",
		map[string]string{"system_device": "8:16", "obi_disk_stacked": "false", "disk_io_direction": "write"})
	require.NotNil(t, opDuration)
	upperBounds := func(h *dto.Histogram) []float64 {
		bounds := []float64{}
		for _, b := range h.GetBucket() {
			bounds = append(bounds, b.GetUpperBound())
		}
		return bounds
	}
	assert.Equal(t, upperBounds(opDuration.GetHistogram()), upperBounds(flush.GetHistogram()),
		"flush shares the disk operation duration buckets")

	failedFlush := gatheredMetric(t, registry, "obi_stat_disk_flush_duration_seconds", failed)
	require.NotNil(t, failedFlush, "a failed flush carries its error.type")
	assert.Equal(t, uint64(1), failedFlush.GetHistogram().GetSampleCount())

	discard := gatheredMetric(t, registry, "obi_stat_disk_discard_duration_seconds", ok)
	require.NotNil(t, discard, "discard histogram not registered or not observed")
	assert.Equal(t, uint64(2), discard.GetHistogram().GetSampleCount())

	discardBytes := gatheredMetric(t, registry, "obi_stat_disk_discard_io_bytes_total",
		map[string]string{"system_device": "8:16", "obi_disk_stacked": "false"})
	require.NotNil(t, discardBytes, "discard bytes counter not registered or not observed")
	assert.InEpsilon(t, float64(2<<20), discardBytes.GetCounter().GetValue(), 0)
	assert.Equal(t, upperBounds(opDuration.GetHistogram()), upperBounds(discard.GetHistogram()),
		"discard shares the disk operation duration buckets")
}

// A failed discard released nothing: it is timed, with its error.type, but
// adds no bytes.
func TestStatsReporterFailedDiscardReleasesNoBytes(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newDiskStatsReporter(t, registry)

	reporter.observeDiskDiscard(blockIoKindStat(ebpf.CodeBlockDiscard, 1<<20, -int32(unix.EIO)))

	failed := gatheredMetric(t, registry, "obi_stat_disk_discard_duration_seconds",
		map[string]string{"system_device": "8:16", "obi_disk_stacked": "false", "error_type": "EIO"})
	require.NotNil(t, failed, "a failed discard is still timed")
	assert.Equal(t, uint64(1), failed.GetHistogram().GetSampleCount())
	assert.Nil(t, gatheredMetric(t, registry, "obi_stat_disk_discard_io_bytes_total",
		map[string]string{"system_device": "8:16", "obi_disk_stacked": "false"}), "a failed discard released no bytes")

	reporter.observeDiskDiscard(blockIoKindStat(ebpf.CodeBlockDiscard, 4096, 0))

	discardBytes := gatheredMetric(t, registry, "obi_stat_disk_discard_io_bytes_total",
		map[string]string{"system_device": "8:16", "obi_disk_stacked": "false"})
	require.NotNil(t, discardBytes)
	assert.InEpsilon(t, float64(4096), discardBytes.GetCounter().GetValue(), 0)
}

// The read/write metrics see reads and writes only: a flush is not a 0-byte
// write and a discard is not a read.
func TestStatsReporterReadWriteMetricsSkipFlushAndDiscard(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newStatsReporterWithFeatures(t, registry, export.FeatureStorageBlock|export.FeatureStorageBlockQueueDepth)

	for _, stat := range []*ebpf.Stat{
		blockIoKindStat(ebpf.CodeBlockFlush, 0, -int32(unix.EIO)),
		blockIoKindStat(ebpf.CodeBlockDiscard, 1<<20, -int32(unix.EIO)),
	} {
		reporter.observeDiskOpDuration(stat)
		reporter.observeDiskIOBytes(stat)
		reporter.observeDiskQueueDuration(stat)
		reporter.observeDiskQueueDepth(stat)
		reporter.observeDiskOpErrors(stat)
	}
	for _, stat := range []*ebpf.Stat{
		blockIoKindStat(ebpf.CodeBlockWrite, 4096, 0),
		blockIoKindStat(ebpf.CodeBlockRead, 4096, 0),
	} {
		reporter.observeDiskFlushDuration(stat)
		reporter.observeDiskDiscard(stat)
	}

	metrics, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range metrics {
		assert.Empty(t, family.GetMetric(), "%s observed a request of another kind", family.GetName())
	}
}

// Each of flush and discard is selectable on its own.
func TestStatsReporterDiskFlushDiscardFeatureGating(t *testing.T) {
	for _, tc := range []struct {
		features    export.Features
		wantFlush   bool
		wantDiscard bool
	}{
		{export.FeatureStorageBlockFlush, true, false},
		{export.FeatureStorageBlockDiscard, false, true},
		{export.FeatureStorageBlockDuration | export.FeatureStorageBlockIo, false, false},
	} {
		registry := prometheus.NewRegistry()
		reporter := newStatsReporterWithFeatures(t, registry, tc.features)
		reporter.observeDiskFlushDuration(blockIoKindStat(ebpf.CodeBlockFlush, 0, 0))
		reporter.observeDiskDiscard(blockIoKindStat(ebpf.CodeBlockDiscard, 4096, 0))

		assert.Equal(t, tc.wantFlush, gatheredMetric(t, registry, "obi_stat_disk_flush_duration_seconds",
			map[string]string{"system_device": "8:16", "obi_disk_stacked": "false", "error_type": ""}) != nil)
		assert.Equal(t, tc.wantDiscard, gatheredMetric(t, registry, "obi_stat_disk_discard_duration_seconds",
			map[string]string{"system_device": "8:16", "obi_disk_stacked": "false", "error_type": ""}) != nil)
		assert.Equal(t, tc.wantDiscard, gatheredMetric(t, registry, "obi_stat_disk_discard_io_bytes_total",
			map[string]string{"system_device": "8:16", "obi_disk_stacked": "false"}) != nil)
	}
}
