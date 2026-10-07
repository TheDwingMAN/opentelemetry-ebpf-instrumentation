// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func (tf *testFamily) promCollector(tb testing.TB, bounds []float64, ttl time.Duration) *Collector {
	tb.Helper()
	c := NewCollector(tf.reg, ttl)
	_, proj := devOpLabels(false)
	_, projErr := devOpLabels(true)
	labels := []string{"dev", "op"}
	require.NoError(tb, c.Add(testDuration, PromMetric{Help: "duration", Bounds: bounds, LabelNames: labels, Project: proj}))
	require.NoError(tb, c.Add(testIO, PromMetric{Help: "io", LabelNames: labels, Project: proj}))
	require.NoError(tb, c.Add(testErrors, PromMetric{Help: "errors", LabelNames: []string{"dev", "op", "err"}, Project: projErr}))
	return c
}

func TestCollector_ExplicitGolden(t *testing.T) {
	// OTel and Prometheus with different bounds share one kernel layout.
	promBounds := []float64{0.001, 0.01, 0.1}
	tf := newTestFamily(t, 2, diskBounds, func(c *Config) {
		l, err := NewExplicitLayout(diskBounds, promBounds)
		require.NoError(t, err)
		c.Metrics = testMetrics(l)
		c.Layout.Buckets = l.Buckets()
	})
	c := tf.promCollector(t, promBounds, 0)
	layout := tf.family.cfg.Metrics[0].Layout
	k := blkKey(devA, ebpf.CodeBlockRead, 0)
	record(tf.m, layout, k, 0, 4096, 1_000_000)  // exactly 1ms: le="0.001"
	record(tf.m, layout, k, 1, 4096, 1_000_001)  // just above: le="0.01"
	record(tf.m, layout, k, 1, 512, 200_000_000) // 200ms: +Inf
	record(tf.m, layout, blkKey(devA, ebpf.CodeBlockRead, -5), 0, 0, 50_000)

	const golden = `
# HELP test_duration_seconds duration
# TYPE test_duration_seconds histogram
test_duration_seconds_bucket{dev="264241152",op="0",le="0.001"} 2
test_duration_seconds_bucket{dev="264241152",op="0",le="0.01"} 3
test_duration_seconds_bucket{dev="264241152",op="0",le="0.1"} 3
test_duration_seconds_bucket{dev="264241152",op="0",le="+Inf"} 4
test_duration_seconds_sum{dev="264241152",op="0"} 0.202050001
test_duration_seconds_count{dev="264241152",op="0"} 4
# HELP test_errors_total errors
# TYPE test_errors_total counter
test_errors_total{dev="264241152",err="-5",op="0"} 1
# HELP test_io_bytes_total io
# TYPE test_io_bytes_total counter
test_io_bytes_total{dev="264241152",op="0"} 8704
`
	assert.Equal(t, strings.TrimLeft(golden, "\n"), promText(t, c))
}

func TestCollector_NativeHistogram(t *testing.T) {
	l, err := NewExponentialLayout(DefaultExponentialScale)
	require.NoError(t, err)
	tf := newTestFamilyLayout(t, 1, l, nil)
	c := tf.promCollector(t, nil, 0)
	k := blkKey(devA, ebpf.CodeBlockRead, 0)
	record(tf.m, l, k, 0, 1, 0)
	record(tf.m, l, k, 0, 1, 1_000_000)
	record(tf.m, l, k, 0, 1, 1_000_000)
	record(tf.m, l, k, 0, 1, 4_000_000)

	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(c))
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != "test_duration_seconds" {
			continue
		}
		require.Len(t, mf.Metric, 1)
		dto := mf.Metric[0].GetHistogram()
		assert.Equal(t, int32(2), dto.GetSchema())
		assert.Equal(t, uint64(4), dto.GetSampleCount())
		assert.Equal(t, uint64(1), dto.GetZeroCount())
		assert.InDelta(t, 0.006, dto.GetSampleSum(), 1e-12)
		// Keys -39 (upper bound 2^(-39/4) >= 1ms) and -31, as spans with
		// delta-encoded counts.
		require.Len(t, dto.GetPositiveSpan(), 2)
		assert.Equal(t, int32(-39), dto.GetPositiveSpan()[0].GetOffset())
		assert.Equal(t, uint32(1), dto.GetPositiveSpan()[0].GetLength())
		assert.Equal(t, int32(7), dto.GetPositiveSpan()[1].GetOffset())
		assert.Equal(t, []int64{2, -1}, dto.GetPositiveDelta())
		assert.Empty(t, dto.GetBucket(), "no classic buckets on an exponential layout")
		return
	}
	t.Fatal("no test_duration_seconds family")
}

func TestCollector_ExpiresSeries(t *testing.T) {
	tf := newTestFamily(t, 1, diskBounds, nil)
	c := tf.promCollector(t, diskBounds, 5*time.Second)
	record(tf.m, tf.layout, blkKey(devA, ebpf.CodeBlockRead, 0), 0, 1, 1)
	assert.Contains(t, promText(t, c), "test_io_bytes_total")
	tf.clock.Advance(6 * time.Second)
	assert.NotContains(t, promText(t, c), "test_io_bytes_total")
}

// promText is the text exposition of what the collectors export.
func promText(tb testing.TB, cs ...prometheus.Collector) string {
	tb.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(cs...)
	mfs, err := reg.Gather()
	require.NoError(tb, err)
	var sb strings.Builder
	for _, mf := range mfs {
		_, err := expfmt.MetricFamilyToText(&sb, mf)
		require.NoError(tb, err)
	}
	return sb.String()
}

// levelCounter counts the records a logger emits, by level.
type levelCounter struct {
	mu     sync.Mutex
	counts map[slog.Level]int
}

func (h *levelCounter) Enabled(context.Context, slog.Level) bool { return true }
func (h *levelCounter) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *levelCounter) WithGroup(string) slog.Handler            { return h }

func (h *levelCounter) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.counts[r.Level]++
	return nil
}

func (h *levelCounter) count(l slog.Level) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counts[l]
}

func TestCollector_BuildErrorsWarnOnceInAWhile(t *testing.T) {
	tf := newTestFamily(t, 1, diskBounds, nil)
	c := NewCollector(tf.reg, 0)
	logs := &levelCounter{counts: map[slog.Level]int{}}
	c.log = slog.New(logs)
	// One label name for two label values: the series can't be built.
	_, proj := devOpLabels(false)
	require.NoError(t, c.Add(testIO, PromMetric{Help: "io", LabelNames: []string{"dev"}, Project: proj}))
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	record(tf.m, tf.layout, blkKey(devA, ebpf.CodeBlockRead, 0), 0, 1, 1)
	record(tf.m, tf.layout, blkKey(devB, ebpf.CodeBlockRead, 0), 0, 1, 1)

	gather := func() {
		_, _ = reg.Gather()
		tf.clock.Advance(time.Minute)
	}
	gather()
	assert.Equal(t, 1, logs.count(slog.LevelWarn), "the first error is a warning")
	assert.Equal(t, 1, logs.count(slog.LevelDebug), "the second series of the same scrape is not")
	for range 9 {
		gather()
	}
	assert.Equal(t, 1, logs.count(slog.LevelWarn), "rate-limited")
	assert.Equal(t, 19, logs.count(slog.LevelDebug))
	gather()
	assert.Equal(t, 2, logs.count(slog.LevelWarn), "warned again after 10 minutes")
}
