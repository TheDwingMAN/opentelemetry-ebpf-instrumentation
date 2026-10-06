// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg

import (
	"context"
	"encoding/binary"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

var diskBounds = []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0}

const (
	devA = 252 << 20
	devB = 252<<20 | 16
)

func cumulative(sdkmetric.InstrumentKind) metricdata.Temporality {
	return metricdata.CumulativeTemporality
}

func delta(sdkmetric.InstrumentKind) metricdata.Temporality { return metricdata.DeltaTemporality }

// otelProducer exports every test metric; errors keep the err label.
func (tf *testFamily) otelProducer(tb testing.TB, temporality func(sdkmetric.InstrumentKind) metricdata.Temporality, ttl time.Duration) *Producer {
	tb.Helper()
	p := NewProducer(tf.reg, "test", temporality, ttl)
	proj, _ := devOpLabels(false)
	projErr, _ := devOpLabels(true)
	require.NoError(tb, p.Add(testDuration, OTelMetric{Bounds: diskBounds, Project: proj}))
	require.NoError(tb, p.Add(testIO, OTelMetric{Project: proj}))
	require.NoError(tb, p.Add(testErrors, OTelMetric{Project: projErr}))
	return p
}

func produce(tb testing.TB, p *Producer) map[string]metricdata.Metrics {
	tb.Helper()
	sm, err := p.Produce(context.Background())
	require.NoError(tb, err)
	out := map[string]metricdata.Metrics{}
	for _, s := range sm {
		for _, m := range s.Metrics {
			out[m.Name] = m
		}
	}
	return out
}

func sumValue(tb testing.TB, m metricdata.Metrics, attrs ...attribute.KeyValue) int64 {
	tb.Helper()
	want := attribute.NewSet(attrs...)
	for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
		if dp.Attributes.Equals(&want) {
			return dp.Value
		}
	}
	tb.Fatalf("no data point %v in %s", want.ToSlice(), m.Name)
	return 0
}

func histPoint(tb testing.TB, m metricdata.Metrics, attrs ...attribute.KeyValue) metricdata.HistogramDataPoint[float64] {
	tb.Helper()
	want := attribute.NewSet(attrs...)
	for _, dp := range m.Data.(metricdata.Histogram[float64]).DataPoints {
		if dp.Attributes.Equals(&want) {
			return dp
		}
	}
	tb.Fatalf("no data point %v in %s", want.ToSlice(), m.Name)
	return metricdata.HistogramDataPoint[float64]{}
}

func devAOp(op ebpf.BlockOpCode) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("dev", strconv.Itoa(devA)), attribute.String("op", strconv.Itoa(int(op))),
	}
}

func TestFamily_KeysMergeIntoTheExportedSeries(t *testing.T) {
	tf := newTestFamily(t, 2, diskBounds, nil)
	p := tf.otelProducer(t, cumulative, 0)

	ok := blkKey(devA, ebpf.CodeBlockRead, 0)
	eio := blkKey(devA, ebpf.CodeBlockRead, -5)
	flush := blkKey(devA, ebpf.CodeBlockFlush, 0)
	record(tf.m, tf.layout, ok, 0, 4096, 150_000)   // 150us
	record(tf.m, tf.layout, ok, 1, 4096, 150_000)   // same bucket, other CPU
	record(tf.m, tf.layout, eio, 1, 512, 3_000_000) // 3ms, failed
	record(tf.m, tf.layout, flush, 0, 0, 1_000_000)

	got := produce(t, p)
	dur := histPoint(t, got["test.duration"], devAOp(ebpf.CodeBlockRead)...)
	assert.Equal(t, uint64(3), dur.Count, "both keys of the read series")
	assert.InDelta(t, 0.0033, dur.Sum, 1e-12)
	assert.Equal(t, diskBounds, dur.Bounds)
	assert.Equal(t, uint64(2), dur.BucketCounts[1], "150us is in (100us, 250us]")
	assert.Equal(t, uint64(1), dur.BucketCounts[5], "3ms is in (2.5ms, 5ms]")
	var bucketSum uint64
	for _, n := range dur.BucketCounts {
		bucketSum += n
	}
	assert.Equal(t, dur.Count, bucketSum, "count == sum(buckets)")

	assert.Equal(t, int64(4096*2+512), sumValue(t, got["test.io"], devAOp(ebpf.CodeBlockRead)...))
	assert.Equal(t, int64(1), sumValue(t, got["test.errors"],
		append(devAOp(ebpf.CodeBlockRead), attribute.String("err", "-5"))...))
	assert.Len(t, got["test.errors"].Data.(metricdata.Sum[int64]).DataPoints, 1, "only failed requests count as errors")
	assert.Len(t, got["test.duration"].Data.(metricdata.Histogram[float64]).DataPoints, 1, "flushes select no read/write metric")
}

func TestFamily_DecorateDropsKeysLikeTheFilter(t *testing.T) {
	var decorated atomic.Int32
	tf := newTestFamily(t, 1, diskBounds, func(c *Config) {
		c.Decorate = func(s *ebpf.Stat) bool {
			decorated.Add(1)
			return s.BlockIo.Dev != devB
		}
	})
	p := tf.otelProducer(t, cumulative, 0)
	record(tf.m, tf.layout, blkKey(devA, ebpf.CodeBlockWrite, 0), 0, 8192, 50_000)
	record(tf.m, tf.layout, blkKey(devB, ebpf.CodeBlockWrite, 0), 0, 8192, 50_000)

	got := produce(t, p)
	points := got["test.io"].Data.(metricdata.Sum[int64]).DataPoints
	require.Len(t, points, 1)
	assert.Equal(t, int64(8192), sumValue(t, got["test.io"], devAOp(ebpf.CodeBlockWrite)...))
	assert.Equal(t, int32(2), decorated.Load())

	// A final decoration is reused while the key keeps counting.
	tf.clock.Advance(time.Second)
	record(tf.m, tf.layout, blkKey(devA, ebpf.CodeBlockWrite, 0), 0, 8192, 50_000)
	produce(t, p)
	assert.Equal(t, int32(2), decorated.Load())

	// ...until it is older than RedecorateAfter.
	tf.clock.Advance(DefaultRedecorateAfter)
	record(tf.m, tf.layout, blkKey(devA, ebpf.CodeBlockWrite, 0), 0, 8192, 50_000)
	got = produce(t, p)
	assert.Equal(t, int32(3), decorated.Load())
	assert.Equal(t, int64(3*8192), sumValue(t, got["test.io"], devAOp(ebpf.CodeBlockWrite)...))
}

func TestFamily_NonFinalDecorationIsRetried(t *testing.T) {
	var calls int
	tf := newTestFamily(t, 1, diskBounds, func(c *Config) {
		c.Stat = func(key, values []byte) (*ebpf.Stat, bool) {
			calls++
			s, _ := blkStat(key, values)
			return s, calls > 1
		}
	})
	p := tf.otelProducer(t, cumulative, 0)
	k := blkKey(devA, ebpf.CodeBlockRead, 0)
	record(tf.m, tf.layout, k, 0, 1, 1)
	produce(t, p)
	record(tf.m, tf.layout, k, 0, 1, 1)
	tf.clock.Advance(time.Second)
	produce(t, p)
	record(tf.m, tf.layout, k, 0, 1, 1)
	tf.clock.Advance(time.Second)
	produce(t, p)
	assert.Equal(t, 2, calls, "decorated again once, then reused")
}

func TestFamily_IdleKeysAreDeletedWithoutLosingCounts(t *testing.T) {
	tf := newTestFamily(t, 2, diskBounds, nil)
	p := tf.otelProducer(t, cumulative, 0)
	k := blkKey(devA, ebpf.CodeBlockRead, 0)
	record(tf.m, tf.layout, k, 0, 100, 1000)
	produce(t, p)

	// Collections every second poll the map many times within the idle
	// time: the key stays.
	idleAfter := DefaultIdleAfter(DefaultTickInterval)
	for range idleAfter/time.Second - 1 {
		tf.clock.Advance(time.Second)
		produce(t, p)
	}
	assert.Len(t, tf.m.entries, 1, "idle for less than two ticks: kept, however many polls")

	tf.clock.Advance(time.Second)
	produce(t, p)
	assert.Empty(t, tf.m.entries, "idle for two ticks: deleted from the kernel map")

	// The kernel creates the key again.
	record(tf.m, tf.layout, k, 1, 50, 1000)
	tf.clock.Advance(time.Second)
	got := produce(t, p)
	assert.Equal(t, int64(150), sumValue(t, got["test.io"], devAOp(ebpf.CodeBlockRead)...), "totals survive the deletion")
	assert.Equal(t, uint64(2), histPoint(t, got["test.duration"], devAOp(ebpf.CodeBlockRead)...).Count)
}

// A key that counts once per background tick is never idle for two ticks:
// it is not deleted and decorated again every time it comes back.
func TestFamily_KeysCountingEveryTickStay(t *testing.T) {
	var decorated int
	tf := newTestFamily(t, 1, diskBounds, func(c *Config) {
		c.RedecorateAfter = time.Hour
		c.Decorate = func(*ebpf.Stat) bool { decorated++; return true }
	})
	p := tf.otelProducer(t, cumulative, 0)
	k := blkKey(devA, ebpf.CodeBlockRead, 0)
	for range 10 {
		record(tf.m, tf.layout, k, 0, 1, 1000)
		for range DefaultTickInterval / (5 * time.Second) {
			produce(t, p)
			tf.clock.Advance(5 * time.Second)
		}
	}
	assert.Len(t, tf.m.entries, 1)
	assert.Equal(t, 1, decorated)
}

func TestFamily_DeletionsAreCappedPerPoll(t *testing.T) {
	tf := newTestFamily(t, 1, diskBounds, nil)
	p := tf.otelProducer(t, cumulative, 0)
	const keys = DefaultMaxDeletesPerPoll + 6
	for i := range keys {
		record(tf.m, tf.layout, blkKey(uint32(i), ebpf.CodeBlockRead, 0), 0, 1, 1000)
	}
	produce(t, p)

	tf.clock.Advance(DefaultIdleAfter(DefaultTickInterval))
	produce(t, p)
	assert.Len(t, tf.m.entries, keys-DefaultMaxDeletesPerPoll, "one poll deletes at most the cap")
	tf.clock.Advance(time.Second)
	produce(t, p)
	assert.Empty(t, tf.m.entries, "the next poll deletes the rest")
	got := produce(t, p)
	assert.Len(t, got["test.io"].Data.(metricdata.Sum[int64]).DataPoints, keys, "no count lost")
}

func TestFamily_DeletableKeepsKeys(t *testing.T) {
	var asked []uint32
	tf := newTestFamily(t, 1, diskBounds, func(c *Config) {
		c.IdleAfter = 2 * time.Second
		c.Deletable = func(key []byte) bool {
			asked = append(asked, binary.NativeEndian.Uint32(key))
			// devB is "tombstoned": never deleted.
			return binary.NativeEndian.Uint32(key) != devB
		}
	})
	p := tf.otelProducer(t, cumulative, 0)
	record(tf.m, tf.layout, blkKey(devA, ebpf.CodeBlockRead, 0), 0, 1, 1)
	record(tf.m, tf.layout, blkKey(devB, ebpf.CodeBlockRead, 0), 0, 1, 1)
	produce(t, p)
	tf.clock.Advance(time.Second)
	produce(t, p)
	assert.Empty(t, asked, "not idle long enough: Deletable is not asked")
	for range 3 {
		tf.clock.Advance(time.Second)
		produce(t, p)
	}
	assert.Len(t, tf.m.entries, 1)
	assert.Contains(t, tf.m.entries, string(blkKey(devB, ebpf.CodeBlockRead, 0)))
	assert.Contains(t, asked, uint32(devA))
}

func TestFamily_ExpiredSeriesComeBackFromZero(t *testing.T) {
	tf := newTestFamily(t, 1, diskBounds, nil)
	p := tf.otelProducer(t, cumulative, 5*time.Second)
	k := blkKey(devA, ebpf.CodeBlockRead, 0)
	record(tf.m, tf.layout, k, 0, 100, 1000)
	produce(t, p)

	tf.clock.Advance(6 * time.Second)
	got := produce(t, p)
	assert.NotContains(t, got, "test.io", "no update for longer than the TTL")

	record(tf.m, tf.layout, k, 0, 7, 1000)
	tf.clock.Advance(time.Second)
	got = produce(t, p)
	assert.Equal(t, int64(7), sumValue(t, got["test.io"], devAOp(ebpf.CodeBlockRead)...),
		"a new series, as the per-event exporter recreates a removed one")
}

// With a TTL shorter than RedecorateAfter, a key can still be linked to an
// expired series when another key of the same labels creates its
// replacement: both must count into the exported one.
func TestFamily_ExpiredSeriesDoesNotReplaceItsSuccessor(t *testing.T) {
	tf := newTestFamily(t, 1, diskBounds, nil)
	p := tf.otelProducer(t, cumulative, 5*time.Second)
	// Both keys project to the same test.io series (no err label); the
	// newer one comes first in the map.
	older := blkKey(devA, ebpf.CodeBlockRead, -5)
	newer := blkKey(devA, ebpf.CodeBlockRead, 0)
	record(tf.m, tf.layout, older, 0, 100, 1000)
	produce(t, p)
	tf.clock.Advance(6 * time.Second)
	assert.NotContains(t, produce(t, p), "test.io", "expired")

	record(tf.m, tf.layout, newer, 0, 7, 1000)
	record(tf.m, tf.layout, older, 0, 3, 1000)
	tf.clock.Advance(time.Second)
	got := produce(t, p)
	assert.Equal(t, int64(10), sumValue(t, got["test.io"], devAOp(ebpf.CodeBlockRead)...),
		"the older key counts into the series the newer one created")

	record(tf.m, tf.layout, older, 0, 1, 1000)
	tf.clock.Advance(time.Second)
	got = produce(t, p)
	assert.Equal(t, int64(11), sumValue(t, got["test.io"], devAOp(ebpf.CodeBlockRead)...))
}

func TestFamily_AttachingAnExporterLater(t *testing.T) {
	tf := newTestFamily(t, 1, diskBounds, nil)
	first := tf.otelProducer(t, cumulative, 0)
	k := blkKey(devA, ebpf.CodeBlockRead, 0)
	record(tf.m, tf.layout, k, 0, 100, 1000)
	produce(t, first)

	second := tf.otelProducer(t, cumulative, 0)
	record(tf.m, tf.layout, k, 0, 5, 1000)
	tf.clock.Advance(time.Second)
	assert.Equal(t, int64(105), sumValue(t, produce(t, first)["test.io"], devAOp(ebpf.CodeBlockRead)...))
	assert.Equal(t, int64(5), sumValue(t, produce(t, second)["test.io"], devAOp(ebpf.CodeBlockRead)...),
		"counts from its attachment on")
}

func TestFamily_ReadsNothingBeforeRun(t *testing.T) {
	tf := newTestFamily(t, 1, diskBounds, nil)
	f, err := NewFamily(tf.family.cfg)
	require.NoError(t, err)
	reg, err := NewRegistry(f)
	require.NoError(t, err)
	tf.family, tf.reg = f, reg

	first := tf.otelProducer(t, cumulative, 0)
	k := blkKey(devA, ebpf.CodeBlockRead, 0)
	record(tf.m, tf.layout, k, 0, 100, 1000)
	assert.Empty(t, produce(t, first), "not running: the map is not read")

	second := tf.otelProducer(t, cumulative, 0)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	f.Run(ctx)
	tf.clock.Advance(time.Second)
	for _, p := range []*Producer{first, second} {
		assert.Equal(t, int64(100), sumValue(t, produce(t, p)["test.io"], devAOp(ebpf.CodeBlockRead)...),
			"every exporter attached before Run sees every count")
	}
}

func TestFamily_ValidatesMetrics(t *testing.T) {
	l, err := NewExplicitLayout(diskBounds)
	require.NoError(t, err)
	base := Config{
		Source: newFakeMap(testKeySize, testStride(l), 1), Stat: blkStat,
		Layout: ValueLayout{Counters: testWords, Buckets: l.Buckets()},
	}

	cfg := base
	cfg.Metrics = []*Metric{{Name: testIO, Kind: KindCounter}}
	_, err = NewFamily(cfg)
	require.Error(t, err, "counter without Value")

	cfg = base
	cfg.Metrics = []*Metric{{Name: testDuration, Kind: KindHistogram, Layout: l, SumWord: 1, BucketWord: 3}}
	_, err = NewFamily(cfg)
	require.Error(t, err, "buckets past the value layout")

	cfg = base
	_, err = NewFamily(Config{Source: cfg.Source})
	require.Error(t, err, "no Stat")

	f1, err := NewFamily(Config{Source: base.Source, Stat: blkStat, Layout: base.Layout, Metrics: testMetrics(l)})
	require.NoError(t, err)
	f2, err := NewFamily(Config{Source: base.Source, Stat: blkStat, Layout: base.Layout, Metrics: testMetrics(l)})
	require.NoError(t, err)
	_, err = NewRegistry(f1, f2)
	require.Error(t, err, "a metric from two families")

	var nilRegistry *Registry
	assert.False(t, nilRegistry.Handles(testIO))
}

// Prometheus scrapes, OTel collections, the background tick and the kernel
// all run at once: every value the kernel counted is exported once, by each
// exporter, and the race detector sees no shared state.
func TestFamily_ConcurrentScrapeAndCollect(t *testing.T) {
	tf := newTestFamily(t, 4, diskBounds, func(c *Config) {
		c.Clock = time.Now
		c.TickInterval = time.Millisecond
		c.MinPollInterval = time.Nanosecond
	})
	p := tf.otelProducer(t, cumulative, 0)
	c := NewCollector(tf.reg, 0)
	_, promProj := devOpLabels(false)
	require.NoError(t, c.Add(testIO, PromMetric{Help: "io", LabelNames: []string{"dev", "op"}, Project: promProj}))
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); tf.family.Run(ctx) }()
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			_, _ = p.Produce(ctx)
		}
	}()
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			_, _ = reg.Gather()
		}
	}()

	const writes = 2000
	k := blkKey(devA, ebpf.CodeBlockWrite, 0)
	for i := range writes {
		record(tf.m, tf.layout, k, i%4, 3, 20_000)
	}
	cancel()
	wg.Wait()

	got := produce(t, p)
	assert.Equal(t, int64(3*writes), sumValue(t, got["test.io"], devAOp(ebpf.CodeBlockWrite)...))
	mfs, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, mfs, 1)
	assert.InDelta(t, float64(3*writes), mfs[0].Metric[0].GetCounter().GetValue(), 0)
}
