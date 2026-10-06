// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

var testTime = attributes.Name{Section: "test.time", OTEL: "test.time", Prom: "test_time_seconds_total", Unit: "s"}

// timeFamily is the test family with one more metric: the nanosecond sum
// word exported as a counter of seconds, as obi.stat.disk.operation_time.
func timeFamily(t *testing.T) *testFamily {
	t.Helper()
	return newTestFamily(t, 2, diskBounds, func(c *Config) {
		c.Metrics = append(c.Metrics, &Metric{
			Name: testTime, Kind: KindDurationCounter,
			Value: func(d Delta) uint64 { return d.Counter(wordSumNs) },
		})
	})
}

func TestDurationCounter_OTelSecondsCumulativeAndDelta(t *testing.T) {
	for _, temporality := range []metricdata.Temporality{metricdata.CumulativeTemporality, metricdata.DeltaTemporality} {
		t.Run(temporality.String(), func(t *testing.T) {
			tf := timeFamily(t)
			p := NewProducer(tf.reg, "test", func(sdkmetric.InstrumentKind) metricdata.Temporality { return temporality }, 0)
			proj, _ := devOpLabels(false)
			require.NoError(t, p.Add(testTime, OTelMetric{Project: proj}))

			k := blkKey(devA, ebpf.CodeBlockWrite, 0)
			record(tf.m, tf.layout, k, 0, 4096, 1_500_000)
			record(tf.m, tf.layout, k, 1, 4096, 500_000)
			first := produce(t, p)["test.time"]
			sum := first.Data.(metricdata.Sum[float64])
			assert.True(t, sum.IsMonotonic)
			assert.Equal(t, temporality, sum.Temporality)
			require.Len(t, sum.DataPoints, 1)
			assert.InDelta(t, 0.002, sum.DataPoints[0].Value, 1e-12, "1.5 ms + 0.5 ms on two CPUs")
			assert.Equal(t, "s", first.Unit)

			tf.clock.Advance(time.Second)
			record(tf.m, tf.layout, k, 0, 4096, 3_000_000)
			second := produce(t, p)["test.time"].Data.(metricdata.Sum[float64])
			want := 0.005
			if temporality == metricdata.DeltaTemporality {
				want = 0.003
			}
			assert.InDelta(t, want, second.DataPoints[0].Value, 1e-12)
		})
	}
}

func TestDurationCounter_PrometheusCounterInSeconds(t *testing.T) {
	tf := timeFamily(t)
	c := NewCollector(tf.reg, 0)
	_, proj := devOpLabels(false)
	require.NoError(t, c.Add(testTime, PromMetric{Help: "time", LabelNames: []string{"dev", "op"}, Project: proj}))

	k := blkKey(devA, ebpf.CodeBlockRead, 0)
	record(tf.m, tf.layout, k, 0, 512, 250_000_000)
	record(tf.m, tf.layout, k, 1, 512, 1_000_000_000)

	const golden = `
# HELP test_time_seconds_total time
# TYPE test_time_seconds_total counter
test_time_seconds_total{dev="264241152",op="0"} 1.25
`
	assert.Equal(t, strings.TrimLeft(golden, "\n"), promText(t, c))
}

func TestDurationCounter_NeedsAValue(t *testing.T) {
	_, err := NewFamily(Config{
		Name: "test", Source: newFakeMap(testKeySize, 8, 1), Layout: ValueLayout{Counters: 1}, Stat: blkStat,
		Metrics: []*Metric{{Name: testTime, Kind: KindDurationCounter}},
	})
	require.Error(t, err)
}
