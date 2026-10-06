// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package parity runs the same stat events through the per-event stats
// exporters and through kernel aggregation (statagg), and compares what the
// OTel and Prometheus exporters emit. Steps that move a stat family to
// kernel aggregation use it to show that no exported series changes.
package parity // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/parity"

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// sumTolerance is the relative difference allowed between histogram sums:
// the per-event exporters add float seconds one value at a time, kernel
// aggregation adds integer nanoseconds and converts once.
const sumTolerance = 1e-9

// Setup is the configuration both export paths run with.
type Setup struct {
	Features  export.Features
	Selection attributes.Selection
	// Filters is filters.stats: the per-event path drops the events it
	// rejects, as the pipeline's attribute filter does; the aggregated path
	// hands it to the kernel as the families' decoration.
	Filters     filter.AttributeFamilyConfig
	OTelBuckets export.Buckets
	PromBuckets export.Buckets
	// Exponential exports OTel base-2 exponential histograms and compares
	// Prometheus native histograms, both at the kernel's scale.
	Exponential bool
}

// Kernel is the aggregated side under test: families whose metrics the
// registry names, and how the kernel programs would count an event in them.
type Kernel struct {
	Registry *statagg.Registry
	Families []*statagg.Family
	Record   func(stat *ebpf.Stat)
}

// Run exports events per event and, through the kernel newKernel builds
// (decorate is the families' decoration), aggregated, and requires both to
// emit the same OTLP data points and Prometheus samples: same series and
// attributes, counters, counts and bucket counts exactly, and histogram sums
// within sumTolerance. Timestamps and OTLP min/max, which the kernel does
// not track, are left out.
func Run(t *testing.T, setup Setup, events []*ebpf.Stat, newKernel func(decorate func(*ebpf.Stat) bool) Kernel) {
	t.Helper()
	matchers, err := filter.NewMatcherSet(setup.Filters, nil, nil, ebpf.StatStringGetters)
	require.NoError(t, err)

	var kept []*ebpf.Stat
	for _, e := range events {
		if matchers.Matches(e) {
			kept = append(kept, e)
		}
	}
	perEventOTel, perEventProm := export1(t, setup, nil, kept, nil)

	kernel := newKernel(matchers.Matches)
	for _, e := range events {
		kernel.Record(e)
	}
	aggOTel, aggProm := export1(t, setup, kernel.Registry, nil, kernel.Families)

	require.NotEmpty(t, perEventOTel, "the per-event path exported nothing")
	assert.Equal(t, perEventOTel, aggOTel, "OTLP data points")
	assert.Equal(t, perEventProm, aggProm, "Prometheus samples")
}

// export1 runs the OTel and Prometheus stats exporters, fed with events or
// with the aggregated registry, and returns their normalized output.
func export1(t *testing.T, setup Setup, aggregated *statagg.Registry, events []*ebpf.Stat, families []*statagg.Family) ([]string, []string) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	exports := make(chan pmetric.Metrics, 100)
	sink, err := consumer.NewMetrics(func(_ context.Context, md pmetric.Metrics) error {
		exports <- md
		return nil
	})
	require.NoError(t, err)

	aggregation := otelcfg.HistogramAggregationExplicit
	if setup.Exponential {
		aggregation = otelcfg.HistogramAggregationExponential
	}
	otelMetrics := &otelcfg.MetricsConfig{
		MetricsConsumer:      sink,
		Interval:             20 * time.Millisecond,
		Buckets:              setup.OTelBuckets,
		HistogramAggregation: aggregation,
		ExponentialHistogram: otelcfg.ExponentialHistogramConfig{MaxSize: 160, MaxScale: statagg.DefaultExponentialScale},
		TTL:                  time.Hour,
	}
	common := &perapp.GlobalMetricsConfig{Features: setup.Features}
	selector := func() *attributes.SelectorConfig {
		return &attributes.SelectorConfig{SelectionCfg: setup.Selection}
	}

	input := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(len(events) + 1))
	otelRun, err := otel.StatMetricsExporterProvider(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: otelMetrics}},
		&otel.StatMetricsConfig{Metrics: otelMetrics, CommonCfg: common, SelectorCfg: selector(), Aggregated: aggregated},
		input)(ctx)
	require.NoError(t, err)

	registry := prometheus.NewPedanticRegistry()
	nativeFactor := prom.DefaultNativeHistogramConfig.BucketFactor
	if setup.Exponential {
		// A factor between the kernel scale's own, 2^(2^-scale), and the next
		// coarser scale's: the client picks schema = scale from it.
		nativeFactor = math.Exp2(1.5 * math.Exp2(-float64(statagg.DefaultExponentialScale)))
	}
	promRun, err := prom.StatsPrometheusEndpoint(&global.ContextInfo{}, &prom.StatsPrometheusConfig{
		Config: &prom.PrometheusConfig{
			Registry: registry,
			Buckets:  setup.PromBuckets,
			TTL:      time.Hour,
			NativeHistogram: prom.NativeHistogramConfig{
				BucketFactor: nativeFactor, MaxBucketNumber: 160, MinResetDuration: time.Hour,
			},
		},
		CommonCfg: common, SelectorCfg: selector(), Aggregated: aggregated,
	}, input)(ctx)
	require.NoError(t, err)

	// Every exporter is attached: the families may read their maps.
	for _, f := range families {
		go f.Run(ctx)
	}

	done := make(chan struct{}, 2)
	go func() { otelRun(ctx); done <- struct{}{} }()
	go func() { promRun(ctx); done <- struct{}{} }()
	if len(events) > 0 {
		input.Send(events)
	}
	input.Close()
	for range 2 {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the exporters did not drain their input")
		}
	}

	// The second export after the input drained holds everything.
	var last pmetric.Metrics
	drained := len(exports)
	for i := range drained + 2 {
		select {
		case last = <-exports:
		case <-time.After(10 * time.Second):
			t.Fatalf("no OTel export %d", i)
		}
	}
	mfs, err := registry.Gather()
	require.NoError(t, err)
	return otlpPoints(last), promSamples(mfs, setup.Exponential)
}

// otlpPoints flattens an OTLP export into sorted, comparable lines.
func otlpPoints(md pmetric.Metrics) []string {
	var out []string
	for _, rm := range md.ResourceMetrics().All() {
		res := attrs(rm.Resource().Attributes())
		for _, sm := range rm.ScopeMetrics().All() {
			for _, m := range sm.Metrics().All() {
				head := fmt.Sprintf("%s scope=%s resource=%s unit=%q desc=%q", m.Name(), sm.Scope().Name(), res, m.Unit(), m.Description())
				out = append(out, metricPoints(head, m)...)
			}
		}
	}
	sort.Strings(out)
	return out
}

func metricPoints(head string, m pmetric.Metric) []string {
	var out []string
	switch m.Type() {
	case pmetric.MetricTypeSum:
		s := m.Sum()
		for _, dp := range s.DataPoints().All() {
			out = append(out, fmt.Sprintf("%s sum temporality=%s monotonic=%t %s value=%d",
				head, s.AggregationTemporality(), s.IsMonotonic(), attrs(dp.Attributes()), dp.IntValue()))
		}
	case pmetric.MetricTypeHistogram:
		h := m.Histogram()
		for _, dp := range h.DataPoints().All() {
			out = append(out, fmt.Sprintf("%s histogram temporality=%s %s count=%d bounds=%v buckets=%v sum=%s",
				head, h.AggregationTemporality(), attrs(dp.Attributes()), dp.Count(),
				dp.ExplicitBounds().AsRaw(), dp.BucketCounts().AsRaw(), roundSum(dp.Sum())))
		}
	case pmetric.MetricTypeExponentialHistogram:
		h := m.ExponentialHistogram()
		for _, dp := range h.DataPoints().All() {
			out = append(out, fmt.Sprintf("%s exponential temporality=%s %s count=%d scale=%d zero=%d offset=%d buckets=%v sum=%s",
				head, h.AggregationTemporality(), attrs(dp.Attributes()), dp.Count(), dp.Scale(), dp.ZeroCount(),
				dp.Positive().Offset(), dp.Positive().BucketCounts().AsRaw(), roundSum(dp.Sum())))
		}
	default:
		out = append(out, fmt.Sprintf("%s unexpected type %s", head, m.Type()))
	}
	return out
}

func attrs(m pcommon.Map) string {
	kv := make([]string, 0, m.Len())
	for k, v := range m.All() {
		kv = append(kv, k+"="+v.AsString()+":"+v.Type().String())
	}
	slices.Sort(kv)
	return "{" + strings.Join(kv, ",") + "}"
}

// roundSum keeps the digits of a sum that both paths agree on.
func roundSum(v float64) string {
	if v == 0 {
		return "0"
	}
	digits := int(-math.Floor(math.Log10(sumTolerance)))
	return fmt.Sprintf("%.*g", digits, v)
}

// promSamples flattens gathered Prometheus families into sorted lines:
// classic histograms, or native ones when native is set. The per-event
// histograms carry both; kernel aggregation emits one of them.
func promSamples(mfs []*dto.MetricFamily, native bool) []string {
	var out []string
	for _, mf := range mfs {
		head := fmt.Sprintf("%s type=%s help=%q", mf.GetName(), mf.GetType(), mf.GetHelp())
		for _, m := range mf.GetMetric() {
			labels := make([]string, 0, len(m.GetLabel()))
			for _, l := range m.GetLabel() {
				labels = append(labels, l.GetName()+"="+l.GetValue())
			}
			line := head + " {" + strings.Join(labels, ",") + "}"
			switch mf.GetType() {
			case dto.MetricType_COUNTER:
				line += fmt.Sprintf(" value=%v", m.GetCounter().GetValue())
			case dto.MetricType_GAUGE:
				line += fmt.Sprintf(" value=%v", m.GetGauge().GetValue())
			case dto.MetricType_HISTOGRAM:
				line += histogramSample(m.GetHistogram(), native)
			}
			out = append(out, line)
		}
	}
	sort.Strings(out)
	return out
}

func histogramSample(h *dto.Histogram, native bool) string {
	s := fmt.Sprintf(" count=%d sum=%s", h.GetSampleCount(), roundSum(h.GetSampleSum()))
	if !native {
		for _, b := range h.GetBucket() {
			s += fmt.Sprintf(" le%v=%d", b.GetUpperBound(), b.GetCumulativeCount())
		}
		return s
	}
	s += fmt.Sprintf(" schema=%d zero=%d threshold=%v", h.GetSchema(), h.GetZeroCount(), h.GetZeroThreshold())
	return s + fmt.Sprintf(" buckets=%v", nativeBuckets(h.GetPositiveSpan(), h.GetPositiveDelta()))
}

// nativeBuckets decodes spans and delta-encoded counts into index=count
// pairs, without the empty buckets either encoding may keep.
func nativeBuckets(spans []*dto.BucketSpan, deltas []int64) []string {
	var out []string
	var idx int32
	var count int64
	d := 0
	for _, sp := range spans {
		idx += sp.GetOffset()
		for range sp.GetLength() {
			count += deltas[d]
			d++
			if count != 0 {
				out = append(out, fmt.Sprintf("%d=%d", idx, count))
			}
			idx++
		}
	}
	return out
}
