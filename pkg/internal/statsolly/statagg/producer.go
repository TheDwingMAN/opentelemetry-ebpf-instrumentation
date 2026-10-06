// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/attributes"
)

// OTelMetric is how the OTel exporter emits an aggregated metric.
type OTelMetric struct {
	Description string
	// Bounds are the exporter's explicit bucket bounds, the ones of its
	// View; unused by exponential layouts.
	Bounds []float64
	// Project gives the attribute set of a stat, omitting what the
	// exporter's per-event path omits.
	Project Projection[attribute.Set]
}

// Producer is an OTel metric Producer that emits aggregated metrics on the
// stats PeriodicReader, next to the per-event instruments. An SDK instrument
// cannot take "N more values in this bucket", which is all a kernel histogram
// provides, hence a Producer. Histograms carry no min and max: the kernel
// does not track them.
type Producer struct {
	registry    *Registry
	scope       instrumentation.Scope
	temporality func(sdkmetric.InstrumentKind) metricdata.Temporality
	ttl         time.Duration

	mu       sync.Mutex
	families []*otelFamily
}

type otelFamily struct {
	family *Family
	acc    *Accumulator[attribute.Set]
	out    []*otelMetric
}

type otelMetric struct {
	name        attributes.Name
	description string
	bounds      []float64
	fold        []int
	temporality metricdata.Temporality
}

// NewProducer emits, under the instrumentation scope, the metrics of the
// registry that Add names. temporality is the exporter's choice per
// instrument kind; series unchanged for ttl are dropped.
func NewProducer(r *Registry, scope string,
	temporality func(sdkmetric.InstrumentKind) metricdata.Temporality, ttl time.Duration,
) *Producer {
	return &Producer{
		registry:    r,
		scope:       instrumentation.Scope{Name: scope},
		temporality: temporality,
		ttl:         ttl,
	}
}

// Add makes the Producer emit an aggregated metric.
func (p *Producer) Add(name attributes.Name, m OTelMetric) error {
	ref, err := p.registry.lookup(name)
	if err != nil {
		return err
	}
	def := ref.family.cfg.Metrics[ref.index]
	out := &otelMetric{name: name, description: m.Description, bounds: m.Bounds, temporality: p.temporality(instrumentKind(def.Kind))}
	if def.Kind == KindHistogram && def.Layout.Kind == LayoutExplicit {
		if out.fold, err = def.Layout.Fold(m.Bounds); err != nil {
			return err
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	of := p.familyOf(ref.family)
	of.family.mu.Lock()
	of.acc.export(ref.index, m.Project)
	of.family.mu.Unlock()
	of.out[ref.index] = out
	return nil
}

func (p *Producer) familyOf(f *Family) *otelFamily {
	for _, of := range p.families {
		if of.family == f {
			return of
		}
	}
	of := &otelFamily{family: f, acc: newAccumulator[attribute.Set](f), out: make([]*otelMetric, len(f.cfg.Metrics))}
	f.attach(of.acc)
	p.families = append(p.families, of)
	return of
}

func instrumentKind(k Kind) sdkmetric.InstrumentKind {
	switch k {
	case KindUpDownCounter:
		return sdkmetric.InstrumentKindUpDownCounter
	case KindHistogram:
		return sdkmetric.InstrumentKindHistogram
	default:
		return sdkmetric.InstrumentKindCounter
	}
}

// Produce reads every family's kernel map, unless an exporter just did, and
// returns its series.
func (p *Producer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	var metrics []metricdata.Metrics
	for _, of := range p.families {
		of.family.collect(func(now time.Time) {
			of.acc.expire(now, p.ttl)
			for i, out := range of.out {
				if out == nil {
					continue
				}
				if m, ok := out.produce(of.acc.metrics[i], now); ok {
					metrics = append(metrics, m)
				}
			}
		})
	}
	if len(metrics) == 0 {
		return nil, nil
	}
	return []metricdata.ScopeMetrics{{Scope: p.scope, Metrics: metrics}}, nil
}

func (o *otelMetric) produce(m *accMetric[attribute.Set], now time.Time) (metricdata.Metrics, bool) {
	var data metricdata.Aggregation
	switch {
	case m.def.Kind == KindHistogram && m.def.Layout.Kind == LayoutExponential:
		data, _ = o.exponential(m, now)
	case m.def.Kind == KindHistogram:
		data, _ = o.histogram(m, now)
	case m.def.Kind == KindDurationCounter:
		data, _ = o.seconds(m, now)
	default:
		data, _ = o.sum(m, now)
	}
	if data == nil {
		return metricdata.Metrics{}, false
	}
	return metricdata.Metrics{Name: o.name.OTEL, Description: o.description, Unit: o.name.Unit, Data: data}, true
}

// emitted returns what a series adds to this export: all of it for
// cumulative temporality; for delta, what it counted since the last export,
// and ok=false when nothing counted into it since.
func (o *otelMetric) emitted(s *series[attribute.Set], now time.Time) (e snapshot, start time.Time, ok bool) {
	if !s.counted {
		return snapshot{}, time.Time{}, false
	}
	e = snapshot{value: s.value, sumNs: s.sumNs, buckets: s.buckets}
	if o.temporality != metricdata.DeltaTemporality {
		return e, s.start, true
	}
	last, start := s.last, s.start
	if last == nil {
		last = &snapshot{buckets: make([]uint64, len(s.buckets))}
		s.last = last
	} else {
		if !s.updated.After(last.at) {
			return e, time.Time{}, false
		}
		start = last.at
	}
	d := snapshot{value: s.value - last.value, sumNs: s.sumNs - last.sumNs, buckets: make([]uint64, len(s.buckets))}
	for i := range s.buckets {
		d.buckets[i] = s.buckets[i] - last.buckets[i]
	}
	last.value, last.sumNs, last.at = s.value, s.sumNs, now
	copy(last.buckets, s.buckets)
	return d, start, true
}

func sum(b []uint64) uint64 {
	var n uint64
	for _, v := range b {
		n += v
	}
	return n
}

func (o *otelMetric) sum(m *accMetric[attribute.Set], now time.Time) (metricdata.Aggregation, bool) {
	points := make([]metricdata.DataPoint[int64], 0, len(m.series))
	for _, s := range m.series {
		e, start, ok := o.emitted(s, now)
		if !ok {
			continue
		}
		points = append(points, metricdata.DataPoint[int64]{
			Attributes: s.labels, StartTime: start, Time: now, Value: int64(e.value),
		})
	}
	if len(points) == 0 {
		return nil, false
	}
	return metricdata.Sum[int64]{
		DataPoints:  points,
		Temporality: o.temporality,
		IsMonotonic: m.def.Kind == KindCounter,
	}, true
}

// seconds emits a KindDurationCounter, whose series count nanoseconds.
func (o *otelMetric) seconds(m *accMetric[attribute.Set], now time.Time) (metricdata.Aggregation, bool) {
	points := make([]metricdata.DataPoint[float64], 0, len(m.series))
	for _, s := range m.series {
		e, start, ok := o.emitted(s, now)
		if !ok {
			continue
		}
		points = append(points, metricdata.DataPoint[float64]{
			Attributes: s.labels, StartTime: start, Time: now, Value: time.Duration(e.value).Seconds(),
		})
	}
	if len(points) == 0 {
		return nil, false
	}
	return metricdata.Sum[float64]{DataPoints: points, Temporality: o.temporality, IsMonotonic: true}, true
}

func (o *otelMetric) histogram(m *accMetric[attribute.Set], now time.Time) (metricdata.Aggregation, bool) {
	points := make([]metricdata.HistogramDataPoint[float64], 0, len(m.series))
	for _, s := range m.series {
		e, start, ok := o.emitted(s, now)
		if !ok {
			continue
		}
		counts := make([]uint64, len(o.bounds)+1)
		for i, n := range e.buckets {
			counts[o.fold[i]] += n
		}
		points = append(points, metricdata.HistogramDataPoint[float64]{
			Attributes:   s.labels,
			StartTime:    start,
			Time:         now,
			Count:        sum(e.buckets),
			Bounds:       o.bounds,
			BucketCounts: counts,
			Sum:          time.Duration(e.sumNs).Seconds(),
		})
	}
	if len(points) == 0 {
		return nil, false
	}
	return metricdata.Histogram[float64]{DataPoints: points, Temporality: o.temporality}, true
}

func (o *otelMetric) exponential(m *accMetric[attribute.Set], now time.Time) (metricdata.Aggregation, bool) {
	layout := m.def.Layout
	points := make([]metricdata.ExponentialHistogramDataPoint[float64], 0, len(m.series))
	for _, s := range m.series {
		e, start, ok := o.emitted(s, now)
		if !ok {
			continue
		}
		p := metricdata.ExponentialHistogramDataPoint[float64]{
			Attributes: s.labels,
			StartTime:  start,
			Time:       now,
			Count:      sum(e.buckets),
			Sum:        time.Duration(e.sumNs).Seconds(),
			Scale:      layout.Scale,
			ZeroCount:  e.buckets[0],
		}
		if first, last, ok := populated(e.buckets[1:]); ok {
			p.PositiveBucket.Offset, _ = layout.ExponentialIndex(first + 1)
			p.PositiveBucket.Counts = append([]uint64(nil), e.buckets[first+1:last+2]...)
		}
		points = append(points, p)
	}
	if len(points) == 0 {
		return nil, false
	}
	return metricdata.ExponentialHistogram[float64]{DataPoints: points, Temporality: o.temporality}, true
}

// populated returns the first and last non-zero entries of b.
func populated(b []uint64) (first, last int, ok bool) {
	first, last = -1, -1
	for i, n := range b {
		if n == 0 {
			continue
		}
		if first < 0 {
			first = i
		}
		last = i
	}
	return first, last, first >= 0
}
