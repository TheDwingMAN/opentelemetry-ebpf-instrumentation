// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/export/attributes"
)

// PromMetric is how the Prometheus exporter emits an aggregated metric.
type PromMetric struct {
	Help string
	// Bounds are the exporter's classic bucket bounds; unused by exponential
	// layouts, which are emitted as native histograms.
	Bounds     []float64
	LabelNames []string
	// Project gives the label values of a stat, in LabelNames order, as the
	// exporter's per-event path computes them.
	Project Projection[[]string]
}

// Collector is a Prometheus collector of aggregated metrics: const counters,
// gauges, classic histograms (explicit layouts) and native histograms
// (exponential layouts, schema = scale). An explicit layout gives classic
// buckets only, whatever the exporter's native histogram settings, and an
// exponential one native buckets only; the per-event histograms carry both.
// Add every metric before registering it, since Describe reports what was
// added.
type Collector struct {
	registry *Registry
	ttl      time.Duration
	log      *slog.Logger

	mu       sync.Mutex
	families []*promFamily
	lastWarn time.Time
}

type promFamily struct {
	family *Family
	acc    *Accumulator[[]string]
	out    []*promMetric
}

type promMetric struct {
	desc   *prometheus.Desc
	bounds []float64
	fold   []int
}

// buildErrorWarnInterval is how often a series that can't be built is
// logged at Warn; in between, at Debug.
const buildErrorWarnInterval = 10 * time.Minute

// NewCollector emits the metrics of the registry that Add names; series
// unchanged for ttl are dropped.
func NewCollector(r *Registry, ttl time.Duration) *Collector {
	return &Collector{registry: r, ttl: ttl, log: slog.With("component", "statagg.Collector")}
}

// logBuildError logs a series that can't be built, which the scrape then
// lacks: at Warn the first time and then at most every
// buildErrorWarnInterval, at Debug otherwise. It runs with c.mu held.
func (c *Collector) logBuildError(now time.Time, desc *prometheus.Desc, err error) {
	if c.lastWarn.IsZero() || now.Sub(c.lastWarn) >= buildErrorWarnInterval {
		c.lastWarn = now
		c.log.Warn("can't build an aggregated metric; it is missing from the scrape", "metric", desc, "error", err)
		return
	}
	c.log.Debug("can't build aggregated metric", "metric", desc, "error", err)
}

// Add makes the Collector emit an aggregated metric.
func (c *Collector) Add(name attributes.Name, m PromMetric) error {
	ref, err := c.registry.lookup(name)
	if err != nil {
		return err
	}
	def := ref.family.cfg.Metrics[ref.index]
	out := &promMetric{desc: prometheus.NewDesc(name.Prom, m.Help, m.LabelNames, nil), bounds: m.Bounds}
	if def.Kind == KindHistogram && def.Layout.Kind == LayoutExplicit {
		if out.fold, err = def.Layout.Fold(m.Bounds); err != nil {
			return err
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	pf := c.familyOf(ref.family)
	pf.family.mu.Lock()
	pf.acc.export(ref.index, m.Project)
	pf.family.mu.Unlock()
	pf.out[ref.index] = out
	return nil
}

func (c *Collector) familyOf(f *Family) *promFamily {
	for _, pf := range c.families {
		if pf.family == f {
			return pf
		}
	}
	pf := &promFamily{family: f, acc: newAccumulator[[]string](f), out: make([]*promMetric, len(f.cfg.Metrics))}
	f.attach(pf.acc)
	c.families = append(c.families, pf)
	return pf
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pf := range c.families {
		for _, out := range pf.out {
			if out != nil {
				ch <- out.desc
			}
		}
	}
}

// Collect implements prometheus.Collector: it reads every family's kernel
// map, unless an exporter just did, and sends its series.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pf := range c.families {
		pf.family.collect(func(now time.Time) {
			pf.acc.expire(now, c.ttl)
			for i, out := range pf.out {
				if out == nil {
					continue
				}
				for _, s := range pf.acc.metrics[i].series {
					if !s.counted {
						continue
					}
					m, err := out.metric(pf.acc.metrics[i].def, s)
					if err != nil {
						c.logBuildError(now, out.desc, err)
						continue
					}
					ch <- m
				}
			}
		})
	}
}

func (o *promMetric) metric(def *Metric, s *series[[]string]) (prometheus.Metric, error) {
	switch def.Kind {
	case KindCounter:
		return prometheus.NewConstMetricWithCreatedTimestamp(o.desc, prometheus.CounterValue,
			float64(s.value), s.start, s.labels...)
	case KindUpDownCounter:
		return prometheus.NewConstMetric(o.desc, prometheus.GaugeValue, float64(int64(s.value)), s.labels...)
	}
	sumSeconds := time.Duration(s.sumNs).Seconds()
	if def.Layout.Kind == LayoutExponential {
		return o.native(def.Layout, s, sumSeconds)
	}
	counts := make([]uint64, len(o.bounds)+1)
	for i, n := range s.buckets {
		counts[o.fold[i]] += n
	}
	// Classic buckets are cumulative; the overflow bucket is +Inf, which the
	// client adds from the count.
	cumulative := make(map[float64]uint64, len(o.bounds))
	var below uint64
	for i, b := range o.bounds {
		below += counts[i]
		cumulative[b] = below
	}
	return prometheus.NewConstHistogramWithCreatedTimestamp(o.desc, s.count(), sumSeconds, cumulative, s.start, s.labels...)
}

// native builds a native histogram, whose bucket key k counts values in
// (base^(k-1), base^k]: the OTel index of the same bucket plus one.
func (o *promMetric) native(layout *Layout, s *series[[]string], sumSeconds float64) (prometheus.Metric, error) {
	positive := map[int]int64{}
	for i, n := range s.buckets[1:] {
		if n == 0 {
			continue
		}
		k, _ := layout.ExponentialIndex(i + 1)
		positive[int(k)+1] = int64(n)
	}
	return prometheus.NewConstNativeHistogram(o.desc, s.count(), sumSeconds, positive, nil,
		s.buckets[0], layout.Scale, prometheus.DefNativeHistogramZeroThreshold, s.start, s.labels...)
}
