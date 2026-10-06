// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"time"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// Projection turns a decorated stat into the identity of the series it counts
// in for one exporter: a key that tells series apart and the labels the
// exporter emits (an attribute.Set for OTel, label values for Prometheus). It
// is the same attribute selection the exporter's per-event path applies.
type Projection[L any] func(stat *ebpf.Stat) (key string, labels L)

// seriesCore is the cumulative state of one exported series, kept in kernel
// bucket layout. It is what kernel keys link to and count into.
type seriesCore struct {
	value   uint64
	sumNs   uint64
	buckets []uint64

	start   time.Time
	updated time.Time

	// dead is set once the series expired; the next count revives it as a
	// new series, as the per-event exporters recreate a removed series.
	dead  bool
	owner reviver
}

type reviver interface{ revive(now time.Time) }

func (s *seriesCore) touch(now time.Time) {
	if s.dead {
		s.owner.revive(now)
	}
	s.updated = now
}

// count is the number of values a histogram series counted.
func (s *seriesCore) count() uint64 {
	var n uint64
	for _, b := range s.buckets {
		n += b
	}
	return n
}

// snapshot is what a delta-temporality exporter sent last for a series.
type snapshot struct {
	value   uint64
	sumNs   uint64
	buckets []uint64
	at      time.Time
}

// series is a seriesCore with the labels one exporter emits for it.
type series[L any] struct {
	seriesCore
	key    string
	labels L
	metric *accMetric[L]
	last   *snapshot
}

func (s *series[L]) revive(now time.Time) {
	s.dead = false
	s.value, s.sumNs = 0, 0
	clear(s.buckets)
	s.start = now
	s.last = nil
	s.metric.series[s.key] = s
}

type accMetric[L any] struct {
	def     *Metric
	project Projection[L]
	series  map[string]*series[L]
}

// Accumulator holds the series one exporter emits for the metrics of one
// Family: cumulative counts per series, after projection, fed by the
// family's deltas. All of its methods run with the family locked.
type Accumulator[L any] struct {
	family  *Family
	metrics []*accMetric[L]
}

func newAccumulator[L any](f *Family) *Accumulator[L] {
	return &Accumulator[L]{family: f, metrics: make([]*accMetric[L], len(f.cfg.Metrics))}
}

// export makes the accumulator emit metric i with project.
func (a *Accumulator[L]) export(i int, project Projection[L]) {
	a.metrics[i] = &accMetric[L]{def: a.family.cfg.Metrics[i], project: project, series: map[string]*series[L]{}}
}

func (a *Accumulator[L]) link(i int, stat *ebpf.Stat, now time.Time) *seriesCore {
	m := a.metrics[i]
	if m == nil {
		return nil
	}
	key, labels := m.project(stat)
	if s, ok := m.series[key]; ok {
		return &s.seriesCore
	}
	s := &series[L]{key: key, labels: labels, metric: m}
	s.start, s.updated, s.owner = now, now, s
	if m.def.Kind == KindHistogram {
		s.buckets = make([]uint64, m.def.Layout.Buckets())
	}
	m.series[key] = s
	return &s.seriesCore
}

// expire drops the series nothing counted into for longer than ttl, as the
// per-event exporters' expirers do. A ttl of 0 keeps every series.
func (a *Accumulator[L]) expire(now time.Time, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	for _, m := range a.metrics {
		if m == nil {
			continue
		}
		for key, s := range m.series {
			if now.Sub(s.updated) > ttl {
				s.dead = true
				delete(m.series, key)
			}
		}
	}
}
