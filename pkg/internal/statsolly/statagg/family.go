// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// Defaults of a Family's Config.
const (
	// DefaultMinPollInterval bounds how often exporter collections read the
	// kernel map: a Prometheus scrape right after an OTel collection reuses
	// what the collection read.
	DefaultMinPollInterval = time.Second
	// DefaultTickInterval is the background poll, which keeps u32 bucket
	// deltas wrap-safe and deletes idle keys when no exporter collects.
	DefaultTickInterval = 30 * time.Second
	// DefaultRedecorateAfter is how long the decoration of a key that keeps
	// counting is reused before the pipeline decorators run on it again, so
	// Kubernetes metadata that changes reaches its series.
	DefaultRedecorateAfter = 30 * time.Second
	// DefaultIdlePolls is how many polls in a row a key must count nothing
	// before it is deleted from the kernel map.
	DefaultIdlePolls = 2
)

// Kind is the instrument a Metric is exported as.
type Kind uint8

const (
	// KindCounter is a monotonic sum: OTel Sum[int64], Prometheus counter.
	KindCounter Kind = iota
	// KindUpDownCounter is a sum that can go down: OTel non-monotonic
	// Sum[int64], Prometheus gauge. Its Value is two's complement.
	KindUpDownCounter
	// KindHistogram is a duration histogram in seconds, from a nanosecond
	// sum word and kernel buckets.
	KindHistogram
)

// Metric is how a metric is read from the keys of a kernel map.
type Metric struct {
	Name attributes.Name
	Kind Kind

	// Select reports whether the counts of a key, decorated as stat, feed
	// this metric, like the per-event exporters' condition on a stat (e.g.
	// reads and writes only). Nil selects every key.
	Select func(stat *ebpf.Stat) bool

	// Value is what a counter adds for a key's Delta.
	Value func(d Delta) uint64
	// SkipZero leaves a series untouched when Value is 0, for counters whose
	// per-event exporter skips events that add 0.
	SkipZero bool

	// SumWord is the Delta word of a histogram's sum, in nanoseconds;
	// BucketWord its first bucket word, Layout its kernel buckets.
	SumWord    int
	BucketWord int
	Layout     *Layout
}

func (m *Metric) validate(layout ValueLayout) error {
	words := layout.Counters + layout.Buckets
	switch m.Kind {
	case KindCounter, KindUpDownCounter:
		if m.Value == nil {
			return fmt.Errorf("metric %s: a counter needs a Value", m.Name.OTEL)
		}
	case KindHistogram:
		if m.Layout == nil {
			return fmt.Errorf("metric %s: a histogram needs a Layout", m.Name.OTEL)
		}
		if m.SumWord >= layout.Counters || m.BucketWord+m.Layout.Buckets() > words {
			return fmt.Errorf("metric %s: histogram words outside the value layout", m.Name.OTEL)
		}
	default:
		return fmt.Errorf("metric %s: unknown kind %d", m.Name.OTEL, m.Kind)
	}
	return nil
}

// Config of a Family.
type Config struct {
	// Name identifies the family in logs, e.g. "blk_agg".
	Name   string
	Source Source
	Layout ValueLayout

	// Stat turns a kernel key, and its values, into the stat the per-event
	// path would have seen for its events, before the pipeline decorators.
	// A key with no stat (nil) counts for no metric. final=false asks for
	// the key to be decorated again the next time it counts something, for
	// a stat that lacks something that may come later (a cgroup the index
	// does not know yet).
	Stat func(key, values []byte) (stat *ebpf.Stat, final bool)

	// Decorate runs the stats pipeline decorators and filters on a stat
	// (Kubernetes metadata, filters.stats, the dynamic PID selector), the
	// same functions the per-event pipeline runs. A key whose stat it drops
	// counts for no metric. Nil keeps every stat undecorated.
	Decorate func(stat *ebpf.Stat) bool

	// Deletable reports whether a key the reader found unchanged for idle
	// polls in a row may be deleted from the kernel map. Nil deletes it
	// after DefaultIdlePolls. Neither Stat nor Deletable may keep key after
	// returning.
	Deletable func(key []byte, idle int) bool

	Metrics []*Metric

	MinPollInterval time.Duration
	TickInterval    time.Duration
	RedecorateAfter time.Duration
	Clock           func() time.Time
}

// sink is one exporter's view of a Family's metrics.
type sink interface {
	// link returns the series of metric i for a decorated stat, or nil when
	// the exporter does not export metric i.
	link(i int, stat *ebpf.Stat, now time.Time) *seriesCore
}

// decoration is a Family's state of a kernel key.
type decoration struct {
	decorated time.Time
	final     bool
	// links holds, per sink and metric, the series the key counts into,
	// resolved when it was last decorated with sinkGen sinks.
	links   [][]*seriesCore
	sinkGen int
}

// Family reads one kernel aggregation map and feeds its deltas to the
// accumulators of every exporter that exports its metrics. One mutex covers
// reading, decorating, accumulating and exporting, so a Prometheus scrape and
// an OTel collection never split one delta between them.
type Family struct {
	cfg    Config
	reader *Reader
	log    *slog.Logger

	mu    sync.Mutex
	sinks []sink
	// started is set by Run: until then exporters collect without reading
	// the map, so every exporter attached before Run sees every delta.
	started  bool
	lastPoll time.Time
	pollErr  bool
}

// NewFamily validates cfg and fills in its defaults.
func NewFamily(cfg Config) (*Family, error) {
	if cfg.Source == nil || cfg.Stat == nil {
		return nil, errors.New("statagg family needs a Source and a Stat function")
	}
	for _, m := range cfg.Metrics {
		if err := m.validate(cfg.Layout); err != nil {
			return nil, fmt.Errorf("family %s: %w", cfg.Name, err)
		}
	}
	reader, err := NewReader(cfg.Source, cfg.Layout)
	if err != nil {
		return nil, fmt.Errorf("family %s: %w", cfg.Name, err)
	}
	if cfg.MinPollInterval == 0 {
		cfg.MinPollInterval = DefaultMinPollInterval
	}
	if cfg.TickInterval == 0 {
		cfg.TickInterval = DefaultTickInterval
	}
	if cfg.RedecorateAfter == 0 {
		cfg.RedecorateAfter = DefaultRedecorateAfter
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Deletable == nil {
		cfg.Deletable = func(_ []byte, idle int) bool { return idle >= DefaultIdlePolls }
	}
	return &Family{
		cfg:    cfg,
		reader: reader,
		log:    slog.With("component", "statagg.Family", "family", cfg.Name),
	}, nil
}

// Run starts reading the kernel map, every TickInterval and whenever an
// exporter collects, until ctx is done. Attach every exporter
// before: one attached later misses what the map counted until then.
func (f *Family) Run(ctx context.Context) {
	f.start()
	ticker := time.NewTicker(f.cfg.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.mu.Lock()
			f.poll(f.cfg.Clock())
			f.mu.Unlock()
		}
	}
}

func (f *Family) start() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = true
}

// attach adds an exporter's sink. Keys are linked to the new sink the next
// time they count something; what they counted before is not in it.
func (f *Family) attach(s sink) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sinks = append(f.sinks, s)
}

// collect runs export with the family locked, after reading the kernel map
// unless the family is not running yet or an exporter read it less than
// MinPollInterval ago.
func (f *Family) collect(export func(now time.Time)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.cfg.Clock()
	if f.started && now.Sub(f.lastPoll) >= f.cfg.MinPollInterval {
		f.poll(now)
	}
	export(now)
}

func (f *Family) poll(now time.Time) {
	f.lastPoll = now
	visit := func(k *kernelKey, d Delta, values []byte) { f.count(k, d, values, now) }
	if err := f.reader.Poll(now, visit); err != nil {
		f.logPollError(err)
		return
	}
	f.deleteIdle(visit)
}

func (f *Family) deleteIdle(visit func(k *kernelKey, d Delta, values []byte)) {
	for _, k := range f.reader.keys {
		if k.idle == 0 || !f.cfg.Deletable(f.reader.keyBytes(k), k.idle) {
			continue
		}
		if err := f.reader.Delete(k, visit); err != nil {
			f.logPollError(err)
			return
		}
	}
}

func (f *Family) logPollError(err error) {
	if !f.pollErr {
		f.pollErr = true
		f.log.Warn("can't read the kernel aggregation map; its metrics stop until it can", "error", err)
		return
	}
	f.log.Debug("can't read the kernel aggregation map", "error", err)
}

// count adds what a kernel key counted to every series it feeds, decorating
// the key first when it is new, when its decoration asked for another try or
// is older than RedecorateAfter, or when a sink was attached since.
func (f *Family) count(k *kernelKey, d Delta, values []byte, now time.Time) {
	if k.decorated.IsZero() || !k.final || k.sinkGen != len(f.sinks) ||
		now.Sub(k.decorated) >= f.cfg.RedecorateAfter {
		f.decorate(k, values, now)
	}
	for _, links := range k.links {
		for i, s := range links {
			if s != nil {
				f.cfg.Metrics[i].add(s, d, now)
			}
		}
	}
}

func (f *Family) decorate(k *kernelKey, values []byte, now time.Time) {
	stat, final := f.cfg.Stat(f.reader.keyBytes(k), values)
	keep := stat != nil && (f.cfg.Decorate == nil || f.cfg.Decorate(stat))
	k.decorated, k.final, k.sinkGen = now, final, len(f.sinks)

	if len(k.links) != len(f.sinks) {
		k.links = make([][]*seriesCore, len(f.sinks))
	}
	for s, sk := range f.sinks {
		if k.links[s] == nil {
			k.links[s] = make([]*seriesCore, len(f.cfg.Metrics))
		}
		for i, m := range f.cfg.Metrics {
			k.links[s][i] = nil
			if keep && (m.Select == nil || m.Select(stat)) {
				k.links[s][i] = sk.link(i, stat, now)
			}
		}
	}
}

// add counts a key's delta into one series.
func (m *Metric) add(s *seriesCore, d Delta, now time.Time) {
	switch m.Kind {
	case KindHistogram:
		n := d.Sum(m.BucketWord, m.Layout.Buckets())
		if n == 0 {
			return
		}
		s.touch(now)
		for i := range s.buckets {
			s.buckets[i] += d[m.BucketWord+i]
		}
		s.sumNs += d.Counter(m.SumWord)
	default:
		v := m.Value(d)
		if v == 0 && m.SkipZero {
			return
		}
		s.touch(now)
		s.value += v
	}
}

// Registry is the set of families whose metrics are exported from kernel
// aggregation maps rather than per event.
type Registry struct {
	metrics map[string]metricRef
}

type metricRef struct {
	family *Family
	index  int
}

// NewRegistry indexes the metrics of families. A metric may come from one
// family only.
func NewRegistry(families ...*Family) (*Registry, error) {
	r := &Registry{metrics: map[string]metricRef{}}
	for _, f := range families {
		for i, m := range f.cfg.Metrics {
			if _, dup := r.metrics[m.Name.OTEL]; dup {
				return nil, fmt.Errorf("metric %s comes from two families", m.Name.OTEL)
			}
			r.metrics[m.Name.OTEL] = metricRef{family: f, index: i}
		}
	}
	return r, nil
}

// Handles reports whether a kernel map aggregates the metric, in which case
// an exporter must not also register its per-event instrument. A nil
// Registry handles nothing.
func (r *Registry) Handles(name attributes.Name) bool {
	if r == nil {
		return false
	}
	_, ok := r.metrics[name.OTEL]
	return ok
}

func (r *Registry) lookup(name attributes.Name) (metricRef, error) {
	if r == nil {
		return metricRef{}, fmt.Errorf("metric %s is not aggregated", name.OTEL)
	}
	ref, ok := r.metrics[name.OTEL]
	if !ok {
		return metricRef{}, fmt.Errorf("metric %s is not aggregated", name.OTEL)
	}
	return ref, nil
}
