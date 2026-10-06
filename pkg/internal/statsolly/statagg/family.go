// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"bytes"
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
	// DefaultMaxDeletesPerPoll bounds the keys one poll deletes from the
	// kernel map, one syscall each, so the family lock that scrapes and
	// collections wait on is held for a bounded time; the rest wait for the
	// next poll.
	DefaultMaxDeletesPerPoll = 1024
	// DefaultNewKeyInterval is the period of the new-key check, which lists
	// the keys of the map, without their values, and polls only when one is
	// new: a key is decorated within about a second of its first count,
	// while the pod it counts for, and its cgroup, still exist, rather than
	// at the next tick or scrape, when a pod shorter than that gap is gone.
	DefaultNewKeyInterval = time.Second
	// DefaultRetryPendingFor is how long after a key first appears a
	// decoration that is not final yet (a pod the Kubernetes store does not
	// know yet, a container whose ID it has not seen yet) has the new-key
	// check poll again, so the key is decorated again while its pod lives.
	DefaultRetryPendingFor = 10 * time.Second
)

// DefaultIdleAfter is how long a key must count nothing before it is deleted
// from the kernel map: two background ticks. It is a time, not a number of
// polls, because exporter collections poll too: a key that counts every 30 s
// must stay in the map rather than be deleted and decorated again after two
// 1 s collections, and every deletion opens a window in which the kernel
// reuses the freed element of a preallocated map.
func DefaultIdleAfter(tick time.Duration) time.Duration { return 2 * tick }

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
	// KindDurationCounter is a monotonic sum of time in seconds, from a
	// Value in nanoseconds: OTel Sum[float64], Prometheus counter (e.g. a
	// semconv operation_time).
	KindDurationCounter
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

	// Variants, when set, makes the metric emit, from every key, one series
	// per entry instead of one: each reads its own word of the same key's
	// Delta and, before its series' attributes are read, tags the stat with
	// whatever its Mark sets (e.g. the two directions of NFS client IO's
	// wire bytes, which the kernel counts together in one key). Two
	// variants whose attributes end up equal, the way two different real
	// keys can, add into that one series together. Kind must be
	// KindCounter; Value and SkipZero are unused.
	Variants []Variant
}

// Variant is one of a split Metric's several series from each key.
type Variant struct {
	// Value is what this variant's series adds for a key's Delta.
	Value func(d Delta) uint64
	// Mark sets, on the stat a key decorates to, whatever this metric's
	// attributes read to tell this variant's series from the others. Nil
	// for a variant that needs no mark.
	Mark func(stat *ebpf.Stat)
}

func (m *Metric) validate(layout ValueLayout) error {
	words := layout.Counters + layout.Buckets
	switch m.Kind {
	case KindCounter, KindUpDownCounter, KindDurationCounter:
		if len(m.Variants) > 0 {
			if m.Kind != KindCounter {
				return fmt.Errorf("metric %s: variants need a counter", m.Name.OTEL)
			}
			for i, v := range m.Variants {
				if v.Value == nil {
					return fmt.Errorf("metric %s: variant %d needs a Value", m.Name.OTEL, i)
				}
			}
		} else if m.Value == nil {
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

// slots is how many series Metric links per key: one, or one per Variant.
func (m *Metric) slots() int {
	if len(m.Variants) > 0 {
		return len(m.Variants)
	}
	return 1
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

	// Pending reports, after Decorate, that stat still lacks something that
	// may come later (set by a decorator, as the NFS owner's): the key is
	// decorated again the next time it counts, as with Stat's final=false.
	// Nil means never.
	Pending func(stat *ebpf.Stat) bool

	// Deletable reports whether a key that counted nothing for IdleAfter may
	// be deleted from the kernel map now, e.g. not while the cgroup it
	// counts for is a tombstone. Nil deletes every such key. Neither Stat
	// nor Deletable may keep key after returning.
	Deletable func(key []byte) bool

	Metrics []*Metric

	MinPollInterval time.Duration
	TickInterval    time.Duration
	RedecorateAfter time.Duration
	// IdleAfter defaults to DefaultIdleAfter(TickInterval), whatever
	// NewKeyInterval: the new-key check's polls do not make keys idle
	// sooner.
	IdleAfter time.Duration
	// NewKeyInterval is the period of the new-key check
	// (DefaultNewKeyInterval when 0); a negative one disables the check,
	// for a map whose keys need nothing that may be gone by the next tick.
	NewKeyInterval time.Duration
	// RetryPendingFor is how long after it first appears a key whose
	// decoration is not final (Stat's final=false, or Pending) has the
	// new-key check poll again (DefaultRetryPendingFor when 0).
	RetryPendingFor time.Duration
	// Learn, when set, is called by the new-key check with the keys it
	// found new, before the poll that decorates them, without the family
	// lock, so it may block scrapes no longer than the check does: e.g.
	// for the cgroup index to learn their cgroups while they exist. The
	// keys are copies it may keep.
	Learn func(keys [][]byte)
	// MaxDeletesPerPoll defaults to DefaultMaxDeletesPerPoll.
	MaxDeletesPerPoll int
	Clock             func() time.Time
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
	// links holds, per sink, metric and variant slot (Metric.slots, one for
	// a metric with no Variants), the series the key counts into, resolved
	// when it was last decorated with sinkGen sinks.
	links   [][][]*seriesCore
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
	started bool
	// stopped is set when Run returns, after its last read: from then on
	// exporters collect what was read without reading the map, which its
	// owner may close.
	stopped  bool
	lastPoll time.Time
	pollErr  bool
	// polls counts the reads of the map.
	polls uint64
	// pending holds the keys younger than RetryPendingFor whose decoration
	// is not final: the new-key check polls while there is one.
	pending map[*kernelKey]struct{}
	// checkErr is set while the new-key check cannot list the map.
	checkErr bool
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
	if cfg.IdleAfter == 0 {
		cfg.IdleAfter = DefaultIdleAfter(cfg.TickInterval)
	}
	if cfg.NewKeyInterval == 0 {
		cfg.NewKeyInterval = DefaultNewKeyInterval
	}
	if cfg.RetryPendingFor == 0 {
		cfg.RetryPendingFor = DefaultRetryPendingFor
	}
	if cfg.MaxDeletesPerPoll == 0 {
		cfg.MaxDeletesPerPoll = DefaultMaxDeletesPerPoll
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Deletable == nil {
		cfg.Deletable = func([]byte) bool { return true }
	}
	return &Family{
		cfg:     cfg,
		reader:  reader,
		log:     slog.With("component", "statagg.Family", "family", cfg.Name),
		pending: map[*kernelKey]struct{}{},
	}, nil
}

// Run starts reading the kernel map, every TickInterval, whenever an
// exporter collects, and whenever the new-key check, every NewKeyInterval,
// finds a key the family has not decorated yet, until ctx is done. Attach
// every exporter before: one attached later misses what the map counted
// until then.
//
// Once ctx is done, Run reads the map one last time, so what the kernel
// counted until then reaches the exporters, and returns: from then on the
// family never reads the map again, and its owner may close it.
func (f *Family) Run(ctx context.Context) {
	f.start()
	defer f.stop()
	ticker := time.NewTicker(f.cfg.TickInterval)
	defer ticker.Stop()
	var newKeys <-chan time.Time
	if f.cfg.NewKeyInterval > 0 {
		check := time.NewTicker(f.cfg.NewKeyInterval)
		defer check.Stop()
		newKeys = check.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.mu.Lock()
			f.poll(f.cfg.Clock())
			f.mu.Unlock()
		case <-newKeys:
			f.checkNewKeys()
		}
	}
}

// checkNewKeys lists the keys of the map, without their values, and polls
// when one of them is new, or when a young key's decoration is not final
// yet: a key decorated a second after its first count still finds its
// process, its cgroup and its pod, where the next tick, or scrape, may be
// too late for a short-lived pod. With no new key it reads nothing else, so
// the steady state costs one key listing per NewKeyInterval.
func (f *Family) checkNewKeys() {
	f.mu.Lock()
	if !f.started || f.stopped {
		f.mu.Unlock()
		return
	}
	fresh, due := f.newKeys(f.cfg.Clock())
	polls := f.polls
	f.mu.Unlock()
	if !due {
		return
	}
	if len(fresh) > 0 && f.cfg.Learn != nil {
		f.cfg.Learn(fresh)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	// A collection that read the map since has decorated the new keys.
	if f.stopped || f.polls != polls {
		return
	}
	f.poll(f.cfg.Clock())
}

// newKeys returns the keys of the map the Reader has not seen, and whether
// a poll is due: for them, for a young key whose decoration is not final,
// or for a young key that has not counted anything yet (found between the
// kernel's creation of its zeroed value and its first count).
func (f *Family) newKeys(now time.Time) (fresh [][]byte, due bool) {
	for k := range f.pending {
		if now.Sub(k.born) >= f.cfg.RetryPendingFor || f.reader.keys[k.key] != k {
			delete(f.pending, k)
		}
	}
	due = len(f.pending) > 0
	err := forEachKey(f.cfg.Source, func(key []byte) {
		k, known := f.reader.keys[string(key)]
		switch {
		case !known:
			fresh = append(fresh, bytes.Clone(key))
			due = true
		case k.decorated.IsZero() && now.Sub(k.born) < f.cfg.RetryPendingFor:
			due = true
		}
	})
	if err != nil {
		if !f.checkErr {
			f.checkErr = true
			f.log.Debug("can't list the keys of the kernel aggregation map", "error", err)
		}
		return nil, due
	}
	f.checkErr = false
	return fresh, due
}

// stop reads the map a last time, without deleting idle keys, which would
// only cost syscalls on a map about to be closed, and stops reading it. The
// lock waits for a collection that is reading the map.
func (f *Family) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.read(f.cfg.Clock())
	f.stopped = true
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
// unless the family is not running (yet or any more) or an exporter read it
// less than MinPollInterval ago.
func (f *Family) collect(export func(now time.Time)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.cfg.Clock()
	if f.started && !f.stopped && now.Sub(f.lastPoll) >= f.cfg.MinPollInterval {
		f.poll(now)
	}
	export(now)
}

func (f *Family) poll(now time.Time) {
	if f.read(now) {
		f.deleteIdle(now, f.visitor(now))
	}
}

// read counts what every key counted since the previous read, reporting
// whether the map could be read.
func (f *Family) read(now time.Time) bool {
	f.lastPoll = now
	f.polls++
	if err := f.reader.Poll(now, f.visitor(now)); err != nil {
		f.logPollError(err)
		return false
	}
	return true
}

func (f *Family) visitor(now time.Time) func(k *kernelKey, d Delta, values []byte) {
	return func(k *kernelKey, d Delta, values []byte) { f.count(k, d, values, now) }
}

// deleteIdle deletes up to MaxDeletesPerPoll keys that counted nothing for
// IdleAfter, as Deletable allows.
func (f *Family) deleteIdle(now time.Time, visit func(k *kernelKey, d Delta, values []byte)) {
	deleted := 0
	for _, k := range f.reader.keys {
		if deleted >= f.cfg.MaxDeletesPerPoll {
			return
		}
		if now.Sub(k.changed) < f.cfg.IdleAfter || !f.cfg.Deletable(f.reader.keyBytes(k)) {
			continue
		}
		if err := f.reader.Delete(k, visit); err != nil {
			f.logPollError(err)
			return
		}
		deleted++
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
	for _, perMetric := range k.links {
		for i, slots := range perMetric {
			m := f.cfg.Metrics[i]
			for v, s := range slots {
				if s == nil {
					continue
				}
				if len(m.Variants) == 0 {
					slots[v] = m.add(s, d, now)
				} else {
					slots[v] = m.addVariant(v, s, d, now)
				}
			}
		}
	}
}

func (f *Family) decorate(k *kernelKey, values []byte, now time.Time) {
	stat, final := f.cfg.Stat(f.reader.keyBytes(k), values)
	keep := stat != nil && (f.cfg.Decorate == nil || f.cfg.Decorate(stat))
	if final && stat != nil && f.cfg.Pending != nil && f.cfg.Pending(stat) {
		final = false
	}
	k.decorated, k.final, k.sinkGen = now, final, len(f.sinks)
	if !final && now.Sub(k.born) < f.cfg.RetryPendingFor {
		f.pending[k] = struct{}{}
	} else {
		delete(f.pending, k)
	}

	if len(k.links) != len(f.sinks) {
		k.links = make([][][]*seriesCore, len(f.sinks))
	}
	for s, sk := range f.sinks {
		if k.links[s] == nil {
			k.links[s] = make([][]*seriesCore, len(f.cfg.Metrics))
		}
		for i, m := range f.cfg.Metrics {
			if len(k.links[s][i]) != m.slots() {
				k.links[s][i] = make([]*seriesCore, m.slots())
			}
			for v := range k.links[s][i] {
				k.links[s][i][v] = nil
			}
			if !keep || (m.Select != nil && !m.Select(stat)) {
				continue
			}
			if len(m.Variants) == 0 {
				k.links[s][i][0] = sk.link(i, stat, now)
				continue
			}
			for v, variant := range m.Variants {
				if variant.Mark != nil {
					variant.Mark(stat)
				}
				k.links[s][i][v] = sk.link(i, stat, now)
			}
		}
	}
}

// add counts a key's delta into series s and returns the series the key
// counts into from now on: s, or the one that replaced it once it expired.
func (m *Metric) add(s *seriesCore, d Delta, now time.Time) *seriesCore {
	switch m.Kind {
	case KindHistogram:
		n := d.Sum(m.BucketWord, m.Layout.Buckets())
		if n == 0 {
			return s
		}
		s = s.touch(now)
		for i := range s.buckets {
			s.buckets[i] += d[m.BucketWord+i]
		}
		s.sumNs += d.Counter(m.SumWord)
	default:
		v := m.Value(d)
		if v == 0 && m.SkipZero {
			return s
		}
		s = s.touch(now)
		s.value += v
	}
	return s
}

// addVariant counts a key's delta into series s through variant v of a
// split Metric, the way add does for a metric with no Variants.
func (m *Metric) addVariant(v int, s *seriesCore, d Delta, now time.Time) *seriesCore {
	val := m.Variants[v].Value(d)
	s = s.touch(now)
	s.value += val
	return s
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
