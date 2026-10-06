// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	counterSize = 8 // a u64 counter word
	bucketSize  = 4 // a u32 bucket word
)

// Source is a kernel aggregation map as the Reader sees it: raw keys, and
// values made of one copy per CPU.
type Source interface {
	// KeySize is the size of a key, in bytes.
	KeySize() int
	// ValueStride is the size of one CPU's copy of a value, in bytes: the
	// value size rounded up to 8 bytes on per-CPU maps.
	ValueStride() int
	// CPUs is the number of copies of every value: the possible CPUs of a
	// per-CPU map, 1 for a map shared by all CPUs.
	CPUs() int
	// ForEach calls fn for every entry, with its key and the copies of its
	// value back to back. Neither slice may be used after fn returns.
	ForEach(fn func(key, values []byte)) error
	// LookupAndDelete removes key and writes its last values into values,
	// reporting false when the key was not in the map.
	LookupAndDelete(key, values []byte) (bool, error)
}

// ValueLayout describes the counting part of a kernel value: Counters u64
// words followed by Buckets u32 words. Anything after them (padding, a sample
// PID) is not counted.
//
// The Reader keeps, per key, only the previous totals: each word summed
// across CPUs, u64 words modulo 2^64 and u32 bucket words modulo 2^32. A
// delta is the difference of two totals in the same modulus, which equals
// the sum of the per-CPU differences: exact for monotonic counters and, in
// two's complement, for signed ones (a +1 on one CPU and a -1 on another),
// and exact for buckets whatever the CPUs' copies wrapped, as long as a key
// counts fewer than 2^32 values in one bucket between two polls on all CPUs
// together: 143 million a second with the 30 s background poll, well above
// what one device, errno and request kind completes. Keeping totals rather
// than every CPU's copy makes the Reader's memory independent of the number
// of CPUs.
type ValueLayout struct {
	Counters int
	Buckets  int
}

func (l ValueLayout) size() int { return l.Counters*counterSize + l.Buckets*bucketSize }

// Delta is how much a kernel key counted since the previous poll: its
// Counters words, summed across CPUs, then its Buckets words.
type Delta []uint64

// Counter returns counter word i.
func (d Delta) Counter(i int) uint64 { return d[i] }

// Sum adds up n words from word i on, e.g. the buckets of a histogram: its
// number of values.
func (d Delta) Sum(i, n int) uint64 {
	var s uint64
	for _, w := range d[i : i+n] {
		s += w
	}
	return s
}

// kernelKey is the Reader's state of one key of the kernel map.
type kernelKey struct {
	key string
	// prev holds the key's totals at the previous poll, in the value
	// layout: counters summed across CPUs, then buckets summed modulo 2^32.
	prev []byte
	// changed is when a poll last found the key changed, or first found it.
	changed time.Time
	// seen is the poll generation that last found the key in the map.
	seen uint64

	decoration
}

// Reader turns successive snapshots of a kernel map into per-key deltas. It
// is the only code that deletes keys of the map. It is not safe for
// concurrent use: its Family serializes it.
type Reader struct {
	src    Source
	layout ValueLayout
	stride int
	cpus   int

	keys map[string]*kernelKey
	gen  uint64

	delta  Delta
	final  []byte
	keyBuf []byte
	// totals is the scratch of diff: the current totals of a key.
	totals []uint64
	// zero is one CPU's counting words, zeroed: CPUs that never counted
	// for a key are skipped.
	zero []byte
}

// NewReader checks that the layout fits the source's values.
func NewReader(src Source, layout ValueLayout) (*Reader, error) {
	if layout.size() > src.ValueStride() {
		return nil, fmt.Errorf("value layout of %d bytes exceeds the %d-byte map value", layout.size(), src.ValueStride())
	}
	return &Reader{
		src:    src,
		layout: layout,
		stride: src.ValueStride(),
		cpus:   src.CPUs(),
		keys:   map[string]*kernelKey{},
		delta:  make(Delta, layout.Counters+layout.Buckets),
		final:  make([]byte, src.ValueStride()*src.CPUs()),
		totals: make([]uint64, layout.Counters+layout.Buckets),
		zero:   make([]byte, layout.size()),
	}, nil
}

// Poll reads the whole map and calls visit for every key that counted
// something since the previous poll, with what it counted. The Delta is only
// valid during the call. A key that left the map without the Reader deleting
// it is forgotten, so if it comes back it counts from zero again. A key the
// source returns twice in one walk (a batch walk that restarts) is read the
// first time only: what it counted in between is in the next poll.
func (r *Reader) Poll(now time.Time, visit func(k *kernelKey, d Delta, values []byte)) error {
	r.gen++
	err := r.src.ForEach(func(key, values []byte) {
		k, ok := r.keys[string(key)]
		if ok && k.seen == r.gen {
			return
		}
		if !ok {
			// A key enters the map zeroed, so all of its first values are new.
			k = &kernelKey{key: string(key), prev: make([]byte, r.layout.size()), changed: now}
			r.keys[k.key] = k
		}
		k.seen = r.gen
		if !r.diff(k.prev, values) {
			return
		}
		k.changed = now
		visit(k, r.delta, values)
	})
	if err != nil {
		return fmt.Errorf("reading kernel map: %w", err)
	}
	for key, k := range r.keys {
		if k.seen != r.gen {
			delete(r.keys, key)
		}
	}
	return nil
}

// Delete removes k from the kernel map. The values the key counted between
// the last poll and the deletion are passed to visit, when there are any, so
// deleting a key never loses what the Reader could still see of it.
func (r *Reader) Delete(k *kernelKey, visit func(k *kernelKey, d Delta, values []byte)) error {
	found, err := r.src.LookupAndDelete(r.keyBytes(k), r.final)
	if err != nil {
		return fmt.Errorf("deleting kernel map key: %w", err)
	}
	delete(r.keys, k.key)
	if found && r.diff(k.prev, r.final) {
		visit(k, r.delta, r.final)
	}
	return nil
}

// keyBytes returns k's key in a buffer that is valid until the next call.
func (r *Reader) keyBytes(k *kernelKey) []byte {
	r.keyBuf = append(r.keyBuf[:0], k.key...)
	return r.keyBuf
}

// diff sets r.delta to the totals of values minus prev and stores them in
// prev. It reports whether anything changed.
func (r *Reader) diff(prev, values []byte) bool {
	r.sum(values)
	changed := false
	for w := range r.layout.Counters {
		at := w * counterSize
		cur := r.totals[w]
		d := cur - binary.NativeEndian.Uint64(prev[at:])
		r.delta[w] = d
		if d != 0 {
			changed = true
			binary.NativeEndian.PutUint64(prev[at:], cur)
		}
	}
	base := r.layout.Counters * counterSize
	for b := range r.layout.Buckets {
		at := base + b*bucketSize
		cur := uint32(r.totals[r.layout.Counters+b])
		d := cur - binary.NativeEndian.Uint32(prev[at:])
		r.delta[r.layout.Counters+b] = uint64(d)
		if d != 0 {
			changed = true
			binary.NativeEndian.PutUint32(prev[at:], cur)
		}
	}
	return changed
}

// sum sets r.totals to the words of values summed across CPUs; bucket words
// are only meaningful modulo 2^32.
func (r *Reader) sum(values []byte) {
	clear(r.totals)
	size := r.layout.size()
	base := r.layout.Counters * counterSize
	counters, buckets := r.totals[:r.layout.Counters], r.totals[r.layout.Counters:]
	for cpu := range r.cpus {
		c := values[cpu*r.stride:][:size]
		if bytes.Equal(c, r.zero) {
			continue
		}
		for w := range counters {
			counters[w] += binary.NativeEndian.Uint64(c[w*counterSize:])
		}
		b := c[base:]
		for i := range buckets {
			buckets[i] += uint64(binary.NativeEndian.Uint32(b[i*bucketSize:]))
		}
	}
}
