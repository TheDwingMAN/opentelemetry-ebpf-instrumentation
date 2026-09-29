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
// PID) is not counted. u64 words are summed across CPUs as they are, which is
// exact for monotonic counters and, in two's complement, for signed ones (a
// +1 on one CPU and a -1 on another). u32 bucket words wrap, so each CPU's
// copy is subtracted from its previous copy before the sum: that is exact as
// long as no single CPU counts 2^32 values in one bucket between two polls,
// which the 30 s background poll guarantees at any realistic rate.
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
	// prev holds the values of every CPU at the previous poll.
	prev []byte
	// idle counts the polls in a row that saw no change, since changed.
	idle    int
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
	}, nil
}

// Poll reads the whole map and calls visit for every key that counted
// something since the previous poll, with what it counted. The Delta is only
// valid during the call. A key that left the map without the Reader deleting
// it is forgotten, so if it comes back it counts from zero again.
func (r *Reader) Poll(now time.Time, visit func(k *kernelKey, d Delta, values []byte)) error {
	r.gen++
	err := r.src.ForEach(func(key, values []byte) {
		k, ok := r.keys[string(key)]
		if !ok {
			// A key enters the map zeroed, so all of its first values are new.
			k = &kernelKey{key: string(key), prev: make([]byte, len(values)), changed: now}
			r.keys[k.key] = k
		}
		k.seen = r.gen
		if !r.diff(k.prev, values) {
			k.idle++
			return
		}
		k.idle, k.changed = 0, now
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

// diff sets r.delta to cur - prev and stores cur in prev. It reports whether
// anything changed.
func (r *Reader) diff(prev, cur []byte) bool {
	clear(r.delta)
	changed := false
	for cpu := range r.cpus {
		off := cpu * r.stride
		p, c := prev[off:off+r.stride], cur[off:off+r.stride]
		if bytes.Equal(p, c) {
			continue
		}
		changed = true
		r.addCPU(p, c)
		copy(p, c)
	}
	return changed
}

func (r *Reader) addCPU(prev, cur []byte) {
	for w := range r.layout.Counters {
		at := w * counterSize
		r.delta[w] += binary.NativeEndian.Uint64(cur[at:]) - binary.NativeEndian.Uint64(prev[at:])
	}
	base := r.layout.Counters * counterSize
	for b := range r.layout.Buckets {
		at := base + b*bucketSize
		r.delta[r.layout.Counters+b] += uint64(binary.NativeEndian.Uint32(cur[at:]) - binary.NativeEndian.Uint32(prev[at:]))
	}
}
