// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package stataggtest provides in-memory kernel maps and a block-like
// aggregation family for tests of statagg users.
package stataggtest // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"

import (
	"encoding/binary"
	"slices"
	"sync"
)

// MemMap is an in-memory kernel aggregation map: a statagg.Source whose
// values are written the way eBPF programs update them.
type MemMap struct {
	mu      sync.Mutex
	keySize int
	stride  int
	cpus    int
	entries map[string][]byte
	// reads and listings count the calls of ForEach and ForEachKey.
	reads, listings int
}

// NewMemMap returns an empty map. A per-CPU map (cpus > 1) strides its
// values at 8 bytes, as the kernel does.
func NewMemMap(keySize, valueSize, cpus int) *MemMap {
	stride := valueSize
	if cpus > 1 {
		stride = (valueSize + 7) &^ 7
	}
	return &MemMap{keySize: keySize, stride: stride, cpus: cpus, entries: map[string][]byte{}}
}

func (m *MemMap) KeySize() int     { return m.keySize }
func (m *MemMap) ValueStride() int { return m.stride }
func (m *MemMap) CPUs() int        { return m.cpus }

// ForEach visits the entries in key order.
func (m *MemMap) ForEach(fn func(key, values []byte)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	for _, k := range m.sortedKeys() {
		fn([]byte(k), m.entries[k])
	}
	return nil
}

// ForEachKey visits the keys in order, without their values: the
// statagg.KeyLister of a per-CPU map.
func (m *MemMap) ForEachKey(fn func(key []byte)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listings++
	for _, k := range m.sortedKeys() {
		fn([]byte(k))
	}
	return nil
}

func (m *MemMap) sortedKeys() []string {
	keys := make([]string, 0, len(m.entries))
	for k := range m.entries {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Reads is the number of ForEach calls: full reads of keys and values.
func (m *MemMap) Reads() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reads
}

// Listings is the number of ForEachKey calls: key-only listings.
func (m *MemMap) Listings() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listings
}

func (m *MemMap) LookupAndDelete(key, values []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.entries[string(key)]
	if !ok {
		return false, nil
	}
	copy(values, v)
	delete(m.entries, string(key))
	return true, nil
}

// Len is the number of keys in the map.
func (m *MemMap) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// AddU64 adds n to the u64 at byte offset of key's value on cpu, creating
// the key zeroed first, as a lookup-or-init does.
func (m *MemMap) AddU64(key []byte, cpu, offset int, n uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.value(key)[cpu*m.stride+offset:]
	binary.NativeEndian.PutUint64(v, binary.NativeEndian.Uint64(v)+n)
}

// AddU32 adds n to the u32 at byte offset of key's value on cpu; it wraps
// like the kernel's u32 buckets.
func (m *MemMap) AddU32(key []byte, cpu, offset int, n uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.value(key)[cpu*m.stride+offset:]
	binary.NativeEndian.PutUint32(v, binary.NativeEndian.Uint32(v)+n)
}

// SetU32 writes n to the u32 at byte offset of key's value on cpu, creating
// the key zeroed first: a field a program stores rather than adds to.
func (m *MemMap) SetU32(key []byte, cpu, offset int, n uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	binary.NativeEndian.PutUint32(m.value(key)[cpu*m.stride+offset:], n)
}

func (m *MemMap) value(key []byte) []byte {
	v, ok := m.entries[string(key)]
	if !ok {
		v = make([]byte, m.stride*m.cpus)
		m.entries[string(key)] = v
	}
	return v
}
