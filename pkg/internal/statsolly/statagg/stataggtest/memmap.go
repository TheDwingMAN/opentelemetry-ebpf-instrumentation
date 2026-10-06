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
	keys := make([]string, 0, len(m.entries))
	for k := range m.entries {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fn([]byte(k), m.entries[k])
	}
	return nil
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

func (m *MemMap) value(key []byte) []byte {
	v, ok := m.entries[string(key)]
	if !ok {
		v = make([]byte, m.stride*m.cpus)
		m.entries[string(key)] = v
	}
	return v
}
