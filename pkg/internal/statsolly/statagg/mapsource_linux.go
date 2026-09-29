// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"errors"
	"fmt"
	"reflect"

	cebpf "github.com/cilium/ebpf"
)

// batchBytes bounds the buffers of one batch lookup: a per-CPU value is
// copied once per possible CPU, so a 152-byte value on 128 CPUs takes 19 KiB
// and a batch holds about 50 keys.
const (
	batchBytes   = 1 << 20
	minBatchKeys = 16
)

// MapSource is a Source over a kernel map, read with batch lookups into
// buffers allocated once.
type MapSource struct {
	m         *cebpf.Map
	keySize   int
	valueSize int
	stride    int
	cpus      int
	perCPU    bool

	// keys and values are slices of byte arrays, one element per key (a
	// value element holds every CPU's copy): the batch API counts elements
	// and fills their memory in place. keysOut and valuesOut box them once.
	batch     int
	keys      reflect.Value
	values    reflect.Value
	keysOut   any
	valuesOut any

	// cpuValues is a slice of [valueSize]byte arrays, one per CPU, for
	// single-key lookups of per-CPU maps.
	cpuValues    reflect.Value
	cpuValuesOut any

	noLookupAndDelete bool
}

// NewMapSource reads m.
func NewMapSource(m *cebpf.Map) (*MapSource, error) {
	s := &MapSource{
		m:         m,
		keySize:   int(m.KeySize()),
		valueSize: int(m.ValueSize()),
		stride:    int(m.ValueSize()),
		cpus:      1,
	}
	switch m.Type() {
	case cebpf.PerCPUHash, cebpf.PerCPUArray, cebpf.LRUCPUHash:
		cpus, err := cebpf.PossibleCPU()
		if err != nil {
			return nil, fmt.Errorf("possible CPUs: %w", err)
		}
		s.perCPU, s.cpus = true, cpus
		s.stride = (s.valueSize + 7) &^ 7
		s.cpuValues = byteArrays(s.valueSize, cpus)
		s.cpuValuesOut = s.cpuValues.Interface()
	}
	s.resize(min(max(batchBytes/(s.stride*s.cpus), minBatchKeys), int(m.MaxEntries())))
	return s, nil
}

func (s *MapSource) resize(batch int) {
	s.batch = batch
	s.keys = byteArrays(s.keySize, batch)
	s.values = byteArrays(s.stride*s.cpus, batch)
	s.keysOut, s.valuesOut = s.keys.Interface(), s.values.Interface()
}

// byteArrays makes a slice of n [size]byte arrays.
func byteArrays(size, n int) reflect.Value {
	return reflect.MakeSlice(reflect.SliceOf(reflect.ArrayOf(size, reflect.TypeFor[byte]())), n, n)
}

func (s *MapSource) KeySize() int     { return s.keySize }
func (s *MapSource) ValueStride() int { return s.stride }
func (s *MapSource) CPUs() int        { return s.cpus }

// ForEach reads the map in batches. When a hash bucket holds more keys than
// a batch (the kernel's ENOSPC), the batch doubles and the walk restarts;
// keys seen twice count nothing the second time.
func (s *MapSource) ForEach(fn func(key, values []byte)) error {
	var cursor cebpf.MapBatchCursor
	for {
		n, err := s.m.BatchLookup(&cursor, s.keysOut, s.valuesOut, nil)
		for i := range n {
			fn(s.keys.Index(i).Bytes(), s.values.Index(i).Bytes())
		}
		switch {
		case errors.Is(err, cebpf.ErrKeyNotExist):
			return nil
		case err != nil && n == 0 && s.batch < int(s.m.MaxEntries()):
			// The only error a batch lookup that returns nothing
			// recovers from is a batch smaller than a hash bucket.
			s.resize(min(2*s.batch, int(s.m.MaxEntries())))
			cursor = cebpf.MapBatchCursor{}
		case err != nil:
			return err
		}
	}
}

// LookupAndDelete removes key with its last values. Kernels before 5.14 do
// not look up and delete hash map elements in one call: there the lookup and
// the delete are separate, and what the key counts between them is lost.
func (s *MapSource) LookupAndDelete(key, values []byte) (bool, error) {
	if !s.noLookupAndDelete {
		err := s.lookup(key, values, true)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, cebpf.ErrKeyNotExist):
			return false, nil
		}
		s.noLookupAndDelete = true
	}
	if err := s.lookup(key, values, false); err != nil {
		if errors.Is(err, cebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	if err := s.m.Delete(key); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
		return false, err
	}
	return true, nil
}

func (s *MapSource) lookup(key, values []byte, andDelete bool) error {
	out := any(values[:s.valueSize])
	if s.perCPU {
		out = s.cpuValuesOut
	}
	var err error
	if andDelete {
		err = s.m.LookupAndDelete(key, out)
	} else {
		err = s.m.Lookup(key, out)
	}
	if err != nil || !s.perCPU {
		return err
	}
	for cpu := range s.cpus {
		copy(values[cpu*s.stride:], s.cpuValues.Index(cpu).Bytes())
	}
	return nil
}
