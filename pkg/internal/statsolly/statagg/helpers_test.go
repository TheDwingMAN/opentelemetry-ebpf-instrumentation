// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg

import (
	"encoding/binary"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// fakeMap is an in-memory kernel map: raw keys, per-CPU values.
type fakeMap struct {
	mu      sync.Mutex
	keySize int
	stride  int
	cpus    int
	entries map[string][]byte
}

func newFakeMap(keySize, stride, cpus int) *fakeMap {
	return &fakeMap{keySize: keySize, stride: stride, cpus: cpus, entries: map[string][]byte{}}
}

func (m *fakeMap) KeySize() int     { return m.keySize }
func (m *fakeMap) ValueStride() int { return m.stride }
func (m *fakeMap) CPUs() int        { return m.cpus }

func (m *fakeMap) ForEach(fn func(key, values []byte)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.entries))
	for k := range m.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fn([]byte(k), m.entries[k])
	}
	return nil
}

func (m *fakeMap) LookupAndDelete(key, values []byte) (bool, error) {
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

// value returns the values of key, creating them zeroed as the kernel's
// lookup-or-init does.
func (m *fakeMap) value(key []byte) []byte {
	v, ok := m.entries[string(key)]
	if !ok {
		v = make([]byte, m.stride*m.cpus)
		m.entries[string(key)] = v
	}
	return v
}

func (m *fakeMap) addU64(key []byte, cpu, word int, n uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.value(key)[cpu*m.stride+word*counterSize:]
	binary.NativeEndian.PutUint64(v, binary.NativeEndian.Uint64(v)+n)
}

func (m *fakeMap) addU32(key []byte, cpu, offset, word int, n uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.value(key)[cpu*m.stride+offset+word*bucketSize:]
	binary.NativeEndian.PutUint32(v, binary.NativeEndian.Uint32(v)+n)
}

// Test family: a block-like map keyed by {u32 dev; u8 op; u8 pad[3]; s32 err},
// valued {u64 bytes; u64 sum_ns; u32 bkt[len(layout)+1]; pad}.
const (
	testKeySize = 12
	wordBytes   = 0
	wordSumNs   = 1
	testWords   = 2
)

func blkKey(dev uint32, op ebpf.BlockOpCode, err int32) []byte {
	k := make([]byte, testKeySize)
	binary.NativeEndian.PutUint32(k, dev)
	k[4] = byte(op)
	binary.NativeEndian.PutUint32(k[8:], uint32(err))
	return k
}

func blkStat(key, _ []byte) (*ebpf.Stat, bool) {
	return &ebpf.Stat{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{
		Dev:   binary.NativeEndian.Uint32(key),
		Op:    key[4],
		Error: int32(binary.NativeEndian.Uint32(key[8:])),
	}}, true
}

func testStride(l *Layout) int {
	size := testWords*counterSize + l.Buckets()*bucketSize
	return (size + 7) &^ 7
}

// record does what the kernel program would for one completed request.
func record(m *fakeMap, l *Layout, key []byte, cpu int, bytes, latNs uint64) {
	m.addU64(key, cpu, wordBytes, bytes)
	m.addU64(key, cpu, wordSumNs, latNs)
	idx := sort.Search(len(l.BoundsNs), func(i int) bool { return latNs <= l.BoundsNs[i] })
	m.addU32(key, cpu, testWords*counterSize, idx, 1)
}

var (
	testDuration = attributes.Name{Section: "test.duration", OTEL: "test.duration", Prom: "test_duration_seconds", Unit: "s"}
	testIO       = attributes.Name{Section: "test.io", OTEL: "test.io", Prom: "test_io_bytes_total", Unit: "By"}
	testErrors   = attributes.Name{Section: "test.errors", OTEL: "test.errors", Prom: "test_errors_total", Unit: "{error}"}
)

func testMetrics(l *Layout) []*Metric {
	return []*Metric{
		{
			Name: testDuration, Kind: KindHistogram,
			Select:  func(s *ebpf.Stat) bool { return s.BlockIo.IsReadWrite() },
			SumWord: wordSumNs, BucketWord: testWords, Layout: l,
		},
		{
			Name: testIO, Kind: KindCounter,
			Select: func(s *ebpf.Stat) bool { return s.BlockIo.IsReadWrite() },
			Value:  func(d Delta) uint64 { return d.Counter(wordBytes) },
		},
		{
			Name: testErrors, Kind: KindCounter,
			Select: func(s *ebpf.Stat) bool { return s.BlockIo.IsReadWrite() && s.BlockIo.Error != 0 },
			Value:  func(d Delta) uint64 { return d.Sum(testWords, l.Buckets()) },
		},
	}
}

// fakeClock is a settable clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type testFamily struct {
	m      *fakeMap
	layout *Layout
	family *Family
	clock  *fakeClock
	reg    *Registry
}

func newTestFamily(t testing.TB, cpus int, bounds []float64, mod func(*Config)) *testFamily {
	t.Helper()
	l, err := NewExplicitLayout(bounds)
	require.NoError(t, err)
	return newTestFamilyLayout(t, cpus, l, mod)
}

func newTestFamilyLayout(t testing.TB, cpus int, l *Layout, mod func(*Config)) *testFamily {
	t.Helper()
	m := newFakeMap(testKeySize, testStride(l), cpus)
	clock := newFakeClock()
	cfg := Config{
		Name:   "test",
		Source: m,
		Layout: ValueLayout{Counters: testWords, Buckets: l.Buckets()},
		Stat:   blkStat,
		// Every poll in a test is a real read of the map.
		MinPollInterval: time.Nanosecond,
		Clock:           clock.Now,
		Metrics:         testMetrics(l),
	}
	if mod != nil {
		mod(&cfg)
	}
	f, err := NewFamily(cfg)
	require.NoError(t, err)
	reg, err := NewRegistry(f)
	require.NoError(t, err)
	// Tests collect right away, and attach exporters when they need them.
	f.start()
	return &testFamily{m: m, layout: l, family: f, clock: clock, reg: reg}
}

// devOpLabels projects a stat to "dev" and "op" labels, and "err" when with
// errors, like an exporter's attribute selection.
func devOpLabels(withErr bool) (Projection[attribute.Set], Projection[[]string]) {
	values := func(s *ebpf.Stat) []string {
		v := []string{strconv.Itoa(int(s.BlockIo.Dev)), strconv.Itoa(int(s.BlockIo.Op))}
		if withErr {
			v = append(v, strconv.Itoa(int(s.BlockIo.Error)))
		}
		return v
	}
	names := []string{"dev", "op", "err"}
	otel := func(s *ebpf.Stat) (string, attribute.Set) {
		v := values(s)
		kvs := make([]attribute.KeyValue, len(v))
		for i := range v {
			kvs[i] = attribute.String(names[i], v[i])
		}
		return strings.Join(v, "\x00"), attribute.NewSet(kvs...)
	}
	prom := func(s *ebpf.Stat) (string, []string) {
		v := values(s)
		return strings.Join(v, "\x00"), slices.Clone(v)
	}
	return otel, prom
}
