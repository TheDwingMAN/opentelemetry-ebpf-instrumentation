// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg

import (
	"context"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// Benchmarks of the collection path at 1k and 10k kernel keys on 4 CPUs,
// reported per key: reading and diffing the map, decorating and projecting
// new keys, and building each exporter's output.

const benchCPUs = 4

func benchFamily(b *testing.B, keys int) (*testFamily, [][]byte) {
	b.Helper()
	tf := newTestFamily(b, benchCPUs, diskBounds, neverDelete)
	ks := make([][]byte, keys)
	for i := range ks {
		ks[i] = blkKey(uint32(i), ebpf.CodeBlockRead, 0)
		record(tf.m, tf.layout, ks[i], i%benchCPUs, 4096, 200_000)
	}
	return tf, ks
}

// neverDelete keeps every key in the map, so benchmarks poll the same keys.
func neverDelete(c *Config) { c.Deletable = func([]byte) bool { return false } }

func perKey(b *testing.B, keys int) {
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(keys), "ns/key")
}

var benchSizes = []int{1_000, 10_000}

// A poll of a map whose keys counted nothing since the last one: the steady
// cost of an idle map.
func BenchmarkPoll_Unchanged(b *testing.B) {
	for _, keys := range benchSizes {
		b.Run(strconv.Itoa(keys), func(b *testing.B) {
			tf, _ := benchFamily(b, keys)
			tf.otelProducer(b, cumulative, 0)
			tf.family.poll(tf.clock.Now())
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				tf.clock.Advance(time.Second)
				tf.family.poll(tf.clock.Now())
			}
			perKey(b, keys)
		})
	}
}

// A poll where every key counted one more request: diff and accumulate into
// both exporters' series, decorations reused.
func BenchmarkPoll_AllChanged(b *testing.B) {
	for _, keys := range benchSizes {
		b.Run(strconv.Itoa(keys), func(b *testing.B) {
			tf, ks := benchFamily(b, keys)
			tf.otelProducer(b, cumulative, 0)
			tf.promCollector(b, diskBounds, 0)
			tf.family.poll(tf.clock.Now())
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				for i, k := range ks {
					record(tf.m, tf.layout, k, i%benchCPUs, 4096, 200_000)
				}
				tf.clock.Advance(time.Second)
				b.StartTimer()
				tf.family.poll(tf.clock.Now())
			}
			perKey(b, keys)
		})
	}
}

// The first poll of new keys: decoration and projection for two exporters.
func BenchmarkPoll_NewKeys(b *testing.B) {
	for _, keys := range benchSizes {
		b.Run(strconv.Itoa(keys), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				b.StopTimer()
				tf, _ := benchFamily(b, keys)
				tf.otelProducer(b, cumulative, 0)
				tf.promCollector(b, diskBounds, 0)
				b.StartTimer()
				tf.family.poll(tf.clock.Now())
			}
			perKey(b, keys)
		})
	}
}

func BenchmarkProduce(b *testing.B) {
	for _, keys := range benchSizes {
		b.Run(strconv.Itoa(keys), func(b *testing.B) {
			tf, _ := benchFamily(b, keys)
			p := tf.otelProducer(b, cumulative, 0)
			ctx := context.Background()
			if _, err := p.Produce(ctx); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := p.Produce(ctx); err != nil {
					b.Fatal(err)
				}
			}
			perKey(b, keys)
		})
	}
}

func BenchmarkCollect(b *testing.B) {
	for _, keys := range benchSizes {
		b.Run(strconv.Itoa(keys), func(b *testing.B) {
			tf, _ := benchFamily(b, keys)
			reg := prometheus.NewRegistry()
			reg.MustRegister(tf.promCollector(b, diskBounds, 0))
			if _, err := reg.Gather(); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := reg.Gather(); err != nil {
					b.Fatal(err)
				}
			}
			perKey(b, keys)
		})
	}
}

// Many-CPU benchmarks: a per-CPU map holds a copy of every value per possible
// CPU, so what the Reader keeps per key, and what a poll reads, grow with the
// CPU count. Unless Sparse, every key has counted on every CPU, the worst
// case. retained-B/key is the heap the first poll leaves behind per key (Reader state, decorations,
// both exporters' series), without the map itself.

var cpuBenchSizes = []struct{ cpus, keys int }{{64, 1_000}, {64, 9_000}, {128, 1_000}, {128, 9_000}}

// benchFamilyCPUs makes keys that counted on spread CPUs each.
func benchFamilyCPUs(b *testing.B, cpus, keys, spread int) (*testFamily, [][]byte) {
	b.Helper()
	tf := newTestFamily(b, cpus, diskBounds, neverDelete)
	ks := make([][]byte, keys)
	for i := range ks {
		ks[i] = blkKey(uint32(i), ebpf.CodeBlockRead, 0)
		for n := range spread {
			record(tf.m, tf.layout, ks[i], (i+n)%cpus, 4096, 200_000)
		}
	}
	tf.otelProducer(b, cumulative, 0)
	tf.promCollector(b, diskBounds, 0)
	return tf, ks
}

// firstPoll polls tf once and returns a function that reports the heap the
// poll retained, to call after the timed loop (ResetTimer drops metrics).
func firstPoll(b *testing.B, tf *testFamily, keys int) (report func()) {
	b.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	tf.family.poll(tf.clock.Now())
	runtime.GC()
	runtime.ReadMemStats(&after)
	retained := float64(after.HeapAlloc) - float64(before.HeapAlloc)
	return func() {
		b.ReportMetric(retained/float64(keys), "retained-B/key")
		b.ReportMetric(retained/(1<<20), "retained-MiB")
	}
}

func cpuBenchName(cpus, keys int) string {
	return "cpus=" + strconv.Itoa(cpus) + "/keys=" + strconv.Itoa(keys)
}

func BenchmarkPollCPUs_Unchanged(b *testing.B) {
	for _, s := range cpuBenchSizes {
		b.Run(cpuBenchName(s.cpus, s.keys), func(b *testing.B) {
			benchPollUnchanged(b, s.cpus, s.keys, s.cpus)
		})
	}
}

// Keys that counted on 4 CPUs each, as a container's keys typically do: the
// CPUs that never counted for a key cost a comparison with zero.
func BenchmarkPollCPUs_UnchangedSparse(b *testing.B) {
	for _, s := range cpuBenchSizes {
		b.Run(cpuBenchName(s.cpus, s.keys), func(b *testing.B) {
			benchPollUnchanged(b, s.cpus, s.keys, 4)
		})
	}
}

func benchPollUnchanged(b *testing.B, cpus, keys, spread int) {
	b.Helper()
	tf, _ := benchFamilyCPUs(b, cpus, keys, spread)
	report := firstPoll(b, tf, keys)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		tf.clock.Advance(time.Second)
		tf.family.poll(tf.clock.Now())
	}
	perKey(b, keys)
	report()
}

// Every key counted one more request on one CPU since the last poll.
func BenchmarkPollCPUs_AllChanged(b *testing.B) {
	for _, s := range cpuBenchSizes {
		b.Run(cpuBenchName(s.cpus, s.keys), func(b *testing.B) {
			tf, ks := benchFamilyCPUs(b, s.cpus, s.keys, s.cpus)
			report := firstPoll(b, tf, s.keys)
			b.ReportAllocs()
			b.ResetTimer()
			for n := range b.N {
				b.StopTimer()
				for i, k := range ks {
					record(tf.m, tf.layout, k, (i+n)%s.cpus, 4096, 200_000)
				}
				tf.clock.Advance(time.Second)
				b.StartTimer()
				tf.family.poll(tf.clock.Now())
			}
			perKey(b, s.keys)
			report()
		})
	}
}
