// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package statagg

import (
	"context"
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
	tf := newTestFamily(b, benchCPUs, diskBounds, func(c *Config) {
		c.Deletable = func([]byte, int) bool { return false }
	})
	ks := make([][]byte, keys)
	for i := range ks {
		ks[i] = blkKey(uint32(i), ebpf.CodeBlockRead, 0)
		record(tf.m, tf.layout, ks[i], i%benchCPUs, 4096, 200_000)
	}
	return tf, ks
}

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
