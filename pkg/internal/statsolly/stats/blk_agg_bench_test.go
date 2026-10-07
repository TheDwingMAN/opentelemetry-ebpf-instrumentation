// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
)

// The userspace cost of the aggregated block metrics on a busy node: one
// Prometheus scrape plus one OTel collection that read the kernel maps of 6
// disks, every kind of request, with two failing keys, where every key
// counted on every CPU since the previous read. It does not grow with the
// request rate: at 500k requests a second and a 15 s scrape, one op is the
// cost of 7.5M requests. The in-memory maps sort their keys on every walk,
// which the kernel's batch lookup does not; BenchmarkMapSource_BlkAgg
// (statagg, privileged) measures the real map read.
func BenchmarkBlockFamilies_Scrape(b *testing.B) {
	for _, cpus := range []int{4, 128} {
		b.Run("cpus="+strconv.Itoa(cpus), func(b *testing.B) {
			bb := newBlockBench(b, cpus)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				bb.count()
				b.StartTimer()
				bb.scrape()
			}
		})
	}
}

// The same scrape when no request completed since the previous one.
func BenchmarkBlockFamilies_ScrapeIdle(b *testing.B) {
	bb := newBlockBench(b, 128)
	bb.count()
	bb.scrape()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		bb.scrape()
	}
}

type blockBench struct {
	b          *testing.B
	svc, queue *stataggtest.MemMap
	layout     *statagg.Layout
	now        time.Time
	reg        *prometheus.Registry
	producer   *statagg.Producer
	keys       [][]byte
	cpus       int
}

func newBlockBench(b *testing.B, cpus int) *blockBench {
	b.Helper()
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(b, err)
	bb := &blockBench{
		b:      b,
		svc:    stataggtest.NewMemMap(blkKeySize, int(unsafe.Sizeof(ebpf.StatsBlkAggVal{})), cpus),
		queue:  stataggtest.NewMemMap(blkKeySize, int(unsafe.Sizeof(ebpf.StatsBlkQueueAggVal{})), cpus),
		layout: layout,
		now:    time.Unix(1_700_000_000, 0),
		cpus:   cpus,
	}
	for d := range uint32(6) {
		for _, kind := range []ebpf.BlockOpCode{ebpf.CodeBlockRead, ebpf.CodeBlockWrite, ebpf.CodeBlockFlush, ebpf.CodeBlockDiscard} {
			bb.keys = append(bb.keys, blockKey(253<<20|d*16, uint8(kind), 0))
		}
	}
	bb.keys = append(bb.keys, blockKey(253<<20, uint8(ebpf.CodeBlockRead), 5),
		blockKey(253<<20|16, uint8(ebpf.CodeBlockFlush), 5))

	keep := func(*ebpf.Stat) bool { return true }
	families, err := blockFamilies(bb.svc, bb.queue, layout, allBlockFeatures,
		func() (func(*ebpf.Stat) bool, error) { return keep, nil }, func() time.Time { return bb.now })
	require.NoError(b, err)
	registry, err := statagg.NewRegistry(families...)
	require.NoError(b, err)

	names := []attributes.Name{
		attributes.StatDiskOperationDuration, attributes.StatDiskIO, attributes.StatDiskQueueDuration,
		attributes.StatDiskOperationErrors, attributes.StatDiskFlushDuration, attributes.StatDiskDiscardDuration,
		attributes.StatDiskDiscardIO,
	}
	bounds := export.DefaultBuckets.StatDiskOperationDurationHistogram
	collector := statagg.NewCollector(registry, time.Hour)
	bb.producer = statagg.NewProducer(registry, "bench",
		func(sdkmetric.InstrumentKind) metricdata.Temporality { return metricdata.CumulativeTemporality }, time.Hour)
	for _, name := range names {
		require.NoError(b, collector.Add(name, statagg.PromMetric{
			Help: "h", Bounds: bounds, LabelNames: []string{"system_device", "disk_io_direction", "error_type"},
			Project: func(s *ebpf.Stat) (string, []string) {
				values := []string{
					strconv.Itoa(int(s.BlockIo.Dev)), strconv.Itoa(int(s.BlockIo.Op)),
					strconv.Itoa(int(s.BlockIo.Error)),
				}
				return statagg.SeriesKey(values), values
			},
		}))
		require.NoError(b, bb.producer.Add(name, statagg.OTelMetric{
			Bounds: bounds,
			Project: func(s *ebpf.Stat) (string, attribute.Set) {
				values := []string{strconv.Itoa(int(s.BlockIo.Dev)), strconv.Itoa(int(s.BlockIo.Op))}
				return statagg.SeriesKey(values), attribute.NewSet(
					attribute.String("system.device", values[0]), attribute.String("disk.io.direction", values[1]))
			},
		}))
	}
	bb.reg = prometheus.NewRegistry()
	require.NoError(b, bb.reg.Register(collector))
	for _, f := range families {
		go f.Run(b.Context())
	}
	// Run marks the families started asynchronously: wait for a scrape
	// that reads the maps.
	bb.count()
	require.Eventually(b, func() bool {
		bb.now = bb.now.Add(time.Second)
		mfs, err := bb.reg.Gather()
		return err == nil && len(mfs) > 0
	}, 5*time.Second, 10*time.Millisecond)
	return bb
}

// count adds one completion of every key on every CPU, the worst case of a
// busy node where every CPU completes requests for every device.
func (bb *blockBench) count() {
	const counter, bucket = 8, 4
	for i, k := range bb.keys {
		for cpu := range bb.cpus {
			bb.svc.AddU64(k, cpu, blkWordBytes*counter, 4096)
			bb.svc.AddU64(k, cpu, blkWordSvcSum*counter, 200_000+uint64(i))
			bb.svc.AddU32(k, cpu, blkWordSvcFirst*counter+(i%bb.layout.Buckets())*bucket, 1)
			if k[blkKeyKind] <= uint8(ebpf.CodeBlockWrite) {
				bb.queue.AddU64(k, cpu, blkWordQueueSum*counter, 30_000)
				bb.queue.AddU32(k, cpu, blkWordQueueFirst*counter+(i%bb.layout.Buckets())*bucket, 1)
			}
		}
	}
}

// scrape is one Prometheus scrape and one OTel collection, 15 s after the
// previous ones: the first reads the maps.
func (bb *blockBench) scrape() {
	bb.now = bb.now.Add(15 * time.Second)
	if _, err := bb.reg.Gather(); err != nil {
		bb.b.Fatal(err)
	}
	if _, err := bb.producer.Produce(bb.b.Context()); err != nil {
		bb.b.Fatal(err)
	}
}
