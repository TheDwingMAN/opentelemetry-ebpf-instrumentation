// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"math"
	"os"
	"testing"
	"unsafe"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

const (
	loopReads           = 32
	diskstatReadSectors = 2
)

// blockAggCounts is what the aggregation maps counted for one device.
type blockAggCounts struct {
	reads, writes, flushes, discards uint64
	readBytes, writeBytes            uint64
	discardBytes, flushBytes         uint64
	failed                           uint64
	// queued is the number of reads and writes in the queue map; svcSumNs
	// the sum of every service time.
	queued   uint64
	svcSumNs uint64
}

// The same workloads as the per-event tests, counted in the kernel maps:
// every request diskstats accounts is counted once, in its kind's key, with
// its bytes, and no insert fails.
func TestBlockAggregationOnLoopDevice(t *testing.T) {
	for name, agg := range map[string]*BlockAggregation{
		"explicit":    aggForTest(false),
		"exponential": aggForTest(true),
	} {
		t.Run(name, func(t *testing.T) {
			fetcher := attachAggregatingBlockPrograms(t, export.FeatureStorageBlock, agg)
			maps := fetcher.BlockAggregation()
			require.NotNil(t, maps, "the block programs count in the aggregation maps")
			require.NotNil(t, maps.Queue, "queue.duration is on")

			loop := newLoopDevice(t, 4*loopDiscardBytes)
			idle := &blockEvents{}
			before, _ := loop.settle(t, idle)
			base := aggCounts(t, maps, loop.kernelDev)

			writeWithFdatasync(t, loop.path, loopWrites)
			readBlocks(t, loop.path, loopReads)
			discard(t, loop.path, loopDiscardBytes, loopDiscardBytes)
			after, _ := loop.settle(t, idle)
			got := aggCounts(t, maps, loop.kernelDev).since(base)

			delta := func(field int) uint64 { return after[field] - before[field] }
			require.NotZero(t, delta(diskstatWrites), "the workload reached the device")
			assert.Equal(t, delta(diskstatReads), got.reads, "one count per completed read request")
			assert.Equal(t, delta(diskstatWrites)-delta(diskstatFlushes), got.writes,
				"one count per completed write request; the empty preflush writes are flushes")
			assert.Equal(t, delta(diskstatWriteSectors)*diskstatSectorBytes, got.writeBytes)
			// udev may read the new device while the workload runs.
			assert.GreaterOrEqual(t, got.readBytes, uint64(loopReads*loopBlockBytes))
			assert.Equal(t, delta(diskstatReadSectors)*diskstatSectorBytes, got.readBytes)
			assert.Equal(t, delta(diskstatFlushes), got.flushes, "one count per completed flush")
			assert.Zero(t, got.flushBytes, "a flush moves no data")
			assert.Equal(t, delta(diskstatDiscards), got.discards)
			assert.Equal(t, uint64(loopDiscardBytes), got.discardBytes)
			assert.Zero(t, got.failed)
			assert.NotZero(t, got.svcSumNs)
			assert.LessOrEqual(t, got.queued, got.reads+got.writes, "only reads and writes have a queue wait")

			assertNothingInFlight(t, fetcher, loop.kernelDev)
			assertNoDrops(t, fetcher.KernelDropsMap())
			assert.NotEmpty(t, fetcher.BlockPrograms(), "the attached programs are reported")
		})
	}
}

// The per-event and aggregated modes are exclusive: in AGG mode no block
// event reaches the ring buffer.
func TestBlockAggregationSendsNoEvents(t *testing.T) {
	fetcher := attachAggregatingBlockPrograms(t, export.FeatureStorageBlock, aggForTest(false))
	reader, err := ringbuf.NewReader(fetcher.StatsEventsMap())
	require.NoError(t, err)
	loop := newLoopDevice(t, loopWrites*loopBlockBytes)
	events := collectBlockEvents(t, reader, loop.kernelDev)

	writeWithFdatasync(t, loop.path, loopWrites)
	_, seen := loop.settle(t, events)
	assert.Equal(t, blockEventCounts{}, seen)
}

func aggForTest(exponential bool) *BlockAggregation {
	size := blkExplicitBounds
	if exponential {
		size = blkExponentialBounds
	}
	bounds := make([]uint64, size)
	for i := range bounds {
		bounds[i] = math.MaxUint64
	}
	// 10 us, 100 us, 1 ms (and 0 for the exponential zero bucket).
	copy(bounds, []uint64{0, 10_000, 100_000, 1_000_000})
	return &BlockAggregation{Exponential: exponential, BoundsNs: bounds, BudgetBytes: 8 << 20}
}

func attachAggregatingBlockPrograms(t *testing.T, features export.Features, agg *BlockAggregation) *StatsFetcher {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs and set up block devices")
	}
	fetcher, err := NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{}, FsAggregation{}, NFSConfig{}, agg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	return fetcher
}

// aggCounts sums what the maps counted for dev, across CPUs and errnos.
func aggCounts(t *testing.T, maps *BlockAggMaps, dev uint32) blockAggCounts {
	t.Helper()

	var c blockAggCounts
	forEachAggValue(t, maps.Service, func(key StatsBlkAggKey, bytes, sumNs uint64, buckets []uint32) {
		if key.Dev != dev {
			return
		}
		var n uint64
		for _, b := range buckets {
			n += uint64(b)
		}
		if key.Err != 0 {
			c.failed += n
		}
		c.svcSumNs += sumNs
		switch StatsBlkIoOp(key.Kind) {
		case StatsBlkIoOpBlkOpRead:
			c.reads += n
			c.readBytes += bytes
		case StatsBlkIoOpBlkOpWrite:
			c.writes += n
			c.writeBytes += bytes
		case StatsBlkIoOpBlkOpFlush:
			c.flushes += n
			c.flushBytes += bytes
		case StatsBlkIoOpBlkOpDiscard:
			c.discards += n
			c.discardBytes += bytes
		default:
			t.Errorf("aggregation key with unknown kind %d", key.Kind)
		}
	})
	forEachQueueValue(t, maps.Queue, func(key StatsBlkAggKey, buckets []uint32) {
		if key.Dev != dev {
			return
		}
		for _, b := range buckets {
			c.queued += uint64(b)
		}
	})
	return c
}

func (c blockAggCounts) since(base blockAggCounts) blockAggCounts {
	return blockAggCounts{
		reads: c.reads - base.reads, writes: c.writes - base.writes,
		flushes: c.flushes - base.flushes, discards: c.discards - base.discards,
		readBytes: c.readBytes - base.readBytes, writeBytes: c.writeBytes - base.writeBytes,
		discardBytes: c.discardBytes - base.discardBytes, flushBytes: c.flushBytes - base.flushBytes,
		failed: c.failed - base.failed, queued: c.queued - base.queued, svcSumNs: c.svcSumNs - base.svcSumNs,
	}
}

// forEachAggValue visits every key of a blk_agg map, explicit or
// exponential, with its values summed across CPUs.
func forEachAggValue(t *testing.T, m *ciliumebpf.Map, fn func(StatsBlkAggKey, uint64, uint64, []uint32)) {
	t.Helper()

	var key StatsBlkAggKey
	if m.ValueSize() == uint32(unsafe.Sizeof(StatsBlkAggVal{})) {
		var perCPU []StatsBlkAggVal
		iter := m.Iterate()
		for iter.Next(&key, &perCPU) {
			var bytes, sum uint64
			buckets := make([]uint32, len(perCPU[0].SvcBkt))
			for _, v := range perCPU {
				bytes, sum = bytes+v.Bytes, sum+v.SvcSumNs
				for i, b := range v.SvcBkt {
					buckets[i] += b
				}
			}
			fn(key, bytes, sum, buckets)
		}
		require.NoError(t, iter.Err())
		return
	}
	var perCPU []StatsBlkAggExpVal
	iter := m.Iterate()
	for iter.Next(&key, &perCPU) {
		var bytes, sum uint64
		buckets := make([]uint32, len(perCPU[0].SvcBkt))
		for _, v := range perCPU {
			bytes, sum = bytes+v.Bytes, sum+v.SvcSumNs
			for i, b := range v.SvcBkt {
				buckets[i] += b
			}
		}
		fn(key, bytes, sum, buckets)
	}
	require.NoError(t, iter.Err())
}

func forEachQueueValue(t *testing.T, m *ciliumebpf.Map, fn func(StatsBlkAggKey, []uint32)) {
	t.Helper()

	var key StatsBlkAggKey
	if m.ValueSize() == uint32(unsafe.Sizeof(StatsBlkQueueAggVal{})) {
		var perCPU []StatsBlkQueueAggVal
		iter := m.Iterate()
		for iter.Next(&key, &perCPU) {
			buckets := make([]uint32, len(perCPU[0].QueueBkt))
			for _, v := range perCPU {
				for i, b := range v.QueueBkt {
					buckets[i] += b
				}
			}
			fn(key, buckets)
		}
		require.NoError(t, iter.Err())
		return
	}
	var perCPU []StatsBlkQueueAggExpVal
	iter := m.Iterate()
	for iter.Next(&key, &perCPU) {
		buckets := make([]uint32, len(perCPU[0].QueueBkt))
		for _, v := range perCPU {
			for i, b := range v.QueueBkt {
				buckets[i] += b
			}
		}
		fn(key, buckets)
	}
	require.NoError(t, iter.Err())
}

func assertNoDrops(t *testing.T, drops *ciliumebpf.Map) {
	t.Helper()

	for idx, name := range KernelDropReasons {
		var perCPU []uint64
		require.NoError(t, drops.Lookup(idx, &perCPU))
		var total uint64
		for _, n := range perCPU {
			total += n
		}
		assert.Zero(t, total, "failed inserts into %s", name)
	}
}

// readBlocks reads n blocks from the start of path with O_DIRECT.
func readBlocks(t *testing.T, path string, n int) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()

	buf, err := unix.Mmap(-1, 0, loopBlockBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	defer func() { _ = unix.Munmap(buf) }()

	for i := range n {
		_, err := f.ReadAt(buf, int64(i*loopBlockBytes))
		require.NoError(t, err)
	}
}

// The queue interval comes from the request's accounting start, so it exists
// exactly where the kernel wrote that start: every plain read on a device
// with queue/iostats=1 has a queue time, and none does with iostats=0, where
// the field holds a stale value from an earlier use of the tag.
func TestBlockQueueTimeFollowsIostats(t *testing.T) {
	spec := kernelBTF()
	if spec == nil {
		t.Skip("no kernel BTF")
	}
	if _, err := spec.AnyTypeByName("rqf_flags"); err != nil {
		t.Skip("the kernel BTF has no enum rqf_flags: no queue time is recorded on it")
	}
	fetcher := attachAggregatingBlockPrograms(t, export.FeatureStorageBlock, aggForTest(false))
	maps := fetcher.BlockAggregation()
	require.NotNil(t, maps)
	require.NotNil(t, maps.Queue, "queue.duration is on")

	loop := newLoopDevice(t, 4*loopDiscardBytes)
	idle := &blockEvents{}
	loop.settle(t, idle)

	setIostats := func(v string) {
		t.Helper()
		require.NoError(t, os.WriteFile(loop.sysQueue("iostats"), []byte(v), 0))
	}
	// The loop device stays after the test, for the next one to reuse.
	t.Cleanup(func() { _ = os.WriteFile(loop.sysQueue("iostats"), []byte("1"), 0) })
	// Reads only: no PREFLUSH or FUA, so queue.duration count == read count.
	for _, iostats := range []string{"1", "0"} {
		setIostats(iostats)
		loop.settle(t, idle)
		base := aggCounts(t, maps, loop.kernelDev)
		readBlocks(t, loop.path, loopReads)
		loop.settle(t, idle)
		got := aggCounts(t, maps, loop.kernelDev).since(base)

		require.GreaterOrEqual(t, got.reads, uint64(loopReads))
		if iostats == "1" {
			assert.Equal(t, got.reads, got.queued, "iostats=1: every read has a queue time")
		} else {
			assert.Zero(t, got.queued, "iostats=0: the stale start is not a queue time")
		}
	}
}
