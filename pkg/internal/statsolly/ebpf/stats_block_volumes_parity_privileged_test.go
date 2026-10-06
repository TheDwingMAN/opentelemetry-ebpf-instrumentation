// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"maps"
	"math"
	"os"
	"slices"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// blkParitySkew bounds how much the durations of one bio or request differ
// between two sets of programs attached side by side: each takes its own
// clock reads at the queueing and at the completion, one program run apart.
// That is a few hundred nanoseconds to a few microseconds on average, and up
// to 6 us were seen for a single discard completed by the loop worker.
const blkParitySkew = 20 * time.Microsecond

// blkParityKey is what the aggregation maps count a completion under.
type blkParityKey struct {
	dev, partDev uint32
	kind         uint8
	err          uint16
}

type blkParityValue struct {
	count, bytes, sumNs uint64
	buckets             []uint64
	// nearBound counts the events whose duration is within blkParitySkew
	// of a bound: the other programs may have put them in the next bucket.
	nearBound uint64
}

type blkParity map[blkParityKey]*blkParityValue

func (p blkParity) value(key blkParityKey, buckets int) *blkParityValue {
	v := p[key]
	if v == nil {
		v = &blkParityValue{buckets: make([]uint64, buckets)}
		p[key] = v
	}
	return v
}

func (p blkParity) clone() blkParity {
	c := blkParity{}
	for key, v := range p {
		cv := *v
		cv.buckets = slices.Clone(v.buckets)
		c[key] = &cv
	}
	return c
}

// since is what was counted after base, without the keys that counted
// nothing.
func (p blkParity) since(base blkParity) blkParity {
	d := blkParity{}
	for key, v := range p {
		b := base[key]
		if b == nil {
			b = &blkParityValue{buckets: make([]uint64, len(v.buckets))}
		}
		if v.count == b.count {
			continue
		}
		dv := d.value(key, len(v.buckets))
		dv.count, dv.bytes, dv.sumNs = v.count-b.count, v.bytes-b.bytes, v.sumNs-b.sumNs
		dv.nearBound = v.nearBound - b.nearBound
		for i := range v.buckets {
			dv.buckets[i] = v.buckets[i] - b.buckets[i]
		}
	}
	return d
}

// blkHistIdx is stat_hist_idx of bpf/statsolly/hist.h: the index of the
// first bound >= ns.
func blkHistIdx(bounds []uint64, ns uint64) int {
	i, _ := slices.BinarySearch(bounds, ns)
	return i
}

func blkNearBound(bounds []uint64, ns uint64) bool {
	for _, b := range bounds {
		if b == math.MaxUint64 {
			return false
		}
		if max(b, ns)-min(b, ns) <= uint64(blkParitySkew) {
			return true
		}
	}
	return false
}

// parityEvents is what the ring buffer events of some devices add up to, as
// the aggregation maps would count them.
type parityEvents struct {
	mu     sync.Mutex
	counts blkParity
	events uint64
}

func (e *parityEvents) snapshot() (blkParity, uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.counts.clone(), e.events
}

// collectParityEvents counts the block events of devs until the reader is
// closed, in the buckets of bounds.
func collectParityEvents(t *testing.T, reader *ringbuf.Reader, bounds []uint64, devs ...uint32) *parityEvents {
	t.Helper()

	events := &parityEvents{counts: blkParity{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var record ringbuf.Record
		for {
			if err := reader.ReadInto(&record); err != nil {
				return
			}
			if len(record.RawSample) < int(unsafe.Sizeof(StatsBlockIo{})) ||
				StatType(record.RawSample[0]) != StatTypeBlockIo {
				continue
			}
			event := (*StatsBlockIo)(unsafe.Pointer(&record.RawSample[0]))
			if !slices.Contains(devs, event.Dev) {
				continue
			}
			key := blkParityKey{dev: event.Dev, partDev: event.PartDev, kind: event.Op, err: blkErrnoKey(event.Error)}

			events.mu.Lock()
			v := events.counts.value(key, len(bounds)+1)
			v.count++
			v.bytes += event.Bytes
			v.sumNs += event.LatencyNs
			v.buckets[blkHistIdx(bounds, event.LatencyNs)]++
			if blkNearBound(bounds, event.LatencyNs) {
				v.nearBound++
			}
			events.events++
			events.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		reader.Close()
		<-done
	})
	return events
}

// blkErrnoKey is blk_agg_err: the errno of a completion's error, positive.
func blkErrnoKey(err int32) uint16 {
	e := int64(err)
	if e < 0 {
		e = -e
	}
	return uint16(min(e, math.MaxUint16))
}

// aggParity reads what the aggregation maps counted for devs.
func aggParity(t *testing.T, aggMaps *BlockAggMaps, devs ...uint32) blkParity {
	t.Helper()

	p := blkParity{}
	forEachAggValue(t, aggMaps.Service, func(key StatsBlkAggKey, bytes, sumNs uint64, buckets []uint32) {
		if !slices.Contains(devs, key.Dev) {
			return
		}
		v := p.value(blkParityKey{dev: key.Dev, partDev: key.PartDev, kind: key.Kind, err: key.Err}, len(buckets))
		v.bytes, v.sumNs = bytes, sumNs
		for i, b := range buckets {
			v.buckets[i] = uint64(b)
			v.count += uint64(b)
		}
	})
	return p
}

// waitEventsDrained waits until no more events arrive.
func waitEventsDrained(t *testing.T, events *parityEvents) {
	t.Helper()

	_, last := events.snapshot()
	for start := time.Now(); time.Since(start) < 10*time.Second; {
		time.Sleep(300 * time.Millisecond)
		_, n := events.snapshot()
		if n == last {
			return
		}
		last = n
	}
	t.Fatal("block events kept arriving")
}

// readErrors reads n blocks of a device whose every read fails.
func readErrors(t *testing.T, path string, n int) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	buf, err := unix.Mmap(-1, 0, loopBlockBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	defer func() { _ = unix.Munmap(buf) }()
	for i := range n {
		_, err := f.ReadAt(buf, int64(i*loopBlockBytes))
		require.ErrorIs(t, err, unix.EIO)
	}
}

// Kernel aggregation must count what the per-event path sends (spec: the
// aggregated output equals the per-event one). The statagg parity harness
// feeds synthetic events; here the programs themselves are compared on live
// I/O. Two fetchers are attached side by side, one sending events and one
// aggregating, so both measure the same bios and requests: reads, writes,
// fdatasync flushes, FUA writes and a discard on a linear volume, failed reads
// on an error volume, and the requests all that becomes on the loop device
// below. Each key (device, partition, kind, errno) must have the same count
// and bytes in both; durations may differ by the skew between the two
// programs' clock reads, so the sums and the buckets are compared within it.
func TestBlockVolumesAggregationMatchesEvents(t *testing.T) {
	const errorReads = 8
	for name, agg := range map[string]*BlockAggregation{
		"explicit":    aggForTest(false),
		"exponential": aggForTest(true),
	} {
		t.Run(name, func(t *testing.T) {
			aggregating := attachAggregatingBlockPrograms(t, volumeFeatures, agg)
			aggMaps := aggregating.BlockAggregation()
			require.NotNil(t, aggMaps)
			require.NotNil(t, aggMaps.Service, "the aggregating fetcher counts in the kernel maps")
			sending, reader := attachBlockPrograms(t, volumeFeatures)
			require.Nil(t, sending.BlockAggregation().Service, "the other one sends events")

			loop := newLoopDevice(t, 4*loopDiscardBytes)
			volume := linearVolume(t, loop)
			failing := dmVolume(t, "0 2048 error")
			trackNewVolumes(t, aggregating)
			trackNewVolumes(t, sending)
			devs := []uint32{volume.kernelDev, failing.kernelDev, loop.kernelDev}
			for _, fetcher := range []*StatsFetcher{aggregating, sending} {
				tracked := trackedVolumes(t, fetcher)
				require.Contains(t, tracked, volume.kernelDev)
				require.Contains(t, tracked, failing.kernelDev)
			}
			events := collectParityEvents(t, reader, agg.BoundsNs, devs...)

			idle := &blockEvents{}
			settle := func() (blkParity, blkParity) {
				for _, disk := range []*testDisk{volume, failing, loop} {
					disk.settle(t, idle)
				}
				waitEventsDrained(t, events)
				sent, _ := events.snapshot()
				return sent, aggParity(t, aggMaps, devs...)
			}
			sentBase, aggBase := settle()

			writeWithFdatasync(t, volume.path, loopWrites)
			writeDsync(t, volume.path, loopWrites/4)
			readBlocks(t, volume.path, loopReads)
			discard(t, volume.path, loopDiscardBytes, loopDiscardBytes)
			readErrors(t, failing.path, errorReads)

			sentNow, aggNow := settle()
			sent, aggregated := sentNow.since(sentBase), aggNow.since(aggBase)

			require.NotEmpty(t, sent)
			var volumeOps, failedOps uint64
			for key, v := range sent {
				switch {
				case key.dev == volume.kernelDev:
					volumeOps += v.count
				case key.dev == failing.kernelDev && key.err == uint16(unix.EIO):
					failedOps += v.count
				}
			}
			require.GreaterOrEqual(t, volumeOps, uint64(loopWrites+loopReads+1), "the volume's bios were sent")
			require.GreaterOrEqual(t, failedOps, uint64(errorReads), "the failed bios were sent, with their errno")

			assert.ElementsMatch(t, slices.Collect(maps.Keys(sent)), slices.Collect(maps.Keys(aggregated)),
				"the same keys in both modes")
			for key, want := range sent {
				got := aggregated[key]
				if got == nil {
					continue
				}
				assert.Equal(t, want.count, got.count, "count of %+v", key)
				assert.Equal(t, want.bytes, got.bytes, "bytes of %+v", key)

				skew := want.count * uint64(blkParitySkew)
				assert.LessOrEqual(t, max(want.sumNs, got.sumNs)-min(want.sumNs, got.sumNs), skew,
					"duration sum of %+v: %d ns sent, %d ns aggregated", key, want.sumNs, got.sumNs)

				var moved uint64
				for i := range want.buckets {
					moved += max(want.buckets[i], got.buckets[i]) - min(want.buckets[i], got.buckets[i])
				}
				// An event in the next bucket is one too few in one bucket
				// and one too many in the other.
				assert.LessOrEqual(t, moved, 2*want.nearBound, "buckets of %+v: sent %v, aggregated %v",
					key, want.buckets, got.buckets)
				t.Logf("%+v: %d ops, %d bytes; duration sum %d ns sent, %d aggregated; %d near a bound, %d moved",
					key, want.count, want.bytes, want.sumNs, got.sumNs, want.nearBound, moved)
			}

			assertNoBioInFlight(t, aggregating, devs...)
			assertNoBioInFlight(t, sending, devs...)
			assertNoDrops(t, aggregating.KernelDropsMap())
			assertNoDrops(t, sending.KernelDropsMap())
		})
	}
}
