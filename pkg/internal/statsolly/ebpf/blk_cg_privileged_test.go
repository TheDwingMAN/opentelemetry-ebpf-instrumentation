// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
)

// Without storage_block_pod the issue reads no cgroup and the completion
// updates no blk_cg_agg key: the map has one entry and stays empty, and the
// fetcher hands no pod map to the exporters.
func TestBlockPodOffCountsNothingPerCgroup(t *testing.T) {
	fetcher := attachAggregatingBlockPrograms(t, export.FeatureStorageBlock, aggForTest(false))
	require.Nil(t, fetcher.BlockAggregation().Cgroup)
	assert.Equal(t, uint32(1), fetcher.objects.BlkCgAgg.MaxEntries())

	loop := newLoopDevice(t, 64*loopBlockBytes)
	idle := &blockEvents{}
	loop.settle(t, idle)
	for i := range 16 {
		writeDirectAt(t, loop.path, int64(i*loopBlockBytes), loopBlockBytes)
	}
	readBlocks(t, loop.path, 8)
	loop.settle(t, idle)

	assert.Empty(t, cgCounts(t, fetcher.objects.BlkCgAgg, loop.kernelDev))
}

// The cgroup the pod counters charge a read or write to is the one its bio
// belongs to: for direct I/O, the submitter's. The tp_btf programs read it
// with direct loads, the raw_tp fallback through bpf_probe_read_kernel: each
// set is attached alone to a collection of its own and must count the same.
func TestBlockPodChargesTheSubmittersCgroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs and set up block devices")
	}
	self := ownCgroupID(t)
	storage := planStorage(true, kernelBTF(), quietLog)
	if len(storage.stages) == 0 || storage.stages[0].sets[0].attach == blockAttachClassic {
		t.Skip("the classic block tracepoints read no cgroup")
	}
	for _, set := range storage.stages[0].sets {
		t.Run(set.attach.String(), func(t *testing.T) {
			objects := loadPodCountingObjects(t, storage)
			links, err := attachBlockProgramSet(blockPrograms(&objects.StatsPrograms), set)
			require.NoError(t, err)
			t.Cleanup(func() { closeAll(links) })

			const writes, reads = 16, 8
			loop := newLoopDevice(t, 64*loopBlockBytes)
			idle := &blockEvents{}
			loop.settle(t, idle)
			base := cgCounts(t, objects.BlkCgAgg, loop.kernelDev)
			start := time.Now()
			for i := range writes {
				writeDirectAt(t, loop.path, int64(i*loopBlockBytes), loopBlockBytes)
			}
			readBlocks(t, loop.path, reads)
			elapsed := time.Since(start)
			loop.settle(t, idle)
			got := cgCounts(t, objects.BlkCgAgg, loop.kernelDev).since(base)

			mine := got[cgKey{cgid: self, kind: uint8(StatsBlkIoOpBlkOpWrite)}]
			assert.Equal(t, uint64(writes), mine.count, "every write is charged to the writer's cgroup")
			assert.Equal(t, uint64(writes*loopBlockBytes), mine.bytes)
			assert.Positive(t, mine.timeNs)
			assert.Less(t, mine.timeNs, uint64(elapsed), "operation time is within the writes' run")
			assert.Equal(t, uint64(reads), got[cgKey{cgid: self, kind: uint8(StatsBlkIoOpBlkOpRead)}].count)
			// udev probes a block device again when a writer closes it (its
			// watch rule), with reads of its own: those are charged, rightly,
			// to udev's cgroup. Nothing this test wrote may be charged there.
			for key, c := range got {
				if key.cgid != self {
					assert.Equal(t, uint8(StatsBlkIoOpBlkOpRead), key.kind,
						"only another process's reads may be charged elsewhere: %+v %+v", key, c)
				}
			}
			assertNoDrops(t, objects.StatsDrops)
		})
	}
}

// TestBlockPodProgramCost measures what the cgroup read at issue and the
// blk_cg_agg update at completion add to a request (spec step 21 perf: K-ns
// against step 6), with the tp_btf programs on a loop device, the flag off
// and on, under concurrent direct reads. It reports the numbers; the lab
// gate is the device IOPS.
func TestBlockPodProgramCost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs and set up block devices")
	}
	storage := planStorage(true, kernelBTF(), quietLog)
	if len(storage.stages) == 0 || storage.stages[0].sets[0].attach != blockAttachTpBtf {
		t.Skip("the tp_btf block programs are not available")
	}
	stats, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		t.Skipf("can't enable BPF run time statistics: %v", err)
	}
	defer stats.Close()

	const (
		requests = 100_000
		readers  = 8
	)
	loop := newLoopDevice(t, requests*loopBlockBytes)
	measure := func(pod bool) (issue, complete float64) {
		t.Helper()
		objects := loadCountingObjects(t, storage, pod)
		set := storage.stages[0].sets[0]
		programs := blockPrograms(&objects.StatsPrograms)
		links, err := attachBlockProgramSet(programs, set)
		require.NoError(t, err)
		defer closeAll(links)

		idle := &blockEvents{}
		readBlocksConcurrently(t, loop.path, requests/10, readers)
		loop.settle(t, idle)
		before := map[string]*ebpf.ProgramStats{}
		for _, name := range set.programs() {
			before[name], err = programs[name].Stats()
			require.NoError(t, err)
		}
		readBlocksConcurrently(t, loop.path, requests, readers)
		loop.settle(t, idle)
		perRun := func(name string) float64 {
			now, err := programs[name].Stats()
			require.NoError(t, err)
			runs := now.RunCount - before[name].RunCount
			require.GreaterOrEqual(t, runs, uint64(requests))
			return float64(now.Runtime-before[name].Runtime) / float64(runs)
		}
		return perRun(set.issue), perRun(set.complete)
	}
	offIssue, offComplete := measure(false)
	onIssue, onComplete := measure(true)
	t.Logf("tp_btf, %d direct 4 KiB reads from %d readers, mean ns per run: storage_block_pod off: issue %.1f complete %.1f;"+
		" on: issue %.1f complete %.1f; per request %+.1f ns",
		requests, readers, offIssue, offComplete, onIssue, onComplete, onIssue+onComplete-offIssue-offComplete)
}

// loadPodCountingObjects loads the stats collection as NewStatsFetcher would
// with storage_block_pod and storage_block_io on, in the per-event emit mode
// with nothing emitted, attaching nothing.
func loadPodCountingObjects(t *testing.T, storage storagePlan) *StatsObjects {
	t.Helper()
	return loadCountingObjects(t, storage, true)
}

func loadCountingObjects(t *testing.T, storage storagePlan, pod bool) *StatsObjects {
	t.Helper()
	blockLoad := planBlockLoad(true, storage, false, false, func() uint32 { return minBlockInflightEntries })
	blockLoad.wantCgroup = pod
	blockLoad.agg = planBlockAgg(nil, false, 0, 1, 0, possibleCPUs(), false, blockLoad.mapEntries, quietLog)
	planBlockCgroup(pod, 1, possibleCPUs(), 0, 8<<20, blockLoad.mapEntries, quietLog)
	cfg := &config.EBPFTracer{}
	objects := &StatsObjects{}
	require.NoError(t, loadStatsObjects(cfg, blockLoad, statsConstants(cfg, blockLoad, FsAggregation{}), storage.firstLoadDisable(),
		objects, map[string]*ebpf.Map{}, &sync.Mutex{}, nil))
	t.Cleanup(func() { objects.Close() })
	return objects
}

type cgKey struct {
	cgid uint64
	kind uint8
}

type cgCount struct{ count, bytes, timeNs uint64 }

type cgCountsByKey map[cgKey]cgCount

func (c cgCountsByKey) since(base cgCountsByKey) cgCountsByKey {
	out := cgCountsByKey{}
	for k, v := range c {
		b := base[k]
		if d := (cgCount{v.count - b.count, v.bytes - b.bytes, v.timeNs - b.timeNs}); d.count != 0 {
			out[k] = d
		}
	}
	return out
}

// cgCounts sums blk_cg_agg's per-CPU values for dev by cgroup and kind.
func cgCounts(t *testing.T, m *ebpf.Map, dev uint32) cgCountsByKey {
	t.Helper()
	out := cgCountsByKey{}
	var (
		key    StatsBlkCgKey
		values []StatsBlkCgVal
	)
	iter := m.Iterate()
	for iter.Next(&key, &values) {
		if key.Dev != dev {
			continue
		}
		k := cgKey{cgid: key.Cgid, kind: uint8(key.Kind)}
		c := out[k]
		for _, v := range values {
			c.count += v.Count
			c.bytes += v.Bytes
			c.timeNs += v.TimeNs
		}
		out[k] = c
	}
	require.NoError(t, iter.Err())
	return out
}

// ownCgroupID is this process's cgroup v2 id, bpf_get_current_cgroup_id():
// the inode of its directory.
func ownCgroupID(t *testing.T) uint64 {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		path, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		var st unix.Stat_t
		if err := unix.Stat(filepath.Join("/sys/fs/cgroup", path), &st); err != nil {
			t.Skipf("can't read this process's cgroup: %v", err)
		}
		return st.Ino
	}
	t.Skip("no cgroup v2 hierarchy")
	return 0
}
