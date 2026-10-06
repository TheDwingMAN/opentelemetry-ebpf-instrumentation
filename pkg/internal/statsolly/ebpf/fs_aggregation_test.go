// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"math"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

// The map the programs do not add into is created with one entry, both of
// them in per-event mode.
func TestFsAccumEntries(t *testing.T) {
	unused := unusedMapEntries
	for _, tc := range []struct {
		name              string
		agg               FsAggregation
		explicit, expMaps bool
	}{
		{name: "per event"},
		{name: "explicit", agg: FsAggregation{Enabled: true}, explicit: true},
		{name: "exponential", agg: FsAggregation{Enabled: true, Exponential: true}, expMaps: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := LoadFsIo()
			require.NoError(t, err)
			full := spec.Maps[FsIoMapFsIoAccum].MaxEntries
			require.Greater(t, full, unused)
			require.NoError(t, setMapEntries(spec, fsAccumEntries(tc.agg)))

			assert.Equal(t, tc.explicit, spec.Maps[FsIoMapFsIoAccum].MaxEntries == full)
			assert.Equal(t, tc.expMaps, spec.Maps[FsIoMapFsIoAccumExp].MaxEntries == full)
			if tc.agg.Enabled {
				assert.Equal(t, full, spec.Maps[fsAccumMapName(tc.agg)].MaxEntries, "the map in use keeps its size")
			}
		})
	}
}

// The aggregation constants reach the filesystem programs: the mode, the
// layout and the bounds, padded with the largest value to the 128 entries of
// fs_bounds_ns, which the explicit layout's search reads the first 32 of.
func TestFsAggregationConstants(t *testing.T) {
	consts := statsConstants(&config.EBPFTracer{}, blockLoadPlan{},
		FsAggregation{Enabled: true, Exponential: true, BoundsNs: []uint64{0, 1000, 2000}})

	assert.Equal(t, uint8(FsIoFsEmitKindFsEmitAgg), consts["fs_emit_mode"])
	assert.Equal(t, uint8(1), consts["fs_hist_exp"])
	bounds, ok := consts["fs_bounds_ns"].([fsHistMaxBounds]uint64)
	require.True(t, ok)
	assert.Equal(t, []uint64{0, 1000, 2000}, bounds[:3])
	for _, b := range bounds[3:] {
		require.Equal(t, uint64(math.MaxUint64), b)
	}

	spec, err := LoadFsIo()
	require.NoError(t, err)
	v := spec.Variables["fs_bounds_ns"]
	require.NotNil(t, v)
	assert.EqualValues(t, unsafe.Sizeof(bounds), v.Size(), "fs_bounds_ns is k_stat_hist_exp_max_bounds wide")

	perEvent := statsConstants(&config.EBPFTracer{}, blockLoadPlan{}, FsAggregation{})
	assert.Equal(t, uint8(FsIoFsEmitKindFsEmitRingbuf), perEvent["fs_emit_mode"])
	assert.Equal(t, uint8(0), perEvent["fs_hist_exp"])
}

// fentry/fexit programs keep their start in task storage where the kernel
// lets them; kprobe programs, and fentry ones on a kernel that rejects task
// storage in tracing programs, in the fs_start hash map, which only then is
// swept.
func TestFsLoaderStartMap(t *testing.T) {
	fentry := fsAttachPlan{Fs: CodeFsNFS, Module: "nfs", UseFentry: true, ReadSym: "r", WriteSym: "w"}
	kprobe := fentry
	kprobe.UseFentry = false

	t.Run("task storage", func(t *testing.T) {
		l, _, specs := fakeFsLoader(t, nil)
		l.taskBTF = true
		assert.False(t, l.startsInHash(fentry))
		assert.True(t, l.startsInHash(kprobe))

		_, err := l.load(fentry)
		require.NoError(t, err)
		assert.Equal(t, uint8(1), taskBTFConst(t, (*specs)[0]))
	})

	t.Run("tracing programs cannot use task storage", func(t *testing.T) {
		l, _, specs := fakeFsLoader(t, nil)
		l.taskBTF = true
		load := l.newCollection
		l.newCollection = func(spec *ebpf.CollectionSpec, o ebpf.CollectionOptions) (*ebpf.Collection, error) {
			if taskBTFConst(t, spec) == 1 {
				_, _ = load(spec, o)
				return nil, errors.New("helper call to bpf_task_storage_get is not allowed")
			}
			return load(spec, o)
		}

		_, err := l.load(fentry)
		require.NoError(t, err)
		require.Len(t, *specs, 2)
		assert.Equal(t, uint8(1), taskBTFConst(t, (*specs)[0]))
		assert.Equal(t, uint8(0), taskBTFConst(t, (*specs)[1]), "loaded again with fs_start")
		assert.True(t, l.startsInHash(fentry), "for good")
	})

	t.Run("no task storage at all", func(t *testing.T) {
		l, _, _ := fakeFsLoader(t, nil)
		l.taskBTF = false
		assert.True(t, l.startsInHash(fentry))
	})

	t.Run("a failure task storage does not cause", func(t *testing.T) {
		l, _, _ := fakeFsLoader(t, nil)
		l.taskBTF = true
		l.newCollection = func(*ebpf.CollectionSpec, ebpf.CollectionOptions) (*ebpf.Collection, error) {
			return nil, errors.New("no memory")
		}
		_, err := l.load(fentry)
		require.ErrorContains(t, err, "no memory")
		assert.True(t, l.taskBTF, "task storage is kept for the next try")
	})
}

// taskBTFConst returns the fs_task_btf a load was given.
func taskBTFConst(t *testing.T, spec *ebpf.CollectionSpec) uint8 {
	t.Helper()
	v := spec.Variables[fsTaskBTFConst]
	require.NotNil(t, v)
	var b uint8
	require.NoError(t, v.Get(&b))
	return b
}

// A kernel without task storage maps gets a one-entry hash map in place of
// fs_start_task: the programs reference it, but no load with fs_task_btf
// clear reaches it.
func TestStubTaskStorage(t *testing.T) {
	spec, err := LoadFsIo()
	require.NoError(t, err)
	require.Equal(t, ebpf.TaskStorage, spec.Maps[FsIoMapFsStartTask].Type)

	stubTaskStorage(spec)
	m := spec.Maps[FsIoMapFsStartTask]
	assert.Equal(t, ebpf.Hash, m.Type)
	assert.Zero(t, m.Flags)
	assert.Equal(t, unusedMapEntries, m.MaxEntries)
}

// The sweep deletes the starts older than the maximum age and no other: not
// the recent ones, not the cleared ones, and a start whose call returned
// meanwhile is no error.
func TestSweepFsStarts(t *testing.T) {
	const now = uint64(3600 * time.Second)
	maxAge := 10 * time.Minute
	entries := map[uint64]FsIoFsStartVal{
		1: {Ts: now - uint64(maxAge) - 1},       // stale
		2: {Ts: now - uint64(maxAge)},           // exactly the age: kept
		3: {Ts: now - uint64(time.Second)},      // in flight
		4: {Ts: 0},                              // no start
		5: {Ts: now + uint64(time.Millisecond)}, // written after now was read
		6: {Ts: 1},                              // stale, returned meanwhile
	}
	seq := func(yield func(uint64, FsIoFsStartVal) bool) {
		for id, val := range entries {
			if !yield(id, val) {
				return
			}
		}
	}
	var deleted []uint64
	del := func(id uint64) error {
		if id == 6 {
			return ebpf.ErrKeyNotExist
		}
		deleted = append(deleted, id)
		return nil
	}

	n, err := sweepFsStarts(seq, del, now, maxAge)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, []uint64{1}, deleted)

	_, err = sweepFsStarts(seq, func(uint64) error { return errors.New("boom") }, now, maxAge)
	assert.ErrorContains(t, err, "boom")
}

// fs_start is swept on every refresh while an attached filesystem keeps its
// starts there (kprobes), and not while every one uses task storage.
func TestFsAttacherSweepsOnlyTheHashStartMap(t *testing.T) {
	n := newFakeNode()
	n.probeable[CodeFsExt4] = true
	n.probeable[CodeFsXFS] = true
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	a := n.attacher()
	sweeps := 0
	a.sweepStarts = func() (int, error) { sweeps++; return 0, nil }

	a.refresh() // ext4 attached on fentry: task storage
	a.refresh()
	assert.Zero(t, sweeps, "no filesystem keeps its starts in fs_start")

	n.rejectFentry[CodeFsXFS] = errFentryUnsupported
	n.pvs[CodeFsXFS] = true
	a.refresh() // xfs attached on kprobes
	require.True(t, attachedSet(a)[CodeFsXFS])
	a.refresh()
	assert.Equal(t, 1, sweeps, "swept once xfs keeps its starts there")

	delete(n.pvs, CodeFsXFS)
	refreshToDetach(a)
	sweeps = 0
	a.refresh()
	assert.Zero(t, sweeps, "xfs detached: nothing keeps its starts in fs_start")

	closeAttacher(t, a)
}

// dropsRecorder records the storage drops reported as internal metrics.
type dropsRecorder struct {
	imetrics.NoopReporter
	drops map[string]uint64
}

func (r *dropsRecorder) BpfStorageDrops(reason string, dropped uint64) {
	r.drops[reason] += dropped
}

// Drops are logged and reported per reason when they grow, and each refresh
// adds only what grew since the last one to the internal metric.
func TestFsAttacherLogsDrops(t *testing.T) {
	n := newFakeNode()
	a := n.attacher()
	metrics := &dropsRecorder{drops: map[string]uint64{}}
	a.metrics = metrics
	drops := []uint64{0, 0}
	a.readDrops = func() ([]uint64, error) { return append([]uint64(nil), drops...), nil }

	a.refresh()
	assert.Equal(t, []uint64{0, 0}, a.loggedDrops)
	assert.Empty(t, metrics.drops, "nothing reported before a drop")
	drops[0] = 3
	a.refresh()
	assert.Equal(t, []uint64{3, 0}, a.loggedDrops)
	assert.Equal(t, map[string]uint64{"fs_accum_full": 3}, metrics.drops)
	drops[1] = 1
	a.refresh()
	assert.Equal(t, []uint64{3, 1}, a.loggedDrops)
	assert.Equal(t, map[string]uint64{"fs_accum_full": 3, "fs_start_failed": 1}, metrics.drops)
	drops[0] = 5
	a.refresh()
	assert.Equal(t, map[string]uint64{"fs_accum_full": 5, "fs_start_failed": 1}, metrics.drops,
		"the counter follows the kernel total, adding only the growth")
	a.readDrops = func() ([]uint64, error) { return nil, errors.New("map closed") }
	a.refresh()
	assert.Equal(t, map[string]uint64{"fs_accum_full": 5, "fs_start_failed": 1}, metrics.drops,
		"a failed read reports nothing")

	closeAttacher(t, a)
}

// Every fs_drop_reason has its own bpf.drop.reason value.
func TestFsDropReasonLabels(t *testing.T) {
	seen := map[string]bool{}
	for reason := range FsIoFsDropReasonFsDropReasons {
		label := fsDropReasonLabel(reason)
		assert.NotEqual(t, "fs_unknown", label, "reason %d", reason)
		assert.False(t, seen[label], "reason %d repeats %q", reason, label)
		seen[label] = true
	}
}

// The sync probes keep starts in fs_start even when no filesystem does, so
// the sweep runs with an empty hashStarts.
func TestFsAttacherSweepsForSyncHashStarts(t *testing.T) {
	n := newFakeNode()
	a := n.attacher()
	sweeps := 0
	a.sweepStarts = func() (int, error) { sweeps++; return 0, nil }

	a.maintain()
	assert.Zero(t, sweeps)
	a.syncHashStarts = true
	a.maintain()
	assert.Equal(t, 1, sweeps)
	closeAttacher(t, a)
}
