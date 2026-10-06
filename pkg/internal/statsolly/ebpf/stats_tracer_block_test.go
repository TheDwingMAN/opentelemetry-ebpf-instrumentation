// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

// StatsBlockIo is maintained by hand; the bpf2go type is generated from
// block_io_t itself, so matching it field by field is the byte-match with C.
func TestStatsBlockIoMatchesGeneratedLayout(t *testing.T) {
	mirror := reflect.TypeFor[StatsBlockIo]()
	generated := reflect.TypeFor[StatsBlockIoT]()
	require.Equal(t, generated.Size(), mirror.Size(), "sizeof block_io_t")
	require.Equal(t, generated.NumField(), mirror.NumField())
	for i := range generated.NumField() {
		g, m := generated.Field(i), mirror.Field(i)
		assert.Equal(t, g.Name, m.Name)
		assert.Equal(t, g.Offset, m.Offset, "offset of %s", g.Name)
		assert.Equal(t, g.Type.Size(), m.Type.Size(), "size of %s", g.Name)
	}
}

func TestPlanBlockLoad(t *testing.T) {
	const sysfsEntries = 5000
	sysfs := func() uint32 { return sysfsEntries }
	noSysfs := func() uint32 {
		t.Fatal("sysfs must only be read for the request-keyed programs")
		return 0
	}
	requestKeyed := storagePlan{
		stages: []blockLoadStage{{sets: []blockProgramSet{
			tpBtfBlockPrograms(blockTracepointLayout{}), rawTpBlockPrograms(blockTracepointLayout{}),
		}}},
		layout: blockTracepointLayout{completeErrno: true},
	}
	classic := storagePlan{stages: []blockLoadStage{{sets: []blockProgramSet{classicBlockPrograms()}}}}

	t.Run("block off: every block map shrinks", func(t *testing.T) {
		plan := planBlockLoad(false, storagePlan{}, false, false, noSysfs)
		assert.Equal(t, map[string]uint32{
			StatsMapBlkRqInflight:       unusedMapEntries,
			StatsMapBlkRqInflightSector: unusedMapEntries,
			StatsMapBlkDevState:         unusedMapEntries,
		}, plan.mapEntries)
		assert.False(t, plan.wantQueueDepth)
	})

	t.Run("request-keyed programs: request map sized from sysfs, sector map idle", func(t *testing.T) {
		plan := planBlockLoad(true, requestKeyed, true, false, sysfs)
		assert.Equal(t, map[string]uint32{
			StatsMapBlkRqInflight:       sysfsEntries,
			StatsMapBlkRqInflightSector: unusedMapEntries,
			StatsMapBlkDevState:         unusedMapEntries,
		}, plan.mapEntries)
		assert.False(t, plan.wantQueueDepth)
		assert.True(t, plan.wantQueue)
		assert.True(t, plan.completeErrno, "the errno layout reaches the constants")
	})

	t.Run("classic tracepoints: request map idle, sector map keeps its size", func(t *testing.T) {
		plan := planBlockLoad(true, classic, true, false, noSysfs)
		assert.Equal(t, map[string]uint32{
			StatsMapBlkRqInflight: unusedMapEntries,
			StatsMapBlkDevState:   unusedMapEntries,
		}, plan.mapEntries)
	})

	t.Run("queue depth keeps the per-device counter map", func(t *testing.T) {
		plan := planBlockLoad(true, requestKeyed, true, true, sysfs)
		assert.NotContains(t, plan.mapEntries, StatsMapBlkDevState)
		assert.True(t, plan.wantQueueDepth)
	})
}

// Every map the plan sizes must exist in the collection, or every load fails.
func TestBlockLoadPlanMapsExist(t *testing.T) {
	requestKeyed := storagePlan{stages: []blockLoadStage{{sets: []blockProgramSet{rawTpBlockPrograms(blockTracepointLayout{})}}}}
	classic := storagePlan{stages: []blockLoadStage{{sets: []blockProgramSet{classicBlockPrograms()}}}}
	for _, plan := range []blockLoadPlan{
		planBlockLoad(false, storagePlan{}, false, false, nil),
		planBlockLoad(true, requestKeyed, false, false, func() uint32 { return minBlockInflightEntries }),
		planBlockLoad(true, classic, false, false, nil),
	} {
		spec, err := LoadStats()
		require.NoError(t, err)
		require.NoError(t, setMapEntries(spec, plan.mapEntries))
		for name, n := range plan.mapEntries {
			assert.Equal(t, n, spec.Maps[name].MaxEntries, name)
		}
	}
}

func TestSetMapEntriesUnknownMap(t *testing.T) {
	spec, err := LoadStats()
	require.NoError(t, err)
	assert.Error(t, setMapEntries(spec, map[string]uint32{"no_such_map": 1}))
}

func TestBlockInflightEntries(t *testing.T) {
	addDevice := func(t *testing.T, sysBlock, name, nrRequests string, hwQueues int) {
		t.Helper()
		queue := filepath.Join(sysBlock, name, "queue")
		require.NoError(t, os.MkdirAll(queue, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(queue, "nr_requests"), []byte(nrRequests), 0o644))
		for i := range hwQueues {
			require.NoError(t, os.MkdirAll(filepath.Join(sysBlock, name, "mq", strconv.Itoa(i)), 0o755))
		}
	}

	t.Run("sums nr_requests over hardware queues", func(t *testing.T) {
		sysBlock := t.TempDir()
		addDevice(t, sysBlock, "vda", "256\n", 4)
		addDevice(t, sysBlock, "vdb", "256\n", 4)
		addDevice(t, sysBlock, "nvme0n1", "1023\n", 4)
		// bio-based: no hardware queues, never reaches the request tracepoints
		addDevice(t, sysBlock, "dm-0", "128\n", 0)
		assert.Equal(t, uint32(2*256*4+1023*4), blockInflightEntries(sysBlock))
	})

	t.Run("small nodes get the minimum", func(t *testing.T) {
		sysBlock := t.TempDir()
		addDevice(t, sysBlock, "vda", "256\n", 1)
		assert.Equal(t, minBlockInflightEntries, blockInflightEntries(sysBlock))
	})

	t.Run("large nodes are capped", func(t *testing.T) {
		sysBlock := t.TempDir()
		for _, name := range []string{"nvme0n1", "nvme1n1", "nvme2n1"} {
			addDevice(t, sysBlock, name, "1023\n", 64)
		}
		assert.Equal(t, maxBlockInflightEntries, blockInflightEntries(sysBlock))
	})

	t.Run("unreadable values are skipped", func(t *testing.T) {
		sysBlock := t.TempDir()
		addDevice(t, sysBlock, "vda", "garbage", 4)
		addDevice(t, sysBlock, "vdb", "1024", 8)
		assert.Equal(t, uint32(1024*8), blockInflightEntries(sysBlock))
	})

	t.Run("no sysfs: the largest size", func(t *testing.T) {
		assert.Equal(t, maxBlockInflightEntries, blockInflightEntries(filepath.Join(t.TempDir(), "missing")))
	})
}

// Only the kinds some enabled metric uses cross the ring buffer.
func TestBlockEmitKinds(t *testing.T) {
	const (
		readWrite = 1<<StatsBlkIoOpBlkOpRead | 1<<StatsBlkIoOpBlkOpWrite
		flush     = 1 << StatsBlkIoOpBlkOpFlush
		discard   = 1 << StatsBlkIoOpBlkOpDiscard
	)
	for _, tc := range []struct {
		features export.Features
		want     uint8
	}{
		{export.FeatureStorageBlock, readWrite | flush | discard},
		{export.FeatureStorageBlockDuration, readWrite},
		{export.FeatureStorageBlockIo, readWrite},
		{export.FeatureStorageBlockQueue, readWrite},
		{export.FeatureStorageBlockErrors, readWrite},
		{export.FeatureStorageBlockQueueDepth, readWrite},
		{export.FeatureStorageBlockFlush, flush},
		{export.FeatureStorageBlockDiscard, discard},
		{export.FeatureStorageBlockFlush | export.FeatureStorageBlockDiscard, flush | discard},
		{export.FeatureStorageFS, 0},
	} {
		assert.Equal(t, tc.want, blockEmitKinds(tc.features), "features %b", tc.features)
	}
}

// blockWantPartition derives blk_want_part from attributes.select: on by
// default, nothing in disk's statsDiskAttributes selects obi.disk.partition
// (it is opt-in), and selecting it on just one of its metrics is enough.
func TestBlockWantPartition(t *testing.T) {
	selector := func(t *testing.T, sel attributes.Selection) *attributes.AttrSelector {
		t.Helper()
		p, err := attributes.NewAttrSelector(attributes.UndefinedGroup, &attributes.SelectorConfig{SelectionCfg: sel})
		require.NoError(t, err)
		return p
	}

	t.Run("default attribute set never selects it", func(t *testing.T) {
		assert.False(t, blockWantPartition(selector(t, nil)))
	})

	t.Run("selected on one metric is enough", func(t *testing.T) {
		sel := attributes.Selection{
			"obi.stat.disk.io": attributes.InclusionLists{Include: []string{"obi.disk.partition"}},
		}
		assert.True(t, blockWantPartition(selector(t, sel)))
	})

	t.Run("selected on a metric that does not carry it changes nothing", func(t *testing.T) {
		sel := attributes.Selection{
			"obi.stat.disk.queue.depth": attributes.InclusionLists{Include: []string{"obi.disk.partition"}},
		}
		assert.False(t, blockWantPartition(selector(t, sel)))
	})
}
