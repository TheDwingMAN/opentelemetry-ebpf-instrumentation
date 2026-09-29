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
		t.Fatal("sysfs must only be read for the raw tracepoints")
		return 0
	}

	t.Run("block off: every block map shrinks", func(t *testing.T) {
		plan := planBlockLoad(false, false, false, noSysfs)
		assert.Equal(t, map[string]uint32{
			StatsMapBlkRqInflight:       unusedMapEntries,
			StatsMapBlkRqInflightSector: unusedMapEntries,
			StatsMapBlkInsert:           unusedMapEntries,
			StatsMapBlkDevState:         unusedMapEntries,
		}, plan.mapEntries)
		assert.False(t, plan.wantQueueDepth)
	})

	t.Run("raw tracepoints: request map sized from sysfs, sector map idle", func(t *testing.T) {
		plan := planBlockLoad(true, true, false, sysfs)
		assert.Equal(t, map[string]uint32{
			StatsMapBlkRqInflight:       sysfsEntries,
			StatsMapBlkRqInflightSector: unusedMapEntries,
			StatsMapBlkDevState:         unusedMapEntries,
		}, plan.mapEntries)
		assert.False(t, plan.wantQueueDepth)
	})

	t.Run("classic tracepoints: request map idle, sector map keeps its size", func(t *testing.T) {
		plan := planBlockLoad(true, false, false, noSysfs)
		assert.Equal(t, map[string]uint32{
			StatsMapBlkRqInflight: unusedMapEntries,
			StatsMapBlkDevState:   unusedMapEntries,
		}, plan.mapEntries)
	})

	t.Run("queue depth keeps the per-device counter map", func(t *testing.T) {
		plan := planBlockLoad(true, true, true, sysfs)
		assert.NotContains(t, plan.mapEntries, StatsMapBlkDevState)
		assert.True(t, plan.wantQueueDepth)
	})
}

// Every map the plan sizes must exist in the collection, or every load fails.
func TestBlockLoadPlanMapsExist(t *testing.T) {
	for _, plan := range []blockLoadPlan{
		planBlockLoad(false, false, false, nil),
		planBlockLoad(true, true, false, func() uint32 { return minBlockInflightEntries }),
		planBlockLoad(true, false, false, nil),
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
