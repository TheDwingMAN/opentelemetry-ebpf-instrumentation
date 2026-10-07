// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"encoding/binary"
	"io"
	"log/slog"
	"math/bits"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

const allKinds = 1<<StatsBlkIoOpBlkOpRead | 1<<StatsBlkIoOpBlkOpWrite |
	1<<StatsBlkIoOpBlkOpFlush | 1<<StatsBlkIoOpBlkOpDiscard

func explicitAgg(budget uint64) *BlockAggregation {
	bounds := make([]uint64, blkExplicitBounds)
	for i := range bounds {
		bounds[i] = ^uint64(0)
	}
	bounds[0], bounds[1] = 1000, 2000
	return &BlockAggregation{BoundsNs: bounds, BudgetBytes: budget}
}

func TestPlanBlockAgg_PerEvent(t *testing.T) {
	entries := map[string]uint32{}
	plan := planBlockAgg(nil, true, allKinds, 6, 0, 128, false, entries, quietLog)
	assert.Equal(t, map[string]uint32{
		StatsMapBlkAgg: unusedMapEntries, StatsMapBlkQ_agg: unusedMapEntries,
		StatsMapBlkAggExp: unusedMapEntries, StatsMapBlkQ_aggExp: unusedMapEntries,
	}, entries, "no aggregation map costs memory")

	consts := plan.constants()
	assert.Equal(t, uint8(StatsBlkEmitK_blkEmitRingbuf), consts["blk_emit_mode"])
	assert.Equal(t, uint8(0), consts["blk_hist_exp"])
}

// A node with 6 devices, all 4 kinds: the service map holds a key per kind
// for those devices and for 32 disks attached later, plus 32 errno keys; the
// queue map the same for reads and writes only. At 128 possible CPUs both
// fit in the default 8 MiB budget.
func TestPlanBlockAgg_SizedFromTheDevices(t *testing.T) {
	entries := map[string]uint32{}
	plan := planBlockAgg(explicitAgg(8<<20), true, allKinds, 6, 0, 128, false, entries, quietLog)
	const devices = 6 + blkAggHotplugDevices
	assert.Equal(t, map[string]uint32{
		StatsMapBlkAgg: 4*devices + blkAggErrorKeys, StatsMapBlkQ_agg: 2*devices + blkAggErrorKeys,
		StatsMapBlkAggExp: unusedMapEntries, StatsMapBlkQ_aggExp: unusedMapEntries,
	}, entries)
	allocated := perCPUBytes(entries[StatsMapBlkAgg], blkAggExplicit.serviceValue, 128) +
		perCPUBytes(entries[StatsMapBlkQ_agg], blkAggExplicit.queueValue, 128)
	assert.LessOrEqual(t, allocated, uint64(8<<20))
	assert.Equal(t, uint64(184*152*128), perCPUBytes(entries[StatsMapBlkAgg], blkAggExplicit.serviceValue, 128))
	assert.True(t, plan.queue)

	consts := plan.constants()
	assert.Equal(t, uint8(StatsBlkEmitK_blkEmitAgg), consts["blk_emit_mode"])
	assert.Equal(t, uint8(0), consts["blk_hist_exp"])
	bounds := consts["blk_bounds_ns"].([blkExplicitBounds]uint64)
	assert.Equal(t, uint64(1000), bounds[0])
	assert.Equal(t, ^uint64(0), bounds[2])
}

func TestPlanBlockAgg_OnlyTheEmittedKindsAndNoQueueMap(t *testing.T) {
	entries := map[string]uint32{}
	readWrite := uint8(1<<StatsBlkIoOpBlkOpRead | 1<<StatsBlkIoOpBlkOpWrite)
	plan := planBlockAgg(explicitAgg(8<<20), false, readWrite, 10, 0, 4, false, entries, quietLog)
	assert.Equal(t, uint32(2*(10+blkAggHotplugDevices)+blkAggErrorKeys), entries[StatsMapBlkAgg])
	assert.Equal(t, unusedMapEntries, entries[StatsMapBlkQ_agg], "no queue wait, no queue map")
	assert.False(t, plan.queue)

	// Flushes alone never reach the queue map.
	entries = map[string]uint32{}
	plan = planBlockAgg(explicitAgg(8<<20), true, 1<<StatsBlkIoOpBlkOpFlush, 10, 0, 4, false, entries, quietLog)
	assert.Equal(t, unusedMapEntries, entries[StatsMapBlkQ_agg])
	assert.False(t, plan.queue)
}

func TestPlanBlockAgg_Exponential(t *testing.T) {
	agg := &BlockAggregation{Exponential: true, BoundsNs: make([]uint64, blkExponentialBounds), BudgetBytes: 8 << 20}
	agg.BoundsNs[5] = 42
	entries := map[string]uint32{}
	plan := planBlockAgg(agg, true, allKinds, 2, 0, 8, false, entries, quietLog)
	const devices = 2 + blkAggHotplugDevices
	assert.Equal(t, map[string]uint32{
		StatsMapBlkAgg: unusedMapEntries, StatsMapBlkQ_agg: unusedMapEntries,
		StatsMapBlkAggExp: 4*devices + blkAggErrorKeys, StatsMapBlkQ_aggExp: 2*devices + blkAggErrorKeys,
	}, entries)

	consts := plan.constants()
	assert.Equal(t, uint8(1), consts["blk_hist_exp"])
	assert.Equal(t, uint64(42), consts["blk_exp_bounds_ns"].([blkExponentialBounds]uint64)[5])
	assert.Equal(t, [blkExplicitBounds]uint64{}, consts["blk_bounds_ns"])
}

// A budget that can't hold every key the devices may need caps the maps,
// first the room for later disks, then the devices present; one that can't
// hold even the errno keys still leaves one key.
func TestPlanBlockAgg_BudgetClamp(t *testing.T) {
	svc, queue := uint64(unsafe.Sizeof(StatsBlkAggVal{})*128), uint64(unsafe.Sizeof(StatsBlkQueueAggVal{})*128)
	errorKeys := blkAggErrorKeys * (svc + queue)
	perDevice := 4*svc + 2*queue

	for name, tc := range map[string]struct {
		budget      uint64
		devicesFit  int
		wantService uint32
	}{
		"room for 10 later disks": {errorKeys + perDevice*16, 16, 4*16 + blkAggErrorKeys},
		"not all present devices": {errorKeys + perDevice*3, 3, 4*3 + blkAggErrorKeys},
		"only the errno keys":     {errorKeys, 0, blkAggErrorKeys},
	} {
		t.Run(name, func(t *testing.T) {
			entries := map[string]uint32{}
			planBlockAgg(explicitAgg(tc.budget), true, allKinds, 6, 0, 128, false, entries, quietLog)
			assert.Equal(t, tc.wantService, entries[StatsMapBlkAgg])
			assert.Equal(t, uint32(2*tc.devicesFit+blkAggErrorKeys), entries[StatsMapBlkQ_agg])
			allocated := perCPUBytes(entries[StatsMapBlkAgg], blkAggExplicit.serviceValue, 128) +
				perCPUBytes(entries[StatsMapBlkQ_agg], blkAggExplicit.queueValue, 128)
			assert.LessOrEqual(t, allocated, tc.budget)
		})
	}

	entries := map[string]uint32{}
	planBlockAgg(explicitAgg(1), true, allKinds, 6, 0, 128, false, entries, quietLog)
	assert.Equal(t, uint32(1), entries[StatsMapBlkAgg])
	assert.Equal(t, uint32(1), entries[StatsMapBlkQ_agg])

	entries = map[string]uint32{}
	planBlockAgg(explicitAgg(errorKeys/2), true, allKinds, 6, 0, 128, false, entries, quietLog)
	assert.Equal(t, uint32(blkAggErrorKeys/2), entries[StatsMapBlkAgg], "as many keys as the budget holds")

	// Without the queue map the same budget holds more service keys.
	entries = map[string]uint32{}
	planBlockAgg(explicitAgg(errorKeys+perDevice*3), false, allKinds, 6, 0, 128, false, entries, quietLog)
	assert.Greater(t, entries[StatsMapBlkAgg], uint32(4*3+blkAggErrorKeys))
}

func TestBlockRequestDevices(t *testing.T) {
	sysBlock := t.TempDir()
	for name, hwQueues := range map[string]int{"vda": 4, "nvme0n1": 8, "loop0": 1, "dm-0": 0, "md0": 0} {
		require.NoError(t, os.MkdirAll(filepath.Join(sysBlock, name), 0o755))
		for i := range hwQueues {
			require.NoError(t, os.MkdirAll(filepath.Join(sysBlock, name, "mq", strconv.Itoa(i)), 0o755))
		}
	}
	assert.Equal(t, 3, blockRequestDevices(sysBlock, false), "bio-based devices never reach the request tracepoints")
	assert.Zero(t, blockRequestDevices(filepath.Join(sysBlock, "missing"), true))
}

// The aggregation constants load into the stats collection: the bound arrays
// fit its variables, and every map the plan sizes exists.
func TestBlockAggConstantsAndMapsFitTheCollection(t *testing.T) {
	for name, agg := range map[string]*BlockAggregation{
		"per event":   nil,
		"explicit":    explicitAgg(8 << 20),
		"exponential": {Exponential: true, BoundsNs: make([]uint64, blkExponentialBounds), BudgetBytes: 8 << 20},
	} {
		t.Run(name, func(t *testing.T) {
			load := blockLoadPlan{mapEntries: map[string]uint32{}, emitKinds: allKinds}
			load.agg = planBlockAgg(agg, true, allKinds, 3, 0, 4, false, load.mapEntries, quietLog)

			spec, err := LoadStats()
			require.NoError(t, err)
			consts := statsConstants(&config.EBPFTracer{}, load, FsAggregation{})
			require.NoError(t, ebpfconvenience.RewriteConstants(spec, specConstants(spec, consts)))
			require.NoError(t, setMapEntries(spec, load.mapEntries))

			mode := spec.Variables["blk_emit_mode"]
			require.NotNil(t, mode)
			var got uint8
			require.NoError(t, mode.Get(&got))
			assert.Equal(t, consts["blk_emit_mode"], got)

			if agg != nil && !agg.Exponential {
				var bounds [blkExplicitBounds]uint64
				require.NoError(t, spec.Variables["blk_bounds_ns"].Get(&bounds))
				assert.Equal(t, uint64(2000), bounds[1])
				assert.Equal(t, binary.Size(bounds), int(spec.Variables["blk_bounds_ns"].Size()))
			}
		})
	}
}

func TestBlockAggPartitionSizing(t *testing.T) {
	sysBlock := t.TempDir()
	// Two disks with 10 partitions each; a partition has a "partition" file.
	for _, disk := range []string{"vda", "vdb"} {
		require.NoError(t, os.MkdirAll(filepath.Join(sysBlock, disk, "mq", "0"), 0o755))
		for i := 1; i <= 10; i++ {
			part := filepath.Join(sysBlock, disk, disk+strconv.Itoa(i))
			require.NoError(t, os.MkdirAll(part, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(part, "partition"), []byte("1\n"), 0o644))
		}
		require.NoError(t, os.MkdirAll(filepath.Join(sysBlock, disk, "queue"), 0o755))
	}
	assert.Equal(t, 2, blockRequestDevices(sysBlock, false))
	assert.Equal(t, 22, blockRequestDevices(sysBlock, true), "disks and their partitions are keys")

	withoutPart := map[string]uint32{}
	planBlockAgg(explicitAgg(1<<30), true, allKinds, 2, 0, 4, false, withoutPart, quietLog)
	withPart := map[string]uint32{}
	planBlockAgg(explicitAgg(1<<30), true, allKinds, 22, 0, 4, true, withPart, quietLog)
	need := uint32(bits.OnesCount8(allKinds))*22 + blkAggErrorKeys
	assert.GreaterOrEqual(t, withPart[StatsMapBlkAgg], need, "every partition has a key")
	assert.Greater(t, withPart[StatsMapBlkAgg], withoutPart[StatsMapBlkAgg])
}
