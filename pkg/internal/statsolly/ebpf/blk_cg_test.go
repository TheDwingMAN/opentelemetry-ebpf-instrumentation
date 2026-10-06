// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlanBlockCgroup_OffCostsOneEntry(t *testing.T) {
	entries := map[string]uint32{}
	planBlockCgroup(false, 6, 128, 0, 8<<20, entries, quietLog)
	assert.Equal(t, map[string]uint32{StatsMapBlkCgAgg: unusedMapEntries}, entries)
}

// The spec 2.3 estimate: (max pods + pods removed within the tombstone
// window) x 3 cgroups (2 containers and the conmon scope) per pod, plus the
// node's own cgroups, on every device, in both directions.
func TestPlanBlockCgroup_SizedFromThePodsAndDevices(t *testing.T) {
	entries := map[string]uint32{}
	planBlockCgroup(true, 6, 4, 0, 8<<20, entries, quietLog)
	const perDevice = ((110+110)*3 + blkCgNodeCgroups) * 2
	assert.Equal(t, uint32(perDevice*6), entries[StatsMapBlkCgAgg])
	assert.Equal(t, uintptr(24), blkCgValue, "count, bytes and time: three u64 words")
}

// ebpf.maps.global_scale_factor scales the estimate as it scales the other
// maps, by powers of two.
func TestPlanBlockCgroup_FollowsTheGlobalScaleFactor(t *testing.T) {
	sized := func(scale int) uint32 {
		entries := map[string]uint32{}
		planBlockCgroup(true, 2, 4, scale, 1<<30, entries, quietLog)
		return entries[StatsMapBlkCgAgg]
	}
	base := sized(0)
	assert.Equal(t, 2*base, sized(1))
	assert.Equal(t, base/4, sized(-2))
}

// On a large node the per-CPU copies would exceed the budget: the map holds
// what fits, at least one key, and a completion whose key does not fit is a
// counted drop. 250 pods on 6 devices at 128 CPUs (spec section 5) take
// 27.6 MB unclamped.
func TestPlanBlockCgroup_ClampedByItsBudget(t *testing.T) {
	entries := map[string]uint32{}
	planBlockCgroup(true, 6, 128, 0, 8<<20, entries, quietLog)
	keys := entries[StatsMapBlkCgAgg]
	assert.Equal(t, uint32((8<<20)/(24*128)), keys)
	assert.LessOrEqual(t, perCPUBytes(keys, blkCgValue, 128), uint64(8<<20))

	planBlockCgroup(true, 6, 128, 0, 1, entries, quietLog)
	assert.Equal(t, uint32(1), entries[StatsMapBlkCgAgg], "a budget below one key still holds one")
}

// No device found in sysfs (a container without /sys/block) still sizes the
// map for one.
func TestPlanBlockCgroup_NoDevices(t *testing.T) {
	entries := map[string]uint32{}
	planBlockCgroup(true, 0, 4, 0, 8<<20, entries, quietLog)
	require.NotZero(t, entries[StatsMapBlkCgAgg])
	assert.Equal(t, uint32(((110+110)*3+blkCgNodeCgroups)*2), entries[StatsMapBlkCgAgg])
}
