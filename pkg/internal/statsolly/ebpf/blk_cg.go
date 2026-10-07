// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"log/slog"
	"unsafe"
)

// The key estimate of blk_cg_agg, the pod counters (spec 2.3): one key per
// cgroup that I/O is charged to, device and direction.
const (
	// blkCgPods is the pods a node runs at once: the kubelet's default
	// --max-pods.
	blkCgPods = 110
	// blkCgRemovedPods is room for the pods removed within the cgroup
	// index's 10 minute tombstone window, whose keys stay while writeback
	// still charges their files to them: a whole turnover.
	blkCgRemovedPods = blkCgPods
	// blkCgCgroupsPerPod are the cgroups of a pod that I/O lands in (S0-d):
	// two containers and the conmon scope that writes their logs. Pod and
	// QoS slices take I/O only after a container is removed, and fit in the
	// removed pods' room.
	blkCgCgroupsPerPod = 3
	// blkCgNodeCgroups are the cgroups outside any pod that I/O is charged
	// to: the root (kernel threads such as jbd2), system services, user
	// sessions, the CSI node plugin.
	blkCgNodeCgroups = 32
	// blkCgDirections: reads and writes.
	blkCgDirections = 2
)

var blkCgValue = unsafe.Sizeof(StatsBlkCgVal{})

// planBlockCgroup sizes blk_cg_agg, the per-CPU map storage_block_pod counts
// reads and writes in per cgroup, device and direction: entries for every
// cgroup the pods of a full node, the pods removed within the tombstone
// window and the node's services charge I/O to, on every device (devices
// counts the partitions too when obi.disk.partition is selected, which the
// key then holds), scaled as ebpf.maps.global_scale_factor scales the other
// maps, then capped so that its copies for every possible CPU fit in budget.
// A completion whose key does not fit is not counted, and the drop is.
// Without want the map gets one entry.
func planBlockCgroup(want bool, devices, cpus, scale int, budget uint64, entries map[string]uint32, log *slog.Logger) {
	entries[StatsMapBlkCgAgg] = unusedMapEntries
	if !want {
		return
	}

	cgroups := uint64((blkCgPods+blkCgRemovedPods)*blkCgCgroupsPerPod + blkCgNodeCgroups)
	estimate := scaleEntries(cgroups*uint64(max(devices, 1))*blkCgDirections, scale)
	fit := budget / perCPUBytes(1, blkCgValue, cpus)
	keys := uint32(max(min(estimate, fit, uint64(maxUint32Entries)), 1))
	entries[StatsMapBlkCgAgg] = keys

	logArgs := []any{
		"map", StatsMapBlkCgAgg, "keys", keys, "estimated_keys", estimate, "devices", devices, "cpus", cpus,
		"allocated_bytes", perCPUBytes(keys, blkCgValue, cpus),
	}
	if uint64(keys) < estimate {
		log.Info("the pod-attributed block counters' map is capped by its memory budget; if"+
			" obi.bpf.map.insert.failures counts blk_cg_agg drops, raise"+
			" ebpf.storage_aggregation.block_pod_maps_budget_bytes", append(logArgs, "budget_bytes", budget)...)
		return
	}
	log.Info("block reads and writes are counted per cgroup in a kernel map", logArgs...)
}

// maxUint32Entries bounds a map's entries, which the kernel takes as a u32.
const maxUint32Entries = ^uint32(0)

// scaleEntries scales n as ebpf.maps.global_scale_factor scales map sizes:
// by 2^scale.
func scaleEntries(n uint64, scale int) uint64 {
	if scale >= 0 {
		return n << uint(scale)
	}
	return max(n>>uint(-scale), 1)
}
