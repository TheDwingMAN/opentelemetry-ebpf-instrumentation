// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"time"

	ciliumebpf "github.com/cilium/ebpf"
)

// BlockInflightStaleAge is how long an in-flight entry may go without its
// completion before it is taken for the leftover of a completion the programs
// missed: pending_operations stops counting it, and the sweep of the bio
// in-flight map deletes it.
const BlockInflightStaleAge = 5 * time.Minute

// BlockAggregation asks the block programs to count completed requests in
// per-CPU kernel maps (the AGG emit mode) instead of sending an event per
// request through the ring buffer.
type BlockAggregation struct {
	// Exponential selects the exponential bucket layout and its maps.
	Exponential bool
	// BoundsNs are the kernel bucket bounds, in nanoseconds, padded to the
	// size of the layout's bound array (statagg.Layout.KernelBounds).
	BoundsNs []uint64
	// BudgetBytes caps the memory the per-CPU aggregation maps allocate
	// together.
	BudgetBytes uint64
}

// BlockAggMaps are the kernel maps a block aggregation counts in, and the
// in-flight map pending_operations snapshots.
type BlockAggMaps struct {
	// Service counts every completed request: bytes, service time sum and
	// buckets, per device, kind and errno.
	Service *ciliumebpf.Map
	// Queue counts the queue waits of the reads and writes that have one,
	// with the same keys; nil when obi.stat.disk.queue.duration is off.
	Queue *ciliumebpf.Map
	// Pending is the live request-keyed in-flight map (blk_rq_inflight, or
	// its classic-tracepoint sibling blk_rq_inflight_sector), whichever
	// variant is attached: a userspace batch snapshot of it is
	// pending_operations (D10), independent of whether completions are
	// aggregated in the Service and Queue maps or sent one by one. Nil when
	// no block program is attached.
	Pending *ciliumebpf.Map
	// Cgroup counts the completed reads and writes per cgroup they were
	// charged to, device and direction (blk_cg_agg): the pod counters of
	// storage_block_pod, in either emit mode. Nil when the flag is off.
	Cgroup *ciliumebpf.Map
	// PendingBios is the in-flight map of the bios of tracked stacked volumes
	// (blk_bio_inflight), whose values have the shape of Pending's: its
	// entries are pending operations of those volumes. Nil unless
	// storage_block_volumes is on and its programs are attached.
	PendingBios *ciliumebpf.Map
}

// KernelDropReasons names the reasons the stats programs count in the
// stats_drops map (enum stats_drop), by index: each is the map whose insert
// failed because it was full.
var KernelDropReasons = map[uint32]string{
	uint32(StatsStatsDropK_statsDropBlkInflight):    "blk_rq_inflight",
	uint32(StatsStatsDropK_statsDropBlkAgg):         "blk_agg",
	uint32(StatsStatsDropK_statsDropBlkQueueAgg):    "blk_q_agg",
	uint32(StatsStatsDropK_statsDropBlkBioInflight): "blk_bio_inflight",
	uint32(StatsStatsDropK_statsDropBlkCgAgg):       "blk_cg_agg",
}
