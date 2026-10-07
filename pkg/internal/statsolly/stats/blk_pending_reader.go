// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"encoding/binary"
	"sync"
	"time"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

// PendingSweepAge is how long an in-flight entry may go without a
// completion before Snapshot stops counting it: a missed completion
// (including one block_io.c's recursion protection dropped, counted in
// recursion_misses) would otherwise inflate the pending count forever. It is
// the age at which the sweep of the bio in-flight map deletes an entry.
const PendingSweepAge = ebpf.BlockInflightStaleAge

// The value of blk_rq_inflight, its classic-fallback sibling
// blk_rq_inflight_sector and blk_bio_inflight, the in-flight map of the bios
// of stacked volumes (struct blk_rq_inflight in bpf/statsolly/blk_helpers.h),
// located through its bpf2go type. All share this value shape, so Snapshot
// does not need to know which key kind a Source holds.
var (
	pendingValueSize    = int(unsafe.Sizeof(ebpf.StatsBlkRqInflight{}))
	pendingValueIssueNs = int(unsafe.Offsetof(ebpf.StatsBlkRqInflight{}.IssueNs))
	pendingValueDev     = int(unsafe.Offsetof(ebpf.StatsBlkRqInflight{}.Dev))
	pendingValuePartDev = int(unsafe.Offsetof(ebpf.StatsBlkRqInflight{}.PartDev))
	pendingValueKind    = int(unsafe.Offsetof(ebpf.StatsBlkRqInflight{}.Kind))
)

// PendingKey identifies one pending_operations series before decoration: the
// device, partition (step 13; 0 when not selected or not resolved, which
// several raw keys project onto, summed by Snapshot) and request kind, the
// same fields blockStat projects from the block aggregation keys.
type PendingKey struct {
	Dev     uint32
	PartDev uint32
	Op      uint8
}

// Stat is the synthetic per-key Stat the pipeline's device and direction
// getters resolve PendingKey's attributes from, the same way blockStat
// builds one for the aggregated block metrics.
func (k PendingKey) Stat() *ebpf.Stat {
	return &ebpf.Stat{
		Type:    ebpf.StatTypeBlockIo,
		BlockIo: &ebpf.BlockIo{Dev: k.Dev, PartDev: k.PartDev, Op: k.Op},
	}
}

// PendingReader turns a batch read of blk_rq_inflight (or, on the classic
// tracepoint fallback, blk_rq_inflight_sector) into the pending_operations
// series: no kernel code, a userspace snapshot of the in-flight map (D10,
// revision 4). It is the only part of block pending not folded into the
// statagg Family framework: the map it reads is a working set keyed by
// request, not a per-device counter, so there is no delta to take, only a
// live count.
type PendingReader struct {
	// sources are the in-flight maps: the request one and, with
	// storage_block_volumes, the bio one. A device is in one of them only
	// (a volume's bios never become requests under its own device), so
	// their counts add up without counting anything twice.
	sources []statagg.Source
	monoNow func() time.Duration // CLOCK_MONOTONIC, comparable to issue_ns
	wallNow func() time.Time

	mu sync.Mutex
	// active is the last time each key was seen with at least one pending
	// request, so a device that just went idle still reports zero rather
	// than disappearing, until it has been idle for the caller's ttl.
	active map[PendingKey]time.Time
}

// NewPendingReader reads sources, the fetcher's active in-flight maps.
func NewPendingReader(sources ...statagg.Source) *PendingReader {
	return newPendingReader(timing.MonoTimeNow, time.Now, sources...)
}

func newPendingReader(monoNow func() time.Duration, wallNow func() time.Time, sources ...statagg.Source) *PendingReader {
	return &PendingReader{
		sources: sources, monoNow: monoNow, wallNow: wallNow,
		active: map[PendingKey]time.Time{},
	}
}

// Snapshot walks the in-flight maps once and returns the current pending
// count of every key that is pending now (summed, never overwritten, when
// several raw entries project onto it), or was pending within ttl (zero):
// "devices that had I/O within the series TTL report 0". A key idle for
// longer than ttl is omitted, not zeroed, so the caller's own per-series
// expiry drops it. Entries whose issue_ns is older than PendingSweepAge (a
// missed completion) are not counted.
func (r *PendingReader) Snapshot(ttl time.Duration) (map[PendingKey]uint64, error) {
	now := r.monoNow()
	counts := map[PendingKey]uint64{}
	count := func(_, values []byte) {
		if len(values) < pendingValueSize {
			return
		}
		issueNs := binary.NativeEndian.Uint64(values[pendingValueIssueNs:])
		if now-time.Duration(int64(issueNs)) > PendingSweepAge {
			return
		}
		key := PendingKey{
			Dev:     binary.NativeEndian.Uint32(values[pendingValueDev:]),
			PartDev: binary.NativeEndian.Uint32(values[pendingValuePartDev:]),
			Op:      values[pendingValueKind],
		}
		counts[key]++
	}
	for _, source := range r.sources {
		if err := source.ForEach(count); err != nil {
			return nil, err
		}
	}

	wall := r.wallNow()
	r.mu.Lock()
	defer r.mu.Unlock()
	for key := range counts {
		r.active[key] = wall
	}
	out := make(map[PendingKey]uint64, len(r.active))
	for key, last := range r.active {
		if wall.Sub(last) > ttl {
			delete(r.active, key)
			continue
		}
		out[key] = counts[key]
	}
	return out, nil
}

// CollectPending snapshots r and runs decorate on every key's Stat, in the
// same place the per-event pipeline would: a key decorate drops (Kubernetes
// metadata, filters.stats, the dynamic PID selector) contributes no point.
// Unlike the block aggregation Families, there is no shared Registry here:
// pending_operations takes no delta, so each caller (one per exporter) is
// expected to hold its own Reader and decorator rather than share one. The
// result type is ebpf.PendingPoint, not one of this package's own, so that
// the exporters (which must not import this package: see
// statagg/parity's otel dependency) can take a snapshot function without
// it.
func CollectPending(
	r *PendingReader, ttl time.Duration, decorate func(*ebpf.Stat) bool,
) ([]ebpf.PendingPoint, error) {
	counts, err := r.Snapshot(ttl)
	if err != nil {
		return nil, err
	}
	out := make([]ebpf.PendingPoint, 0, len(counts))
	for key, value := range counts {
		stat := key.Stat()
		if decorate != nil && !decorate(stat) {
			continue
		}
		out = append(out, ebpf.PendingPoint{Stat: stat, Value: value})
	}
	return out, nil
}
