// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
)

// newPendingSnapshot returns a function that snapshots pending_operations,
// decorated the way the stats pipeline would (newAggregatedStatDecorator),
// or nil when the fetcher attached no block program or storage_block_pending
// is off. Unlike newBlockFamilies, there is no statagg.Registry to share
// between exporters: a pending snapshot takes no delta, so call this once
// per exporter, each with its own ttl, so each gets its own Reader and
// decorator rather than contend over one (aggregationDeps' caches are built
// for a single caller, as newAggregatedStatDecorator documents).
func (s *Stats) newPendingSnapshot(ctx context.Context, ttl time.Duration) (func() ([]ebpf.PendingPoint, error), error) {
	if s.fetcher == nil || !s.cfg.Metrics.Features.StorageBlockPending() {
		return nil, nil
	}
	maps := s.fetcher.BlockAggregation()
	if maps == nil || maps.Pending == nil {
		return nil, nil
	}

	// newSnapshotSource, not newMapSource: on the classic-tracepoint
	// fallback this map is blk_rq_inflight_sector, an LRU_HASH (see its
	// comment in bpf/statsolly/maps/blk_rq_inflight.h), which newMapSource
	// rejects as unsafe for a delta-aggregation Reader. PendingReader takes
	// no delta, so an LRU eviction only undercounts one poll.
	source, err := newSnapshotSource(maps.Pending)
	if err != nil {
		return nil, fmt.Errorf("block pending map: %w", err)
	}
	sources := []statagg.Source{source}
	// With storage_block_volumes, the bios in flight on the tracked stacked
	// volumes are pending operations of those volumes.
	if maps.PendingBios != nil {
		bios, err := newSnapshotSource(maps.PendingBios)
		if err != nil {
			return nil, fmt.Errorf("bio pending map: %w", err)
		}
		sources = append(sources, bios)
	}
	decorate, err := s.newAggregatedStatDecorator(ctx)
	if err != nil {
		return nil, err
	}
	reader := stats.NewPendingReader(sources...)

	return func() ([]ebpf.PendingPoint, error) {
		return stats.CollectPending(reader, ttl, decorate)
	}, nil
}
