// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package agent

import (
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

// fakePendingFetcher is the minimal ebpFetcher newPendingSnapshot needs: a
// BlockAggregation whose Pending map is the classic-tracepoint fallback's
// real shape (LRU_HASH), the case 69b316063..HEAD regressed.
type fakePendingFetcher struct {
	pending *ciliumebpf.Map
}

func (f *fakePendingFetcher) Close() error                    { return nil }
func (f *fakePendingFetcher) StatsEventsMap() *ciliumebpf.Map { return nil }
func (f *fakePendingFetcher) DebugEventsMap() *ciliumebpf.Map { return nil }
func (f *fakePendingFetcher) NFSRPCMap() *ciliumebpf.Map      { return nil }
func (f *fakePendingFetcher) FsAccumMap() *ciliumebpf.Map     { return nil }
func (f *fakePendingFetcher) KernelDropsMap() *ciliumebpf.Map { return nil }
func (f *fakePendingFetcher) BlockAggregation() *ebpf.BlockAggMaps {
	return &ebpf.BlockAggMaps{Pending: f.pending}
}

// On the classic tracepoint fallback (blockAttachClassic), blockPendingMap
// returns blk_rq_inflight_sector, declared BPF_MAP_TYPE_LRU_HASH (see
// bpf/statsolly/maps/blk_rq_inflight.h). Before the NewSnapshotSource fix,
// newPendingSnapshot routed this through statagg.NewMapSource, which
// rejects LRUHash, and failed pipeline construction for the whole Stats
// agent whenever storage_block_pending was enabled on such a kernel.
func TestNewPendingSnapshot_AcceptsTheClassicAttachLRUMap(t *testing.T) {
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type: ciliumebpf.LRUHash, KeySize: 16, ValueSize: 24, MaxEntries: 8,
	})
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })

	s := &Stats{
		ctxInfo: &global.ContextInfo{},
		cfg: &obi.Config{
			Metrics: perapp.GlobalMetricsConfig{Features: export.FeatureStorageBlockPending},
		},
		fetcher: &fakePendingFetcher{pending: m},
	}

	snapshot, err := s.newPendingSnapshot(t.Context(), 0)
	require.NoError(t, err)
	require.NotNil(t, snapshot)

	points, err := snapshot()
	require.NoError(t, err)
	require.Empty(t, points, "an empty in-flight map snapshots to no points")
}
