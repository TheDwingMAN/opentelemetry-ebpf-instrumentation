// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package agent

import (
	"testing"
	"unsafe"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

type fakeBlockFetcher struct {
	fakePendingFetcher
	maps *ebpf.BlockAggMaps
}

func (f *fakeBlockFetcher) BlockAggregation() *ebpf.BlockAggMaps { return f.maps }

func perCPUMap(t *testing.T, key, value uintptr) *ciliumebpf.Map {
	t.Helper()
	m, err := ciliumebpf.NewMap(&ciliumebpf.MapSpec{
		Type: ciliumebpf.PerCPUHash, KeySize: uint32(key), ValueSize: uint32(value), MaxEntries: 8,
	})
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })
	return m
}

// With storage_block_pod, obi.stat.disk.io comes from blk_cg_agg, with the
// pod attributes, and the node-level family leaves it out: a metric may
// come from one family only. Without the flag, it stays node-level. The pod
// family exists in the per-event emit mode too, where there is no blk_agg
// family.
func TestNewBlockFamilies_DiskIOFollowsThePodCounters(t *testing.T) {
	cgroup := perCPUMap(t, unsafe.Sizeof(ebpf.StatsBlkCgKey{}), unsafe.Sizeof(ebpf.StatsBlkCgVal{}))
	service := perCPUMap(t, unsafe.Sizeof(ebpf.StatsBlkAggKey{}), unsafe.Sizeof(ebpf.StatsBlkAggVal{}))
	queue := perCPUMap(t, unsafe.Sizeof(ebpf.StatsBlkAggKey{}), unsafe.Sizeof(ebpf.StatsBlkQueueAggVal{}))

	families := func(t *testing.T, features export.Features, maps *ebpf.BlockAggMaps, aggregated bool) *statagg.Registry {
		t.Helper()
		s := &Stats{
			ctxInfo: &global.ContextInfo{},
			cfg:     blockAggConfig(features, true, true),
			fetcher: &fakeBlockFetcher{maps: maps},
		}
		if aggregated {
			_, s.blockLayout = blockAggregation(s.cfg, quietLog)
			require.NotNil(t, s.blockLayout)
		}
		fs, err := s.newBlockFamilies(t.Context())
		require.NoError(t, err)
		registry, err := statagg.NewRegistry(fs...)
		require.NoError(t, err, "no metric comes from two families")
		assert.Nil(t, s.cgroups, "no cgroup hierarchy is walked without Kubernetes metadata")
		return registry
	}
	pod := export.FeatureStorageBlock | export.FeatureStorageBlockPod

	t.Run("aggregated, with the pod counters", func(t *testing.T) {
		r := families(t, pod, &ebpf.BlockAggMaps{Service: service, Queue: queue, Cgroup: cgroup}, true)
		for _, m := range []attributes.Name{
			attributes.StatDiskIO, attributes.StatDiskOperations, attributes.StatDiskOperationTime,
			attributes.StatDiskOperationDuration,
		} {
			assert.True(t, r.Handles(m), m.OTEL)
		}
	})
	t.Run("per event, with the pod counters", func(t *testing.T) {
		r := families(t, pod, &ebpf.BlockAggMaps{Cgroup: cgroup}, false)
		assert.True(t, r.Handles(attributes.StatDiskIO), "the exporters register no per-event disk.io")
		assert.True(t, r.Handles(attributes.StatDiskOperations))
		assert.False(t, r.Handles(attributes.StatDiskOperationDuration), "the node-level histograms stay per event")
	})
	t.Run("aggregated, without", func(t *testing.T) {
		r := families(t, export.FeatureStorageBlock, &ebpf.BlockAggMaps{Service: service, Queue: queue}, true)
		assert.True(t, r.Handles(attributes.StatDiskIO))
		assert.False(t, r.Handles(attributes.StatDiskOperations))
	})
}
