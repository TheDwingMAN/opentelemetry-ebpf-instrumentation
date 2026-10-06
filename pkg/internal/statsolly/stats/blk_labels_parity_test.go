// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/parity"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
)

// withNodeName records the agent's node, as the stats pipeline does with
// Kubernetes metadata on, for the duration of a test.
func withNodeName(t *testing.T, name string) {
	ebpf.SetNodeName(name)
	t.Cleanup(func() { ebpf.SetNodeName("") })
}

// requireDefaultLabels requires every per-event series to carry the labels
// that are on by default on every disk metric, so that the parity of both
// paths covers them.
func requireDefaultLabels(t *testing.T, otlp, samples []string) {
	t.Helper()
	require.NotEmpty(t, otlp)
	for _, p := range otlp {
		assert.Contains(t, p, "k8s.node.name=node-a:Str", p)
		assert.Contains(t, p, "obi.disk.stacked=", p)
	}
	for _, s := range samples {
		if strings.HasPrefix(s, "obi_stat_disk_") {
			assert.Contains(t, s, "k8s_node_name=node-a", s)
			assert.Contains(t, s, "obi_disk_stacked=", s)
		}
	}
}

// With Kubernetes metadata on, the kernel-aggregated block metrics carry
// k8s.node.name and obi.disk.stacked by default, as the per-event ones do.
func TestBlockAggregationParity_DefaultLabels(t *testing.T) {
	withNodeName(t, "node-a")
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)

	otlp, samples := parity.Run(t, parity.Setup{
		Features:    allBlockFeatures,
		Groups:      attributes.GroupKubernetes,
		OTelBuckets: export.DefaultBuckets,
		PromBuckets: export.DefaultBuckets,
	}, parity.BlockEvents(1000, layout.BoundsNs, false), func(decorate func(*ebpf.Stat) bool) parity.Kernel {
		return newBlockKernel(t, layout, allBlockFeatures, decorate).kernel()
	})
	requireDefaultLabels(t, otlp, samples)
}

// So does obi.stat.disk.io when storage_block_pod counts it per cgroup but
// the pod attributes are not reported.
func TestBlockCgroupParity_DefaultLabels(t *testing.T) {
	withNodeName(t, "node-a")
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)

	otlp, samples := parity.Run(t, parity.Setup{
		Features:    export.FeatureStorageBlockIo,
		Groups:      attributes.GroupKubernetes,
		OTelBuckets: export.DefaultBuckets,
		PromBuckets: export.DefaultBuckets,
	}, parity.BlockEvents(1000, layout.BoundsNs, false), func(decorate func(*ebpf.Stat) bool) parity.Kernel {
		_, _, pods, _ := newPodFixture()
		k := &podKernel{m: stataggtest.NewMemMap(cgKeySize, int(unsafe.Sizeof(ebpf.StatsBlkCgVal{})), blockTestCPUs)}
		f, err := BlockCgroupFamily(k.m, export.FeatureStorageBlockIo, pods, decorate)
		require.NoError(t, err)
		reg, err := statagg.NewRegistry(f)
		require.NoError(t, err)
		i := 0
		return parity.Kernel{Registry: reg, Families: []*statagg.Family{f}, Record: func(s *ebpf.Stat) {
			k.record(cgroupOf(i), s)
			i++
		}}
	})
	requireDefaultLabels(t, otlp, samples)
}
