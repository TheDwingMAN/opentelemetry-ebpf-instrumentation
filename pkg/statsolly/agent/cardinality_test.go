// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestPerPodHistograms(t *testing.T) {
	perPod := func(features export.Features, selection attributes.Selection) map[string][]attr.Name {
		selection.Normalize()
		attrSel, err := attributes.NewAttrSelector(attributes.GroupKubernetes|attributes.GroupContainer,
			&attributes.SelectorConfig{SelectionCfg: selection})
		require.NoError(t, err)
		return perPodHistograms(&features, attrSel)
	}

	assert.Empty(t, perPod(export.FeatureStatsDisk|export.FeatureStatsFsSync|export.FeatureStatsNFS, nil),
		"no histogram is reported per pod by default")

	assert.Equal(t, map[string][]attr.Name{
		"obi.stat.fs.sync.duration": {attr.K8sPodName},
	}, perPod(export.FeatureStatsFsSync, attributes.Selection{
		"obi.stat.fs.sync.duration":   {Include: []string{"k8s.pod.name", "k8s.namespace.name"}},
		"obi.stat.fs.sync.operations": {Include: []string{"k8s.pod.name"}},
	}), "only the histograms count, and the per-workload attributes don't")

	assert.Equal(t, map[string][]attr.Name{
		"obi.stat.disk.operation.duration": {attr.ContainerID},
	}, perPod(export.FeatureStatsDiskOperationDuration|export.FeatureStatsDiskIO, attributes.Selection{
		"obi.stat.disk.*": {Include: []string{"container.id"}},
	}))

	assert.Empty(t, perPod(export.FeatureStatsDiskIO, attributes.Selection{
		"obi.stat.nfs.client.procedure.duration": {Include: []string{"k8s.pod.name"}},
	}), "disabled histograms don't count")
}

// TestDetailedProfileIsPerWorkload checks the selection of the detailed profile of the storage stats
// in devdocs/metrics.md: every storage latency histogram per workload, none per pod
func TestDetailedProfileIsPerWorkload(t *testing.T) {
	selection := attributes.Selection{"obi.stat.*.duration": {
		Include: []string{"*"},
		Exclude: []string{"obi.ip", "obi.disk.partition", "container.id", "k8s.pod.name", "k8s.container.name", "k8s.kind"},
	}}
	selection.Normalize()
	attrSel, err := attributes.NewAttrSelector(attributes.GroupKubernetes|attributes.GroupContainer,
		&attributes.SelectorConfig{SelectionCfg: selection})
	require.NoError(t, err)

	features := export.FeatureStatsDisk | export.FeatureStatsFsSync | export.FeatureStatsNFS
	assert.Empty(t, perPodHistograms(&features, attrSel))
	for _, histogram := range []attributes.Name{
		attributes.StatDiskOperationDuration, attributes.StatDiskFlushDuration,
		attributes.StatDiskDiscardDuration, attributes.StatFsSyncDuration, attributes.StatNFSClientProcedureDuration,
	} {
		assert.Subset(t, attrSel.For(histogram), []attr.Name{attr.K8sNamespaceName, attr.K8sOwnerName}, histogram.OTEL)
	}
	assert.Equal(t, []attr.Name{
		attr.ErrorType, attr.K8sClusterName, attr.K8sNamespaceName, attr.K8sOwnerName, attr.FsSyncType,
	}, attrSel.For(attributes.StatFsSyncOperations), "the counters keep their defaults")
}
