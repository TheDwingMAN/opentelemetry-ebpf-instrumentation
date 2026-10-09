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

func TestPerPodHistogramAttributes(t *testing.T) {
	selecting := func(metric attributes.Name, include ...string) *attributes.AttrSelector {
		attrSel, err := attributes.NewAttrSelector(attributes.GroupKubernetes, &attributes.SelectorConfig{
			SelectionCfg: attributes.Selection{metric.Section: attributes.InclusionLists{Include: include}},
		})
		require.NoError(t, err)
		return attrSel
	}
	disk := export.FeatureStatsDisk
	counters := export.FeatureStatsDiskOperations | export.FeatureStatsDiskServiceTime

	assert.Empty(t, perPodHistogramAttributes(&disk, selecting(attributes.StatDiskServiceDuration)),
		"not by default, even in Kubernetes")
	assert.Empty(t, perPodHistogramAttributes(&disk, selecting(attributes.StatDiskServiceDuration, "k8s.namespace.name", "k8s.owner.name")),
		"per workload")
	assert.Equal(t, []attr.Name{attr.ContainerID, attr.K8sPodName},
		perPodHistogramAttributes(&disk, selecting(attributes.StatDiskServiceDuration, "k8s.pod.name", "container.id", "k8s.namespace.name")))
	assert.Empty(t, perPodHistogramAttributes(&disk, selecting(attributes.StatDiskOperations, "k8s.pod.name")),
		"the counters cost a series each")
	assert.Empty(t, perPodHistogramAttributes(&counters, selecting(attributes.StatDiskServiceDuration, "k8s.pod.name")),
		"the histogram is disabled")
}
