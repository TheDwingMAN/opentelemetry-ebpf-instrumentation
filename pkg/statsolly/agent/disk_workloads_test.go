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
	"go.opentelemetry.io/obi/pkg/filter"
)

func TestDiskReadsCgroup(t *testing.T) {
	selecting := func(metric attributes.Name, include ...string) attributes.Selection {
		return attributes.Selection{metric.Section: attributes.InclusionLists{Include: include}}
	}
	for _, tc := range []struct {
		name      string
		groups    attributes.AttrGroups
		features  export.Features
		selection attributes.Selection
		filters   filter.AttributeFamilyConfig
		want      bool
	}{
		{name: "default attributes", features: export.FeatureStatsDisk},
		{
			name: "selected", features: export.FeatureStatsDiskOperations,
			selection: selecting(attributes.StatDiskOperations, "container.id"), want: true,
		},
		{
			name: "selected on a disabled metric", features: export.FeatureStatsDiskIO,
			selection: selecting(attributes.StatDiskOperations, "container.*"),
		},
		{
			name: "filtered, with underscores", features: export.FeatureStatsDiskIO,
			filters: filter.AttributeFamilyConfig{"container_id": {Match: "a1*"}}, want: true,
		},
		{
			name: "disk stats disabled", features: export.FeatureStatsTCPRtt,
			filters: filter.AttributeFamilyConfig{"container.id": {Match: "a1*"}},
		},
		{name: "counters in Kubernetes", groups: attributes.GroupKubernetes, features: export.FeatureStatsDiskOperations, want: true},
		{name: "histogram in Kubernetes", groups: attributes.GroupKubernetes, features: export.FeatureStatsDiskServiceDuration},
		{
			name: "Kubernetes namespace filtered", features: export.FeatureStatsDiskIO,
			filters: filter.AttributeFamilyConfig{"k8s_namespace_name": {Match: "shop"}}, want: true,
		},
		{
			name: "cluster filtered", features: export.FeatureStatsDiskIO,
			filters: filter.AttributeFamilyConfig{"k8s.cluster.name": {Match: "prod"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrSel, err := attributes.NewAttrSelector(tc.groups, &attributes.SelectorConfig{SelectionCfg: tc.selection})
			require.NoError(t, err)
			assert.Equal(t, tc.want, diskReadsCgroup(tc.features, attrSel, tc.filters))
		})
	}
}

func TestPerPodHistogramAttributes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features export.Features
		metric   attributes.Name
		include  []string
		want     []attr.Name
	}{
		{name: "default attributes", features: export.FeatureStatsDisk, metric: attributes.StatDiskServiceDuration},
		{
			name: "per workload", features: export.FeatureStatsDisk, metric: attributes.StatDiskServiceDuration,
			include: []string{"k8s.namespace.name", "k8s.owner.name"},
		},
		{
			name: "per pod and container", features: export.FeatureStatsDisk, metric: attributes.StatDiskServiceDuration,
			include: []string{"k8s.pod.name", "container.id", "k8s.namespace.name"}, want: []attr.Name{attr.ContainerID, attr.K8sPodName},
		},
		{
			name: "counters per pod", features: export.FeatureStatsDiskOperations, metric: attributes.StatDiskOperations,
			include: []string{"k8s.pod.name"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrSel, err := attributes.NewAttrSelector(attributes.GroupKubernetes, &attributes.SelectorConfig{
				SelectionCfg: attributes.Selection{tc.metric.Section: attributes.InclusionLists{Include: tc.include}},
			})
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.want, perPodHistogramAttributes(tc.features, attrSel))
		})
	}
}
