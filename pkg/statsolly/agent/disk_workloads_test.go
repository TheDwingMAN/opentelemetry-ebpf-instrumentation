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
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func TestCgroupReads(t *testing.T) {
	selecting := func(metric attributes.Name, include ...string) attributes.Selection {
		return attributes.Selection{metric.Section: attributes.InclusionLists{Include: include}}
	}
	disk, fsSync, both := ebpf.CgroupReads{Disk: true}, ebpf.CgroupReads{FsSync: true}, ebpf.CgroupReads{Disk: true, FsSync: true}
	for _, tc := range []struct {
		name             string
		groups           attributes.AttrGroups
		features         export.Features
		selection        attributes.Selection
		filters          filter.AttributeFamilyConfig
		dynamicSelection bool
		want             ebpf.CgroupReads
	}{
		{name: "default attributes", features: export.FeatureStatsDisk},
		{
			name: "selected", features: export.FeatureStatsDiskOperations,
			selection: selecting(attributes.StatDiskOperations, "container.id"), want: disk,
		},
		{
			name: "selected on a disabled metric", features: export.FeatureStatsDiskIO,
			selection: selecting(attributes.StatDiskOperations, "container.*"),
		},
		{
			name: "filtered, with underscores", features: export.FeatureStatsDiskIO,
			filters: filter.AttributeFamilyConfig{"container_id": {Match: "a1*"}}, want: disk,
		},
		{
			name: "disk stats disabled", features: export.FeatureStatsTCPRtt,
			filters: filter.AttributeFamilyConfig{"container.id": {Match: "a1*"}},
		},
		{name: "counters in Kubernetes", groups: attributes.GroupKubernetes, features: export.FeatureStatsDiskOperations, want: disk},
		{name: "histogram in Kubernetes", groups: attributes.GroupKubernetes, features: export.FeatureStatsDiskServiceDuration},
		{
			name: "Kubernetes namespace filtered", features: export.FeatureStatsDiskIO,
			filters: filter.AttributeFamilyConfig{"k8s_namespace_name": {Match: "shop"}}, want: disk,
		},
		{
			name: "cluster filtered", features: export.FeatureStatsDiskIO,
			filters: filter.AttributeFamilyConfig{"k8s.cluster.name": {Match: "prod"}},
		},
		{name: "dynamic selection", features: export.FeatureStatsDiskServiceDuration, dynamicSelection: true, want: disk},
		{
			name: "file syncs selected", features: export.FeatureStatsDisk | export.FeatureStatsFsSync,
			selection: selecting(attributes.StatFsSyncDuration, "container.id"), want: fsSync,
		},
		{name: "file sync histogram in Kubernetes", groups: attributes.GroupKubernetes, features: export.FeatureStatsFsSyncDuration},
		{name: "file sync counters in Kubernetes", groups: attributes.GroupKubernetes, features: export.FeatureStatsFsSyncTime, want: fsSync},
		{
			name: "both filtered", features: export.FeatureStatsDiskIO | export.FeatureStatsFsSync,
			filters: filter.AttributeFamilyConfig{"k8s.owner.name": {Match: "db"}}, want: both,
		},
		{name: "both under dynamic selection", features: export.FeatureStatsDisk | export.FeatureStatsFsSync, dynamicSelection: true, want: both},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrSel, err := attributes.NewAttrSelector(tc.groups, &attributes.SelectorConfig{SelectionCfg: tc.selection})
			require.NoError(t, err)
			assert.Equal(t, tc.want, cgroupReads(tc.features, attrSel, tc.filters, tc.dynamicSelection))
		})
	}
}

func TestPerPodHistograms(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features export.Features
		metric   attributes.Name
		include  []string
		want     map[string][]attr.Name
	}{
		{name: "default attributes", features: export.FeatureStatsDisk, metric: attributes.StatDiskServiceDuration},
		{
			name: "per workload", features: export.FeatureStatsDisk, metric: attributes.StatDiskServiceDuration,
			include: []string{"k8s.namespace.name", "k8s.owner.name"},
		},
		{
			name: "per pod and container", features: export.FeatureStatsDisk, metric: attributes.StatDiskServiceDuration,
			include: []string{"k8s.pod.name", "container.id", "k8s.namespace.name"},
			want:    map[string][]attr.Name{"obi.stat.disk.service.duration": {attr.ContainerID, attr.K8sPodName}},
		},
		{
			name: "counters per pod", features: export.FeatureStatsDiskOperations, metric: attributes.StatDiskOperations,
			include: []string{"k8s.pod.name"},
		},
		{
			name: "file syncs per container", features: export.FeatureStatsFsSync, metric: attributes.StatFsSyncDuration,
			include: []string{"container.id"}, want: map[string][]attr.Name{"obi.stat.fs.sync.duration": {attr.ContainerID}},
		},
		{
			name: "file syncs disabled", features: export.FeatureStatsDisk, metric: attributes.StatFsSyncDuration,
			include: []string{"container.id"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrSel, err := attributes.NewAttrSelector(attributes.GroupKubernetes, &attributes.SelectorConfig{
				SelectionCfg: attributes.Selection{tc.metric.Section: attributes.InclusionLists{Include: tc.include}},
			})
			require.NoError(t, err)
			want := tc.want
			if want == nil {
				want = map[string][]attr.Name{}
			}
			assert.Equal(t, want, perPodHistograms(tc.features, attrSel))
		})
	}
}
