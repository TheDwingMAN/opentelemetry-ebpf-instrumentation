// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"slices"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// workloadAttributes are the attributes of the storage stats that come from the cgroup that the
// kernel charges the I/O or the sync to. The cluster is the same for every workload.
var workloadAttributes = []attr.Name{
	attr.ContainerID, attr.K8sNamespaceName, attr.K8sOwnerName, attr.K8sKind, attr.K8sPodName, attr.K8sContainerName,
}

// perPodAttributes are the workload attributes that make a series per pod or container
var perPodAttributes = []attr.Name{attr.ContainerID, attr.K8sPodName, attr.K8sContainerName}

type storageMetric struct {
	enabled bool
	name    attributes.Name
}

// cgroupReads tells which storage probes read the cgroup of the I/O or the syncs: those of an
// enabled metric that reports, or whose stats a filter matches, an attribute of the workload that
// they are charged to, and all of them under dynamic application selection, which selects the stats
// by their container
func cgroupReads(features export.Features, attrSel *attributes.AttrSelector, filters filter.AttributeFamilyConfig,
	dynamicSelection bool,
) ebpf.CgroupReads {
	var filtered []attr.Name
	for name := range filters {
		filtered = append(filtered, attr.Name(name))
	}
	readsCgroup := func(enabled bool, metrics []storageMetric) bool {
		names := slices.Clone(filtered)
		for _, metric := range metrics {
			if metric.enabled {
				names = append(names, attrSel.For(metric.name)...)
			}
		}
		return enabled && (dynamicSelection || slices.ContainsFunc(names, isWorkloadAttribute))
	}
	return ebpf.CgroupReads{
		Disk: readsCgroup(features.StatsDisk(), []storageMetric{
			{enabled: features.StatsDiskServiceDuration(), name: attributes.StatDiskServiceDuration},
			{enabled: features.StatsDiskIO(), name: attributes.StatDiskIO},
			{enabled: features.StatsDiskOperations(), name: attributes.StatDiskOperations},
			{enabled: features.StatsDiskServiceTime(), name: attributes.StatDiskServiceTime},
		}),
		FsSync: readsCgroup(features.StatsFsSync(), []storageMetric{
			{enabled: features.StatsFsSyncDuration(), name: attributes.StatFsSyncDuration},
			{enabled: features.StatsFsSyncOperations(), name: attributes.StatFsSyncOperations},
			{enabled: features.StatsFsSyncTime(), name: attributes.StatFsSyncTime},
		}),
	}
}

// isWorkloadAttribute tells whether an attribute, named with dots or underscores, is a workload one
func isWorkloadAttribute(name attr.Name) bool {
	return slices.ContainsFunc(workloadAttributes, func(workload attr.Name) bool { return workload.Prom() == name.Prom() })
}

// perPodHistograms returns, by metric, the attributes that report an enabled latency histogram per
// pod or container, at a series per bucket for each
func perPodHistograms(features export.Features, attrSel *attributes.AttrSelector) map[string][]attr.Name {
	perPod := map[string][]attr.Name{}
	for _, histogram := range []storageMetric{
		{enabled: features.StatsDiskServiceDuration(), name: attributes.StatDiskServiceDuration},
		{enabled: features.StatsFsSyncDuration(), name: attributes.StatFsSyncDuration},
	} {
		names := slices.DeleteFunc(attrSel.For(histogram.name), func(name attr.Name) bool {
			return !slices.Contains(perPodAttributes, name)
		})
		if histogram.enabled && len(names) > 0 {
			perPod[histogram.name.OTEL] = names
		}
	}
	return perPod
}
