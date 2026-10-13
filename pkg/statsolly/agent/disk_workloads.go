// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"slices"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/filter"
)

// workloadAttributes are the attributes of the disk stats that come from the cgroup that the kernel
// charges the I/O to. The cluster is the same for every workload.
var workloadAttributes = []attr.Name{
	attr.ContainerID, attr.K8sNamespaceName, attr.K8sOwnerName, attr.K8sKind, attr.K8sPodName, attr.K8sContainerName,
}

// perPodAttributes are the workload attributes that make a series per pod or container
var perPodAttributes = []attr.Name{attr.ContainerID, attr.K8sPodName, attr.K8sContainerName}

// diskReadsCgroup tells whether the disk probes read the cgroup of the I/O: when an enabled disk
// metric reports, or a stats filter matches, an attribute of the workload that it is charged to, and
// under dynamic application selection, which selects the I/O by its container
func diskReadsCgroup(features export.Features, attrSel *attributes.AttrSelector, filters filter.AttributeFamilyConfig,
	dynamicSelection bool,
) bool {
	var names []attr.Name
	for name := range filters {
		names = append(names, attr.Name(name))
	}
	for _, metric := range []struct {
		enabled bool
		name    attributes.Name
	}{
		{enabled: features.StatsDiskServiceDuration(), name: attributes.StatDiskServiceDuration},
		{enabled: features.StatsDiskIO(), name: attributes.StatDiskIO},
		{enabled: features.StatsDiskOperations(), name: attributes.StatDiskOperations},
		{enabled: features.StatsDiskServiceTime(), name: attributes.StatDiskServiceTime},
	} {
		if metric.enabled {
			names = append(names, attrSel.For(metric.name)...)
		}
	}
	return features.StatsDisk() && (dynamicSelection || slices.ContainsFunc(names, isWorkloadAttribute))
}

// isWorkloadAttribute tells whether an attribute, named with dots or underscores, is a workload one
func isWorkloadAttribute(name attr.Name) bool {
	return slices.ContainsFunc(workloadAttributes, func(workload attr.Name) bool { return workload.Prom() == name.Prom() })
}

// perPodHistogramAttributes returns the attributes that report the latency histogram per pod or
// container, at a series per bucket for each
func perPodHistogramAttributes(features export.Features, attrSel *attributes.AttrSelector) []attr.Name {
	if !features.StatsDiskServiceDuration() {
		return nil
	}
	return slices.DeleteFunc(attrSel.For(attributes.StatDiskServiceDuration), func(name attr.Name) bool {
		return !slices.Contains(perPodAttributes, name)
	})
}
