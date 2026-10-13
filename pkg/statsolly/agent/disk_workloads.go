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
// charges the I/O to
var workloadAttributes = []attr.Name{attr.ContainerID}

// diskReadsCgroup tells whether the disk probes read the cgroup of the I/O: when an enabled disk
// metric reports, or a stats filter matches, an attribute of the workload that it is charged to
func diskReadsCgroup(features export.Features, attrSel *attributes.AttrSelector, filters filter.AttributeFamilyConfig) bool {
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
	return features.StatsDisk() && slices.ContainsFunc(names, isWorkloadAttribute)
}

// isWorkloadAttribute tells whether an attribute, named with dots or underscores, is a workload one
func isWorkloadAttribute(name attr.Name) bool {
	return slices.ContainsFunc(workloadAttributes, func(workload attr.Name) bool { return workload.Prom() == name.Prom() })
}
