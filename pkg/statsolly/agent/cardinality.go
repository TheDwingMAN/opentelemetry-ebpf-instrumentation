// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"slices"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// perPodAttributes are the attributes that report a metric per pod or container instead of per
// workload
var perPodAttributes = []attr.Name{attr.K8sPodName, attr.K8sContainerName, attr.ContainerID}

// perPodHistogramAttributes returns the attributes that report the disk latency histogram per pod
// or container, when it is enabled. Each of its series is multiplied by the number of buckets, and
// pods come and go, so it is the most expensive way to report the disk stats per pod.
func perPodHistogramAttributes(features *export.Features, attrSel *attributes.AttrSelector) []attr.Name {
	if !features.StatsDiskServiceDuration() {
		return nil
	}
	var perPod []attr.Name
	for _, name := range attrSel.For(attributes.StatDiskServiceDuration) {
		if slices.Contains(perPodAttributes, name) {
			perPod = append(perPod, name)
		}
	}
	return perPod
}

// warnPerPodHistograms warns when the disk latency histogram is reported per pod or container
func warnPerPodHistograms(features *export.Features, groups attributes.AttrGroups, selectorCfg *attributes.SelectorConfig) {
	attrSel, err := attributes.NewAttrSelector(groups, selectorCfg)
	if err != nil {
		// the exporters report the invalid selection
		return
	}
	if names := perPodHistogramAttributes(features, attrSel); len(names) > 0 {
		alog().Warn("the disk latency histogram is reported per pod or container: each of them adds a series "+
			"per bucket. The operations and service time counters give their mean latency at one series each",
			"histogram", attributes.StatDiskServiceDuration.OTEL, "attributes", names)
	}
}
