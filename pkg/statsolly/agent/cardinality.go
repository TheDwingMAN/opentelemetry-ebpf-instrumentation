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

// storageHistogram is a latency histogram of the storage stats, and whether it is enabled
type storageHistogram struct {
	enabled bool
	name    attributes.Name
}

func storageHistograms(features *export.Features) []storageHistogram {
	return []storageHistogram{
		{enabled: features.StatsDiskServiceDuration(), name: attributes.StatDiskServiceDuration},
		{enabled: features.StatsFsSyncDuration(), name: attributes.StatFsSyncDuration},
	}
}

// perPodHistogramAttributes returns the attributes that report a latency histogram per pod or
// container, when it is enabled. Each of its series is multiplied by the number of buckets, and
// pods come and go, so it is the most expensive way to report the storage stats per pod.
func perPodHistogramAttributes(histogram storageHistogram, attrSel *attributes.AttrSelector) []attr.Name {
	if !histogram.enabled {
		return nil
	}
	var perPod []attr.Name
	for _, name := range attrSel.For(histogram.name) {
		if slices.Contains(perPodAttributes, name) {
			perPod = append(perPod, name)
		}
	}
	return perPod
}

// warnPerPodHistograms warns when a latency histogram of the storage stats is reported per pod or
// container
func warnPerPodHistograms(features *export.Features, groups attributes.AttrGroups, selectorCfg *attributes.SelectorConfig) {
	attrSel, err := attributes.NewAttrSelector(groups, selectorCfg)
	if err != nil {
		// the exporters report the invalid selection
		return
	}
	for _, histogram := range storageHistograms(features) {
		if names := perPodHistogramAttributes(histogram, attrSel); len(names) > 0 {
			alog().Warn("a storage latency histogram is reported per pod or container: each of them adds a series "+
				"per bucket. The operations and time counters of the same stats give their mean latency at one series each",
				"histogram", histogram.name.OTEL, "attributes", names)
		}
	}
}
