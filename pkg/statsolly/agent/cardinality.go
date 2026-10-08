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
// workload, or per volume, like the mountpoints of the PersistentVolumes that the pods mount
var perPodAttributes = []attr.Name{attr.K8sPodName, attr.K8sContainerName, attr.ContainerID, attr.FilesystemMountpoint}

// perPodHistograms returns the enabled storage latency histograms that are reported per pod,
// container or volume, with those attributes. Each of their series is multiplied by the number of
// buckets, and pods and their volumes come and go, so they are the most expensive way to report the
// storage stats per pod or volume.
func perPodHistograms(features *export.Features, attrSel *attributes.AttrSelector) map[string][]attr.Name {
	histograms := []struct {
		enabled bool
		name    attributes.Name
	}{
		{features.StatsDiskOperationDuration(), attributes.StatDiskOperationDuration},
		{features.StatsDiskFlush(), attributes.StatDiskFlushDuration},
		{features.StatsDiskDiscard(), attributes.StatDiskDiscardDuration},
		{features.StatsFsSyncDuration(), attributes.StatFsSyncDuration},
		{features.StatsNFSClientProcedureDuration(), attributes.StatNFSClientProcedureDuration},
	}
	perPod := map[string][]attr.Name{}
	for _, h := range histograms {
		if !h.enabled {
			continue
		}
		for _, name := range attrSel.For(h.name) {
			if slices.Contains(perPodAttributes, name) {
				perPod[h.name.OTEL] = append(perPod[h.name.OTEL], name)
			}
		}
	}
	return perPod
}

// warnPerPodHistograms warns about the storage latency histograms that are reported per pod,
// container or volume
func warnPerPodHistograms(features *export.Features, groups attributes.AttrGroups, selectorCfg *attributes.SelectorConfig) {
	attrSel, err := attributes.NewAttrSelector(groups, selectorCfg)
	if err != nil {
		// the exporters report the invalid selection
		return
	}
	for histogram, names := range perPodHistograms(features, attrSel) {
		alog().Warn("a storage latency histogram is reported per pod, container or volume: each of them adds "+
			"a series per bucket. The operations and time counters give their mean latency at one series each",
			"histogram", histogram, "attributes", names)
	}
}
