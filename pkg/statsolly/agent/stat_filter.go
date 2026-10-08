// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"fmt"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// tcpStatSections are the metrics of the TCP stats
var tcpStatSections = []attributes.Section{
	attributes.StatTCPRtt.Section, attributes.StatTCPFailedConnections.Section, attributes.StatTCPRetransmits.Section,
	attributes.StatTCPIo.Section, attributes.StatTCPSuccessfulConnections.Section,
}

// storageStatMetrics are the metrics that report the storage stats of each type
var storageStatMetrics = map[ebpf.StatType][]attributes.Name{
	ebpf.StatTypeDiskIO: {
		attributes.StatDiskOperationDuration, attributes.StatDiskIO, attributes.StatDiskOperations,
		attributes.StatDiskServiceTime, attributes.StatDiskQueueTime, attributes.StatDiskFlushDuration,
		attributes.StatDiskDiscardDuration, attributes.StatDiskDiscardIO,
	},
	ebpf.StatTypeFsSync: {
		attributes.StatFsSyncDuration, attributes.StatFsSyncOperations, attributes.StatFsSyncOperationTime,
	},
	ebpf.StatTypeDiskPending: {attributes.StatDiskOperationInflight},
	ebpf.StatTypeNFSProcedure: {
		attributes.StatNFSClientProcedureDuration, attributes.StatNFSClientProcedureCount,
		attributes.StatNFSClientProcedureTime,
	},
	ebpf.StatTypeNFSIO:      {attributes.StatNFSClientIO},
	ebpf.StatTypePodVolume:  {attributes.StatK8sPodVolumeInfo},
	ebpf.StatTypeDiskVolume: {attributes.StatDiskVolumeInfo},
}

// tcpStatFilters returns the stats attribute filters that apply to the TCP stats: all of them but
// those on the attributes that the storage stat metrics have and the TCP stat metrics don't. A
// filter on an attribute that no metric has is an error.
func tcpStatFilters(config filter.AttributeFamilyConfig, extraGroupAttributesCfg map[string][]attr.Name) (filter.AttributeFamilyConfig, error) {
	if _, err := filter.NewMatcherSet(config, nil, extraGroupAttributesCfg, ebpf.StatStringGetters); err != nil {
		return nil, err
	}
	names := attributes.AllAttributeNames(nil, extraGroupAttributesCfg)
	tcpNames := attributes.SectionAttributeNames(extraGroupAttributesCfg, tcpStatSections...)
	for name := range attributes.SectionAttributeNames(extraGroupAttributesCfg, attributes.StatSections()...) {
		if _, ok := tcpNames[name]; !ok {
			delete(names, name)
		}
	}
	return configOfAttributes(config, names), nil
}

// filterStorageStatsByAttribute drops the storage stats that don't match the stats attribute
// filters. A storage stat is only matched against the filters of the attributes that the metrics
// of its type have: a filter on an attribute of the disk metrics doesn't drop the file sync stats,
// nor a filter on an attribute of the TCP metrics any storage stat.
func filterStorageStatsByAttribute(
	config filter.AttributeFamilyConfig,
	extraGroupAttributesCfg map[string][]attr.Name,
	input, output *msg.Queue[[]*ebpf.Stat],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if len(config) == 0 {
			return swarm.Bypass(input, output)
		}
		matchers, err := newStorageStatMatchers(config, extraGroupAttributesCfg)
		if err != nil {
			return nil, err
		}

		in := input.Subscribe(msg.SubscriberName("StorageAttributeFilter"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, nil, func(stats []*ebpf.Stat) {
				if stats = matchers.filter(stats); len(stats) > 0 {
					output.SendCtx(ctx, stats)
				}
			})
		}, nil
	}
}

// storageStatMatchers are the attribute matchers of each type of storage stat
type storageStatMatchers map[ebpf.StatType]filter.MatcherSet[*ebpf.Stat]

func newStorageStatMatchers(config filter.AttributeFamilyConfig, extraGroupAttributesCfg map[string][]attr.Name) (storageStatMatchers, error) {
	matchers := storageStatMatchers{}
	for statType, metrics := range storageStatMetrics {
		sections := make([]attributes.Section, 0, len(metrics))
		for _, metric := range metrics {
			sections = append(sections, metric.Section)
		}
		typeConfig := configOfAttributes(config, attributes.SectionAttributeNames(extraGroupAttributesCfg, sections...))
		var err error
		if matchers[statType], err = filter.NewMatcherSet(typeConfig, nil, extraGroupAttributesCfg,
			ebpf.StatStringGetters); err != nil {
			return nil, fmt.Errorf("stats of type %d: %w", statType, err)
		}
	}
	return matchers, nil
}

// configOfAttributes returns the filters of the given attributes. Filters can name the attributes
// with dots or underscores.
func configOfAttributes(config filter.AttributeFamilyConfig, names map[attr.Name]struct{}) filter.AttributeFamilyConfig {
	promNames := make(map[string]struct{}, len(names))
	for name := range names {
		promNames[name.Prom()] = struct{}{}
	}
	selected := filter.AttributeFamilyConfig{}
	for name, match := range config {
		if _, ok := promNames[attr.Name(name).Prom()]; ok {
			selected[name] = match
		}
	}
	return selected
}

func (m storageStatMatchers) filter(stats []*ebpf.Stat) []*ebpf.Stat {
	w := 0
	for _, stat := range stats {
		// a type without metrics has no matchers, and is kept
		if !m[stat.Type].Matches(stat) {
			continue
		}
		stats[w] = stat
		w++
	}
	return stats[:w]
}
