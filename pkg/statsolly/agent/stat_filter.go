// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"slices"

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

// diskStatSections are the metrics of the disk stats, the storage stats
var diskStatSections = []attributes.Section{attributes.StatDiskServiceDuration.Section}

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
// filters. A storage stat is only matched against the filters of the attributes that the disk stat
// metrics have: a filter on an attribute of the TCP metrics doesn't drop any storage stat.
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
				if stats = filterStats(matchers, stats); len(stats) > 0 {
					output.SendCtx(ctx, stats)
				}
			})
		}, nil
	}
}

// newStorageStatMatchers returns the matchers of the filters on the attributes of the disk stat
// metrics
func newStorageStatMatchers(config filter.AttributeFamilyConfig, extraGroupAttributesCfg map[string][]attr.Name) (filter.MatcherSet[*ebpf.Stat], error) {
	diskConfig := configOfAttributes(config, attributes.SectionAttributeNames(extraGroupAttributesCfg, diskStatSections...))
	return filter.NewMatcherSet(diskConfig, nil, extraGroupAttributesCfg, ebpf.StatStringGetters)
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

// filterStats keeps the stats that match
func filterStats(matchers filter.MatcherSet[*ebpf.Stat], stats []*ebpf.Stat) []*ebpf.Stat {
	return slices.DeleteFunc(stats, func(stat *ebpf.Stat) bool { return !matchers.Matches(stat) })
}
