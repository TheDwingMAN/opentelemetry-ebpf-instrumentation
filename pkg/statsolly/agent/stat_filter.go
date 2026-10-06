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

// statMatchers are the attribute matchers of each stat type
type statMatchers struct {
	byType map[ebpf.StatType]filter.MatcherSet[*ebpf.Stat]
	// all the matchers, for the stats of a type without its own
	all filter.MatcherSet[*ebpf.Stat]
}

// filterStatsByAttribute drops the stats that don't match the stats attribute filters. A stat is
// only matched against the filters of the attributes that the metrics of its type have: a filter
// on an attribute of the TCP metrics doesn't drop the storage stats, nor a filter on an attribute
// of the disk metrics the TCP or the file sync stats.
func filterStatsByAttribute(
	config filter.AttributeFamilyConfig,
	extraGroupAttributesCfg map[string][]attr.Name,
	input, output *msg.Queue[[]*ebpf.Stat],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if len(config) == 0 {
			return swarm.Bypass(input, output)
		}
		matchers, err := newStatMatchers(config, extraGroupAttributesCfg)
		if err != nil {
			return nil, err
		}

		in := input.Subscribe(msg.SubscriberName("StatsAttributeFilter"))
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

func newStatMatchers(config filter.AttributeFamilyConfig, extraGroupAttributesCfg map[string][]attr.Name) (*statMatchers, error) {
	// an attribute that no metric has is still an error
	all, err := filter.NewMatcherSet(config, nil, extraGroupAttributesCfg, ebpf.StatStringGetters)
	if err != nil {
		return nil, err
	}

	matchers := &statMatchers{byType: map[ebpf.StatType]filter.MatcherSet[*ebpf.Stat]{}, all: all}
	for statType, metrics := range ebpf.StatTypeMetrics() {
		sections := make([]attributes.Section, 0, len(metrics))
		for _, metric := range metrics {
			sections = append(sections, metric.Section)
		}
		typeConfig := configOfAttributes(config, attributes.SectionAttributeNames(extraGroupAttributesCfg, sections...))
		if matchers.byType[statType], err = filter.NewMatcherSet(typeConfig, nil, extraGroupAttributesCfg,
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

func (m *statMatchers) filter(stats []*ebpf.Stat) []*ebpf.Stat {
	w := 0
	for _, stat := range stats {
		matchers, ok := m.byType[stat.Type]
		if !ok {
			matchers = m.all
		}
		if !matchers.Matches(stat) {
			continue
		}
		stats[w] = stat
		w++
	}
	return stats[:w]
}
