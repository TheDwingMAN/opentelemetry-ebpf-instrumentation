// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"fmt"

	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/pipe/cidr"
	"go.opentelemetry.io/obi/pkg/internal/pipe/decorate"
	"go.opentelemetry.io/obi/pkg/internal/pipe/geoip"
	"go.opentelemetry.io/obi/pkg/internal/pipe/rdns"
	"go.opentelemetry.io/obi/pkg/internal/pipe/transform/k8s"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/selection"
)

// aggregationDeps are what the stats pipeline builds that the decoration of
// aggregated stats must share: the Kubernetes store, the PVC lookup, and the
// dynamic PID trackers, which only the pipeline's nodes run.
type aggregationDeps struct {
	store        *kube.Store
	pvc          ebpf.PVCLookup
	mountpoints  k8s.PIDMountpoints[*ebpf.Stat]
	dynamicAttrs *selection.DynamicFlowAttrs
	dynamicIPs   *selection.DynamicAppIPs
}

// newAggregatedStatDecorator returns, as one function, what the stats
// pipeline does to a stat between the tracer and the exporters: the same
// stages in the same order, with the same filters.stats and dynamic PID
// selection. A statagg family runs it on each new or changed kernel key, so
// both export paths drop the same series. It returns false for a stat the
// pipeline drops. The stages that cache for a single goroutine get their own
// instances, so each family needs its own decorator; the dynamic PID trackers
// are the pipeline's. Call it once buildPipeline has set s.aggDeps.
func (s *Stats) newAggregatedStatDecorator(ctx context.Context) (func(*ebpf.Stat) bool, error) {
	k8sDecorate, err := k8s.NewItemDecorator(ctx, &s.cfg.Attributes.Kubernetes, s.ctxInfo.K8sInformer,
		statAttrs, isStorageStat)
	if err != nil {
		return nil, err
	}
	pvc := s.aggDeps.pvc
	if pvc == nil {
		pvc = noPVCLookup
	}
	pidDecorate := k8s.NewPIDItemDecoratorWith(s.aggDeps.store, statAttrs, fsIoPID, fsIoSetMount,
		ebpf.CachedPVCLookup(pvc), s.aggDeps.mountpoints)
	nfsOwnerDecorate := s.newNFSOwnerDecorate()
	rdnsDecorate := rdns.NewItemDecorator(&s.cfg.Stats.ReverseDNS, statAttrs)
	geoIPDecorate, err := geoip.NewItemDecorator(&s.cfg.Stats.GeoIP, statAttrs)
	if err != nil {
		return nil, err
	}
	cidrDecorate, err := cidr.NewItemDecorator(s.cfg.Stats.CIDRs, statAttrs)
	if err != nil {
		return nil, err
	}
	agentDecorate := decorate.NewItemDecorator(s.agentIP, statAttrs)
	matchers, err := filter.NewMatcherSet(s.cfg.Filters.Stats, nil, s.cfg.Attributes.ExtraGroupAttributes, ebpf.StatStringGetters)
	if err != nil {
		return nil, fmt.Errorf("stats attribute filter: %w", err)
	}
	dynamicAttrs, dynamicIPs := s.aggDeps.dynamicAttrs, s.aggDeps.dynamicIPs

	return func(stat *ebpf.Stat) bool {
		if k8sDecorate != nil && !k8sDecorate(stat) {
			return false
		}
		if pidDecorate != nil {
			pidDecorate(ctx, stat)
		}
		for _, d := range [...]func(*ebpf.Stat){nfsOwnerDecorate, rdnsDecorate, geoIPDecorate, cidrDecorate, agentDecorate} {
			if d != nil {
				d(stat)
			}
		}
		if dynamicAttrs != nil {
			dynamicAttrs.Apply(statAttrs(stat))
		}
		if dynamicIPs != nil && !dynamicIPs.Allows(statAttrs(stat)) {
			return false
		}
		return matchers.Matches(stat)
	}, nil
}

// cgroupIndex returns the cgroup index the families' decoration shares,
// built on first use: one scan of the cgroup tree serves them all. Run
// starts it.
func (s *Stats) cgroupIndex() *statagg.CgroupIndex {
	if s.cgroups == nil {
		s.cgroups = statagg.NewCgroupIndex()
	}
	return s.cgroups
}

// buildAggregation builds the families of the kernel aggregation maps the
// fetcher created, each with its own newAggregatedStatDecorator, and returns
// the registry the exporters emit them from: nil when there is none. It
// keeps the families (and the cgroup index their decoration uses) for Run to
// start once the exporters attached. Call it once the pipeline has set
// s.aggDeps.
func (s *Stats) buildAggregation(ctx context.Context) (*statagg.Registry, error) {
	var families []*statagg.Family
	for _, build := range [...]func(context.Context) (*statagg.Family, error){s.fsFamily, s.nfsFamily} {
		family, err := build(ctx)
		if err != nil {
			return nil, err
		}
		if family != nil {
			families = append(families, family)
		}
	}
	if len(families) == 0 {
		return nil, nil
	}
	registry, err := statagg.NewRegistry(families...)
	if err != nil {
		return nil, err
	}
	s.families = families
	return registry, nil
}

// nfsFamily returns the family of the NFS client RPC map, nil when the
// fetcher created none.
func (s *Stats) nfsFamily(ctx context.Context) (*statagg.Family, error) {
	if s.fetcher == nil || s.fetcher.NFSRPCMap() == nil {
		return nil, nil
	}
	src, err := newMapSource(s.fetcher.NFSRPCMap())
	if err != nil {
		return nil, fmt.Errorf("NFS client RPC map: %w", err)
	}
	decorate, err := s.newAggregatedStatDecorator(ctx)
	if err != nil {
		return nil, err
	}
	return stats.NewNFSRPCFamily(src, s.nfsLayout, s.cfg.Metrics.Features, decorate)
}

// runAggregation reads the kernel aggregation maps until ctx is done; stop
// waits for the last read. The exporters must be attached, which building
// the pipeline does.
func (s *Stats) runAggregation(ctx context.Context) {
	if s.cgroups != nil {
		go s.cgroups.Run(ctx)
	}
	for _, f := range s.families {
		s.familiesRunning.Go(func() { f.Run(ctx) })
	}
}
