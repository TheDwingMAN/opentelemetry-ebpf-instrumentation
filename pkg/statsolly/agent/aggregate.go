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
// are the pipeline's. Call it after buildPipeline.
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
	pidDecorate := k8s.NewPIDItemDecorator(s.aggDeps.store, statAttrs, fsIoPID, fsIoSetMount, ebpf.CachedPVCLookup(pvc))
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

// aggregatedFamilies builds the families of the kernel aggregation maps the
// fetcher created, with the decoration of newAggregatedStatDecorator, and
// returns the registry the exporters emit them from: nil when there is none.
// Call it once the dynamic PID trackers are built; Run starts the families
// once the exporters attached.
func (s *Stats) aggregatedFamilies(ctx context.Context) (*statagg.Registry, error) {
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
	nfs, err := stats.NewNFSRPCFamily(src, s.nfsLayout, s.cfg.Metrics.Features, decorate)
	if err != nil {
		return nil, err
	}
	s.families = []*statagg.Family{nfs}
	return statagg.NewRegistry(s.families...)
}
