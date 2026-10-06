// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
	"go.opentelemetry.io/obi/pkg/obi"
)

// blockAggregation decides whether the block programs count completions in
// kernel maps, and in which histogram layout. It returns nil, for an event
// per request, when block metrics are off, the user disabled aggregation,
// the deprecated queue depth (per event only) or print_stats (which prints
// the pipeline's events) is on, or the enabled histograms need more bounds
// than a kernel histogram holds.
func blockAggregation(cfg *obi.Config, log *slog.Logger) (*ebpf.BlockAggregation, *statagg.Layout) {
	features := cfg.Metrics.Features
	switch {
	case !features.StorageBlock():
		return nil, nil
	case cfg.EBPF.StorageAggregation.Disabled:
		log.Info("storage kernel aggregation is disabled; block requests are sent to userspace one by one")
		return nil, nil
	case features.StorageBlockQueueDepth():
		log.Info("the deprecated obi.stat.disk.queue.depth is measured per request;" +
			" block requests are sent to userspace one by one")
		return nil, nil
	case cfg.Stats.Print:
		log.Info("print_stats prints every block request; block requests are sent to userspace one by one")
		return nil, nil
	}

	otelEnabled := cfg.OTELMetrics.EndpointEnabled()
	promEnabled := cfg.Prometheus.EndpointEnabled()
	var sets [][]float64
	if otelEnabled {
		sets = append(sets, blockHistogramBounds(features, &cfg.OTELMetrics.Buckets)...)
	}
	if promEnabled {
		sets = append(sets, blockHistogramBounds(features, &cfg.Prometheus.Buckets)...)
	}
	choice := statagg.HistogramChoice{
		OTelExponential: otelEnabled && cfg.OTELMetrics.HistogramAggregation == otelcfg.HistogramAggregationExponential,
		OptIn:           cfg.EBPF.StorageAggregation.ExponentialHistograms,
	}
	layout, err := choice.NewLayout(sets...)
	if err != nil {
		msg := "can't count the block histograms in the kernel; block requests are sent to userspace one by one"
		if errors.Is(err, statagg.ErrTooManyBounds) {
			msg += ". The bounds of otel_metrics_export.buckets.stat_disk_operation_duration_histogram and" +
				" prometheus_export.buckets.stat_disk_operation_duration_histogram together must be at most " +
				strconv.Itoa(statagg.MaxExplicitBounds)
		}
		log.Warn(msg, "error", err)
		return nil, nil
	}

	return &ebpf.BlockAggregation{
		Exponential: layout.Kind == statagg.LayoutExponential,
		BoundsNs:    layout.KernelBounds(),
		BudgetBytes: uint64(cfg.EBPF.StorageAggregation.BlockMapsBudgetBytes),
	}, layout
}

// blockHistogramBounds returns the bucket bounds of the enabled block
// histograms in one exporter's buckets: the kernel counts them all in one
// layout, which must hold every bound of each, and only of those, so that a
// disabled metric's or exporter's buckets can't push it past its size.
func blockHistogramBounds(features export.Features, buckets *export.Buckets) [][]float64 {
	var sets [][]float64
	for _, h := range []struct {
		enabled bool
		bounds  []float64
	}{
		{features.StorageBlockDuration(), buckets.StatDiskOperationDurationHistogram},
		// The queue wait, flush and discard histograms share the operation
		// duration buckets, as in both exporters.
		{features.StorageBlockQueue(), buckets.StatDiskOperationDurationHistogram},
		{features.StorageBlockFlush(), buckets.StatDiskOperationDurationHistogram},
		{features.StorageBlockDiscard(), buckets.StatDiskOperationDurationHistogram},
	} {
		if h.enabled {
			sets = append(sets, h.bounds)
		}
	}
	return sets
}

// newBlockFamilies builds the families that read the block aggregation maps,
// each with its own pipeline decoration: the node-level ones when the
// fetcher loaded the block programs in the aggregation mode, and the pod
// counters' (storage_block_pod) in either mode. Call it once the pipeline's
// decoration dependencies (aggDeps) are set.
func (s *Stats) newBlockFamilies(ctx context.Context) ([]*statagg.Family, error) {
	if s.fetcher == nil {
		return nil, nil
	}
	maps := s.fetcher.BlockAggregation()
	if maps == nil {
		return nil, nil
	}

	features := s.cfg.Metrics.Features
	var families []*statagg.Family
	if maps.Cgroup != nil {
		f, err := s.newBlockCgroupFamily(ctx, maps.Cgroup, features)
		if err != nil {
			return nil, err
		}
		families = append(families, f)
		// obi.stat.disk.io is then counted per cgroup, with the pod
		// attributes; the node-level path leaves it out.
		features &^= export.FeatureStorageBlockIo
	}
	if s.blockLayout == nil || maps.Service == nil {
		return families, nil
	}
	nodeLevel, err := s.newBlockNodeFamilies(ctx, maps, features)
	if err != nil {
		return nil, err
	}
	return append(families, nodeLevel...), nil
}

// newBlockNodeFamilies builds the families of blk_agg and blk_q_agg, which
// export the node-level block metrics of features.
func (s *Stats) newBlockNodeFamilies(ctx context.Context, maps *ebpf.BlockAggMaps, features export.Features) ([]*statagg.Family, error) {
	service, err := newMapSource(maps.Service)
	if err != nil {
		return nil, fmt.Errorf("block aggregation map: %w", err)
	}
	var queue statagg.Source
	if maps.Queue != nil {
		q, err := newMapSource(maps.Queue)
		if err != nil {
			return nil, fmt.Errorf("block queue aggregation map: %w", err)
		}
		queue = q
	}
	return stats.BlockFamilies(service, queue, s.blockLayout, features,
		func() (func(*ebpf.Stat) bool, error) { return s.newAggregatedStatDecorator(ctx) })
}

// newBlockCgroupFamily builds the family of blk_cg_agg. With Kubernetes
// metadata, the shared cgroup index (cgroupIndex) resolves each counted
// cgroup to its pod; Run starts it with the families. Without, the counters are per device and
// direction only, and no cgroup hierarchy is walked.
func (s *Stats) newBlockCgroupFamily(ctx context.Context, m *ciliumebpf.Map, features export.Features) (*statagg.Family, error) {
	src, err := newMapSource(m)
	if err != nil {
		return nil, fmt.Errorf("block cgroup aggregation map: %w", err)
	}
	decorate, err := s.newAggregatedStatDecorator(ctx)
	if err != nil {
		return nil, err
	}
	var pods *stats.BlockPodResolver
	if s.aggDeps.store != nil {
		pods = stats.NewBlockPodResolver(s.cgroupIndex(), s.aggDeps.store)
	} else {
		pods = stats.NewBlockPodResolver(nil, nil)
	}
	return stats.BlockCgroupFamily(src, features, pods, decorate)
}
