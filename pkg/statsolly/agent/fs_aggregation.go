// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
	"go.opentelemetry.io/obi/pkg/obi"
)

// fsAggregation decides how the filesystem programs report operations: added
// into a kernel map, with the histogram layout it returns, unless the
// configuration asks for events (storage_aggregation.disabled, or print_stats,
// which prints each one) or the exporters' filesystem histogram bounds do not
// fit a kernel histogram. Only the exporters that export the filesystem
// histogram count towards its layout.
func fsAggregation(cfg *obi.Config, log *slog.Logger) (ebpf.FsAggregation, *statagg.Layout) {
	features := cfg.Metrics.Features
	switch {
	case !features.StorageFS():
		return ebpf.FsAggregation{}, nil
	case cfg.EBPF.StorageAggregation.Disabled:
		log.Info("filesystem metrics are exported per event, as ebpf.storage_aggregation.disabled asks")
		return ebpf.FsAggregation{}, nil
	case cfg.Stats.Print:
		log.Info("filesystem metrics are exported per event, so that stats.print_stats prints them")
		return ebpf.FsAggregation{}, nil
	}

	otelEnabled := cfg.OTELMetrics.EndpointEnabled() && features.StatMetrics()
	promEnabled := cfg.Prometheus.EndpointEnabled() && features.StatMetrics()
	var bounds [][]float64
	if features.StorageFSDuration() {
		if otelEnabled {
			bounds = append(bounds, cfg.OTELMetrics.Buckets.StatFsOperationDurationHistogram)
		}
		if promEnabled {
			bounds = append(bounds, cfg.Prometheus.Buckets.StatFsOperationDurationHistogram)
		}
	}
	choice := statagg.HistogramChoice{
		OTelExponential: otelEnabled && cfg.OTELMetrics.HistogramAggregation == otelcfg.HistogramAggregationExponential,
		OptIn:           cfg.EBPF.StorageAggregation.ExponentialHistograms,
	}
	layout, err := choice.NewLayout(bounds...)
	if err != nil {
		log.Warn("the filesystem histogram buckets do not fit a kernel histogram; filesystem metrics are exported"+
			" per event, at a higher CPU cost. Use at most 32 distinct bounds across"+
			" otel_metrics_export.buckets.stat_fs_operation_duration_histogram and"+
			" prometheus_export.buckets.stat_fs_operation_duration_histogram",
			"error", err)
		return ebpf.FsAggregation{}, nil
	}
	return ebpf.FsAggregation{
		Enabled:     true,
		Exponential: layout.Kind == statagg.LayoutExponential,
		BoundsNs:    layout.KernelBounds(),
	}, layout
}

// cgroupV2 reports whether the host runs cgroup v2 alone; a variable for
// tests.
var cgroupV2 = statagg.CgroupV2

// fsFamily returns the family of the filesystem aggregation map, nil when
// the filesystem programs send ring buffer events.
func (s *Stats) fsFamily(ctx context.Context) (*statagg.Family, error) {
	if s.fsAccum == nil {
		return nil, nil
	}
	decorate, err := s.newAggregatedStatDecorator(ctx)
	if err != nil {
		return nil, fmt.Errorf("decorating aggregated stats: %w", err)
	}

	fs := stats.FsAccum{Source: s.fsAccum, Layout: s.fsLayout, Decorate: decorate}
	if s.aggDeps.store != nil {
		fs.Pods = s.podMemory()
	}
	if cgroupV2() {
		fs.Cgroups = s.cgroupIndex()
	} else {
		alog().Info("no cgroup v2 hierarchy: aggregated filesystem metrics find their pod through a process" +
			" of each container, not through its cgroup")
	}
	family, err := stats.NewFsAccumFamily(fs)
	if err != nil {
		return nil, fmt.Errorf("filesystem aggregation: %w", err)
	}
	return family, nil
}
