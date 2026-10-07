// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// KernelCountersInterval is how often KernelCounters reads the kernel
// counters.
const KernelCountersInterval = 30 * time.Second

// KernelCounters reports what the stats programs count about themselves as
// OBI internal metrics: the inserts that failed because a map was full (the
// stats_drops map, per map). It logs the first drop of each map, since a drop
// means a metric undercounts. The block programs' recursion misses are
// reported by the fetcher, with those of the other storage programs, as
// obi.bpf.storage.program.recursion.misses.
type KernelCounters struct {
	drops   *ciliumebpf.Map
	metrics imetrics.Reporter
	log     *slog.Logger
	warned  map[string]bool
}

// NewKernelCounters reads drops (per-CPU u64 counters indexed as
// ebpf.KernelDropReasons; nil for none).
func NewKernelCounters(drops *ciliumebpf.Map, metrics imetrics.Reporter) *KernelCounters {
	if metrics == nil {
		metrics = imetrics.NoopReporter{}
	}
	return &KernelCounters{
		drops:   drops,
		metrics: metrics,
		log:     slog.With("component", "stats.KernelCounters"),
		warned:  map[string]bool{},
	}
}

// Run reports the counters every KernelCountersInterval until ctx is done.
func (k *KernelCounters) Run(ctx context.Context) {
	ticker := time.NewTicker(KernelCountersInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			k.Report()
		}
	}
}

// Report reads and reports the counters once.
func (k *KernelCounters) Report() {
	if k.drops != nil {
		for _, idx := range slices.Sorted(maps.Keys(ebpf.KernelDropReasons)) {
			k.reportDrops(idx, ebpf.KernelDropReasons[idx])
		}
	}
}

func (k *KernelCounters) reportDrops(idx uint32, mapName string) {
	var perCPU []uint64
	if err := k.drops.Lookup(idx, &perCPU); err != nil {
		k.log.Debug("can't read the stats drop counters", "map", mapName, "error", err)
		return
	}
	var total uint64
	for _, n := range perCPU {
		total += n
	}
	if total > 0 && !k.warned[mapName] {
		k.warned[mapName] = true
		k.log.Warn("a stats eBPF map is full: what its programs could not insert is not counted,"+
			" and the metrics it feeds undercount; see obi.bpf.map.insert.failures", "map", mapName, "failures", total)
	}
	k.metrics.BpfMapInsertFailures(mapName, total)
}
