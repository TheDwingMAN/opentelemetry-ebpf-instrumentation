// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"encoding/binary"
	"time"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

// The key of blk_agg and blk_q_agg (struct blk_agg_key in
// bpf/statsolly/blk_helpers.h), located through its bpf2go type.
var (
	blkKeySize    = int(unsafe.Sizeof(ebpf.StatsBlkAggKey{}))
	blkKeyDev     = int(unsafe.Offsetof(ebpf.StatsBlkAggKey{}.Dev))
	blkKeyPartDev = int(unsafe.Offsetof(ebpf.StatsBlkAggKey{}.PartDev))
	blkKeyKind    = int(unsafe.Offsetof(ebpf.StatsBlkAggKey{}.Kind))
	blkKeyErr     = int(unsafe.Offsetof(ebpf.StatsBlkAggKey{}.Err))
)

// The counting words of the values (maps/blk_agg.h, maps/blk_q_agg.h): u64
// counters, then the u32 buckets of the layout. The explicit and exponential
// values differ in their number of buckets only.
const (
	// blk_agg: bytes, service time sum, service time buckets.
	blkWordBytes    = 0
	blkWordSvcSum   = 1
	blkSvcCounters  = 2
	blkWordSvcFirst = blkSvcCounters
	// blk_q_agg: queue wait sum, queue wait buckets.
	blkWordQueueSum   = 0
	blkQueueCounters  = 1
	blkWordQueueFirst = blkQueueCounters
)

// BlockFamilies reads the block aggregation maps: service is blk_agg (or
// blk_agg_exp), queue is blk_q_agg (or blk_q_agg_exp), nil when the queue
// wait is not measured. The families export the enabled block metrics, with
// the conditions the per-event exporters apply to each event: reads and
// writes feed the read/write metrics, flushes and discards their own, a
// failed read or write counts as an error, and a failed discard releases no
// bytes. newDecorate gives each family the pipeline's decoration and filters,
// which cache per caller and so must not be shared between families.
func BlockFamilies(
	service, queue statagg.Source, layout *statagg.Layout, features export.Features,
	newDecorate func() (func(*ebpf.Stat) bool, error),
) ([]*statagg.Family, error) {
	return blockFamilies(service, queue, layout, features, newDecorate, time.Now)
}

// blockFamilies is BlockFamilies on a clock.
func blockFamilies(
	service, queue statagg.Source, layout *statagg.Layout, features export.Features,
	newDecorate func() (func(*ebpf.Stat) bool, error), clock func() time.Time,
) ([]*statagg.Family, error) {
	buckets := layout.Buckets()
	svc := func(name attributes.Name, sel func(*ebpf.BlockIo) bool) *statagg.Metric {
		return &statagg.Metric{
			Name: name, Kind: statagg.KindHistogram, Select: blockSelect(sel),
			SumWord: blkWordSvcSum, BucketWord: blkWordSvcFirst, Layout: layout,
		}
	}
	bytes := func(d statagg.Delta) uint64 { return d.Counter(blkWordBytes) }
	completions := func(d statagg.Delta) uint64 { return d.Sum(blkWordSvcFirst, buckets) }
	readWrite := (*ebpf.BlockIo).IsReadWrite

	var metrics []*statagg.Metric
	if features.StorageBlockDuration() {
		metrics = append(metrics, svc(attributes.StatDiskOperationDuration, readWrite))
	}
	if features.StorageBlockIo() {
		metrics = append(metrics, &statagg.Metric{
			Name: attributes.StatDiskIO, Kind: statagg.KindCounter, Select: blockSelect(readWrite), Value: bytes,
		})
	}
	if features.StorageBlockErrors() {
		metrics = append(metrics, &statagg.Metric{
			Name: attributes.StatDiskOperationErrors, Kind: statagg.KindCounter,
			Select: blockSelect(func(b *ebpf.BlockIo) bool { return b.IsReadWrite() && b.Error != 0 }),
			Value:  completions,
		})
	}
	if features.StorageBlockFlush() {
		metrics = append(metrics, svc(attributes.StatDiskFlushDuration, (*ebpf.BlockIo).IsFlush))
	}
	if features.StorageBlockDiscard() {
		metrics = append(metrics, svc(attributes.StatDiskDiscardDuration, (*ebpf.BlockIo).IsDiscard),
			&statagg.Metric{
				Name: attributes.StatDiskDiscardIO, Kind: statagg.KindCounter,
				Select: blockSelect(func(b *ebpf.BlockIo) bool { return b.IsDiscard() && b.Error == 0 }),
				Value:  bytes,
			})
	}

	var families []*statagg.Family
	add := func(name string, src statagg.Source, layoutWords statagg.ValueLayout, metrics []*statagg.Metric) error {
		decorate, err := newDecorate()
		if err != nil {
			return err
		}
		f, err := statagg.NewFamily(statagg.Config{
			Name: name, Source: src, Layout: layoutWords, Stat: blockStat, Decorate: decorate, Metrics: metrics,
			Clock: clock,
		})
		if err != nil {
			return err
		}
		families = append(families, f)
		return nil
	}
	// The kernel counts in blk_agg whenever a kind of request reaches it,
	// so its family reads it, even with none of its metrics enabled (only the
	// queue wait's), to delete its idle keys.
	if err := add("blk_agg", service, statagg.ValueLayout{Counters: blkSvcCounters, Buckets: buckets, Monotonic: true}, metrics); err != nil {
		return nil, err
	}
	if queue != nil && features.StorageBlockQueue() {
		queueMetric := &statagg.Metric{
			Name: attributes.StatDiskQueueDuration, Kind: statagg.KindHistogram, Select: blockSelect(readWrite),
			SumWord: blkWordQueueSum, BucketWord: blkWordQueueFirst, Layout: layout,
		}
		if err := add("blk_q_agg", queue, statagg.ValueLayout{Counters: blkQueueCounters, Buckets: buckets, Monotonic: true},
			[]*statagg.Metric{queueMetric}); err != nil {
			return nil, err
		}
	}
	return families, nil
}

func blockSelect(sel func(*ebpf.BlockIo) bool) func(*ebpf.Stat) bool {
	return func(s *ebpf.Stat) bool { return sel(s.BlockIo) }
}

// blockStat is the stat the per-event path builds for every completion a
// kernel key counts: its device, kind and error. The key holds the errno
// positive; the event, and so the stat, holds it negative.
func blockStat(key, _ []byte) (*ebpf.Stat, bool) {
	if len(key) < blkKeySize {
		return nil, true
	}
	return &ebpf.Stat{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{
		Dev:     binary.NativeEndian.Uint32(key[blkKeyDev:]),
		PartDev: binary.NativeEndian.Uint32(key[blkKeyPartDev:]),
		Op:      key[blkKeyKind],
		Error:   -int32(binary.NativeEndian.Uint16(key[blkKeyErr:])),
	}}, true
}
