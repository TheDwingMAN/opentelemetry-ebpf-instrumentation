// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"encoding/binary"
	"sort"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/parity"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
)

const blockTestCPUs = 4

var allBlockFeatures = export.FeatureStorageBlockDuration | export.FeatureStorageBlockIo |
	export.FeatureStorageBlockQueue | export.FeatureStorageBlockErrors |
	export.FeatureStorageBlockFlush | export.FeatureStorageBlockDiscard

// The value words the families read are where the kernel structs have them.
func TestBlockValueWordsMatchTheKernelStructs(t *testing.T) {
	const counter = int(unsafe.Sizeof(uint64(0)))
	svc, exp := ebpf.StatsBlkAggVal{}, ebpf.StatsBlkAggExpVal{}
	assert.Equal(t, blkWordBytes*counter, int(unsafe.Offsetof(svc.Bytes)))
	assert.Equal(t, blkWordSvcSum*counter, int(unsafe.Offsetof(svc.SvcSumNs)))
	assert.Equal(t, blkWordSvcFirst*counter, int(unsafe.Offsetof(svc.SvcBkt)))
	assert.Equal(t, blkWordSvcFirst*counter, int(unsafe.Offsetof(exp.SvcBkt)))

	q, qexp := ebpf.StatsBlkQueueAggVal{}, ebpf.StatsBlkQueueAggExpVal{}
	assert.Equal(t, blkWordQueueSum*counter, int(unsafe.Offsetof(q.QueueSumNs)))
	assert.Equal(t, blkWordQueueFirst*counter, int(unsafe.Offsetof(q.QueueBkt)))
	assert.Equal(t, blkWordQueueFirst*counter, int(unsafe.Offsetof(qexp.QueueBkt)))

	explicit, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)
	exponential, err := statagg.NewExponentialLayout(statagg.DefaultExponentialScale)
	require.NoError(t, err)
	// Every bucket a layout can have has a word in the value.
	assert.Len(t, svc.SvcBkt, statagg.MaxExplicitBounds+1)
	assert.Len(t, q.QueueBkt, statagg.MaxExplicitBounds+1)
	assert.Len(t, exp.SvcBkt, statagg.MaxExponentialBounds+1)
	assert.Len(t, qexp.QueueBkt, statagg.MaxExponentialBounds+1)
	assert.LessOrEqual(t, explicit.Buckets(), len(svc.SvcBkt))
	assert.LessOrEqual(t, exponential.Buckets(), len(exp.SvcBkt))
}

func TestBlockStat(t *testing.T) {
	s, final := blockStat(blockKey(252<<20|16, uint8(ebpf.CodeBlockFlush), 5), nil)
	require.NotNil(t, s)
	assert.True(t, final)
	assert.Equal(t, ebpf.StatTypeBlockIo, s.Type)
	assert.Equal(t, &ebpf.BlockIo{Dev: 252<<20 | 16, Op: uint8(ebpf.CodeBlockFlush), Error: -5}, s.BlockIo,
		"the key's positive errno is the event's negative error")

	s, _ = blockStat(blockKey(8<<20, uint8(ebpf.CodeBlockRead), 0), nil)
	assert.Zero(t, s.BlockIo.Error)

	// Step 13: the aggregation key carries the partition too.
	withPart := blockKeyWithPart(252<<20, 252<<20|1, uint8(ebpf.CodeBlockWrite), 0)
	s, _ = blockStat(withPart, nil)
	assert.Equal(t, uint32(252<<20|1), s.BlockIo.PartDev, "the key's partition decodes into the stat")

	s, _ = blockStat([]byte{1, 2}, nil)
	assert.Nil(t, s, "a short key counts for no metric")
}

// blockKernel builds the block families on in-memory maps, and records each
// event the way blk_io.c's blk_aggregate counts a completion.
type blockKernel struct {
	svc, queue *stataggtest.MemMap
	layout     *statagg.Layout
	families   []*statagg.Family
	registry   *statagg.Registry
	n          int
}

func newBlockKernel(t *testing.T, layout *statagg.Layout, features export.Features, decorate func(*ebpf.Stat) bool) *blockKernel {
	t.Helper()
	svcSize, queueSize := int(unsafe.Sizeof(ebpf.StatsBlkAggVal{})), int(unsafe.Sizeof(ebpf.StatsBlkQueueAggVal{}))
	if layout.Kind == statagg.LayoutExponential {
		svcSize, queueSize = int(unsafe.Sizeof(ebpf.StatsBlkAggExpVal{})), int(unsafe.Sizeof(ebpf.StatsBlkQueueAggExpVal{}))
	}
	k := &blockKernel{
		svc:    stataggtest.NewMemMap(blkKeySize, svcSize, blockTestCPUs),
		queue:  stataggtest.NewMemMap(blkKeySize, queueSize, blockTestCPUs),
		layout: layout,
	}
	if decorate == nil {
		decorate = func(*ebpf.Stat) bool { return true }
	}
	var err error
	k.families, err = BlockFamilies(k.svc, k.queue, layout, features,
		func() (func(*ebpf.Stat) bool, error) { return decorate, nil })
	require.NoError(t, err)
	k.registry, err = statagg.NewRegistry(k.families...)
	require.NoError(t, err)
	return k
}

// blockKey is a whole-disk key (part_dev 0).
func blockKey(dev uint32, kind uint8, errno uint16) []byte {
	return blockKeyWithPart(dev, 0, kind, errno)
}

// blockKeyWithPart is blk_agg_key_of: device, partition, kind and the
// positive errno.
func blockKeyWithPart(dev, partDev uint32, kind uint8, errno uint16) []byte {
	k := make([]byte, blkKeySize)
	binary.NativeEndian.PutUint32(k[blkKeyDev:], dev)
	binary.NativeEndian.PutUint32(k[blkKeyPartDev:], partDev)
	k[blkKeyKind] = kind
	binary.NativeEndian.PutUint16(k[blkKeyErr:], errno)
	return k
}

// record is blk_aggregate: the key's errno is the error made positive (and
// clamped to 16 bits), every completion counts its bytes and service time,
// and reads and writes with a queue wait count it in the queue map.
func (k *blockKernel) record(s *ebpf.Stat) {
	const counter, bucket = 8, 4
	io := s.BlockIo
	errno := uint16(min(uint32(-io.Error), 0xffff))
	key := blockKeyWithPart(io.Dev, io.PartDev, io.Op, errno)
	cpu := k.n % blockTestCPUs
	k.n++

	k.svc.AddU64(key, cpu, blkWordBytes*counter, io.Bytes)
	k.svc.AddU64(key, cpu, blkWordSvcSum*counter, io.LatencyNs)
	k.svc.AddU32(key, cpu, blkWordSvcFirst*counter+k.idx(io.LatencyNs)*bucket, 1)
	if io.QueueNs == 0 || !io.IsReadWrite() {
		return
	}
	k.queue.AddU64(key, cpu, blkWordQueueSum*counter, io.QueueNs)
	k.queue.AddU32(key, cpu, blkWordQueueFirst*counter+k.idx(io.QueueNs)*bucket, 1)
}

// idx is bpf/statsolly/hist.h's search: the first bound >= v.
func (k *blockKernel) idx(v uint64) int {
	return sort.Search(len(k.layout.BoundsNs), func(i int) bool { return v <= k.layout.BoundsNs[i] })
}

func (k *blockKernel) kernel() parity.Kernel {
	return parity.Kernel{Registry: k.registry, Families: k.families, Record: k.record}
}

func runBlockParity(t *testing.T, setup parity.Setup, layout *statagg.Layout, events []*ebpf.Stat) {
	t.Helper()
	parity.Run(t, setup, events, func(decorate func(*ebpf.Stat) bool) parity.Kernel {
		return newBlockKernel(t, layout, setup.Features, decorate).kernel()
	})
}

func TestBlockAggregationParity_ExplicitBuckets(t *testing.T) {
	otelBuckets, promBuckets := export.DefaultBuckets, export.DefaultBuckets
	// The exporters' bounds differ: the kernel counts in their union.
	promBuckets.StatDiskOperationDurationHistogram = []float64{0.0005, 0.001, 0.003, 0.01, 0.1, 1}
	layout, err := statagg.NewExplicitLayout(otelBuckets.StatDiskOperationDurationHistogram,
		promBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)

	runBlockParity(t, parity.Setup{Features: allBlockFeatures, OTelBuckets: otelBuckets, PromBuckets: promBuckets},
		layout, parity.BlockEvents(3000, layout.BoundsNs, false))
}

func TestBlockAggregationParity_ExponentialBuckets(t *testing.T) {
	layout, err := statagg.NewExponentialLayout(statagg.DefaultExponentialScale)
	require.NoError(t, err)
	runBlockParity(t, parity.Setup{
		Features:    allBlockFeatures,
		OTelBuckets: export.DefaultBuckets,
		PromBuckets: export.DefaultBuckets,
		Exponential: true,
	}, layout, parity.BlockEvents(3000, layout.BoundsNs, true))
}

// Each metric alone: the families export only what is enabled, and every
// metric keeps its own condition on the events.
func TestBlockAggregationParity_OneMetricAtATime(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)
	for name, f := range map[string]export.Features{
		"duration": export.FeatureStorageBlockDuration,
		"io":       export.FeatureStorageBlockIo,
		"queue":    export.FeatureStorageBlockQueue,
		"errors":   export.FeatureStorageBlockErrors,
		"flush":    export.FeatureStorageBlockFlush,
		"discard":  export.FeatureStorageBlockDiscard,
	} {
		t.Run(name, func(t *testing.T) {
			runBlockParity(t, parity.Setup{
				Features: f, OTelBuckets: export.DefaultBuckets, PromBuckets: export.DefaultBuckets,
			}, layout, parity.BlockEvents(1000, layout.BoundsNs, false))
		})
	}
}

func TestBlockAggregationParity_FiltersAndSelection(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)
	for name, setup := range map[string]parity.Setup{
		"direction filter": {Filters: filter.AttributeFamilyConfig{"disk.io.direction": filter.MatchDefinition{Match: "read"}}},
		"error filter":     {Filters: filter.AttributeFamilyConfig{"error.type": filter.MatchDefinition{NotMatch: "ETIMEDOUT"}}},
		"error.type selected": {Selection: attributes.Selection{
			attributes.StatDiskOperationDuration.Section: attributes.InclusionLists{Include: []string{"*"}},
			attributes.StatDiskQueueDuration.Section:     attributes.InclusionLists{Include: []string{"*"}},
			attributes.StatDiskIO.Section:                attributes.InclusionLists{Exclude: []string{"disk.io.direction"}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			setup.Features = allBlockFeatures
			setup.OTelBuckets, setup.PromBuckets = export.DefaultBuckets, export.DefaultBuckets
			runBlockParity(t, setup, layout, parity.BlockEvents(1000, layout.BoundsNs, false))
		})
	}
}

// obi.disk.partition (step 13) is carried in the aggregation key itself, not
// only in a getter: selecting it must still agree between the per-event and
// aggregated paths, including the whole-disk (part_dev 0) series that
// shares a device with a partitioned one.
func TestBlockAggregationParity_Partition(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)

	const dev = uint32(252 << 20)
	events := []*ebpf.Stat{
		{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{
			Dev: dev, PartDev: dev | 1, Op: uint8(ebpf.CodeBlockRead), Bytes: 4096, LatencyNs: 50_000,
		}},
		{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{
			Dev: dev, PartDev: dev | 2, Op: uint8(ebpf.CodeBlockWrite), Bytes: 8192, LatencyNs: 120_000,
		}},
		{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{
			Dev: dev, PartDev: 0, Op: uint8(ebpf.CodeBlockRead), Bytes: 16384, LatencyNs: 75_000,
		}},
	}

	runBlockParity(t, parity.Setup{
		Features: allBlockFeatures, OTelBuckets: export.DefaultBuckets, PromBuckets: export.DefaultBuckets,
		Selection: attributes.Selection{
			attributes.StatDiskOperationDuration.Section: attributes.InclusionLists{Include: []string{"*"}},
			attributes.StatDiskIO.Section:                attributes.InclusionLists{Include: []string{"*"}},
		},
	}, layout, events)
}

// The bios of stacked volumes (storage_block_volumes, step 20) are counted in
// the maps of the requests, under the volume's own device: every kind, with
// no queue wait, failures included, and a partition when the bio was
// submitted to one (an md array's partition is 259:N, its disk 9:M). The
// aggregated path must export them as the per-event path does, next to the
// requests of the disk below.
func TestBlockAggregationParity_Volumes(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)

	const (
		disk     = uint32(252 << 20)
		thin     = uint32(253<<20 | 4)
		md       = uint32(9<<20 | 127)
		mdPart   = uint32(259<<20 | 2)
		eio      = -5
		enospc   = -28
		chunk    = 64 << 10
		journal  = 4096
		oneMiB   = 1 << 20
		fragment = 16
	)
	bio := func(dev, part uint32, op ebpf.BlockOpCode, bytes, latencyNs uint64, errno int32) *ebpf.Stat {
		return &ebpf.Stat{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{
			Dev: dev, PartDev: part, Op: uint8(op), Bytes: bytes, LatencyNs: latencyNs, Error: errno,
		}}
	}
	var events []*ebpf.Stat
	for i := range uint64(200) {
		// One 1 MiB write bio on the thin volume, counted once, and the
		// requests its fragments became on the disk, each with a queue wait.
		events = append(events, bio(thin, 0, ebpf.CodeBlockWrite, oneMiB, 900_000+i*1000, 0))
		for range fragment {
			rq := bio(disk, 0, ebpf.CodeBlockWrite, chunk, 40_000+i*100, 0)
			rq.BlockIo.QueueNs = 5_000 + i
			events = append(events, rq)
		}
		events = append(events,
			bio(thin, 0, ebpf.CodeBlockRead, journal, 60_000+i*500, 0),
			// An empty preflush bio is the volume's flush; a failed one keeps its errno.
			bio(thin, 0, ebpf.CodeBlockFlush, 0, 1_500_000+i*100, 0),
			bio(md, mdPart, ebpf.CodeBlockWrite, journal, 80_000+i*300, 0),
			bio(md, 0, ebpf.CodeBlockRead, journal, 70_000+i*300, 0),
		)
		if i%20 == 0 {
			events = append(events,
				bio(thin, 0, ebpf.CodeBlockWrite, journal, 30_000, enospc),
				bio(thin, 0, ebpf.CodeBlockRead, journal, 20_000, eio),
				bio(thin, 0, ebpf.CodeBlockFlush, 0, 10_000, eio),
				bio(thin, 0, ebpf.CodeBlockDiscard, 64<<20, 2_000_000, 0),
				bio(md, mdPart, ebpf.CodeBlockDiscard, oneMiB, 300_000, eio),
			)
		}
	}

	for name, selection := range map[string]attributes.Selection{
		"default attributes": nil,
		"partition selected": {
			attributes.StatDiskOperationDuration.Section: attributes.InclusionLists{Include: []string{"*"}},
			attributes.StatDiskIO.Section:                attributes.InclusionLists{Include: []string{"*"}},
			attributes.StatDiskOperationErrors.Section:   attributes.InclusionLists{Include: []string{"*"}},
			attributes.StatDiskDiscardDuration.Section:   attributes.InclusionLists{Include: []string{"*"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			runBlockParity(t, parity.Setup{
				Features: allBlockFeatures, OTelBuckets: export.DefaultBuckets, PromBuckets: export.DefaultBuckets,
				Selection: selection,
			}, layout, events)
		})
	}
}

// With only the queue wait enabled, nothing exports blk_agg, but the kernel
// still counts reads and writes there: its family must still read it and
// delete its idle keys, or the map fills up and counts drops.
func TestBlockFamilies_ServiceMapReadWithoutItsMetrics(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)
	k := newBlockKernel(t, layout, export.FeatureStorageBlockQueue, nil)
	require.Len(t, k.families, 2)
	assert.True(t, k.registry.Handles(attributes.StatDiskQueueDuration))
	assert.False(t, k.registry.Handles(attributes.StatDiskOperationDuration))
}

// Without the queue wait there is no queue family, whatever map is passed.
func TestBlockFamilies_NoQueueFamilyWithoutQueueWait(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)
	k := newBlockKernel(t, layout, export.FeatureStorageBlockDuration, nil)
	require.Len(t, k.families, 1)
	assert.False(t, k.registry.Handles(attributes.StatDiskQueueDuration))

	families, err := BlockFamilies(k.svc, nil, layout, allBlockFeatures,
		func() (func(*ebpf.Stat) bool, error) { return nil, nil })
	require.NoError(t, err)
	assert.Len(t, families, 1, "a nil queue map has no family")
}
