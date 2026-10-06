// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

// fakeBioInflight is the bio in-flight map in memory.
type fakeBioInflight struct {
	entries map[uint64]BlkBioBlkRqInflight
	// reuse are bio pointers the kernel reuses for a new bio, queued at the
	// given time, between the sweep's pass and its delete.
	reuse map[uint64]uint64
}

func (f *fakeBioInflight) ForEach(fn func(bio uint64, v *BlkBioBlkRqInflight)) error {
	for bio, v := range f.entries {
		fn(bio, &v)
	}
	for bio, issueNs := range f.reuse {
		v := f.entries[bio]
		v.IssueNs = issueNs
		f.entries[bio] = v
	}
	return nil
}

func (f *fakeBioInflight) DeleteIfQueuedAt(bio, issueNs uint64) error {
	if v, ok := f.entries[bio]; ok && v.IssueNs == issueNs {
		delete(f.entries, bio)
	}
	return nil
}

type sweepFixture struct {
	sweeper     *bioSweeper
	inflight    *fakeBioInflight
	now         time.Duration
	quarantined map[uint32]int
	log         *bytes.Buffer
	next        uint64
}

func newSweepFixture() *sweepFixture {
	f := &sweepFixture{
		inflight: &fakeBioInflight{entries: map[uint64]BlkBioBlkRqInflight{}, reuse: map[uint64]uint64{}},
		now:      time.Hour, quarantined: map[uint32]int{}, log: &bytes.Buffer{}, next: 0xffff_8880_0000_0000,
	}
	f.sweeper = &bioSweeper{
		log:        slog.New(slog.NewTextHandler(f.log, nil)),
		inflight:   f.inflight,
		capacity:   1 << 16,
		monoNow:    func() time.Duration { return f.now },
		quarantine: func(dev uint32, stale int) { f.quarantined[dev] = stale },
	}
	return f
}

// queue adds n bios of dev queued age ago and returns the pointer of the
// last.
func (f *sweepFixture) queue(dev uint32, age time.Duration, n int) uint64 {
	for range n {
		f.next += 0x100
		f.inflight.entries[f.next] = BlkBioBlkRqInflight{IssueNs: uint64(f.now - age), Dev: dev}
	}
	return f.next
}

func (f *sweepFixture) left(dev uint32) int {
	n := 0
	for _, v := range f.inflight.entries {
		if v.Dev == dev {
			n++
		}
	}
	return n
}

// The sweep deletes the entries left for longer than the stale age, and only
// those: a bio in flight for seconds, or minutes, is still in flight.
func TestBioSweepDeletesStaleEntriesOnly(t *testing.T) {
	const healthy, lossy = 1, 2
	f := newSweepFixture()
	f.queue(healthy, time.Millisecond, 100)
	f.queue(healthy, BlockInflightStaleAge-time.Second, 5)
	f.queue(lossy, time.Second, 3)
	f.queue(lossy, BlockInflightStaleAge+time.Second, blkVolDeadBios-1)

	assert.Equal(t, blkVolDeadBios-1, f.sweeper.sweep())
	assert.Equal(t, 105, f.left(healthy))
	assert.Equal(t, 3, f.left(lossy))
	assert.Empty(t, f.quarantined, "a few missed completions do not cost a volume its metrics")

	assert.Zero(t, f.sweeper.sweep(), "nothing is stale any more")
	assert.Equal(t, 1, strings.Count(f.log.String(), "level=INFO"), "swept entries are logged once")
}

// A volume that leaves many bios behind is one whose driver does not trace
// completions: it is handed to quarantine, which takes it out of the set, and
// its younger bios go with it.
func TestBioSweepQuarantinesAVolumeWhoseBiosNeverComplete(t *testing.T) {
	const healthy, dead = 1, 2
	f := newSweepFixture()
	f.queue(healthy, time.Millisecond, 10)
	f.queue(healthy, 2*BlockInflightStaleAge, 1)
	f.queue(dead, 2*BlockInflightStaleAge, blkVolDeadBios)
	f.queue(dead, time.Second, 50)

	assert.Equal(t, blkVolDeadBios+1, f.sweeper.sweep())
	assert.Equal(t, map[uint32]int{dead: blkVolDeadBios}, f.quarantined)
	assert.Equal(t, 10, f.left(healthy))
	assert.Zero(t, f.left(dead), "a volume no longer tracked keeps no room in the map, nor pending bios")
}

// The map is shared by every volume. One whose bios never complete fills it at
// its I/O rate, and the bios of every volume would then be dropped until its
// entries were minutes old: in a crowded map, bios left for seconds are
// stale, and the volume is quarantined at once.
func TestBioSweepCrowdedMapQuarantinesWithinSeconds(t *testing.T) {
	const healthy, dead = 1, 2
	f := newSweepFixture()
	f.sweeper.capacity = 512
	f.queue(healthy, time.Millisecond, 20)
	f.queue(healthy, blkBioCrowdedAge+time.Second, blkVolDeadBios-1)
	f.queue(dead, blkBioCrowdedAge+time.Second, 200)
	f.queue(dead, time.Millisecond, 40)
	require.GreaterOrEqual(t, 2*len(f.inflight.entries), f.sweeper.capacity, "the map is half full")

	assert.Equal(t, 200+blkVolDeadBios-1, f.sweeper.sweep())
	assert.Equal(t, map[uint32]int{dead: 200}, f.quarantined)
	assert.Equal(t, 20, f.left(healthy), "bios in flight for less than the crowded age stay")
	assert.Zero(t, f.left(dead))
	assert.Equal(t, 1, strings.Count(f.log.String(), "level=WARN"), f.log.String())

	t.Run("a map with room keeps bios for the stale age", func(t *testing.T) {
		f := newSweepFixture()
		f.queue(dead, blkBioCrowdedAge+time.Second, 200)
		assert.Zero(t, f.sweeper.sweep())
		assert.Empty(t, f.quarantined)
		assert.Equal(t, 200, f.left(dead))
	})
}

// Wired to the set, a sweep that finds a dead volume removes it from the
// kernel set with one warning.
func TestBioSweepRemovesADeadVolumeFromTheSet(t *testing.T) {
	dm3, md0 := devT(majorDM, 3), devT(majorMD, 0)
	set := newVolumeSetFixture(map[uint32]string{dm3: "dm-3", md0: "md0"})
	require.NoError(t, set.set.refresh())

	f := newSweepFixture()
	f.sweeper.quarantine = set.set.quarantine
	f.queue(md0, 2*BlockInflightStaleAge, 3*blkVolDeadBios)
	f.queue(dm3, time.Millisecond, 4)

	f.sweeper.sweep()
	assert.Equal(t, []uint32{dm3}, set.kernel.sorted())
	assert.Equal(t, 1, set.warnings())

	// md0 keeps leaving bios behind until its entries are gone; it is not
	// tracked any more, so nothing is warned about again.
	f.queue(md0, 2*BlockInflightStaleAge, blkVolDeadBios)
	f.sweeper.sweep()
	assert.Equal(t, 1, set.warnings())
	assert.Zero(t, f.left(md0))
}

// Between the pass and the delete the kernel can reuse a struct bio: the
// entry under that pointer is then a live bio, and is not deleted.
func TestBioSweepSparesAReusedPointer(t *testing.T) {
	f := newSweepFixture()
	reused := f.queue(1, 2*BlockInflightStaleAge, 1)
	f.inflight.reuse[reused] = uint64(f.now)
	f.queue(1, 2*BlockInflightStaleAge, 2)

	assert.Equal(t, 3, f.sweeper.sweep())
	require.Contains(t, f.inflight.entries, reused)
	assert.Equal(t, uint64(f.now), f.inflight.entries[reused].IssueNs)
	assert.Equal(t, 1, f.left(1))
}

// The programs are chosen from the tracepoint prototypes, as for requests:
// tp_btf with raw_tp next to it, then raw_tp alone; the completion program
// is attached before the queue one.
func TestBioLoadStages(t *testing.T) {
	stages := bioLoadStages(blockTracepointLayout{})
	require.Len(t, stages, 2)
	assert.Equal(t, []string{
		progObiStatsTpBtfBlockBioComplete, progObiStatsTpBtfBlockBioQueue,
		progObiStatsRawTpBlockBioComplete, progObiStatsRawTpBlockBioQueue,
	}, stages[0].programs())
	assert.Equal(t, []string{progObiStatsRawTpBlockBioComplete, progObiStatsRawTpBlockBioQueue}, stages[1].programs())
	assert.ElementsMatch(t, []string{progObiStatsTpBtfBlockBioQueueLegacy, progObiStatsRawTpBlockBioQueueLegacy},
		programsNotIn(allBioProgramNames(), stages[0].programs()))

	legacy := bioLoadStages(blockTracepointLayout{bioQueueLegacy: true})
	assert.Equal(t, []string{
		progObiStatsTpBtfBlockBioComplete, progObiStatsTpBtfBlockBioQueueLegacy,
		progObiStatsRawTpBlockBioComplete, progObiStatsRawTpBlockBioQueueLegacy,
	}, legacy[0].programs(), "block_bio_queue(q, bio), before Linux 5.11")

	for _, set := range stages[0].sets {
		assert.Equal(t, RawTracepointBlockBioQueue, set.issueTP)
		assert.Equal(t, RawTracepointBlockBioComplete, set.compTP)
	}
}

// Every program name is one of the BlkBio object.
func TestBioProgramNamesMatchTheObject(t *testing.T) {
	spec, err := LoadBlkBio()
	require.NoError(t, err)
	names := allBioProgramNames()
	assert.Len(t, spec.Programs, len(names))
	for _, name := range names {
		assert.Contains(t, spec.Programs, name)
	}
	assert.Len(t, bioPrograms(&BlkBioPrograms{}), len(names))
}

func TestBlockVolumesUnsupported(t *testing.T) {
	var (
		voidPtr     = &btf.Pointer{Target: &btf.Void{}}
		gendisk     = &btf.Struct{Name: "gendisk"}
		blockDevice = &btf.Struct{Name: "block_device", Members: []btf.Member{
			{Name: "bd_disk", Type: &btf.Pointer{Target: gendisk}},
		}}
		bio = &btf.Struct{Name: "bio", Members: []btf.Member{
			{Name: "bi_bdev", Type: &btf.Pointer{Target: blockDevice}},
		}}
		// Before Linux 5.12 a bio pointed at its gendisk.
		oldBio      = &btf.Struct{Name: "bio", Members: []btf.Member{{Name: "bi_disk", Type: &btf.Pointer{Target: gendisk}}}}
		request     = &btf.Pointer{Target: &btf.Struct{Name: "request"}}
		queue       = &btf.Pointer{Target: &btf.Struct{Name: "request_queue"}}
		blkSts      = &btf.Int{Name: "u8", Size: 1}
		unsignedInt = &btf.Int{Name: "unsigned int", Size: 4}
	)
	tracepoint := func(name string, args ...btf.Type) btf.Type {
		params := []btf.FuncParam{{Type: voidPtr}}
		for _, a := range args {
			params = append(params, btf.FuncParam{Type: a})
		}
		return &btf.Typedef{Name: "btf_trace_" + name, Type: &btf.Pointer{
			Target: &btf.FuncProto{Return: &btf.Void{}, Params: params},
		}}
	}
	specOf := func(types ...btf.Type) *btf.Spec {
		b, err := btf.NewBuilder(types, nil)
		require.NoError(t, err)
		spec, err := b.Spec()
		require.NoError(t, err)
		return spec
	}
	requestTracepoints := []btf.Type{
		tracepoint("block_rq_issue", request),
		tracepoint("block_rq_complete", request, blkSts, unsignedInt),
	}
	bioTracepoints := func(bio *btf.Struct) []btf.Type {
		ptr := &btf.Pointer{Target: bio}
		return append([]btf.Type{
			tracepoint("block_bio_queue", ptr), tracepoint("block_bio_complete", queue, ptr),
		}, requestTracepoints...)
	}

	t.Run("RHEL 9 and current kernels", func(t *testing.T) {
		layout, reason := blockVolumesUnsupported(specOf(append(bioTracepoints(bio), bio)...))
		assert.Empty(t, reason)
		assert.False(t, layout.bioQueueLegacy)
	})
	t.Run("no BTF", func(t *testing.T) {
		_, reason := blockVolumesUnsupported(nil)
		assert.Contains(t, reason, "no BTF")
	})
	t.Run("no bio tracepoint prototypes", func(t *testing.T) {
		_, reason := blockVolumesUnsupported(specOf(append(requestTracepoints, bio)...))
		assert.Contains(t, reason, "block_bio_queue")
	})
	t.Run("no request tracepoint prototypes", func(t *testing.T) {
		_, reason := blockVolumesUnsupported(specOf(bio))
		assert.NotEmpty(t, reason)
	})
	t.Run("a bio without bi_bdev, before Linux 5.12", func(t *testing.T) {
		_, reason := blockVolumesUnsupported(specOf(append(bioTracepoints(oldBio), oldBio)...))
		assert.Contains(t, reason, "bi_bdev")
	})
}

// The bio collection gets the load-time constants of the stats collection
// from the one statsConstants map: every constant its programs read is set,
// to the value the request programs get, and the maps both declare have one
// size.
func TestBioCollectionSharesConstantsAndMapSizes(t *testing.T) {
	for name, agg := range map[string]*BlockAggregation{
		"per event":   nil,
		"explicit":    explicitAgg(8 << 20),
		"exponential": {Exponential: true, BoundsNs: make([]uint64, blkExponentialBounds), BudgetBytes: 8 << 20},
	} {
		t.Run(name, func(t *testing.T) {
			load := blockLoadPlan{
				mapEntries: map[string]uint32{StatsMapBlkDevState: unusedMapEntries},
				emitKinds:  allKinds, wantPart: true,
			}
			load.agg = planBlockAgg(agg, true, allKinds, 3, 2, 4, false, load.mapEntries, quietLog)
			consts := statsConstants(&config.EBPFTracer{BpfDebug: true, StatsWakeupDataBytes: 4096}, load, FsAggregation{})

			stats, err := LoadStats()
			require.NoError(t, err)
			require.NoError(t, ebpfconvenience.RewriteConstants(stats, specConstants(stats, consts)))
			require.NoError(t, setMapEntries(stats, load.mapEntries))

			bio, err := LoadBlkBio()
			require.NoError(t, err)
			require.NoError(t, ebpfconvenience.RewriteConstants(bio, specConstants(bio, consts)))
			for name, n := range load.mapEntries {
				if m := bio.Maps[name]; m != nil {
					m.MaxEntries = n
				}
			}

			for name, v := range bio.Variables {
				if !v.Constant() || (!strings.HasPrefix(name, "blk_") && !strings.HasPrefix(name, "stats_")) {
					continue
				}
				require.Contains(t, consts, name, "a constant of the bio programs is left at its default")
				require.Contains(t, stats.Variables, name)
				assert.Equal(t, stats.Variables[name].Value, v.Value, "constant %s differs between the collections", name)
			}
			for _, name := range []string{"blk_emit_mode", "blk_emit_kinds", "blk_want_part", "blk_hist_exp", "blk_bounds_ns"} {
				assert.Contains(t, bio.Variables, name)
			}
			assert.False(t, bio.Variables["blk_vol_major"].Constant(), "userspace writes the majors while the programs run")
			assert.NotContains(t, bio.Variables, "blk_want_queue", "a bio has no queue wait")

			shared := 0
			for name, m := range bio.Maps {
				other := stats.Maps[name]
				if other == nil || m.Pinning != ebpfconvenience.PinInternal {
					continue
				}
				shared++
				assert.Equal(t, other.MaxEntries, m.MaxEntries, "map %s", name)
				assert.Equal(t, other.Type, m.Type, "map %s", name)
				assert.Equal(t, other.KeySize, m.KeySize, "map %s", name)
				assert.Equal(t, other.ValueSize, m.ValueSize, "map %s", name)
			}
			assert.GreaterOrEqual(t, shared, 5, "the aggregation maps, the events, the drop counters, the queue depth")
			assert.NotContains(t, bio.Maps, StatsMapBlkQ_agg, "the bio programs do not count a queue wait")
			assert.NotContains(t, bio.Maps, StatsMapBlkRqInflight)
			assert.NotContains(t, stats.Maps, BlkBioMapBlkBioInflight,
				"the bio maps exist only when the bio collection is loaded")
			assert.NotContains(t, stats.Maps, BlkBioMapBlkBioDevs)
		})
	}
}

// Stacked volumes add keys to the service map, one per kind as for a disk,
// and none to the queue map: a bio has no queue wait.
func TestPlanBlockAgg_Volumes(t *testing.T) {
	const disks, volumes = 6, 10
	entries := map[string]uint32{}
	planBlockAgg(explicitAgg(8<<20), true, allKinds, disks, volumes, 4, false, entries, quietLog)
	assert.Equal(t, uint32(4*(disks+volumes+blkAggHotplugDevices)+blkAggErrorKeys), entries[StatsMapBlkAgg])
	assert.Equal(t, uint32(2*(disks+blkAggHotplugDevices)+blkAggErrorKeys), entries[StatsMapBlkQ_agg])

	// A budget that holds fewer devices than the node has: the volumes
	// count among the devices that do not fit.
	var warned bytes.Buffer
	tight := map[string]uint32{}
	perDevice := 4*perCPUBytes(1, blkAggExplicit.serviceValue, 4) + 2*perCPUBytes(1, blkAggExplicit.queueValue, 4)
	errorKeys := perCPUBytes(blkAggErrorKeys, blkAggExplicit.serviceValue, 4) + perCPUBytes(blkAggErrorKeys, blkAggExplicit.queueValue, 4)
	planBlockAgg(explicitAgg(errorKeys+perDevice*8), true, allKinds, disks, volumes, 4, false, tight,
		slog.New(slog.NewTextHandler(&warned, nil)))
	assert.Equal(t, uint32(4*8+blkAggErrorKeys), tight[StatsMapBlkAgg])
	assert.Equal(t, uint32(2*8+blkAggErrorKeys), tight[StatsMapBlkQ_agg])
	assert.Contains(t, warned.String(), "level=WARN")
	assert.Contains(t, warned.String(), "volumes=10")
}
