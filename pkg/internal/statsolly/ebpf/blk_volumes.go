// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

// The bio programs of stacked volumes are an object of their own, apart from
// the stats object: they load as one more collection, only with
// storage_block_volumes, and a kernel that rejects them disables the volumes
// alone. Their maps are PinInternal: the aggregation maps, the ring buffer
// and the drop counters are the ones the block request programs use.
// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 -output-stem stats_blkbio BlkBio ../../../../bpf/statsolly/blk_bio.c -- -I../../../../bpf

// Program names of the BlkBio object.
const (
	progObiStatsTpBtfBlockBioQueue       = "obi_stats_tp_btf_block_bio_queue"
	progObiStatsTpBtfBlockBioQueueLegacy = "obi_stats_tp_btf_block_bio_queue_legacy"
	progObiStatsTpBtfBlockBioComplete    = "obi_stats_tp_btf_block_bio_complete"

	progObiStatsRawTpBlockBioQueue       = "obi_stats_raw_tp_block_bio_queue"
	progObiStatsRawTpBlockBioQueueLegacy = "obi_stats_raw_tp_block_bio_queue_legacy"
	progObiStatsRawTpBlockBioComplete    = "obi_stats_raw_tp_block_bio_complete"
)

// The bio tracepoints, attached by name as raw tracepoints (raw_tp and
// tp_btf). block_bio_queue fires when a bio is submitted to a device,
// block_bio_complete when a bio of a bio-based device ends.
const (
	RawTracepointBlockBioQueue    = "block_bio_queue"
	RawTracepointBlockBioComplete = "block_bio_complete"
)

// blockVolumeRefreshInterval is how often the set of tracked volumes is read
// again from sysfs: a volume created after startup is measured from the next
// pass on.
const blockVolumeRefreshInterval = 30 * time.Second

// The program sets reuse blockProgramSet: the queue program is its issue
// program, attached after the completion one for the same reason.
func tpBtfBioPrograms(layout blockTracepointLayout) blockProgramSet {
	return blockProgramSet{
		attach:   blockAttachTpBtf,
		issue:    pick(layout.bioQueueLegacy, progObiStatsTpBtfBlockBioQueueLegacy, progObiStatsTpBtfBlockBioQueue),
		complete: progObiStatsTpBtfBlockBioComplete,
		issueTP:  RawTracepointBlockBioQueue, compTP: RawTracepointBlockBioComplete,
	}
}

func rawTpBioPrograms(layout blockTracepointLayout) blockProgramSet {
	return blockProgramSet{
		attach:   blockAttachRawTp,
		issue:    pick(layout.bioQueueLegacy, progObiStatsRawTpBlockBioQueueLegacy, progObiStatsRawTpBlockBioQueue),
		complete: progObiStatsRawTpBlockBioComplete,
		issueTP:  RawTracepointBlockBioQueue, compTP: RawTracepointBlockBioComplete,
	}
}

func allBioProgramNames() []string {
	return []string{
		progObiStatsTpBtfBlockBioQueue, progObiStatsTpBtfBlockBioQueueLegacy, progObiStatsTpBtfBlockBioComplete,
		progObiStatsRawTpBlockBioQueue, progObiStatsRawTpBlockBioQueueLegacy, progObiStatsRawTpBlockBioComplete,
	}
}

// bioLoadStages are the loads of the bio collection tried in order, as for
// the request programs: tp_btf with raw_tp next to it, so that an attach
// failure of the first falls back without a reload, then raw_tp alone, for a
// kernel that rejects the tp_btf programs.
func bioLoadStages(layout blockTracepointLayout) []blockLoadStage {
	tpBtf, rawTp := tpBtfBioPrograms(layout), rawTpBioPrograms(layout)
	return []blockLoadStage{
		{sets: []blockProgramSet{tpBtf, rawTp}},
		{sets: []blockProgramSet{rawTp}},
	}
}

// blockVolumesUnsupported says why the bios of stacked volumes can't be
// measured on a kernel with this BTF, or "" when they can. The programs read
// the bio's device as bio->bi_bdev->bd_disk, which exists since Linux 5.12;
// before, a bio pointed at its gendisk (bi_disk), a layout these programs
// have no variant for. There is no fallback without BTF either: the classic
// bio tracepoints do not carry the bio pointer that pairs a completion with
// its queueing.
func blockVolumesUnsupported(kernel *btf.Spec) (blockTracepointLayout, string) {
	if kernel == nil {
		return blockTracepointLayout{}, "the kernel has no BTF"
	}
	layout, err := blockTracepointLayoutFrom(kernel)
	switch {
	case err != nil:
		return layout, "the kernel BTF does not give the block tracepoints' arguments: " + err.Error()
	case layout.bioUnknown:
		return layout, "the kernel BTF does not give the arguments of block_bio_queue and block_bio_complete as known"
	case !memberPointsToStruct(kernel, "bio", "bi_bdev", "block_device"):
		return layout, "struct bio has no bi_bdev on this kernel (older than Linux 5.12)"
	case !memberPointsToStruct(kernel, "block_device", "bd_disk", "gendisk"):
		return layout, "struct block_device has no bd_disk on this kernel"
	}
	return layout, ""
}

// blockVolumes is the loaded bio collection, its attached programs and the
// upkeep of what they depend on: the set of tracked volumes and the sweep of
// the in-flight map.
type blockVolumes struct {
	log      *slog.Logger
	objects  *BlkBioObjects
	links    []io.Closer
	attached blockAttach
	programs map[string]*ebpf.Program
	set      *volumeSet
	sweeper  *bioSweeper

	stop    chan struct{}
	stopped chan struct{}
}

// startBlockVolumes loads the bio collection, fills the set of tracked
// volumes, attaches the programs and starts the upkeep. mapEntries are the
// sizes the stats collection gave the block maps: the ones this collection
// shares must be declared with the same.
func startBlockVolumes(
	log *slog.Logger, cfg *config.EBPFTracer, consts map[string]any, mapEntries map[string]uint32,
	sharedMaps map[string]*ebpf.Map, mu *sync.Mutex, kernel *btf.Spec, cache *btf.Cache,
) (*blockVolumes, error) {
	layout, reason := blockVolumesUnsupported(kernel)
	if reason != "" {
		return nil, errors.New(reason)
	}

	stages := bioLoadStages(layout)
	objects := &BlkBioObjects{}
	stage := 0
	for ; ; stage++ {
		*objects = BlkBioObjects{}
		err := loadBlkBioObjects(cfg, consts, mapEntries, stages[stage], objects, sharedMaps, mu, cache)
		if err == nil {
			break
		}
		if stage+1 == len(stages) {
			return nil, fmt.Errorf("loading the bio programs: %w", err)
		}
		log.Warn("loading the bio programs of stacked volumes failed with those of "+
			strings.Join(stages[stage].setNames(), ", ")+"; retrying with "+
			strings.Join(stages[stage+1].setNames(), ", ")+" (likely kernel incompatibility)", "error", err)
	}

	v := &blockVolumes{
		log: log, objects: objects,
		stop: make(chan struct{}), stopped: make(chan struct{}),
	}
	v.set = newVolumeSet(log, func() (blockVolumeScan, error) { return listBlockVolumes(sysBlockDevicesDir) },
		volumeDevMap{objects.BlkBioDevs},
		func(majors [blkVolMajors]uint32) error { return objects.BlkVolMajor.Set(majors) })
	v.sweeper = &bioSweeper{
		log: log, inflight: newBioInflightMap(objects.BlkBioInflight),
		capacity: int(objects.BlkBioInflight.MaxEntries()), monoNow: timing.MonoTimeNow,
		quarantine: v.set.quarantine,
	}
	// The set first: the programs then measure from their first bio.
	if err := v.set.refresh(); err != nil {
		objects.Close()
		return nil, fmt.Errorf("tracking the stacked volumes: %w", err)
	}

	programs := bioPrograms(&objects.BlkBioPrograms)
	if err := v.attach(stages[stage], programs); err != nil {
		objects.Close()
		return nil, err
	}

	log.Info("the I/O of stacked volumes is measured from their bios", "attach", v.attached,
		"volumes", v.set.names(), "in_flight_entries", objects.BlkBioInflight.MaxEntries())
	go v.run()
	return v, nil
}

// attach attaches the first program set of stage that attaches whole.
func (v *blockVolumes) attach(stage blockLoadStage, programs map[string]*ebpf.Program) error {
	var errs []error
	for _, set := range stage.sets {
		links, err := attachBlockProgramSet(programs, set)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if len(errs) > 0 {
			v.log.Warn("failed bio tracepoint attachment; fell back to "+set.attach.String(), "error", errors.Join(errs...))
		}
		v.links, v.attached = links, set.attach
		v.programs = attachedPrograms(stage, set.attach, programs)
		return nil
	}
	return fmt.Errorf("attaching the bio programs: %w", errors.Join(errs...))
}

func (v *blockVolumes) run() {
	defer close(v.stopped)
	refresh := time.NewTicker(blockVolumeRefreshInterval)
	defer refresh.Stop()
	sweep := time.NewTicker(blkBioSweepInterval)
	defer sweep.Stop()
	for {
		select {
		case <-v.stop:
			return
		case <-refresh.C:
			if err := v.set.refresh(); err != nil {
				v.log.Debug("refreshing the tracked stacked volumes failed", "error", err)
			}
		case <-sweep.C:
			v.sweeper.sweep()
		}
	}
}

// Close stops the upkeep and detaches the programs, the queue program first
// so that no bio enters the in-flight map once its completion can no longer
// take it out.
func (v *blockVolumes) Close() error {
	close(v.stop)
	<-v.stopped
	var errs []error
	for _, l := range slices.Backward(v.links) {
		errs = append(errs, l.Close())
	}
	errs = append(errs, v.objects.Close())
	return errors.Join(errs...)
}

// loadBlkBioObjects loads the bio collection with the programs of stage.
func loadBlkBioObjects(
	cfg *config.EBPFTracer, consts map[string]any, mapEntries map[string]uint32, stage blockLoadStage,
	objects *BlkBioObjects, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex, cache *btf.Cache,
) error {
	spec, err := LoadBlkBio()
	if err != nil {
		return fmt.Errorf("loading BPF data: %w", err)
	}
	if err := fixupSpec(spec, programsNotIn(allBioProgramNames(), stage.programs())); err != nil {
		return fmt.Errorf("fixing up BPF spec: %w", err)
	}
	// Sized as the stats collection sizes its maps, or the shared maps it
	// created would not match this spec's.
	ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)
	for name, n := range mapEntries {
		if m := spec.Maps[name]; m != nil {
			m.MaxEntries = n
		}
	}
	if err := ebpfconvenience.LoadSpec(spec, objects, specConstants(spec, consts), sharedMaps, mu, "", cache); err != nil {
		return fmt.Errorf("loading the bio eBPF spec: %w", err)
	}
	return nil
}

// bioPrograms indexes the loaded bio programs by name.
func bioPrograms(p *BlkBioPrograms) map[string]*ebpf.Program {
	return map[string]*ebpf.Program{
		progObiStatsTpBtfBlockBioQueue:       p.ObiStatsTpBtfBlockBioQueue,
		progObiStatsTpBtfBlockBioQueueLegacy: p.ObiStatsTpBtfBlockBioQueueLegacy,
		progObiStatsTpBtfBlockBioComplete:    p.ObiStatsTpBtfBlockBioComplete,
		progObiStatsRawTpBlockBioQueue:       p.ObiStatsRawTpBlockBioQueue,
		progObiStatsRawTpBlockBioQueueLegacy: p.ObiStatsRawTpBlockBioQueueLegacy,
		progObiStatsRawTpBlockBioComplete:    p.ObiStatsRawTpBlockBioComplete,
	}
}
