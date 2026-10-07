// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
)

type probe struct {
	name    string
	program *ebpf.Program
	enabled bool
}

// Program names
const (
	progObiStatsKprobeTCPCloseSrtt                        = "obi_stats_kprobe_tcp_close_srtt"
	progObiStatsKprobeTCPCloseIoFlush                     = "obi_stats_kprobe_tcp_close_io_flush"
	progObiStatsTpInetSockSetStateConnRole                = "obi_stats_tp_inet_sock_set_state_conn_role"
	progObiStatsTpInetSockSetStateTCPFailedConnection     = "obi_stats_tp_inet_sock_set_state_tcp_failed_connection"
	progObiStatsTpInetSockSetStateTCPSuccessfulConnection = "obi_stats_tp_inet_sock_set_state_tcp_successful_connection"
	progObiStatsRawTpTCPRetransmitSkb                     = "obi_stats_raw_tp_tcp_retransmit_skb"
	progObiStatsKprobeTCPSendmsg                          = "obi_stats_kprobe_tcp_sendmsg"
	progObiStatsKretprobeTCPSendmsg                       = "obi_stats_kretprobe_tcp_sendmsg"
	progObiStatsKprobeTCPCleanupRbuf                      = "obi_stats_kprobe_tcp_cleanup_rbuf"
)

// Hook point names, grouped by attach type.
const (
	// Kprobes: kernel function names.
	KprobeTCPClose       = "tcp_close"
	KprobeTCPSendMsg     = "tcp_sendmsg"
	KprobeTCPCleanupRbuf = "tcp_cleanup_rbuf"

	// Tracepoints: group/name, are validated by TestTracepointConstantFormat
	TracepointInetSockSetState = "sock/inet_sock_set_state"
	TracepointBlockRqIssue     = "block/block_rq_issue"
	TracepointBlockRqComplete  = "block/block_rq_complete"
	// The same three events as raw tracepoints, attached by name without
	// tracefs (raw_tp and tp_btf). Preferred whenever the kernel BTF lets the
	// programs decode a request; the classic tracepoints remain for kernels
	// where it does not.
	RawTracepointBlockRqIssue    = "block_rq_issue"
	RawTracepointBlockRqComplete = "block_rq_complete"

	// Raw tracepoints: name only (no group prefix).
	RawTracepointTCPRetransmitSkb = "tcp_retransmit_skb"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type stat_type -type tcp_fail_reason -type tcp_handshake_role -type network_io_direction -type tcp_io_t -type tcp_rtt_t -type tcp_failed_connection_t -type tcp_retransmit_t -type tcp_successful_connection_t -type blk_io_op -type block_io_t -type fs_io_t -type stats_drop -type blk_emit -target $BPF_TARGETS Stats ../../../../bpf/statsolly/stats.c -- -I../../../../bpf

type StatsFetcher struct {
	log       *slog.Logger
	objects   *StatsObjects
	closables []io.Closer
	nfs       *nfsRPC
	// fsAccum is the filesystem aggregation map in use, nil when the
	// filesystem programs emit ring buffer events.
	fsAccum *ebpf.Map

	blockAgg      *BlockAggMaps
	blockPrograms map[string]*ebpf.Program
	// blockVolumes is the bio collection of storage_block_volumes, nil when
	// it is off or could not be loaded.
	blockVolumes *blockVolumes
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.StatFetcher")
}

// NewStatsFetcher loads and attaches the stats programs. With blockAgg, the
// block programs count completed requests in kernel maps (BlockAggregation)
// instead of sending events; nil keeps an event per request.
func NewStatsFetcher(
	cfg *config.EBPFTracer, features *export.Features, selectorCfg *attributes.SelectorConfig, fsAgg FsAggregation,
	nfsCfg NFSConfig, blockAgg *BlockAggregation, metrics imetrics.Reporter,
) (*StatsFetcher, error) {
	tlog := tlog()
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	objects := StatsObjects{}

	// UndefinedGroup is intentional: we only need to check NetworkTCPHandshakeRole,
	// which is a direct metric attribute.
	attrSel, err := attributes.NewAttrSelector(attributes.UndefinedGroup, selectorCfg)
	if err != nil {
		return nil, fmt.Errorf("creating attr selector: %w", err)
	}

	// OR across both metrics: a single shared probe writes sock_role for both consumers,
	// so the probe is needed if either metric has the attribute enabled.
	// Note: tcp successful connection probe derives role from oldstate and never reads sock_role
	connRoleAttrSelected := slices.Contains(attrSel.For(attributes.StatTCPRtt), attr.NetworkTCPHandshakeRole) ||
		slices.Contains(attrSel.For(attributes.StatTCPFailedConnections), attr.NetworkTCPHandshakeRole)
	connRoleUsed := (features.StatsTCPFailedConnections() || features.StatsTCPRtt()) && connRoleAttrSelected

	var toDisable []string
	if !features.StatsTCPFailedConnections() {
		toDisable = append(toDisable, progObiStatsTpInetSockSetStateTCPFailedConnection)
	}
	if !features.StatsTCPSuccessfulConnections() {
		toDisable = append(toDisable, progObiStatsTpInetSockSetStateTCPSuccessfulConnection)
	}
	if !connRoleUsed {
		toDisable = append(toDisable, progObiStatsTpInetSockSetStateConnRole)
	}
	if !features.StatsTCPRtt() {
		toDisable = append(toDisable, progObiStatsKprobeTCPCloseSrtt)
	}
	if !features.StatsTCPRetransmits() {
		toDisable = append(toDisable, progObiStatsRawTpTCPRetransmitSkb)
	}
	if !features.StatsTCPIo() {
		toDisable = append(toDisable, progObiStatsKprobeTCPSendmsg, progObiStatsKretprobeTCPSendmsg, progObiStatsKprobeTCPCleanupRbuf, progObiStatsKprobeTCPCloseIoFlush)
	}
	start := time.Now()
	// The startup loads are one BTF burst; startFsAttacher's first pass ends
	// it when filesystems are probed, this when they are not or on an error.
	btfParse, _ := kernelBTFCache.Parse()
	defer kernelBTFCache.Release()

	storageBlock := features.StorageBlock()
	storage := planStorage(storageBlock, kernelBTF(), tlog)
	wantQueue := features.StorageBlockQueue()
	if reason := blockQueueUnsupported(storageBlock, storage, kernelBTF()); wantQueue && reason != "" {
		tlog.Warn("obi.stat.disk.queue.duration is enabled but can't be recorded on this kernel: "+reason+
			"; the metric will have no series", "feature", "storage_block_queue")
		wantQueue = false
	}
	blockLoad := planBlockLoad(storageBlock, storage, wantQueue, features.StorageBlockQueueDepth(), func() uint32 {
		return blockInflightEntries(sysBlockDevicesDir)
	})
	blockLoad.emitKinds = blockEmitKinds(*features)
	if !features.StorageFS() {
		fsAgg = FsAggregation{}
	}
	blockLoad.wantPart = storageBlock && blockWantPartition(attrSel)
	if !storageBlock || len(storage.stages) == 0 || blockLoad.wantQueueDepth {
		// queue.depth is per event only: its caller never asks for both.
		blockAgg = nil
	}
	// The bios of stacked volumes are counted in the same maps, under the
	// volume's device: the maps are sized for the volumes there are now.
	wantVolumes := storageBlock && len(storage.stages) > 0 && features.StorageBlockVolumes()
	volumeDevices := 0
	if wantVolumes {
		volumeDevices = blockVolumeDevices(sysBlockDevicesDir, blockLoad.wantPart)
	}
	requestDevices := blockRequestDevices(sysBlockDevicesDir, blockLoad.wantPart)
	blockLoad.agg = planBlockAgg(blockAgg, wantQueue, blockLoad.emitKinds, requestDevices,
		volumeDevices, possibleCPUs(), blockLoad.wantPart, blockLoad.mapEntries, tlog)
	// The pod counters (storage_block_pod) are counted in the kernel in
	// either emit mode: they have no per-event path.
	blockLoad.wantCgroup = storageBlock && len(storage.stages) > 0 && features.StorageBlockPod()
	planBlockCgroup(blockLoad.wantCgroup, requestDevices+volumeDevices, possibleCPUs(),
		cfg.MapsConfig.GlobalScaleFactor, uint64(cfg.StorageAggregation.BlockPodMapsBudgetBytes), blockLoad.mapEntries, tlog)
	consts := statsConstants(cfg, blockLoad, fsAgg)

	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	load := func(toDisable []string) error {
		objects = StatsObjects{}
		return loadStatsObjects(cfg, blockLoad, consts, toDisable, &objects, sharedMaps, &mu, kernelBTFCache.Cache())
	}
	blockStage, err := loadWithBlockFallback(load, toDisable, storage.stages, tlog)
	if err != nil {
		return nil, err
	}

	var closables []io.Closer

	// kprobes
	for _, k := range []probe{
		{
			name:    KprobeTCPClose,
			program: objects.ObiStatsKprobeTcpCloseSrtt,
			enabled: features.StatsTCPRtt(),
		},
		{
			name:    KprobeTCPClose,
			program: objects.ObiStatsKprobeTcpCloseIoFlush,
			enabled: features.StatsTCPIo(),
		},
		{
			name:    KprobeTCPSendMsg,
			program: objects.ObiStatsKprobeTcpSendmsg,
			enabled: features.StatsTCPIo(),
		},
		{
			name:    KprobeTCPCleanupRbuf,
			program: objects.ObiStatsKprobeTcpCleanupRbuf,
			enabled: features.StatsTCPIo(),
		},
	} {
		if !k.enabled {
			continue
		}

		l, err := kprobe.Attach(k.name, k.program, false)
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed kprobe attachment %s: %w", k.name, err)
		}
		closables = append(closables, l)
	}

	// kretprobes
	for _, k := range []probe{
		{
			name:    KprobeTCPSendMsg,
			program: objects.ObiStatsKretprobeTcpSendmsg,
			enabled: features.StatsTCPIo(),
		},
	} {
		if !k.enabled {
			continue
		}
		l, err := kprobe.Attach(k.name, k.program, true)
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed kretprobe attachment %s: %w", k.name, err)
		}
		closables = append(closables, l)
	}

	// tracepoints
	// ObiStatsTpInetSockSetStateTcpFailedConnection (or any other probes that use role)
	// must be attached before ObiStatsTpInetSockSetStateConnRole.
	// Both attach to the same tracepoint and BPF programs run FIFO:
	// the probes read sock_role first, conn_role deletes it after.
	// Swapping the order would cause tcp_failed_conn or any other probes
	// to see NULL on the same TCP_CLOSE event that conn_role is cleaning up.
	for _, t := range []probe{
		{
			name:    TracepointInetSockSetState,
			program: objects.ObiStatsTpInetSockSetStateTcpSuccessfulConnection,
			enabled: features.StatsTCPSuccessfulConnections(),
		},
		{
			name:    TracepointInetSockSetState,
			program: objects.ObiStatsTpInetSockSetStateTcpFailedConnection,
			enabled: features.StatsTCPFailedConnections(),
		},
		{
			name:    TracepointInetSockSetState,
			program: objects.ObiStatsTpInetSockSetStateConnRole,
			enabled: connRoleUsed,
		},
	} {
		if !t.enabled {
			continue
		}

		group, tp, _ := strings.Cut(t.name, "/")
		l, err := link.Tracepoint(group, tp, t.program, nil)
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed tracepoint attachment %s: %w", t.name, err)
		}
		closables = append(closables, l)
	}

	// block tracepoints: best-effort. A kernel where the block tracepoints
	// cannot be attached must not take down the rest of the stats agent.
	blockAttached := blockAttachNone
	var attachedBlockPrograms map[string]*ebpf.Program
	if blockStage < len(storage.stages) {
		programs := blockPrograms(&objects.StatsPrograms)
		var links []io.Closer
		links, blockAttached = attachBlockSets(storage.stages[blockStage].sets,
			func(set blockProgramSet) ([]io.Closer, error) { return attachBlockProgramSet(programs, set) }, tlog)
		closables = append(closables, links...)
		attachedBlockPrograms = attachedPrograms(storage.stages[blockStage], blockAttached, programs)
	}

	// bios of stacked volumes: best-effort, a collection of its own. They
	// are counted where the requests are, so without the block programs
	// there is nowhere to report them.
	var volumes *blockVolumes
	switch {
	case !features.StorageBlockVolumes():
	case blockAttached == blockAttachNone:
		tlog.Warn("storage_block_volumes is enabled but the block programs are not attached (it adds stacked volumes"+
			" to the storage_block metrics, and needs one of them enabled); stacked volumes are not measured",
			"feature", "storage_block_volumes")
	default:
		var err error
		volumes, err = startBlockVolumes(tlog, cfg, consts, blockLoad.mapEntries, sharedMaps, &mu,
			kernelBTF(), kernelBTFCache.Cache())
		if err != nil {
			tlog.Warn("the bios of stacked volumes can't be measured on this kernel; LVM, md and other"+
				" device-mapper volumes have no series of their own, and their I/O is measured on the disks below",
				"feature", "storage_block_volumes", "error", err)
			break
		}
		closables = append(closables, volumes)
		if attachedBlockPrograms == nil {
			attachedBlockPrograms = map[string]*ebpf.Program{}
		}
		maps.Copy(attachedBlockPrograms, volumes.programs)
	}
	// Every block program attached, the bio ones included, reports its
	// recursion misses.
	if len(attachedBlockPrograms) > 0 {
		closables = append(closables, startBlockRecursionPoll(attachedBlockPrograms, metrics))
	}

	// NFS client RPCs: best-effort, as a collection of its own that attaches
	// once sunrpc is there. Started before the filesystems, whose first
	// pass ends the startup BTF burst this one shares.
	var nfs *nfsRPC
	if features.StorageNFS() {
		nfs, err = startNFS(tlog, cfg, *features, nfsCfg, metrics)
		if err != nil {
			tlog.Warn("NFS programs cannot be loaded; disabling the NFS client RPC metrics", "error", err)
		} else {
			closables = append(closables, nfs)
		}
	}

	// filesystem I/O: best-effort per filesystem. Each filesystem loads as a
	// collection of its own, when it becomes probeable (network filesystems)
	// or when the node first mounts a volume of its type (ext4, xfs, btrfs),
	// so a filesystem the kernel rejects disables only itself.
	var fsAccum *ebpf.Map
	if features.StorageFS() {
		attacher, err := startFsAttacher(tlog, cfg, consts, fsAgg, sharedMaps, &mu, metrics, features.StorageFSSync())
		if err != nil {
			tlog.Warn("filesystem probes cannot be loaded; disabling filesystem metrics", "error", err)
		} else {
			closables = append(closables, attacher)
			fsAccum = attacher.accum
		}
	}

	// raw tracepoints
	for _, t := range []probe{
		{
			name:    RawTracepointTCPRetransmitSkb,
			program: objects.ObiStatsRawTpTcpRetransmitSkb,
			enabled: features.StatsTCPRetransmits(),
		},
	} {
		if !t.enabled {
			continue
		}
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    t.name,
			Program: t.program,
		})
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed raw tracepoint attachment %s: %w", t.name, err)
		}
		closables = append(closables, l)
	}

	if blockLoad.wantCgroup && blockAttached == blockAttachClassic {
		tlog.Warn("storage_block_pod is enabled but the block programs run on the classic tracepoints, which"+
			" carry no request: obi.stat.disk.operations, operation_time and disk.io have no pod attributes",
			"feature", "storage_block_pod")
	}

	tlog.Info("stats eBPF programs loaded", "duration", time.Since(start), "kernel_btf_parse", btfParse.kernel,
		"module_btf_parse", btfParse.modules, "btf_modules", btfParse.moduleCount, "block", blockAttached)

	fetcher := &StatsFetcher{
		log:           tlog,
		objects:       &objects,
		closables:     closables,
		nfs:           nfs,
		fsAccum:       fsAccum,
		blockAgg:      blockAggMaps(blockLoad, blockAttached, &objects.StatsMaps),
		blockPrograms: attachedBlockPrograms,
		blockVolumes:  volumes,
	}
	if volumes != nil && fetcher.blockAgg != nil {
		fetcher.blockAgg.PendingBios = volumes.objects.BlkBioInflight
	}
	return fetcher, nil
}

// blockAggMaps returns the maps the attached block programs count or track
// requests in, or nil when no block program is attached. Service and Queue,
// where completions are aggregated, stay nil when the programs send events
// instead (agg == nil): Pending and Cgroup are independent of that choice,
// since the in-flight map is populated on every attach variant and the pod
// counters are always counted in the kernel.
func blockAggMaps(load blockLoadPlan, attached blockAttach, loaded *StatsMaps) *BlockAggMaps {
	if attached == blockAttachNone {
		return nil
	}
	out := &BlockAggMaps{Pending: blockPendingMap(attached, loaded)}
	if load.wantCgroup {
		out.Cgroup = loaded.BlkCgAgg
	}
	plan := load.agg
	if plan.agg == nil {
		return out
	}
	byName := map[string]*ebpf.Map{
		StatsMapBlkAgg: loaded.BlkAgg, StatsMapBlkQ_agg: loaded.BlkQ_agg,
		StatsMapBlkAggExp: loaded.BlkAggExp, StatsMapBlkQ_aggExp: loaded.BlkQ_aggExp,
	}
	out.Service = byName[plan.maps.service]
	if plan.queue {
		out.Queue = byName[plan.maps.queue]
	}
	return out
}

// blockPendingMap is the in-flight map the attached variant keeps live:
// blk_rq_inflight_sector, (dev, sector)-keyed, for the classic tracepoints;
// blk_rq_inflight, request-pointer-keyed, for the raw_tp and tp_btf variants
// (planBlockLoad sizes only the live one; the other is a 1-entry stub).
func blockPendingMap(attached blockAttach, loaded *StatsMaps) *ebpf.Map {
	if attached == blockAttachClassic {
		return loaded.BlkRqInflightSector
	}
	return loaded.BlkRqInflight
}

// attachedPrograms returns the programs of the set of stage that attached.
func attachedPrograms(stage blockLoadStage, attached blockAttach, programs map[string]*ebpf.Program) map[string]*ebpf.Program {
	for _, set := range stage.sets {
		if set.attach != attached {
			continue
		}
		out := map[string]*ebpf.Program{}
		for _, name := range set.programs() {
			if p := programs[name]; p != nil {
				out[name] = p
			}
		}
		return out
	}
	return nil
}

// possibleCPUs is the number of copies of every value of a per-CPU map.
func possibleCPUs() int {
	if n, err := ebpf.PossibleCPU(); err == nil {
		return n
	}
	return runtime.NumCPU()
}

func closeAll(closables []io.Closer) {
	for _, c := range closables {
		if c != nil {
			c.Close()
		}
	}
}

// Close any resources that are taken
func (m *StatsFetcher) Close() error {
	m.log.Debug("unregistering eBPF objects")

	var errs []error
	for _, c := range m.closables {
		if c != nil {
			errs = append(errs, c.Close())
		}
	}
	return errors.Join(errs...)
}

// StatsEventsMap returns the ring buffer map for stats events.
// The caller (ForwardRingbuf) is responsible for creating and closing the reader.
func (m *StatsFetcher) StatsEventsMap() *ebpf.Map {
	return m.objects.StatsEvents
}

func (m *StatsFetcher) DebugEventsMap() *ebpf.Map {
	return m.objects.DebugEvents
}

// NFSRPCMap returns the map the kernel counts NFS client RPC attempts in,
// in the layout NFSConfig selected, or nil when no NFS metric is enabled or
// the NFS maps could not be created.
func (m *StatsFetcher) NFSRPCMap() *ebpf.Map {
	if m.nfs == nil {
		return nil
	}
	return m.nfs.accum
}

// FsAccumMap returns the kernel map the filesystem programs aggregate into,
// or nil when they send ring buffer events or no filesystem program loads.
func (m *StatsFetcher) FsAccumMap() *ebpf.Map {
	return m.fsAccum
}

// BlockAggregation returns the maps the block programs count completed
// requests in, or nil when they send an event per request.
func (m *StatsFetcher) BlockAggregation() *BlockAggMaps {
	return m.blockAgg
}

// KernelDropsMap returns the per-CPU counters of what the stats programs
// could not count because a map was full, indexed as KernelDropReasons.
func (m *StatsFetcher) KernelDropsMap() *ebpf.Map {
	return m.objects.StatsDrops
}

// BlockPrograms returns the attached block programs, by name.
func (m *StatsFetcher) BlockPrograms() map[string]*ebpf.Program {
	return m.blockPrograms
}

// PrepareStorageSpec applies to spec what the stats loaders apply before
// loading with every storage metric enabled, for the verifier tests. On the
// stats spec it stubs out the block tracepoint family this kernel does not
// use (its tp_btf and raw_tp programs, in the variant its tracepoint
// prototypes take, or the classic ones). On the bio spec of stacked volumes
// it does the same, and stubs every program out on a kernel where the loader
// does not load them. On the filesystem spec it keeps both program families of every
// filesystem, the kprobe fallback included, whatever this kernel would plan:
// see verifierFsProbes.
func PrepareStorageSpec(spec *ebpf.CollectionSpec) error {
	if spec.Programs[progObiStatsRawTpBlockRqIssue] != nil {
		plan := planStorage(true, kernelBTF(), slog.Default())
		if err := fixupSpec(spec, plan.firstLoadDisable()); err != nil {
			return err
		}
	}
	if spec.Programs[progObiStatsRawTpBlockBioQueue] != nil {
		// The bio spec: its tp_btf and raw_tp programs in the variant this
		// kernel's block_bio_queue takes, or none on a kernel the loader
		// does not load them on.
		var keep []string
		if layout, reason := blockVolumesUnsupported(kernelBTF()); reason == "" {
			keep = bioLoadStages(layout)[0].programs()
		}
		if err := fixupSpec(spec, programsNotIn(allBioProgramNames(), keep)); err != nil {
			return err
		}
	}
	if spec.Programs[progObiStatsFentryNFSRead] != nil {
		return keepFsPrograms(spec, verifierFsProbes(planFsAttach(), kernelBTF()))
	}
	return nil
}

// statsConstants returns the load-time constants of every stats collection:
// the main one and each filesystem's. A collection is given the ones it
// declares (specConstants), so the values never differ between collections.
func statsConstants(cfg *config.EBPFTracer, blockLoad blockLoadPlan, fsAgg FsAggregation) map[string]any {
	wantQueueDepth := boolConst(blockLoad.wantQueueDepth)
	consts := map[string]any{
		"g_bpf_debug":             cfg.BpfDebug,
		"stats_wakeup_data_bytes": uint32(cfg.StatsWakeupDataBytes),
		"blk_want_queue_depth":    wantQueueDepth,
		"blk_emit_kinds":          blockLoad.emitKinds,
		"fs_emit_mode":            fsEmitMode(fsAgg),
		"fs_hist_exp":             boolConst(fsAgg.Enabled && fsAgg.Exponential),
		"fs_bounds_ns":            fsKernelBounds(fsAgg.BoundsNs),
		"blk_complete_errno":      boolConst(blockLoad.completeErrno),
		"blk_want_queue":          boolConst(blockLoad.wantQueue),
		"blk_want_part":           boolConst(blockLoad.wantPart),
		"blk_want_cgroup":         boolConst(blockLoad.wantCgroup),
	}
	maps.Copy(consts, blockLoad.agg.constants())
	return consts
}

func boolConst(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func fsEmitMode(fsAgg FsAggregation) uint8 {
	if fsAgg.Enabled {
		return uint8(FsIoFsEmitKindFsEmitAgg)
	}
	return uint8(FsIoFsEmitKindFsEmitRingbuf)
}

// fsKernelBounds returns fs_bounds_ns: bounds, padded with math.MaxUint64 to
// the exponential layout's size, which the explicit layout's search reads the
// first entries of. Bounds beyond it are dropped: the layout never has them.
func fsKernelBounds(bounds []uint64) [fsHistMaxBounds]uint64 {
	var padded [fsHistMaxBounds]uint64
	n := copy(padded[:], bounds)
	for i := n; i < len(padded); i++ {
		padded[i] = math.MaxUint64
	}
	return padded
}

// fsHistMaxBounds is k_stat_hist_exp_max_bounds (bpf/statsolly/hist.h), the
// size of fs_bounds_ns.
const fsHistMaxBounds = 128

// specConstants returns the members of consts that spec declares.
func specConstants(spec *ebpf.CollectionSpec, consts map[string]any) map[string]any {
	declared := make(map[string]any, len(consts))
	for name, value := range consts {
		if _, ok := spec.Variables[name]; ok {
			declared[name] = value
		}
	}
	return declared
}

// loadStatsObjects loads the stats eBPF spec into objects. sharedMaps and mu
// are threaded in from the caller (rather than created fresh here) so that a
// retry via loadWithStorageFallback reuses the PinInternal maps a prior,
// failed attempt already created instead of orphaning them and creating a
// second set.
func loadStatsObjects(
	cfg *config.EBPFTracer, blockLoad blockLoadPlan, consts map[string]any, toDisable []string,
	objects *StatsObjects, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex, cache *btf.Cache,
) error {
	spec, err := LoadStats()
	if err != nil {
		return fmt.Errorf("loading BPF data: %w", err)
	}

	if err := fixupSpec(spec, toDisable); err != nil {
		return fmt.Errorf("fixing up BPF spec: %w", err)
	}

	ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)

	if err := setMapEntries(spec, blockLoad.mapEntries); err != nil {
		return fmt.Errorf("sizing block maps: %w", err)
	}

	if err := ebpfconvenience.LoadSpec(spec, objects, specConstants(spec, consts), sharedMaps, mu, "", cache); err != nil {
		return fmt.Errorf("loading stats eBPF spec: %w", err)
	}
	return nil
}

// sysBlockDevicesDir lists every block device, with its request queue
// settings under queue/ and one directory per hardware queue under mq/.
const sysBlockDevicesDir = "/sys/block"

const (
	minBlockInflightEntries uint32 = 4 << 10
	maxBlockInflightEntries uint32 = 64 << 10
	// A map no loaded program uses must still be created; one entry is the
	// smallest the kernel accepts.
	unusedMapEntries uint32 = 1
)

// blockLoadPlan is what every load of the stats collection applies for the
// block programs. The block maps are PinInternal, shared by the first load and
// its retry without block programs, and a load whose map spec differs from the
// shared map is rejected, so the plan is made once and reused.
type blockLoadPlan struct {
	mapEntries     map[string]uint32
	wantQueueDepth bool
	// wantQueue is blk_want_queue: the queue wait is measured.
	wantQueue bool
	// completeErrno is blk_complete_errno.
	completeErrno bool
	// wantPart is blk_want_part: obi.disk.partition is selected on a disk
	// metric that carries it, so the partition is read at issue (1.2, 2.1).
	// Unlike wantQueue it comes from attributes.select, not a feature flag.
	wantPart bool
	// wantCgroup is blk_want_cgroup: storage_block_pod counts reads and
	// writes per cgroup in blk_cg_agg.
	wantCgroup bool
	// emitKinds is blk_emit_kinds: one bit per enum blk_io_op whose
	// completions reach userspace.
	emitKinds uint8
	// agg is how completions are counted in kernel maps, if they are.
	agg blockAggPlan
}

// blockEmitKinds returns the kinds of block request the enabled metrics use.
// The kernel ends the others at completion, without a ring buffer event, so
// flushes and discards cost no userspace work unless their metrics are on.
func blockEmitKinds(features export.Features) uint8 {
	var kinds uint8
	if features.StorageBlockReadWrite() {
		kinds |= 1<<StatsBlkIoOpBlkOpRead | 1<<StatsBlkIoOpBlkOpWrite
	}
	if features.StorageBlockFlush() {
		kinds |= 1 << StatsBlkIoOpBlkOpFlush
	}
	if features.StorageBlockDiscard() {
		kinds |= 1 << StatsBlkIoOpBlkOpDiscard
	}
	return kinds
}

// blockPartitionMetrics is every disk metric whose attribute set can carry
// obi.disk.partition (1.1): it is opt-in there, not gated by its own feature
// flag.
var blockPartitionMetrics = []attributes.Name{
	attributes.StatDiskOperationDuration,
	attributes.StatDiskIO,
	attributes.StatDiskQueueDuration,
	attributes.StatDiskOperationErrors,
	attributes.StatDiskDiscardDuration,
	attributes.StatDiskDiscardIO,
	attributes.StatDiskPendingOperations,
}

// blockWantPartition reports whether attributes.select picked
// obi.disk.partition on any metric that carries it, so blk_want_part (and
// the 2-3 extra reads per completion it gates) is paid for only when asked
// for, never unconditionally in the aggregation key (2.0, 2.1).
func blockWantPartition(attrSel *attributes.AttrSelector) bool {
	for _, m := range blockPartitionMetrics {
		if slices.Contains(attrSel.For(m), attr.DiskPartition) {
			return true
		}
	}
	return false
}

// planBlockLoad sizes the block maps for the programs that will run: the
// request-keyed in-flight map, from inflightEntries, when the BTF-decoding
// programs can run, the (dev, sector) one for the classic tracepoints, the
// map nothing touches at one entry, so the idle family, a disabled
// storage_block and queue depth cost no memory. Both request-keyed families (tp_btf,
// raw_tp) share the request-keyed maps.
func planBlockLoad(block bool, storage storagePlan, queue, queueDepth bool, inflightEntries func() uint32) blockLoadPlan {
	entries := map[string]uint32{}
	if !block || len(storage.stages) == 0 {
		for _, name := range []string{StatsMapBlkRqInflight, StatsMapBlkRqInflightSector, StatsMapBlkDevState} {
			entries[name] = unusedMapEntries
		}
		return blockLoadPlan{mapEntries: entries}
	}

	if storage.stages[0].sets[0].attach == blockAttachClassic {
		entries[StatsMapBlkRqInflight] = unusedMapEntries
	} else {
		entries[StatsMapBlkRqInflight] = inflightEntries()
		entries[StatsMapBlkRqInflightSector] = unusedMapEntries
	}
	if !queueDepth {
		entries[StatsMapBlkDevState] = unusedMapEntries
	}
	return blockLoadPlan{
		mapEntries:     entries,
		wantQueueDepth: queueDepth,
		wantQueue:      queue,
		completeErrno:  storage.layout.completeErrno,
	}
}

// blockInflightEntries sizes the request-keyed in-flight map: at most
// nr_requests requests are in flight per hardware queue, summed over every
// device with hardware queues (bio-based devices such as dm-linear never
// reach the request tracepoints). The sum is clamped, leaving room for
// devices that appear later; an unreadable sysfs gets the largest size.
func blockInflightEntries(sysBlock string) uint32 {
	devices, err := os.ReadDir(sysBlock)
	if err != nil {
		return maxBlockInflightEntries
	}

	var total uint64
	for _, dev := range devices {
		hwQueues, err := os.ReadDir(filepath.Join(sysBlock, dev.Name(), "mq"))
		if err != nil || len(hwQueues) == 0 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(sysBlock, dev.Name(), "queue", "nr_requests"))
		if err != nil {
			continue
		}
		nrRequests, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
		if err != nil {
			continue
		}
		total += nrRequests * uint64(len(hwQueues))
	}
	return uint32(min(max(total, uint64(minBlockInflightEntries)), uint64(maxBlockInflightEntries)))
}

func setMapEntries(spec *ebpf.CollectionSpec, entries map[string]uint32) error {
	for name, n := range entries {
		m := spec.Maps[name]
		if m == nil {
			return fmt.Errorf("unknown map name %s", name)
		}
		m.MaxEntries = n
	}
	return nil
}

// startBlockRecursionPoll reports the recursion misses of progs, the block
// programs that attached, to metrics every fsAttachInterval until the
// returned closer is closed. Block has no refresh loop of its own, so this
// one only reads the counters, which cost nothing per event.
func startBlockRecursionPoll(progs map[string]*ebpf.Program, metrics imetrics.Reporter) io.Closer {
	p := &blockRecursionPoll{stop: make(chan struct{}), stopped: make(chan struct{})}
	go func() {
		defer close(p.stopped)
		var misses recursionMisses
		ticker := time.NewTicker(fsAttachInterval)
		defer ticker.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-ticker.C:
				misses.poll(progs, metrics)
			}
		}
	}()
	return p
}

type blockRecursionPoll struct{ stop, stopped chan struct{} }

func (p *blockRecursionPoll) Close() error {
	close(p.stop)
	<-p.stopped
	return nil
}

// fixupSpec replaces disabled programs with no-op stubs before loading,
// preventing unused eBPF code from being loaded into the kernel.
func fixupSpec(spec *ebpf.CollectionSpec, toDisable []string) error {
	for _, name := range toDisable {
		if spec.Programs[name] == nil {
			return fmt.Errorf("unknown program name %s", name)
		}
		// The stub is a kprobe whatever the original program was, mirroring
		// common.FixupSpec. A tracing program (fentry/fexit) must supply an
		// attach btf_id at load time, which it derives from AttachTo, and a
		// disabled program has no valid symbol to point at -- keeping the
		// original type makes the kernel reject the whole collection with
		// "Tracing programs must provide btf_id". A kprobe needs no btf_id,
		// and nothing ever attaches a disabled program.
		spec.Programs[name] = &ebpf.ProgramSpec{
			Name:         "stats_dummy",
			Type:         ebpf.Kprobe,
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
			License:      "Dual MIT/GPL",
		}
	}
	return nil
}
