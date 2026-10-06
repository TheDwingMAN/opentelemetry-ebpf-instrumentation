// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
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
	progObiStatsTpBlockRqInsert                           = "obi_stats_tp_block_rq_insert"
	progObiStatsTpBlockRqIssue                            = "obi_stats_tp_block_rq_issue"
	progObiStatsTpBlockRqComplete                         = "obi_stats_tp_block_rq_complete"
	progObiStatsRawTpBlockRqInsert                        = "obi_stats_raw_tp_block_rq_insert"
	progObiStatsRawTpBlockRqIssue                         = "obi_stats_raw_tp_block_rq_issue"
	progObiStatsRawTpBlockRqComplete                      = "obi_stats_raw_tp_block_rq_complete"
)

// Hook point names, grouped by attach type.
const (
	// Kprobes: kernel function names.
	KprobeTCPClose       = "tcp_close"
	KprobeTCPSendMsg     = "tcp_sendmsg"
	KprobeTCPCleanupRbuf = "tcp_cleanup_rbuf"

	// Tracepoints: group/name, are validated by TestTracepointConstantFormat
	TracepointInetSockSetState = "sock/inet_sock_set_state"
	TracepointBlockRqInsert    = "block/block_rq_insert"
	TracepointBlockRqIssue     = "block/block_rq_issue"
	TracepointBlockRqComplete  = "block/block_rq_complete"
	// The same three events as raw tracepoints, attached by name without
	// tracefs. Preferred whenever the kernel BTF lets the programs decode a
	// request; the classic tracepoints remain for kernels where it does not.
	RawTracepointBlockRqInsert   = "block_rq_insert"
	RawTracepointBlockRqIssue    = "block_rq_issue"
	RawTracepointBlockRqComplete = "block_rq_complete"

	// Raw tracepoints: name only (no group prefix).
	RawTracepointTCPRetransmitSkb = "tcp_retransmit_skb"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type stat_type -type tcp_fail_reason -type tcp_handshake_role -type network_io_direction -type tcp_io_t -type tcp_rtt_t -type tcp_failed_connection_t -type tcp_retransmit_t -type tcp_successful_connection_t -type blk_io_op -type block_io_t -type fs_io_t -target $BPF_TARGETS Stats ../../../../bpf/statsolly/stats.c -- -I../../../../bpf

type StatsFetcher struct {
	log       *slog.Logger
	objects   *StatsObjects
	closables []io.Closer
	nfs       *nfsRPC
	// fsAccum is the filesystem aggregation map in use, nil when the
	// filesystem programs emit ring buffer events.
	fsAccum *ebpf.Map
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.StatFetcher")
}

func NewStatsFetcher(
	cfg *config.EBPFTracer, features *export.Features, selectorCfg *attributes.SelectorConfig, fsAgg FsAggregation,
	nfsCfg NFSConfig, metrics imetrics.Reporter,
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
	storage := planStorage(storageBlock)
	useRawBlock := storage.useRawBlock
	toDisable = append(toDisable, storage.toDisable...)
	blockLoad := planBlockLoad(storageBlock, useRawBlock, features.StorageBlockQueueDepth(), func() uint32 {
		return blockInflightEntries(sysBlockDevicesDir)
	})
	blockLoad.emitKinds = blockEmitKinds(*features)
	if !features.StorageFS() {
		fsAgg = FsAggregation{}
	}
	consts := statsConstants(cfg, blockLoad, fsAgg)

	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	load := func(toDisable []string) error {
		objects = StatsObjects{}
		return loadStatsObjects(cfg, blockLoad, consts, toDisable, &objects, sharedMaps, &mu, kernelBTFCache.Cache())
	}
	storageBlock, err = loadWithStorageFallback(load, toDisable, storageBlock, tlog)
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
	if storageBlock {
		closables = append(closables, attachBlockProbes(&objects, useRawBlock, tlog)...)
		closables = append(closables, startBlockRecursionPoll(&objects, metrics))
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

	tlog.Info("stats eBPF programs loaded", "duration", time.Since(start), "kernel_btf_parse", btfParse.kernel,
		"module_btf_parse", btfParse.modules, "btf_modules", btfParse.moduleCount)

	return &StatsFetcher{
		log:       tlog,
		objects:   &objects,
		closables: closables,
		nfs:       nfs,
		fsAccum:   fsAccum,
	}, nil
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

// storagePlan is what the block programs need done to the stats spec before
// load on this kernel: the programs to stub out and which block tracepoint
// family was kept. The filesystem programs are not in the stats spec; they
// load as collections of their own (fs_tracer.go).
type storagePlan struct {
	toDisable   []string
	useRawBlock bool
}

func planStorage(block bool) storagePlan {
	var plan storagePlan

	// Both block families are compiled in; only one is loaded. Raw tracepoints
	// need no tracefs mount but must be able to decode struct request through
	// BTF, so the choice is made here, before load, like the fentry/kprobe
	// choice for filesystems.
	plan.useRawBlock = block && blockRawTracepointCapable()
	switch {
	case !block:
		plan.toDisable = append(plan.toDisable, allBlockProgramNames()...)
	case plan.useRawBlock:
		plan.toDisable = append(plan.toDisable, blockTracepointPrograms()...)
	default:
		plan.toDisable = append(plan.toDisable, blockRawTracepointPrograms()...)
	}
	return plan
}

// PrepareStorageSpec applies to spec what the stats loaders apply before
// loading with every storage metric enabled, for the verifier tests. On the
// stats spec it stubs out the block tracepoint family this kernel does not
// use. On the filesystem spec it keeps both program families of every
// filesystem, the kprobe fallback included, whatever this kernel would plan:
// see verifierFsProbes.
func PrepareStorageSpec(spec *ebpf.CollectionSpec) error {
	if spec.Programs[progObiStatsRawTpBlockRqIssue] != nil {
		if err := fixupSpec(spec, planStorage(true).toDisable); err != nil {
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
	var wantQueueDepth uint8
	if blockLoad.wantQueueDepth {
		wantQueueDepth = 1
	}
	return map[string]any{
		"g_bpf_debug":             cfg.BpfDebug,
		"stats_wakeup_data_bytes": uint32(cfg.StatsWakeupDataBytes),
		"blk_want_queue_depth":    wantQueueDepth,
		"blk_emit_kinds":          blockLoad.emitKinds,
		"fs_emit_mode":            fsEmitMode(fsAgg),
		"fs_hist_exp":             boolConst(fsAgg.Enabled && fsAgg.Exponential),
		"fs_bounds_ns":            fsKernelBounds(fsAgg.BoundsNs),
	}
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

func blockTracepointPrograms() []string {
	return []string{progObiStatsTpBlockRqInsert, progObiStatsTpBlockRqIssue, progObiStatsTpBlockRqComplete}
}

func blockRawTracepointPrograms() []string {
	return []string{progObiStatsRawTpBlockRqInsert, progObiStatsRawTpBlockRqIssue, progObiStatsRawTpBlockRqComplete}
}

func allBlockProgramNames() []string {
	return append(blockTracepointPrograms(), blockRawTracepointPrograms()...)
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
	// emitKinds is blk_emit_kinds: one bit per enum blk_io_op whose
	// completions reach userspace.
	emitKinds uint8
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

// planBlockLoad sizes the block maps for the programs that will run: the
// in-flight map of the tracepoint family in use, from inflightEntries for the
// raw family, and one entry for every map nothing touches, so the idle
// family, a disabled storage_block and a disabled queue depth cost no memory.
func planBlockLoad(block, useRaw, queueDepth bool, inflightEntries func() uint32) blockLoadPlan {
	entries := map[string]uint32{}
	if !block {
		for _, name := range []string{StatsMapBlkRqInflight, StatsMapBlkRqInflightSector, StatsMapBlkInsert, StatsMapBlkDevState} {
			entries[name] = unusedMapEntries
		}
		return blockLoadPlan{mapEntries: entries}
	}

	if useRaw {
		entries[StatsMapBlkRqInflight] = inflightEntries()
		entries[StatsMapBlkRqInflightSector] = unusedMapEntries
	} else {
		entries[StatsMapBlkRqInflight] = unusedMapEntries
	}
	if !queueDepth {
		entries[StatsMapBlkDevState] = unusedMapEntries
	}
	return blockLoadPlan{mapEntries: entries, wantQueueDepth: queueDepth}
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

// startBlockRecursionPoll reports the block programs' recursion misses to
// metrics every fsAttachInterval until the returned closer is closed. Block
// has no refresh loop of its own, so this one only reads the counters, which
// cost nothing per event.
func startBlockRecursionPoll(objects *StatsObjects, metrics imetrics.Reporter) io.Closer {
	progs := map[string]*ebpf.Program{
		progObiStatsTpBlockRqComplete:    objects.ObiStatsTpBlockRqComplete,
		progObiStatsTpBlockRqInsert:      objects.ObiStatsTpBlockRqInsert,
		progObiStatsTpBlockRqIssue:       objects.ObiStatsTpBlockRqIssue,
		progObiStatsRawTpBlockRqComplete: objects.ObiStatsRawTpBlockRqComplete,
		progObiStatsRawTpBlockRqInsert:   objects.ObiStatsRawTpBlockRqInsert,
		progObiStatsRawTpBlockRqIssue:    objects.ObiStatsRawTpBlockRqIssue,
	}
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

// attachBlockProbes attaches one block family. On any failure it detaches
// what it managed and returns nothing: block metrics are then off, and the
// rest of the agent keeps running.
func attachBlockProbes(objects *StatsObjects, useRaw bool, log *slog.Logger) []io.Closer {
	var links []io.Closer
	fail := func(name string, err error) []io.Closer {
		log.Warn("failed block tracepoint attachment; disabling storage block metrics",
			"tracepoint", name, "raw", useRaw, "error", err)
		closeAll(links)
		return nil
	}

	// Completion attaches first: a request issued before the issue program
	// attached has no in-flight entry and its completion is ignored, while
	// issue attached first would leave behind the entries of requests that
	// complete before the completion program attaches.
	if useRaw {
		for _, t := range []struct {
			name    string
			program *ebpf.Program
		}{
			{RawTracepointBlockRqComplete, objects.ObiStatsRawTpBlockRqComplete},
			{RawTracepointBlockRqInsert, objects.ObiStatsRawTpBlockRqInsert},
			{RawTracepointBlockRqIssue, objects.ObiStatsRawTpBlockRqIssue},
		} {
			l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: t.name, Program: t.program})
			if err != nil {
				return fail(t.name, err)
			}
			links = append(links, l)
		}
		return links
	}

	for _, t := range []struct {
		name    string
		program *ebpf.Program
	}{
		{TracepointBlockRqComplete, objects.ObiStatsTpBlockRqComplete},
		{TracepointBlockRqInsert, objects.ObiStatsTpBlockRqInsert},
		{TracepointBlockRqIssue, objects.ObiStatsTpBlockRqIssue},
	} {
		group, tp, _ := strings.Cut(t.name, "/")
		l, err := link.Tracepoint(group, tp, t.program, nil)
		if err != nil {
			return fail(t.name, err)
		}
		links = append(links, l)
	}
	return links
}

// loadWithStorageFallback loads the stats spec and, when a kernel
// incompatibility fails the whole load with storage block metrics enabled,
// retries once with the block tracepoints stubbed out. It returns whether
// storage block metrics remain enabled. The filesystem programs are not part
// of this load, so a filesystem the kernel rejects can never take block or
// TCP metrics down with it.
func loadWithStorageFallback(
	load func(toDisable []string) error,
	toDisable []string,
	storageBlock bool,
	log *slog.Logger,
) (blockOK bool, err error) {
	err = load(toDisable)
	if err == nil || !storageBlock {
		return storageBlock, err
	}

	log.Warn("loading stats eBPF spec failed with storage block metrics enabled;"+
		" disabling storage block metrics and retrying (likely kernel incompatibility)", "error", err)
	toDisable = append(slices.Clone(toDisable), allBlockProgramNames()...)
	return false, load(toDisable)
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
