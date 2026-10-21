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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
)

type probe struct {
	name    string
	program *ebpf.Program
	enabled bool
	// the storage features of a storage probe, 0 for a TCP probe
	feature export.Features
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
	progObiStatsRawTpBlockRqIssue                         = "obi_stats_raw_tp_block_rq_issue"
	progObiStatsRawTpBlockRqIssueLegacy                   = "obi_stats_raw_tp_block_rq_issue_legacy"
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

	// Raw tracepoints: name only (no group prefix).
	RawTracepointTCPRetransmitSkb = "tcp_retransmit_skb"
	RawTracepointBlockRqIssue     = "block_rq_issue"
	RawTracepointBlockRqComplete  = "block_rq_complete"
	RawTracepointRPCStatsLatency  = "rpc_stats_latency"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type stat_type -type tcp_fail_reason -type tcp_handshake_role -type network_io_direction -type disk_op -type disk_io_key_t -type disk_io_accum_t -type disk_cgroup_name_t -type fs_sync_type -type fs_sync_key_t -type fs_sync_accum_t -type nfs_procedure_key_t -type nfs_procedure_accum_t -type tcp_io_t -type tcp_rtt_t -type tcp_failed_connection_t -type tcp_retransmit_t -type tcp_successful_connection_t -target $BPF_TARGETS Stats ../../../../bpf/statsolly/stats.c -- -I../../../../bpf

type StatsFetcher struct {
	log       *slog.Logger
	objects   *StatsObjects
	closables []io.Closer

	// the storage features whose probes are attached, or wait for their kernel module
	storage               export.Features
	diskStatusIsBlkStatus bool
	// the NFS client probe waits for the sunrpc module, and RefreshNFSProbes attaches it
	nfsWaiting bool
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.StatFetcher")
}

// NewStatsFetcher loads and attaches the probes of the enabled stat features. The storage probes
// read the cgroups that reads tells. An enabled storage feature whose probes can't be loaded or
// attached is disabled with a warning, while a TCP probe that fails is an error.
func NewStatsFetcher(cfg *config.EBPFTracer, features *export.Features, selectorCfg *attributes.SelectorConfig,
	reads CgroupReads,
) (*StatsFetcher, error) {
	tlog := tlog()
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

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

	fetcher, err := loadDegradingStorage(tlog, planStorage(tlog, features), func(storage storagePlan) (*StatsFetcher, error) {
		return loadAndAttach(cfg, features, toDisable, connRoleUsed, storage, reads)
	})
	if err == nil && fetcher.nfsWaiting {
		tlog.Info("the NFS client stats wait for the sunrpc kernel module: their probe is attached when it is loaded")
	}
	return fetcher, err
}

// storagePlan is what the storage probes load: the enabled storage features but those disabled,
// the block layout of the kernel, and the file sync hooks, by function, that fentry and fexit
// programs time
type storagePlan struct {
	features export.Features
	blockLayout
	fsSyncTracing map[string]bool
}

// storageError is a failure of the probes of storage features, which disables them
type storageError struct {
	features export.Features
	// a failed load, rather than a failed attach
	load bool
	err  error
}

func (e *storageError) Error() string { return e.err.Error() }

func (e *storageError) Unwrap() error { return e.err }

func planStorage(log *slog.Logger, features *export.Features) storagePlan {
	storage := storagePlan{features: *features & (export.FeatureStatsDisk | export.FeatureStatsFsSync | export.FeatureStatsNFS)}
	if storage.features.StatsDisk() {
		var err error
		if storage.blockLayout, err = kernelBlockLayout(); err != nil {
			storage.drop(log, export.FeatureStatsDisk,
				fmt.Errorf("reading the block tracepoint prototypes in the kernel BTF: %w", err))
		}
	}
	if !storage.features.StatsFsSync() && !storage.features.StatsNFS() {
		return storage
	}
	kernel, err := btf.LoadKernelSpec()
	// without the kernel BTF, the kprobes time every file sync hook
	if storage.features.StatsFsSync() && err == nil {
		storage.fsSyncTracing = fsSyncTracingHooks(kernel)
	}
	if storage.features.StatsNFS() {
		if err == nil {
			err = kernelRPCTypes(kernel)
		}
		if err != nil {
			storage.drop(log, export.FeatureStatsNFS, err)
		}
	}
	return storage
}

// drop disables the planned storage features of a group
func (s *storagePlan) drop(log *slog.Logger, group export.Features, err error) {
	log.Warn("storage stats disabled on this node: their probes can't be loaded or attached. The TCP stats keep running",
		"features", (s.features & group).Names(), "error", err)
	s.features &^= group
}

// loadDegradingStorage loads and attaches the probes, and disables the storage features of each
// storageError until the rest load and attach. A failed load first moves the file syncs from the
// fentry and fexit programs to the kprobes, which every supported kernel loads.
func loadDegradingStorage(log *slog.Logger, storage storagePlan,
	loadAndAttach func(storagePlan) (*StatsFetcher, error),
) (*StatsFetcher, error) {
	for {
		fetcher, err := loadAndAttach(storage)
		var failed *storageError
		switch {
		case !errors.As(err, &failed):
			return fetcher, err
		case failed.load && storage.features.StatsFsSync() && len(storage.fsSyncTracing) > 0:
			log.Debug("can't load the stats programs with the fentry and fexit programs of the file syncs: "+
				"probing the file syncs with kprobes", "error", err)
			storage.fsSyncTracing = nil
		// each other storageError disables a planned feature, so that the loop ends
		case storage.features&failed.features == 0:
			return fetcher, err
		default:
			storage.drop(log, failed.features, err)
		}
	}
}

// loadAndAttach loads the stats programs of the TCP features and of the planned storage features,
// and attaches their probes. A failed load while storage features are planned, and a storage probe
// that can't be attached, are storageErrors. On failure, it closes what it loaded.
func loadAndAttach(cfg *config.EBPFTracer, features *export.Features, toDisable []string, connRoleUsed bool,
	storage storagePlan, reads CgroupReads,
) (_ *StatsFetcher, err error) {
	objects := StatsObjects{}
	sharedMaps := map[string]*ebpf.Map{}
	defer func() {
		if err != nil {
			objects.Close()
			for _, m := range sharedMaps {
				m.Close()
			}
		}
	}()

	spec, err := LoadStats()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	diskEnabled := storage.features.StatsDisk()
	fsSyncEnabled := storage.features.StatsFsSync()
	nfsEnabled := storage.features.StatsNFS()
	toDisable = slices.Concat(toDisable, diskProgramsToDisable(diskEnabled, storage.issueHasQueueArg),
		fsSyncProgramsToDisable(fsSyncEnabled, storage.fsSyncTracing), nfsProgramsToDisable(nfsEnabled))

	setFsSyncTracingTargets(spec)
	if err := fixupSpec(spec, toDisable); err != nil {
		return nil, fmt.Errorf("fixing up BPF spec: %w", err)
	}

	ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)
	// without the number of CPUs, the in-flight maps keep their size
	cpus, _ := ebpf.PossibleCPU()
	sizeStorageMaps(spec, storage.features, reads, cpus)

	var mu sync.Mutex
	if err := ebpfconvenience.LoadSpec(spec, &objects, map[string]any{
		"g_bpf_debug":               cfg.BpfDebug,
		"stats_wakeup_data_bytes":   uint32(cfg.StatsWakeupDataBytes),
		"disk_latency_bounds_ns":    diskLatencyBoundsNs(),
		"disk_status_is_blk_status": storage.completeReportsBlkStatus,
		"disk_read_cgroup":          reads.Disk,
		"disk_rqf_io_stat":          storage.rqfIOStat,
		"disk_rqf_flush_seq":        storage.rqfFlushSeq,
		"disk_req_op_zone_append":   storage.zoneAppendOp,
		"fs_sync_read_cgroup":       reads.FsSync,
	}, sharedMaps, &mu, "", nil); err != nil {
		err = fmt.Errorf("loading stats eBPF spec: %w", err)
		if storage.features != 0 {
			// the kernel's error doesn't tell which program it can't load
			return nil, &storageError{features: storage.features, load: true, err: err}
		}
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

	// raw tracepoints
	// The block request completion is attached before the issue, so that no request is recorded
	// without its completion being seen.
	for _, t := range []probe{
		{
			name:    RawTracepointTCPRetransmitSkb,
			program: objects.ObiStatsRawTpTcpRetransmitSkb,
			enabled: features.StatsTCPRetransmits(),
		},
		{
			name:    RawTracepointBlockRqComplete,
			program: objects.ObiStatsRawTpBlockRqComplete,
			enabled: diskEnabled,
			feature: export.FeatureStatsDisk,
		},
		{
			name:    RawTracepointBlockRqIssue,
			program: diskIssueProgram(&objects, storage.issueHasQueueArg),
			enabled: diskEnabled,
			feature: export.FeatureStatsDisk,
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
			err = fmt.Errorf("failed raw tracepoint attachment %s: %w", t.name, err)
			if t.feature != 0 {
				return nil, &storageError{features: t.feature, err: err}
			}
			return nil, err
		}
		closables = append(closables, l)
	}

	var nfsWaiting bool
	if nfsEnabled {
		l, waiting, err := attachNFS(&objects)
		if err != nil {
			closeAll(closables)
			return nil, &storageError{features: export.FeatureStatsNFS, err: err}
		}
		if !waiting {
			closables = append(closables, l)
		}
		nfsWaiting = waiting
	}

	if fsSyncEnabled {
		links, mechanisms, err := attachFsSync(tlog(), &objects, storage.fsSyncTracing)
		if err != nil {
			closeAll(closables)
			return nil, err
		}
		closables = append(closables, links...)
		logFsSyncMechanisms(tlog(), mechanisms)
	}

	return &StatsFetcher{
		log:       tlog(),
		objects:   &objects,
		closables: closables,

		storage:               storage.features,
		diskStatusIsBlkStatus: storage.completeReportsBlkStatus,
		nfsWaiting:            nfsWaiting,
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

// DiskIOAccumMap returns the map where the kernel accumulates the block request durations, or nil
// when the disk stats are disabled
func (m *StatsFetcher) DiskIOAccumMap() *ebpf.Map {
	if !m.storage.StatsDisk() {
		return nil
	}
	return m.objects.DiskIoAccum
}

// FsSyncAccumMap returns the map where the kernel accumulates the file sync durations, or nil when
// the file sync stats are disabled
func (m *StatsFetcher) FsSyncAccumMap() *ebpf.Map {
	if !m.storage.StatsFsSync() {
		return nil
	}
	return m.objects.FsSyncAccum
}

// NFSProcedureAccumMap returns the map where the kernel accumulates the durations of the NFS client
// RPCs, or nil when the NFS client stats are disabled. Its probe may be attached later.
func (m *StatsFetcher) NFSProcedureAccumMap() *ebpf.Map {
	if !m.storage.StatsNFS() {
		return nil
	}
	return m.objects.NfsProcedureAccum
}

// DiskCgroupNamesMap returns the map where the kernel records the names of the cgroups that block
// I/O and file syncs are charged to, or nil when the storage stats are disabled
func (m *StatsFetcher) DiskCgroupNamesMap() *ebpf.Map {
	if m.storage == 0 {
		return nil
	}
	return m.objects.DiskCgroupNames
}

// DiskStatusIsBlkStatus tells whether the statuses in the keys of DiskIOAccumMap are blk_status_t
// values (Linux 5.16+) instead of errnos
func (m *StatsFetcher) DiskStatusIsBlkStatus() bool {
	return m.diskStatusIsBlkStatus
}

// fixupSpec replaces disabled programs with no-op stubs before loading,
// preventing unused eBPF code from being loaded into the kernel.
func fixupSpec(spec *ebpf.CollectionSpec, toDisable []string) error {
	for _, name := range toDisable {
		prog := spec.Programs[name]
		if prog == nil {
			return fmt.Errorf("unknown program name %s", name)
		}
		// a stub has no kernel function for a tracing program to attach to
		typ := prog.Type
		if typ == ebpf.Tracing {
			typ = ebpf.Kprobe
		}
		spec.Programs[name] = &ebpf.ProgramSpec{
			Name:         "stats_dummy",
			Type:         typ,
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
			License:      "Dual MIT/GPL",
		}
	}
	return nil
}
