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
	"slices"
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
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

type probe struct {
	name    string
	program *ebpf.Program
	enabled bool
	// optional probes that can't be attached are skipped, e.g. when the kernel doesn't have the
	// function
	optional bool
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
	progObiStatsRawTpBlockBioQueue                        = "obi_stats_raw_tp_block_bio_queue"
	progObiStatsRawTpBlockBioQueueLegacy                  = "obi_stats_raw_tp_block_bio_queue_legacy"
	progObiStatsRawTpBlockBioComplete                     = "obi_stats_raw_tp_block_bio_complete"
	progObiStatsKprobeVfsFsyncRange                       = "obi_stats_kprobe_vfs_fsync_range"
	progObiStatsKretprobeVfsFsyncRange                    = "obi_stats_kretprobe_vfs_fsync_range"
	progObiStatsKprobeDoFsync                             = "obi_stats_kprobe_do_fsync"
	progObiStatsKretprobeDoFsync                          = "obi_stats_kretprobe_do_fsync"
	progObiStatsKprobeSysFsync                            = "obi_stats_kprobe_sys_fsync"
	progObiStatsKprobeSysFdatasync                        = "obi_stats_kprobe_sys_fdatasync"
	progObiStatsKprobeSysSyncfs                           = "obi_stats_kprobe_sys_syncfs"
	progObiStatsKprobeSysSyncFileRange                    = "obi_stats_kprobe_sys_sync_file_range"
	progObiStatsKprobeSysSync                             = "obi_stats_kprobe_sys_sync"
	progObiStatsKretprobeSysFsSync                        = "obi_stats_kretprobe_sys_fs_sync"
)

// Hook point names, grouped by attach type.
const (
	// Kprobes: kernel function names.
	KprobeTCPClose       = "tcp_close"
	KprobeTCPSendMsg     = "tcp_sendmsg"
	KprobeTCPCleanupRbuf = "tcp_cleanup_rbuf"
	KprobeVfsFsyncRange  = "vfs_fsync_range"
	KprobeDoFsync        = "do_fsync"
	// system calls: the kernel symbols are prefixed per architecture, e.g. __x64_sys_fsync
	KprobeSysFsync         = "sys_fsync"
	KprobeSysFdatasync     = "sys_fdatasync"
	KprobeSysSyncfs        = "sys_syncfs"
	KprobeSysSyncFileRange = "sys_sync_file_range"
	KprobeSysSync          = "sys_sync"

	// Tracepoints: group/name, are validated by TestTracepointConstantFormat
	TracepointInetSockSetState = "sock/inet_sock_set_state"

	// Raw tracepoints: name only (no group prefix).
	RawTracepointTCPRetransmitSkb = "tcp_retransmit_skb"
	RawTracepointBlockRqIssue     = "block_rq_issue"
	RawTracepointBlockRqComplete  = "block_rq_complete"
	RawTracepointBlockBioQueue    = "block_bio_queue"
	RawTracepointBlockBioComplete = "block_bio_complete"
)

// maxDiskLatencyBounds is the number of histogram boundaries the kernel can bucket latencies with:
// one less than the number of buckets, the last one being the overflow bucket.
const maxDiskLatencyBounds = len(StatsDiskIoAccumT{}.LatencyCount) - 1

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type stat_type -type tcp_fail_reason -type tcp_handshake_role -type network_io_direction -type disk_op -type disk_io_key_t -type disk_io_accum_t -type disk_rq_start_t -type disk_cgroup_name_t -type fs_sync_type -type fs_sync_key_t -type fs_sync_accum_t -type nfs_procedure_key_t -type nfs_procedure_accum_t -type nfs_io_key_t -type tcp_io_t -type tcp_rtt_t -type tcp_failed_connection_t -type tcp_retransmit_t -type tcp_successful_connection_t -target amd64,arm64 Stats ../../../../bpf/statsolly/stats.c -- -I../../../../bpf

type StatsFetcher struct {
	log       *slog.Logger
	objects   *StatsObjects
	closables []io.Closer

	diskAttached          bool
	diskStatusIsBlkStatus bool
	bioAttached           bool
	fsSyncAttached        bool
	nfs                   nfsAttached
}

// LatencyHistograms are the boundaries, in seconds, of the latency histograms that the kernel
// accumulates
type LatencyHistograms struct {
	// Disk buckets the durations of the block requests and their wait before issue
	Disk           []float64
	FsSyncDuration []float64
	NFS            []float64
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.StatFetcher")
}

// NewStatsFetcher loads and attaches the stat probes of the enabled features
func NewStatsFetcher(cfg *config.EBPFTracer, features *export.Features, selectorCfg *attributes.SelectorConfig, histograms LatencyHistograms) (*StatsFetcher, error) {
	tlog := tlog()
	diskLatencyBoundsNs, err := diskLatencyBoundsToNs(histograms.Disk)
	if err != nil {
		return nil, err
	}
	fsSyncLatencyBoundsNs, err := diskLatencyBoundsToNs(histograms.FsSyncDuration)
	if err != nil {
		return nil, err
	}
	nfsLatencyBoundsNs, err := diskLatencyBoundsToNs(histograms.NFS)
	if err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	objects := StatsObjects{}
	spec, err := LoadStats()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
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

	diskEnabled := features.StatsDisk()
	var blockLayout blockTracepointLayout
	if diskEnabled {
		blockLayout = kernelBlockTracepointLayout(tlog)
	}
	diskAttached := diskEnabled && !blockLayout.unknown
	toDisable = append(toDisable, diskProgramsToDisable(diskEnabled, blockLayout)...)
	bioAttached := diskAttached && features.StatsDiskStackedVolumes() && !blockLayout.bioUnknown
	toDisable = append(toDisable, bioProgramsToDisable(bioAttached, blockLayout)...)
	if !features.StatsFsSyncDuration() {
		toDisable = append(toDisable, progObiStatsKprobeVfsFsyncRange, progObiStatsKretprobeVfsFsyncRange,
			progObiStatsKprobeDoFsync, progObiStatsKretprobeDoFsync,
			progObiStatsKprobeSysFsync, progObiStatsKprobeSysFdatasync, progObiStatsKprobeSysSyncfs,
			progObiStatsKprobeSysSyncFileRange, progObiStatsKprobeSysSync, progObiStatsKretprobeSysFsSync)
	}
	var nfsProbesAvailable nfsProbes
	if features.StatsNFS() {
		nfsProbesAvailable = kernelNFSProbes()
		warnUnavailableNFSProbes(tlog, features, nfsProbesAvailable)
	}
	nfsLoaded := nfsLoadFor(features, nfsProbesAvailable)
	toDisable = append(toDisable, nfsLoaded.programsToDisable()...)

	if err := fixupSpec(spec, toDisable); err != nil {
		return nil, fmt.Errorf("fixing up BPF spec: %w", err)
	}

	ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)

	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	if err := ebpfconvenience.LoadSpec(spec, &objects, map[string]any{
		"g_bpf_debug":                cfg.BpfDebug,
		"stats_wakeup_data_bytes":    uint32(cfg.StatsWakeupDataBytes),
		"disk_latency_bounds_ns":     diskLatencyBoundsNs,
		"disk_latency_bounds_len":    uint32(len(histograms.Disk)),
		"disk_status_is_blk_status":  blockLayout.completeReportsBlkStatus,
		"fs_sync_latency_bounds_ns":  fsSyncLatencyBoundsNs,
		"fs_sync_latency_bounds_len": uint32(len(histograms.FsSyncDuration)),
		"nfs_latency_bounds_ns":      nfsLatencyBoundsNs,
		"nfs_latency_bounds_len":     uint32(len(histograms.NFS)),
	}, sharedMaps, &mu, "", nil); err != nil {
		return nil, fmt.Errorf("loading stats eBPF spec: %w", err)
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
		{
			name:    KprobeVfsFsyncRange,
			program: objects.ObiStatsKprobeVfsFsyncRange,
			enabled: features.StatsFsSyncDuration(),
		},
		{
			name:     KprobeDoFsync,
			program:  objects.ObiStatsKprobeDoFsync,
			enabled:  features.StatsFsSyncDuration(),
			optional: true,
		},
	} {
		if !k.enabled {
			continue
		}

		l, err := link.Kprobe(k.name, k.program, nil)
		if err != nil && k.optional {
			tlog.Debug("skipping optional kprobe", "function", k.name, "error", err)
			continue
		}
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
		{
			name:    KprobeVfsFsyncRange,
			program: objects.ObiStatsKretprobeVfsFsyncRange,
			enabled: features.StatsFsSyncDuration(),
		},
		{
			name:     KprobeDoFsync,
			program:  objects.ObiStatsKretprobeDoFsync,
			enabled:  features.StatsFsSyncDuration(),
			optional: true,
		},
	} {
		if !k.enabled {
			continue
		}
		l, err := link.Kretprobe(k.name, k.program, nil)
		if err != nil && k.optional {
			tlog.Debug("skipping optional kretprobe", "function", k.name, "error", err)
			continue
		}
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed kretprobe attachment %s: %w", k.name, err)
		}
		closables = append(closables, l)
	}

	if features.StatsFsSyncDuration() {
		closables = append(closables, attachSyncSyscalls(tlog, &objects)...)
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
	for _, t := range []probe{
		{
			name:    RawTracepointTCPRetransmitSkb,
			program: objects.ObiStatsRawTpTcpRetransmitSkb,
			enabled: features.StatsTCPRetransmits(),
		},
		{
			name:    RawTracepointBlockRqIssue,
			program: objects.ObiStatsRawTpBlockRqIssue,
			enabled: diskAttached && !blockLayout.issueHasQueueArg,
		},
		{
			name:    RawTracepointBlockRqIssue,
			program: objects.ObiStatsRawTpBlockRqIssueLegacy,
			enabled: diskAttached && blockLayout.issueHasQueueArg,
		},
		{
			name:    RawTracepointBlockRqComplete,
			program: objects.ObiStatsRawTpBlockRqComplete,
			enabled: diskAttached,
		},
		{
			name:    RawTracepointBlockBioQueue,
			program: objects.ObiStatsRawTpBlockBioQueue,
			enabled: bioAttached && !blockLayout.bioQueueHasQueueArg,
		},
		{
			name:    RawTracepointBlockBioQueue,
			program: objects.ObiStatsRawTpBlockBioQueueLegacy,
			enabled: bioAttached && blockLayout.bioQueueHasQueueArg,
		},
		{
			name:    RawTracepointBlockBioComplete,
			program: objects.ObiStatsRawTpBlockBioComplete,
			enabled: bioAttached,
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

	nfs, nfsClosables := attachNFS(tlog, &objects, nfsLoaded)
	closables = append(closables, nfsClosables...)

	return &StatsFetcher{
		log:                   tlog,
		objects:               &objects,
		closables:             closables,
		diskAttached:          diskAttached,
		diskStatusIsBlkStatus: blockLayout.completeReportsBlkStatus,
		bioAttached:           bioAttached,
		fsSyncAttached:        features.StatsFsSyncDuration(),
		nfs:                   nfs,
	}, nil
}

// attachSyncSyscalls attaches the probes of the sync system calls. The entry and return probes of
// each system call are attached together or not at all: a sync that starts without its return
// probe would never complete. Missing system calls are skipped, the kernel functions that sync
// files are still probed.
func attachSyncSyscalls(log *slog.Logger, objects *StatsObjects) []io.Closer {
	var closables []io.Closer
	for _, syscall := range []struct {
		name  string
		entry *ebpf.Program
	}{
		{KprobeSysFsync, objects.ObiStatsKprobeSysFsync},
		{KprobeSysFdatasync, objects.ObiStatsKprobeSysFdatasync},
		{KprobeSysSyncfs, objects.ObiStatsKprobeSysSyncfs},
		{KprobeSysSyncFileRange, objects.ObiStatsKprobeSysSyncFileRange},
		{KprobeSysSync, objects.ObiStatsKprobeSysSync},
	} {
		entry, err := link.Kprobe(syscall.name, syscall.entry, nil)
		if err != nil {
			log.Debug("skipping sync system call", "syscall", syscall.name, "error", err)
			continue
		}
		ret, err := link.Kretprobe(syscall.name, objects.ObiStatsKretprobeSysFsSync, nil)
		if err != nil {
			entry.Close()
			log.Debug("skipping sync system call", "syscall", syscall.name, "error", err)
			continue
		}
		closables = append(closables, entry, ret)
	}
	return closables
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

// DiskIOAccumMap returns the map where the kernel accumulates block I/O latencies, or nil if the
// disk probes are not attached.
func (m *StatsFetcher) DiskIOAccumMap() *ebpf.Map {
	if !m.diskAttached {
		return nil
	}
	return m.objects.DiskIoAccum
}

// DiskRequestsMap returns the map where the kernel tracks the block requests in flight, or nil if
// the disk probes are not attached.
func (m *StatsFetcher) DiskRequestsMap() *ebpf.Map {
	if !m.diskAttached {
		return nil
	}
	return m.objects.DiskRqStart
}

// DiskBioAccumMap returns the map where the kernel accumulates the bios of the stacked volumes, or
// nil if the bio probes are not attached.
func (m *StatsFetcher) DiskBioAccumMap() *ebpf.Map {
	if !m.bioAttached {
		return nil
	}
	return m.objects.DiskBioAccum
}

// DiskBioDevicesMap returns the map of the stacked volumes whose bios the kernel measures, or nil
// if the bio probes are not attached.
func (m *StatsFetcher) DiskBioDevicesMap() *ebpf.Map {
	if !m.bioAttached {
		return nil
	}
	return m.objects.DiskBioDevices
}

// FsSyncAccumMap returns the map where the kernel accumulates file sync latencies, or nil if the
// file sync probes are not attached.
func (m *StatsFetcher) FsSyncAccumMap() *ebpf.Map {
	if !m.fsSyncAttached {
		return nil
	}
	return m.objects.FsSyncAccum
}

// DiskCgroupNamesMap returns the map where the kernel records the names of the cgroups that
// block I/O, file syncs and NFS RPCs are charged to, or nil if none of their probes are attached.
func (m *StatsFetcher) DiskCgroupNamesMap() *ebpf.Map {
	if !m.diskAttached && !m.fsSyncAttached && !m.nfs.procedures && !m.nfs.bytes {
		return nil
	}
	return m.objects.DiskCgroupNames
}

// DiskStatusIsBlkStatus tells whether the kernel reports block request completion statuses as
// blk_status_t values (Linux 5.16+) instead of errnos.
func (m *StatsFetcher) DiskStatusIsBlkStatus() bool {
	return m.diskStatusIsBlkStatus
}

// blockTracepointLayout describes the arguments of the block tracepoints in the running kernel
type blockTracepointLayout struct {
	// block_rq_issue is (q, rq) instead of (rq): before Linux 5.11, unless backported
	issueHasQueueArg bool
	// block_rq_complete reports a blk_status_t (Linux 5.16+) instead of a negative errno
	completeReportsBlkStatus bool
	// the layout could not be told, so the disk probes can't be loaded
	unknown bool
	// block_bio_queue is (q, bio) instead of (bio): before Linux 5.11
	bioQueueHasQueueArg bool
	// the layout of the bio tracepoints could not be told, so the bio probes can't be loaded
	bioUnknown bool
}

// kernelBlockTracepointLayout reads the block tracepoint prototypes from the kernel BTF. The kernel
// version can't be used: the block_rq_issue change was backported to 5.10.137 and RHEL 8.6.
func kernelBlockTracepointLayout(log *slog.Logger) blockTracepointLayout {
	spec, err := btf.LoadKernelSpec()
	if err == nil {
		var layout blockTracepointLayout
		if layout, err = blockTracepointLayoutFrom(tracepointProto(spec)); err == nil {
			return layout
		}
	}
	log.Warn("disk stat metrics are disabled: can't tell the block tracepoints arguments from the kernel BTF",
		"error", err)
	return blockTracepointLayout{unknown: true}
}

func tracepointProto(spec *btf.Spec) func(string) (*btf.FuncProto, error) {
	return func(name string) (*btf.FuncProto, error) {
		var typedef *btf.Typedef
		if err := spec.TypeByName(name, &typedef); err != nil {
			return nil, err
		}
		if ptr, ok := typedef.Type.(*btf.Pointer); ok {
			if proto, ok := ptr.Target.(*btf.FuncProto); ok {
				return proto, nil
			}
		}
		return nil, fmt.Errorf("%s is not a function pointer", name)
	}
}

// Parameters of the btf_trace_<tracepoint> prototypes: the tracepoint's private data, followed by
// the tracepoint arguments.
const (
	blockRqIssueParams        = 2 // data, rq
	blockRqIssueLegacyParams  = 3 // data, q, rq
	blockRqCompleteErrorParam = 2 // data, rq, error, nr_bytes
	blockBioQueueParams       = 2 // data, bio
	blockBioQueueLegacyParams = 3 // data, q, bio
)

// blockTracepointLayoutFrom tells the layout from the btf_trace_<tracepoint> prototypes
func blockTracepointLayoutFrom(proto func(string) (*btf.FuncProto, error)) (blockTracepointLayout, error) {
	var layout blockTracepointLayout

	issue, err := proto("btf_trace_block_rq_issue")
	if err != nil {
		return layout, err
	}
	switch len(issue.Params) {
	case blockRqIssueParams:
	case blockRqIssueLegacyParams:
		layout.issueHasQueueArg = true
	default:
		return layout, fmt.Errorf("unexpected block_rq_issue prototype with %d parameters", len(issue.Params))
	}

	complete, err := proto("btf_trace_block_rq_complete")
	if err != nil {
		return layout, err
	}
	if len(complete.Params) <= blockRqCompleteErrorParam {
		return layout, fmt.Errorf("unexpected block_rq_complete prototype with %d parameters", len(complete.Params))
	}
	errType, ok := btf.UnderlyingType(complete.Params[blockRqCompleteErrorParam].Type).(*btf.Int)
	if !ok {
		return layout, errors.New("unexpected block_rq_complete error argument type")
	}
	// blk_status_t is a u8, the errno it replaced an int
	layout.completeReportsBlkStatus = errType.Size == 1

	// the bio tracepoints only measure stacked volumes: without them, the requests still are
	bioQueue, err := proto("btf_trace_block_bio_queue")
	switch {
	case err != nil:
		layout.bioUnknown = true
	case len(bioQueue.Params) == blockBioQueueLegacyParams:
		layout.bioQueueHasQueueArg = true
	case len(bioQueue.Params) != blockBioQueueParams:
		layout.bioUnknown = true
	}
	return layout, nil
}

// diskLatencyBoundsToNs converts the disk latency histogram boundaries from seconds to the
// nanoseconds the kernel buckets latencies with. The kernel needs them in increasing order.
func diskLatencyBoundsToNs(bounds []float64) ([maxDiskLatencyBounds]uint64, error) {
	var boundsNs [maxDiskLatencyBounds]uint64
	if len(bounds) > maxDiskLatencyBounds {
		return boundsNs, fmt.Errorf("disk latency histograms support up to %d bucket boundaries, got %d",
			maxDiskLatencyBounds, len(bounds))
	}

	for i, bound := range bounds {
		if bound <= 0 {
			return boundsNs, fmt.Errorf("disk latency histogram boundaries must be positive, got %v", bounds)
		}
		boundsNs[i] = uint64(math.Round(bound * float64(time.Second)))
		if i > 0 && boundsNs[i] <= boundsNs[i-1] {
			return boundsNs, fmt.Errorf("disk latency histogram boundaries must increase by at least 1ns, got %v", bounds)
		}
	}
	return boundsNs, nil
}

// diskProgramsToDisable returns the disk programs that must not be loaded
func diskProgramsToDisable(enabled bool, layout blockTracepointLayout) []string {
	switch {
	case !enabled || layout.unknown:
		return []string{progObiStatsRawTpBlockRqIssue, progObiStatsRawTpBlockRqIssueLegacy, progObiStatsRawTpBlockRqComplete}
	case layout.issueHasQueueArg:
		return []string{progObiStatsRawTpBlockRqIssue}
	default:
		return []string{progObiStatsRawTpBlockRqIssueLegacy}
	}
}

func bioProgramsToDisable(enabled bool, layout blockTracepointLayout) []string {
	switch {
	case !enabled:
		return []string{progObiStatsRawTpBlockBioQueue, progObiStatsRawTpBlockBioQueueLegacy, progObiStatsRawTpBlockBioComplete}
	case layout.bioQueueHasQueueArg:
		return []string{progObiStatsRawTpBlockBioQueue}
	default:
		return []string{progObiStatsRawTpBlockBioQueueLegacy}
	}
}

// fixupSpec replaces disabled programs with no-op stubs before loading,
// preventing unused eBPF code from being loaded into the kernel.
func fixupSpec(spec *ebpf.CollectionSpec, toDisable []string) error {
	for _, name := range toDisable {
		prog := spec.Programs[name]
		if prog == nil {
			return fmt.Errorf("unknown program name %s", name)
		}
		spec.Programs[name] = &ebpf.ProgramSpec{
			Name:         "stats_dummy",
			Type:         prog.Type,
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
			License:      "Dual MIT/GPL",
		}
	}
	return nil
}
