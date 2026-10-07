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
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
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
}

// fsSyncRetprobeMaxActive is how many calls of a sync function the kernel tracks at once for their
// return probe, its maximum. The default, about twice the number of CPUs, is exceeded when many
// threads sync at once, e.g. when the storage stalls, and the returns of the other calls are
// missed.
const fsSyncRetprobeMaxActive = 4096

// lruLocalFreeTarget is how many free entries each CPU keeps for itself in an LRU map
// (LOCAL_FREE_TARGET in kernel/bpf/bpf_lru_list.c)
const lruLocalFreeTarget = 128

// inFlightMaps hold an entry from the start of each block request, bio, file sync or NFS task until
// it completes, in LRU maps
var inFlightMaps = []string{"disk_rq_start", "disk_bio_start", "fs_sync_start", "nfs_task_cgroup"}

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

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type stat_type -type tcp_fail_reason -type tcp_handshake_role -type network_io_direction -type disk_op -type disk_io_key_t -type disk_io_accum_t -type disk_rq_start_t -type disk_cgroup_name_t -type fs_sync_type -type fs_sync_key_t -type fs_sync_accum_t -type nfs_procedure_key_t -type nfs_procedure_accum_t -type nfs_io_key_t -type tcp_io_t -type tcp_rtt_t -type tcp_failed_connection_t -type tcp_retransmit_t -type tcp_successful_connection_t -target $BPF_TARGETS Stats ../../../../bpf/statsolly/stats.c -- -I../../../../bpf

type StatsFetcher struct {
	log       *slog.Logger
	objects   *StatsObjects
	closables []io.Closer

	diskAttached          bool
	diskStatusIsBlkStatus bool
	bioAttached           bool
	fsSyncAttached        bool
	nfs                   nfsState
	disabled              []DisabledFeature

	// mu guards closables, closed and nfs, except nfs.loaded, which never changes, against RefreshNFSProbes
	mu     sync.Mutex
	closed bool
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

// NewStatsFetcher loads and attaches the stat probes of the enabled features. The storage probes
// read the attributes that the reported attributes need, and the ones in reads. The TCP probes are
// required, while the storage ones are optional: a storage feature whose probes can't be loaded or
// attached, or wait for a kernel module, is disabled, and listed by DisabledStorageFeatures, and
// the other stats keep working.
func NewStatsFetcher(cfg *config.EBPFTracer, features *export.Features, attrGroups attributes.AttrGroups,
	selectorCfg *attributes.SelectorConfig, histograms LatencyHistograms, reads ProbeReads,
) (*StatsFetcher, error) {
	tlog := tlog()
	// the kernel buckets each group of histograms with the union of their boundaries in the
	// enabled exporters
	diskLatencyBoundsNs, err := diskLatencyBoundsToNs(histograms.Disk)
	if err != nil {
		return nil, fmt.Errorf("the buckets of stat_disk_operation_duration_histogram, stat_disk_queue_duration_histogram, "+
			"stat_disk_flush_duration_histogram and stat_disk_discard_duration_histogram: %w", err)
	}
	fsSyncLatencyBoundsNs, err := diskLatencyBoundsToNs(histograms.FsSyncDuration)
	if err != nil {
		return nil, fmt.Errorf("the buckets of stat_fs_sync_duration_histogram: %w", err)
	}
	nfsLatencyBoundsNs, err := diskLatencyBoundsToNs(histograms.NFS)
	if err != nil {
		return nil, fmt.Errorf("the buckets of stat_nfs_client_procedure_duration_histogram: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	attrSel, err := attributes.NewAttrSelector(attrGroups, selectorCfg)
	if err != nil {
		return nil, fmt.Errorf("creating attr selector: %w", err)
	}

	// OR across both metrics: a single shared probe writes sock_role for both consumers,
	// so the probe is needed if either metric has the attribute enabled.
	// Note: tcp successful connection probe derives role from oldstate and never reads sock_role
	connRoleAttrSelected := slices.Contains(attrSel.For(attributes.StatTCPRtt), attr.NetworkTCPHandshakeRole) ||
		slices.Contains(attrSel.For(attributes.StatTCPFailedConnections), attr.NetworkTCPHandshakeRole)
	connRoleUsed := (features.StatsTCPFailedConnections() || features.StatsTCPRtt()) && connRoleAttrSelected

	var tcpToDisable []string
	if !features.StatsTCPFailedConnections() {
		tcpToDisable = append(tcpToDisable, progObiStatsTpInetSockSetStateTCPFailedConnection)
	}
	if !features.StatsTCPSuccessfulConnections() {
		tcpToDisable = append(tcpToDisable, progObiStatsTpInetSockSetStateTCPSuccessfulConnection)
	}
	if !connRoleUsed {
		tcpToDisable = append(tcpToDisable, progObiStatsTpInetSockSetStateConnRole)
	}
	if !features.StatsTCPRtt() {
		tcpToDisable = append(tcpToDisable, progObiStatsKprobeTCPCloseSrtt)
	}
	if !features.StatsTCPRetransmits() {
		tcpToDisable = append(tcpToDisable, progObiStatsRawTpTCPRetransmitSkb)
	}
	if !features.StatsTCPIo() {
		tcpToDisable = append(tcpToDisable, progObiStatsKprobeTCPSendmsg, progObiStatsKretprobeTCPSendmsg, progObiStatsKprobeTCPCleanupRbuf, progObiStatsKprobeTCPCloseIoFlush)
	}

	storage := planStorageProbes(tlog, features)
	diskReads := diskAttributeReads(features, attrSel, reads.Filtered)
	fsSyncReads := fsSyncAttributeReads(features, attrSel, reads.Filtered)
	if reads.Workloads {
		diskReads.cgroup = true
		fsSyncReads.cgroup = true
	}

	objects := StatsObjects{}
	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	load := func(toDisable []string) error {
		spec, err := LoadStats()
		if err != nil {
			return fmt.Errorf("loading BPF data: %w", err)
		}
		if err := fixupSpec(spec, toDisable); err != nil {
			return fmt.Errorf("fixing up BPF spec: %w", err)
		}
		ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)
		if cpus, err := ebpf.PossibleCPU(); err == nil {
			sizeInFlightMaps(spec, cpus)
		} else {
			tlog.Debug("can't size the in-flight maps to the CPUs", "error", err)
		}
		return ebpfconvenience.LoadSpec(spec, &objects, map[string]any{
			"g_bpf_debug":                cfg.BpfDebug,
			"stats_wakeup_data_bytes":    uint32(cfg.StatsWakeupDataBytes),
			"disk_latency_bounds_ns":     diskLatencyBoundsNs,
			"disk_latency_bounds_len":    uint32(len(histograms.Disk)),
			"disk_status_is_blk_status":  storage.layout.completeReportsBlkStatus,
			"disk_rqf_flush_seq":         storage.layout.flushSeqFlag,
			"disk_req_op_zone_append":    storage.layout.zoneAppendOp,
			"disk_rqf_io_stat":           storage.layout.ioStatFlag,
			"disk_read_cgroup":           diskReads.cgroup,
			"disk_read_partition":        diskReads.partition,
			"fs_sync_latency_bounds_ns":  fsSyncLatencyBoundsNs,
			"fs_sync_latency_bounds_len": uint32(len(histograms.FsSyncDuration)),
			"fs_sync_read_cgroup":        fsSyncReads.cgroup,
			"fs_sync_read_filesystem":    fsSyncReads.filesystem,
			"nfs_latency_bounds_ns":      nfsLatencyBoundsNs,
			"nfs_latency_bounds_len":     uint32(len(histograms.NFS)),
		}, sharedMaps, &mu, "", nil)
	}
	err = load(slices.Concat(tcpToDisable, storage.programsToDisable()))
	if err != nil && storage.any() {
		// as OBI does with an optional tracer that can't be loaded, the stats go on without the
		// storage programs
		storage.disableAll(fmt.Errorf("can't load their BPF programs: %w", err))
		err = load(slices.Concat(tcpToDisable, storage.programsToDisable()))
	}
	if err != nil {
		return nil, fmt.Errorf("loading stats eBPF spec: %w", err)
	}

	closables, err := attachTCPProbes(tlog, &objects, features, connRoleUsed)
	if err != nil {
		closeAll(closables)
		return nil, err
	}
	closables = append(closables, storage.attach(tlog, &objects)...)

	return &StatsFetcher{
		log:                   tlog,
		objects:               &objects,
		closables:             closables,
		diskAttached:          storage.disk,
		diskStatusIsBlkStatus: storage.layout.completeReportsBlkStatus,
		bioAttached:           storage.bio,
		fsSyncAttached:        storage.fsSync,
		nfs:                   storage.nfsState,
		disabled:              storage.disabled,
	}, nil
}

// attachTCPProbes attaches the probes of the enabled TCP stats, which are required
func attachTCPProbes(log *slog.Logger, objects *StatsObjects, features *export.Features, connRoleUsed bool) ([]io.Closer, error) {
	var closables []io.Closer

	// kretprobes, attached before the kprobes: a call that starts once its kprobe is attached must
	// not return before its kretprobe is, or its start is never completed
	if features.StatsTCPIo() {
		l, err := attachKretprobe(log, KprobeTCPSendMsg, objects.ObiStatsKretprobeTcpSendmsg, 0)
		if err != nil {
			return closables, fmt.Errorf("failed kretprobe attachment %s: %w", KprobeTCPSendMsg, err)
		}
		closables = append(closables, l)
	}

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
			return closables, fmt.Errorf("failed kprobe attachment %s: %w", k.name, err)
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
			return closables, fmt.Errorf("failed tracepoint attachment %s: %w", t.name, err)
		}
		closables = append(closables, l)
	}

	// raw tracepoints
	if features.StatsTCPRetransmits() {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    RawTracepointTCPRetransmitSkb,
			Program: objects.ObiStatsRawTpTcpRetransmitSkb,
		})
		if err != nil {
			return closables, fmt.Errorf("failed raw tracepoint attachment %s: %w", RawTracepointTCPRetransmitSkb, err)
		}
		closables = append(closables, l)
	}
	return closables, nil
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
		links, err := attachFsSyncPair(log, syscall.name, syscall.entry, objects.ObiStatsKretprobeSysFsSync)
		if err != nil {
			log.Debug("skipping sync system call", "syscall", syscall.name, "error", err)
			continue
		}
		closables = append(closables, links...)
	}
	return closables
}

// attachDoFsync attaches the probes of do_fsync, when the kernel has it as a function of its own
func attachDoFsync(log *slog.Logger, objects *StatsObjects) []io.Closer {
	links, err := attachFsSyncPair(log, KprobeDoFsync, objects.ObiStatsKprobeDoFsync, objects.ObiStatsKretprobeDoFsync)
	if err != nil {
		log.Debug("skipping optional file sync function", "function", KprobeDoFsync, "error", err)
		return nil
	}
	return links
}

// attachFsSyncPair attaches the return probe of a file sync function, then its entry probe, or
// neither: a sync started without its return probe would never be completed
func attachFsSyncPair(log *slog.Logger, symbol string, entry, ret *ebpf.Program) ([]io.Closer, error) {
	retLink, err := attachKretprobe(log, symbol, ret, fsSyncRetprobeMaxActive)
	if err != nil {
		return nil, err
	}
	entryLink, err := kprobe.Attach(symbol, entry, false)
	if err != nil {
		retLink.Close()
		return nil, err
	}
	return []io.Closer{retLink, entryLink}, nil
}

// attachKretprobe attaches a return probe that tracks up to maxActive calls at once. That needs
// tracefs: without it, the kernel default is used.
func attachKretprobe(log *slog.Logger, symbol string, program *ebpf.Program, maxActive int) (io.Closer, error) {
	if maxActive > 0 {
		l, err := link.Kretprobe(symbol, program, &link.KprobeOptions{RetprobeMaxActive: maxActive})
		if err == nil {
			return l, nil
		}
		log.Debug("attaching the kretprobe with the default number of instances", "function", symbol, "error", err)
	}
	return kprobe.Attach(symbol, program, true)
}

// sizeInFlightMaps gives the in-flight maps room for twice the free entries that the CPUs can keep
// for themselves. Before Linux 6.16, once those hold most of an LRU map, a CPU that needs an entry
// evicts one in flight instead of taking a free one from another CPU, and that request is never
// counted. It only grows the maps of hosts with more than 64 CPUs.
func sizeInFlightMaps(spec *ebpf.CollectionSpec, cpus int) {
	minEntries := uint32(2 * lruLocalFreeTarget * cpus)
	for _, name := range inFlightMaps {
		if m, ok := spec.Maps[name]; ok && m.MaxEntries < minEntries {
			m.MaxEntries = minEntries
		}
	}
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

	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
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
// block I/O, file syncs and NFS RPCs are charged to, or nil if none of their probes are attached,
// or loaded for the NFS ones, which may be attached later.
func (m *StatsFetcher) DiskCgroupNamesMap() *ebpf.Map {
	if !m.diskAttached && !m.fsSyncAttached && !m.nfs.loaded.statsLatency && !m.nfs.loaded.pgio {
		return nil
	}
	return m.objects.DiskCgroupNames
}

// DisabledStorageFeatures returns the enabled storage features whose probes can't be loaded or
// attached on this node, or wait for a kernel module
func (m *StatsFetcher) DisabledStorageFeatures() []DisabledFeature {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Concat(m.disabled, m.nfs.disabled())
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
	// flushSeqFlag is the RQF_FLUSH_SEQ flag of the block requests
	flushSeqFlag uint32
	// zoneAppendOp is REQ_OP_ZONE_APPEND, whose value depends on the kernel, or 0 if the kernel has none
	zoneAppendOp uint32
	// ioStatFlag is the RQF_IO_STAT flag of the block requests, 0 where the kernel numbers its
	// flags with macros
	ioStatFlag uint32
}

// kernelBlockTracepointLayout reads the block tracepoint prototypes from the kernel BTF. The kernel
// version can't be used: the block_rq_issue change was backported to 5.10.137 and RHEL 8.6.
func kernelBlockTracepointLayout(log *slog.Logger) (blockTracepointLayout, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return blockTracepointLayout{unknown: true}, err
	}
	layout, err := blockTracepointLayoutFrom(tracepointProto(spec))
	if err != nil {
		return blockTracepointLayout{unknown: true}, err
	}
	major, minor := ebpfcommon.KernelVersion()
	layout.flushSeqFlag = requestFlushSeqFlag(enumerator(spec), major, minor)
	if layout.flushSeqFlag == 0 {
		log.Warn("can't find the RQF_FLUSH_SEQ request flag in the kernel BTF: the writes with a cache " +
			"flush before or after them may be counted twice")
	}
	zoneAppendOp, _ := enumerator(spec)("REQ_OP_ZONE_APPEND")
	layout.zoneAppendOp = uint32(zoneAppendOp)
	layout.ioStatFlag = requestIOStatFlag(enumerator(spec))
	return layout, nil
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

// rqfFlushSeqBitBeforeEnum is the bit of RQF_FLUSH_SEQ when the request flags were macros, before
// Linux 6.11
const rqfFlushSeqBitBeforeEnum = 4

// The first Linux version that numbers the request flags with an enum
const (
	rqfEnumKernelMajor = 6
	rqfEnumKernelMinor = 11
)

// requestFlushSeqFlag is the RQF_FLUSH_SEQ flag of the block requests. Linux 6.11 and later, and
// backports such as RHEL 9.6, number the request flags with an enum, which is anonymous in some
// versions (e.g. 6.12): the BPF programs can't relocate its enumerators, so they get the flag from
// userspace. The flag is only assumed from the kernel version when the BTF has no such enumerator,
// and 0 (unknown) for an enum kernel: the bit of the macros is another flag there, which would
// drop all the requests of the devices with an I/O scheduler.
func requestFlushSeqFlag(enumerator func(string) (uint64, bool), kernelMajor, kernelMinor int) uint32 {
	if bit, ok := enumerator("__RQF_FLUSH_SEQ"); ok {
		return 1 << bit
	}
	if kernelMajor > rqfEnumKernelMajor || (kernelMajor == rqfEnumKernelMajor && kernelMinor >= rqfEnumKernelMinor) {
		return 0
	}
	return 1 << rqfFlushSeqBitBeforeEnum
}

// requestIOStatFlag is the RQF_IO_STAT flag of the block requests. From Linux 6.13, the kernel
// writes rq->start_time_ns only for the requests it accounts in /proc/diskstats, so a request of a
// device without I/O statistics keeps the start of an earlier use. The kernels that number their
// request flags with macros write the time or 0 at every allocation, and need no flag.
func requestIOStatFlag(enumerator func(string) (uint64, bool)) uint32 {
	if bit, ok := enumerator("__RQF_IO_STAT"); ok {
		return 1 << bit
	}
	return 0
}

// enumerator looks up the value of an enumerator in the enums of a BTF spec, named or anonymous
func enumerator(spec *btf.Spec) func(string) (uint64, bool) {
	return func(name string) (uint64, bool) {
		for typ, err := range spec.All() {
			if err != nil {
				return 0, false
			}
			enum, ok := typ.(*btf.Enum)
			if !ok {
				continue
			}
			for _, value := range enum.Values {
				if value.Name == name {
					return value.Value, true
				}
			}
		}
		return 0, false
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
		return boundsNs, fmt.Errorf("the kernel supports up to %d distinct boundaries across the exporters, got %d",
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

// diskReads tells which attributes of the block I/O the disk probes read: the cgroup the I/O is
// charged to, for the container and Kubernetes attributes, and the partition that it targets
type diskReads struct {
	cgroup, partition bool
}

// diskAttributeReads returns the attributes of the block I/O that the enabled disk metrics report
// or that the filters match
func diskAttributeReads(features *export.Features, attrSel *attributes.AttrSelector, filtered []attr.Name) diskReads {
	metrics := []struct {
		enabled bool
		name    attributes.Name
	}{
		{enabled: features.StatsDiskOperationDuration(), name: attributes.StatDiskOperationDuration},
		{enabled: features.StatsDiskIO(), name: attributes.StatDiskIO},
		{enabled: features.StatsDiskOperations(), name: attributes.StatDiskOperations},
		{enabled: features.StatsDiskOperationTime(), name: attributes.StatDiskOperationTime},
		{enabled: features.StatsDiskQueueDuration(), name: attributes.StatDiskQueueDuration},
		{enabled: features.StatsDiskFlush(), name: attributes.StatDiskFlushDuration},
		{enabled: features.StatsDiskDiscard(), name: attributes.StatDiskDiscardDuration},
		{enabled: features.StatsDiskDiscard(), name: attributes.StatDiskDiscardIO},
	}
	var reads diskReads
	read := func(names []attr.Name) {
		for _, name := range names {
			switch {
			case sameAttribute(name, attr.DiskPartition):
				reads.partition = true
			case reportsWorkload(name):
				reads.cgroup = true
			}
		}
	}
	for _, metric := range metrics {
		if metric.enabled {
			read(attrSel.For(metric.name))
			read(filtered)
		}
	}
	return reads
}

// fsSyncReads tells which attributes of the file syncs the file sync probes read: the cgroup the
// sync is charged to, for the container and Kubernetes attributes, and the filesystem of the
// synced file
type fsSyncReads struct {
	cgroup, filesystem bool
}

// fsSyncAttributeReads returns the attributes of the file syncs that the enabled file sync metrics
// report or that the filters match
func fsSyncAttributeReads(features *export.Features, attrSel *attributes.AttrSelector, filtered []attr.Name) fsSyncReads {
	metrics := []struct {
		enabled bool
		name    attributes.Name
	}{
		{enabled: features.StatsFsSyncDuration(), name: attributes.StatFsSyncDuration},
		{enabled: features.StatsFsSyncOperations(), name: attributes.StatFsSyncOperations},
		{enabled: features.StatsFsSyncOperationTime(), name: attributes.StatFsSyncOperationTime},
	}
	var reads fsSyncReads
	for _, metric := range metrics {
		if !metric.enabled {
			continue
		}
		for _, name := range slices.Concat(attrSel.For(metric.name), filtered) {
			switch {
			case sameAttribute(name, attr.FilesystemMountpoint) || sameAttribute(name, attr.FilesystemType):
				reads.filesystem = true
			case reportsWorkload(name):
				reads.cgroup = true
			}
		}
	}
	return reads
}

// reportsWorkload tells whether an attribute describes the workload that the kernel charges an
// operation to, which the probes find from its cgroup
func reportsWorkload(name attr.Name) bool {
	return sameAttribute(name, attr.ContainerID) || strings.HasPrefix(name.Prom(), "k8s_")
}

// sameAttribute tells whether two attribute names, with dots or underscores, are the same
func sameAttribute(name, other attr.Name) bool {
	return name.Prom() == other.Prom()
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
