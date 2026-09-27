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
}

// Program names
const (
	progObiStatsKprobeTCPCloseSrtt                    = "obi_stats_kprobe_tcp_close_srtt"
	progObiStatsKprobeTCPCloseIoFlush                 = "obi_stats_kprobe_tcp_close_io_flush"
	progObiStatsTpInetSockSetStateConnRole            = "obi_stats_tp_inet_sock_set_state_conn_role"
	progObiStatsTpInetSockSetStateTCPFailedConnection = "obi_stats_tp_inet_sock_set_state_tcp_failed_connection"
	progObiStatsRawTpTCPRetransmitSkb                 = "obi_stats_raw_tp_tcp_retransmit_skb"
	progObiStatsKprobeTCPSendmsg                      = "obi_stats_kprobe_tcp_sendmsg"
	progObiStatsKretprobeTCPSendmsg                   = "obi_stats_kretprobe_tcp_sendmsg"
	progObiStatsKprobeTCPCleanupRbuf                  = "obi_stats_kprobe_tcp_cleanup_rbuf"
	progObiStatsTpBlockRqInsert                       = "obi_stats_tp_block_rq_insert"
	progObiStatsTpBlockRqIssue                        = "obi_stats_tp_block_rq_issue"
	progObiStatsTpBlockRqComplete                     = "obi_stats_tp_block_rq_complete"
	progObiStatsRawTpBlockRqInsert                    = "obi_stats_raw_tp_block_rq_insert"
	progObiStatsRawTpBlockRqIssue                     = "obi_stats_raw_tp_block_rq_issue"
	progObiStatsRawTpBlockRqComplete                  = "obi_stats_raw_tp_block_rq_complete"

	progObiStatsFentryNFSRead   = "obi_stats_fentry_nfs_read"
	progObiStatsFexitNFSRead    = "obi_stats_fexit_nfs_read"
	progObiStatsFentryNFSWrite  = "obi_stats_fentry_nfs_write"
	progObiStatsFexitNFSWrite   = "obi_stats_fexit_nfs_write"
	progObiStatsFentryNFSFsync  = "obi_stats_fentry_nfs_fsync"
	progObiStatsFexitNFSFsync   = "obi_stats_fexit_nfs_fsync"
	progObiStatsFentryCephRead  = "obi_stats_fentry_ceph_read"
	progObiStatsFexitCephRead   = "obi_stats_fexit_ceph_read"
	progObiStatsFentryCephWrite = "obi_stats_fentry_ceph_write"
	progObiStatsFexitCephWrite  = "obi_stats_fexit_ceph_write"
	progObiStatsFentryCephFsync = "obi_stats_fentry_ceph_fsync"
	progObiStatsFexitCephFsync  = "obi_stats_fexit_ceph_fsync"
	progObiStatsFentryCIFSRead  = "obi_stats_fentry_cifs_read"
	progObiStatsFexitCIFSRead   = "obi_stats_fexit_cifs_read"
	progObiStatsFentryCIFSWrite = "obi_stats_fentry_cifs_write"
	progObiStatsFexitCIFSWrite  = "obi_stats_fexit_cifs_write"
	progObiStatsFentryCIFSFsync = "obi_stats_fentry_cifs_fsync"
	progObiStatsFexitCIFSFsync  = "obi_stats_fexit_cifs_fsync"
	progObiStatsFentryFUSERead  = "obi_stats_fentry_fuse_read"
	progObiStatsFexitFUSERead   = "obi_stats_fexit_fuse_read"
	progObiStatsFentryFUSEWrite = "obi_stats_fentry_fuse_write"
	progObiStatsFexitFUSEWrite  = "obi_stats_fexit_fuse_write"
	progObiStatsFentryFUSEFsync = "obi_stats_fentry_fuse_fsync"
	progObiStatsFexitFUSEFsync  = "obi_stats_fexit_fuse_fsync"

	progObiStatsFentryExt4Read   = "obi_stats_fentry_ext4_read"
	progObiStatsFexitExt4Read    = "obi_stats_fexit_ext4_read"
	progObiStatsFentryExt4Write  = "obi_stats_fentry_ext4_write"
	progObiStatsFexitExt4Write   = "obi_stats_fexit_ext4_write"
	progObiStatsFentryExt4Fsync  = "obi_stats_fentry_ext4_fsync"
	progObiStatsFexitExt4Fsync   = "obi_stats_fexit_ext4_fsync"
	progObiStatsFentryXFSRead    = "obi_stats_fentry_xfs_read"
	progObiStatsFexitXFSRead     = "obi_stats_fexit_xfs_read"
	progObiStatsFentryXFSWrite   = "obi_stats_fentry_xfs_write"
	progObiStatsFexitXFSWrite    = "obi_stats_fexit_xfs_write"
	progObiStatsFentryXFSFsync   = "obi_stats_fentry_xfs_fsync"
	progObiStatsFexitXFSFsync    = "obi_stats_fexit_xfs_fsync"
	progObiStatsFentryBtrfsRead  = "obi_stats_fentry_btrfs_read"
	progObiStatsFexitBtrfsRead   = "obi_stats_fexit_btrfs_read"
	progObiStatsFentryBtrfsWrite = "obi_stats_fentry_btrfs_write"
	progObiStatsFexitBtrfsWrite  = "obi_stats_fexit_btrfs_write"
	progObiStatsFentryBtrfsFsync = "obi_stats_fentry_btrfs_fsync"
	progObiStatsFexitBtrfsFsync  = "obi_stats_fexit_btrfs_fsync"

	progObiStatsKprobeNFSRead        = "obi_stats_kprobe_nfs_read"
	progObiStatsKretprobeNFSRead     = "obi_stats_kretprobe_nfs_read"
	progObiStatsKprobeNFSWrite       = "obi_stats_kprobe_nfs_write"
	progObiStatsKretprobeNFSWrite    = "obi_stats_kretprobe_nfs_write"
	progObiStatsFentrySpliceNFS      = "obi_stats_fentry_nfs_splice_read"
	progObiStatsFexitSpliceNFS       = "obi_stats_fexit_nfs_splice_read"
	progObiStatsKprobeSpliceNFS      = "obi_stats_kprobe_nfs_splice_read"
	progObiStatsKretprobeSpliceNFS   = "obi_stats_kretprobe_nfs_splice_read"
	progObiStatsFentrySpliceFuse     = "obi_stats_fentry_fuse_splice_read"
	progObiStatsFexitSpliceFuse      = "obi_stats_fexit_fuse_splice_read"
	progObiStatsKprobeSpliceFuse     = "obi_stats_kprobe_fuse_splice_read"
	progObiStatsKretprobeSpliceFuse  = "obi_stats_kretprobe_fuse_splice_read"
	progObiStatsFentrySpliceExt4     = "obi_stats_fentry_ext4_splice_read"
	progObiStatsFexitSpliceExt4      = "obi_stats_fexit_ext4_splice_read"
	progObiStatsKprobeSpliceExt4     = "obi_stats_kprobe_ext4_splice_read"
	progObiStatsKretprobeSpliceExt4  = "obi_stats_kretprobe_ext4_splice_read"
	progObiStatsFentrySpliceBtrfs    = "obi_stats_fentry_btrfs_splice_read"
	progObiStatsFexitSpliceBtrfs     = "obi_stats_fexit_btrfs_splice_read"
	progObiStatsKprobeSpliceBtrfs    = "obi_stats_kprobe_btrfs_splice_read"
	progObiStatsKretprobeSpliceBtrfs = "obi_stats_kretprobe_btrfs_splice_read"
	progObiStatsKprobeNFSFsync       = "obi_stats_kprobe_nfs_fsync"
	progObiStatsKretprobeNFSFsync    = "obi_stats_kretprobe_nfs_fsync"
	progObiStatsKprobeCephRead       = "obi_stats_kprobe_ceph_read"
	progObiStatsKretprobeCephRead    = "obi_stats_kretprobe_ceph_read"
	progObiStatsKprobeCephWrite      = "obi_stats_kprobe_ceph_write"
	progObiStatsKretprobeCephWrite   = "obi_stats_kretprobe_ceph_write"
	progObiStatsKprobeCephFsync      = "obi_stats_kprobe_ceph_fsync"
	progObiStatsKretprobeCephFsync   = "obi_stats_kretprobe_ceph_fsync"
	progObiStatsKprobeCIFSRead       = "obi_stats_kprobe_cifs_read"
	progObiStatsKretprobeCIFSRead    = "obi_stats_kretprobe_cifs_read"
	progObiStatsKprobeCIFSWrite      = "obi_stats_kprobe_cifs_write"
	progObiStatsKretprobeCIFSWrite   = "obi_stats_kretprobe_cifs_write"
	progObiStatsKprobeCIFSFsync      = "obi_stats_kprobe_cifs_fsync"
	progObiStatsKretprobeCIFSFsync   = "obi_stats_kretprobe_cifs_fsync"
	progObiStatsKprobeFUSERead       = "obi_stats_kprobe_fuse_read"
	progObiStatsKretprobeFUSERead    = "obi_stats_kretprobe_fuse_read"
	progObiStatsKprobeFUSEWrite      = "obi_stats_kprobe_fuse_write"
	progObiStatsKretprobeFUSEWrite   = "obi_stats_kretprobe_fuse_write"
	progObiStatsKprobeFUSEFsync      = "obi_stats_kprobe_fuse_fsync"
	progObiStatsKretprobeFUSEFsync   = "obi_stats_kretprobe_fuse_fsync"

	progObiStatsKprobeExt4Read      = "obi_stats_kprobe_ext4_read"
	progObiStatsKretprobeExt4Read   = "obi_stats_kretprobe_ext4_read"
	progObiStatsKprobeExt4Write     = "obi_stats_kprobe_ext4_write"
	progObiStatsKretprobeExt4Write  = "obi_stats_kretprobe_ext4_write"
	progObiStatsKprobeExt4Fsync     = "obi_stats_kprobe_ext4_fsync"
	progObiStatsKretprobeExt4Fsync  = "obi_stats_kretprobe_ext4_fsync"
	progObiStatsKprobeXFSRead       = "obi_stats_kprobe_xfs_read"
	progObiStatsKretprobeXFSRead    = "obi_stats_kretprobe_xfs_read"
	progObiStatsKprobeXFSWrite      = "obi_stats_kprobe_xfs_write"
	progObiStatsKretprobeXFSWrite   = "obi_stats_kretprobe_xfs_write"
	progObiStatsKprobeXFSFsync      = "obi_stats_kprobe_xfs_fsync"
	progObiStatsKretprobeXFSFsync   = "obi_stats_kretprobe_xfs_fsync"
	progObiStatsKprobeBtrfsRead     = "obi_stats_kprobe_btrfs_read"
	progObiStatsKretprobeBtrfsRead  = "obi_stats_kretprobe_btrfs_read"
	progObiStatsKprobeBtrfsWrite    = "obi_stats_kprobe_btrfs_write"
	progObiStatsKretprobeBtrfsWrite = "obi_stats_kretprobe_btrfs_write"
	progObiStatsKprobeBtrfsFsync    = "obi_stats_kprobe_btrfs_fsync"
	progObiStatsKretprobeBtrfsFsync = "obi_stats_kretprobe_btrfs_fsync"
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
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type tcp_io_t -type tcp_rtt_t -type tcp_failed_connection_t -type tcp_retransmit_t -type block_io_t -type fs_io_t -target amd64,arm64 Stats ../../../../bpf/statsolly/stats.c -- -I../../../../bpf

type StatsFetcher struct {
	log       *slog.Logger
	objects   *StatsObjects
	closables []io.Closer
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.StatFetcher")
}

func NewStatsFetcher(cfg *config.EBPFTracer, features *export.Features, selectorCfg *attributes.SelectorConfig) (*StatsFetcher, error) {
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
	connRoleAttrSelected := slices.Contains(attrSel.For(attributes.StatTCPRtt), attr.NetworkTCPHandshakeRole) ||
		slices.Contains(attrSel.For(attributes.StatTCPFailedConnections), attr.NetworkTCPHandshakeRole)
	connRoleUsed := (features.StatsTCPFailedConnections() || features.StatsTCPRtt()) && connRoleAttrSelected

	var toDisable []string
	if !features.StatsTCPFailedConnections() {
		toDisable = append(toDisable, progObiStatsTpInetSockSetStateTCPFailedConnection)
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
	storageBlock := features.StorageBlock()
	// Both block families are compiled in; only one is loaded. Raw tracepoints
	// need no tracefs mount but must be able to decode struct request through
	// BTF, so the choice is made here, before load, like the fentry/kprobe
	// choice for filesystems.
	useRawBlock := storageBlock && blockRawTracepointCapable()
	switch {
	case !storageBlock:
		toDisable = append(toDisable, allBlockProgramNames()...)
	case useRawBlock:
		toDisable = append(toDisable, blockTracepointPrograms()...)
	default:
		toDisable = append(toDisable, blockRawTracepointPrograms()...)
	}

	var fsPlans []fsAttachPlan
	if features.StorageFS() {
		fsPlans = planFsAttach()
	}
	fsToDisable, fsAttachTo := planFsToDisable(fsPlans)
	toDisable = append(toDisable, fsToDisable...)

	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	load := func(toDisable []string, attachTo map[string]string) error {
		objects = StatsObjects{}
		return loadStatsObjects(cfg, toDisable, attachTo, &objects, sharedMaps, &mu)
	}
	var fsOK bool
	storageBlock, fsOK, err = loadWithStorageFallback(load, toDisable, fsAttachTo, storageBlock, tlog)
	if err != nil {
		return nil, err
	}
	if !fsOK {
		// Every filesystem program was stubbed out by the fallback above, so
		// attaching any of fsPlans would either fail or attach a no-op stub.
		fsPlans = nil
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

		l, err := link.Kprobe(k.name, k.program, nil)
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
		l, err := link.Kretprobe(k.name, k.program, nil)
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
	}

	// filesystem I/O: best-effort per filesystem. A filesystem whose probes
	// fail to attach is disabled on its own; the rest of the stats agent,
	// including other filesystems, must keep running.
	var fsLinks []io.Closer
	localFSAttached := false
	for _, plan := range fsPlans {
		ls, err := attachFsPlan(&objects, plan)
		if err != nil {
			tlog.Warn("failed filesystem probe attachment; disabling this filesystem",
				"fs", fsTypeStr(plan.Fs), "fentry", plan.UseFentry, "error", err)
			continue
		}
		fsLinks = append(fsLinks, ls...)
		if plan.Fs == CodeFsExt4 || plan.Fs == CodeFsXFS || plan.Fs == CodeFsBtrfs {
			localFSAttached = true
		}
	}
	closables = append(closables, fsLinks...)

	// The allowlist refresher only makes sense once a local filesystem (ext4,
	// xfs, btrfs) is actually attached: those probes are the only ones that
	// consult fs_dev_filter, and network filesystems never populate it.
	if localFSAttached {
		closables = append(closables, startFsDevFilterRefresher(tlog, objects.FsDevFilter))
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

	return &StatsFetcher{
		log:       tlog,
		objects:   &objects,
		closables: closables,
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

// loadStatsObjects loads the stats eBPF spec into objects. sharedMaps and mu
// are threaded in from the caller (rather than created fresh here) so that a
// retry via loadWithStorageFallback reuses the PinInternal maps a prior,
// failed attempt already created instead of orphaning them and creating a
// second set.
func loadStatsObjects(cfg *config.EBPFTracer, toDisable []string, fsAttachTo map[string]string, objects *StatsObjects, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex) error {
	spec, err := LoadStats()
	if err != nil {
		return fmt.Errorf("loading BPF data: %w", err)
	}

	if err := fixupSpec(spec, toDisable); err != nil {
		return fmt.Errorf("fixing up BPF spec: %w", err)
	}

	if err := setFsAttachTargets(spec, fsAttachTo); err != nil {
		return fmt.Errorf("setting filesystem attach targets: %w", err)
	}

	ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)

	if err := ebpfconvenience.LoadSpec(spec, objects, map[string]any{
		"g_bpf_debug":             cfg.BpfDebug,
		"stats_wakeup_data_bytes": uint32(cfg.StatsWakeupDataBytes),
	}, sharedMaps, mu, "", nil); err != nil {
		return fmt.Errorf("loading stats eBPF spec: %w", err)
	}
	return nil
}

// loadWithStorageFallback loads the spec, degrading storage metrics through
// up to two extra attempts when a kernel incompatibility fails the whole
// load: first with the storage block tracepoints stubbed out (if enabled),
// then with every filesystem program stubbed out and fsAttachTo cleared.
// fentry/fexit programs are BTF-checked against their AttachTo target at
// load time, so a signature mismatch on a single filesystem symbol otherwise
// fails the whole load and takes down the rest of the stats agent with it.
// It returns whether storage block metrics and filesystem metrics remain
// enabled.
func blockTracepointPrograms() []string {
	return []string{progObiStatsTpBlockRqInsert, progObiStatsTpBlockRqIssue, progObiStatsTpBlockRqComplete}
}

func blockRawTracepointPrograms() []string {
	return []string{progObiStatsRawTpBlockRqInsert, progObiStatsRawTpBlockRqIssue, progObiStatsRawTpBlockRqComplete}
}

func allBlockProgramNames() []string {
	return append(blockTracepointPrograms(), blockRawTracepointPrograms()...)
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

	if useRaw {
		for _, t := range []struct {
			name    string
			program *ebpf.Program
		}{
			{RawTracepointBlockRqInsert, objects.ObiStatsRawTpBlockRqInsert},
			{RawTracepointBlockRqIssue, objects.ObiStatsRawTpBlockRqIssue},
			{RawTracepointBlockRqComplete, objects.ObiStatsRawTpBlockRqComplete},
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
		{TracepointBlockRqInsert, objects.ObiStatsTpBlockRqInsert},
		{TracepointBlockRqIssue, objects.ObiStatsTpBlockRqIssue},
		{TracepointBlockRqComplete, objects.ObiStatsTpBlockRqComplete},
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

func loadWithStorageFallback(
	load func(toDisable []string, attachTo map[string]string) error,
	toDisable []string,
	fsAttachTo map[string]string,
	storageBlock bool,
	log *slog.Logger,
) (blockOK, fsOK bool, err error) {
	err = load(toDisable, fsAttachTo)
	if err == nil {
		return storageBlock, true, nil
	}

	blockOK = storageBlock
	if blockOK {
		log.Warn("loading stats eBPF spec failed with storage block metrics enabled;"+
			" disabling storage block metrics and retrying (likely kernel incompatibility)", "error", err)
		toDisable = append(toDisable, allBlockProgramNames()...)
		blockOK = false

		if err = load(toDisable, fsAttachTo); err == nil {
			return false, true, nil
		}
	}

	log.Warn("loading stats eBPF spec failed with filesystem metrics enabled;"+
		" disabling filesystem metrics and retrying (likely kernel incompatibility)", "error", err)
	toDisable = append(toDisable, allFsProgramNames()...)
	if err = load(toDisable, nil); err != nil {
		return false, false, err
	}
	return blockOK, false, nil
}

// allFsProgramNames returns every fentry/fexit/kprobe/kretprobe program name
// across every filesystem and operation family (read/write/fsync), for
// loadWithStorageFallback's last-resort filesystem stub.
func allFsProgramNames() []string {
	var names []string
	for _, tgt := range fsTargets {
		n := fsProgNamesFor(tgt.Fs)
		names = append(names, n.fentryPrograms()...)
		names = append(names, n.kprobePrograms()...)
		names = append(names, n.fentryFsyncPrograms()...)
		names = append(names, n.kprobeFsyncPrograms()...)
		names = append(names, n.fentrySplicePrograms()...)
		names = append(names, n.kprobeSplicePrograms()...)
	}
	return names
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

// setFsAttachTargets points the winning fentry/fexit programs at the symbols
// resolveFsSymbol found. The kernel only checks BTF compatibility for a
// Tracing program's AttachTo at load time, so this must run before load.
func setFsAttachTargets(spec *ebpf.CollectionSpec, attachTo map[string]string) error {
	for name, target := range attachTo {
		prog := spec.Programs[name]
		if prog == nil {
			return fmt.Errorf("unknown program name %s", name)
		}
		prog.AttachTo = target
	}
	return nil
}

// fsProgramNames names the twelve programs -- fentry read/write/fsync, fexit
// read/write/fsync, kprobe read/write/fsync, kretprobe read/write/fsync --
// available for one filesystem.
type fsProgramNames struct {
	FentryRead, FexitRead       string
	FentryWrite, FexitWrite     string
	FentryFsync, FexitFsync     string
	KprobeRead, KretprobeRead   string
	KprobeWrite, KretprobeWrite string
	KprobeFsync, KretprobeFsync string
	// Empty for filesystems without a dedicated splice_read symbol.
	FentrySpliceRead, FexitSpliceRead     string
	KprobeSpliceRead, KretprobeSpliceRead string
}

func fsProgNamesFor(fs FsTypeCode) fsProgramNames {
	switch fs {
	case CodeFsNFS:
		return fsProgramNames{
			FentryRead: progObiStatsFentryNFSRead, FexitRead: progObiStatsFexitNFSRead,
			FentryWrite: progObiStatsFentryNFSWrite, FexitWrite: progObiStatsFexitNFSWrite,
			FentryFsync: progObiStatsFentryNFSFsync, FexitFsync: progObiStatsFexitNFSFsync,
			KprobeRead: progObiStatsKprobeNFSRead, KretprobeRead: progObiStatsKretprobeNFSRead,
			KprobeWrite: progObiStatsKprobeNFSWrite, KretprobeWrite: progObiStatsKretprobeNFSWrite,
			KprobeFsync: progObiStatsKprobeNFSFsync, KretprobeFsync: progObiStatsKretprobeNFSFsync,
			FentrySpliceRead: progObiStatsFentrySpliceNFS, FexitSpliceRead: progObiStatsFexitSpliceNFS,
			KprobeSpliceRead: progObiStatsKprobeSpliceNFS, KretprobeSpliceRead: progObiStatsKretprobeSpliceNFS,
		}
	case CodeFsCeph:
		return fsProgramNames{
			FentryRead: progObiStatsFentryCephRead, FexitRead: progObiStatsFexitCephRead,
			FentryWrite: progObiStatsFentryCephWrite, FexitWrite: progObiStatsFexitCephWrite,
			FentryFsync: progObiStatsFentryCephFsync, FexitFsync: progObiStatsFexitCephFsync,
			KprobeRead: progObiStatsKprobeCephRead, KretprobeRead: progObiStatsKretprobeCephRead,
			KprobeWrite: progObiStatsKprobeCephWrite, KretprobeWrite: progObiStatsKretprobeCephWrite,
			KprobeFsync: progObiStatsKprobeCephFsync, KretprobeFsync: progObiStatsKretprobeCephFsync,
		}
	case CodeFsCIFS:
		return fsProgramNames{
			FentryRead: progObiStatsFentryCIFSRead, FexitRead: progObiStatsFexitCIFSRead,
			FentryWrite: progObiStatsFentryCIFSWrite, FexitWrite: progObiStatsFexitCIFSWrite,
			FentryFsync: progObiStatsFentryCIFSFsync, FexitFsync: progObiStatsFexitCIFSFsync,
			KprobeRead: progObiStatsKprobeCIFSRead, KretprobeRead: progObiStatsKretprobeCIFSRead,
			KprobeWrite: progObiStatsKprobeCIFSWrite, KretprobeWrite: progObiStatsKretprobeCIFSWrite,
			KprobeFsync: progObiStatsKprobeCIFSFsync, KretprobeFsync: progObiStatsKretprobeCIFSFsync,
		}
	case CodeFsFUSE:
		return fsProgramNames{
			FentryRead: progObiStatsFentryFUSERead, FexitRead: progObiStatsFexitFUSERead,
			FentryWrite: progObiStatsFentryFUSEWrite, FexitWrite: progObiStatsFexitFUSEWrite,
			FentryFsync: progObiStatsFentryFUSEFsync, FexitFsync: progObiStatsFexitFUSEFsync,
			KprobeRead: progObiStatsKprobeFUSERead, KretprobeRead: progObiStatsKretprobeFUSERead,
			KprobeWrite: progObiStatsKprobeFUSEWrite, KretprobeWrite: progObiStatsKretprobeFUSEWrite,
			KprobeFsync: progObiStatsKprobeFUSEFsync, KretprobeFsync: progObiStatsKretprobeFUSEFsync,
			FentrySpliceRead: progObiStatsFentrySpliceFuse, FexitSpliceRead: progObiStatsFexitSpliceFuse,
			KprobeSpliceRead: progObiStatsKprobeSpliceFuse, KretprobeSpliceRead: progObiStatsKretprobeSpliceFuse,
		}
	case CodeFsExt4:
		return fsProgramNames{
			FentryRead: progObiStatsFentryExt4Read, FexitRead: progObiStatsFexitExt4Read,
			FentryWrite: progObiStatsFentryExt4Write, FexitWrite: progObiStatsFexitExt4Write,
			FentryFsync: progObiStatsFentryExt4Fsync, FexitFsync: progObiStatsFexitExt4Fsync,
			KprobeRead: progObiStatsKprobeExt4Read, KretprobeRead: progObiStatsKretprobeExt4Read,
			KprobeWrite: progObiStatsKprobeExt4Write, KretprobeWrite: progObiStatsKretprobeExt4Write,
			KprobeFsync: progObiStatsKprobeExt4Fsync, KretprobeFsync: progObiStatsKretprobeExt4Fsync,
			FentrySpliceRead: progObiStatsFentrySpliceExt4, FexitSpliceRead: progObiStatsFexitSpliceExt4,
			KprobeSpliceRead: progObiStatsKprobeSpliceExt4, KretprobeSpliceRead: progObiStatsKretprobeSpliceExt4,
		}
	case CodeFsXFS:
		return fsProgramNames{
			FentryRead: progObiStatsFentryXFSRead, FexitRead: progObiStatsFexitXFSRead,
			FentryWrite: progObiStatsFentryXFSWrite, FexitWrite: progObiStatsFexitXFSWrite,
			FentryFsync: progObiStatsFentryXFSFsync, FexitFsync: progObiStatsFexitXFSFsync,
			KprobeRead: progObiStatsKprobeXFSRead, KretprobeRead: progObiStatsKretprobeXFSRead,
			KprobeWrite: progObiStatsKprobeXFSWrite, KretprobeWrite: progObiStatsKretprobeXFSWrite,
			KprobeFsync: progObiStatsKprobeXFSFsync, KretprobeFsync: progObiStatsKretprobeXFSFsync,
		}
	case CodeFsBtrfs:
		return fsProgramNames{
			FentryRead: progObiStatsFentryBtrfsRead, FexitRead: progObiStatsFexitBtrfsRead,
			FentryWrite: progObiStatsFentryBtrfsWrite, FexitWrite: progObiStatsFexitBtrfsWrite,
			FentryFsync: progObiStatsFentryBtrfsFsync, FexitFsync: progObiStatsFexitBtrfsFsync,
			KprobeRead: progObiStatsKprobeBtrfsRead, KretprobeRead: progObiStatsKretprobeBtrfsRead,
			KprobeWrite: progObiStatsKprobeBtrfsWrite, KretprobeWrite: progObiStatsKretprobeBtrfsWrite,
			KprobeFsync: progObiStatsKprobeBtrfsFsync, KretprobeFsync: progObiStatsKretprobeBtrfsFsync,
			FentrySpliceRead: progObiStatsFentrySpliceBtrfs, FexitSpliceRead: progObiStatsFexitSpliceBtrfs,
			KprobeSpliceRead: progObiStatsKprobeSpliceBtrfs, KretprobeSpliceRead: progObiStatsKretprobeSpliceBtrfs,
		}
	default:
		return fsProgramNames{}
	}
}

func (n fsProgramNames) fentryPrograms() []string {
	return []string{n.FentryRead, n.FexitRead, n.FentryWrite, n.FexitWrite}
}

func (n fsProgramNames) kprobePrograms() []string {
	return []string{n.KprobeRead, n.KretprobeRead, n.KprobeWrite, n.KretprobeWrite}
}

func (n fsProgramNames) fentryFsyncPrograms() []string {
	return []string{n.FentryFsync, n.FexitFsync}
}

func (n fsProgramNames) kprobeFsyncPrograms() []string {
	return []string{n.KprobeFsync, n.KretprobeFsync}
}

// The splice families are empty for filesystems that have no dedicated
// splice_read symbol, and an empty name is not a program fixupSpec knows.
func (n fsProgramNames) fentrySplicePrograms() []string {
	if n.FentrySpliceRead == "" {
		return nil
	}
	return []string{n.FentrySpliceRead, n.FexitSpliceRead}
}

func (n fsProgramNames) kprobeSplicePrograms() []string {
	if n.KprobeSpliceRead == "" {
		return nil
	}
	return []string{n.KprobeSpliceRead, n.KretprobeSpliceRead}
}

// planFsToDisable turns the per-filesystem attach plans into the programs to
// stub out before load and the AttachTo targets to set on the survivors.
// A filesystem absent from plans (module not loaded, or neither read/write
// symbol probeable) has all its program families disabled; a planned
// filesystem has only its losing read/write family disabled. Both families
// are never loaded together for the same filesystem. Fsync is decided
// separately: a plan with no FsyncSym (no fsync candidate probeable) has both
// its fsync families disabled while read/write still attach.
func planFsToDisable(plans []fsAttachPlan) (toDisable []string, attachTo map[string]string) {
	byFs := make(map[FsTypeCode]fsAttachPlan, len(plans))
	for _, p := range plans {
		byFs[p.Fs] = p
	}

	attachTo = map[string]string{}
	for _, tgt := range fsTargets {
		names := fsProgNamesFor(tgt.Fs)
		plan, planned := byFs[tgt.Fs]
		if !planned {
			toDisable = append(toDisable, names.fentryPrograms()...)
			toDisable = append(toDisable, names.kprobePrograms()...)
			toDisable = append(toDisable, names.fentryFsyncPrograms()...)
			toDisable = append(toDisable, names.kprobeFsyncPrograms()...)
			toDisable = append(toDisable, names.fentrySplicePrograms()...)
			toDisable = append(toDisable, names.kprobeSplicePrograms()...)
			continue
		}

		if !plan.UseFentry {
			toDisable = append(toDisable, names.fentryPrograms()...)
		} else {
			toDisable = append(toDisable, names.kprobePrograms()...)
			attachTo[names.FentryRead] = plan.ReadSym
			attachTo[names.FexitRead] = plan.ReadSym
			attachTo[names.FentryWrite] = plan.WriteSym
			attachTo[names.FexitWrite] = plan.WriteSym
		}

		switch {
		case plan.SpliceReadSym == "":
			toDisable = append(toDisable, names.fentrySplicePrograms()...)
			toDisable = append(toDisable, names.kprobeSplicePrograms()...)
		case !plan.UseFentry:
			toDisable = append(toDisable, names.fentrySplicePrograms()...)
		default:
			toDisable = append(toDisable, names.kprobeSplicePrograms()...)
			attachTo[names.FentrySpliceRead] = plan.SpliceReadSym
			attachTo[names.FexitSpliceRead] = plan.SpliceReadSym
		}

		if plan.FsyncSym == "" {
			toDisable = append(toDisable, names.fentryFsyncPrograms()...)
			toDisable = append(toDisable, names.kprobeFsyncPrograms()...)
			continue
		}
		if !plan.UseFentry {
			toDisable = append(toDisable, names.fentryFsyncPrograms()...)
		} else {
			toDisable = append(toDisable, names.kprobeFsyncPrograms()...)
			attachTo[names.FentryFsync] = plan.FsyncSym
			attachTo[names.FexitFsync] = plan.FsyncSym
		}
	}
	return toDisable, attachTo
}

// fsProgramsFor returns the loaded programs backing an fsAttachPlan.
func fsProgramsFor(fs FsTypeCode, objects *StatsObjects) (fentryRead, fexitRead, fentryWrite, fexitWrite,
	kprobeRead, kretprobeRead, kprobeWrite, kretprobeWrite *ebpf.Program,
) {
	switch fs {
	case CodeFsNFS:
		return objects.ObiStatsFentryNfsRead, objects.ObiStatsFexitNfsRead,
			objects.ObiStatsFentryNfsWrite, objects.ObiStatsFexitNfsWrite,
			objects.ObiStatsKprobeNfsRead, objects.ObiStatsKretprobeNfsRead,
			objects.ObiStatsKprobeNfsWrite, objects.ObiStatsKretprobeNfsWrite
	case CodeFsCeph:
		return objects.ObiStatsFentryCephRead, objects.ObiStatsFexitCephRead,
			objects.ObiStatsFentryCephWrite, objects.ObiStatsFexitCephWrite,
			objects.ObiStatsKprobeCephRead, objects.ObiStatsKretprobeCephRead,
			objects.ObiStatsKprobeCephWrite, objects.ObiStatsKretprobeCephWrite
	case CodeFsCIFS:
		return objects.ObiStatsFentryCifsRead, objects.ObiStatsFexitCifsRead,
			objects.ObiStatsFentryCifsWrite, objects.ObiStatsFexitCifsWrite,
			objects.ObiStatsKprobeCifsRead, objects.ObiStatsKretprobeCifsRead,
			objects.ObiStatsKprobeCifsWrite, objects.ObiStatsKretprobeCifsWrite
	case CodeFsFUSE:
		return objects.ObiStatsFentryFuseRead, objects.ObiStatsFexitFuseRead,
			objects.ObiStatsFentryFuseWrite, objects.ObiStatsFexitFuseWrite,
			objects.ObiStatsKprobeFuseRead, objects.ObiStatsKretprobeFuseRead,
			objects.ObiStatsKprobeFuseWrite, objects.ObiStatsKretprobeFuseWrite
	case CodeFsExt4:
		return objects.ObiStatsFentryExt4Read, objects.ObiStatsFexitExt4Read,
			objects.ObiStatsFentryExt4Write, objects.ObiStatsFexitExt4Write,
			objects.ObiStatsKprobeExt4Read, objects.ObiStatsKretprobeExt4Read,
			objects.ObiStatsKprobeExt4Write, objects.ObiStatsKretprobeExt4Write
	case CodeFsXFS:
		return objects.ObiStatsFentryXfsRead, objects.ObiStatsFexitXfsRead,
			objects.ObiStatsFentryXfsWrite, objects.ObiStatsFexitXfsWrite,
			objects.ObiStatsKprobeXfsRead, objects.ObiStatsKretprobeXfsRead,
			objects.ObiStatsKprobeXfsWrite, objects.ObiStatsKretprobeXfsWrite
	case CodeFsBtrfs:
		return objects.ObiStatsFentryBtrfsRead, objects.ObiStatsFexitBtrfsRead,
			objects.ObiStatsFentryBtrfsWrite, objects.ObiStatsFexitBtrfsWrite,
			objects.ObiStatsKprobeBtrfsRead, objects.ObiStatsKretprobeBtrfsRead,
			objects.ObiStatsKprobeBtrfsWrite, objects.ObiStatsKretprobeBtrfsWrite
	default:
		return nil, nil, nil, nil, nil, nil, nil, nil
	}
}

// fsFsyncProgramsFor returns the loaded fsync programs backing an
// fsAttachPlan.
// fsSpliceReadProgramsFor returns the splice_read programs for a filesystem,
// or all nil for the filesystems that have no dedicated symbol.
func fsSpliceReadProgramsFor(fs FsTypeCode, objects *StatsObjects) (fentry, fexit, kprobe, kretprobe *ebpf.Program) {
	switch fs {
	case CodeFsNFS:
		return objects.ObiStatsFentryNfsSpliceRead, objects.ObiStatsFexitNfsSpliceRead,
			objects.ObiStatsKprobeNfsSpliceRead, objects.ObiStatsKretprobeNfsSpliceRead
	case CodeFsFUSE:
		return objects.ObiStatsFentryFuseSpliceRead, objects.ObiStatsFexitFuseSpliceRead,
			objects.ObiStatsKprobeFuseSpliceRead, objects.ObiStatsKretprobeFuseSpliceRead
	case CodeFsExt4:
		return objects.ObiStatsFentryExt4SpliceRead, objects.ObiStatsFexitExt4SpliceRead,
			objects.ObiStatsKprobeExt4SpliceRead, objects.ObiStatsKretprobeExt4SpliceRead
	case CodeFsBtrfs:
		return objects.ObiStatsFentryBtrfsSpliceRead, objects.ObiStatsFexitBtrfsSpliceRead,
			objects.ObiStatsKprobeBtrfsSpliceRead, objects.ObiStatsKretprobeBtrfsSpliceRead
	default:
		return nil, nil, nil, nil
	}
}

func fsFsyncProgramsFor(fs FsTypeCode, objects *StatsObjects) (fentryFsync, fexitFsync, kprobeFsync, kretprobeFsync *ebpf.Program) {
	switch fs {
	case CodeFsNFS:
		return objects.ObiStatsFentryNfsFsync, objects.ObiStatsFexitNfsFsync,
			objects.ObiStatsKprobeNfsFsync, objects.ObiStatsKretprobeNfsFsync
	case CodeFsCeph:
		return objects.ObiStatsFentryCephFsync, objects.ObiStatsFexitCephFsync,
			objects.ObiStatsKprobeCephFsync, objects.ObiStatsKretprobeCephFsync
	case CodeFsCIFS:
		return objects.ObiStatsFentryCifsFsync, objects.ObiStatsFexitCifsFsync,
			objects.ObiStatsKprobeCifsFsync, objects.ObiStatsKretprobeCifsFsync
	case CodeFsFUSE:
		return objects.ObiStatsFentryFuseFsync, objects.ObiStatsFexitFuseFsync,
			objects.ObiStatsKprobeFuseFsync, objects.ObiStatsKretprobeFuseFsync
	case CodeFsExt4:
		return objects.ObiStatsFentryExt4Fsync, objects.ObiStatsFexitExt4Fsync,
			objects.ObiStatsKprobeExt4Fsync, objects.ObiStatsKretprobeExt4Fsync
	case CodeFsXFS:
		return objects.ObiStatsFentryXfsFsync, objects.ObiStatsFexitXfsFsync,
			objects.ObiStatsKprobeXfsFsync, objects.ObiStatsKretprobeXfsFsync
	case CodeFsBtrfs:
		return objects.ObiStatsFentryBtrfsFsync, objects.ObiStatsFexitBtrfsFsync,
			objects.ObiStatsKprobeBtrfsFsync, objects.ObiStatsKretprobeBtrfsFsync
	default:
		return nil, nil, nil, nil
	}
}

// attachFsPlan attaches the read+write programs (entry+exit), plus fsync when
// plan.FsyncSym is set, for one filesystem's chosen plan. On the first attach
// failure it rolls back the links already made for this filesystem and
// returns an error; the caller disables only this filesystem and leaves the
// rest of the fetcher running.
func attachFsPlan(objects *StatsObjects, plan fsAttachPlan) ([]io.Closer, error) {
	fentryRead, fexitRead, fentryWrite, fexitWrite,
		kprobeRead, kretprobeRead, kprobeWrite, kretprobeWrite := fsProgramsFor(plan.Fs, objects)
	fentryFsync, fexitFsync, kprobeFsync, kretprobeFsync := fsFsyncProgramsFor(plan.Fs, objects)
	fentrySplice, fexitSplice, kprobeSplice, kretprobeSplice := fsSpliceReadProgramsFor(plan.Fs, objects)

	var steps []func() (io.Closer, error)
	if plan.UseFentry {
		steps = []func() (io.Closer, error){
			func() (io.Closer, error) {
				return link.AttachTracing(link.TracingOptions{Program: fentryRead, AttachType: ebpf.AttachTraceFEntry})
			},
			func() (io.Closer, error) {
				return link.AttachTracing(link.TracingOptions{Program: fexitRead, AttachType: ebpf.AttachTraceFExit})
			},
			func() (io.Closer, error) {
				return link.AttachTracing(link.TracingOptions{Program: fentryWrite, AttachType: ebpf.AttachTraceFEntry})
			},
			func() (io.Closer, error) {
				return link.AttachTracing(link.TracingOptions{Program: fexitWrite, AttachType: ebpf.AttachTraceFExit})
			},
		}
		if plan.FsyncSym != "" {
			steps = append(steps,
				func() (io.Closer, error) {
					return link.AttachTracing(link.TracingOptions{Program: fentryFsync, AttachType: ebpf.AttachTraceFEntry})
				},
				func() (io.Closer, error) {
					return link.AttachTracing(link.TracingOptions{Program: fexitFsync, AttachType: ebpf.AttachTraceFExit})
				},
			)
		}
		if plan.SpliceReadSym != "" {
			steps = append(steps,
				func() (io.Closer, error) {
					return link.AttachTracing(link.TracingOptions{Program: fentrySplice, AttachType: ebpf.AttachTraceFEntry})
				},
				func() (io.Closer, error) {
					return link.AttachTracing(link.TracingOptions{Program: fexitSplice, AttachType: ebpf.AttachTraceFExit})
				},
			)
		}
	} else {
		steps = []func() (io.Closer, error){
			func() (io.Closer, error) { return link.Kprobe(plan.ReadSym, kprobeRead, nil) },
			func() (io.Closer, error) { return link.Kretprobe(plan.ReadSym, kretprobeRead, nil) },
			func() (io.Closer, error) { return link.Kprobe(plan.WriteSym, kprobeWrite, nil) },
			func() (io.Closer, error) { return link.Kretprobe(plan.WriteSym, kretprobeWrite, nil) },
		}
		if plan.FsyncSym != "" {
			steps = append(steps,
				func() (io.Closer, error) { return link.Kprobe(plan.FsyncSym, kprobeFsync, nil) },
				func() (io.Closer, error) { return link.Kretprobe(plan.FsyncSym, kretprobeFsync, nil) },
			)
		}
		if plan.SpliceReadSym != "" {
			steps = append(steps,
				func() (io.Closer, error) { return link.Kprobe(plan.SpliceReadSym, kprobeSplice, nil) },
				func() (io.Closer, error) { return link.Kretprobe(plan.SpliceReadSym, kretprobeSplice, nil) },
			)
		}
	}

	links := make([]io.Closer, 0, len(steps))
	for _, step := range steps {
		l, err := step()
		if err != nil {
			closeAll(links)
			return nil, err
		}
		links = append(links, l)
	}
	return links, nil
}
