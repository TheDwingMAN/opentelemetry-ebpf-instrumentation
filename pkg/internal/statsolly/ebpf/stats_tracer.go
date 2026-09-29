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
	progObiStatsTpBlockRqIssue                        = "obi_stats_tp_block_rq_issue"
	progObiStatsTpBlockRqComplete                     = "obi_stats_tp_block_rq_complete"

	progObiStatsFentryNFSRead   = "obi_stats_fentry_nfs_read"
	progObiStatsFexitNFSRead    = "obi_stats_fexit_nfs_read"
	progObiStatsFentryNFSWrite  = "obi_stats_fentry_nfs_write"
	progObiStatsFexitNFSWrite   = "obi_stats_fexit_nfs_write"
	progObiStatsFentryCephRead  = "obi_stats_fentry_ceph_read"
	progObiStatsFexitCephRead   = "obi_stats_fexit_ceph_read"
	progObiStatsFentryCephWrite = "obi_stats_fentry_ceph_write"
	progObiStatsFexitCephWrite  = "obi_stats_fexit_ceph_write"
	progObiStatsFentryCIFSRead  = "obi_stats_fentry_cifs_read"
	progObiStatsFexitCIFSRead   = "obi_stats_fexit_cifs_read"
	progObiStatsFentryCIFSWrite = "obi_stats_fentry_cifs_write"
	progObiStatsFexitCIFSWrite  = "obi_stats_fexit_cifs_write"
	progObiStatsFentryFUSERead  = "obi_stats_fentry_fuse_read"
	progObiStatsFexitFUSERead   = "obi_stats_fexit_fuse_read"
	progObiStatsFentryFUSEWrite = "obi_stats_fentry_fuse_write"
	progObiStatsFexitFUSEWrite  = "obi_stats_fexit_fuse_write"

	progObiStatsKprobeNFSRead      = "obi_stats_kprobe_nfs_read"
	progObiStatsKretprobeNFSRead   = "obi_stats_kretprobe_nfs_read"
	progObiStatsKprobeNFSWrite     = "obi_stats_kprobe_nfs_write"
	progObiStatsKretprobeNFSWrite  = "obi_stats_kretprobe_nfs_write"
	progObiStatsKprobeCephRead     = "obi_stats_kprobe_ceph_read"
	progObiStatsKretprobeCephRead  = "obi_stats_kretprobe_ceph_read"
	progObiStatsKprobeCephWrite    = "obi_stats_kprobe_ceph_write"
	progObiStatsKretprobeCephWrite = "obi_stats_kretprobe_ceph_write"
	progObiStatsKprobeCIFSRead     = "obi_stats_kprobe_cifs_read"
	progObiStatsKretprobeCIFSRead  = "obi_stats_kretprobe_cifs_read"
	progObiStatsKprobeCIFSWrite    = "obi_stats_kprobe_cifs_write"
	progObiStatsKretprobeCIFSWrite = "obi_stats_kretprobe_cifs_write"
	progObiStatsKprobeFUSERead     = "obi_stats_kprobe_fuse_read"
	progObiStatsKretprobeFUSERead  = "obi_stats_kretprobe_fuse_read"
	progObiStatsKprobeFUSEWrite    = "obi_stats_kprobe_fuse_write"
	progObiStatsKretprobeFUSEWrite = "obi_stats_kretprobe_fuse_write"
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
	if !storageBlock {
		toDisable = append(toDisable, progObiStatsTpBlockRqIssue, progObiStatsTpBlockRqComplete)
	}

	var fsPlans []fsAttachPlan
	if features.StorageFS() {
		fsPlans = planFsAttach()
	}
	fsToDisable, fsAttachTo := planFsToDisable(fsPlans)
	toDisable = append(toDisable, fsToDisable...)

	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	load := func(toDisable []string) error {
		objects = StatsObjects{}
		return loadStatsObjects(cfg, toDisable, fsAttachTo, &objects, sharedMaps, &mu)
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
	var storageLinks []io.Closer
	for _, t := range []probe{
		{
			name:    TracepointBlockRqIssue,
			program: objects.ObiStatsTpBlockRqIssue,
			enabled: storageBlock,
		},
		{
			name:    TracepointBlockRqComplete,
			program: objects.ObiStatsTpBlockRqComplete,
			enabled: storageBlock,
		},
	} {
		if !t.enabled {
			continue
		}

		group, tp, _ := strings.Cut(t.name, "/")
		l, err := link.Tracepoint(group, tp, t.program, nil)
		if err != nil {
			tlog.Warn("failed block tracepoint attachment; disabling storage block metrics",
				"tracepoint", t.name, "error", err)
			closeAll(storageLinks)
			storageLinks = nil
			break
		}
		storageLinks = append(storageLinks, l)
	}
	closables = append(closables, storageLinks...)

	// filesystem I/O: best-effort per filesystem. A filesystem whose probes
	// fail to attach is disabled on its own; the rest of the stats agent,
	// including other filesystems, must keep running.
	var fsLinks []io.Closer
	for _, plan := range fsPlans {
		ls, err := attachFsPlan(&objects, plan)
		if err != nil {
			tlog.Warn("failed filesystem probe attachment; disabling this filesystem",
				"fs", fsTypeStr(plan.Fs), "fentry", plan.UseFentry, "error", err)
			continue
		}
		fsLinks = append(fsLinks, ls...)
	}
	closables = append(closables, fsLinks...)

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

// loadWithStorageFallback loads the spec and, if loading fails while the
// storage block programs are enabled, stubs them out and retries once, so a
// kernel incompatibility in the storage probes never takes down the rest of
// the stats agent. It returns whether storage block metrics remain enabled.
func loadWithStorageFallback(load func(toDisable []string) error, toDisable []string, storageBlock bool, log *slog.Logger) (bool, error) {
	err := load(toDisable)
	if err == nil {
		return storageBlock, nil
	}
	if !storageBlock {
		return false, err
	}

	log.Warn("loading stats eBPF spec failed with storage block metrics enabled;"+
		" disabling storage block metrics and retrying (likely kernel incompatibility)", "error", err)
	toDisable = append(toDisable, progObiStatsTpBlockRqIssue, progObiStatsTpBlockRqComplete)
	if err := load(toDisable); err != nil {
		return false, err
	}
	return false, nil
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

// fsProgramNames names the eight programs -- fentry read/write, fexit
// read/write, kprobe read/write, kretprobe read/write -- available for one
// filesystem.
type fsProgramNames struct {
	FentryRead, FexitRead       string
	FentryWrite, FexitWrite     string
	KprobeRead, KretprobeRead   string
	KprobeWrite, KretprobeWrite string
}

func fsProgNamesFor(fs FsTypeCode) fsProgramNames {
	switch fs {
	case CodeFsNFS:
		return fsProgramNames{
			FentryRead: progObiStatsFentryNFSRead, FexitRead: progObiStatsFexitNFSRead,
			FentryWrite: progObiStatsFentryNFSWrite, FexitWrite: progObiStatsFexitNFSWrite,
			KprobeRead: progObiStatsKprobeNFSRead, KretprobeRead: progObiStatsKretprobeNFSRead,
			KprobeWrite: progObiStatsKprobeNFSWrite, KretprobeWrite: progObiStatsKretprobeNFSWrite,
		}
	case CodeFsCeph:
		return fsProgramNames{
			FentryRead: progObiStatsFentryCephRead, FexitRead: progObiStatsFexitCephRead,
			FentryWrite: progObiStatsFentryCephWrite, FexitWrite: progObiStatsFexitCephWrite,
			KprobeRead: progObiStatsKprobeCephRead, KretprobeRead: progObiStatsKretprobeCephRead,
			KprobeWrite: progObiStatsKprobeCephWrite, KretprobeWrite: progObiStatsKretprobeCephWrite,
		}
	case CodeFsCIFS:
		return fsProgramNames{
			FentryRead: progObiStatsFentryCIFSRead, FexitRead: progObiStatsFexitCIFSRead,
			FentryWrite: progObiStatsFentryCIFSWrite, FexitWrite: progObiStatsFexitCIFSWrite,
			KprobeRead: progObiStatsKprobeCIFSRead, KretprobeRead: progObiStatsKretprobeCIFSRead,
			KprobeWrite: progObiStatsKprobeCIFSWrite, KretprobeWrite: progObiStatsKretprobeCIFSWrite,
		}
	case CodeFsFUSE:
		return fsProgramNames{
			FentryRead: progObiStatsFentryFUSERead, FexitRead: progObiStatsFexitFUSERead,
			FentryWrite: progObiStatsFentryFUSEWrite, FexitWrite: progObiStatsFexitFUSEWrite,
			KprobeRead: progObiStatsKprobeFUSERead, KretprobeRead: progObiStatsKretprobeFUSERead,
			KprobeWrite: progObiStatsKprobeFUSEWrite, KretprobeWrite: progObiStatsKretprobeFUSEWrite,
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

// planFsToDisable turns the per-filesystem attach plans into the programs to
// stub out before load and the AttachTo targets to set on the survivors.
// A filesystem absent from plans (module not loaded, or neither symbol
// probeable) has both its program families disabled; a planned filesystem
// has only its losing family disabled. Both families are never loaded
// together for the same filesystem.
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
			continue
		}
		if !plan.UseFentry {
			toDisable = append(toDisable, names.fentryPrograms()...)
			continue
		}
		toDisable = append(toDisable, names.kprobePrograms()...)
		attachTo[names.FentryRead] = plan.ReadSym
		attachTo[names.FexitRead] = plan.ReadSym
		attachTo[names.FentryWrite] = plan.WriteSym
		attachTo[names.FexitWrite] = plan.WriteSym
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
	default:
		return nil, nil, nil, nil, nil, nil, nil, nil
	}
}

// attachFsPlan attaches the four programs (read+write, entry+exit) for one
// filesystem's chosen plan. On the first attach failure it rolls back the
// links already made for this filesystem and returns an error; the caller
// disables only this filesystem and leaves the rest of the fetcher running.
func attachFsPlan(objects *StatsObjects, plan fsAttachPlan) ([]io.Closer, error) {
	fentryRead, fexitRead, fentryWrite, fexitWrite,
		kprobeRead, kretprobeRead, kprobeWrite, kretprobeWrite := fsProgramsFor(plan.Fs, objects)

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
	} else {
		steps = []func() (io.Closer, error){
			func() (io.Closer, error) { return link.Kprobe(plan.ReadSym, kprobeRead, nil) },
			func() (io.Closer, error) { return link.Kretprobe(plan.ReadSym, kretprobeRead, nil) },
			func() (io.Closer, error) { return link.Kprobe(plan.WriteSym, kprobeWrite, nil) },
			func() (io.Closer, error) { return link.Kretprobe(plan.WriteSym, kretprobeWrite, nil) },
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
