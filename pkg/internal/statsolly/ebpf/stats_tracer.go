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
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type stat_type -type tcp_fail_reason -type tcp_handshake_role -type network_io_direction -type disk_op -type disk_io_key_t -type disk_io_accum_t -type tcp_io_t -type tcp_rtt_t -type tcp_failed_connection_t -type tcp_retransmit_t -type tcp_successful_connection_t -target $BPF_TARGETS Stats ../../../../bpf/statsolly/stats.c -- -I../../../../bpf

type StatsFetcher struct {
	log       *slog.Logger
	objects   *StatsObjects
	closables []io.Closer

	diskStatusIsBlkStatus bool
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
	var issueHasQueueArg, completeReportsBlkStatus bool
	if diskEnabled {
		if issueHasQueueArg, completeReportsBlkStatus, err = kernelBlockTracepoints(); err != nil {
			return nil, fmt.Errorf("reading the block tracepoint prototypes in the kernel BTF: %w", err)
		}
	}
	toDisable = append(toDisable, diskProgramsToDisable(diskEnabled, issueHasQueueArg)...)

	if err := fixupSpec(spec, toDisable); err != nil {
		return nil, fmt.Errorf("fixing up BPF spec: %w", err)
	}

	ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)
	// without the number of CPUs, the in-flight map keeps its size
	cpus, _ := ebpf.PossibleCPU()
	sizeDiskMaps(spec, diskEnabled, cpus)

	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	if err := ebpfconvenience.LoadSpec(spec, &objects, map[string]any{
		"g_bpf_debug":               cfg.BpfDebug,
		"stats_wakeup_data_bytes":   uint32(cfg.StatsWakeupDataBytes),
		"disk_latency_bounds_ns":    diskLatencyBoundsNs(),
		"disk_status_is_blk_status": completeReportsBlkStatus,
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
		},
		{
			name:    RawTracepointBlockRqIssue,
			program: diskIssueProgram(&objects, issueHasQueueArg),
			enabled: diskEnabled,
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

		diskStatusIsBlkStatus: completeReportsBlkStatus,
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

// DiskIOAccumMap returns the map where the kernel accumulates the block request durations
func (m *StatsFetcher) DiskIOAccumMap() *ebpf.Map {
	return m.objects.DiskIoAccum
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
		spec.Programs[name] = &ebpf.ProgramSpec{
			Name:         "stats_dummy",
			Type:         prog.Type,
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
			License:      "Dual MIT/GPL",
		}
	}
	return nil
}
