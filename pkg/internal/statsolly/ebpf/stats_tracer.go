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

// lruLocalFreeTarget is how many free entries each CPU keeps for itself in an LRU map
// (LOCAL_FREE_TARGET in kernel/bpf/bpf_lru_list.c)
const lruLocalFreeTarget = 128

// inFlightMaps are the LRU maps whose live entries must not be evicted: they hold an entry from the
// issue of each block request until it completes
var inFlightMaps = []string{"disk_rq_start"}

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

	diskAttached          bool
	diskStatusIsBlkStatus bool
	disabled              []DisabledFeature
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.StatFetcher")
}

// NewStatsFetcher loads and attaches the stat probes of the enabled features. The TCP probes are
// required, while the storage ones are optional: a storage feature whose probes can't be loaded or
// attached is disabled, and listed by DisabledStorageFeatures, and the other stats keep working.
func NewStatsFetcher(cfg *config.EBPFTracer, features *export.Features, selectorCfg *attributes.SelectorConfig) (*StatsFetcher, error) {
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

	objects := StatsObjects{}
	load := newStatsLoader(&objects, cfg.MapsConfig.GlobalScaleFactor, map[string]any{
		"g_bpf_debug":               cfg.BpfDebug,
		"stats_wakeup_data_bytes":   uint32(cfg.StatsWakeupDataBytes),
		"disk_latency_bounds_ns":    diskLatencyBoundsNs(),
		"disk_status_is_blk_status": storage.layout.completeReportsBlkStatus,
		"disk_rqf_flush_seq":        storage.layout.flushSeqFlag,
		"disk_req_op_zone_append":   storage.layout.zoneAppendOp,
		"disk_rqf_io_stat":          storage.layout.ioStatFlag,
	})
	if err := storage.loadOrDisable(load, tcpToDisable); err != nil {
		return nil, fmt.Errorf("loading stats eBPF spec: %w", err)
	}

	closables, err := attachTCPProbes(&objects, features, connRoleUsed)
	if err != nil {
		return nil, err
	}
	closables = append(closables, storage.attach(&objects)...)

	return &StatsFetcher{
		log:                   tlog,
		objects:               &objects,
		closables:             closables,
		diskAttached:          storage.disk,
		diskStatusIsBlkStatus: storage.layout.completeReportsBlkStatus,
		disabled:              storage.disabled,
	}, nil
}

// attachTCPProbes attaches the probes of the enabled TCP stats, which are required
func attachTCPProbes(objects *StatsObjects, features *export.Features, connRoleUsed bool) ([]io.Closer, error) {
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

	return closables, nil
}

// sizeInFlightMaps gives the in-flight maps room for twice the free entries that the CPUs can keep
// for themselves. Before Linux 6.16, except from 6.12.39, 6.6.99, RHEL 9.8 and RHEL 10.2, which
// have the fix, once those hold most of an LRU map, a CPU that needs an entry evicts a live one
// instead of taking a free one from another CPU: an evicted request is never counted. It grows the
// maps of 16384 entries on hosts with more than 64 CPUs.
func sizeInFlightMaps(spec *ebpf.CollectionSpec, cpus int) {
	minEntries := uint32(2 * lruLocalFreeTarget * cpus)
	for _, name := range inFlightMaps {
		if m, ok := spec.Maps[name]; ok && m.MaxEntries < minEntries {
			m.MaxEntries = minEntries
		}
	}
}

// storageMapPrefix starts the names of the maps of the storage features
const storageMapPrefix = "disk_"

func isStorageMap(name string) bool {
	return strings.HasPrefix(name, storageMapPrefix)
}

// shrinkUnusedStorageMaps gives a single entry to the storage maps that no program of the spec uses:
// those of the disabled storage features, whose programs are stubs. StatsObjects holds every map, so
// they are created anyway, and would take their full size of kernel memory.
func shrinkUnusedStorageMaps(spec *ebpf.CollectionSpec) {
	used := map[string]bool{}
	for _, program := range spec.Programs {
		for _, ins := range program.Instructions {
			if ins.IsLoadFromMap() {
				used[ins.Reference()] = true
			}
		}
	}
	for name, m := range spec.Maps {
		if isStorageMap(name) && !used[name] {
			m.MaxEntries = 1
		}
	}
}

// newStatsLoader returns the function that loads the stats programs, but those to disable, into
// objects. Each load creates its own maps, sized for the programs it loads, and closes them if it
// fails: a load without the storage programs gets their maps with a single entry.
func newStatsLoader(objects *StatsObjects, globalScaleFactor int, constants map[string]any) func(toDisable []string) error {
	return func(toDisable []string) error {
		spec, err := LoadStats()
		if err != nil {
			return fmt.Errorf("loading BPF data: %w", err)
		}
		if err := fixupSpec(spec, toDisable); err != nil {
			return fmt.Errorf("fixing up BPF spec: %w", err)
		}
		ebpfconvenience.SetupMapSizes(spec, globalScaleFactor)
		if cpus, err := ebpf.PossibleCPU(); err == nil {
			sizeInFlightMaps(spec, cpus)
		} else {
			tlog().Debug("can't size the in-flight maps to the CPUs", "error", err)
		}
		shrinkUnusedStorageMaps(spec)

		sharedMaps := map[string]*ebpf.Map{}
		var mu sync.Mutex
		if err := ebpfconvenience.LoadSpec(spec, objects, constants, sharedMaps, &mu, "", nil); err != nil {
			for _, m := range sharedMaps {
				m.Close()
			}
			return err
		}
		return nil
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

// DisabledStorageFeatures returns the enabled storage features whose probes can't be loaded or
// attached on this node
func (m *StatsFetcher) DisabledStorageFeatures() []DisabledFeature {
	return m.disabled
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
	return layout, nil
}

// diskLatencyBoundsNs returns DiskLatencyBounds in the nanoseconds that the kernel buckets
// latencies with
func diskLatencyBoundsNs() [diskLatencyBuckets - 1]uint64 {
	var boundsNs [diskLatencyBuckets - 1]uint64
	for i, bound := range export.DiskLatencyBounds {
		boundsNs[i] = uint64(math.Round(bound * float64(time.Second)))
	}
	return boundsNs
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
