// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

func TestFixupSpec(t *testing.T) {
	const origKpName = "real_kp"
	const origTpName = "real_tp"
	const origConnRoleName = "real_conn_role"
	const origSuccessTpName = "real_success_tp"

	const origSendmsgName = "real_sendmsg"
	const origRetprobeSendmsgName = "real_retprobe_sendmsg"
	const origCleanupRbufName = "real_cleanup_rbuf"
	const origCloseIoFlushName = "real_close_io_flush"
	const origRetransmitName = "real_retransmit"

	makeSpec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				progObiStatsKprobeTCPCloseSrtt:                        {Name: origKpName, Type: ebpf.Kprobe},
				progObiStatsTpInetSockSetStateTCPFailedConnection:     {Name: origTpName, Type: ebpf.TracePoint},
				progObiStatsTpInetSockSetStateConnRole:                {Name: origConnRoleName, Type: ebpf.TracePoint},
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: {Name: origSuccessTpName, Type: ebpf.TracePoint},
				progObiStatsKprobeTCPSendmsg:                          {Name: origSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKretprobeTCPSendmsg:                       {Name: origRetprobeSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCleanupRbuf:                      {Name: origCleanupRbufName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCloseIoFlush:                     {Name: origCloseIoFlushName, Type: ebpf.Kprobe},
				progObiStatsRawTpTCPRetransmitSkb:                     {Name: origRetransmitName, Type: ebpf.RawTracepoint},
			},
		}
	}

	tests := []struct {
		name      string
		toDisable []string
		want      map[string]string
	}{
		{
			name:      "disable nothing",
			toDisable: nil,
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                        origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection:     origTpName,
				progObiStatsTpInetSockSetStateConnRole:                origConnRoleName,
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: origSuccessTpName,
				progObiStatsKprobeTCPSendmsg:                          origSendmsgName,
				progObiStatsKretprobeTCPSendmsg:                       origRetprobeSendmsgName,
				progObiStatsKprobeTCPCleanupRbuf:                      origCleanupRbufName,
				progObiStatsKprobeTCPCloseIoFlush:                     origCloseIoFlushName,
				progObiStatsRawTpTCPRetransmitSkb:                     origRetransmitName,
			},
		},
		{
			// Regression: stats_tcp_io standalone (no stats_tcp_rtt) must still attach
			// the io_flush probe on tcp_close to avoid losing the final incomplete batch.
			name:      "disable srtt only",
			toDisable: []string{progObiStatsKprobeTCPCloseSrtt},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
				progObiStatsKprobeTCPCloseIoFlush:                 origCloseIoFlushName,
				progObiStatsKprobeTCPSendmsg:                      origSendmsgName,
				progObiStatsKretprobeTCPSendmsg:                   origRetprobeSendmsgName,
				progObiStatsKprobeTCPCleanupRbuf:                  origCleanupRbufName,
				progObiStatsRawTpTCPRetransmitSkb:                 origRetransmitName,
			},
		},
		{
			name:      "disable retransmits only",
			toDisable: []string{progObiStatsRawTpTCPRetransmitSkb},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
				progObiStatsRawTpTCPRetransmitSkb:                 "stats_dummy",
			},
		},
		{
			name:      "disable failed conn only",
			toDisable: []string{progObiStatsTpInetSockSetStateTCPFailedConnection},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
			},
		},
		{
			name:      "disable successful conn only",
			toDisable: []string{progObiStatsTpInetSockSetStateTCPSuccessfulConnection},
			want: map[string]string{
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection:     origTpName,
				progObiStatsTpInetSockSetStateConnRole:                origConnRoleName,
			},
		},
		{
			name:      "disable conn role only",
			toDisable: []string{progObiStatsTpInetSockSetStateConnRole},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            "stats_dummy",
			},
		},
		{
			name:      "disable io programs",
			toDisable: []string{progObiStatsKprobeTCPSendmsg, progObiStatsKretprobeTCPSendmsg, progObiStatsKprobeTCPCleanupRbuf, progObiStatsKprobeTCPCloseIoFlush},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:    origKpName,
				progObiStatsKprobeTCPSendmsg:      "stats_dummy",
				progObiStatsKretprobeTCPSendmsg:   "stats_dummy",
				progObiStatsKprobeTCPCleanupRbuf:  "stats_dummy",
				progObiStatsKprobeTCPCloseIoFlush: "stats_dummy",
			},
		},
		{
			name: "disable all",
			toDisable: []string{
				progObiStatsKprobeTCPCloseSrtt,
				progObiStatsTpInetSockSetStateTCPFailedConnection,
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection,
				progObiStatsTpInetSockSetStateConnRole,
				progObiStatsKprobeTCPSendmsg,
				progObiStatsKretprobeTCPSendmsg,
				progObiStatsKprobeTCPCleanupRbuf,
				progObiStatsKprobeTCPCloseIoFlush,
				progObiStatsRawTpTCPRetransmitSkb,
			},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                        "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection:     "stats_dummy",
				progObiStatsTpInetSockSetStateTCPSuccessfulConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateConnRole:                "stats_dummy",
				progObiStatsKprobeTCPSendmsg:                          "stats_dummy",
				progObiStatsKretprobeTCPSendmsg:                       "stats_dummy",
				progObiStatsKprobeTCPCleanupRbuf:                      "stats_dummy",
				progObiStatsKprobeTCPCloseIoFlush:                     "stats_dummy",
				progObiStatsRawTpTCPRetransmitSkb:                     "stats_dummy",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := makeSpec()
			if err := fixupSpec(spec, tc.toDisable); err != nil {
				t.Fatalf("fixupSpec: %v", err)
			}
			for prog, wantName := range tc.want {
				if got := spec.Programs[prog].Name; got != wantName {
					t.Errorf("program %s: got %q, want %q", prog, got, wantName)
				}
			}
		})
	}
}

func TestFixupSpecUnknownProgram(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			progObiStatsKprobeTCPCloseSrtt: {Name: "real_kp", Type: ebpf.Kprobe},
		},
	}
	if err := fixupSpec(spec, []string{"nonexistent_prog"}); err == nil {
		t.Error("expected error for unknown program name, got nil")
	}
}

// TestTracepointConstantFormat validates that all tracepoint constants are in group/name format.
// When adding a new tracepoint constant, add it to the hooks slice below.
func TestTracepointConstantFormat(t *testing.T) {
	hooks := []string{
		TracepointInetSockSetState,
	}
	for _, hook := range hooks {
		if _, _, ok := strings.Cut(hook, "/"); !ok {
			t.Errorf("tracepoint constant %q is not in group/name format", hook)
		}
	}
}

func TestDiskProgramsToDisable(t *testing.T) {
	allDisk := []string{
		progObiStatsRawTpBlockRqIssue,
		progObiStatsRawTpBlockRqIssueLegacy,
		progObiStatsRawTpBlockRqComplete,
	}
	assert.ElementsMatch(t, allDisk, diskProgramsToDisable(false, blockTracepointLayout{}),
		"no disk program is loaded when disk stats are disabled")
	assert.Equal(t, []string{progObiStatsRawTpBlockRqIssueLegacy},
		diskProgramsToDisable(true, blockTracepointLayout{}),
		"current kernels load the single-argument block_rq_issue program")
	assert.Equal(t, []string{progObiStatsRawTpBlockRqIssue},
		diskProgramsToDisable(true, blockTracepointLayout{issueHasQueueArg: true}),
		"older kernels load the (q, rq) block_rq_issue program")
}

func TestDiskLatencyBoundsNs(t *testing.T) {
	boundsNs := diskLatencyBoundsNs()
	assert.Equal(t, uint64(100_000), boundsNs[0])
	assert.Equal(t, uint64(60_000_000_000), boundsNs[len(boundsNs)-1])
	assert.IsIncreasing(t, boundsNs[:], "the kernel needs them in increasing order, at the nanosecond")
}

func TestBlockTracepointLayoutFromBTF(t *testing.T) {
	voidPtr := btf.FuncParam{Name: "__data", Type: &btf.Pointer{Target: &btf.Void{}}}
	rq := btf.FuncParam{Name: "rq", Type: &btf.Pointer{Target: &btf.Struct{Name: "request"}}}
	queue := btf.FuncParam{Name: "q", Type: &btf.Pointer{Target: &btf.Struct{Name: "request_queue"}}}
	nrBytes := btf.FuncParam{Name: "nr_bytes", Type: &btf.Int{Name: "unsigned int", Size: 4}}
	errnoArg := btf.FuncParam{Name: "error", Type: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}
	blkStatusArg := btf.FuncParam{Name: "error", Type: &btf.Typedef{
		Name: "blk_status_t", Type: &btf.Typedef{Name: "u8", Type: &btf.Int{Name: "unsigned char", Size: 1}},
	}}

	protos := func(issue, complete []btf.FuncParam) func(string) (*btf.FuncProto, error) {
		return func(name string) (*btf.FuncProto, error) {
			switch name {
			case "btf_trace_block_rq_issue":
				return &btf.FuncProto{Params: issue}, nil
			case "btf_trace_block_rq_complete":
				return &btf.FuncProto{Params: complete}, nil
			}
			return nil, btf.ErrNotFound
		}
	}

	current, err := blockTracepointLayoutFrom(protos(
		[]btf.FuncParam{voidPtr, rq}, []btf.FuncParam{voidPtr, rq, blkStatusArg, nrBytes}))
	require.NoError(t, err)
	assert.Equal(t, blockTracepointLayout{completeReportsBlkStatus: true}, current)

	// e.g. 5.8 and RHEL 8 up to 8.5
	legacy, err := blockTracepointLayoutFrom(protos(
		[]btf.FuncParam{voidPtr, queue, rq}, []btf.FuncParam{voidPtr, rq, errnoArg, nrBytes}))
	require.NoError(t, err)
	assert.Equal(t, blockTracepointLayout{issueHasQueueArg: true}, legacy)

	// e.g. 5.10.137+, RHEL 8.6+ and 5.11 to 5.15
	mixed, err := blockTracepointLayoutFrom(protos(
		[]btf.FuncParam{voidPtr, rq}, []btf.FuncParam{voidPtr, rq, errnoArg, nrBytes}))
	require.NoError(t, err)
	assert.Equal(t, blockTracepointLayout{}, mixed)

	_, err = blockTracepointLayoutFrom(protos(
		[]btf.FuncParam{voidPtr}, []btf.FuncParam{voidPtr, rq, errnoArg, nrBytes}))
	require.Error(t, err, "an unexpected prototype is an error, not a guess")
}

// requestFlags is the enum of the request flags, which some kernels leave anonymous
func requestFlags(name string) *btf.Enum {
	return &btf.Enum{Name: name, Size: 4, Values: []btf.EnumValue{
		{Name: "__RQF_STARTED", Value: 0}, {Name: "__RQF_FLUSH_SEQ", Value: 1}, {Name: "__RQF_IO_STAT", Value: 8},
	}}
}

// requestFlagsMacros stands for the BTF of a kernel that numbers the request flags with macros
var requestFlagsMacros = &btf.Int{Name: "int", Size: 4}

func btfSpecOf(t *testing.T, typ btf.Type) *btf.Spec {
	t.Helper()
	builder, err := btf.NewBuilder([]btf.Type{typ}, nil)
	require.NoError(t, err)
	raw, err := builder.Marshal(nil, nil)
	require.NoError(t, err)
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	require.NoError(t, err)
	return spec
}

// The request flags were macros, then numbered by an enum that some kernels leave anonymous, and
// that some older kernels have backported (RHEL 9.6)
func TestRequestFlushSeqFlag(t *testing.T) {
	for _, tc := range []struct {
		name         string
		typ          btf.Type
		major, minor int
		want         uint32
	}{
		{"macros", requestFlagsMacros, 6, 10, 1 << 4},
		{"macros, RHEL 8", requestFlagsMacros, 4, 18, 1 << 4},
		{"anonymous enum", requestFlags(""), 6, 12, 1 << 1},
		{"named enum", requestFlags("rqf_flags"), 6, 18, 1 << 1},
		{"backported enum", requestFlags(""), 5, 14, 1 << 1},
		// the bit of the macros is RQF_SCHED_TAGS in the enum: no flag rather than a wrong one
		{"enum kernel without the enum in its BTF", requestFlagsMacros, 6, 11, 0},
		{"later enum kernel without the enum in its BTF", requestFlagsMacros, 7, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := btfSpecOf(t, tc.typ)
			assert.Equal(t, tc.want, requestFlushSeqFlag(enumerator(spec), tc.major, tc.minor))
		})
	}
}

// Only the kernels that number the request flags with an enum need RQF_IO_STAT
func TestRequestIOStatFlag(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  btf.Type
		want uint32
	}{
		{"macros", requestFlagsMacros, 0},
		{"anonymous enum (6.12, RHEL 9.6)", requestFlags(""), 1 << 8},
		{"named enum (6.18)", requestFlags("rqf_flags"), 1 << 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, requestIOStatFlag(enumerator(btfSpecOf(t, tc.typ))))
		})
	}
}

func TestSizeInFlightMap(t *testing.T) {
	newSpec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
			"disk_rq_start": {Type: ebpf.LRUHash, MaxEntries: 1 << 14},
			"disk_io_accum": {Type: ebpf.Hash, MaxEntries: 1 << 12},
		}}
	}

	// up to 64 CPUs, the map of 16384 entries keeps its size
	spec := newSpec()
	sizeInFlightMap(spec, 64)
	assert.Equal(t, uint32(1<<14), spec.Maps["disk_rq_start"].MaxEntries)

	// beyond, it gets twice the free entries that the CPUs can keep for themselves
	spec = newSpec()
	sizeInFlightMap(spec, 192)
	assert.Equal(t, uint32(2*128*192), spec.Maps["disk_rq_start"].MaxEntries)
	assert.Equal(t, uint32(1<<12), spec.Maps["disk_io_accum"].MaxEntries, "not an in-flight map")

	// a map already scaled beyond it is left alone
	spec = newSpec()
	spec.Maps["disk_rq_start"].MaxEntries = 1 << 17
	sizeInFlightMap(spec, 192)
	assert.Equal(t, uint32(1<<17), spec.Maps["disk_rq_start"].MaxEntries)
}

// The storage maps that no loaded program uses take a single entry, whatever the scale and the CPUs
func TestShrinkUnusedStorageMaps(t *testing.T) {
	// sizes returns the size of each map for the programs of the given storage probes, before and
	// after the shrink
	sizes := func(t *testing.T, storage storageProbes) (before, after map[string]uint32) {
		t.Helper()
		spec, err := LoadStats()
		require.NoError(t, err)
		require.NoError(t, fixupSpec(spec, storage.programsToDisable()))
		ebpfconvenience.SetupMapSizes(spec, 2)
		sizeInFlightMap(spec, 192)
		maxEntries := func() map[string]uint32 {
			entries := map[string]uint32{}
			for name, m := range spec.Maps {
				entries[name] = m.MaxEntries
			}
			return entries
		}
		before = maxEntries()
		shrinkUnusedStorageMaps(spec)
		return before, maxEntries()
	}

	// the probes of each storage feature keep the sizes of their maps, and only of theirs: every
	// other storage map takes one entry, and the TCP maps keep their sizes
	for _, tc := range []struct {
		name    string
		storage storageProbes
		used    []string
	}{
		{name: "TCP only"},
		{"block requests", storageProbes{disk: true}, []string{
			"disk_io_accum", "disk_io_accum_init_storage", "disk_rq_start",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after := sizes(t, tc.storage)
			for name, entries := range after {
				want := before[name]
				if isStorageMap(name) && !slices.Contains(tc.used, name) {
					want = 1
				}
				assert.Equal(t, want, entries, name)
			}
		})
	}
}
