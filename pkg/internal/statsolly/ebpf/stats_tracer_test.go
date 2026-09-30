// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
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
	assert.ElementsMatch(t, allDisk, diskProgramsToDisable(true, blockTracepointLayout{unknown: true}),
		"no disk program is loaded when the tracepoint layout can't be told")
	assert.Equal(t, []string{progObiStatsRawTpBlockRqIssueLegacy},
		diskProgramsToDisable(true, blockTracepointLayout{}),
		"current kernels load the single-argument block_rq_issue program")
	assert.Equal(t, []string{progObiStatsRawTpBlockRqIssue},
		diskProgramsToDisable(true, blockTracepointLayout{issueHasQueueArg: true}),
		"older kernels load the (q, rq) block_rq_issue program")
}

func TestDiskLatencyBoundsToNs(t *testing.T) {
	boundsNs, err := diskLatencyBoundsToNs([]float64{0.00005, 0.001, 2.5})
	require.NoError(t, err)
	assert.Equal(t, []uint64{50_000, 1_000_000, 2_500_000_000}, boundsNs[:3])
	assert.Zero(t, boundsNs[3], "unused boundaries are left unset")

	_, err = diskLatencyBoundsToNs(nil)
	require.NoError(t, err, "no boundaries means a single bucket")

	_, err = diskLatencyBoundsToNs(make([]float64, maxDiskLatencyBounds+1))
	require.Error(t, err, "more boundaries than the kernel has room for")

	_, err = diskLatencyBoundsToNs([]float64{0, 0.001})
	require.Error(t, err, "boundaries must be positive")

	_, err = diskLatencyBoundsToNs([]float64{0.001, 0.0005})
	require.Error(t, err, "boundaries must increase")

	_, err = diskLatencyBoundsToNs([]float64{1e-10, 2e-10})
	require.Error(t, err, "boundaries closer than a nanosecond collapse in the kernel")
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

	bio := btf.FuncParam{Name: "bio", Type: &btf.Pointer{Target: &btf.Struct{Name: "bio"}}}

	protos := func(issue, complete, bioQueue []btf.FuncParam) func(string) (*btf.FuncProto, error) {
		return func(name string) (*btf.FuncProto, error) {
			switch name {
			case "btf_trace_block_rq_issue":
				return &btf.FuncProto{Params: issue}, nil
			case "btf_trace_block_rq_complete":
				return &btf.FuncProto{Params: complete}, nil
			case "btf_trace_block_bio_queue":
				if bioQueue != nil {
					return &btf.FuncProto{Params: bioQueue}, nil
				}
			}
			return nil, btf.ErrNotFound
		}
	}

	current, err := blockTracepointLayoutFrom(protos(
		[]btf.FuncParam{voidPtr, rq}, []btf.FuncParam{voidPtr, rq, blkStatusArg, nrBytes}, []btf.FuncParam{voidPtr, bio}))
	require.NoError(t, err)
	assert.Equal(t, blockTracepointLayout{completeReportsBlkStatus: true}, current)

	// e.g. 5.8 and RHEL 8 up to 8.5
	legacy, err := blockTracepointLayoutFrom(protos(
		[]btf.FuncParam{voidPtr, queue, rq}, []btf.FuncParam{voidPtr, rq, errnoArg, nrBytes}, []btf.FuncParam{voidPtr, queue, bio}))
	require.NoError(t, err)
	assert.Equal(t, blockTracepointLayout{issueHasQueueArg: true, bioQueueHasQueueArg: true}, legacy)

	// e.g. 5.10.137+ or RHEL 8.6+: block_rq_issue changed, block_bio_queue didn't
	backported, err := blockTracepointLayoutFrom(protos(
		[]btf.FuncParam{voidPtr, rq}, []btf.FuncParam{voidPtr, rq, errnoArg, nrBytes}, []btf.FuncParam{voidPtr, queue, bio}))
	require.NoError(t, err)
	assert.Equal(t, blockTracepointLayout{bioQueueHasQueueArg: true}, backported)

	// e.g. 5.11 to 5.15
	mixed, err := blockTracepointLayoutFrom(protos(
		[]btf.FuncParam{voidPtr, rq}, []btf.FuncParam{voidPtr, rq, errnoArg, nrBytes}, []btf.FuncParam{voidPtr, bio}))
	require.NoError(t, err)
	assert.Equal(t, blockTracepointLayout{}, mixed)

	withoutBio, err := blockTracepointLayoutFrom(protos(
		[]btf.FuncParam{voidPtr, rq}, []btf.FuncParam{voidPtr, rq, errnoArg, nrBytes}, nil))
	require.NoError(t, err, "the requests are measured without the bio tracepoint")
	assert.Equal(t, blockTracepointLayout{bioUnknown: true}, withoutBio)

	_, err = blockTracepointLayoutFrom(protos(
		[]btf.FuncParam{voidPtr}, []btf.FuncParam{voidPtr, rq, errnoArg, nrBytes}, nil))
	require.Error(t, err, "an unexpected prototype is an error, not a guess")
}

func TestBioProgramsToDisable(t *testing.T) {
	all := []string{progObiStatsRawTpBlockBioQueue, progObiStatsRawTpBlockBioQueueLegacy, progObiStatsRawTpBlockBioComplete}
	assert.Equal(t, all, bioProgramsToDisable(false, blockTracepointLayout{}))
	assert.Equal(t, []string{progObiStatsRawTpBlockBioQueueLegacy}, bioProgramsToDisable(true, blockTracepointLayout{}))
	assert.Equal(t, []string{progObiStatsRawTpBlockBioQueue},
		bioProgramsToDisable(true, blockTracepointLayout{bioQueueHasQueueArg: true}))
}

func TestDiskAttributeReads(t *testing.T) {
	selecting := func(metric string, include ...string) *attributes.SelectorConfig {
		return &attributes.SelectorConfig{SelectionCfg: attributes.Selection{
			attributes.Section(metric): attributes.InclusionLists{Include: include},
		}}
	}
	reads := func(features export.Features, groups attributes.AttrGroups, selection *attributes.SelectorConfig) diskReads {
		attrSel, err := attributes.NewAttrSelector(groups, selection)
		require.NoError(t, err)
		return diskAttributeReads(&features, attrSel)
	}

	assert.Equal(t, diskReads{}, reads(export.FeatureStatsDisk, attributes.UndefinedGroup, &attributes.SelectorConfig{}),
		"no default attribute of the disk metrics needs the cgroup or the partition outside Kubernetes")
	assert.Equal(t, diskReads{cgroup: true}, reads(export.FeatureStatsDisk, attributes.GroupKubernetes, &attributes.SelectorConfig{}),
		"the Kubernetes attributes of the workload are reported by default")
	assert.Equal(t, diskReads{cgroup: true},
		reads(export.FeatureStatsDiskOperations, attributes.UndefinedGroup, selecting("obi.stat.disk.operations", "container.id")))
	assert.Equal(t, diskReads{partition: true},
		reads(export.FeatureStatsDiskIO, attributes.UndefinedGroup, selecting("obi.stat.disk.io", "obi.disk.partition")))
	assert.Equal(t, diskReads{},
		reads(export.FeatureStatsDiskIO, attributes.UndefinedGroup, selecting("obi.stat.disk.operations", "container.id", "obi.disk.partition")),
		"the attributes of disabled metrics don't count")
}

func TestFsSyncAttributeReads(t *testing.T) {
	selecting := func(include ...string) *attributes.SelectorConfig {
		return &attributes.SelectorConfig{SelectionCfg: attributes.Selection{
			"obi.stat.fs.sync.duration": attributes.InclusionLists{Include: include},
		}}
	}
	reads := func(features export.Features, groups attributes.AttrGroups, selection *attributes.SelectorConfig) fsSyncReads {
		attrSel, err := attributes.NewAttrSelector(groups, selection)
		require.NoError(t, err)
		return fsSyncAttributeReads(&features, attrSel)
	}

	assert.Equal(t, fsSyncReads{}, reads(export.FeatureStatsFsSyncDuration, attributes.UndefinedGroup, &attributes.SelectorConfig{}),
		"no default attribute of the file sync metric needs the cgroup or the filesystem outside Kubernetes")
	assert.Equal(t, fsSyncReads{cgroup: true}, reads(export.FeatureStatsFsSyncDuration, attributes.GroupKubernetes, &attributes.SelectorConfig{}),
		"the Kubernetes attributes of the workload are reported by default")
	assert.Equal(t, fsSyncReads{cgroup: true},
		reads(export.FeatureStatsFsSyncDuration, attributes.UndefinedGroup, selecting("container.id")))
	assert.Equal(t, fsSyncReads{filesystem: true},
		reads(export.FeatureStatsFsSyncDuration, attributes.UndefinedGroup, selecting("system.filesystem.mountpoint")))
	assert.Equal(t, fsSyncReads{filesystem: true},
		reads(export.FeatureStatsFsSyncDuration, attributes.UndefinedGroup, selecting("system.filesystem.type")))
	assert.Equal(t, fsSyncReads{},
		reads(export.FeatureStatsDisk, attributes.UndefinedGroup, selecting("container.id", "system.filesystem.mountpoint")),
		"the attributes of a disabled metric don't count")
}
