// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestFixupSpec(t *testing.T) {
	const origKpName = "real_kp"
	const origTpName = "real_tp"
	const origConnRoleName = "real_conn_role"

	const origSendmsgName = "real_sendmsg"
	const origRetprobeSendmsgName = "real_retprobe_sendmsg"
	const origCleanupRbufName = "real_cleanup_rbuf"
	const origCloseIoFlushName = "real_close_io_flush"
	const origRetransmitName = "real_retransmit"

	makeSpec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				progObiStatsKprobeTCPCloseSrtt:                    {Name: origKpName, Type: ebpf.Kprobe},
				progObiStatsTpInetSockSetStateTCPFailedConnection: {Name: origTpName, Type: ebpf.TracePoint},
				progObiStatsTpInetSockSetStateConnRole:            {Name: origConnRoleName, Type: ebpf.TracePoint},
				progObiStatsKprobeTCPSendmsg:                      {Name: origSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKretprobeTCPSendmsg:                   {Name: origRetprobeSendmsgName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCleanupRbuf:                  {Name: origCleanupRbufName, Type: ebpf.Kprobe},
				progObiStatsKprobeTCPCloseIoFlush:                 {Name: origCloseIoFlushName, Type: ebpf.Kprobe},
				progObiStatsRawTpTCPRetransmitSkb:                 {Name: origRetransmitName, Type: ebpf.RawTracepoint},
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
				progObiStatsKprobeTCPCloseSrtt:                    origKpName,
				progObiStatsTpInetSockSetStateTCPFailedConnection: origTpName,
				progObiStatsTpInetSockSetStateConnRole:            origConnRoleName,
				progObiStatsKprobeTCPSendmsg:                      origSendmsgName,
				progObiStatsKretprobeTCPSendmsg:                   origRetprobeSendmsgName,
				progObiStatsKprobeTCPCleanupRbuf:                  origCleanupRbufName,
				progObiStatsKprobeTCPCloseIoFlush:                 origCloseIoFlushName,
				progObiStatsRawTpTCPRetransmitSkb:                 origRetransmitName,
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
				progObiStatsTpInetSockSetStateConnRole,
				progObiStatsKprobeTCPSendmsg,
				progObiStatsKretprobeTCPSendmsg,
				progObiStatsKprobeTCPCleanupRbuf,
				progObiStatsKprobeTCPCloseIoFlush,
				progObiStatsRawTpTCPRetransmitSkb,
			},
			want: map[string]string{
				progObiStatsKprobeTCPCloseSrtt:                    "stats_dummy",
				progObiStatsTpInetSockSetStateTCPFailedConnection: "stats_dummy",
				progObiStatsTpInetSockSetStateConnRole:            "stats_dummy",
				progObiStatsKprobeTCPSendmsg:                      "stats_dummy",
				progObiStatsKretprobeTCPSendmsg:                   "stats_dummy",
				progObiStatsKprobeTCPCleanupRbuf:                  "stats_dummy",
				progObiStatsKprobeTCPCloseIoFlush:                 "stats_dummy",
				progObiStatsRawTpTCPRetransmitSkb:                 "stats_dummy",
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

// TestFsFsyncProgramsForRoutesByFilesystem asserts that fsFsyncProgramsFor
// picks the fsync program set matching the requested filesystem, and that an
// unknown filesystem code returns all-nil rather than defaulting to one of
// the known filesystems.
func TestFsFsyncProgramsForRoutesByFilesystem(t *testing.T) {
	objects := &StatsObjects{}
	objects.ObiStatsFentryNfsFsync = &ebpf.Program{}
	objects.ObiStatsFexitNfsFsync = &ebpf.Program{}
	objects.ObiStatsKprobeNfsFsync = &ebpf.Program{}
	objects.ObiStatsKretprobeNfsFsync = &ebpf.Program{}
	objects.ObiStatsFentryCephFsync = &ebpf.Program{}
	objects.ObiStatsFexitCephFsync = &ebpf.Program{}
	objects.ObiStatsKprobeCephFsync = &ebpf.Program{}
	objects.ObiStatsKretprobeCephFsync = &ebpf.Program{}
	objects.ObiStatsFentryCifsFsync = &ebpf.Program{}
	objects.ObiStatsFexitCifsFsync = &ebpf.Program{}
	objects.ObiStatsKprobeCifsFsync = &ebpf.Program{}
	objects.ObiStatsKretprobeCifsFsync = &ebpf.Program{}
	objects.ObiStatsFentryFuseFsync = &ebpf.Program{}
	objects.ObiStatsFexitFuseFsync = &ebpf.Program{}
	objects.ObiStatsKprobeFuseFsync = &ebpf.Program{}
	objects.ObiStatsKretprobeFuseFsync = &ebpf.Program{}

	for _, tc := range []struct {
		fs                                               FsTypeCode
		wantFentry, wantFexit, wantKprobe, wantKretprobe *ebpf.Program
	}{
		{CodeFsNFS, objects.ObiStatsFentryNfsFsync, objects.ObiStatsFexitNfsFsync, objects.ObiStatsKprobeNfsFsync, objects.ObiStatsKretprobeNfsFsync},
		{CodeFsCeph, objects.ObiStatsFentryCephFsync, objects.ObiStatsFexitCephFsync, objects.ObiStatsKprobeCephFsync, objects.ObiStatsKretprobeCephFsync},
		{CodeFsCIFS, objects.ObiStatsFentryCifsFsync, objects.ObiStatsFexitCifsFsync, objects.ObiStatsKprobeCifsFsync, objects.ObiStatsKretprobeCifsFsync},
		{CodeFsFUSE, objects.ObiStatsFentryFuseFsync, objects.ObiStatsFexitFuseFsync, objects.ObiStatsKprobeFuseFsync, objects.ObiStatsKretprobeFuseFsync},
	} {
		fentry, fexit, kprobe, kretprobe := fsFsyncProgramsFor(tc.fs, objects)
		if fentry != tc.wantFentry || fexit != tc.wantFexit || kprobe != tc.wantKprobe || kretprobe != tc.wantKretprobe {
			t.Errorf("fsFsyncProgramsFor(%d): got (%p,%p,%p,%p), want (%p,%p,%p,%p)",
				tc.fs, fentry, fexit, kprobe, kretprobe, tc.wantFentry, tc.wantFexit, tc.wantKprobe, tc.wantKretprobe)
		}
	}

	fentry, fexit, kprobe, kretprobe := fsFsyncProgramsFor(CodeFsUnknown, objects)
	if fentry != nil || fexit != nil || kprobe != nil || kretprobe != nil {
		t.Errorf("fsFsyncProgramsFor(unknown): got (%p,%p,%p,%p), want all nil", fentry, fexit, kprobe, kretprobe)
	}
}

// TestTracepointConstantFormat validates that all tracepoint constants are in group/name format.
// When adding a new tracepoint constant, add it to the hooks slice below.
func TestTracepointConstantFormat(t *testing.T) {
	hooks := []string{
		TracepointInetSockSetState,
		TracepointBlockRqInsert,
		TracepointBlockRqIssue,
		TracepointBlockRqComplete,
	}
	for _, hook := range hooks {
		if _, _, ok := strings.Cut(hook, "/"); !ok {
			t.Errorf("tracepoint constant %q is not in group/name format", hook)
		}
	}
}
