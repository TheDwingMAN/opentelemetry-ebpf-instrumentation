// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"log/slog"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
)

type fakeNFSTypes struct {
	structs map[string]bool
	params  map[string]int
}

func (f fakeNFSTypes) hasStruct(_, name string) bool {
	return f.structs[name]
}

func (f fakeNFSTypes) proto(_, name string) (*btf.FuncProto, error) {
	params, ok := f.params[name]
	if !ok {
		return nil, btf.ErrNotFound
	}
	return &btf.FuncProto{Params: make([]btf.FuncParam, params)}, nil
}

func TestNFSProbesFrom(t *testing.T) {
	allTypes := map[string]bool{"rpc_task": true, "nfs_pgio_header": true}
	currentProtos := map[string]int{
		"btf_trace_rpc_stats_latency":  rpcStatsLatencyParams,
		"btf_trace_nfs_readpage_done":  nfsPgioDoneParams,
		"btf_trace_nfs_writeback_done": nfsPgioDoneParams,
	}

	probes := nfsProbesFrom(fakeNFSTypes{structs: allTypes, params: currentProtos}, false)
	require.NoError(t, probes.rpc)
	require.NoError(t, probes.pgio, "the prototypes in the BTF are checked on any kernel version")

	// e.g. Linux 5.8 and 5.10: the modules have no BTF, the types are in vmlinux
	probes = nfsProbesFrom(fakeNFSTypes{structs: allTypes}, true)
	require.NoError(t, probes.rpc)
	require.NoError(t, probes.pgio)

	probes = nfsProbesFrom(fakeNFSTypes{structs: allTypes}, false)
	require.Error(t, probes.rpc, "older kernels without the prototypes are not trusted")
	require.Error(t, probes.pgio)

	probes = nfsProbesFrom(fakeNFSTypes{structs: allTypes, params: map[string]int{
		"btf_trace_rpc_stats_latency":  rpcStatsLatencyParams,
		"btf_trace_nfs_readpage_done":  4,
		"btf_trace_nfs_writeback_done": nfsPgioDoneParams,
	}}, true)
	require.NoError(t, probes.rpc)
	require.Error(t, probes.pgio, "an unexpected prototype is an error, not a guess")

	probes = nfsProbesFrom(fakeNFSTypes{structs: map[string]bool{"rpc_task": true}, params: currentProtos}, true)
	require.NoError(t, probes.rpc)
	require.Error(t, probes.pgio, "the nfs module types are missing")

	probes = nfsProbesFrom(fakeNFSTypes{params: currentProtos}, true)
	require.Error(t, probes.rpc, "the sunrpc module types are missing")
	require.Error(t, probes.pgio, "the I/O probes read the RPC tasks too")
}

func TestNFSLoadFor(t *testing.T) {
	available := nfsProbes{}
	all := export.FeatureStatsNFS
	procedures := export.FeatureStatsNFSClientProcedureDuration
	bytes := export.FeatureStatsNFSClientIO
	none := export.FeatureStatsDisk

	assert.Equal(t, nfsLoad{taskBegin: true, statsLatency: true, pgio: true},
		nfsLoadFor(&all, available, true))
	assert.Equal(t, nfsLoad{taskBegin: true, statsLatency: true}, nfsLoadFor(&procedures, available, true))
	for _, counter := range []export.Features{export.FeatureStatsNFSClientProcedureCount, export.FeatureStatsNFSClientProcedureTime} {
		assert.Equal(t, nfsLoad{taskBegin: true, statsLatency: true}, nfsLoadFor(&counter, available, true),
			"the procedure counters need the RPC probes too")
	}
	assert.Equal(t, nfsLoad{taskBegin: true, pgio: true}, nfsLoadFor(&bytes, available, true))
	assert.Equal(t, nfsLoad{}, nfsLoadFor(&none, available, true))
	assert.Equal(t, nfsLoad{statsLatency: true, pgio: true}, nfsLoadFor(&all, available, false),
		"without an attribute of the workload, the threads that start the RPCs are not read")

	withoutNFSTypes := nfsProbes{pgio: assert.AnError}
	assert.Equal(t, nfsLoad{taskBegin: true, statsLatency: true},
		nfsLoadFor(&all, withoutNFSTypes, true))

	assert.ElementsMatch(t, []string{
		progObiStatsRawTpRPCTaskBegin, progObiStatsRawTpRPCStatsLatency,
		progObiStatsRawTpNFSReadpageDone, progObiStatsRawTpNFSWritebackDone,
	}, nfsLoad{}.programsToDisable())
	assert.Empty(t, nfsLoad{taskBegin: true, statsLatency: true, pgio: true}.programsToDisable())
}

func TestNFSStateDisabled(t *testing.T) {
	all := nfsLoad{taskBegin: true, statsLatency: true, pgio: true}
	procedures := nfsLoad{taskBegin: true, statsLatency: true}
	waitingForSunrpc := DisabledFeature{
		Feature: featureNFSProcedures,
		Reason:  "waiting for the tracepoints of the sunrpc kernel module: the probes are attached when they exist",
	}
	waitingForNFS := DisabledFeature{
		Feature: featureNFSIO,
		Reason:  "waiting for the tracepoints of the nfs kernel module: the probes are attached when they exist",
	}

	tests := []struct {
		name  string
		state nfsState
		want  []DisabledFeature
	}{
		{name: "nothing loaded", state: nfsState{}},
		{
			name:  "all waiting",
			state: nfsState{loaded: all, pending: all},
			want:  []DisabledFeature{waitingForSunrpc, waitingForNFS},
		},
		{
			name:  "procedures attached, I/O waiting",
			state: nfsState{loaded: all, attached: procedures, pending: nfsLoad{pgio: true}},
			want:  []DisabledFeature{waitingForNFS},
		},
		{
			name:  "I/O neither attached nor waiting",
			state: nfsState{loaded: all, attached: procedures},
			want: []DisabledFeature{{
				Feature: featureNFSIO,
				Reason:  "can't attach the nfs_readpage_done and nfs_writeback_done tracepoints",
			}},
		},
		{name: "all attached", state: nfsState{loaded: all, attached: all}},
		{
			name:  "procedures only, waiting",
			state: nfsState{loaded: procedures, pending: procedures},
			want:  []DisabledFeature{waitingForSunrpc},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.state.disabled())
		})
	}
}

func TestNFSStateStopUnsupported(t *testing.T) {
	all := nfsLoad{taskBegin: true, statsLatency: true, pgio: true}
	procedures := nfsLoad{taskBegin: true, statsLatency: true}

	tests := []struct {
		name   string
		state  nfsState
		probes nfsProbes
		want   nfsState
	}{
		{
			name:   "no probe can run",
			state:  nfsState{loaded: all, pending: all},
			probes: nfsProbes{rpc: assert.AnError, pgio: assert.AnError},
			want:   nfsState{loaded: all},
		},
		{
			name:   "the I/O probes can't run",
			state:  nfsState{loaded: all, pending: all},
			probes: nfsProbes{pgio: assert.AnError},
			want:   nfsState{loaded: all, pending: procedures},
		},
		{
			name:   "an attached family is not touched",
			state:  nfsState{loaded: all, attached: procedures, pending: nfsLoad{pgio: true}},
			probes: nfsProbes{rpc: assert.AnError},
			want:   nfsState{loaded: all, attached: procedures, pending: nfsLoad{pgio: true}},
		},
		{
			name:   "rpc_task_begin keeps waiting for an attached family",
			state:  nfsState{loaded: all, attached: nfsLoad{statsLatency: true}, pending: nfsLoad{taskBegin: true, pgio: true}},
			probes: nfsProbes{pgio: assert.AnError},
			want:   nfsState{loaded: all, attached: nfsLoad{statsLatency: true}, pending: nfsLoad{taskBegin: true}},
		},
		{
			name:  "all probes can run",
			state: nfsState{loaded: all, pending: all},
			want:  nfsState{loaded: all, pending: all},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.state.stopUnsupported(slog.New(slog.DiscardHandler), tt.probes)
			assert.Equal(t, tt.want, tt.state)
		})
	}
}

// The fetcher has no objects nor logger, so any attach would panic
func TestRefreshNFSProbesStopsWhenClosed(t *testing.T) {
	fetcher := &StatsFetcher{closed: true, nfs: nfsState{pending: nfsLoad{pgio: true}}}
	assert.NotPanics(t, fetcher.RefreshNFSProbes)
}
