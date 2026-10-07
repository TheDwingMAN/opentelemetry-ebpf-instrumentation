// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
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
		nfsLoadFor(&all, available))
	assert.Equal(t, nfsLoad{taskBegin: true, statsLatency: true}, nfsLoadFor(&procedures, available))
	for _, counter := range []export.Features{export.FeatureStatsNFSClientProcedureCount, export.FeatureStatsNFSClientProcedureTime} {
		assert.Equal(t, nfsLoad{taskBegin: true, statsLatency: true}, nfsLoadFor(&counter, available),
			"the procedure counters need the RPC probes too")
	}
	assert.Equal(t, nfsLoad{taskBegin: true, pgio: true}, nfsLoadFor(&bytes, available))
	assert.Equal(t, nfsLoad{}, nfsLoadFor(&none, available))

	withoutNFSTypes := nfsProbes{pgio: assert.AnError}
	assert.Equal(t, nfsLoad{taskBegin: true, statsLatency: true},
		nfsLoadFor(&all, withoutNFSTypes))

	assert.ElementsMatch(t, []string{
		progObiStatsRawTpRPCTaskBegin, progObiStatsRawTpRPCStatsLatency,
		progObiStatsRawTpNFSReadpageDone, progObiStatsRawTpNFSWritebackDone,
	}, nfsLoad{}.programsToDisable())
	assert.Empty(t, nfsLoad{taskBegin: true, statsLatency: true, pgio: true}.programsToDisable())
}
