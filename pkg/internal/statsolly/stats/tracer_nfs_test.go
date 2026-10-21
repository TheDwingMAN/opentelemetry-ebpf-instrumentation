// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func nfsProcedureKey(procedure string, version uint32, status uint16) ebpf.StatsNfsProcedureKeyT {
	key := ebpf.StatsNfsProcedureKeyT{Version: version, Status: status}
	copy(key.Server[:], "fs-0123456789abcdef0.efs.us-east-1.amazonaws.com")
	copy(key.Procedure[:], procedure)
	return key
}

// rpcs is the kernel value of n RPCs of 200 µs, in the second bucket
func rpcs(n uint64) ebpf.StatsNfsProcedureAccumT {
	var accum ebpf.StatsNfsProcedureAccumT
	accum.LatencyCount[1] = n
	accum.LatencySumNs = n * 200_000
	return accum
}

// The reader forwards what each server, procedure, version and outcome completed since the previous
// read, and names the NULL procedure, which the kernel doesn't
func TestNFSProcedureReader(t *testing.T) {
	read, lookup, ping := nfsProcedureKey("READ", 4, 0), nfsProcedureKey("LOOKUP", 3, 2), nfsProcedureKey("", 4, 0)
	src := &fakeAccum[ebpf.StatsNfsProcedureKeyT, ebpf.StatsNfsProcedureAccumT]{
		entries: map[ebpf.StatsNfsProcedureKeyT]ebpf.StatsNfsProcedureAccumT{read: rpcs(4), lookup: rpcs(1), ping: rpcs(1)},
	}
	r := newNFSProcedureReader(src, defaultDiskReadInterval)

	procedures := map[string]*ebpf.NFSProcedure{}
	for _, stat := range r.readStats() {
		require.Equal(t, ebpf.StatTypeNFSProcedure, stat.Type)
		assert.Equal(t, "fs-0123456789abcdef0.efs.us-east-1.amazonaws.com", stat.NFSProcedure.Server)
		procedures[stat.NFSProcedure.Procedure] = stat.NFSProcedure
	}
	require.Len(t, procedures, 3)
	assert.Equal(t, uint32(4), procedures["READ"].Version)
	assert.Empty(t, procedures["READ"].ErrorType)
	assertLatency(t, procedures["READ"].Latency, 0.0008, 0, 4)
	assert.Equal(t, uint32(3), procedures["LOOKUP"].Version)
	assert.Equal(t, "ENOENT", procedures["LOOKUP"].ErrorType)
	assertLatency(t, procedures["NULL"].Latency, 0.0002, 0, 1)

	src.entries[read] = rpcs(6)
	stats := r.readStats()
	require.Len(t, stats, 1, "only what changed")
	assertLatency(t, stats[0].NFSProcedure.Latency, 0.0004, 0, 2)
}
