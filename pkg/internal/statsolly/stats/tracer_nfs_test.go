// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

type fakeAccum[K comparable, V any] struct {
	entries map[K]V
}

func (f *fakeAccum[K, V]) read() (map[K]V, error) {
	return maps.Clone(f.entries), nil
}

func (f *fakeAccum[K, V]) delete(key K) error {
	delete(f.entries, key)
	return nil
}

func nfsProcedureKey(server, procedure string, version uint32, status uint16) ebpf.StatsNfsProcedureKeyT {
	key := ebpf.StatsNfsProcedureKeyT{CgroupId: 100, Version: version, Status: status}
	copy(key.Server[:], server)
	copy(key.Procedure[:], procedure)
	return key
}

func nfsIOKey(server string, direction ebpf.StatsNetworkIoDirection) ebpf.StatsNfsIoKeyT {
	key := ebpf.StatsNfsIoKeyT{CgroupId: 100, Direction: direction}
	copy(key.Server[:], server)
	return key
}

func TestNFSProcedureReader(t *testing.T) {
	const containerID = "40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9"
	read := nfsProcedureKey("10.0.0.5", "READ", 4, 0)
	stale := nfsProcedureKey("10.0.0.5", "GETATTR", 3, uint16(unix.ESTALE))
	rpcs := func(count, latencyNs uint64) ebpf.StatsNfsProcedureAccumT {
		var a ebpf.StatsNfsProcedureAccumT
		a.LatencyCount[1], a.LatencySumNs[1] = count, count*latencyNs
		return a
	}
	src := &fakeAccum[ebpf.StatsNfsProcedureKeyT, ebpf.StatsNfsProcedureAccumT]{
		entries: map[ebpf.StatsNfsProcedureKeyT]ebpf.StatsNfsProcedureAccumT{
			read:  rpcs(4, 2_000_000),
			stale: rpcs(1, 2_000_000),
		},
	}
	r := newNFSProcedureReader(src, testBounds, newCgroupContainers(fakeCgroupNames{
		100: "cri-containerd-" + containerID + ".scope",
	}))

	stats := r.readStats()
	require.Len(t, stats, 2)
	byProcedure := map[string]*ebpf.NFSProcedure{}
	for _, stat := range stats {
		assert.Equal(t, ebpf.StatTypeNFSProcedure, stat.Type)
		assert.Equal(t, containerID, stat.NFSProcedure.ContainerID)
		assert.Equal(t, "10.0.0.5", stat.NFSProcedure.Server)
		byProcedure[stat.NFSProcedure.Procedure] = stat.NFSProcedure
	}
	assert.Equal(t, uint32(4), byProcedure["READ"].Version)
	assert.Empty(t, byProcedure["READ"].ErrorType)
	assert.Equal(t, []ebpf.LatencySample{{Seconds: 0.002, Count: 4}}, byProcedure["READ"].Latency)
	assert.Equal(t, uint64(4), byProcedure["READ"].Calls)
	assert.InDelta(t, 0.008, byProcedure["READ"].Time, 1e-12)
	assert.Equal(t, uint32(3), byProcedure["GETATTR"].Version)
	assert.Equal(t, "ESTALE", byProcedure["GETATTR"].ErrorType)

	src.entries[read] = rpcs(6, 2_000_000)
	stats = r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, []ebpf.LatencySample{{Seconds: 0.002, Count: 2}}, stats[0].NFSProcedure.Latency)
	assert.Equal(t, uint64(2), stats[0].NFSProcedure.Calls)
	assert.InDelta(t, 0.004, stats[0].NFSProcedure.Time, 1e-12)
}

func TestNFSIOReader(t *testing.T) {
	reads := nfsIOKey("fd00::5", ebpf.StatsNetworkIoDirectionDirectionReceive)
	writes := nfsIOKey("fd00::5", ebpf.StatsNetworkIoDirectionDirectionTransmit)
	src := &fakeAccum[ebpf.StatsNfsIoKeyT, uint64]{entries: map[ebpf.StatsNfsIoKeyT]uint64{
		reads:  1 << 20,
		writes: 4096,
	}}
	r := newNFSIOReader(src, newCgroupContainers(fakeCgroupNames{}))

	stats := r.readStats()
	require.Len(t, stats, 2)
	bytes := map[uint8]uint64{}
	for _, stat := range stats {
		assert.Equal(t, ebpf.StatTypeNFSIO, stat.Type)
		assert.Equal(t, "fd00::5", stat.NFSIO.Server)
		assert.Empty(t, stat.NFSIO.ContainerID, "cgroups with no name are not containers")
		bytes[stat.NFSIO.Direction] = stat.NFSIO.Bytes
	}
	assert.Equal(t, map[uint8]uint64{
		uint8(ebpf.CodeDirectionReceive):  1 << 20,
		uint8(ebpf.CodeDirectionTransmit): 4096,
	}, bytes)

	src.entries[writes] = 3 * 4096
	stats = r.readStats()
	require.Len(t, stats, 1, "only what grew is reported")
	assert.Equal(t, uint64(2*4096), stats[0].NFSIO.Bytes)

	// the LRU map evicted and re-created the entry
	src.entries[writes] = 512
	stats = r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, uint64(512), stats[0].NFSIO.Bytes)
}

func TestNFSErrorType(t *testing.T) {
	assert.Empty(t, nfsErrorType(0))
	assert.Equal(t, "EIO", nfsErrorType(uint16(unix.EIO)))
	// NFS4ERR_DELAY, which the client retries instead of translating
	assert.Equal(t, "10008", nfsErrorType(10008))
}
