// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func newNFSProcedureReader(
	accum accumSource[ebpf.StatsNfsProcedureKeyT, ebpf.StatsNfsProcedureAccumT],
	latencyBounds []float64,
	containers *cgroupContainers,
) *accumReader[ebpf.StatsNfsProcedureKeyT, ebpf.StatsNfsProcedureAccumT] {
	n := nfsProcedureStats{latencyBounds: latencyBounds, containers: containers}
	return newAccumReader("nfs_procedure_accum", accum, n.stat)
}

type nfsProcedureStats struct {
	latencyBounds []float64
	containers    *cgroupContainers
}

// stat returns the NFS RPCs that completed since the previous read of the key, or nil
func (n *nfsProcedureStats) stat(key ebpf.StatsNfsProcedureKeyT, current, previous ebpf.StatsNfsProcedureAccumT) *ebpf.Stat {
	if anyDecreased(current.LatencyCount[:], previous.LatencyCount[:]) {
		previous = ebpf.StatsNfsProcedureAccumT{}
	}
	delta := latencyDelta(n.latencyBounds, current.LatencyCount[:], current.LatencySumNs[:],
		previous.LatencyCount[:], previous.LatencySumNs[:])
	if delta.operations == 0 {
		return nil
	}
	return &ebpf.Stat{
		Type: ebpf.StatTypeNFSProcedure,
		NFSProcedure: &ebpf.NFSProcedure{
			Server:      unix.ByteSliceToString(key.Server[:]),
			Procedure:   unix.ByteSliceToString(key.Procedure[:]),
			Version:     key.Version,
			ErrorType:   nfsErrorType(key.Status),
			ContainerID: n.containers.containerID(key.CgroupId),
			Latency:     delta.latency,
		},
	}
}

func newNFSIOReader(
	accum accumSource[ebpf.StatsNfsIoKeyT, uint64],
	containers *cgroupContainers,
) *accumReader[ebpf.StatsNfsIoKeyT, uint64] {
	stat := func(key ebpf.StatsNfsIoKeyT, current, previous uint64) *ebpf.Stat {
		// kernel counters only grow; a decrease means the LRU map evicted and re-created the entry
		if current < previous {
			previous = 0
		}
		if current == previous {
			return nil
		}
		return &ebpf.Stat{
			Type: ebpf.StatTypeNFSIO,
			NFSIO: &ebpf.NFSIO{
				Server:      unix.ByteSliceToString(key.Server[:]),
				Direction:   uint8(key.Direction),
				ContainerID: containers.containerID(key.CgroupId),
				Bytes:       current - previous,
			},
		}
	}
	return newAccumReader("nfs_io_accum", accum, stat)
}

// nfsErrorType names the status of an NFS RPC after its errno. The NFSv4 errors that the client
// doesn't translate into errnos, and the kernel-internal errnos, are reported by their number.
// Empty on success.
func nfsErrorType(status uint16) string {
	if status == 0 {
		return ""
	}
	if name := unix.ErrnoName(syscall.Errno(status)); name != "" {
		return name
	}
	return strconv.Itoa(int(status))
}
