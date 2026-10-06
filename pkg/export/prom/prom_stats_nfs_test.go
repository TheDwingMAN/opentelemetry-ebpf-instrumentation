// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func nfsRPCStat(statIdx uint16, status int32, executeNs, retrans uint64) *ebpf.Stat {
	return &ebpf.Stat{Type: ebpf.StatTypeNFSRPC, NFSRPC: &ebpf.NFSRPC{
		Version: 3, StatIdx: statIdx, Status: status,
		Family: 2, Addr: [16]byte{192, 168, 122, 34},
		ExecuteNs: executeNs, Retransmits: retrans,
	}}
}

// An NFSv3 RPC is named by its procedure, and carries no NFSv4 operation
// (Prometheus drops the empty label); the version is a string label. Errors
// count the failed attempts, retransmits every transmission after the first.
func TestStatsReporterRecordsNFSMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newStatsReporterWithFeatures(t, registry, export.FeatureStorageNFS)

	reporter.observeNFSRPC(nfsRPCStat(6, 0, 2_000_000, 0))
	reporter.observeNFSRPC(nfsRPCStat(6, 0, 10_400_000_000, 2))
	reporter.observeNFSRPC(nfsRPCStat(7, -528, 1_000_000, 0))

	read := map[string]string{
		"onc_rpc_version":        "3",
		"onc_rpc_procedure_name": "READ",
		"nfs_operation_name":     "",
		"server_address":         "192.168.122.34",
	}
	duration := gatheredMetric(t, registry, "obi_stat_nfs_client_rpc_duration_seconds", read)
	require.NotNil(t, duration)
	assert.Equal(t, uint64(2), duration.GetHistogram().GetSampleCount())
	for _, b := range duration.GetHistogram().GetBucket() {
		if b.GetUpperBound() == 10 {
			assert.Equal(t, uint64(1), b.GetCumulativeCount(), "10.4 s is above the 10 s bound")
		}
	}

	retransmits := gatheredMetric(t, registry, "obi_stat_nfs_client_rpc_retransmits_total", read)
	require.NotNil(t, retransmits)
	assert.InDelta(t, 2.0, retransmits.GetCounter().GetValue(), 0)

	write := map[string]string{
		"onc_rpc_version":        "3",
		"onc_rpc_procedure_name": "WRITE",
		"nfs_operation_name":     "",
		"server_address":         "192.168.122.34",
		"error_type":             "EJUKEBOX",
	}
	errs := gatheredMetric(t, registry, "obi_stat_nfs_client_rpc_errors_total", write)
	require.NotNil(t, errs)
	assert.InDelta(t, 1.0, errs.GetCounter().GetValue(), 0)
	assert.Nil(t, gatheredMetric(t, registry, "obi_stat_nfs_client_rpc_retransmits_total", map[string]string{
		"onc_rpc_version": "3", "onc_rpc_procedure_name": "WRITE", "nfs_operation_name": "", "server_address": "192.168.122.34",
	}), "no retransmission, no series")
}

// StatNFSClientIO counts one attempt's wire bytes as two series, by
// direction: the kernel counts them together in one key, so neither
// procedure nor version tells them apart by default (section 5).
func TestStatsReporterRecordsNFSClientIOMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := newStatsReporterWithFeatures(t, registry, export.FeatureStorageNFSIo)

	stat := nfsRPCStat(6, 0, 2_000_000, 0)
	stat.NFSRPC.TxBytes, stat.NFSRPC.RxBytes = 180, 4096
	reporter.observeNFSRPC(stat)

	tx := gatheredMetric(t, registry, "obi_stat_nfs_client_io_bytes_total", map[string]string{
		"network_io_direction": "transmit", "server_address": "192.168.122.34",
	})
	require.NotNil(t, tx)
	assert.InDelta(t, 180, tx.GetCounter().GetValue(), 0)

	rx := gatheredMetric(t, registry, "obi_stat_nfs_client_io_bytes_total", map[string]string{
		"network_io_direction": "receive", "server_address": "192.168.122.34",
	})
	require.NotNil(t, rx)
	assert.InDelta(t, 4096, rx.GetCounter().GetValue(), 0)

	// Observing the same stat twice must not have left stat.NFSRPC.Direction
	// mutated for the caller: both directions still read back correctly.
	reporter.observeNFSRPC(stat)
	assert.Equal(t, uint8(0), stat.NFSRPC.Direction, "the caller's stat is never mutated in place")
	tx = gatheredMetric(t, registry, "obi_stat_nfs_client_io_bytes_total", map[string]string{
		"network_io_direction": "transmit", "server_address": "192.168.122.34",
	})
	assert.InDelta(t, 360, tx.GetCounter().GetValue(), 0)
}
