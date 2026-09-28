// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"maps"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const timeout = 5 * time.Second

func TestFilter(t *testing.T) {
	ctx := t.Context()

	registry := prometheus.NewRegistry()
	promServer := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry}))
	t.Cleanup(promServer.Close)

	stats := Stats{
		agentIP: net.ParseIP("1.2.3.4"),
		ctxInfo: &global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		cfg: &obi.Config{
			Prometheus: prom.PrometheusConfig{
				Registry: registry,
				Path:     "/metrics",
				TTL:      time.Hour,
			},
			Metrics: perapp.GlobalMetricsConfig{Features: export.FeatureStatsTCPRtt | export.FeatureStatsTCPFailedConnections | export.FeatureStatsTCPRetransmits | export.FeatureStatsTCPIo | export.FeatureStatsTCPSuccessfulConnections},
			Attributes: obi.Attributes{Select: attributes.Selection{
				attributes.StatTCPRtt.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port"},
				},
				attributes.StatTCPFailedConnections.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port", "reason"},
				},
				attributes.StatTCPSuccessfulConnections.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port", "network_tcp_handshake_role"},
				},
				attributes.StatTCPRetransmits.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port"},
				},
				attributes.StatTCPIo.Section: attributes.InclusionLists{
					Include: []string{"obi_ip", "dst_port", "src_port", "network_io_direction"},
				},
			}},
		},
	}

	ringBuf := make(chan []*ebpf.Stat, 10)
	// override eBPF stat fetchers
	newRingBufTracer = func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
		return func(ctx context.Context) {
			for i := range ringBuf {
				out.SendCtx(ctx, i)
			}
		}
	}

	runner, err := stats.buildPipeline(ctx)
	require.NoError(t, err)

	go runner.Start(ctx)

	ringBuf <- []*ebpf.Stat{
		fakeRecord(123, 456),
		fakeRecord(789, 1011),
		fakeRecord(333, 444),
	}
	ringBuf <- []*ebpf.Stat{
		fakeRecord(1213, 1415),
		fakeRecord(3333, 8080),
	}

	ringBuf <- []*ebpf.Stat{
		fakeFailedConnRecord(555, 666, uint8(ebpf.CodeConnectionRefused)),
		fakeFailedConnRecord(777, 888, uint8(ebpf.CodeTimedOut)),
	}

	ringBuf <- []*ebpf.Stat{
		fakeSuccessfulConnRecord(444, 999, uint8(ebpf.CodeRoleClient)),
	}

	ringBuf <- []*ebpf.Stat{
		fakeRetransmitRecord(777, 888),
	}

	ringBuf <- []*ebpf.Stat{
		fakeIoRecord(100, 200, uint8(ebpf.CodeDirectionTransmit), 1500),
		fakeIoRecord(100, 200, uint8(ebpf.CodeDirectionReceive), 2000),
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		allMetrics, err := promtest.Scrape(promServer.URL)
		require.NoError(ct, err)

		// Filter for only the metrics you want to verify
		var filtered []promtest.ScrapedMetric
		for _, m := range allMetrics {
			switch m.Name {
			case "obi_stat_tcp_rtt_seconds_count",
				"obi_stat_tcp_failed_connections_total",
				"obi_stat_tcp_successful_connections_total",
				"obi_stat_tcp_retransmits_total",
				"obi_stat_tcp_io_bytes_total",
				"promhttp_metric_handler_errors_total":
				// Reset values to 0 if you don't care about the specific count,
				// or keep them if you want to verify the Value: 1 seen in your logs.
				filtered = append(filtered, m)
			}
		}

		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_tcp_rtt_seconds_count", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "1011", "src_port": "789"}},
			{Name: "obi_stat_tcp_rtt_seconds_count", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "1415", "src_port": "1213"}},
			{Name: "obi_stat_tcp_rtt_seconds_count", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "444", "src_port": "333"}},
			{Name: "obi_stat_tcp_rtt_seconds_count", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "456", "src_port": "123"}},
			{Name: "obi_stat_tcp_rtt_seconds_count", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "8080", "src_port": "3333"}},
			{Name: "obi_stat_tcp_failed_connections_total", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "666", "src_port": "555", "reason": "refused"}},
			{Name: "obi_stat_tcp_failed_connections_total", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "888", "src_port": "777", "reason": "timed-out"}},
			{Name: "obi_stat_tcp_successful_connections_total", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "999", "src_port": "444", "network_tcp_handshake_role": "client"}},
			{Name: "obi_stat_tcp_retransmits_total", Value: 1, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "888", "src_port": "777"}},
			{Name: "obi_stat_tcp_io_bytes_total", Value: 1500, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "200", "src_port": "100", "network_io_direction": "transmit"}},
			{Name: "obi_stat_tcp_io_bytes_total", Value: 2000, Labels: map[string]string{"obi_ip": "1.2.3.4", "dst_port": "200", "src_port": "100", "network_io_direction": "receive"}},
			{Name: "promhttp_metric_handler_errors_total", Value: 0, Labels: map[string]string{"cause": "encoding"}},
			{Name: "promhttp_metric_handler_errors_total", Value: 0, Labels: map[string]string{"cause": "gathering"}},
		}, filtered)
	}, timeout, 100*time.Millisecond)
}

func fakeRecord(srcPort, dstPort uint16) *ebpf.Stat {
	return &ebpf.Stat{
		TCPRtt: &ebpf.TCPRtt{
			SrttUs: 100,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeFailedConnRecord(srcPort, dstPort uint16, reason uint8) *ebpf.Stat {
	return &ebpf.Stat{
		TCPFailedConnection: &ebpf.TCPFailedConnection{
			Reason: reason,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeSuccessfulConnRecord(srcPort, dstPort uint16, role uint8) *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeTCPSuccessfulConnection,
		TCPSuccessfulConnection: &ebpf.TCPSuccessfulConnection{
			Role: role,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeRetransmitRecord(srcPort, dstPort uint16) *ebpf.Stat {
	return &ebpf.Stat{
		TCPRetransmit: true,
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func fakeIoRecord(srcPort, dstPort uint16, direction uint8, bytes uint32) *ebpf.Stat {
	return &ebpf.Stat{
		TCPIo: &ebpf.TCPIo{
			Direction: direction,
			Bytes:     bytes,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}
}

func TestDiskStats(t *testing.T) {
	diskEvents, promURL := startDiskPipeline(t, export.FeatureStatsDiskOperationDuration)

	diskEvents <- []*ebpf.Stat{
		fakeDiskRecord("nvme0n1", ebpf.CodeDiskOpWrite, "",
			ebpf.LatencySample{Seconds: 0.0005, Count: 3}, ebpf.LatencySample{Seconds: 0.004, Count: 2}),
		fakeDiskRecord("nvme0n1", ebpf.CodeDiskOpWrite, "EIO",
			ebpf.LatencySample{Seconds: 0.02, Count: 1}),
	}
	diskEvents <- []*ebpf.Stat{
		fakeDiskRecord("nvme0n1", ebpf.CodeDiskOpWrite, "",
			ebpf.LatencySample{Seconds: 0.0005, Count: 1}),
	}

	// the exposition format writes empty labels, which Prometheus treats as absent
	okWrite := map[string]string{"obi_disk_stacked": "false", "system_device": "nvme0n1", "disk_io_direction": "write", "error_type": ""}
	failedWrite := map[string]string{"obi_disk_stacked": "false", "system_device": "nvme0n1", "disk_io_direction": "write", "error_type": "EIO"}
	withLe := func(labels map[string]string, le string) map[string]string {
		out := map[string]string{"le": le}
		maps.Copy(out, labels)
		return out
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		disk := scrapeDiskMetrics(ct, promURL, "obi_stat_disk_operation_duration_seconds")
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_disk_operation_duration_seconds_bucket", Value: 4, Labels: withLe(okWrite, "0.001")},
			{Name: "obi_stat_disk_operation_duration_seconds_bucket", Value: 6, Labels: withLe(okWrite, "0.01")},
			{Name: "obi_stat_disk_operation_duration_seconds_bucket", Value: 6, Labels: withLe(okWrite, "+Inf")},
			{Name: "obi_stat_disk_operation_duration_seconds_count", Value: 6, Labels: okWrite},
			{Name: "obi_stat_disk_operation_duration_seconds_sum", Value: 0.0005*4 + 0.004*2, Labels: okWrite},
			{Name: "obi_stat_disk_operation_duration_seconds_bucket", Value: 0, Labels: withLe(failedWrite, "0.001")},
			{Name: "obi_stat_disk_operation_duration_seconds_bucket", Value: 0, Labels: withLe(failedWrite, "0.01")},
			{Name: "obi_stat_disk_operation_duration_seconds_bucket", Value: 1, Labels: withLe(failedWrite, "+Inf")},
			{Name: "obi_stat_disk_operation_duration_seconds_count", Value: 1, Labels: failedWrite},
			{Name: "obi_stat_disk_operation_duration_seconds_sum", Value: 0.02, Labels: failedWrite},
		}, disk)
	}, timeout, 100*time.Millisecond)
}

func TestDiskCounters(t *testing.T) {
	diskEvents, promURL := startDiskPipeline(t,
		export.FeatureStatsDiskIO|export.FeatureStatsDiskOperations|export.FeatureStatsDiskOperationTime)

	write := fakeDiskRecord("vda", ebpf.CodeDiskOpWrite, "")
	write.DiskIO.Operations, write.DiskIO.Time, write.DiskIO.Bytes = 3, 0.25, 12288
	failedWrite := fakeDiskRecord("vda", ebpf.CodeDiskOpWrite, "EIO")
	failedWrite.DiskIO.Operations, failedWrite.DiskIO.Time = 1, 0.5
	read := fakeDiskRecord("vda", ebpf.CodeDiskOpRead, "")
	read.DiskIO.Operations, read.DiskIO.Time, read.DiskIO.Bytes = 2, 0.125, 8192
	diskEvents <- []*ebpf.Stat{write, failedWrite, read}

	vdaWrite := map[string]string{"obi_disk_stacked": "false", "system_device": "vda", "disk_io_direction": "write"}
	vdaRead := map[string]string{"obi_disk_stacked": "false", "system_device": "vda", "disk_io_direction": "read"}
	withError := func(errorType string) map[string]string {
		out := map[string]string{"error_type": errorType}
		maps.Copy(out, vdaWrite)
		return out
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_disk_io_bytes_total", Value: 12288, Labels: vdaWrite},
			{Name: "obi_stat_disk_io_bytes_total", Value: 8192, Labels: vdaRead},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_disk_io_bytes_total"), "failed requests transfer no bytes")
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_disk_operations_total", Value: 3, Labels: withError("")},
			{Name: "obi_stat_disk_operations_total", Value: 1, Labels: withError("EIO")},
			{Name: "obi_stat_disk_operations_total", Value: 2, Labels: map[string]string{
				"obi_disk_stacked": "false", "system_device": "vda", "disk_io_direction": "read", "error_type": "",
			}},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_disk_operations_total"))
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_disk_operation_time_seconds_total", Value: 0.75, Labels: vdaWrite},
			{Name: "obi_stat_disk_operation_time_seconds_total", Value: 0.125, Labels: vdaRead},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_disk_operation_time_seconds_total"))
	}, timeout, 100*time.Millisecond)
}

func TestDiskOperationsBeyondReadsAndWrites(t *testing.T) {
	diskEvents, promURL := startDiskPipeline(t, export.FeatureStatsDiskOperations|export.FeatureStatsDiskQueueDuration|
		export.FeatureStatsDiskFlush|export.FeatureStatsDiskDiscard|export.FeatureStatsDiskPendingOperations)

	write := fakeDiskRecord("vda", ebpf.CodeDiskOpWrite, "", ebpf.LatencySample{Seconds: 0.004, Count: 2})
	write.DiskIO.Operations = 2
	write.DiskIO.Queue = []ebpf.LatencySample{{Seconds: 0.0005, Count: 2}}
	flush := fakeDiskRecord("vda", ebpf.CodeDiskOpFlush, "", ebpf.LatencySample{Seconds: 0.02, Count: 3})
	flush.DiskIO.Operations = 3
	discard := fakeDiskRecord("vda", ebpf.CodeDiskOpDiscard, "", ebpf.LatencySample{Seconds: 0.004, Count: 1})
	discard.DiskIO.Operations, discard.DiskIO.Bytes = 1, 1<<20
	pending := &ebpf.Stat{Type: ebpf.StatTypeDiskPending, DiskPending: &ebpf.DiskPending{
		Device: "vda", Op: ebpf.CodeDiskOpRead, Requests: 5,
	}}
	lvm := fakeDiskRecord("dm-0", ebpf.CodeDiskOpWrite, "")
	lvm.DiskIO.Operations, lvm.DiskIO.Stacked = 4, true
	diskEvents <- []*ebpf.Stat{write, flush, discard, pending, lvm}

	vdaWrite := map[string]string{"obi_disk_stacked": "false", "system_device": "vda", "disk_io_direction": "write"}
	vda := map[string]string{"obi_disk_stacked": "false", "system_device": "vda", "error_type": ""}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_disk_operations_total", Value: 2, Labels: map[string]string{
				"obi_disk_stacked": "false", "system_device": "vda", "disk_io_direction": "write", "error_type": "",
			}},
			{Name: "obi_stat_disk_operations_total", Value: 4, Labels: map[string]string{
				"obi_disk_stacked": "true", "system_device": "dm-0", "disk_io_direction": "write", "error_type": "",
			}},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_disk_operations_total"), "flushes and discards have their own metrics")
		assert.Contains(ct, scrapeDiskMetrics(ct, promURL, "obi_stat_disk_queue_duration_seconds_count"),
			promtest.ScrapedMetric{Name: "obi_stat_disk_queue_duration_seconds_count", Value: 2, Labels: vdaWrite})
		assert.Contains(ct, scrapeDiskMetrics(ct, promURL, "obi_stat_disk_flush_duration_seconds_count"),
			promtest.ScrapedMetric{Name: "obi_stat_disk_flush_duration_seconds_count", Value: 3, Labels: vda})
		assert.Contains(ct, scrapeDiskMetrics(ct, promURL, "obi_stat_disk_discard_duration_seconds_count"),
			promtest.ScrapedMetric{Name: "obi_stat_disk_discard_duration_seconds_count", Value: 1, Labels: vda})
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_disk_discard_io_bytes_total", Value: 1 << 20, Labels: map[string]string{"obi_disk_stacked": "false", "system_device": "vda"}},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_disk_discard_io_bytes_total"))
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_disk_pending_operations", Value: 5, Labels: map[string]string{"obi_disk_stacked": "false", "system_device": "vda", "disk_io_direction": "read"}},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_disk_pending_operations"))
	}, timeout, 100*time.Millisecond)
}

func TestDiskPendingOperationsOfSeveralStatsInOneSeries(t *testing.T) {
	diskEvents, promURL := startDiskPipeline(t, export.FeatureStatsDiskPendingOperations, func(cfg *obi.Config) {
		cfg.Attributes.Select = attributes.Selection{
			attributes.StatDiskPendingOperations.Section: attributes.InclusionLists{Exclude: []string{"disk.io.direction"}},
		}
	})

	pending := func(op ebpf.DiskOpCode, requests int64) *ebpf.Stat {
		return &ebpf.Stat{Type: ebpf.StatTypeDiskPending, DiskPending: &ebpf.DiskPending{Device: "vda", Op: op, Requests: requests}}
	}
	diskEvents <- []*ebpf.Stat{pending(ebpf.CodeDiskOpRead, 5), pending(ebpf.CodeDiskOpWrite, 3)}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_disk_pending_operations", Value: 8, Labels: map[string]string{"obi_disk_stacked": "false", "system_device": "vda"}},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_disk_pending_operations"), "the reads and writes add up")
	}, timeout, 100*time.Millisecond)
}

func TestFsSyncStats(t *testing.T) {
	diskEvents, promURL := startDiskPipeline(t, export.FeatureStatsFsSyncDuration)

	diskEvents <- []*ebpf.Stat{
		{Type: ebpf.StatTypeFsSync, FsSync: &ebpf.FsSync{
			Type:    ebpf.CodeFsSyncFsync,
			Latency: []ebpf.LatencySample{{Seconds: 0.004, Count: 3}},
		}},
		{Type: ebpf.StatTypeFsSync, FsSync: &ebpf.FsSync{
			Type:      ebpf.CodeFsSyncFdatasync,
			ErrorType: "EIO",
			Latency:   []ebpf.LatencySample{{Seconds: 0.02, Count: 1}},
		}},
	}

	ok := map[string]string{"error_type": "", "obi_fs_sync_type": "fsync"}
	failed := map[string]string{"error_type": "EIO", "obi_fs_sync_type": "fdatasync"}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_fs_sync_duration_seconds_count", Value: 3, Labels: ok},
			{Name: "obi_stat_fs_sync_duration_seconds_count", Value: 1, Labels: failed},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_fs_sync_duration_seconds_count"))
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_fs_sync_duration_seconds_sum", Value: 0.012, Labels: ok},
			{Name: "obi_stat_fs_sync_duration_seconds_sum", Value: 0.02, Labels: failed},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_fs_sync_duration_seconds_sum"))
	}, timeout, 100*time.Millisecond)
}

func TestNFSStats(t *testing.T) {
	diskEvents, promURL := startDiskPipeline(t, export.FeatureStatsNFS)

	diskEvents <- []*ebpf.Stat{
		{Type: ebpf.StatTypeNFSProcedure, NFSProcedure: &ebpf.NFSProcedure{
			Server: "10.0.0.5", Procedure: "READ", Version: 4,
			Latency: []ebpf.LatencySample{{Seconds: 0.004, Count: 3}},
		}},
		{Type: ebpf.StatTypeNFSProcedure, NFSProcedure: &ebpf.NFSProcedure{
			Server: "10.0.0.5", Procedure: "GETATTR", Version: 4, ErrorType: "ESTALE",
			Latency: []ebpf.LatencySample{{Seconds: 0.02, Count: 1}},
		}},
		{Type: ebpf.StatTypeNFSIO, NFSIO: &ebpf.NFSIO{
			Server: "10.0.0.5", Direction: uint8(ebpf.CodeDirectionReceive), Bytes: 1 << 20,
		}},
		{Type: ebpf.StatTypeNFSIO, NFSIO: &ebpf.NFSIO{
			Server: "10.0.0.5", Direction: uint8(ebpf.CodeDirectionTransmit), Bytes: 4096,
		}},
	}

	read := map[string]string{"server_address": "10.0.0.5", "onc_rpc_procedure_name": "READ", "onc_rpc_version": "4", "error_type": ""}
	stale := map[string]string{"server_address": "10.0.0.5", "onc_rpc_procedure_name": "GETATTR", "onc_rpc_version": "4", "error_type": "ESTALE"}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_nfs_client_procedure_duration_seconds_count", Value: 3, Labels: read},
			{Name: "obi_stat_nfs_client_procedure_duration_seconds_count", Value: 1, Labels: stale},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_nfs_client_procedure_duration_seconds_count"))
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_nfs_client_io_bytes_total", Value: 1 << 20, Labels: map[string]string{
				"server_address": "10.0.0.5", "network_io_direction": "receive",
			}},
			{Name: "obi_stat_nfs_client_io_bytes_total", Value: 4096, Labels: map[string]string{
				"server_address": "10.0.0.5", "network_io_direction": "transmit",
			}},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_nfs_client_io_bytes_total"))
	}, timeout, 100*time.Millisecond)
}

func TestPodVolumeStats(t *testing.T) {
	volumes := make(chan []*ebpf.Stat, 10)
	defaultPodVolumesTracer := newPodVolumesTracer
	t.Cleanup(func() { newPodVolumesTracer = defaultPodVolumesTracer })
	newPodVolumesTracer = func(_ context.Context, _ *Stats, out *msg.Queue[[]*ebpf.Stat]) (swarm.RunFunc, error) {
		return func(ctx context.Context) {
			defer out.MarkCloseable()
			for i := range volumes {
				out.SendCtx(ctx, i)
			}
		}, nil
	}
	_, promURL := startDiskPipeline(t, export.FeatureStatsDiskPodVolumes)

	volume := ebpf.PodVolume{
		Namespace: "default", PodName: "db-0", OwnerName: "db", OwnerKind: "StatefulSet",
		VolumeName: "data", ClaimName: "data-db-0", PersistentVolume: "pvc-5d1c",
		MountedDevice: "dm-0", Device: "sda", Value: 1,
	}
	volumes <- []*ebpf.Stat{{Type: ebpf.StatTypePodVolume, PodVolume: &volume}}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_k8s_pod_volume_device", Value: 1, Labels: map[string]string{
				"k8s_volume_name":                "data",
				"k8s_volume_type":                "persistentVolumeClaim",
				"k8s_persistentvolumeclaim_name": "data-db-0",
				"k8s_persistentvolume_name":      "pvc-5d1c",
				"obi_disk_volume_device":         "dm-0",
				"system_device":                  "sda",
			}},
		}, scrapeDiskMetrics(ct, promURL, "obi_stat_k8s_pod_volume_device"))
	}, timeout, 100*time.Millisecond)
}

// startDiskPipeline runs the stats pipeline with the given disk features, exporting to
// Prometheus. It returns the channel to send disk stats through and the Prometheus URL.
func startDiskPipeline(t *testing.T, features export.Features, configure ...func(*obi.Config)) (chan<- []*ebpf.Stat, string) {
	registry := prometheus.NewRegistry()
	promServer := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry}))
	t.Cleanup(promServer.Close)

	stats := Stats{
		agentIP: net.ParseIP("1.2.3.4"),
		ctxInfo: &global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		cfg: &obi.Config{
			Prometheus: prom.PrometheusConfig{
				Registry: registry,
				Path:     "/metrics",
				TTL:      time.Hour,
				Buckets: export.Buckets{
					StatDiskOperationDurationHistogram:      []float64{0.001, 0.01},
					StatFsSyncDurationHistogram:             []float64{0.001, 0.01},
					StatNFSClientProcedureDurationHistogram: []float64{0.001, 0.01},
				},
			},
			Metrics: perapp.GlobalMetricsConfig{Features: features},
		},
	}

	for _, c := range configure {
		c(stats.cfg)
	}

	diskEvents := make(chan []*ebpf.Stat, 10)
	defaultDiskTracer := newDiskTracer
	t.Cleanup(func() { newDiskTracer = defaultDiskTracer })
	newDiskTracer = func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
		return func(ctx context.Context) {
			defer out.MarkCloseable()
			for i := range diskEvents {
				out.SendCtx(ctx, i)
			}
		}
	}
	ringBuf := make(chan []*ebpf.Stat)
	t.Cleanup(func() { close(ringBuf) })
	newRingBufTracer = func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
		return func(ctx context.Context) {
			defer out.MarkCloseable()
			for i := range ringBuf {
				out.SendCtx(ctx, i)
			}
		}
	}

	runner, err := stats.buildPipeline(t.Context())
	require.NoError(t, err)
	go runner.Start(t.Context())
	return diskEvents, promServer.URL
}

func scrapeDiskMetrics(ct *assert.CollectT, promURL, namePrefix string) []promtest.ScrapedMetric {
	allMetrics, err := promtest.Scrape(promURL)
	require.NoError(ct, err)
	var disk []promtest.ScrapedMetric
	for _, m := range allMetrics {
		if strings.HasPrefix(m.Name, namePrefix) {
			disk = append(disk, m)
		}
	}
	return disk
}

func fakeDiskRecord(device string, op ebpf.DiskOpCode, errorType string, latency ...ebpf.LatencySample) *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeDiskIO,
		DiskIO: &ebpf.DiskIO{
			Device:    device,
			Op:        op,
			ErrorType: errorType,
			Latency:   latency,
		},
	}
}
