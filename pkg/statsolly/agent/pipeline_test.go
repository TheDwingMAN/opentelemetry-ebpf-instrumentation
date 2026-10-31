// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	statstracers "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const timeout = 5 * time.Second

func TestFilter(t *testing.T) {
	ctx := t.Context()

	promServer := testutil.NewPrometheusServer(t)

	stats := Stats{
		agentIP: net.ParseIP("1.2.3.4"),
		ctxInfo: &global.ContextInfo{
			Prometheus: promServer.Manager,
		},
		cfg: &obi.Config{
			Prometheus: prom.PrometheusConfig{
				Port: promServer.Port,
				Path: "/metrics",
				TTL:  time.Hour,
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

// The disk stats get the OBI IP, go through the stats filters and are exported. The paths of a
// dm-multipath device have the counters, but not the histograms. The cache flushes are only in
// their own histogram.
func TestDiskStats(t *testing.T) {
	disk, promURL := startDiskPipeline(t, func(s *Stats) {
		s.cfg.Attributes.Select = attributes.Selection{"obi.stat.disk.*": attributes.InclusionLists{Include: []string{"*"}}}
		s.cfg.Filters.Stats = filter.AttributeFamilyConfig{"system.device": {NotMatch: "vda"}}
	})

	disk <- []*ebpf.Stat{fakeDiskRecord("nvme0n1", 5), fakeDiskRecord("vda", 1)}
	disk <- []*ebpf.Stat{fakeDiskRecord("nvme0n1", 1)}
	failed := fakeDiskRecord("nvme0n1", 2)
	failed.DiskIO.ErrorType, failed.DiskIO.Bytes = "EIO", 0
	path := fakeDiskRecord("sdb", 3)
	path.DiskIO.MultipathPath = true
	flush, pathFlush := fakeDiskRecord("nvme0n1", 4), fakeDiskRecord("sdb", 1)
	flush.DiskIO.Op, pathFlush.DiskIO.Op, pathFlush.DiskIO.MultipathPath = ebpf.CodeDiskOpFlush, ebpf.CodeDiskOpFlush, true
	disk <- []*ebpf.Stat{failed, path, flush, pathFlush}

	labels := func(device, errorType string) map[string]string {
		return map[string]string{
			"obi_ip": "1.2.3.4", "system_device": device, "obi_disk_stacked": "false", "obi_disk_volume_name": "",
			"disk_io_direction": "write", "error_type": errorType, "container_id": "",
		}
	}
	ioLabels := func(device string) map[string]string {
		labels := labels(device, "")
		delete(labels, "error_type")
		return labels
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		allMetrics, err := promtest.Scrape(promURL)
		require.NoError(ct, err)
		named := func(name string) []promtest.ScrapedMetric {
			return slices.DeleteFunc(slices.Clone(allMetrics), func(m promtest.ScrapedMetric) bool { return m.Name != name })
		}
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_disk_service_duration_seconds_count", Value: 6, Labels: labels("nvme0n1", "")},
			{Name: "obi_stat_disk_service_duration_seconds_count", Value: 2, Labels: labels("nvme0n1", "EIO")},
		}, named("obi_stat_disk_service_duration_seconds_count"))
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_disk_operations_total", Value: 6, Labels: labels("nvme0n1", "")},
			{Name: "obi_stat_disk_operations_total", Value: 2, Labels: labels("nvme0n1", "EIO")},
			{Name: "obi_stat_disk_operations_total", Value: 3, Labels: labels("sdb", "")},
		}, named("obi_stat_disk_operations_total"))
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_disk_io_bytes_total", Value: 6 * 4096, Labels: ioLabels("nvme0n1")},
			{Name: "obi_stat_disk_io_bytes_total", Value: 3 * 4096, Labels: ioLabels("sdb")},
		}, named("obi_stat_disk_io_bytes_total"))
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{{
			Name: "obi_stat_disk_flush_duration_seconds_count", Value: 4, Labels: map[string]string{
				"obi_ip": "1.2.3.4", "system_device": "nvme0n1", "obi_disk_stacked": "false", "obi_disk_volume_name": "", "error_type": "",
				"container_id": "",
			},
		}}, named("obi_stat_disk_flush_duration_seconds_count"))
	}, timeout, 100*time.Millisecond)
}

// The NFS client stats are exported with their server, and their procedure under the attribute of
// their NFS version: the histogram those of the node, and the counters those of the workloads
func TestNFSStats(t *testing.T) {
	rpcs, promURL := startDiskPipeline(t, func(s *Stats) {
		s.cfg.Metrics.Features = export.FeatureStatsNFS
		s.cfg.Attributes.Select = attributes.Selection{
			"obi_stat_nfs_client_procedure_count_total":   attributes.InclusionLists{Include: []string{"*"}},
			attributes.StatNFSClientProcedureTime.Section: attributes.InclusionLists{Include: []string{"*"}},
		}
		s.cfg.Attributes.Select.Normalize()
	})
	lookup := fakeNFSRecord("LOOKUP", 3, 1)
	lookup.NFSProcedure.ErrorType = "ENOENT"
	commit := &ebpf.Stat{Type: ebpf.StatTypeNFSProcedureCgroup, NFSProcedure: &ebpf.NFSProcedure{
		Server: "nas", Procedure: "COMMIT", Version: 4, ContainerID: "0123abcd", Count: 2, Time: 0.5,
	}}
	written := &ebpf.Stat{Type: ebpf.StatTypeNFSIO, NFSIO: &ebpf.NFSIO{
		Server: "nas", Direction: ebpf.CodeDirectionTransmit, ContainerID: "0123abcd", Bytes: 65536,
	}}
	rpcs <- []*ebpf.Stat{fakeNFSRecord("WRITE", 4, 2), lookup, commit, written}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		allMetrics, err := promtest.Scrape(promURL)
		require.NoError(ct, err)
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_nfs_client_procedure_duration_seconds_count", Value: 2, Labels: map[string]string{
				"server_address": "nas", "nfs_operation_name": "WRITE", "onc_rpc_procedure_name": "", "onc_rpc_version": "4", "error_type": "",
			}},
			{Name: "obi_stat_nfs_client_procedure_duration_seconds_count", Value: 1, Labels: map[string]string{
				"server_address": "nas", "nfs_operation_name": "", "onc_rpc_procedure_name": "LOOKUP", "onc_rpc_version": "3", "error_type": "ENOENT",
			}},
		}, slices.DeleteFunc(slices.Clone(allMetrics), func(m promtest.ScrapedMetric) bool {
			return m.Name != "obi_stat_nfs_client_procedure_duration_seconds_count"
		}))
		labels := map[string]string{
			"server_address": "nas", "nfs_operation_name": "COMMIT", "onc_rpc_procedure_name": "", "onc_rpc_version": "4", "error_type": "",
			"obi_ip": "1.2.3.4", "container_id": "0123abcd",
		}
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{Name: "obi_stat_nfs_client_procedure_count_total", Value: 2, Labels: labels},
			{Name: "obi_stat_nfs_client_procedure_time_seconds_total", Value: 0.5, Labels: labels},
		}, slices.DeleteFunc(slices.Clone(allMetrics), func(m promtest.ScrapedMetric) bool {
			return !strings.HasPrefix(m.Name, "obi_stat_nfs_client_procedure_count") && !strings.HasPrefix(m.Name, "obi_stat_nfs_client_procedure_time")
		}))
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{{
			Name: "obi_stat_nfs_client_io_bytes_total", Value: 65536,
			Labels: map[string]string{"server_address": "nas", "network_io_direction": "transmit"},
		}}, slices.DeleteFunc(allMetrics, func(m promtest.ScrapedMetric) bool { return m.Name != "obi_stat_nfs_client_io_bytes_total" }))
	}, timeout, 100*time.Millisecond)
}

// Under dynamic application selection, the disk stats are those of the containers of the selected
// applications: none while nothing is selected
func TestFsSyncStats(t *testing.T) {
	syncs, promURL := startDiskPipeline(t, func(s *Stats) { s.cfg.Metrics.Features = export.FeatureStatsFsSync })
	failed := fakeFsSyncRecord(ebpf.CodeFsSyncFdatasync, 1)
	failed.FsSync.ErrorType = "EIO"
	syncs <- []*ebpf.Stat{fakeFsSyncRecord(ebpf.CodeFsSyncFsync, 3), failed}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		allMetrics, err := promtest.Scrape(promURL)
		require.NoError(ct, err)
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{
				Name: "obi_stat_fs_sync_duration_seconds_count", Value: 3,
				Labels: map[string]string{"obi_fs_sync_type": "fsync", "error_type": ""},
			},
			{
				Name: "obi_stat_fs_sync_duration_seconds_count", Value: 1,
				Labels: map[string]string{"obi_fs_sync_type": "fdatasync", "error_type": "EIO"},
			},
		}, slices.DeleteFunc(slices.Clone(allMetrics), func(m promtest.ScrapedMetric) bool {
			return m.Name != "obi_stat_fs_sync_duration_seconds_count"
		}))
		assert.ElementsMatch(ct, []promtest.ScrapedMetric{
			{
				Name: "obi_stat_fs_sync_operations_total", Value: 3,
				Labels: map[string]string{"obi_fs_sync_type": "fsync", "error_type": ""},
			},
			{
				Name: "obi_stat_fs_sync_operations_total", Value: 1,
				Labels: map[string]string{"obi_fs_sync_type": "fdatasync", "error_type": "EIO"},
			},
		}, slices.DeleteFunc(allMetrics, func(m promtest.ScrapedMetric) bool {
			return m.Name != "obi_stat_fs_sync_operations_total"
		}))
	}, timeout, 100*time.Millisecond)
}

func TestDiskStatsUnderDynamicSelection(t *testing.T) {
	disk, promURL := startDiskPipeline(t, func(s *Stats) {
		s.ctxInfo.DynamicSelector = discover.NewDynamicSelector()
		s.cfg.Metrics.Features = export.FeatureStatsDisk | export.FeatureStatsFsSync | export.FeatureStatsNFS
	})
	inContainer := fakeDiskRecord("vda", 1)
	inContainer.DiskIO.ContainerID = "0123abcd"
	syncInContainer := fakeFsSyncRecord(ebpf.CodeFsSyncFsync, 1)
	syncInContainer.FsSync.ContainerID = "0123abcd"
	disk <- []*ebpf.Stat{inContainer, fakeDiskRecord("vda", 1), syncInContainer, fakeNFSRecord("READ", 4, 1)}

	assert.Never(t, func() bool {
		allMetrics, err := promtest.Scrape(promURL)
		return err == nil && slices.ContainsFunc(allMetrics, func(m promtest.ScrapedMetric) bool {
			return strings.HasPrefix(m.Name, "obi_stat_")
		})
	}, time.Second, 100*time.Millisecond)
}

// The storage stats are selected and decorated by the container that the kernel charged them to
func TestStorageContainerID(t *testing.T) {
	for want, stat := range map[string]*ebpf.Stat{
		"disk": {Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{ContainerID: "disk"}},
		"sync": {Type: ebpf.StatTypeFsSync, FsSync: &ebpf.FsSync{ContainerID: "sync"}},
		"rpcs": {Type: ebpf.StatTypeNFSProcedureCgroup, NFSProcedure: &ebpf.NFSProcedure{ContainerID: "rpcs"}},
		"io":   {Type: ebpf.StatTypeNFSIO, NFSIO: &ebpf.NFSIO{ContainerID: "io"}},
		"":     fakeNFSRecord("READ", 4, 1),
	} {
		assert.Equal(t, want, storageContainerID(stat))
	}
}

// The warning about the cache flushes under dynamic application selection names the bio-based devices
// only when their flushes are measured
func TestFlushesUnderDynamicSelection(t *testing.T) {
	assert.NotContains(t, flushesUnderDynamicSelection(false), "bio-based devices")
	assert.Contains(t, flushesUnderDynamicSelection(true), "bio-based devices")
}

// The features whose probes are loaded leave out, with a warning each, the NFS histogram under
// dynamic application selection and the bio-based devices without a disk metric
func TestProbedFeatures(t *testing.T) {
	disk, bio := export.FeatureStatsDiskOperations, export.FeatureStatsDiskBioDevices
	for _, tc := range []struct {
		name             string
		features         export.Features
		dynamicSelection bool
		want             export.Features
		warnings         int
	}{
		{name: "the metrics", features: disk | export.FeatureStatsNFS, want: disk | export.FeatureStatsNFS},
		{name: "the NFS histogram under dynamic selection", features: export.FeatureStatsNFS, dynamicSelection: true, want: export.FeatureStatsNFSClientWorkloads, warnings: 1},
		{name: "the bio devices with a metric", features: disk | bio, want: disk | bio},
		{name: "the bio devices alone", features: bio | export.FeatureStatsFsSync, want: export.FeatureStatsFsSync, warnings: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log strings.Builder
			got := probedFeatures(slog.New(slog.NewTextHandler(&log, nil)), tc.features, tc.dynamicSelection)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.warnings, strings.Count(log.String(), "level=WARN"), log.String())
		})
	}
}

// The NFS client probes are attached on each refresh until they no longer wait for their modules
func TestRefreshNFSProbesUntilNoneWaits(t *testing.T) {
	const waitingRefreshes = 3
	refreshes := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		refreshNFSProbes(t.Context(), func() bool {
			refreshes++
			return refreshes < waitingRefreshes
		}, time.Millisecond)
	}()

	select {
	case <-done:
		assert.Equal(t, waitingRefreshes, refreshes)
	case <-time.After(timeout):
		t.Fatal("the refreshes didn't stop once the probe no longer waits")
	}
}

// startDiskPipeline runs the stats pipeline of the disk stats, as configure changes it, exporting to
// Prometheus. The disk tracer forwards what the returned channel gets.
func startDiskPipeline(t *testing.T, configure func(*Stats)) (chan<- []*ebpf.Stat, string) {
	promServer := testutil.NewPrometheusServer(t)

	stats := Stats{
		agentIP: net.ParseIP("1.2.3.4"),
		ctxInfo: &global.ContextInfo{
			Prometheus: promServer.Manager,
		},
		cfg: &obi.Config{
			Prometheus: prom.PrometheusConfig{Port: promServer.Port, Path: "/metrics", TTL: time.Hour},
			Metrics:    perapp.GlobalMetricsConfig{Features: export.FeatureStatsDisk},
		},
		diskTracer: &statstracers.DiskMapTracer{},
	}
	configure(&stats)

	ringBuf := make(chan []*ebpf.Stat)
	disk := make(chan []*ebpf.Stat, 10)
	defaultRingBufTracer, defaultDiskTracer := newRingBufTracer, newDiskTracer
	t.Cleanup(func() {
		newRingBufTracer, newDiskTracer = defaultRingBufTracer, defaultDiskTracer
		close(ringBuf)
		close(disk)
	})
	tracer := func(events chan []*ebpf.Stat) func(*Stats, *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
		return func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
			return func(ctx context.Context) {
				defer out.MarkCloseable()
				for i := range events {
					out.SendCtx(ctx, i)
				}
			}
		}
	}
	newRingBufTracer, newDiskTracer = tracer(ringBuf), tracer(disk)

	runner, err := stats.buildPipeline(t.Context())
	require.NoError(t, err)
	go runner.Start(t.Context())
	return disk, promServer.URL
}

func fakeDiskRecord(device string, writes uint64) *ebpf.Stat {
	latency := ebpf.LatencyHistogram{BucketCounts: make([]uint64, len(export.DiskLatencyBounds)+1)}
	latency.BucketCounts[0] = writes
	return &ebpf.Stat{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{
		Device: device, Op: ebpf.CodeDiskOpWrite, Latency: latency, Bytes: writes * 4096,
	}}
}

func fakeNFSRecord(procedure string, version uint32, rpcs uint64) *ebpf.Stat {
	latency := ebpf.LatencyHistogram{BucketCounts: make([]uint64, len(export.DiskLatencyBounds)+1)}
	latency.BucketCounts[0] = rpcs
	return &ebpf.Stat{Type: ebpf.StatTypeNFSProcedure, NFSProcedure: &ebpf.NFSProcedure{
		Server: "nas", Procedure: procedure, Version: version, Latency: latency,
	}}
}

func fakeFsSyncRecord(syncType ebpf.FsSyncTypeCode, syncs uint64) *ebpf.Stat {
	latency := ebpf.LatencyHistogram{BucketCounts: make([]uint64, len(export.DiskLatencyBounds)+1)}
	latency.BucketCounts[0] = syncs
	return &ebpf.Stat{Type: ebpf.StatTypeFsSync, FsSync: &ebpf.FsSync{Type: syncType, Latency: latency}}
}
