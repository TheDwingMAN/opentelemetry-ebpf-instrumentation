// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"maps"
	"net"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/selection"
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
		fakeDiskRecord("nvme0n1", ebpf.CodeDiskOpWrite, "", fakeLatency(0.0005, 0.0005, 0.0005, 0.004, 0.004)),
		fakeDiskRecord("nvme0n1", ebpf.CodeDiskOpWrite, "EIO", fakeLatency(0.02)),
	}
	diskEvents <- []*ebpf.Stat{
		fakeDiskRecord("nvme0n1", ebpf.CodeDiskOpWrite, "", fakeLatency(0.0005)),
	}

	// the exposition format writes empty labels, which Prometheus treats as absent
	okWrite := map[string]string{
		"obi_disk_stacked": "false", "obi_disk_volume_name": "", "system_device": "nvme0n1", "disk_io_direction": "write", "error_type": "",
	}
	failedWrite := map[string]string{
		"obi_disk_stacked": "false", "obi_disk_volume_name": "", "system_device": "nvme0n1", "disk_io_direction": "write", "error_type": "EIO",
	}
	withLe := func(labels map[string]string, le string) map[string]string {
		out := map[string]string{"le": le}
		maps.Copy(out, labels)
		return out
	}

	// the histograms have a bucket per bound of export.DiskLatencyBounds: these are some of them
	someBuckets := func(disk []promtest.ScrapedMetric) []promtest.ScrapedMetric {
		return slices.DeleteFunc(disk, func(m promtest.ScrapedMetric) bool {
			return strings.HasSuffix(m.Name, "_bucket") && !slices.Contains([]string{"0.001", "0.01", "+Inf"}, m.Labels["le"])
		})
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		disk := someBuckets(scrapeDiskMetrics(ct, promURL, "obi_stat_disk_operation_duration_seconds"))
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

// The disk probes couldn't be loaded: the agent has no disk tracer, and the TCP stats go on
func TestDiskStatsWithoutDiskProbes(t *testing.T) {
	registry := prometheus.NewRegistry()
	promServer := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry}))
	t.Cleanup(promServer.Close)

	stats := Stats{
		agentIP: net.ParseIP("1.2.3.4"),
		ctxInfo: &global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		cfg: &obi.Config{
			Prometheus: prom.PrometheusConfig{Registry: registry, Path: "/metrics", TTL: time.Hour},
			Metrics:    perapp.GlobalMetricsConfig{Features: export.FeatureStatsTCPRtt | export.FeatureStatsDiskOperationDuration},
		},
	}

	ringBuf := make(chan []*ebpf.Stat, 1)
	defaultRingBufTracer := newRingBufTracer
	t.Cleanup(func() {
		newRingBufTracer = defaultRingBufTracer
		close(ringBuf)
	})
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

	ringBuf <- []*ebpf.Stat{fakeRecord(123, 456)}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		allMetrics, err := promtest.Scrape(promServer.URL)
		require.NoError(ct, err)
		var rtt []promtest.ScrapedMetric
		for _, m := range allMetrics {
			if m.Name == "obi_stat_tcp_rtt_seconds_count" {
				rtt = append(rtt, m)
			}
		}
		assert.Len(ct, rtt, 1)
	}, timeout, 100*time.Millisecond)
}

// Under dynamic application selection, the storage stats are skipped: their branch of the pipeline is
// not built
func TestStorageStatsUnderDynamicSelection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selector selection.MultiSignalPIDSelector
		storage  bool
	}{
		{name: "without dynamic selection", storage: true},
		{name: "with dynamic selection", selector: discover.NewDynamicSelector()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats := Stats{
				agentIP: net.ParseIP("1.2.3.4"),
				ctxInfo: &global.ContextInfo{
					Prometheus:      &connector.PrometheusManager{},
					DynamicSelector: tc.selector,
				},
				cfg: &obi.Config{
					Prometheus: prom.PrometheusConfig{Registry: prometheus.NewRegistry(), Path: "/metrics", TTL: time.Hour},
					Metrics:    perapp.GlobalMetricsConfig{Features: export.FeatureStatsTCPRtt | export.FeatureStatsDiskOperationDuration},
				},
			}

			var diskTracerAdded bool
			defaultDiskTracer := newDiskTracer
			defaultRingBufTracer := newRingBufTracer
			t.Cleanup(func() {
				newDiskTracer = defaultDiskTracer
				newRingBufTracer = defaultRingBufTracer
			})
			newDiskTracer = func(s *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
				diskTracerAdded = true
				return defaultDiskTracer(s, out)
			}
			newRingBufTracer = func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
				return func(_ context.Context) { out.MarkCloseable() }
			}

			_, err := stats.buildPipeline(t.Context())
			require.NoError(t, err)
			assert.Equal(t, tc.storage, diskTracerAdded)
		})
	}
}

// startDiskPipeline runs the stats pipeline with the given disk features, exporting to
// Prometheus. It returns the channel to send disk stats through and the Prometheus URL.
func startDiskPipeline(t *testing.T, features export.Features, configure ...func(*Stats)) (chan<- []*ebpf.Stat, string) {
	_, diskEvents, promURL := startStatsPipeline(t, features, configure...)
	return diskEvents, promURL
}

// startStatsPipeline runs the stats pipeline with the given features, exporting to Prometheus. It
// returns the channels to send TCP and disk stats through, and the Prometheus URL.
func startStatsPipeline(t *testing.T, features export.Features, configure ...func(*Stats)) (ringBufEvents, diskEvents chan<- []*ebpf.Stat, promURL string) {
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
			Metrics: perapp.GlobalMetricsConfig{Features: features},
		},
	}

	for _, c := range configure {
		c(&stats)
	}

	disk := make(chan []*ebpf.Stat, 10)
	defaultDiskTracer := newDiskTracer
	t.Cleanup(func() {
		newDiskTracer = defaultDiskTracer
		close(disk)
	})
	newDiskTracer = func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
		return func(ctx context.Context) {
			defer out.MarkCloseable()
			for i := range disk {
				out.SendCtx(ctx, i)
			}
		}
	}
	ringBuf := make(chan []*ebpf.Stat, 10)
	defaultRingBufTracer := newRingBufTracer
	t.Cleanup(func() {
		newRingBufTracer = defaultRingBufTracer
		close(ringBuf)
	})
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
	return ringBuf, disk, promServer.URL
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

// fakeLatency is the latency histogram of requests that took the given latencies, in seconds
func fakeLatency(latencies ...float64) *ebpf.LatencyHistogram {
	latency := &ebpf.LatencyHistogram{BucketCounts: make([]uint64, len(export.DiskLatencyBounds)+1)}
	for _, seconds := range latencies {
		// the bucket of the first bound that the latency doesn't exceed
		latency.BucketCounts[sort.SearchFloat64s(export.DiskLatencyBounds, seconds)]++
		latency.Sum += seconds
	}
	return latency
}

func fakeDiskRecord(device string, op ebpf.DiskOpCode, errorType string, latency *ebpf.LatencyHistogram) *ebpf.Stat {
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

// The TCP stats are matched against every filter but those on the attributes that the storage stat
// metrics have and the TCP stat metrics don't, and the filters of each family don't drop the stats
// of the other
func TestStatFiltersOfBothFamilies(t *testing.T) {
	ringBuf, diskEvents, promURL := startStatsPipeline(t,
		export.FeatureStatsTCPRtt|export.FeatureStatsTCPFailedConnections|export.FeatureStatsDiskOperationDuration,
		func(s *Stats) {
			s.cfg.Filters.Stats = filter.AttributeFamilyConfig{
				"reason":        {NotMatch: "unknown"},
				"system.device": {Match: "sda"},
			}
		})

	ringBuf <- []*ebpf.Stat{
		{Type: ebpf.StatTypeTCPRtt, TCPRtt: &ebpf.TCPRtt{SrttUs: 100}},
		{Type: ebpf.StatTypeTCPFailedConnection, TCPFailedConnection: &ebpf.TCPFailedConnection{Reason: uint8(ebpf.CodeConnectionRefused)}},
	}
	diskEvents <- []*ebpf.Stat{
		fakeDiskRecord("sda", ebpf.CodeDiskOpRead, "", fakeLatency(0.0005)),
		fakeDiskRecord("vda", ebpf.CodeDiskOpRead, "", fakeLatency(0.0005)),
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// the RTT stats have no reason, so a filter on it drops them
		assert.Empty(ct, scrapeDiskMetrics(ct, promURL, "obi_stat_tcp_rtt"))
		assert.Len(ct, scrapeDiskMetrics(ct, promURL, "obi_stat_tcp_failed_connections_total"), 1)
		operations := scrapeDiskMetrics(ct, promURL, "obi_stat_disk_operation_duration_seconds_count")
		if assert.Len(ct, operations, 1) {
			assert.Equal(ct, "sda", operations[0].Labels["system_device"])
		}
	}, timeout, 100*time.Millisecond)
}
