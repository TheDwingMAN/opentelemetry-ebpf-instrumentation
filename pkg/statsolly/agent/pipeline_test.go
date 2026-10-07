// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"net"
	"net/http/httptest"
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

func TestIsStorageStat(t *testing.T) {
	assert.True(t, isStorageStat(&ebpf.Stat{Type: ebpf.StatTypeBlockIo}))
	assert.True(t, isStorageStat(&ebpf.Stat{Type: ebpf.StatTypeFsIo}))
	assert.True(t, isStorageStat(&ebpf.Stat{Type: ebpf.StatTypeNFSRPC}))
	assert.False(t, isStorageStat(&ebpf.Stat{Type: ebpf.StatTypeTCPRtt}))
}

func TestFsIoPIDCarriesTheMount(t *testing.T) {
	pidNs, hostPID, mount, ok := fsIoPID(&ebpf.Stat{Type: ebpf.StatTypeFsIo, FsIo: &ebpf.FsIo{PidNs: 7, HostPID: 42, SDev: 77, RootIno: 1234}})
	assert.True(t, ok)
	assert.Equal(t, uint32(7), pidNs)
	assert.Equal(t, uint32(42), hostPID)
	assert.Equal(t, ebpf.MountKey{Dev: 77, RootIno: 1234}, mount)

	_, _, _, ok = fsIoPID(&ebpf.Stat{Type: ebpf.StatTypeBlockIo})
	assert.False(t, ok)
}

func TestFsMountpointsAreOptIn(t *testing.T) {
	for _, tc := range []struct {
		name          string
		features      export.Features
		kube          bool
		include       []string
		host, cont    bool
		includeMetric attributes.Name
	}{
		{name: "default", features: export.FeatureStorageFS, kube: true},
		{
			name: "host selected", features: export.FeatureStorageFS, kube: true,
			include: []string{"system_filesystem_mountpoint"}, host: true, includeMetric: attributes.StatFsIO,
		},
		{
			name: "both selected on another fs metric", features: export.FeatureStorageFS, kube: true,
			include: []string{"system_filesystem_mountpoint", "obi_fs_container_mountpoint"},
			host:    true, cont: true, includeMetric: attributes.StatFsOperationDuration,
		},
		{
			name: "selected without kubernetes", features: export.FeatureStorageFS,
			include: []string{"system_filesystem_mountpoint"}, includeMetric: attributes.StatFsIO,
		},
		{
			name: "selected without the fs feature", features: export.FeatureStorageBlock, kube: true,
			include: []string{"system_filesystem_mountpoint"}, includeMetric: attributes.StatFsIO,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groups := attributes.UndefinedGroup
			if tc.kube {
				groups.Add(attributes.GroupKubernetes)
			}
			cfg := &obi.Config{Metrics: perapp.GlobalMetricsConfig{Features: tc.features}}
			if tc.include != nil {
				cfg.Attributes.Select = attributes.Selection{
					tc.includeMetric.Section: attributes.InclusionLists{Include: tc.include},
				}
				cfg.Attributes.Select.Normalize()
			}
			s := Stats{ctxInfo: &global.ContextInfo{MetricAttributeGroups: groups}, cfg: cfg}

			mp := s.fsMountpoints(&attributes.SelectorConfig{SelectionCfg: cfg.Attributes.Select})

			assert.Equal(t, tc.host, mp.Host)
			assert.Equal(t, tc.cont, mp.ContainerPath != nil)
		})
	}
}
