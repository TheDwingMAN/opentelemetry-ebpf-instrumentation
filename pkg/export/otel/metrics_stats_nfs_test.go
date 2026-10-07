// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// An NFSv4 RPC is named by its operation and carries no ONC RPC procedure
// name, which OTLP leaves out rather than send empty; the errors counter
// carries the error status, the histogram does not.
func TestStatMetricsExporter_NFSMetrics(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	stats := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	cfg := &otelcfg.MetricsConfig{
		Interval:        50 * time.Millisecond,
		CommonEndpoint:  otlp.ServerEndpoint,
		MetricsProtocol: otelcfg.ProtocolHTTPProtobuf,
		TTL:             3 * time.Minute,
		Buckets:         export.DefaultBuckets,
	}
	otelExporter, err := StatMetricsExporterProvider(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		&StatMetricsConfig{
			Metrics:     cfg,
			SelectorCfg: &attributes.SelectorConfig{},
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStorageNFS},
		}, stats)(ctx)
	require.NoError(t, err)
	go otelExporter(ctx)

	stats.Send([]*ebpf.Stat{{Type: ebpf.StatTypeNFSRPC, NFSRPC: &ebpf.NFSRPC{
		Version: 4, StatIdx: 2, Status: -10008, Family: 2, Addr: [16]byte{192, 168, 122, 34},
		ExecuteNs: 3_000_000,
	}}})

	seen := map[string]collector.MetricRecord{}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for drained := false; !drained; {
			select {
			case rec := <-otlp.Records():
				if _, ok := seen[rec.Name]; !ok {
					seen[rec.Name] = rec
				}
			default:
				drained = true
			}
		}
		assert.Contains(ct, seen, "obi.stat.nfs.client.rpc.duration")
		assert.Contains(ct, seen, "obi.stat.nfs.client.rpc.errors")
	}, timeout, 100*time.Millisecond)
	assert.NotContains(t, seen, "obi.stat.nfs.client.rpc.retransmits", "no retransmission, no series")

	duration := seen["obi.stat.nfs.client.rpc.duration"]
	assert.Equal(t, 1, duration.Count)
	assert.InEpsilon(t, 0.003, duration.FloatVal, 0.0001)
	assert.Equal(t, "4", duration.Attributes["onc_rpc.version"])
	assert.Equal(t, "192.168.122.34", duration.Attributes["server.address"])
	assert.Contains(t, duration.Attributes, "nfs.operation.name")
	assert.NotContains(t, duration.Attributes, "onc_rpc.procedure.name")
	assert.NotContains(t, duration.Attributes, "error.type")

	errs := seen["obi.stat.nfs.client.rpc.errors"]
	assert.Equal(t, int64(1), errs.IntVal)
	assert.Equal(t, "NFS4ERR_DELAY", errs.Attributes["error.type"])
}

// StatNFSClientIO counts one attempt's wire bytes as two series, by
// direction: the kernel counts them together in one key, so neither
// procedure nor version tells them apart by default (section 5).
func TestStatMetricsExporter_NFSClientIOMetrics(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	ctx := t.Context()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	stats := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	cfg := &otelcfg.MetricsConfig{
		Interval:        50 * time.Millisecond,
		CommonEndpoint:  otlp.ServerEndpoint,
		MetricsProtocol: otelcfg.ProtocolHTTPProtobuf,
		TTL:             3 * time.Minute,
		Buckets:         export.DefaultBuckets,
	}
	otelExporter, err := StatMetricsExporterProvider(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: cfg}},
		&StatMetricsConfig{
			Metrics:     cfg,
			SelectorCfg: &attributes.SelectorConfig{},
			CommonCfg:   &perapp.GlobalMetricsConfig{Features: export.FeatureStorageNFSIo},
		}, stats)(ctx)
	require.NoError(t, err)
	go otelExporter(ctx)

	stat := &ebpf.Stat{Type: ebpf.StatTypeNFSRPC, NFSRPC: &ebpf.NFSRPC{
		Version: 3, StatIdx: 6, Family: 2, Addr: [16]byte{192, 168, 122, 34},
		TxBytes: 180, RxBytes: 4096,
	}}
	stats.Send([]*ebpf.Stat{stat})

	var tx, rx collector.MetricRecord
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for drained := false; !drained; {
			select {
			case rec := <-otlp.Records():
				if rec.Name != "obi.stat.nfs.client.io" {
					continue
				}
				switch rec.Attributes["network.io.direction"] {
				case "transmit":
					tx = rec
				case "receive":
					rx = rec
				}
			default:
				drained = true
			}
		}
		assert.Equal(ct, "transmit", tx.Attributes["network.io.direction"])
		assert.Equal(ct, "receive", rx.Attributes["network.io.direction"])
	}, timeout, 100*time.Millisecond)

	assert.Equal(t, "192.168.122.34", tx.Attributes["server.address"])
	assert.NotContains(t, tx.Attributes, "onc_rpc.procedure.name", "procedure is opt-in on io")
	assert.InDelta(t, 180, tx.FloatVal+float64(tx.IntVal), 0)
	assert.InDelta(t, 4096, rx.FloatVal+float64(rx.IntVal), 0)

	// stat is shared with every other subscriber of the stats queue: it
	// must never be mutated by recording it.
	assert.Equal(t, uint8(0), stat.NFSRPC.Direction)
}
