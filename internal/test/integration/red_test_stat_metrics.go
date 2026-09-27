// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func testStatMetricsTCPRtt(t *testing.T, port string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		countResults, err := pq.Query(`obi_stat_tcp_rtt_seconds_count{dst_port="` + port + `"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, countResults)

		// pumba injects a 100ms delay on the testclient, so at least ONE
		// per-connection RTT (sum/count per series) should be >= 100ms.
		// Per-series division avoids dilution from other fast connections
		// (e.g. health checks) that share the same dst_port label. A non-empty
		// response means at least one connection was captured with RTT >= 100ms.
		// Threshold is 90ms rather than 100ms to absorb the +/- 1ms timestamp jitter.
		avgQuery := `(obi_stat_tcp_rtt_seconds_sum{dst_port="` + port + `"} /` +
			` obi_stat_tcp_rtt_seconds_count{dst_port="` + port + `"}) >= 0.09`
		avgResults, err := pq.Query(avgQuery)
		require.NoError(ct, err)
		enoughPromResults(ct, avgResults)
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsTCPRttGo(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8381",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponentsTCP(t, testCaseURL)
			testStatMetricsTCPRtt(t, "8080")
		})
	}
}

func testStatMetricsTCPFailedConnectionsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_tcp_failed_connections_total{dst_port="19999",network_tcp_handshake_role="client"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		assert.Positive(ct, totalPromCount(ct, results))
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsTCPSuccessfulConnectionsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		clientResults, err := pq.Query(`obi_stat_tcp_successful_connections_total{dst_port="8080",network_tcp_handshake_role="client"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, clientResults)
		assert.Positive(ct, totalPromCount(ct, clientResults))

		serverResults, err := pq.Query(`obi_stat_tcp_successful_connections_total{src_port="8080",network_tcp_handshake_role="server"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, serverResults)
		assert.Positive(ct, totalPromCount(ct, serverResults))
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsTCPRetransmitsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_tcp_retransmits_total{dst_port="8081"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		assert.Positive(ct, totalPromCount(ct, results))
	}, testTimeout, 100*time.Millisecond)
}

func testStatMetricsTCPIoGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, direction := range []string{"transmit", "receive"} {
		t.Run(direction, func(t *testing.T) {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(`obi_stat_tcp_io_bytes_total{dst_port="8080",network_io_direction="` + direction + `"}`)
				require.NoError(ct, err)
				enoughPromResults(ct, results)
				assert.Positive(ct, totalPromCount(ct, results))
			}, testTimeout, 100*time.Millisecond)
		})
	}
}

// testStatMetricsDiskOperationDuration checks the latency of the O_DIRECT I/O of the disk-io
// component. The rest of the host's block I/O is measured too, so only lower bounds are asserted.
func testStatMetricsDiskOperationDuration(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, direction := range []string{"read", "write"} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(`obi_stat_disk_operation_duration_seconds_count{disk_io_direction="` + direction + `"} > 0`)
			require.NoError(ct, err)
			enoughPromResults(ct, results)
			for _, res := range results {
				assert.NotEmpty(ct, res.Metric["system_device"])
				assert.Empty(ct, res.Metric["error_type"], "the disk-io component I/O doesn't fail")
			}

			sums, err := pq.Query(`obi_stat_disk_operation_duration_seconds_sum{disk_io_direction="` + direction + `"} > 0`)
			require.NoError(ct, err)
			enoughPromResults(ct, sums)
		}, testTimeout, 100*time.Millisecond)
	}
}

// testStatMetricsDiskCounters checks that the I/O of the disk-io container is charged to it
func testStatMetricsDiskCounters(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, metric := range []string{
		"obi_stat_disk_io_bytes_total",
		"obi_stat_disk_operations_total",
		"obi_stat_disk_operation_time_seconds_total",
	} {
		for _, direction := range []string{"read", "write"} {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(metric + `{disk_io_direction="` + direction + `",container_id=~"[0-9a-f]{64}"} > 0`)
				require.NoError(ct, err)
				enoughPromResults(ct, results)
				for _, res := range results {
					assert.NotEmpty(ct, res.Metric["system_device"])
				}
			}, testTimeout, 100*time.Millisecond)
		}
	}
}

// testStatMetricsNoDiskStats checks that the stats aggregate feature doesn't enable the disk stats
func testStatMetricsNoDiskStats(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	results, err := pq.Query(`{__name__=~"obi_stat_disk_.*"}`)
	require.NoError(t, err)
	assert.Empty(t, results)
}
