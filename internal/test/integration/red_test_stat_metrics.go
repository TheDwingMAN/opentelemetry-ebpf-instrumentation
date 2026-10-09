// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"math"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/pkg/export"
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

// diskStatLabels are the Prometheus labels of all the attributes that the disk stat metrics can have
var diskStatLabels = []string{
	"system_device", "obi_disk_stacked", "obi_disk_volume_name", "disk_io_direction", "error_type",
	"obi_ip",
}

var (
	blockDevicePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	ipPattern          = regexp.MustCompile(`^[0-9a-fA-F.:]+$`)
	// the host may keep the docker volumes on an LVM volume, reported with its disk
	stackedPattern = regexp.MustCompile(`^(true|false)$`)

	// the device mapper name of such a volume, only there on device mapper devices
	optionalVolumeNamePattern = regexp.MustCompile(`^([A-Za-z0-9_.+-]+)?$`)
)

// assertDiskStatLabels checks that a series of a disk stat metric has exactly the expected
// attributes, given as patterns of their values, and none of the others
func assertDiskStatLabels(t assert.TestingT, series map[string]string, expected map[string]*regexp.Regexp) {
	assert.Empty(t, promtest.LabelMismatches(series, diskStatLabels, expected), series)
}

// diskIOLabels are the expected attributes of the successful block I/O of the node, with the device
// and direction of the I/O
func diskIOLabels(direction string) map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"system_device":        blockDevicePattern,
		"obi_disk_stacked":     stackedPattern,
		"obi_disk_volume_name": optionalVolumeNamePattern,
		"disk_io_direction":    regexp.MustCompile("^" + direction + "$"),
		"obi_ip":               ipPattern,
	}
}

// assertHistogramBounds checks that the histograms of the given _bucket series have the given
// bucket boundaries
func assertHistogramBounds(t require.TestingT, buckets []promtest.Result, bounds []float64) {
	histograms, err := promtest.BucketBounds(buckets)
	require.NoError(t, err)
	require.NotEmpty(t, histograms)
	for histogram, les := range histograms {
		assert.Equal(t, append(slices.Clone(bounds), math.Inf(1)), les, histogram)
	}
}

// testStatMetricsDiskServiceDuration checks the latency histogram of the successful block I/O of
// the node, which the O_DIRECT I/O of the disk-io container keeps going: its attributes and its
// buckets
func testStatMetricsDiskServiceDuration(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, direction := range []string{"read", "write"} {
		selector := `{disk_io_direction="` + direction + `",error_type=""}`
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			counts, err := pq.Query(`obi_stat_disk_service_duration_seconds_count` + selector + ` > 0`)
			require.NoError(ct, err)
			enoughPromResults(ct, counts)
			for _, res := range counts {
				assertDiskStatLabels(ct, res.Metric, diskIOLabels(direction))
			}

			sums, err := pq.Query(`obi_stat_disk_service_duration_seconds_sum` + selector + ` > 0`)
			require.NoError(ct, err)
			enoughPromResults(ct, sums)

			buckets, err := pq.Query(`obi_stat_disk_service_duration_seconds_bucket` + selector)
			require.NoError(ct, err)
			assertHistogramBounds(ct, buckets, export.DiskLatencyBounds)
		}, testTimeout, 100*time.Millisecond)
	}
}

// testStatMetricsDiskCounters checks the counters of the successful block I/O of the node: their
// attributes, and that the operations and their service time are the count and the sum of the
// latency histogram
func testStatMetricsDiskCounters(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, direction := range []string{"read", "write"} {
		selector := `{disk_io_direction="` + direction + `",error_type=""}`
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			for _, counter := range []string{
				"obi_stat_disk_operations_total", "obi_stat_disk_service_time_seconds_total", "obi_stat_disk_io_bytes_total",
			} {
				results, err := pq.Query(counter + selector + ` > 0`)
				require.NoError(ct, err)
				enoughPromResults(ct, results)
				for _, res := range results {
					assertDiskStatLabels(ct, res.Metric, diskIOLabels(direction))
				}
			}

			mismatches, err := pq.Query(`obi_stat_disk_service_duration_seconds_count` + selector +
				` != obi_stat_disk_operations_total` + selector)
			require.NoError(ct, err)
			assert.Empty(ct, mismatches, "the operations are the count of the histogram")

			mismatches, err = pq.Query(`abs(obi_stat_disk_service_duration_seconds_sum` + selector +
				` - obi_stat_disk_service_time_seconds_total` + selector + `) > 1e-6`)
			require.NoError(ct, err)
			assert.Empty(ct, mismatches, "the service time is the sum of the histogram")
		}, testTimeout, 100*time.Millisecond)
	}
}

// testStatMetricsNoDiskStats checks that the stats aggregate feature doesn't enable the disk stats
func testStatMetricsNoDiskStats(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	results, err := pq.Query(`{__name__=~"obi_stat_disk_.*"}`)
	require.NoError(t, err)
	assert.Empty(t, results)
}
