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

// diskStatLabels are the Prometheus labels of all the attributes that the disk and file sync stat
// metrics can have
var diskStatLabels = []string{
	"system_device", "obi_disk_partition", "obi_disk_stacked", "obi_disk_volume_name", "disk_io_direction", "error_type",
	"container_id", "obi_ip",
	"k8s_cluster_name", "k8s_namespace_name", "k8s_owner_name", "k8s_kind", "k8s_pod_name", "k8s_container_name",
	"obi_fs_sync_type", "system_filesystem_mountpoint", "system_filesystem_type",
}

var (
	blockDevicePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	// the partition is only there when the I/O targets one, which depends on the disk layout of the host
	optionalPartitionPattern = regexp.MustCompile(`^([a-z][a-z0-9-]*)?$`)
	ipPattern                = regexp.MustCompile(`^[0-9a-fA-F.:]+$`)
	// the host may keep the docker volumes on an LVM volume, reported with its disk
	stackedPattern    = regexp.MustCompile(`^(true|false)$`)
	mountpointPattern = regexp.MustCompile(`^/`)
	fsTypePattern     = regexp.MustCompile(`^[a-z0-9._]+$`)

	// the device mapper name of such a volume, only there on device mapper devices
	optionalVolumeNamePattern = regexp.MustCompile(`^([A-Za-z0-9_.+-]+)?$`)
)

// assertDiskStatLabels checks that a series of a disk or file sync stat metric has exactly the
// expected attributes, given as patterns of their values, and none of the others
func assertDiskStatLabels(t assert.TestingT, series map[string]string, expected map[string]*regexp.Regexp) {
	assert.Empty(t, promtest.LabelMismatches(series, diskStatLabels, expected), series)
}

// workloadLabels are the expected attributes of the successful I/O of a container: all the
// attributes are selected, and kubernetes metadata is disabled
func workloadLabels(containerID string) map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"container_id": regexp.MustCompile("^" + containerID + "$"),
		"obi_ip":       ipPattern,
	}
}

// fsSyncLabels are the expected attributes of the successful fsync(2) calls of a container, which
// also have the filesystem of the synced file
func fsSyncLabels(containerID string) map[string]*regexp.Regexp {
	labels := workloadLabels(containerID)
	labels["obi_fs_sync_type"] = regexp.MustCompile(`^fsync$`)
	labels["system_filesystem_mountpoint"] = mountpointPattern
	labels["system_filesystem_type"] = fsTypePattern
	return labels
}

// diskIOLabels are the expected attributes of the successful block I/O of a container, which
// also has the device and direction of the I/O
func diskIOLabels(containerID, direction string) map[string]*regexp.Regexp {
	labels := workloadLabels(containerID)
	labels["system_device"] = blockDevicePattern
	labels["obi_disk_partition"] = optionalPartitionPattern
	labels["obi_disk_stacked"] = stackedPattern
	labels["obi_disk_volume_name"] = optionalVolumeNamePattern
	labels["disk_io_direction"] = regexp.MustCompile("^" + direction + "$")
	return labels
}

// pendingLabels are the expected attributes of the requests in flight of a device, which are not
// charged to workloads
func pendingLabels(direction string) map[string]*regexp.Regexp {
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

// testStatMetricsDiskOperationDuration checks the latency histogram of the O_DIRECT I/O of the
// disk-io container: its attributes, its buckets, and that it counts every request
func testStatMetricsDiskOperationDuration(t *testing.T, containerID string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, direction := range []string{"read", "write"} {
		selector := `{container_id="` + containerID + `",disk_io_direction="` + direction + `"}`
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			counts, err := pq.Query(`obi_stat_disk_operation_duration_seconds_count` + selector + ` > 0`)
			require.NoError(ct, err)
			enoughPromResults(ct, counts)
			for _, res := range counts {
				assertDiskStatLabels(ct, res.Metric, diskIOLabels(containerID, direction))
			}

			sums, err := pq.Query(`obi_stat_disk_operation_duration_seconds_sum` + selector + ` > 0`)
			require.NoError(ct, err)
			enoughPromResults(ct, sums)

			buckets, err := pq.Query(`obi_stat_disk_operation_duration_seconds_bucket` + selector)
			require.NoError(ct, err)
			assertHistogramBounds(ct, buckets, export.DefaultBuckets.StatDiskOperationDurationHistogram)

			// both are reported from the same requests, so they are equal in every scrape
			mismatches, err := pq.Query(`obi_stat_disk_operation_duration_seconds_count` + selector +
				` != obi_stat_disk_operations_total` + selector)
			require.NoError(ct, err)
			assert.Empty(ct, mismatches, "the histogram must count the same requests as the operations counter")
		}, testTimeout, 100*time.Millisecond)
	}
}

// testStatMetricsDiskCounters checks that the I/O of the disk-io container is charged to it, with
// the wait of its requests before their issue
func testStatMetricsDiskCounters(t *testing.T, containerID string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, counter := range []struct{ metric, values string }{
		{"obi_stat_disk_io_bytes_total", "> 0"},
		{"obi_stat_disk_operations_total", "> 0"},
		{"obi_stat_disk_service_time_seconds_total", "> 0"},
		// the wait can sum to 0: the I/O is synchronous, and the block plug of the thread can give
		// each request the same time for its allocation and its issue (Linux 6.9+, RHEL 9.6)
		{"obi_stat_disk_queue_time_seconds_total", ">= 0"},
	} {
		for _, direction := range []string{"read", "write"} {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(counter.metric + `{container_id="` + containerID + `",disk_io_direction="` + direction + `"} ` + counter.values)
				require.NoError(ct, err)
				enoughPromResults(ct, results)
				for _, res := range results {
					assertDiskStatLabels(ct, res.Metric, diskIOLabels(containerID, direction))
				}
			}, testTimeout, 100*time.Millisecond)
		}
	}
}

// testStatMetricsFsSyncDuration checks the latency histogram of the file syncs of the disk-io
// container, which have neither device nor direction
func testStatMetricsFsSyncDuration(t *testing.T, containerID string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	selector := `{container_id="` + containerID + `"}`
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		counts, err := pq.Query(`obi_stat_fs_sync_duration_seconds_count` + selector + ` > 0`)
		require.NoError(ct, err)
		enoughPromResults(ct, counts)
		for _, res := range counts {
			assertDiskStatLabels(ct, res.Metric, fsSyncLabels(containerID))
		}

		sums, err := pq.Query(`obi_stat_fs_sync_duration_seconds_sum` + selector + ` > 0`)
		require.NoError(ct, err)
		enoughPromResults(ct, sums)

		buckets, err := pq.Query(`obi_stat_fs_sync_duration_seconds_bucket` + selector)
		require.NoError(ct, err)
		assertHistogramBounds(ct, buckets, export.DefaultBuckets.StatFsSyncDurationHistogram)
	}, testTimeout, 100*time.Millisecond)
}

// testStatMetricsFsSyncCounters checks that the file syncs of the disk-io container are counted,
// and charged to it, by the file sync counters, as by the histogram
func testStatMetricsFsSyncCounters(t *testing.T, containerID string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	selector := `{container_id="` + containerID + `"}`
	for _, metric := range []string{
		"obi_stat_fs_sync_operations_total",
		"obi_stat_fs_sync_operation_time_seconds_total",
	} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(metric + selector + ` > 0`)
			require.NoError(ct, err)
			enoughPromResults(ct, results)
			for _, res := range results {
				assertDiskStatLabels(ct, res.Metric, fsSyncLabels(containerID))
			}
		}, testTimeout, 100*time.Millisecond)
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// both are reported from the same syncs, so they are equal in every scrape
		mismatches, err := pq.Query(`obi_stat_fs_sync_duration_seconds_count` + selector +
			` != obi_stat_fs_sync_operations_total` + selector)
		require.NoError(ct, err)
		assert.Empty(ct, mismatches, "the histogram must count the same syncs as the operations counter")
	}, testTimeout, 100*time.Millisecond)
}

// testStatMetricsDiskOperationInflight checks that the devices that the disk-io container reads
// and writes report their requests in flight
func testStatMetricsDiskOperationInflight(t *testing.T, containerID string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, direction := range []string{"read", "write"} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			devices, err := pq.Query(`group by (system_device) (obi_stat_disk_operations_total{container_id="` + containerID +
				`",disk_io_direction="` + direction + `"})`)
			require.NoError(ct, err)
			enoughPromResults(ct, devices)
			for _, device := range devices {
				pending, err := pq.Query(`obi_stat_disk_operation_inflight{system_device="` + device.Metric["system_device"] +
					`",disk_io_direction="` + direction + `"} >= 0`)
				require.NoError(ct, err)
				require.Len(ct, pending, 1, "one series per device and direction")
				assertDiskStatLabels(ct, pending[0].Metric, pendingLabels(direction))
			}
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
