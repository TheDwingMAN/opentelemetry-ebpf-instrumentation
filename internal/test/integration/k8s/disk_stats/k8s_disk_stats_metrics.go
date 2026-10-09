// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package diskstats // import "go.opentelemetry.io/obi/internal/test/integration/k8s/disk_stats"

import (
	"context"
	"math"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/pkg/export"
)

const (
	testTimeout        = 5 * time.Minute
	prometheusHostPort = "localhost:39090"
	pollInterval       = time.Second

	// the disk-io Deployment, in 05-disk-io-workload.yml
	workload = `k8s_namespace_name="default",k8s_owner_name="disk-io"`
)

// diskStatLabels are the Prometheus labels of all the attributes that the disk stat metrics can have
var diskStatLabels = []string{
	"system_device", "obi_disk_stacked", "obi_disk_volume_name", "disk_io_direction", "error_type",
	"container_id", "obi_ip",
	"k8s_cluster_name", "k8s_namespace_name", "k8s_owner_name", "k8s_kind", "k8s_pod_name", "k8s_container_name",
}

var (
	blockDevicePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	// the node may keep its volumes on an LVM volume, reported with its disk
	stackedPattern = regexp.MustCompile(`^(true|false)$`)
	// the device mapper name of such a volume, only there on device mapper devices
	optionalVolumeNamePattern = regexp.MustCompile(`^([A-Za-z0-9_.+-]+)?$`)
	// the successful requests have no error type, which Prometheus drops as an empty label
	noErrorPattern = regexp.MustCompile(`^$`)
	clusterPattern = regexp.MustCompile(`^my-kube$`)
)

func FeatureDiskStats() features.Feature {
	return features.New("disk stats").
		Assess("charges the bytes of the block I/O to the container of the workload", testDiskIOChargedToTheContainer).
		Assess("reports the workload on the counters by default", testDiskCountersReportTheWorkloadByDefault).
		Assess("reports only the cluster on the latency histogram by default", testDiskHistogramReportsTheClusterByDefault).
		Assess("counts the requests of the latency histogram", testDiskCountersAreTheCountAndSumOfTheHistogram).
		Assess("reports the workload on the file sync counters by default", testFsSyncCountersReportTheWorkloadByDefault).
		Assess("reports only the cluster on the file sync histogram by default", testFsSyncHistogramReportsTheClusterByDefault).
		Feature()
}

// fsSyncStatLabels are the Prometheus labels of all the attributes that the file sync stat metrics
// can have
var fsSyncStatLabels = []string{
	"obi_fs_sync_type", "error_type", "container_id", "obi_ip",
	"k8s_cluster_name", "k8s_namespace_name", "k8s_owner_name", "k8s_kind", "k8s_pod_name", "k8s_container_name",
}

// fsyncLabels are the expected attributes of the successful fsyncs on the file sync histogram, which
// reports only the cluster by default
func fsyncLabels() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"obi_fs_sync_type": regexp.MustCompile(`^fsync$`),
		"error_type":       noErrorPattern,
		"k8s_cluster_name": clusterPattern,
	}
}

// the successful fsyncs of the disk-io workload
const workloadFsyncs = `{` + workload + `,obi_fs_sync_type="fsync",error_type=""}`

// testFsSyncCountersReportTheWorkloadByDefault checks the default attributes of the file sync
// counters of the disk-io workload, and that they are the count and the sum of the histogram
func testFsSyncCountersReportTheWorkloadByDefault(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	labels := fsyncLabels()
	labels["k8s_namespace_name"] = regexp.MustCompile(`^default$`)
	labels["k8s_owner_name"] = regexp.MustCompile(`^disk-io$`)
	labels["k8s_kind"] = regexp.MustCompile(`^Deployment$`)
	const by = `sum by (obi_fs_sync_type, error_type) `
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, counter := range []string{"obi_stat_fs_sync_operations_total", "obi_stat_fs_sync_time_seconds_total"} {
			results, err := pq.Query(counter + workloadFsyncs + ` > 0`)
			require.NoError(ct, err)
			require.Len(ct, results, 1, counter)
			assert.Empty(ct, promtest.LabelMismatches(results[0].Metric, fsSyncStatLabels, labels), results[0].Metric)
		}

		mismatches, err := pq.Query(by + `(obi_stat_fs_sync_operations_total) != ` +
			by + `(obi_stat_fs_sync_duration_seconds_count)`)
		require.NoError(ct, err)
		assert.Empty(ct, mismatches, "the operations are the count of the histogram")

		mismatches, err = pq.Query(`abs(` + by + `(obi_stat_fs_sync_time_seconds_total) - ` +
			by + `(obi_stat_fs_sync_duration_seconds_sum)) > 1e-6`)
		require.NoError(ct, err)
		assert.Empty(ct, mismatches, "the time is the sum of the histogram")
	}, testTimeout, pollInterval)
	return ctx
}

func testFsSyncHistogramReportsTheClusterByDefault(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	selector := `{obi_fs_sync_type="fsync",error_type=""}`
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		counts, err := pq.Query(`obi_stat_fs_sync_duration_seconds_count` + selector + ` > 0`)
		require.NoError(ct, err)
		require.Len(ct, counts, 1, "one series per sync type and outcome, whatever the workload")
		assert.Empty(ct, promtest.LabelMismatches(counts[0].Metric, fsSyncStatLabels, fsyncLabels()), counts[0].Metric)

		buckets, err := pq.Query(`obi_stat_fs_sync_duration_seconds_bucket` + selector)
		require.NoError(ct, err)
		assertHistogramBounds(ct, buckets, export.FsSyncLatencyBounds)
	}, testTimeout, pollInterval)
	return ctx
}

// deviceLabels are the expected attributes of the device and the direction of the successful I/O
func deviceLabels(direction string) map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"system_device":        blockDevicePattern,
		"obi_disk_stacked":     stackedPattern,
		"obi_disk_volume_name": optionalVolumeNamePattern,
		"disk_io_direction":    regexp.MustCompile("^" + direction + "$"),
		"error_type":           noErrorPattern,
		"k8s_cluster_name":     clusterPattern,
	}
}

// workloadLabels are the expected attributes of the successful I/O of the disk-io workload on the
// counters, which report its workload by default
func workloadLabels(direction string) map[string]*regexp.Regexp {
	labels := deviceLabels(direction)
	labels["k8s_namespace_name"] = regexp.MustCompile(`^default$`)
	labels["k8s_owner_name"] = regexp.MustCompile(`^disk-io$`)
	labels["k8s_kind"] = regexp.MustCompile(`^Deployment$`)
	return labels
}

// allLabels are the expected attributes of the successful I/O of the disk-io workload on
// obi.stat.disk.io, which selects all of them
func allLabels(direction string) map[string]*regexp.Regexp {
	labels := workloadLabels(direction)
	labels["container_id"] = regexp.MustCompile(`^[0-9a-f]{64}$`)
	labels["obi_ip"] = regexp.MustCompile(`^[0-9a-fA-F.:]+$`)
	labels["k8s_pod_name"] = regexp.MustCompile(`^disk-io-`)
	labels["k8s_container_name"] = regexp.MustCompile(`^writer$`)
	return labels
}

func assertDiskStatLabels(t assert.TestingT, series map[string]string, expected map[string]*regexp.Regexp) {
	assert.Empty(t, promtest.LabelMismatches(series, diskStatLabels, expected), series)
}

// successful selects the successful I/O of the disk-io workload in a direction
func successful(direction string) string {
	return `{` + workload + `,disk_io_direction="` + direction + `",error_type=""}`
}

func testDiskIOChargedToTheContainer(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, direction := range []string{"read", "write"} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(`obi_stat_disk_io_bytes_total` + successful(direction) + ` > 0`)
			require.NoError(ct, err)
			require.NotEmpty(ct, results, direction)
			for _, res := range results {
				assertDiskStatLabels(ct, res.Metric, allLabels(direction))
			}
		}, testTimeout, pollInterval)
	}
	return ctx
}

func testDiskCountersReportTheWorkloadByDefault(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, counter := range []string{"obi_stat_disk_operations_total", "obi_stat_disk_service_time_seconds_total"} {
		for _, direction := range []string{"read", "write"} {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(counter + successful(direction) + ` > 0`)
				require.NoError(ct, err)
				require.NotEmpty(ct, results, "%s %s", counter, direction)
				for _, res := range results {
					assertDiskStatLabels(ct, res.Metric, workloadLabels(direction))
				}
			}, testTimeout, pollInterval)
		}
	}
	return ctx
}

func testDiskHistogramReportsTheClusterByDefault(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, direction := range []string{"read", "write"} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			// the devices that the workload did I/O on
			devices, err := pq.Query(`group by (system_device) (obi_stat_disk_operations_total` + successful(direction) + `)`)
			require.NoError(ct, err)
			require.NotEmpty(ct, devices)
			for _, device := range devices {
				selector := `{system_device="` + device.Metric["system_device"] + `",disk_io_direction="` + direction +
					`",error_type=""}`
				counts, err := pq.Query(`obi_stat_disk_service_duration_seconds_count` + selector + ` > 0`)
				require.NoError(ct, err)
				require.Len(ct, counts, 1, "one series per device and direction, whatever the workload")
				assertDiskStatLabels(ct, counts[0].Metric, deviceLabels(direction))

				buckets, err := pq.Query(`obi_stat_disk_service_duration_seconds_bucket` + selector)
				require.NoError(ct, err)
				assertHistogramBounds(ct, buckets, export.DiskLatencyBounds)
			}
		}, testTimeout, pollInterval)
	}
	return ctx
}

// testDiskCountersAreTheCountAndSumOfTheHistogram checks, per device, direction and outcome, that
// the operations are the count of the latency histogram, and their service time its sum
func testDiskCountersAreTheCountAndSumOfTheHistogram(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	const by = `sum by (system_device, disk_io_direction, error_type) `
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		counted, err := pq.Query(by + `(obi_stat_disk_operations_total` + successful("write") + `) > 0`)
		require.NoError(ct, err)
		require.NotEmpty(ct, counted)

		mismatches, err := pq.Query(by + `(obi_stat_disk_operations_total) != ` +
			by + `(obi_stat_disk_service_duration_seconds_count)`)
		require.NoError(ct, err)
		assert.Empty(ct, mismatches, "the operations are the count of the histogram")

		mismatches, err = pq.Query(`abs(` + by + `(obi_stat_disk_service_time_seconds_total) - ` +
			by + `(obi_stat_disk_service_duration_seconds_sum)) > 1e-6`)
		require.NoError(ct, err)
		assert.Empty(ct, mismatches, "the service time is the sum of the histogram")
	}, testTimeout, pollInterval)
	return ctx
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
