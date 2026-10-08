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

// diskStatLabels are the Prometheus labels of all the attributes that the disk and file sync stat
// metrics can have
var diskStatLabels = []string{
	"system_device", "obi_disk_partition", "obi_disk_stacked", "disk_io_direction", "error_type", "container_id", "obi_ip",
	"k8s_cluster_name", "k8s_namespace_name", "k8s_owner_name", "k8s_kind", "k8s_pod_name", "k8s_container_name",
	"obi_fs_sync_type", "system_filesystem_mountpoint", "system_filesystem_type",
}

func FeatureDiskStats() features.Feature {
	return features.New("disk stats").
		Assess("charges block I/O to the workload that did it", testDiskIOChargedToWorkload).
		Assess("reports the disk latency of the workload", testDiskLatencyPerWorkload).
		Assess("reports the file syncs of the workload", testFsSyncPerWorkload).
		Assess("counts the file syncs of the workload", testFsSyncCountersPerWorkload).
		Assess("reports the requests in flight of the disks of the workload", testDiskInflightOfWorkloadDevices).
		Assess("links the pods to the disks of their PersistentVolumeClaims", testPodVolumeDevices).
		Feature()
}

// workloadLabels are the expected attributes of the successful I/O of the disk-io workload, whose
// metrics select all the attributes
func workloadLabels() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"container_id":       regexp.MustCompile(`^[0-9a-f]{64}$`),
		"obi_ip":             regexp.MustCompile(`^[0-9a-fA-F.:]+$`),
		"k8s_cluster_name":   regexp.MustCompile(`^my-kube$`),
		"k8s_namespace_name": regexp.MustCompile(`^default$`),
		"k8s_owner_name":     regexp.MustCompile(`^disk-io$`),
		"k8s_kind":           regexp.MustCompile(`^Deployment$`),
		"k8s_pod_name":       regexp.MustCompile(`^disk-io-`),
		"k8s_container_name": regexp.MustCompile(`^writer$`),
	}
}

// fsSyncLabels are the expected attributes of the successful fsync(2) calls of the disk-io
// workload, which also have the filesystem of the synced file
func fsSyncLabels() map[string]*regexp.Regexp {
	labels := workloadLabels()
	labels["obi_fs_sync_type"] = regexp.MustCompile(`^fsync$`)
	labels["system_filesystem_mountpoint"] = regexp.MustCompile(`^/`)
	labels["system_filesystem_type"] = regexp.MustCompile(`^[a-z0-9._]+$`)
	return labels
}

// diskIOLabels are the expected attributes of the successful block I/O of the disk-io workload,
// which also has the device and direction of the I/O
func diskIOLabels(direction string) map[string]*regexp.Regexp {
	labels := workloadLabels()
	labels["system_device"] = blockDevicePattern
	// only there when the I/O targets a partition, which depends on the disk layout of the node
	labels["obi_disk_partition"] = regexp.MustCompile(`^([a-z][a-z0-9-]*)?$`)
	labels["obi_disk_stacked"] = stackedPattern
	labels["disk_io_direction"] = regexp.MustCompile("^" + direction + "$")
	return labels
}

var (
	blockDevicePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	// the node may keep its volumes on an LVM volume, reported with its disk
	stackedPattern = regexp.MustCompile(`^(true|false)$`)
)

func assertDiskStatLabels(t assert.TestingT, series map[string]string, expected map[string]*regexp.Regexp) {
	assert.Empty(t, promtest.LabelMismatches(series, diskStatLabels, expected), series)
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

func testDiskIOChargedToWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, counter := range []struct{ metric, values string }{
		{"obi_stat_disk_io_bytes_total", "> 0"},
		{"obi_stat_disk_operations_total", "> 0"},
		{"obi_stat_disk_service_time_seconds_total", "> 0"},
		// the wait can sum to 0: the I/O is synchronous, and the block plug of the thread can give
		// each request the same time for its allocation and its issue (Linux 6.10+, RHEL 9.6)
		{"obi_stat_disk_queue_time_seconds_total", ">= 0"},
	} {
		for _, direction := range []string{"read", "write"} {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(counter.metric + `{` + workload + `,disk_io_direction="` + direction + `"} ` + counter.values)
				require.NoError(ct, err)
				require.NotEmpty(ct, results, "%s %s", counter.metric, direction)
				for _, res := range results {
					assertDiskStatLabels(ct, res.Metric, diskIOLabels(direction))
				}
			}, testTimeout, pollInterval)
		}
	}
	return ctx
}

func testDiskLatencyPerWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, direction := range []string{"read", "write"} {
		selector := `{` + workload + `,disk_io_direction="` + direction + `"}`
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			counts, err := pq.Query(`obi_stat_disk_operation_duration_seconds_count` + selector + ` > 0`)
			require.NoError(ct, err)
			require.NotEmpty(ct, counts)
			for _, res := range counts {
				assertDiskStatLabels(ct, res.Metric, diskIOLabels(direction))
			}

			buckets, err := pq.Query(`obi_stat_disk_operation_duration_seconds_bucket` + selector)
			require.NoError(ct, err)
			assertHistogramBounds(ct, buckets, export.DefaultBuckets.StatDiskOperationDurationHistogram)

			// both are reported from the same requests, so they are equal in every scrape
			mismatches, err := pq.Query(`obi_stat_disk_operation_duration_seconds_count` + selector +
				` != obi_stat_disk_operations_total` + selector)
			require.NoError(ct, err)
			assert.Empty(ct, mismatches, "the histogram must count the same requests as the operations counter")
		}, testTimeout, pollInterval)
	}
	return ctx
}

func testFsSyncPerWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	selector := `{` + workload + `}`
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		counts, err := pq.Query(`obi_stat_fs_sync_duration_seconds_count` + selector + ` > 0`)
		require.NoError(ct, err)
		require.NotEmpty(ct, counts)
		for _, res := range counts {
			assertDiskStatLabels(ct, res.Metric, fsSyncLabels())
		}

		buckets, err := pq.Query(`obi_stat_fs_sync_duration_seconds_bucket` + selector)
		require.NoError(ct, err)
		assertHistogramBounds(ct, buckets, export.DefaultBuckets.StatFsSyncDurationHistogram)
	}, testTimeout, pollInterval)
	return ctx
}

func testFsSyncCountersPerWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	selector := `{` + workload + `}`
	for _, metric := range []string{
		"obi_stat_fs_sync_operations_total",
		"obi_stat_fs_sync_operation_time_seconds_total",
	} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(metric + selector + ` > 0`)
			require.NoError(ct, err)
			require.NotEmpty(ct, results)
			for _, res := range results {
				assertDiskStatLabels(ct, res.Metric, fsSyncLabels())
			}
		}, testTimeout, pollInterval)
	}
	return ctx
}

func testDiskInflightOfWorkloadDevices(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, direction := range []string{"read", "write"} {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			devices, err := pq.Query(`group by (system_device) (obi_stat_disk_operations_total{` + workload +
				`,disk_io_direction="` + direction + `"})`)
			require.NoError(ct, err)
			require.NotEmpty(ct, devices)
			for _, device := range devices {
				pending, err := pq.Query(`obi_stat_disk_operation_inflight{system_device="` + device.Metric["system_device"] +
					`",disk_io_direction="` + direction + `"} >= 0`)
				require.NoError(ct, err)
				require.Len(ct, pending, 1, "one series per device and direction")
				assertDiskStatLabels(ct, pending[0].Metric, map[string]*regexp.Regexp{
					"system_device":     blockDevicePattern,
					"obi_disk_stacked":  stackedPattern,
					"disk_io_direction": regexp.MustCompile("^" + direction + "$"),
					"obi_ip":            regexp.MustCompile(`^[0-9a-fA-F.:]+$`),
				})
			}
		}, testTimeout, pollInterval)
	}
	return ctx
}

// podVolumeLabels are the Prometheus labels of obi.stat.k8s.pod.volume.info
var podVolumeLabels = []string{
	"k8s_cluster_name", "k8s_namespace_name", "k8s_pod_name", "k8s_owner_name", "k8s_kind",
	"k8s_volume_name", "k8s_volume_type", "k8s_persistentvolumeclaim_name", "k8s_persistentvolume_name",
	"obi_disk_volume_device", "system_device", "obi_ip",
}

// testPodVolumeDevices checks the device of the volume of the disk-io-pvc workload, from its
// PersistentVolumeClaim, and that the block I/O of the workload goes to that disk
func testPodVolumeDevices(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	var disk string
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		volumes, err := pq.Query(`obi_stat_k8s_pod_volume_info{k8s_owner_name="disk-io-pvc"} == 1`)
		require.NoError(ct, err)
		require.Len(ct, volumes, 1, "the volume is on one disk")
		assert.Empty(ct, promtest.LabelMismatches(volumes[0].Metric, podVolumeLabels, map[string]*regexp.Regexp{
			"k8s_cluster_name":               regexp.MustCompile(`^my-kube$`),
			"k8s_namespace_name":             regexp.MustCompile(`^default$`),
			"k8s_pod_name":                   regexp.MustCompile(`^disk-io-pvc-`),
			"k8s_owner_name":                 regexp.MustCompile(`^disk-io-pvc$`),
			"k8s_volume_name":                regexp.MustCompile(`^data$`),
			"k8s_persistentvolumeclaim_name": regexp.MustCompile(`^disk-io-data$`),
			"k8s_persistentvolume_name":      regexp.MustCompile(`^pvc-`),
			"obi_disk_volume_device":         blockDevicePattern,
			"system_device":                  blockDevicePattern,
		}), volumes[0].Metric)
		disk = volumes[0].Metric["system_device"]
	}, testTimeout, pollInterval)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		written, err := pq.Query(`obi_stat_disk_io_bytes_total{k8s_owner_name="disk-io-pvc",disk_io_direction="write",system_device="` +
			disk + `"} > 0`)
		require.NoError(ct, err)
		assert.NotEmpty(ct, written, "the workload writes to the disk of its volume")
	}, testTimeout, pollInterval)
	return ctx
}
