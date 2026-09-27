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
	"system_device", "disk_io_direction", "error_type", "container_id", "obi_ip",
	"k8s_cluster_name", "k8s_namespace_name", "k8s_owner_name", "k8s_kind", "k8s_pod_name", "k8s_container_name",
}

func FeatureDiskStats() features.Feature {
	return features.New("disk stats").
		Assess("charges block I/O to the workload that did it", testDiskIOChargedToWorkload).
		Assess("reports the disk latency of the workload", testDiskLatencyPerWorkload).
		Assess("reports the file syncs of the workload", testFsSyncPerWorkload).
		Feature()
}

// fsSyncLabels are the expected attributes of the successful file syncs of the disk-io workload,
// whose metrics select all the attributes
func fsSyncLabels() map[string]*regexp.Regexp {
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

// diskIOLabels are the expected attributes of the successful block I/O of the disk-io workload,
// which also has the device and direction of the I/O
func diskIOLabels(direction string) map[string]*regexp.Regexp {
	labels := fsSyncLabels()
	labels["system_device"] = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	labels["disk_io_direction"] = regexp.MustCompile("^" + direction + "$")
	return labels
}

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
	for _, metric := range []string{
		"obi_stat_disk_io_bytes_total",
		"obi_stat_disk_operations_total",
		"obi_stat_disk_operation_time_seconds_total",
	} {
		for _, direction := range []string{"read", "write"} {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(metric + `{` + workload + `,disk_io_direction="` + direction + `"} > 0`)
				require.NoError(ct, err)
				require.NotEmpty(ct, results, "%s %s", metric, direction)
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
