// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package diskstats // import "go.opentelemetry.io/obi/internal/test/integration/k8s/disk_stats"

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const (
	testTimeout        = 5 * time.Minute
	prometheusHostPort = "localhost:39090"
	pollInterval       = time.Second

	// the successful I/O of the disk-io Deployment of 05-disk-io-workload.yml, by the attributes
	// that the counters report by default
	workload = `k8s_cluster_name="my-kube",k8s_namespace_name="default",k8s_owner_name="disk-io",k8s_kind="Deployment",error_type=""`
)

func FeatureDiskStats() features.Feature {
	return features.New("disk stats").
		Assess("charges the bytes of the block I/O to the container of the workload", testDiskIOOfTheContainer).
		Assess("reports the workload on the counters by default", testDiskCountersOfTheWorkload).
		Assess("reports the cluster alone on the latency histogram by default", testDiskHistogramOfTheCluster).
		Assess("counts the requests of the latency histogram", testDiskCountersAreTheHistogram).
		Feature()
}

// queryResults waits until a query has results, and returns them
func queryResults(t *testing.T, query string) []promtest.Result {
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(query)
		require.NoError(ct, err)
		require.NotEmpty(ct, results, query)
	}, testTimeout, pollInterval)
	return results
}

// queryNoResults waits until a query has no results
func queryNoResults(t *testing.T, query string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(query)
		require.NoError(ct, err)
		assert.Empty(ct, results, query)
	}, testTimeout, pollInterval)
}

// obi.stat.disk.io selects every attribute
func testDiskIOOfTheContainer(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	for _, direction := range []string{"read", "write"} {
		queryResults(t, `obi_stat_disk_io_bytes_total{`+workload+`,disk_io_direction="`+direction+
			`",k8s_pod_name=~"disk-io-.+",k8s_container_name="writer",container_id=~"[0-9a-f]{64}"} > 0`)
	}
	return ctx
}

func testDiskCountersOfTheWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	for _, counter := range []string{"obi_stat_disk_operations_total", "obi_stat_disk_service_time_seconds_total"} {
		for _, direction := range []string{"read", "write"} {
			for _, res := range queryResults(t, counter+`{`+workload+`,disk_io_direction="`+direction+`"} > 0`) {
				assert.NotContains(t, res.Metric, "k8s_pod_name", "a series per workload, not per pod")
				assert.NotContains(t, res.Metric, "container_id")
			}
		}
	}
	return ctx
}

func testDiskHistogramOfTheCluster(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	for _, res := range queryResults(t, `obi_stat_disk_service_duration_seconds_count{k8s_cluster_name="my-kube"} > 0`) {
		assert.NotContains(t, res.Metric, "k8s_namespace_name", "the workload is opt-in on the histogram")
		assert.NotContains(t, res.Metric, "k8s_owner_name")
	}
	queryNoResults(t, `count by (system_device, disk_io_direction, error_type) (obi_stat_disk_service_duration_seconds_count) > 1`)
	return ctx
}

func testDiskCountersAreTheHistogram(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	const by = `sum by (system_device, disk_io_direction, error_type) `
	queryNoResults(t, by+`(obi_stat_disk_operations_total) != `+by+`(obi_stat_disk_service_duration_seconds_count)`)
	queryNoResults(t, `abs(`+by+`(obi_stat_disk_service_time_seconds_total) - `+
		by+`(obi_stat_disk_service_duration_seconds_sum)) > 1e-6`)
	return ctx
}
