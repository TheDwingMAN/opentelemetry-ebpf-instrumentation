// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package diskstats // import "go.opentelemetry.io/obi/internal/test/integration/k8s/disk_stats"

import (
	"context"
	"strings"
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

	// the disk-io Deployment, in 05-disk-io-workload.yml
	workload = `k8s_namespace_name="default",k8s_owner_name="disk-io"`
)

func FeatureDiskStats() features.Feature {
	return features.New("disk stats").
		Assess("charges block I/O to the workload that did it", testDiskIOChargedToWorkload).
		Assess("decorates disk metrics with the pod and container", testDiskStatsDecoration).
		Assess("reports the disk latency of the workload", testDiskLatencyPerWorkload).
		Feature()
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
				assert.NotEmpty(ct, results, "%s %s", metric, direction)
			}, testTimeout, pollInterval)
		}
	}
	return ctx
}

func testDiskStatsDecoration(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_disk_operations_total{` + workload + `}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
		for _, res := range results {
			assert.Equal(ct, "my-kube", res.Metric["k8s_cluster_name"])
			assert.Equal(ct, "Deployment", res.Metric["k8s_kind"])
			assert.True(ct, strings.HasPrefix(res.Metric["k8s_pod_name"], "disk-io-"), res.Metric["k8s_pod_name"])
			assert.Equal(ct, "writer", res.Metric["k8s_container_name"])
			assert.Len(ct, res.Metric["container_id"], 64)
			assert.NotEmpty(ct, res.Metric["system_device"])
		}
	}, testTimeout, pollInterval)
	return ctx
}

func testDiskLatencyPerWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_disk_operation_duration_seconds_count{` + workload + `} > 0`)
		require.NoError(ct, err)
		assert.NotEmpty(ct, results)
	}, testTimeout, pollInterval)
	return ctx
}
