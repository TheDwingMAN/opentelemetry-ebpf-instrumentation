// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s // import "go.opentelemetry.io/obi/internal/test/integration/k8s/common"

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const (
	// storageWriterPodRegex matches the pods of the nfs-writer Deployment.
	// Deliberately unanchored: PromQL's =~ anchors the whole value, while
	// assert.Regexp matches a substring, and this pattern is used both ways.
	// An anchored "^nfs-writer-" silently matches nothing in PromQL.
	// (05-uninstrumented-nfs-writer.yml).
	storageWriterPodRegex = "nfs-writer-.+"
	storagePVCName        = "nfs-data"
	storageClassName      = "obi-nfs"
)

// FeatureStorageFsMetrics asserts on the filesystem-layer storage_fs metrics
// (obi_stat_fs_*). Unlike the block layer, filesystem probes run in the
// calling process's context, so these metrics carry pod/PV/PVC/storage-class
// attribution.
func FeatureStorageFsMetrics() features.Feature {
	return features.New("storage filesystem metrics").
		Assess("emits fs.operation duration for write/read/fsync, decorated with pod/PV/PVC/storage-class",
			testStorageFsOperationDuration).
		Assess("fs.io bytes grow across samples for the writer's write operations",
			testStorageFsIOBytesGrow).
		Assess("no fs operation errors for the writer",
			testStorageFsNoOperationErrors).
		Feature()
}

// FeatureStorageBlockMetrics asserts on the block-layer storage_block metrics
// (obi_stat_disk_*). Block tracepoints (block_rq_issue/complete) are
// node-wide, not tied to any task context, so these metrics carry no
// k8s_pod_name label.
func FeatureStorageBlockMetrics() features.Feature {
	return features.New("storage block metrics").
		Assess("emits disk operation duration with device and direction, and no pod attribution",
			testStorageDiskOperationDuration).
		Feature()
}

const storageWriterContainer = "io"

func testStorageFsOperationDuration(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, op := range []string{"write", "read", "fsync"} {
		t.Run(op, func(t *testing.T) {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(
					`obi_stat_fs_operation_duration_seconds_count{system_filesystem_type="nfs",fs_operation="` + op + `"}`)
				require.NoError(ct, err)
				require.NotEmpty(ct, results)

				for _, res := range results {
					assert.Regexp(ct, storageWriterPodRegex, res.Metric["k8s_pod_name"])
					assert.Equal(ct, "default", res.Metric["k8s_namespace_name"])
					// Container attribution is best-effort. The pod comes from
					// the volume mount, which always resolves, but the
					// container name comes from the PID path and is left unset
					// when the store has not tracked the writing process --
					// which is the normal case for short-lived processes and
					// for a deployment that instruments no services. Assert it
					// is never *wrong*, rather than that it is always present.
					assert.Contains(ct, []string{"", storageWriterContainer}, res.Metric["k8s_container_name"])
					assert.NotEmpty(ct, res.Metric["k8s_persistentvolume_name"])
					assert.Equal(ct, storagePVCName, res.Metric["k8s_persistentvolumeclaim_name"])
					assert.Equal(ct, storageClassName, res.Metric["k8s_storageclass_name"])
				}
			}, testTimeout, 100*time.Millisecond)
		})
	}
	return ctx
}

func testStorageFsIOBytesGrow(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	query := `obi_stat_fs_io_bytes_total{system_filesystem_type="nfs",fs_operation="write",k8s_pod_name=~"` +
		storageWriterPodRegex + `"}`

	var first float64
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(query)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
		first = sumPromValues(ct, results)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(query)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
		assert.Greater(ct, sumPromValues(ct, results), first)
	}, testTimeout, 100*time.Millisecond)

	return ctx
}

func testStorageFsNoOperationErrors(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	results, err := pq.Query(`obi_stat_fs_operation_errors_total{k8s_pod_name=~"` + storageWriterPodRegex + `"}`)
	require.NoError(t, err)
	require.Empty(t, results)
	return ctx
}

func testStorageDiskOperationDuration(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`obi_stat_disk_operation_duration_seconds_count`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)

		for _, res := range results {
			assert.NotEmpty(ct, res.Metric["system_device"])
			assert.Contains(ct, []string{"read", "write"}, res.Metric["disk_io_direction"])
			assert.NotContains(ct, res.Metric, "k8s_pod_name")
		}
	}, testTimeout, 100*time.Millisecond)
	return ctx
}

// sumPromValues sums the sample values of a query result.
//
// Parses as float rather than int on purpose: Prometheus renders large sample
// values in scientific notation (e.g. "1.048576e+08"), which strconv.Atoi
// rejects outright.
func sumPromValues(t require.TestingT, results []promtest.Result) float64 {
	total := 0.0
	for _, res := range results {
		require.Len(t, res.Value, 2)
		val, err := strconv.ParseFloat(res.Value[1].(string), 64)
		require.NoError(t, err)
		total += val
	}
	return total
}
