// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

// TestStat_DiskMetrics runs with the default: block requests counted in the
// kernel maps, explicit buckets.
func TestStat_DiskMetrics(t *testing.T) {
	runDiskMetricsSuite(t, "disk-metrics", nil, diskExportPaths)
}

// TestStat_DiskMetricsPerEvent sends every block request to userspace, as
// before kernel aggregation: the same metrics must come out.
func TestStat_DiskMetricsPerEvent(t *testing.T) {
	runDiskMetricsSuite(t, "disk-metrics-per-event",
		[]string{"OTEL_EBPF_STORAGE_AGGREGATION_DISABLED=true"}, diskExportPaths)
}

// TestStat_DiskMetricsExponential counts the block histograms in the kernel's
// exponential layout.
func TestStat_DiskMetricsExponential(t *testing.T) {
	runDiskMetricsSuite(t, "disk-metrics-exponential",
		[]string{"OTEL_EBPF_STORAGE_AGGREGATION_EXPONENTIAL_HISTOGRAMS=true"}, diskNativeExportPath)
}

// runDiskMetricsSuite asserts the histograms on histogramPaths and the
// counters on both export paths.
func runDiskMetricsSuite(t *testing.T, name string, env []string, histogramPaths []string) {
	compose, err := docker.ComposeSuite("docker-compose-disk-metrics.yml", path.Join(pathOutput, "test-suite-"+name+".log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `OTEL_EBPF_CONFIG_SUFFIX=-disk-metrics`, `PROM_CONFIG_SUFFIX=-disk-metrics`)
	compose.Env = append(compose.Env, env...)
	require.NoError(t, compose.Up())
	waitForDiskMetricsPipeline(t, histogramPaths)
	t.Run("Disk Metrics operation duration", testDiskMetricsOpDuration(histogramPaths))
	t.Run("Disk Metrics operation duration write", testDiskMetricsOpDurationWrite(histogramPaths))
	t.Run("Disk Metrics IO bytes", testDiskMetricsIOBytes(diskExportPaths))
	t.Run("Disk Metrics IO bytes write volume", testDiskMetricsIOBytesWriteVolume(diskExportPaths))
	t.Run("Disk Metrics flush duration", testDiskMetricsFlushDuration(histogramPaths))
	t.Run("Disk Metrics Prometheus exposition", testDiskMetricsPromExposition)
	require.NoError(t, compose.Close())
}
