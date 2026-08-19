// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestStat_DiskMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-disk-metrics.yml", path.Join(pathOutput, "test-suite-disk-metrics.log"))
	compose.Env = append(compose.Env, `OTEL_EBPF_CONFIG_SUFFIX=-disk-metrics`, `PROM_CONFIG_SUFFIX=-disk-metrics`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	waitForDiskMetricsPipeline(t)
	t.Run("Disk Metrics operation duration", testDiskMetricsOpDuration)
	t.Run("Disk Metrics operation duration write", testDiskMetricsOpDurationWrite)
	t.Run("Disk Metrics IO bytes", testDiskMetricsIOBytes)
	t.Run("Disk Metrics IO bytes write volume", testDiskMetricsIOBytesWriteVolume)
	t.Run("Disk Metrics Prometheus exposition", testDiskMetricsPromExposition)
	require.NoError(t, compose.Close())
}
