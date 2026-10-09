// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestStat_GoStatMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-stat-metrics.yml", path.Join(pathOutput, "test-suite-go-stat-metrics.log"))
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=8381:8080`, `OTEL_EBPF_CONFIG_SUFFIX=-go-stat-metrics`, `PROM_CONFIG_SUFFIX=-promscrape-otel`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Run("Go Stat Metrics TCP RTT tests", testStatMetricsTCPRttGo)
	t.Run("Go Stat Metrics TCP Failed Connection tests", testStatMetricsTCPFailedConnectionsGo)
	t.Run("Go Stat Metrics TCP Successful Connection tests", testStatMetricsTCPSuccessfulConnectionsGo)
	t.Run("Go Stat Metrics TCP Retransmits tests", testStatMetricsTCPRetransmitsGo)
	t.Run("Go Stat Metrics TCP IO tests", testStatMetricsTCPIoGo)
	t.Run("Go Stat Metrics exclude storage stats", testStatMetricsNoStorageStats)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestStat_GoDiskStatMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-disk-stat-metrics.yml", path.Join(pathOutput, "test-suite-go-disk-stat-metrics.log"))
	compose.Env = append(compose.Env, `OTEL_EBPF_CONFIG_SUFFIX=-go-disk-stat-metrics`, `PROM_CONFIG_SUFFIX=-promscrape-otel`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	containerID, err := compose.ContainerID("disk-io")
	require.NoError(t, err)
	require.Len(t, containerID, 64)
	t.Run("Go Stat Metrics disk service duration tests", func(t *testing.T) {
		testStatMetricsDiskServiceDuration(t, containerID)
	})
	t.Run("Go Stat Metrics disk counters tests", func(t *testing.T) {
		testStatMetricsDiskCounters(t, containerID)
	})
	t.Run("Go Stat Metrics file sync duration tests", func(t *testing.T) {
		testStatMetricsFsSyncDuration(t, containerID)
	})
	t.Run("Go Stat Metrics file sync counters tests", func(t *testing.T) {
		testStatMetricsFsSyncCounters(t, containerID)
	})
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}
