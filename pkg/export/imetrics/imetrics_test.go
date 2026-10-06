// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/avoidedsvc"
	"go.opentelemetry.io/obi/pkg/internal/errtype"
)

func TestIsBuiltinNoopReporter(t *testing.T) {
	t.Run("noop reporter value", func(t *testing.T) {
		assert.True(t, IsBuiltinNoopReporter(NoopReporter{}))
	})

	t.Run("noop reporter pointer", func(t *testing.T) {
		assert.True(t, IsBuiltinNoopReporter(&NoopReporter{}))
	})

	t.Run("prometheus reporter", func(t *testing.T) {
		reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, prometheus.NewRegistry())
		assert.False(t, IsBuiltinNoopReporter(reporter))
	})

	t.Run("noop embedder is not builtin noop", func(t *testing.T) {
		reporter := &noopEmbeddingReporter{}
		assert.False(t, IsBuiltinNoopReporter(reporter))
	})

	t.Run("nil reporter", func(t *testing.T) {
		assert.False(t, IsBuiltinNoopReporter(nil))
	})
}

func TestPrometheusReporterQueueBufferUtilization(t *testing.T) {
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, prometheus.NewRegistry())

	gaugeValue := func(subscriber string) float64 {
		var m dto.Metric
		require.NoError(t, reporter.queueCapacityRatio.WithLabelValues(subscriber).Write(&m))
		return m.GetGauge().GetValue()
	}

	reporter.QueueBufferUtilization("traces", 0.42)
	reporter.QueueBufferUtilization("metrics", 0.1)

	assert.InDelta(t, 0.42, gaugeValue("traces"), 0.001)
	assert.InDelta(t, 0.1, gaugeValue("metrics"), 0.001)

	// a later update overwrites the previous value for the same subscriber
	reporter.QueueBufferUtilization("traces", 0.9)
	assert.InDelta(t, 0.9, gaugeValue("traces"), 0.001)
}

func TestPrometheusReporterBpfStorageDrops(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, registry)

	reporter.BpfStorageDrops("fs_accum_full", 3)
	reporter.BpfStorageDrops("fs_start_failed", 1)
	reporter.BpfStorageDrops("fs_accum_full", 2)

	families, err := registry.Gather()
	require.NoError(t, err)
	got := map[string]float64{}
	for _, family := range families {
		if family.GetName() != "obi_bpf_storage_dropped_operations_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			require.Len(t, m.GetLabel(), 1)
			assert.Equal(t, "bpf_drop_reason", m.GetLabel()[0].GetName())
			got[m.GetLabel()[0].GetValue()] = m.GetCounter().GetValue()
		}
	}
	assert.Equal(t, map[string]float64{"fs_accum_full": 5, "fs_start_failed": 1}, got)
}

func TestPrometheusReporterBpfStorageRecursionMisses(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, registry)

	reporter.BpfStorageRecursionMisses("obi_stats_tp_block_rq_issue", 3)
	reporter.BpfStorageRecursionMisses("obi_stats_tp_block_rq_issue", 2)
	reporter.BpfStorageRecursionMisses("obi_stats_kprobe_nfs_read", 1)

	families, err := registry.Gather()
	require.NoError(t, err)
	got := map[string]float64{}
	for _, family := range families {
		if family.GetName() != "obi_bpf_storage_program_recursion_misses_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			require.Len(t, m.GetLabel(), 1)
			assert.Equal(t, "bpf_probe_name", m.GetLabel()[0].GetName())
			got[m.GetLabel()[0].GetValue()] = m.GetCounter().GetValue()
		}
	}
	assert.Equal(t, map[string]float64{"obi_stats_tp_block_rq_issue": 5, "obi_stats_kprobe_nfs_read": 1}, got)
}

type noopEmbeddingReporter struct {
	NoopReporter
}

func (n *noopEmbeddingReporter) BpfProbeStats(_, _, _ string, _ uint64, _ float64, _ map[float64]uint64) {
}

func TestPrometheusReporterAvoidedServicesBounded(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{
		AvoidedServices: AvoidedServicesConfig{Limit: 3},
	}, nil, registry)

	reporter.AvoidInstrumentationMetrics("svc-0", "ns-0", "inst-0")
	reporter.AvoidInstrumentationTraces("svc-0", "ns-0", "inst-0")
	reporter.AvoidInstrumentationMetrics("svc-1", "ns-1", "inst-1")
	reporter.AvoidInstrumentationTraces("svc-1", "ns-1", "inst-1")

	metrics := gatherAvoidedServices(t, registry)
	require.Len(t, metrics, 3)

	labelSets := map[string]struct{}{}
	overflowRecords := 0
	for _, metric := range metrics {
		labels := metricLabels(metric)
		if labels[avoidedsvc.PrometheusOverflowLabel] == "true" {
			overflowRecords++
			assert.Empty(t, labels["service_name"])
			assert.Empty(t, labels["service_namespace"])
			assert.Empty(t, labels["telemetry_type"])
			continue
		}

		assert.Equal(t, "false", labels[avoidedsvc.PrometheusOverflowLabel])
		labelSets[labels["service_name"]+"/"+
			labels["service_namespace"]+"/"+
			labels["telemetry_type"]] = struct{}{}
	}

	assert.Contains(t, labelSets, "svc-0/ns-0/metrics")
	assert.Contains(t, labelSets, "svc-0/ns-0/traces")
	assert.Equal(t, 1, overflowRecords)
}

func TestPrometheusReporterAvoidedServicesDisabled(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{
		AvoidedServices: AvoidedServicesConfig{Disabled: true},
	}, nil, registry)

	reporter.AvoidInstrumentationMetrics("svc-0", "ns-0", "inst-0")

	mfs, err := registry.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		assert.NotEqual(t, attr.VendorPrefix+"_avoided_services", mf.GetName())
	}
}

// The export-error label is semconv error.type carrying a low-cardinality class, not the error
// message, which would mint a series per distinct failure. Pinned by literal so the derivation
// cannot silently rename an exported label.
func TestPrometheusReporterExportErrorType(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, registry)

	reporter.OTELMetricExportError(status.Error(codes.DeadlineExceeded, "ctx deadline: 10.1.2.3:4317"))
	reporter.OTELTraceExportError(errors.New("plain failure"))

	families, err := registry.Gather()
	require.NoError(t, err)

	found := map[string]string{}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			if label, ok := metricLabels(metric)["error_type"]; ok {
				found[family.GetName()] = label
			}
		}
	}

	assert.Equal(t, map[string]string{
		"obi_otel_metric_export_errors_total": "DEADLINE_EXCEEDED",
		"obi_otel_trace_export_errors_total":  errtype.Other,
	}, found)
}

// process_executable_name replaced process_name on both metrics carrying it.
func TestPrometheusReporterProcessLabel(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, registry)

	reporter.InstrumentProcess("my-service")
	reporter.InstrumentationError("my-service", "attaching_uprobe")

	families, err := registry.Gather()
	require.NoError(t, err)

	labeled := map[string]string{}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			if name, ok := metricLabels(metric)["process_executable_name"]; ok {
				labeled[family.GetName()] = name
			}
		}
	}

	assert.Equal(t, map[string]string{
		"obi_instrumented_processes":       "my-service",
		"obi_instrumentation_errors_total": "my-service",
	}, labeled)
}

func gatherAvoidedServices(t *testing.T, registry *prometheus.Registry) []*dto.Metric {
	t.Helper()

	mfs, err := registry.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == attr.VendorPrefix+"_avoided_services" {
			return mf.GetMetric()
		}
	}
	require.Fail(t, "missing avoided services metric")
	return nil
}

func metricLabels(metric *dto.Metric) map[string]string {
	labels := map[string]string{}
	for _, pair := range metric.GetLabel() {
		labels[pair.GetName()] = pair.GetValue()
	}
	return labels
}
