// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package dontupload contains local regression tests for the metrics-reporter
// eviction fix. These tests are NOT intended for upstream contribution.
//
// Two bugs existed in the original code, both fixed together:
//
//  1. Goroutine leak (memory leak)
//     ForceFlush on eviction does not stop the PeriodicReader background
//     goroutine — only Shutdown does. Over a long run with many distinct
//     services cycling through the LRU cache, goroutines accumulate
//     indefinitely, each holding its metric instruments and data structures.
//
//  2. "failed to upload metrics: HTTP exporter is shutdown"
//     close() fired mr.exporter.Shutdown() in a goroutine with no ordering
//     guarantees. The live PeriodicReader goroutines of still-cached providers
//     kept exporting after the shared exporter was gone.
//
// Both are fixed together:
//   - provider.Shutdown() replaces ForceFlush on eviction → goroutine stops.
//   - noopShutdownExporter wrapper → provider.Shutdown() does NOT propagate to
//     the shared exporter; only MetricsReporter.close() shuts it down, after
//     waiting for all eviction goroutines to finish.
package dontupload_test

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"go.opentelemetry.io/obi/internal/test/collector"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	obiotel "go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const (
	exportInterval  = 20 * time.Millisecond
	evictionTimeout = 5 * time.Second
)

// TestEviction_ExporterRemainsOperational is the regression test for
// "failed to upload metrics: HTTP exporter is shutdown".
//
// It uses a real OTLP HTTP collector so that the real exporter.Shutdown()
// behaviour (marking itself as shut-down) is exercised. With cache size 1,
// the second service immediately evicts the first, calling provider.Shutdown()
// on the evicted entry. Without noopShutdownExporter this would shut down the
// shared exporter and all subsequent Export calls from surviving providers
// would fail silently or log the error.
//
// The test verifies that export records keep arriving at the collector after
// one or more evictions — proving the shared exporter is still alive.
func TestEviction_ExporterRemainsOperational(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	exportMetrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(20))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(10))

	mcfg := &otelcfg.MetricsConfig{
		CommonEndpoint:    otlp.ServerEndpoint,
		MetricsProtocol:   otelcfg.ProtocolHTTPProtobuf,
		Interval:          exportInterval,
		ReportersCacheLen: 1,
		TTL:               time.Minute,
		Instrumentations:  []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
	}

	runFn, err := obiotel.ReportMetrics(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		mcfg,
		&perapp.MetricsConfig{Features: export.FeatureApplicationRED},
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		exportMetrics,
		processEvents,
	)(ctx)
	require.NoError(t, err)
	go runFn(ctx)

	httpSpan := func(name string) request.Span {
		return request.Span{
			Service: svc.Attrs{UID: svc.UID{Name: name}, Features: export.FeatureApplicationRED},
			Type:    request.EventTypeHTTP,
			Method:  "GET",
			Route:   "/ping",
			Status:  200,
		}
	}

	// Phase 1 — service-a fills the single cache slot and exports at least once.
	exportMetrics.Send([]request.Span{httpSpan("service-a")})
	var countAfterA int
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		countAfterA = len(otlp.Records())
		assert.Positive(ct, countAfterA, "expected at least one export from service-a")
	}, evictionTimeout, exportInterval)

	// Phase 2 — service-b evicts service-a; the eviction goroutine calls
	// provider.Shutdown() → PeriodicReader.Shutdown() → noopShutdownExporter.Shutdown() (no-op).
	// Without the fix this call would mark the real exporter as shut-down.
	exportMetrics.Send([]request.Span{httpSpan("service-b")})
	time.Sleep(exportInterval * 5) // let the eviction goroutine complete

	// Phase 3 — service-a re-enters the cache (evicts service-b).
	// If the exporter were shut down the new provider could not export.
	exportMetrics.Send([]request.Span{httpSpan("service-a")})

	countBeforeVerify := len(otlp.Records())
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Greater(ct, len(otlp.Records()), countBeforeVerify,
			"export count stopped growing after eviction — the shared exporter was shut down prematurely")
	}, evictionTimeout, exportInterval)
}

// TestEviction_NoGoroutineLeak is the regression test for the goroutine /
// memory leak surfaced by pprof (43-45 % inuse_space in newMetricSet).
//
// It uses a consumer-based exporter (no network) so the test is fast and
// self-contained. The goroutine lifecycle depends only on whether
// provider.Shutdown() is called on eviction — the exporter type is irrelevant.
//
// The test forces numEvictions LRU evictions and then asserts that the number
// of live PeriodicReader goroutines has not grown by more than +2 above the
// pre-eviction baseline. Without the fix (ForceFlush instead of Shutdown) each
// eviction leaks one goroutine, so the count would grow by ~numEvictions.
func TestEviction_NoGoroutineLeak(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const numEvictions = 10

	var exportCount atomic.Int64
	mcfg := &otelcfg.MetricsConfig{
		Interval:          exportInterval,
		ReportersCacheLen: 1,
		TTL:               time.Minute,
		MetricsConsumer:   &countingConsumer{count: &exportCount},
		Instrumentations:  []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
	}

	exportMetrics := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(numEvictions + 5))
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(10))

	runFn, err := obiotel.ReportMetrics(
		&global.ContextInfo{OTELMetricsExporter: &otelcfg.MetricsExporterInstancer{Cfg: mcfg}},
		mcfg,
		&perapp.MetricsConfig{Features: export.FeatureApplicationRED},
		&attributes.SelectorConfig{},
		request.UnresolvedNames{},
		exportMetrics,
		processEvents,
	)(ctx)
	require.NoError(t, err)
	go runFn(ctx)

	// Wait for the system-metrics provider to be running before taking the baseline.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Positive(ct, exportCount.Load())
	}, evictionTimeout, exportInterval)

	goroutinesBefore := periodicReaderGoroutines()

	// Force numEvictions evictions by cycling through numEvictions+1 service names
	// with a cache size of 1. Each new name evicts the previous entry.
	for i := range numEvictions {
		exportMetrics.Send([]request.Span{{
			Service: svc.Attrs{
				UID:      svc.UID{Name: fmt.Sprintf("svc-%d", i)},
				Features: export.FeatureApplicationRED,
			},
			Type:   request.EventTypeHTTP,
			Method: "GET",
			Route:  "/test",
			Status: 200,
		}})
		// Pause so each span is processed and the eviction callback fires before
		// the next span arrives, keeping evictions clearly sequential.
		time.Sleep(exportInterval)
	}

	// Give the eviction shutdown goroutines time to finish.
	// Each has a timeout of cfg.GetProviderShutdownTimeout() (= Interval = 20ms).
	time.Sleep(exportInterval * 10)
	runtime.GC()     // settle time.AfterFunc callbacks, finalizers, and transient goroutines
	runtime.Gosched()

	goroutinesAfter := periodicReaderGoroutines()

	// Allow at most +2 above the baseline: one for the currently-active service
	// provider and one for any transient state. Without the fix this would be
	// baseline + numEvictions.
	assert.LessOrEqual(t, goroutinesAfter, goroutinesBefore+2,
		"PeriodicReader goroutine count grew by %d after %d evictions (before=%d after=%d). "+
			"Goroutines from evicted providers were not stopped — this is the goroutine leak.",
		goroutinesAfter-goroutinesBefore, numEvictions, goroutinesBefore, goroutinesAfter)
}

// TestProviderShutdownTimeout_Configurable verifies that
// GetProviderShutdownTimeout returns ProviderShutdownTimeout when set
// and falls back to Interval when unset.
func TestProviderShutdownTimeout_Configurable(t *testing.T) {
	fallback := &otelcfg.MetricsConfig{Interval: 5 * time.Second}
	assert.Equal(t, 5*time.Second, fallback.GetProviderShutdownTimeout(),
		"zero ProviderShutdownTimeout should fall back to Interval")

	explicit := &otelcfg.MetricsConfig{
		Interval:                5 * time.Second,
		ProviderShutdownTimeout: 30 * time.Second,
	}
	assert.Equal(t, 30*time.Second, explicit.GetProviderShutdownTimeout(),
		"explicit ProviderShutdownTimeout should take precedence over Interval")
}

// TestExporterInstancer_ShutdownIdempotent verifies that calling
// MetricsExporterInstancer.Shutdown() more than once is safe — the sync.Once
// guard must prevent a double-close of the underlying shared exporter.
func TestExporterInstancer_ShutdownIdempotent(t *testing.T) {
	defer otelcfg.RestoreEnvAfterExecution()()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	otlp, err := collector.Start(ctx)
	require.NoError(t, err)

	instancer := &otelcfg.MetricsExporterInstancer{
		Cfg: &otelcfg.MetricsConfig{
			CommonEndpoint:  otlp.ServerEndpoint,
			MetricsProtocol: otelcfg.ProtocolHTTPProtobuf,
		},
	}

	// Populate i.instance so there is something real to shut down.
	_, err = instancer.Instantiate(ctx)
	require.NoError(t, err)

	// First shutdown must succeed without error.
	require.NoError(t, instancer.Shutdown(ctx), "first Shutdown should return nil")

	// Second shutdown must also succeed (sync.Once prevents double-close).
	require.NoError(t, instancer.Shutdown(ctx), "second Shutdown should return nil (idempotent)")
}

// periodicReaderGoroutines counts live goroutines running
// (*PeriodicReader).run in the OTEL SDK.
func periodicReaderGoroutines() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	stack := string(buf[:n])
	count := 0
	needle := "go.opentelemetry.io/otel/sdk/metric.(*PeriodicReader).run"
	for i := 0; i <= len(stack)-len(needle); i++ {
		if stack[i:i+len(needle)] == needle {
			count++
		}
	}
	return count
}

// countingConsumer is a collector consumer.Metrics that counts calls.
type countingConsumer struct{ count *atomic.Int64 }

func (c *countingConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *countingConsumer) ConsumeMetrics(_ context.Context, _ pmetric.Metrics) error {
	c.count.Add(1)
	return nil
}
