// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg // import "go.opentelemetry.io/obi/pkg/export/otel/otelcfg"

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// NoopShutdownExporter wraps a shared Exporter and turns Shutdown into a no-op.
// This allows individual MeterProviders to call provider.Shutdown() (which stops
// the PeriodicReader goroutine and flushes pending data) without permanently
// marking the shared underlying exporter as shut-down.
// The real exporter is shut down exactly once by MetricsExporterInstancer.Shutdown().
type NoopShutdownExporter struct{ sdkmetric.Exporter }

func (NoopShutdownExporter) Shutdown(context.Context) error { return nil }

func meilog() *slog.Logger {
	return slog.With("component", "otelcommon.MetricsExporterInstancer")
}

// MetricsExporterInstancer provides a common instance for the OTEL metrics exporter,
// so all the OTEL metric families (RED, Network, Service Graph, Internal...) would go through
// the same connection/instance.
// Reporters receive a NoopShutdownExporter wrapper so no individual reporter can
// permanently shut down the shared exporter. Call Shutdown() once after all
// reporters have stopped their MeterProviders.
type MetricsExporterInstancer struct {
	mutex        sync.Mutex
	instance     sdkmetric.Exporter
	Cfg          *MetricsConfig
	shutdownOnce sync.Once
}

// Instantiate returns the shared OTLP/consumer exporter, wrapped in a
// NoopShutdownExporter so that individual reporters cannot permanently shut
// down the shared connection. The real Shutdown is done once by Shutdown().
func (i *MetricsExporterInstancer) Instantiate(ctx context.Context) (sdkmetric.Exporter, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()
	if i.instance != nil {
		wrapped := NoopShutdownExporter{i.instance}
		meilog().Info("DEBUG-LIFECYCLE: Instantiate returning wrapper",
			"path", "cached", "inner_type", fmt.Sprintf("%T", i.instance))
		return wrapped, nil
	}

	// If a MetricsConsumer is configured, use the ConsumerExporter
	if i.Cfg.MetricsConsumer != nil {
		meilog().Debug("instantiating Consumer MetricsReporter")
		i.instance = NewConsumerExporter(i.Cfg.MetricsConsumer)
		meilog().Info("DEBUG-LIFECYCLE: Instantiate returning wrapper",
			"path", "consumer", "inner_type", fmt.Sprintf("%T", i.instance))
		return NoopShutdownExporter{i.instance}, nil
	}

	var err error
	switch proto := i.Cfg.GetProtocol(); proto {
	case ProtocolHTTPJSON, ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
		meilog().Debug("instantiating HTTP MetricsReporter", "protocol", proto)
		if i.instance, err = i.httpMetricsExporter(ctx); err != nil {
			return nil, fmt.Errorf("can't instantiate OTEL HTTP metrics exporter: %w", err)
		}
	case ProtocolGRPC:
		meilog().Debug("instantiating GRPC MetricsReporter", "protocol", proto)
		if i.instance, err = i.grpcMetricsExporter(ctx); err != nil {
			return nil, fmt.Errorf("can't instantiate OTEL GRPC metrics exporter: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, ProtocolGRPC, ProtocolHTTPJSON, ProtocolHTTPProtobuf)
	}
	meilog().Info("DEBUG-LIFECYCLE: Instantiate returning wrapper",
		"path", "otlp", "inner_type", fmt.Sprintf("%T", i.instance))
	return NoopShutdownExporter{i.instance}, nil
}

// Shutdown flushes and closes the underlying shared exporter exactly once.
// Call this after all reporters have shut down their MeterProviders, so no
// PeriodicReader goroutine is still exporting when the connection closes.
func (i *MetricsExporterInstancer) Shutdown(ctx context.Context) error {
	var err error
	i.shutdownOnce.Do(func() {
		meilog().Warn("DEBUG-LIFECYCLE: shutting down real exporter",
			"stack", string(debug.Stack()))
		i.mutex.Lock()
		exp := i.instance
		i.mutex.Unlock()
		if exp != nil {
			err = exp.Shutdown(ctx)
		}
	})
	return err
}

func (i *MetricsExporterInstancer) httpMetricsExporter(ctx context.Context) (sdkmetric.Exporter, error) {
	opts, err := httpMetricEndpointOptions(i.Cfg)
	if err != nil {
		return nil, err
	}
	mexp, err := otlpmetrichttp.New(ctx, opts.AsMetricHTTP()...)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP metric exporter: %w", err)
	}
	return mexp, nil
}

func (i *MetricsExporterInstancer) grpcMetricsExporter(ctx context.Context) (sdkmetric.Exporter, error) {
	opts, err := grpcMetricEndpointOptions(i.Cfg)
	if err != nil {
		return nil, err
	}
	mexp, err := otlpmetricgrpc.New(ctx, opts.AsMetricGRPC()...)
	if err != nil {
		return nil, fmt.Errorf("creating GRPC metric exporter: %w", err)
	}
	return mexp, nil
}
