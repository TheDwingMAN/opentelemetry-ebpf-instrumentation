// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	metric2 "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const statScopeName = "stats_ebpf_events"

// StatMetricsConfig extends MetricsConfig for Statistical Metrics
type StatMetricsConfig struct {
	Metrics     *otelcfg.MetricsConfig
	CommonCfg   *perapp.GlobalMetricsConfig
	SelectorCfg *attributes.SelectorConfig
}

func (mc *StatMetricsConfig) Enabled() bool {
	return mc.Metrics != nil && mc.Metrics.EndpointEnabled() &&
		mc.CommonCfg.Features.StatMetrics()
}

func smlog() *slog.Logger {
	return slog.With("component", "otel.StatMetricsExporter")
}

// getFilteredStatsResourceAttrs returns resource attributes that can be filtered based on the attribute selector
// for statistical metrics.
func getFilteredStatsResourceAttrs(hostID string, attrSelector attributes.Selection) []attribute.KeyValue {
	baseAttrs := []attribute.KeyValue{
		attribute.String(attr.VendorPrefix+string(attr.VendorVersionSuffix), buildinfo.Version),
		attribute.String(attr.VendorPrefix+string(attr.VendorRevisionSuffix), buildinfo.Revision),
		semconv.TelemetryDistroName(attr.TelemetryDistroName),
		semconv.TelemetryDistroVersion(attr.TelemetryDistroVersion()),
	}

	extraAttrs := []attribute.KeyValue{
		semconv.HostID(hostID),
	}

	return otelcfg.GetFilteredAttributesByPrefix(baseAttrs, attrSelector, extraAttrs, []string{"stats.", attr.VendorPrefix + ".stats"})
}

func createFilteredStatsResource(hostID string, attrSelector attributes.Selection) *resource.Resource {
	attrs := getFilteredStatsResourceAttrs(hostID, attrSelector)
	return resource.NewWithAttributes(attr.OBISchemaURL, attrs...)
}

func newStatMeterProvider(res *resource.Resource, exporter *sdkmetric.Exporter, interval time.Duration, cfg *otelcfg.MetricsConfig,
	kernelHistograms *kernelHistogramProducer,
) *metric.MeterProvider {
	isExponential := cfg.HistogramAggregation == otelcfg.HistogramAggregationExponential
	if !isExponential && cfg.HistogramAggregation != otelcfg.HistogramAggregationExplicit {
		smlog().Warn("invalid value for histogram aggregation. Accepted values are: "+
			string(otelcfg.HistogramAggregationExponential)+", "+string(otelcfg.HistogramAggregationExplicit)+" (default). Using default",
			"value", cfg.HistogramAggregation)
	}
	return metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter, metric.WithInterval(interval),
			metric.WithProducer(kernelHistograms))),
		metric.WithView(statHistogramView(attributes.StatTCPRtt.OTEL, cfg.Buckets.StatTCPRttHistogram, isExponential, cfg.ExponentialHistogram)),
	)
}

func statHistogramView(metricName string, buckets []float64, isExponential bool, expCfg otelcfg.ExponentialHistogramConfig) metric.View {
	return newHistogramView(metricName, statScopeName, buckets, isExponential, expCfg)
}

type statMetricsExporter struct {
	tcpRtt                   *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	tcpFailedConnections     *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	tcpRetransmits           *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	tcpIo                    *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	tcpSuccessfulConnections *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	diskServiceDuration      *kernelHistogram
	diskIO                   *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	diskOperations           *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	diskServiceTime          *Expirer[*ebpf.Stat, metric2.Float64Counter, float64]
	fsSyncDuration           *kernelHistogram
	fsSyncOperations         *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	fsSyncTime               *Expirer[*ebpf.Stat, metric2.Float64Counter, float64]
	kernelHistograms         *kernelHistogramProducer
	expireTTL                time.Duration
	in                       <-chan []*ebpf.Stat
}

func StatMetricsExporterProvider(
	ctxInfo *global.ContextInfo,
	cfg *StatMetricsConfig,
	input *msg.Queue[[]*ebpf.Stat],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the swarm library just ignore it.
			return swarm.EmptyRunFunc()
		}
		if cfg.SelectorCfg.SelectionCfg == nil {
			cfg.SelectorCfg.SelectionCfg = make(attributes.Selection)
		}
		exporter, err := newStatMetricsExporter(ctx, ctxInfo, cfg, input)
		if err != nil {
			return nil, err
		}
		return exporter.Do, nil
	}
}

func newStatMetricsExporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *StatMetricsConfig,
	input *msg.Queue[[]*ebpf.Stat],
) (*statMetricsExporter, error) {
	log := smlog()
	log.Debug("instantiating stat metrics exporter provider")
	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		log.Error("can't instantiate metrics exporter", "error", err)
		return nil, err
	}
	exporter = instrumentMetricsExporter(ctxInfo.Metrics, exporter)

	resource := createFilteredStatsResource(ctxInfo.NodeMeta.HostID, cfg.SelectorCfg.SelectionCfg)
	kernelHistograms := newKernelHistogramProducer(exporter.Temporality(sdkmetric.InstrumentKindHistogram), cfg.Metrics.TTL)
	provider := newStatMeterProvider(resource, &exporter, cfg.Metrics.Interval, cfg.Metrics, kernelHistograms)

	attrProv, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, cfg.SelectorCfg)
	if err != nil {
		return nil, fmt.Errorf("stats OTEL exporter attributes enable: %w", err)
	}

	ebpfEvents := provider.Meter(statScopeName)

	nme := &statMetricsExporter{
		kernelHistograms: kernelHistograms,
		expireTTL:        cfg.Metrics.TTL,
	}

	if cfg.CommonCfg.Features.StatsTCPRtt() {
		log := log.With("metricFamily", "StatsTCPRtt")

		tcpRtt, err := ebpfEvents.Float64Histogram(
			attributes.StatTCPRtt.OTEL,
			metric2.WithUnit(attributes.StatTCPRtt.Unit),
		)
		if err != nil {
			log.Error("creating stats tcp rtt histogram", "error", err)
			return nil, err
		}

		log.Debug("restricting attributes not in this list", "attributes", cfg.SelectorCfg.SelectionCfg)
		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPRtt))

		nme.tcpRtt = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, tcpRtt, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsTCPRetransmits() {
		log := log.With("metricFamily", "StatsTCPRetransmits")

		tcpRetransmits, err := ebpfEvents.Int64Counter(attributes.StatTCPRetransmits.OTEL)
		if err != nil {
			log.Error("creating stats tcp retransmits counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPRetransmits))

		nme.tcpRetransmits = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, tcpRetransmits, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsTCPIo() {
		log := log.With("metricFamily", "StatsTCPIo")

		tcpIo, err := ebpfEvents.Int64Counter(attributes.StatTCPIo.OTEL, metric2.WithUnit(attributes.StatTCPIo.Unit))
		if err != nil {
			log.Error("creating stats tcp io counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPIo))

		nme.tcpIo = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, tcpIo, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsTCPFailedConnections() {
		log := log.With("metricFamily", "StatsTCPFailedConnections")

		tcpFailedConnections, err := ebpfEvents.Int64Counter(attributes.StatTCPFailedConnections.OTEL)
		if err != nil {
			log.Error("creating stats tcp failed connection counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPFailedConnections))

		nme.tcpFailedConnections = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, tcpFailedConnections, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsTCPSuccessfulConnections() {
		log := log.With("metricFamily", "StatsTCPSuccessfulConnections")

		tcpSuccessfulConnections, err := ebpfEvents.Int64Counter(attributes.StatTCPSuccessfulConnections.OTEL)
		if err != nil {
			log.Error("creating stats tcp successful connection counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatTCPSuccessfulConnections))

		nme.tcpSuccessfulConnections = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, tcpSuccessfulConnections, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsDiskServiceDuration() {
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskServiceDuration))
		nme.diskServiceDuration = kernelHistograms.histogram(attributes.StatDiskServiceDuration, export.DiskLatencyBounds, attrs)
	}

	if cfg.CommonCfg.Features.StatsDiskIO() {
		diskIO, err := ebpfEvents.Int64Counter(attributes.StatDiskIO.OTEL, metric2.WithUnit(attributes.StatDiskIO.Unit))
		if err != nil {
			return nil, fmt.Errorf("creating stats disk io counter: %w", err)
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskIO))
		nme.diskIO = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, diskIO, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsDiskOperations() {
		diskOperations, err := ebpfEvents.Int64Counter(attributes.StatDiskOperations.OTEL,
			metric2.WithUnit(attributes.StatDiskOperations.Unit))
		if err != nil {
			return nil, fmt.Errorf("creating stats disk operations counter: %w", err)
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskOperations))
		nme.diskOperations = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, diskOperations, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsDiskServiceTime() {
		diskServiceTime, err := ebpfEvents.Float64Counter(attributes.StatDiskServiceTime.OTEL,
			metric2.WithUnit(attributes.StatDiskServiceTime.Unit))
		if err != nil {
			return nil, fmt.Errorf("creating stats disk service time counter: %w", err)
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskServiceTime))
		nme.diskServiceTime = NewExpirer[*ebpf.Stat, metric2.Float64Counter, float64](ctx, diskServiceTime, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsFsSyncDuration() {
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatFsSyncDuration))
		nme.fsSyncDuration = kernelHistograms.histogram(attributes.StatFsSyncDuration, export.DiskLatencyBounds, attrs)
	}

	if cfg.CommonCfg.Features.StatsFsSyncOperations() {
		fsSyncOperations, err := ebpfEvents.Int64Counter(attributes.StatFsSyncOperations.OTEL,
			metric2.WithUnit(attributes.StatFsSyncOperations.Unit))
		if err != nil {
			return nil, fmt.Errorf("creating stats fs sync operations counter: %w", err)
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatFsSyncOperations))
		nme.fsSyncOperations = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, fsSyncOperations, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsFsSyncTime() {
		fsSyncTime, err := ebpfEvents.Float64Counter(attributes.StatFsSyncTime.OTEL,
			metric2.WithUnit(attributes.StatFsSyncTime.Unit))
		if err != nil {
			return nil, fmt.Errorf("creating stats fs sync time counter: %w", err)
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatFsSyncTime))
		nme.fsSyncTime = NewExpirer[*ebpf.Stat, metric2.Float64Counter, float64](ctx, fsSyncTime, attrs, timeNow, cfg.Metrics.TTL)
	}

	nme.in = input.Subscribe(msg.SubscriberName("otel.StatMetricsExporter"))
	return nme, nil
}

func (me *statMetricsExporter) Do(ctx context.Context) {
	for i := range me.in {
		for _, v := range i {
			if me.tcpRtt != nil && v.TCPRtt != nil {
				tcpRtt, attrs := me.tcpRtt.ForRecord(v)
				tcpRtt.Record(ctx, float64(v.TCPRtt.SrttUs)/1_000_000.0, metric2.WithAttributeSet(attrs))
			}
			if me.tcpFailedConnections != nil && v.TCPFailedConnection != nil {
				tcpFailedConnections, attrs := me.tcpFailedConnections.ForRecord(v)
				tcpFailedConnections.Add(ctx, 1, metric2.WithAttributeSet(attrs))
			}
			if me.tcpSuccessfulConnections != nil && v.TCPSuccessfulConnection != nil {
				tcpSuccessfulConnections, attrs := me.tcpSuccessfulConnections.ForRecord(v)
				tcpSuccessfulConnections.Add(ctx, 1, metric2.WithAttributeSet(attrs))
			}
			if me.tcpRetransmits != nil && v.TCPRetransmit {
				tcpRetransmits, attrs := me.tcpRetransmits.ForRecord(v)
				tcpRetransmits.Add(ctx, 1, metric2.WithAttributeSet(attrs))
			}
			if me.tcpIo != nil && v.TCPIo != nil {
				tcpIo, attrs := me.tcpIo.ForRecord(v)
				tcpIo.Add(ctx, int64(v.TCPIo.Bytes), metric2.WithAttributeSet(attrs))
			}
			if v.DiskIO != nil {
				me.recordDiskIO(ctx, v)
			}
			if v.FsSync != nil {
				me.recordFsSync(ctx, v)
			}
		}
	}
}

func (me *statMetricsExporter) recordDiskIO(ctx context.Context, v *ebpf.Stat) {
	if me.diskServiceDuration != nil && !v.DiskIO.MultipathPath {
		me.kernelHistograms.record(me.diskServiceDuration, v, &v.DiskIO.Latency)
	}
	if me.diskIO != nil && v.DiskIO.Bytes > 0 {
		diskIO, attrs := me.diskIO.ForRecord(v)
		diskIO.Add(ctx, int64(v.DiskIO.Bytes), metric2.WithAttributeSet(attrs))
	}
	if me.diskOperations != nil {
		diskOperations, attrs := me.diskOperations.ForRecord(v)
		diskOperations.Add(ctx, int64(v.DiskIO.Latency.Count()), metric2.WithAttributeSet(attrs))
	}
	if me.diskServiceTime != nil {
		diskServiceTime, attrs := me.diskServiceTime.ForRecord(v)
		diskServiceTime.Add(ctx, v.DiskIO.Latency.Sum, metric2.WithAttributeSet(attrs))
	}
}

func (me *statMetricsExporter) recordFsSync(ctx context.Context, v *ebpf.Stat) {
	if me.fsSyncDuration != nil {
		me.kernelHistograms.record(me.fsSyncDuration, v, &v.FsSync.Latency)
	}
	if me.fsSyncOperations != nil {
		fsSyncOperations, attrs := me.fsSyncOperations.ForRecord(v)
		fsSyncOperations.Add(ctx, int64(v.FsSync.Latency.Count()), metric2.WithAttributeSet(attrs))
	}
	if me.fsSyncTime != nil {
		fsSyncTime, attrs := me.fsSyncTime.ForRecord(v)
		fsSyncTime.Add(ctx, v.FsSync.Latency.Sum, metric2.WithAttributeSet(attrs))
	}
}
