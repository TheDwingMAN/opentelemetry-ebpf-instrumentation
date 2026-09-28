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

func newStatMeterProvider(res *resource.Resource, exporter *sdkmetric.Exporter, interval time.Duration, cfg *otelcfg.MetricsConfig) *metric.MeterProvider {
	isExponential := cfg.HistogramAggregation == otelcfg.HistogramAggregationExponential
	if !isExponential && cfg.HistogramAggregation != otelcfg.HistogramAggregationExplicit {
		smlog().Warn("invalid value for histogram aggregation. Accepted values are: "+
			string(otelcfg.HistogramAggregationExponential)+", "+string(otelcfg.HistogramAggregationExplicit)+" (default). Using default",
			"value", cfg.HistogramAggregation)
	}
	return metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter, metric.WithInterval(interval))),
		metric.WithView(statHistogramView(attributes.StatTCPRtt.OTEL, cfg.Buckets.StatTCPRttHistogram, isExponential, cfg.ExponentialHistogram)),
		metric.WithView(statHistogramView(attributes.StatDiskOperationDuration.OTEL, cfg.Buckets.StatDiskOperationDurationHistogram, isExponential, cfg.ExponentialHistogram)),
		metric.WithView(statHistogramView(attributes.StatFsSyncDuration.OTEL, cfg.Buckets.StatFsSyncDurationHistogram, isExponential, cfg.ExponentialHistogram)),
		metric.WithView(statHistogramView(attributes.StatDiskQueueDuration.OTEL, cfg.Buckets.StatDiskQueueDurationHistogram, isExponential, cfg.ExponentialHistogram)),
		metric.WithView(statHistogramView(attributes.StatDiskFlushDuration.OTEL, cfg.Buckets.StatDiskFlushDurationHistogram, isExponential, cfg.ExponentialHistogram)),
		metric.WithView(statHistogramView(attributes.StatDiskDiscardDuration.OTEL, cfg.Buckets.StatDiskDiscardDurationHistogram, isExponential, cfg.ExponentialHistogram)),
		metric.WithView(statHistogramView(attributes.StatNFSClientProcedureDuration.OTEL, cfg.Buckets.StatNFSClientProcedureDurationHistogram, isExponential, cfg.ExponentialHistogram)),
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
	diskOperationDuration    *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	diskIO                   *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	diskOperations           *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	diskOperationTime        *Expirer[*ebpf.Stat, metric2.Float64Counter, float64]
	fsSyncDuration           *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	diskQueueDuration        *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	diskFlushDuration        *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	diskDiscardDuration      *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	diskDiscardIO            *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	diskPendingOperations    *currentUpDownCounter[*ebpf.Stat]
	nfsProcedureDuration     *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	nfsIO                    *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
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
	provider := newStatMeterProvider(resource, &exporter, cfg.Metrics.Interval, cfg.Metrics)

	attrProv, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, cfg.SelectorCfg)
	if err != nil {
		return nil, fmt.Errorf("stats OTEL exporter attributes enable: %w", err)
	}

	ebpfEvents := provider.Meter(statScopeName)

	nme := &statMetricsExporter{
		expireTTL: cfg.Metrics.TTL,
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

	if cfg.CommonCfg.Features.StatsDiskOperationDuration() {
		log := log.With("metricFamily", "StatsDiskOperationDuration")

		diskOperationDuration, err := ebpfEvents.Float64Histogram(
			attributes.StatDiskOperationDuration.OTEL,
			metric2.WithUnit(attributes.StatDiskOperationDuration.Unit),
		)
		if err != nil {
			log.Error("creating stats disk operation duration histogram", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatDiskOperationDuration))

		nme.diskOperationDuration = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, diskOperationDuration, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsDiskIO() {
		diskIO, err := ebpfEvents.Int64Counter(attributes.StatDiskIO.OTEL, metric2.WithUnit(attributes.StatDiskIO.Unit))
		if err != nil {
			log.Error("creating stats disk io counter", "error", err)
			return nil, err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskIO))
		nme.diskIO = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, diskIO, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsDiskOperations() {
		diskOperations, err := ebpfEvents.Int64Counter(attributes.StatDiskOperations.OTEL, metric2.WithUnit(attributes.StatDiskOperations.Unit))
		if err != nil {
			log.Error("creating stats disk operations counter", "error", err)
			return nil, err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskOperations))
		nme.diskOperations = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, diskOperations, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsDiskOperationTime() {
		diskOperationTime, err := ebpfEvents.Float64Counter(attributes.StatDiskOperationTime.OTEL, metric2.WithUnit(attributes.StatDiskOperationTime.Unit))
		if err != nil {
			log.Error("creating stats disk operation time counter", "error", err)
			return nil, err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskOperationTime))
		nme.diskOperationTime = NewExpirer[*ebpf.Stat, metric2.Float64Counter, float64](ctx, diskOperationTime, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsFsSyncDuration() {
		fsSyncDuration, err := ebpfEvents.Float64Histogram(attributes.StatFsSyncDuration.OTEL, metric2.WithUnit(attributes.StatFsSyncDuration.Unit))
		if err != nil {
			log.Error("creating stats file sync duration histogram", "error", err)
			return nil, err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatFsSyncDuration))
		nme.fsSyncDuration = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, fsSyncDuration, attrs, timeNow, cfg.Metrics.TTL)
	}

	if err := nme.createDiskOperationMetrics(ctx, ebpfEvents, attrProv, cfg, log); err != nil {
		return nil, err
	}

	if err := nme.createNFSMetrics(ctx, ebpfEvents, attrProv, cfg, log); err != nil {
		return nil, err
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
			if me.diskPendingOperations != nil && v.DiskPending != nil {
				me.diskPendingOperations.Record(v, v.DiskPending.Requests)
			}
			if me.fsSyncDuration != nil && v.FsSync != nil {
				fsSyncDuration, attrs := me.fsSyncDuration.ForRecord(v)
				recordLatency(ctx, fsSyncDuration, v.FsSync.Latency, metric2.WithAttributeSet(attrs))
			}
			if v.NFSProcedure != nil {
				recordLatencyIn(ctx, me.nfsProcedureDuration, v, v.NFSProcedure.Latency)
			}
			if me.nfsIO != nil && v.NFSIO != nil {
				nfsIO, attrs := me.nfsIO.ForRecord(v)
				nfsIO.Add(ctx, int64(v.NFSIO.Bytes), metric2.WithAttributeSet(attrs))
			}
		}
	}
}

// createDiskOperationMetrics creates the metrics of the block requests beyond reads and writes: their
// wait before issue, flushes, discards and the requests in flight
func (me *statMetricsExporter) createDiskOperationMetrics(
	ctx context.Context,
	meter metric2.Meter,
	attrProv *attributes.AttrSelector,
	cfg *StatMetricsConfig,
	log *slog.Logger,
) error {
	features := cfg.CommonCfg.Features
	histograms := []struct {
		enabled bool
		name    attributes.Name
		dst     **Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	}{
		{features.StatsDiskQueueDuration(), attributes.StatDiskQueueDuration, &me.diskQueueDuration},
		{features.StatsDiskFlush(), attributes.StatDiskFlushDuration, &me.diskFlushDuration},
		{features.StatsDiskDiscard(), attributes.StatDiskDiscardDuration, &me.diskDiscardDuration},
	}
	for _, h := range histograms {
		if !h.enabled {
			continue
		}
		histogram, err := meter.Float64Histogram(h.name.OTEL, metric2.WithUnit(h.name.Unit))
		if err != nil {
			log.Error("creating stats histogram", "metric", h.name.OTEL, "error", err)
			return err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(h.name))
		*h.dst = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, histogram, attrs, timeNow, cfg.Metrics.TTL)
	}

	if features.StatsDiskDiscard() {
		discardIO, err := meter.Int64Counter(attributes.StatDiskDiscardIO.OTEL, metric2.WithUnit(attributes.StatDiskDiscardIO.Unit))
		if err != nil {
			log.Error("creating stats disk discard io counter", "error", err)
			return err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskDiscardIO))
		me.diskDiscardIO = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, discardIO, attrs, timeNow, cfg.Metrics.TTL)
	}

	if features.StatsDiskPendingOperations() {
		pending, err := meter.Int64UpDownCounter(attributes.StatDiskPendingOperations.OTEL,
			metric2.WithUnit(attributes.StatDiskPendingOperations.Unit))
		if err != nil {
			log.Error("creating stats disk pending operations counter", "error", err)
			return err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskPendingOperations))
		me.diskPendingOperations = newCurrentUpDownCounter(ctx, pending, attrs, timeNow, cfg.Metrics.TTL)
	}
	return nil
}

// createNFSMetrics creates the metrics of the NFS client
func (me *statMetricsExporter) createNFSMetrics(
	ctx context.Context,
	meter metric2.Meter,
	attrProv *attributes.AttrSelector,
	cfg *StatMetricsConfig,
	log *slog.Logger,
) error {
	features := cfg.CommonCfg.Features
	if features.StatsNFSClientProcedureDuration() {
		name := attributes.StatNFSClientProcedureDuration
		histogram, err := meter.Float64Histogram(name.OTEL, metric2.WithUnit(name.Unit))
		if err != nil {
			log.Error("creating stats NFS client procedure duration histogram", "error", err)
			return err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(name))
		me.nfsProcedureDuration = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, histogram, attrs, timeNow, cfg.Metrics.TTL)
	}

	if features.StatsNFSClientIO() {
		name := attributes.StatNFSClientIO
		counter, err := meter.Int64Counter(name.OTEL, metric2.WithUnit(name.Unit))
		if err != nil {
			log.Error("creating stats NFS client io counter", "error", err)
			return err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(name))
		me.nfsIO = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, counter, attrs, timeNow, cfg.Metrics.TTL)
	}
	return nil
}

// recordDiskIO records the block requests of a stat into the metrics of their operation
func (me *statMetricsExporter) recordDiskIO(ctx context.Context, v *ebpf.Stat) {
	switch v.DiskIO.Op {
	case ebpf.CodeDiskOpRead, ebpf.CodeDiskOpWrite:
		me.recordDiskCounters(ctx, v)
		recordLatencyIn(ctx, me.diskOperationDuration, v, v.DiskIO.Latency)
		recordLatencyIn(ctx, me.diskQueueDuration, v, v.DiskIO.Queue)
	case ebpf.CodeDiskOpFlush:
		recordLatencyIn(ctx, me.diskFlushDuration, v, v.DiskIO.Latency)
	case ebpf.CodeDiskOpDiscard:
		recordLatencyIn(ctx, me.diskDiscardDuration, v, v.DiskIO.Latency)
		if me.diskDiscardIO != nil && v.DiskIO.Bytes > 0 {
			discardIO, attrs := me.diskDiscardIO.ForRecord(v)
			discardIO.Add(ctx, int64(v.DiskIO.Bytes), metric2.WithAttributeSet(attrs))
		}
	}
}

func recordLatencyIn(ctx context.Context, histogram *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64], v *ebpf.Stat, latency []ebpf.LatencySample) {
	if histogram == nil || len(latency) == 0 {
		return
	}
	h, attrs := histogram.ForRecord(v)
	recordLatency(ctx, h, latency, metric2.WithAttributeSet(attrs))
}

func (me *statMetricsExporter) recordDiskCounters(ctx context.Context, v *ebpf.Stat) {
	if me.diskIO != nil && v.DiskIO.Bytes > 0 {
		diskIO, attrs := me.diskIO.ForRecord(v)
		diskIO.Add(ctx, int64(v.DiskIO.Bytes), metric2.WithAttributeSet(attrs))
	}
	if me.diskOperations != nil {
		diskOperations, attrs := me.diskOperations.ForRecord(v)
		diskOperations.Add(ctx, int64(v.DiskIO.Operations), metric2.WithAttributeSet(attrs))
	}
	if me.diskOperationTime != nil {
		diskOperationTime, attrs := me.diskOperationTime.ForRecord(v)
		diskOperationTime.Add(ctx, v.DiskIO.Time, metric2.WithAttributeSet(attrs))
	}
}

// recordLatency records each kernel histogram bucket sample as many times as requests it stands for
func recordLatency(ctx context.Context, histogram metric2.Float64Histogram, latency []ebpf.LatencySample, attrs metric2.RecordOption) {
	for _, sample := range latency {
		for range sample.Count {
			histogram.Record(ctx, sample.Seconds, attrs)
		}
	}
}
