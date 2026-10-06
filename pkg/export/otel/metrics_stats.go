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
		// Shares StatDiskOperationDurationHistogram buckets: both are block I/O
		// latency histograms in seconds, just measuring different intervals of
		// the same request (queue wait vs. service time).
		metric.WithView(statHistogramView(attributes.StatDiskQueueDuration.OTEL, cfg.Buckets.StatDiskOperationDurationHistogram, isExponential, cfg.ExponentialHistogram)),
		metric.WithView(statHistogramView(attributes.StatDiskQueueDepth.OTEL, cfg.Buckets.StatDiskQueueDepthHistogram, isExponential, cfg.ExponentialHistogram)),
		metric.WithView(statHistogramView(attributes.StatFsOperationDuration.OTEL, cfg.Buckets.StatFsOperationDurationHistogram, isExponential, cfg.ExponentialHistogram)),
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
	diskOpDuration           *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	diskIOBytes              *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	diskQueueDuration        *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	diskQueueDepth           *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	diskOpErrors             *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	fsOpDuration             *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]
	fsIOBytes                *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	fsOpErrors               *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
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

	if cfg.CommonCfg.Features.StorageBlockDuration() {
		log := log.With("metricFamily", "StorageBlockDuration")

		h, err := ebpfEvents.Float64Histogram(attributes.StatDiskOperationDuration.OTEL, metric2.WithUnit("s"))
		if err != nil {
			log.Error("creating disk operation duration histogram", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatDiskOperationDuration))

		nme.diskOpDuration = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, h, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StorageBlockIo() {
		log := log.With("metricFamily", "StorageBlockIo")

		diskIOBytes, err := ebpfEvents.Int64Counter(attributes.StatDiskIO.OTEL, metric2.WithUnit("By"))
		if err != nil {
			log.Error("creating disk io bytes counter", "error", err)
			return nil, err
		}

		bytesAttrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatDiskIO))

		nme.diskIOBytes = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, diskIOBytes, bytesAttrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StorageBlockQueue() {
		log := log.With("metricFamily", "StorageBlockQueue")

		h, err := ebpfEvents.Float64Histogram(attributes.StatDiskQueueDuration.OTEL, metric2.WithUnit(attributes.StatDiskQueueDuration.Unit))
		if err != nil {
			log.Error("creating disk queue duration histogram", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatDiskQueueDuration))

		nme.diskQueueDuration = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, h, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StorageBlockQueueDepth() {
		log := log.With("metricFamily", "StorageBlockQueueDepth")

		depth, err := ebpfEvents.Float64Histogram(attributes.StatDiskQueueDepth.OTEL, metric2.WithUnit(attributes.StatDiskQueueDepth.Unit))
		if err != nil {
			log.Error("creating disk queue depth histogram", "error", err)
			return nil, err
		}

		depthAttrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatDiskQueueDepth))

		nme.diskQueueDepth = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, depth, depthAttrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StorageBlockErrors() {
		log := log.With("metricFamily", "StorageBlockErrors")

		diskOpErrors, err := ebpfEvents.Int64Counter(attributes.StatDiskOperationErrors.OTEL, metric2.WithUnit(attributes.StatDiskOperationErrors.Unit))
		if err != nil {
			log.Error("creating disk operation errors counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatDiskOperationErrors))

		nme.diskOpErrors = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, diskOpErrors, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StorageFSDuration() {
		log := log.With("metricFamily", "StorageFSDuration")

		h, err := ebpfEvents.Float64Histogram(attributes.StatFsOperationDuration.OTEL, metric2.WithUnit("s"),
			metric2.WithDescription("Filesystem read, write and sync latency as the application sees it. Buffered writes end once the data is in the page cache."))
		if err != nil {
			log.Error("creating fs operation duration histogram", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatFsOperationDuration))

		nme.fsOpDuration = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, h, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StorageFSIo() {
		log := log.With("metricFamily", "StorageFSIo")

		fsIOBytes, err := ebpfEvents.Int64Counter(attributes.StatFsIO.OTEL, metric2.WithUnit("By"))
		if err != nil {
			log.Error("creating fs io bytes counter", "error", err)
			return nil, err
		}

		bytesAttrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatFsIO))

		nme.fsIOBytes = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, fsIOBytes, bytesAttrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StorageFSErrors() {
		log := log.With("metricFamily", "StorageFSErrors")

		fsOpErrors, err := ebpfEvents.Int64Counter(attributes.StatFsOperationErrors.OTEL, metric2.WithUnit(attributes.StatFsOperationErrors.Unit))
		if err != nil {
			log.Error("creating fs operation errors counter", "error", err)
			return nil, err
		}

		attrs := attributes.OpenTelemetryGetters(
			ebpf.StatGetters,
			attrProv.For(attributes.StatFsOperationErrors))

		nme.fsOpErrors = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, fsOpErrors, attrs, timeNow, cfg.Metrics.TTL)
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
			if me.diskOpDuration != nil && v.BlockIo != nil {
				h, attrs := me.diskOpDuration.ForRecord(v)
				h.Record(ctx, time.Duration(v.BlockIo.LatencyNs).Seconds(), metric2.WithAttributeSet(attrs))
			}
			if me.diskIOBytes != nil && v.BlockIo != nil {
				diskIOBytes, attrs := me.diskIOBytes.ForRecord(v)
				diskIOBytes.Add(ctx, int64(v.BlockIo.Bytes), metric2.WithAttributeSet(attrs))
			}
			// QueueNs == 0 means no block_rq_insert record matched this
			// request (e.g. blk-mq issued it directly): there is no queue
			// wait to observe, and a genuine 0ns queue wait is not
			// observable in practice.
			if me.diskQueueDuration != nil && v.BlockIo != nil && v.BlockIo.QueueNs != 0 {
				h, attrs := me.diskQueueDuration.ForRecord(v)
				h.Record(ctx, time.Duration(v.BlockIo.QueueNs).Seconds(), metric2.WithAttributeSet(attrs))
			}
			if me.diskQueueDepth != nil && v.BlockIo != nil {
				h, attrs := me.diskQueueDepth.ForRecord(v)
				h.Record(ctx, float64(v.BlockIo.Inflight), metric2.WithAttributeSet(attrs))
			}
			if me.diskOpErrors != nil && v.BlockIo != nil && v.BlockIo.Error != 0 {
				diskOpErrors, attrs := me.diskOpErrors.ForRecord(v)
				diskOpErrors.Add(ctx, 1, metric2.WithAttributeSet(attrs))
			}
			if me.fsOpDuration != nil && v.FsIo != nil {
				h, attrs := me.fsOpDuration.ForRecord(v)
				h.Record(ctx, time.Duration(v.FsIo.LatencyNs).Seconds(), metric2.WithAttributeSet(attrs))
			}
			if me.fsIOBytes != nil && v.FsIo != nil && v.FsIo.Bytes != 0 {
				c, attrs := me.fsIOBytes.ForRecord(v)
				c.Add(ctx, int64(v.FsIo.Bytes), metric2.WithAttributeSet(attrs))
			}
			if me.fsOpErrors != nil && v.FsIo != nil && v.FsIo.Error != 0 {
				fsOpErrors, attrs := me.fsOpErrors.ForRecord(v)
				fsOpErrors.Add(ctx, 1, metric2.WithAttributeSet(attrs))
			}
		}
	}
}
