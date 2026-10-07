// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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

// newStatMeterProvider creates the meter provider of the stat metrics. The latency histograms that
// the kernel accumulates come from kernelHistograms, with explicit buckets.
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
	diskOperationDuration    *kernelHistogram
	diskIO                   *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	diskOperations           *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	diskServiceTime          *Expirer[*ebpf.Stat, metric2.Float64Counter, float64]
	fsSyncDuration           *kernelHistogram
	fsSyncOperations         *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	fsSyncOperationTime      *Expirer[*ebpf.Stat, metric2.Float64Counter, float64]
	diskQueueDuration        *kernelHistogram
	diskFlushDuration        *kernelHistogram
	diskDiscardDuration      *kernelHistogram
	diskDiscardIO            *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	diskOperationInflight    *currentUpDownCounter[*ebpf.Stat]
	nfsProcedureDuration     *kernelHistogram
	nfsProcedureCount        *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	nfsProcedureTime         *Expirer[*ebpf.Stat, metric2.Float64Counter, float64]
	nfsIO                    *Expirer[*ebpf.Stat, metric2.Int64Counter, int64]
	k8sPodVolumeDevice       *currentUpDownCounter[*ebpf.Stat]
	diskVolumeDevice         *currentUpDownCounter[*ebpf.Stat]
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

	if cfg.CommonCfg.Features.StatsDiskOperationDuration() {
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskOperationDuration))
		nme.diskOperationDuration = kernelHistograms.histogram(attributes.StatDiskOperationDuration,
			cfg.Metrics.Buckets.StatDiskOperationDurationHistogram, attrs)
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

	if cfg.CommonCfg.Features.StatsDiskServiceTime() {
		diskServiceTime, err := ebpfEvents.Float64Counter(attributes.StatDiskServiceTime.OTEL, metric2.WithUnit(attributes.StatDiskServiceTime.Unit))
		if err != nil {
			log.Error("creating stats disk service time counter", "error", err)
			return nil, err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskServiceTime))
		nme.diskServiceTime = NewExpirer[*ebpf.Stat, metric2.Float64Counter, float64](ctx, diskServiceTime, attrs, timeNow, cfg.Metrics.TTL)
	}

	if err := nme.createFsSyncMetrics(ctx, ebpfEvents, attrProv, cfg, log); err != nil {
		return nil, err
	}

	if err := nme.createDiskOperationMetrics(ctx, ebpfEvents, attrProv, cfg, log); err != nil {
		return nil, err
	}

	if err := nme.createNFSMetrics(ctx, ebpfEvents, attrProv, cfg, log); err != nil {
		return nil, err
	}

	if cfg.CommonCfg.Features.StatsDiskPodVolumes() {
		volumes, err := ebpfEvents.Int64UpDownCounter(attributes.StatK8sPodVolumeDevice.OTEL,
			metric2.WithUnit(attributes.StatK8sPodVolumeDevice.Unit))
		if err != nil {
			log.Error("creating stats k8s pod volume device counter", "error", err)
			return nil, err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatK8sPodVolumeDevice))
		nme.k8sPodVolumeDevice = newCurrentUpDownCounter(ctx, volumes, attrs, timeNow, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.StatsDiskVolumeDevices() {
		volumes, err := ebpfEvents.Int64UpDownCounter(attributes.StatDiskVolumeDevice.OTEL,
			metric2.WithUnit(attributes.StatDiskVolumeDevice.Unit))
		if err != nil {
			log.Error("creating stats disk volume device counter", "error", err)
			return nil, err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskVolumeDevice))
		nme.diskVolumeDevice = newCurrentUpDownCounter(ctx, volumes, attrs, timeNow, cfg.Metrics.TTL)
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
			if v.NFSProcedure != nil {
				me.recordNFSProcedure(ctx, v)
			}
			if me.nfsIO != nil && v.NFSIO != nil {
				nfsIO, attrs := me.nfsIO.ForRecord(v)
				nfsIO.Add(ctx, int64(v.NFSIO.Bytes), metric2.WithAttributeSet(attrs))
			}
		}
		recordCurrentSums(me.diskOperationInflight, i, func(stat *ebpf.Stat) (int64, bool) {
			if stat.DiskPending == nil {
				return 0, false
			}
			return stat.DiskPending.Requests, true
		})
		recordCurrentSums(me.k8sPodVolumeDevice, i, func(stat *ebpf.Stat) (int64, bool) {
			if stat.PodVolume == nil {
				return 0, false
			}
			return stat.PodVolume.Value, true
		})
		recordCurrentSums(me.diskVolumeDevice, i, func(stat *ebpf.Stat) (int64, bool) {
			if stat.DiskVolume == nil {
				return 0, false
			}
			return stat.DiskVolume.Value, true
		})
	}
}

// recordCurrentSums records, as the current value of each series, the sum of the values of the
// stats of a batch that fall into it. Several stats fall into the same series when some of their
// attributes are not selected, e.g. the reads and writes of a device without disk.io.direction.
func recordCurrentSums(
	counter *currentUpDownCounter[*ebpf.Stat],
	stats []*ebpf.Stat,
	valueOf func(*ebpf.Stat) (int64, bool),
) {
	if counter == nil {
		return
	}
	type series struct {
		stat *ebpf.Stat
		sum  int64
	}
	sums := map[string]*series{}
	for _, stat := range stats {
		value, ok := valueOf(stat)
		if !ok {
			continue
		}
		_, values := attributeSet(counter.attrs, stat)
		key := strings.Join(values, "\x00")
		if s, ok := sums[key]; ok {
			s.sum += value
		} else {
			sums[key] = &series{stat: stat, sum: value}
		}
	}
	for _, s := range sums {
		counter.Record(s.stat, s.sum)
	}
}

// createFsSyncMetrics creates the metrics of the file syncs
func (me *statMetricsExporter) createFsSyncMetrics(
	ctx context.Context,
	meter metric2.Meter,
	attrProv *attributes.AttrSelector,
	cfg *StatMetricsConfig,
	log *slog.Logger,
) error {
	features := cfg.CommonCfg.Features
	if features.StatsFsSyncDuration() {
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatFsSyncDuration))
		me.fsSyncDuration = me.kernelHistograms.histogram(attributes.StatFsSyncDuration,
			cfg.Metrics.Buckets.StatFsSyncDurationHistogram, attrs)
	}

	if features.StatsFsSyncOperations() {
		name := attributes.StatFsSyncOperations
		counter, err := meter.Int64Counter(name.OTEL, metric2.WithUnit(name.Unit))
		if err != nil {
			log.Error("creating stats file sync operations counter", "error", err)
			return err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(name))
		me.fsSyncOperations = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, counter, attrs, timeNow, cfg.Metrics.TTL)
	}

	if features.StatsFsSyncOperationTime() {
		name := attributes.StatFsSyncOperationTime
		counter, err := meter.Float64Counter(name.OTEL, metric2.WithUnit(name.Unit))
		if err != nil {
			log.Error("creating stats file sync operation time counter", "error", err)
			return err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(name))
		me.fsSyncOperationTime = NewExpirer[*ebpf.Stat, metric2.Float64Counter, float64](ctx, counter, attrs, timeNow, cfg.Metrics.TTL)
	}
	return nil
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
	buckets := cfg.Metrics.Buckets
	histograms := []struct {
		enabled bool
		name    attributes.Name
		bounds  []float64
		dst     **kernelHistogram
	}{
		{features.StatsDiskQueueDuration(), attributes.StatDiskQueueDuration, buckets.StatDiskQueueDurationHistogram, &me.diskQueueDuration},
		{features.StatsDiskFlush(), attributes.StatDiskFlushDuration, buckets.StatDiskFlushDurationHistogram, &me.diskFlushDuration},
		{features.StatsDiskDiscard(), attributes.StatDiskDiscardDuration, buckets.StatDiskDiscardDurationHistogram, &me.diskDiscardDuration},
	}
	for _, h := range histograms {
		if h.enabled {
			attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(h.name))
			*h.dst = me.kernelHistograms.histogram(h.name, h.bounds, attrs)
		}
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

	if features.StatsDiskOperationInflight() {
		pending, err := meter.Int64UpDownCounter(attributes.StatDiskOperationInflight.OTEL,
			metric2.WithUnit(attributes.StatDiskOperationInflight.Unit))
		if err != nil {
			log.Error("creating stats disk operation inflight counter", "error", err)
			return err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskOperationInflight))
		me.diskOperationInflight = newCurrentUpDownCounter(ctx, pending, attrs, timeNow, cfg.Metrics.TTL)
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
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(name))
		me.nfsProcedureDuration = me.kernelHistograms.histogram(name, cfg.Metrics.Buckets.StatNFSClientProcedureDurationHistogram, attrs)
	}

	if features.StatsNFSClientProcedureCount() {
		name := attributes.StatNFSClientProcedureCount
		counter, err := meter.Int64Counter(name.OTEL, metric2.WithUnit(name.Unit))
		if err != nil {
			log.Error("creating stats NFS client procedure count counter", "error", err)
			return err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(name))
		me.nfsProcedureCount = NewExpirer[*ebpf.Stat, metric2.Int64Counter, int64](ctx, counter, attrs, timeNow, cfg.Metrics.TTL)
	}

	if features.StatsNFSClientProcedureTime() {
		name := attributes.StatNFSClientProcedureTime
		counter, err := meter.Float64Counter(name.OTEL, metric2.WithUnit(name.Unit))
		if err != nil {
			log.Error("creating stats NFS client procedure time counter", "error", err)
			return err
		}
		attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(name))
		me.nfsProcedureTime = NewExpirer[*ebpf.Stat, metric2.Float64Counter, float64](ctx, counter, attrs, timeNow, cfg.Metrics.TTL)
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
		me.kernelHistograms.record(me.diskOperationDuration, v, v.DiskIO.Latency)
		me.kernelHistograms.record(me.diskQueueDuration, v, v.DiskIO.Queue)
	case ebpf.CodeDiskOpFlush:
		me.kernelHistograms.record(me.diskFlushDuration, v, v.DiskIO.Latency)
	case ebpf.CodeDiskOpDiscard:
		me.kernelHistograms.record(me.diskDiscardDuration, v, v.DiskIO.Latency)
		if me.diskDiscardIO != nil && v.DiskIO.Bytes > 0 {
			discardIO, attrs := me.diskDiscardIO.ForRecord(v)
			discardIO.Add(ctx, int64(v.DiskIO.Bytes), metric2.WithAttributeSet(attrs))
		}
	}
}

// recordFsSync records the file syncs of a stat
func (me *statMetricsExporter) recordFsSync(ctx context.Context, v *ebpf.Stat) {
	me.kernelHistograms.record(me.fsSyncDuration, v, v.FsSync.Latency)
	if me.fsSyncOperations != nil {
		operations, attrs := me.fsSyncOperations.ForRecord(v)
		operations.Add(ctx, int64(v.FsSync.Operations), metric2.WithAttributeSet(attrs))
	}
	if me.fsSyncOperationTime != nil {
		operationTime, attrs := me.fsSyncOperationTime.ForRecord(v)
		operationTime.Add(ctx, v.FsSync.Time, metric2.WithAttributeSet(attrs))
	}
}

// recordNFSProcedure records the NFS client RPCs of a stat
func (me *statMetricsExporter) recordNFSProcedure(ctx context.Context, v *ebpf.Stat) {
	me.kernelHistograms.record(me.nfsProcedureDuration, v, v.NFSProcedure.Latency)
	if me.nfsProcedureCount != nil {
		count, attrs := me.nfsProcedureCount.ForRecord(v)
		count.Add(ctx, int64(v.NFSProcedure.Calls), metric2.WithAttributeSet(attrs))
	}
	if me.nfsProcedureTime != nil {
		procedureTime, attrs := me.nfsProcedureTime.ForRecord(v)
		procedureTime.Add(ctx, v.NFSProcedure.Time, metric2.WithAttributeSet(attrs))
	}
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
	if me.diskServiceTime != nil {
		diskServiceTime, attrs := me.diskServiceTime.ForRecord(v)
		diskServiceTime.Add(ctx, v.DiskIO.Time, metric2.WithAttributeSet(attrs))
	}
}
