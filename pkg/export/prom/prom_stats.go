// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// injectable function reference for testing

// StatsPrometheusConfig for stat metrics just wraps the global prom.StatsPrometheusConfig as provided by the user
type StatsPrometheusConfig struct {
	Config      *PrometheusConfig
	SelectorCfg *attributes.SelectorConfig
	CommonCfg   *perapp.GlobalMetricsConfig
}

// Enabled returns whether the node needs to be activated
func (p StatsPrometheusConfig) Enabled() bool {
	return p.Config != nil && p.Config.EndpointEnabled() && p.CommonCfg.Features.StatMetrics()
}

type statMetricsReporter struct {
	cfg *PrometheusConfig

	tcpRtt                   *Expirer[prometheus.Histogram]
	tcpFailedConnections     *Expirer[prometheus.Counter]
	tcpRetransmits           *Expirer[prometheus.Counter]
	tcpIo                    *Expirer[prometheus.Counter]
	tcpSuccessfulConnections *Expirer[prometheus.Counter]
	diskOpDuration           *Expirer[prometheus.Histogram]
	diskIOBytes              *Expirer[prometheus.Counter]
	diskQueueDuration        *Expirer[prometheus.Histogram]
	diskQueueDepth           *Expirer[prometheus.Histogram]
	diskOpErrors             *Expirer[prometheus.Counter]
	fsOpDuration             *Expirer[prometheus.Histogram]
	fsIOBytes                *Expirer[prometheus.Counter]
	fsOpErrors               *Expirer[prometheus.Counter]

	promConnect *connector.PrometheusManager

	tcpRttAttrs                   []attributes.Field[*ebpf.Stat, string]
	tcpFailedConnectionsAttrs     []attributes.Field[*ebpf.Stat, string]
	tcpRetransmitsAttrs           []attributes.Field[*ebpf.Stat, string]
	tcpIoAttrs                    []attributes.Field[*ebpf.Stat, string]
	tcpSuccessfulConnectionsAttrs []attributes.Field[*ebpf.Stat, string]
	diskOpDurationAttrs           []attributes.Field[*ebpf.Stat, string]
	diskIOBytesAttrs              []attributes.Field[*ebpf.Stat, string]
	diskQueueDurationAttrs        []attributes.Field[*ebpf.Stat, string]
	diskQueueDepthAttrs           []attributes.Field[*ebpf.Stat, string]
	diskOpErrorsAttrs             []attributes.Field[*ebpf.Stat, string]
	fsOpDurationAttrs             []attributes.Field[*ebpf.Stat, string]
	fsIOBytesAttrs                []attributes.Field[*ebpf.Stat, string]
	fsOpErrorsAttrs               []attributes.Field[*ebpf.Stat, string]

	input <-chan []*ebpf.Stat
}

func StatsPrometheusEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *StatsPrometheusConfig,
	input *msg.Queue[[]*ebpf.Stat],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the swarm library just ignore it.
			return swarm.EmptyRunFunc()
		}
		reporter, err := newStatsReporter(ctxInfo, cfg, input)
		if err != nil {
			return nil, err
		}
		if cfg.Config.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

func newStatsReporter(
	ctxInfo *global.ContextInfo,
	cfg *StatsPrometheusConfig,
	input *msg.Queue[[]*ebpf.Stat],
) (*statMetricsReporter, error) {
	group := ctxInfo.MetricAttributeGroups
	// this property can't be set inside the ConfiguredGroups function, otherwise the
	// OTEL exporter would report also some prometheus-exclusive attributes
	group.Add(attributes.GroupPrometheus)

	provider, err := attributes.NewAttrSelector(group, cfg.SelectorCfg)
	if err != nil {
		return nil, fmt.Errorf("stats Prometheus exporter attributes enable: %w", err)
	}

	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &statMetricsReporter{
		cfg:         cfg.Config,
		promConnect: ctxInfo.Prometheus,
	}

	var register []prometheus.Collector
	log := slog.With("component", "prom.StatsEndpoint")
	if cfg.CommonCfg.Features.StatsTCPRtt() {
		log.Debug("registering stat tcp rtt metric")

		mr.tcpRttAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPRtt))

		mr.tcpRtt = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatTCPRtt.Prom,
			Help:                            "measures the smoothed TCP RTT as calculated by the kernel in seconds",
			Buckets:                         cfg.Config.Buckets.StatTCPRttHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.tcpRttAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.tcpRtt)
	}

	if cfg.CommonCfg.Features.StatsTCPRetransmits() {
		log.Debug("registering stat tcp retransmits metric")

		mr.tcpRetransmitsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPRetransmits))

		mr.tcpRetransmits = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPRetransmits.Prom,
			Help: "counts the TCP retransmits between 2 endpoints",
		}, labelNames(mr.tcpRetransmitsAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpRetransmits)
	}

	if cfg.CommonCfg.Features.StatsTCPIo() {
		log.Debug("registering stat tcp io metric")

		mr.tcpIoAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPIo))

		mr.tcpIo = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPIo.Prom,
			Help: "count bytes transferred at the socket layer",
		}, labelNames(mr.tcpIoAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpIo)
	}

	if cfg.CommonCfg.Features.StatsTCPFailedConnections() {
		log.Debug("registering stat tcp failed connections metric")

		mr.tcpFailedConnectionsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPFailedConnections))

		mr.tcpFailedConnections = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPFailedConnections.Prom,
			Help: "counts the TCP failed connections between 2 endpoints",
		}, labelNames(mr.tcpFailedConnectionsAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpFailedConnections)
	}

	if cfg.CommonCfg.Features.StatsTCPSuccessfulConnections() {
		log.Debug("registering stat tcp successful connections metric")

		mr.tcpSuccessfulConnectionsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatTCPSuccessfulConnections))

		mr.tcpSuccessfulConnections = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatTCPSuccessfulConnections.Prom,
			Help: "counts the TCP successful connections between 2 endpoints",
		}, labelNames(mr.tcpSuccessfulConnectionsAttrs)).MetricVec, timeNow, cfg.Config.TTL)

		register = append(register, mr.tcpSuccessfulConnections)
	}

	if cfg.CommonCfg.Features.StorageBlockDuration() {
		log.Debug("registering stat disk operation duration metric")

		mr.diskOpDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskOperationDuration))

		mr.diskOpDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatDiskOperationDuration.Prom,
			Help:                            "measures the block I/O latency as calculated by the kernel in seconds",
			Buckets:                         cfg.Config.Buckets.StatDiskOperationDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.diskOpDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskOpDuration)
	}

	if cfg.CommonCfg.Features.StorageBlockIo() {
		log.Debug("registering stat disk io bytes metric")

		mr.diskIOBytesAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskIO))

		mr.diskIOBytes = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskIO.Prom,
			Help: "count of bytes transferred at the block layer",
		}, labelNames(mr.diskIOBytesAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskIOBytes)
	}

	if cfg.CommonCfg.Features.StorageBlockQueue() {
		log.Debug("registering stat disk queue duration and depth metrics")

		mr.diskQueueDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskQueueDuration))

		mr.diskQueueDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatDiskQueueDuration.Prom,
			Help:                            "measures the time a block I/O request spent queued before being dispatched to the device, in seconds",
			Buckets:                         cfg.Config.Buckets.StatDiskOperationDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.diskQueueDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskQueueDuration)

		mr.diskQueueDepthAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskQueueDepth))

		mr.diskQueueDepth = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatDiskQueueDepth.Prom,
			Help:                            "distribution of block I/O requests still in flight on the device, observed per completion",
			Buckets:                         cfg.Config.Buckets.StatDiskQueueDepthHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.diskQueueDepthAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskQueueDepth)
	}

	if cfg.CommonCfg.Features.StorageBlockErrors() {
		log.Debug("registering stat disk operation errors metric")

		mr.diskOpErrorsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskOperationErrors))

		mr.diskOpErrors = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskOperationErrors.Prom,
			Help: "counts block I/O completions with a non-zero error, broken down by errno",
		}, labelNames(mr.diskOpErrorsAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskOpErrors)
	}

	if cfg.CommonCfg.Features.StorageFSDuration() {
		log.Debug("registering stat fs operation duration metric")

		mr.fsOpDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatFsOperationDuration))

		mr.fsOpDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatFsOperationDuration.Prom,
			Help:                            "measures the filesystem I/O latency as calculated by the kernel in seconds",
			Buckets:                         cfg.Config.Buckets.StatFsOperationDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.fsOpDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.fsOpDuration)
	}

	if cfg.CommonCfg.Features.StorageFSIo() {
		log.Debug("registering stat fs io bytes metric")

		mr.fsIOBytesAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatFsIO))

		mr.fsIOBytes = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatFsIO.Prom,
			Help: "count of bytes transferred at the filesystem layer",
		}, labelNames(mr.fsIOBytesAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.fsIOBytes)
	}

	if cfg.CommonCfg.Features.StorageFSErrors() {
		log.Debug("registering stat fs operation errors metric")

		mr.fsOpErrorsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatFsOperationErrors))

		mr.fsOpErrors = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatFsOperationErrors.Prom,
			Help: "counts filesystem I/O operations that failed, broken down by errno",
		}, labelNames(mr.fsOpErrorsAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.fsOpErrors)
	}

	if cfg.Config.Registry != nil {
		cfg.Config.Registry.MustRegister(register...)
	} else {
		mr.promConnect.Register(cfg.Config.Port, cfg.Config.Path, register...)
	}

	mr.input = input.Subscribe(msg.SubscriberName("prom.StatsReporterInput"))
	return mr, nil
}

func (r *statMetricsReporter) reportMetrics(ctx context.Context) {
	go r.promConnect.StartHTTP(ctx)
	r.collectMetrics(ctx)
}

func (r *statMetricsReporter) collectMetrics(_ context.Context) {
	for stats := range r.input {
		for _, stat := range stats {
			r.observeTCPRtt(stat)
			r.observeTCPFailedConnections(stat)
			r.observeTCPSuccessfulConnections(stat)
			r.observeTCPRetransmits(stat)
			r.observeTCPIo(stat)
			r.observeDiskOpDuration(stat)
			r.observeDiskIOBytes(stat)
			r.observeDiskQueueDuration(stat)
			r.observeDiskQueueDepth(stat)
			r.observeDiskOpErrors(stat)
			r.observeFsOpDuration(stat)
			r.observeFsIOBytes(stat)
			r.observeFsOpErrors(stat)
		}
	}
}

func (r *statMetricsReporter) observeTCPRtt(stat *ebpf.Stat) {
	if r.tcpRtt == nil || stat.TCPRtt == nil {
		return
	}
	r.tcpRtt.WithLabelValues(labelValues(stat, r.tcpRttAttrs)...).
		Metric.Observe(float64(stat.TCPRtt.SrttUs) / 1_000_000.0)
}

func (r *statMetricsReporter) observeTCPFailedConnections(stat *ebpf.Stat) {
	if r.tcpFailedConnections == nil || stat.TCPFailedConnection == nil {
		return
	}
	r.tcpFailedConnections.WithLabelValues(labelValues(stat, r.tcpFailedConnectionsAttrs)...).
		Metric.Add(1)
}

func (r *statMetricsReporter) observeTCPSuccessfulConnections(stat *ebpf.Stat) {
	if r.tcpSuccessfulConnections == nil || stat.TCPSuccessfulConnection == nil {
		return
	}
	r.tcpSuccessfulConnections.WithLabelValues(labelValues(stat, r.tcpSuccessfulConnectionsAttrs)...).
		Metric.Add(1)
}

func (r *statMetricsReporter) observeTCPRetransmits(stat *ebpf.Stat) {
	if r.tcpRetransmits == nil || !stat.TCPRetransmit {
		return
	}
	r.tcpRetransmits.WithLabelValues(labelValues(stat, r.tcpRetransmitsAttrs)...).
		Metric.Add(1)
}

func (r *statMetricsReporter) observeTCPIo(stat *ebpf.Stat) {
	if r.tcpIo == nil || stat.TCPIo == nil {
		return
	}
	r.tcpIo.WithLabelValues(labelValues(stat, r.tcpIoAttrs)...).
		Metric.Add(float64(stat.TCPIo.Bytes))
}

func (r *statMetricsReporter) observeDiskOpDuration(stat *ebpf.Stat) {
	if r.diskOpDuration == nil || stat.BlockIo == nil {
		return
	}
	r.diskOpDuration.WithLabelValues(labelValues(stat, r.diskOpDurationAttrs)...).
		Metric.Observe(time.Duration(stat.BlockIo.LatencyNs).Seconds())
}

func (r *statMetricsReporter) observeDiskIOBytes(stat *ebpf.Stat) {
	if r.diskIOBytes == nil || stat.BlockIo == nil {
		return
	}
	r.diskIOBytes.WithLabelValues(labelValues(stat, r.diskIOBytesAttrs)...).
		Metric.Add(float64(stat.BlockIo.Bytes))
}

func (r *statMetricsReporter) observeDiskQueueDuration(stat *ebpf.Stat) {
	// QueueNs == 0 means no block_rq_insert record matched this request (e.g.
	// blk-mq issued it directly): there is no queue wait to observe, and a
	// genuine 0ns queue wait is not observable in practice.
	if r.diskQueueDuration == nil || stat.BlockIo == nil || stat.BlockIo.QueueNs == 0 {
		return
	}
	r.diskQueueDuration.WithLabelValues(labelValues(stat, r.diskQueueDurationAttrs)...).
		Metric.Observe(time.Duration(stat.BlockIo.QueueNs).Seconds())
}

func (r *statMetricsReporter) observeDiskQueueDepth(stat *ebpf.Stat) {
	if r.diskQueueDepth == nil || stat.BlockIo == nil {
		return
	}
	r.diskQueueDepth.WithLabelValues(labelValues(stat, r.diskQueueDepthAttrs)...).
		Metric.Observe(float64(stat.BlockIo.Inflight))
}

func (r *statMetricsReporter) observeDiskOpErrors(stat *ebpf.Stat) {
	if r.diskOpErrors == nil || stat.BlockIo == nil || stat.BlockIo.Error == 0 {
		return
	}
	r.diskOpErrors.WithLabelValues(labelValues(stat, r.diskOpErrorsAttrs)...).
		Metric.Add(1)
}

func (r *statMetricsReporter) observeFsOpDuration(stat *ebpf.Stat) {
	if r.fsOpDuration == nil || stat.FsIo == nil {
		return
	}
	r.fsOpDuration.WithLabelValues(labelValues(stat, r.fsOpDurationAttrs)...).
		Metric.Observe(time.Duration(stat.FsIo.LatencyNs).Seconds())
}

func (r *statMetricsReporter) observeFsIOBytes(stat *ebpf.Stat) {
	if r.fsIOBytes == nil || stat.FsIo == nil || stat.FsIo.Bytes == 0 {
		return
	}
	r.fsIOBytes.WithLabelValues(labelValues(stat, r.fsIOBytesAttrs)...).
		Metric.Add(float64(stat.FsIo.Bytes))
}

func (r *statMetricsReporter) observeFsOpErrors(stat *ebpf.Stat) {
	if r.fsOpErrors == nil || stat.FsIo == nil || stat.FsIo.Error == 0 {
		return
	}
	r.fsOpErrors.WithLabelValues(labelValues(stat, r.fsOpErrorsAttrs)...).
		Metric.Add(1)
}
