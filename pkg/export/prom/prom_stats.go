// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/export"
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
	diskServiceDuration      *kernelHistogramVec
	diskIO                   *Expirer[prometheus.Counter]
	diskOperations           *Expirer[prometheus.Counter]
	diskServiceTime          *Expirer[prometheus.Counter]
	fsSyncDuration           *kernelHistogramVec

	promConnect *connector.PrometheusManager

	tcpRttAttrs                   []attributes.Field[*ebpf.Stat, string]
	tcpFailedConnectionsAttrs     []attributes.Field[*ebpf.Stat, string]
	tcpRetransmitsAttrs           []attributes.Field[*ebpf.Stat, string]
	tcpIoAttrs                    []attributes.Field[*ebpf.Stat, string]
	tcpSuccessfulConnectionsAttrs []attributes.Field[*ebpf.Stat, string]
	diskServiceDurationAttrs      []attributes.Field[*ebpf.Stat, string]
	diskIOAttrs                   []attributes.Field[*ebpf.Stat, string]
	diskOperationsAttrs           []attributes.Field[*ebpf.Stat, string]
	diskServiceTimeAttrs          []attributes.Field[*ebpf.Stat, string]
	fsSyncDurationAttrs           []attributes.Field[*ebpf.Stat, string]

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

	if cfg.CommonCfg.Features.StatsDiskServiceDuration() {
		log.Debug("registering stat disk service duration metric")

		mr.diskServiceDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskServiceDuration))

		mr.diskServiceDuration = newKernelHistogramVec(attributes.StatDiskServiceDuration.Prom,
			"measures the service time of block I/O requests, from their last issue to the device until their final completion, in seconds",
			export.DiskLatencyBounds, labelNames(mr.diskServiceDurationAttrs), cfg.Config.TTL)
		register = append(register, mr.diskServiceDuration)
	}

	if cfg.CommonCfg.Features.StatsDiskIO() {
		log.Debug("registering stat disk io metric")

		mr.diskIOAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskIO))

		mr.diskIO = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskIO.Prom,
			Help: "bytes of the block I/O requests that completed successfully, as issued to the device",
		}, labelNames(mr.diskIOAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskIO)
	}

	if cfg.CommonCfg.Features.StatsDiskOperations() {
		log.Debug("registering stat disk operations metric")

		mr.diskOperationsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskOperations))

		mr.diskOperations = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskOperations.Prom,
			Help: "number of completed block I/O requests",
		}, labelNames(mr.diskOperationsAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskOperations)
	}

	if cfg.CommonCfg.Features.StatsDiskServiceTime() {
		log.Debug("registering stat disk service time metric")

		mr.diskServiceTimeAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskServiceTime))

		mr.diskServiceTime = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskServiceTime.Prom,
			Help: "sum of the service times of the completed block I/O requests, from their last issue to the device until their final completion, in seconds",
		}, labelNames(mr.diskServiceTimeAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskServiceTime)
	}

	if cfg.CommonCfg.Features.StatsFsSyncDuration() {
		log.Debug("registering stat fs sync duration metric")

		mr.fsSyncDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatFsSyncDuration))

		mr.fsSyncDuration = newKernelHistogramVec(attributes.StatFsSyncDuration.Prom,
			"measures the duration of the file syncs of the applications, from the sync call until it returns, in seconds",
			export.FsSyncLatencyBounds, labelNames(mr.fsSyncDurationAttrs), cfg.Config.TTL)
		register = append(register, mr.fsSyncDuration)
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
			r.observeDiskServiceDuration(stat)
			r.observeDiskIO(stat)
			r.observeDiskOperations(stat)
			r.observeDiskServiceTime(stat)
			r.observeFsSyncDuration(stat)
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

func (r *statMetricsReporter) observeDiskServiceDuration(stat *ebpf.Stat) {
	if r.diskServiceDuration == nil || stat.DiskIO == nil || stat.DiskIO.Latency == nil {
		return
	}
	r.diskServiceDuration.observe(labelValues(stat, r.diskServiceDurationAttrs), stat.DiskIO.Latency)
}

func (r *statMetricsReporter) observeDiskIO(stat *ebpf.Stat) {
	if r.diskIO == nil || stat.DiskIO == nil || stat.DiskIO.Bytes == 0 {
		return
	}
	r.diskIO.WithLabelValues(labelValues(stat, r.diskIOAttrs)...).
		Metric.Add(float64(stat.DiskIO.Bytes))
}

func (r *statMetricsReporter) observeDiskOperations(stat *ebpf.Stat) {
	if r.diskOperations == nil || stat.DiskIO == nil {
		return
	}
	r.diskOperations.WithLabelValues(labelValues(stat, r.diskOperationsAttrs)...).
		Metric.Add(float64(stat.DiskIO.Operations))
}

func (r *statMetricsReporter) observeDiskServiceTime(stat *ebpf.Stat) {
	if r.diskServiceTime == nil || stat.DiskIO == nil {
		return
	}
	r.diskServiceTime.WithLabelValues(labelValues(stat, r.diskServiceTimeAttrs)...).
		Metric.Add(stat.DiskIO.Time)
}

func (r *statMetricsReporter) observeFsSyncDuration(stat *ebpf.Stat) {
	if r.fsSyncDuration == nil || stat.FsSync == nil {
		return
	}
	r.fsSyncDuration.observe(labelValues(stat, r.fsSyncDurationAttrs), stat.FsSync.Latency)
}
