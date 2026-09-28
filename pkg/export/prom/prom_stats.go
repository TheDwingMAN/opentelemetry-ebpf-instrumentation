// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"fmt"
	"log/slog"

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
	diskOperationDuration    *Expirer[prometheus.Histogram]
	diskIO                   *Expirer[prometheus.Counter]
	diskOperations           *Expirer[prometheus.Counter]
	diskOperationTime        *Expirer[prometheus.Counter]
	fsSyncDuration           *Expirer[prometheus.Histogram]
	diskQueueDuration        *Expirer[prometheus.Histogram]
	diskFlushDuration        *Expirer[prometheus.Histogram]
	diskDiscardDuration      *Expirer[prometheus.Histogram]
	diskDiscardIO            *Expirer[prometheus.Counter]
	diskPendingOperations    *Expirer[prometheus.Gauge]
	nfsProcedureDuration     *Expirer[prometheus.Histogram]
	nfsIO                    *Expirer[prometheus.Counter]
	k8sPodVolumeDevice       *Expirer[prometheus.Gauge]

	promConnect *connector.PrometheusManager

	tcpRttAttrs                   []attributes.Field[*ebpf.Stat, string]
	tcpFailedConnectionsAttrs     []attributes.Field[*ebpf.Stat, string]
	tcpRetransmitsAttrs           []attributes.Field[*ebpf.Stat, string]
	tcpIoAttrs                    []attributes.Field[*ebpf.Stat, string]
	tcpSuccessfulConnectionsAttrs []attributes.Field[*ebpf.Stat, string]
	diskOperationDurationAttrs    []attributes.Field[*ebpf.Stat, string]
	diskIOAttrs                   []attributes.Field[*ebpf.Stat, string]
	diskOperationsAttrs           []attributes.Field[*ebpf.Stat, string]
	diskOperationTimeAttrs        []attributes.Field[*ebpf.Stat, string]
	fsSyncDurationAttrs           []attributes.Field[*ebpf.Stat, string]
	diskQueueDurationAttrs        []attributes.Field[*ebpf.Stat, string]
	diskFlushDurationAttrs        []attributes.Field[*ebpf.Stat, string]
	diskDiscardDurationAttrs      []attributes.Field[*ebpf.Stat, string]
	diskDiscardIOAttrs            []attributes.Field[*ebpf.Stat, string]
	diskPendingOperationsAttrs    []attributes.Field[*ebpf.Stat, string]
	nfsProcedureDurationAttrs     []attributes.Field[*ebpf.Stat, string]
	nfsIOAttrs                    []attributes.Field[*ebpf.Stat, string]
	k8sPodVolumeDeviceAttrs       []attributes.Field[*ebpf.Stat, string]

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

	if cfg.CommonCfg.Features.StatsDiskOperationDuration() {
		log.Debug("registering stat disk operation duration metric")

		mr.diskOperationDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskOperationDuration))

		mr.diskOperationDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatDiskOperationDuration.Prom,
			Help:                            "measures the duration of block I/O requests, from their issue to the device until their completion, in seconds",
			Buckets:                         cfg.Config.Buckets.StatDiskOperationDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.diskOperationDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskOperationDuration)
	}

	if cfg.CommonCfg.Features.StatsDiskIO() {
		mr.diskIOAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatDiskIO))
		mr.diskIO = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskIO.Prom,
			Help: "bytes transferred by the block I/O requests that completed successfully",
		}, labelNames(mr.diskIOAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskIO)
	}

	if cfg.CommonCfg.Features.StatsDiskOperations() {
		mr.diskOperationsAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatDiskOperations))
		mr.diskOperations = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskOperations.Prom,
			Help: "number of completed block I/O requests",
		}, labelNames(mr.diskOperationsAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskOperations)
	}

	if cfg.CommonCfg.Features.StatsDiskOperationTime() {
		mr.diskOperationTimeAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatDiskOperationTime))
		mr.diskOperationTime = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskOperationTime.Prom,
			Help: "sum of the durations of the completed block I/O requests, in seconds",
		}, labelNames(mr.diskOperationTimeAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskOperationTime)
	}

	if cfg.CommonCfg.Features.StatsFsSyncDuration() {
		mr.fsSyncDurationAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatFsSyncDuration))
		mr.fsSyncDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatFsSyncDuration.Prom,
			Help:                            "measures the duration of file syncs (fsync, fdatasync, sync, syncfs, sync_file_range and their equivalents), in seconds",
			Buckets:                         cfg.Config.Buckets.StatFsSyncDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.fsSyncDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.fsSyncDuration)
	}

	register = append(register, mr.registerDiskOperationMetrics(cfg, provider)...)
	register = append(register, mr.registerNFSMetrics(cfg, provider)...)
	register = append(register, mr.registerPodVolumeMetrics(cfg, provider)...)

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
			r.observeDiskOperationDuration(stat)
			r.observeDiskCounters(stat)
			r.observeFsSyncDuration(stat)
			r.observeDiskOperations(stat)
			r.observeDiskPendingOperations(stat)
			r.observeNFS(stat)
			r.observePodVolume(stat)
		}
	}
}

// registerNFSMetrics creates the metrics of the NFS client
func (r *statMetricsReporter) registerNFSMetrics(cfg *StatsPrometheusConfig, provider *attributes.AttrSelector) []prometheus.Collector {
	features := cfg.CommonCfg.Features
	var register []prometheus.Collector
	if features.StatsNFSClientProcedureDuration() {
		r.nfsProcedureDurationAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatNFSClientProcedureDuration))
		r.nfsProcedureDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatNFSClientProcedureDuration.Prom,
			Help:                            "measures the duration of the RPCs of the NFS client, in seconds",
			Buckets:                         cfg.Config.Buckets.StatNFSClientProcedureDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(r.nfsProcedureDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, r.nfsProcedureDuration)
	}
	if features.StatsNFSClientIO() {
		r.nfsIOAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatNFSClientIO))
		r.nfsIO = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatNFSClientIO.Prom,
			Help: "bytes that the NFS client read from and wrote to servers",
		}, labelNames(r.nfsIOAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, r.nfsIO)
	}
	return register
}

// registerPodVolumeMetrics creates the metric of the devices of the pod volumes
func (r *statMetricsReporter) registerPodVolumeMetrics(cfg *StatsPrometheusConfig, provider *attributes.AttrSelector) []prometheus.Collector {
	if !cfg.CommonCfg.Features.StatsDiskPodVolumes() {
		return nil
	}
	r.k8sPodVolumeDeviceAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatK8sPodVolumeDevice))
	r.k8sPodVolumeDevice = NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: attributes.StatK8sPodVolumeDevice.Prom,
		Help: "1 for each disk that a volume that a pod mounts from a PersistentVolumeClaim is on",
	}, labelNames(r.k8sPodVolumeDeviceAttrs)).MetricVec, timeNow, cfg.Config.TTL)
	return []prometheus.Collector{r.k8sPodVolumeDevice}
}

// registerDiskOperationMetrics creates the metrics of the block requests beyond reads and
// writes: their wait before issue, flushes, discards and the requests in flight
func (r *statMetricsReporter) registerDiskOperationMetrics(cfg *StatsPrometheusConfig, provider *attributes.AttrSelector) []prometheus.Collector {
	features := cfg.CommonCfg.Features
	var register []prometheus.Collector
	histograms := []struct {
		enabled bool
		name    attributes.Name
		help    string
		buckets []float64
		dst     **Expirer[prometheus.Histogram]
		attrs   *[]attributes.Field[*ebpf.Stat, string]
	}{
		{
			features.StatsDiskQueueDuration(), attributes.StatDiskQueueDuration,
			"measures the time block I/O requests wait between their allocation and their issue to the device, in seconds",
			cfg.Config.Buckets.StatDiskQueueDurationHistogram, &r.diskQueueDuration, &r.diskQueueDurationAttrs,
		},
		{
			features.StatsDiskFlush(), attributes.StatDiskFlushDuration,
			"measures the duration of the cache flushes of block devices, in seconds",
			cfg.Config.Buckets.StatDiskFlushDurationHistogram, &r.diskFlushDuration, &r.diskFlushDurationAttrs,
		},
		{
			features.StatsDiskDiscard(), attributes.StatDiskDiscardDuration,
			"measures the duration of the block discard requests, in seconds",
			cfg.Config.Buckets.StatDiskDiscardDurationHistogram, &r.diskDiscardDuration, &r.diskDiscardDurationAttrs,
		},
	}
	for _, h := range histograms {
		if !h.enabled {
			continue
		}
		*h.attrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(h.name))
		*h.dst = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            h.name.Prom,
			Help:                            h.help,
			Buckets:                         h.buckets,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(*h.attrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, *h.dst)
	}

	if features.StatsDiskDiscard() {
		r.diskDiscardIOAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatDiskDiscardIO))
		r.diskDiscardIO = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskDiscardIO.Prom,
			Help: "bytes discarded by the block discard requests that completed successfully",
		}, labelNames(r.diskDiscardIOAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, r.diskDiscardIO)
	}

	if features.StatsDiskPendingOperations() {
		r.diskPendingOperationsAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatDiskPendingOperations))
		r.diskPendingOperations = NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.StatDiskPendingOperations.Prom,
			Help: "number of block I/O requests that a device is serving",
		}, labelNames(r.diskPendingOperationsAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, r.diskPendingOperations)
	}
	return register
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

func (r *statMetricsReporter) observeDiskOperationDuration(stat *ebpf.Stat) {
	if r.diskOperationDuration == nil || stat.DiskIO == nil || !stat.DiskIO.Op.IsTransfer() {
		return
	}
	observeLatency(r.diskOperationDuration.WithLabelValues(labelValues(stat, r.diskOperationDurationAttrs)...).Metric,
		stat.DiskIO.Latency)
}

func (r *statMetricsReporter) observeFsSyncDuration(stat *ebpf.Stat) {
	if r.fsSyncDuration == nil || stat.FsSync == nil {
		return
	}
	observeLatency(r.fsSyncDuration.WithLabelValues(labelValues(stat, r.fsSyncDurationAttrs)...).Metric,
		stat.FsSync.Latency)
}

// observeLatency observes each kernel histogram bucket sample as many times as requests it stands for
func observeLatency(histogram prometheus.Histogram, latency []ebpf.LatencySample) {
	for _, sample := range latency {
		for range sample.Count {
			histogram.Observe(sample.Seconds)
		}
	}
}

func (r *statMetricsReporter) observeDiskCounters(stat *ebpf.Stat) {
	if stat.DiskIO == nil || !stat.DiskIO.Op.IsTransfer() {
		return
	}
	if r.diskIO != nil && stat.DiskIO.Bytes > 0 {
		r.diskIO.WithLabelValues(labelValues(stat, r.diskIOAttrs)...).
			Metric.Add(float64(stat.DiskIO.Bytes))
	}
	if r.diskOperations != nil {
		r.diskOperations.WithLabelValues(labelValues(stat, r.diskOperationsAttrs)...).
			Metric.Add(float64(stat.DiskIO.Operations))
	}
	if r.diskOperationTime != nil {
		r.diskOperationTime.WithLabelValues(labelValues(stat, r.diskOperationTimeAttrs)...).
			Metric.Add(stat.DiskIO.Time)
	}
}

// observeDiskOperations observes the wait before issue of reads and writes, and the flushes and
// discards
func (r *statMetricsReporter) observeDiskOperations(stat *ebpf.Stat) {
	if stat.DiskIO == nil {
		return
	}
	switch stat.DiskIO.Op {
	case ebpf.CodeDiskOpRead, ebpf.CodeDiskOpWrite:
		observeLatencyIn(r.diskQueueDuration, r.diskQueueDurationAttrs, stat, stat.DiskIO.Queue)
	case ebpf.CodeDiskOpFlush:
		observeLatencyIn(r.diskFlushDuration, r.diskFlushDurationAttrs, stat, stat.DiskIO.Latency)
	case ebpf.CodeDiskOpDiscard:
		observeLatencyIn(r.diskDiscardDuration, r.diskDiscardDurationAttrs, stat, stat.DiskIO.Latency)
		if r.diskDiscardIO != nil && stat.DiskIO.Bytes > 0 {
			r.diskDiscardIO.WithLabelValues(labelValues(stat, r.diskDiscardIOAttrs)...).
				Metric.Add(float64(stat.DiskIO.Bytes))
		}
	}
}

func observeLatencyIn(histogram *Expirer[prometheus.Histogram], attrs []attributes.Field[*ebpf.Stat, string], stat *ebpf.Stat, latency []ebpf.LatencySample) {
	if histogram == nil || len(latency) == 0 {
		return
	}
	observeLatency(histogram.WithLabelValues(labelValues(stat, attrs)...).Metric, latency)
}

func (r *statMetricsReporter) observeNFS(stat *ebpf.Stat) {
	if stat.NFSProcedure != nil {
		observeLatencyIn(r.nfsProcedureDuration, r.nfsProcedureDurationAttrs, stat, stat.NFSProcedure.Latency)
	}
	if r.nfsIO != nil && stat.NFSIO != nil {
		r.nfsIO.WithLabelValues(labelValues(stat, r.nfsIOAttrs)...).Metric.Add(float64(stat.NFSIO.Bytes))
	}
}

func (r *statMetricsReporter) observePodVolume(stat *ebpf.Stat) {
	if r.k8sPodVolumeDevice == nil || stat.PodVolume == nil {
		return
	}
	r.k8sPodVolumeDevice.WithLabelValues(labelValues(stat, r.k8sPodVolumeDeviceAttrs)...).
		Metric.Set(float64(stat.PodVolume.Value))
}

func (r *statMetricsReporter) observeDiskPendingOperations(stat *ebpf.Stat) {
	if r.diskPendingOperations == nil || stat.DiskPending == nil {
		return
	}
	r.diskPendingOperations.WithLabelValues(labelValues(stat, r.diskPendingOperationsAttrs)...).
		Metric.Set(float64(stat.DiskPending.Requests))
}
