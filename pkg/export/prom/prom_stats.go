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
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// Help texts of the storage metrics, which kernel maps may aggregate.
const (
	helpDiskOperationDuration = "measures the block I/O latency as calculated by the kernel in seconds"
	helpDiskIO                = "count of bytes transferred at the block layer"
	helpDiskQueueDuration     = "measures the time a block I/O request spent queued before being dispatched to the device, in seconds"
	helpDiskOperationErrors   = "counts block I/O completions with a non-zero error, broken down by errno"
	helpDiskFlushDuration     = "measures the service time of block cache flush requests, from issue to completion, in seconds"
	helpDiskDiscardDuration   = "measures the service time of block discard and secure erase requests, from issue to completion, in seconds"
	helpDiskDiscardIO         = "count of bytes released by block discard and secure erase requests that completed successfully"
	helpDiskOperations        = "count of completed block read and write requests, by the pod the I/O is charged to"
	helpDiskOperationTime     = "time spent on block read and write requests from their accounting start, in seconds, by the pod the I/O is charged to"
	helpFsOperationDuration   = "filesystem read, write and sync latency in seconds, as the application sees it; buffered writes end once the data is in the page cache"
	helpFsIO                  = "count of bytes transferred at the filesystem layer"
	helpFsOperationErrors     = "counts filesystem I/O operations that failed, broken down by errno"
	helpNFSRPCDuration        = "execute time of each NFS client RPC attempt in seconds; a retry the server asks for (JUKEBOX, DELAY) is a new attempt, which includes the client's backoff"
	helpNFSRPCErrors          = "counts NFS client RPC attempts that ended with an error status, normal misses and server back-pressure included"
	helpNFSRPCRetransmits     = "counts retransmissions of NFS client RPC requests: every transmission of an attempt after the first"
	helpNFSClientIO           = "wire bytes of NFS client RPC calls and replies, headers and every procedure included"
)

// injectable function reference for testing

// StatsPrometheusConfig for stat metrics just wraps the global prom.StatsPrometheusConfig as provided by the user
type StatsPrometheusConfig struct {
	Config      *PrometheusConfig
	SelectorCfg *attributes.SelectorConfig
	CommonCfg   *perapp.GlobalMetricsConfig
	// Aggregated names the stat metrics that kernel maps aggregate: they are
	// collected by a statagg Collector instead of per-event metric vectors.
	// Nil exports every metric per event.
	Aggregated *statagg.Registry
	// PendingSnapshot, when non-nil, is called on every scrape to fill
	// obi.stat.disk.pending_operations: a userspace snapshot has no events
	// to observe, so it is collected by its own prometheus.Collector
	// instead of the per-event or Aggregated paths.
	PendingSnapshot func() ([]ebpf.PendingPoint, error)
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
	diskFlushDuration        *Expirer[prometheus.Histogram]
	diskDiscardDuration      *Expirer[prometheus.Histogram]
	diskDiscardIOBytes       *Expirer[prometheus.Counter]
	fsOpDuration             *Expirer[prometheus.Histogram]
	fsIOBytes                *Expirer[prometheus.Counter]
	fsOpErrors               *Expirer[prometheus.Counter]
	nfsRPCDuration           *Expirer[prometheus.Histogram]
	nfsRPCErrors             *Expirer[prometheus.Counter]
	nfsRPCRetransmits        *Expirer[prometheus.Counter]
	nfsClientIO              *Expirer[prometheus.Counter]

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
	diskFlushDurationAttrs        []attributes.Field[*ebpf.Stat, string]
	diskDiscardDurationAttrs      []attributes.Field[*ebpf.Stat, string]
	diskDiscardIOBytesAttrs       []attributes.Field[*ebpf.Stat, string]
	fsOpDurationAttrs             []attributes.Field[*ebpf.Stat, string]
	fsIOBytesAttrs                []attributes.Field[*ebpf.Stat, string]
	fsOpErrorsAttrs               []attributes.Field[*ebpf.Stat, string]
	nfsRPCDurationAttrs           []attributes.Field[*ebpf.Stat, string]
	nfsRPCErrorsAttrs             []attributes.Field[*ebpf.Stat, string]
	nfsRPCRetransmitsAttrs        []attributes.Field[*ebpf.Stat, string]
	nfsClientIOAttrs              []attributes.Field[*ebpf.Stat, string]

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

	if cfg.CommonCfg.Features.StorageBlockDuration() && !cfg.Aggregated.Handles(attributes.StatDiskOperationDuration) {
		log.Debug("registering stat disk operation duration metric")

		mr.diskOpDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskOperationDuration))

		mr.diskOpDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatDiskOperationDuration.Prom,
			Help:                            helpDiskOperationDuration,
			Buckets:                         cfg.Config.Buckets.StatDiskOperationDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.diskOpDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskOpDuration)
	}

	if cfg.CommonCfg.Features.StorageBlockIo() && !cfg.Aggregated.Handles(attributes.StatDiskIO) {
		log.Debug("registering stat disk io bytes metric")

		mr.diskIOBytesAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskIO))

		mr.diskIOBytes = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskIO.Prom,
			Help: helpDiskIO,
		}, labelNames(mr.diskIOBytesAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskIOBytes)
	}

	if cfg.CommonCfg.Features.StorageBlockQueue() && !cfg.Aggregated.Handles(attributes.StatDiskQueueDuration) {
		log.Debug("registering stat disk queue duration metric")

		mr.diskQueueDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskQueueDuration))

		mr.diskQueueDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatDiskQueueDuration.Prom,
			Help:                            helpDiskQueueDuration,
			Buckets:                         cfg.Config.Buckets.StatDiskOperationDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.diskQueueDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskQueueDuration)
	}

	if cfg.CommonCfg.Features.StorageBlockQueueDepth() {
		log.Debug("registering stat disk queue depth metric")

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

	if cfg.CommonCfg.Features.StorageBlockErrors() && !cfg.Aggregated.Handles(attributes.StatDiskOperationErrors) {
		log.Debug("registering stat disk operation errors metric")

		mr.diskOpErrorsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskOperationErrors))

		mr.diskOpErrors = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskOperationErrors.Prom,
			Help: helpDiskOperationErrors,
		}, labelNames(mr.diskOpErrorsAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskOpErrors)
	}

	if cfg.CommonCfg.Features.StorageBlockFlush() && !cfg.Aggregated.Handles(attributes.StatDiskFlushDuration) {
		log.Debug("registering stat disk flush duration metric")

		mr.diskFlushDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskFlushDuration))

		mr.diskFlushDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatDiskFlushDuration.Prom,
			Help:                            helpDiskFlushDuration,
			Buckets:                         cfg.Config.Buckets.StatDiskOperationDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.diskFlushDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskFlushDuration)
	}

	if cfg.CommonCfg.Features.StorageBlockDiscard() && !cfg.Aggregated.Handles(attributes.StatDiskDiscardDuration) {
		log.Debug("registering stat disk discard duration metric")

		mr.diskDiscardDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskDiscardDuration))

		mr.diskDiscardDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatDiskDiscardDuration.Prom,
			Help:                            helpDiskDiscardDuration,
			Buckets:                         cfg.Config.Buckets.StatDiskOperationDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.diskDiscardDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskDiscardDuration)
	}

	if cfg.CommonCfg.Features.StorageBlockDiscard() && !cfg.Aggregated.Handles(attributes.StatDiskDiscardIO) {
		log.Debug("registering stat disk discard io bytes metric")

		mr.diskDiscardIOBytesAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatDiskDiscardIO))

		mr.diskDiscardIOBytes = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatDiskDiscardIO.Prom,
			Help: helpDiskDiscardIO,
		}, labelNames(mr.diskDiscardIOBytesAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.diskDiscardIOBytes)
	}

	if cfg.CommonCfg.Features.StorageFSDuration() && !cfg.Aggregated.Handles(attributes.StatFsOperationDuration) {
		log.Debug("registering stat fs operation duration metric")

		mr.fsOpDurationAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatFsOperationDuration))

		mr.fsOpDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatFsOperationDuration.Prom,
			Help:                            helpFsOperationDuration,
			Buckets:                         cfg.Config.Buckets.StatFsOperationDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.fsOpDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.fsOpDuration)
	}

	if cfg.CommonCfg.Features.StorageFSIo() && !cfg.Aggregated.Handles(attributes.StatFsIO) {
		log.Debug("registering stat fs io bytes metric")

		mr.fsIOBytesAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatFsIO))

		mr.fsIOBytes = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatFsIO.Prom,
			Help: helpFsIO,
		}, labelNames(mr.fsIOBytesAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.fsIOBytes)
	}

	if cfg.CommonCfg.Features.StorageFSErrors() && !cfg.Aggregated.Handles(attributes.StatFsOperationErrors) {
		log.Debug("registering stat fs operation errors metric")

		mr.fsOpErrorsAttrs = attributes.PrometheusGetters(
			ebpf.StatStringGetters,
			provider.For(attributes.StatFsOperationErrors))

		mr.fsOpErrors = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatFsOperationErrors.Prom,
			Help: helpFsOperationErrors,
		}, labelNames(mr.fsOpErrorsAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.fsOpErrors)
	}

	// The NFS client RPC metrics are counted by the kernel: these metric
	// vectors only see NFS stats in the parity tests of kernel aggregation,
	// whose reference they are.
	if cfg.CommonCfg.Features.StorageNFSDuration() && !cfg.Aggregated.Handles(attributes.StatNFSClientRPCDuration) {
		mr.nfsRPCDurationAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatNFSClientRPCDuration))
		mr.nfsRPCDuration = NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            attributes.StatNFSClientRPCDuration.Prom,
			Help:                            helpNFSRPCDuration,
			Buckets:                         cfg.Config.Buckets.StatNFSClientRPCDurationHistogram,
			NativeHistogramBucketFactor:     cfg.Config.NativeHistogram.BucketFactor,
			NativeHistogramMaxBucketNumber:  cfg.Config.NativeHistogram.MaxBucketNumber,
			NativeHistogramMinResetDuration: cfg.Config.NativeHistogram.MinResetDuration,
		}, labelNames(mr.nfsRPCDurationAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.nfsRPCDuration)
	}

	if cfg.CommonCfg.Features.StorageNFSErrors() && !cfg.Aggregated.Handles(attributes.StatNFSClientRPCErrors) {
		mr.nfsRPCErrorsAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatNFSClientRPCErrors))
		mr.nfsRPCErrors = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatNFSClientRPCErrors.Prom,
			Help: helpNFSRPCErrors,
		}, labelNames(mr.nfsRPCErrorsAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.nfsRPCErrors)
	}

	if cfg.CommonCfg.Features.StorageNFSRetransmits() && !cfg.Aggregated.Handles(attributes.StatNFSClientRPCRetransmits) {
		mr.nfsRPCRetransmitsAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatNFSClientRPCRetransmits))
		mr.nfsRPCRetransmits = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatNFSClientRPCRetransmits.Prom,
			Help: helpNFSRPCRetransmits,
		}, labelNames(mr.nfsRPCRetransmitsAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.nfsRPCRetransmits)
	}

	if cfg.CommonCfg.Features.StorageNFSIo() && !cfg.Aggregated.Handles(attributes.StatNFSClientIO) {
		mr.nfsClientIOAttrs = attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatNFSClientIO))
		mr.nfsClientIO = NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.StatNFSClientIO.Prom,
			Help: helpNFSClientIO,
		}, labelNames(mr.nfsClientIOAttrs)).MetricVec, timeNow, cfg.Config.TTL)
		register = append(register, mr.nfsClientIO)
	}

	if cfg.CommonCfg.Features.StorageBlockPending() && cfg.PendingSnapshot != nil {
		log.Debug("registering stat disk pending operations metric")

		register = append(register, newPendingCollector(cfg, provider))
	}

	if cfg.Aggregated != nil {
		aggregated, err := aggregatedStatsCollector(cfg, provider)
		if err != nil {
			return nil, fmt.Errorf("stats Prometheus exporter aggregated metrics: %w", err)
		}
		register = append(register, aggregated)
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
			r.observeDiskFlushDuration(stat)
			r.observeDiskDiscard(stat)
			r.observeFsOpDuration(stat)
			r.observeFsIOBytes(stat)
			r.observeFsOpErrors(stat)
			r.observeNFSRPC(stat)
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
	if r.diskOpDuration == nil || !stat.BlockIo.IsReadWrite() {
		return
	}
	r.diskOpDuration.WithLabelValues(labelValues(stat, r.diskOpDurationAttrs)...).
		Metric.Observe(time.Duration(stat.BlockIo.LatencyNs).Seconds())
}

func (r *statMetricsReporter) observeDiskIOBytes(stat *ebpf.Stat) {
	if r.diskIOBytes == nil || !stat.BlockIo.IsReadWrite() {
		return
	}
	r.diskIOBytes.WithLabelValues(labelValues(stat, r.diskIOBytesAttrs)...).
		Metric.Add(float64(stat.BlockIo.Bytes))
}

func (r *statMetricsReporter) observeDiskQueueDuration(stat *ebpf.Stat) {
	// QueueNs == 0 means no valid accounting start matched this request (e.g.
	// blk-mq issued it directly): there is no queue wait to observe, and a
	// genuine 0ns queue wait is not observable in practice.
	if r.diskQueueDuration == nil || !stat.BlockIo.IsReadWrite() || stat.BlockIo.QueueNs == 0 {
		return
	}
	r.diskQueueDuration.WithLabelValues(labelValues(stat, r.diskQueueDurationAttrs)...).
		Metric.Observe(time.Duration(stat.BlockIo.QueueNs).Seconds())
}

func (r *statMetricsReporter) observeDiskQueueDepth(stat *ebpf.Stat) {
	if r.diskQueueDepth == nil || !stat.BlockIo.IsReadWrite() {
		return
	}
	r.diskQueueDepth.WithLabelValues(labelValues(stat, r.diskQueueDepthAttrs)...).
		Metric.Observe(float64(stat.BlockIo.Inflight))
}

func (r *statMetricsReporter) observeDiskOpErrors(stat *ebpf.Stat) {
	if r.diskOpErrors == nil || !stat.BlockIo.IsReadWrite() || stat.BlockIo.Error == 0 {
		return
	}
	r.diskOpErrors.WithLabelValues(labelValues(stat, r.diskOpErrorsAttrs)...).
		Metric.Add(1)
}

func (r *statMetricsReporter) observeDiskFlushDuration(stat *ebpf.Stat) {
	if r.diskFlushDuration == nil || !stat.BlockIo.IsFlush() {
		return
	}
	r.diskFlushDuration.WithLabelValues(labelValues(stat, r.diskFlushDurationAttrs)...).
		Metric.Observe(time.Duration(stat.BlockIo.LatencyNs).Seconds())
}

func (r *statMetricsReporter) observeDiskDiscard(stat *ebpf.Stat) {
	if !stat.BlockIo.IsDiscard() {
		return
	}
	if r.diskDiscardDuration != nil {
		r.diskDiscardDuration.WithLabelValues(labelValues(stat, r.diskDiscardDurationAttrs)...).
			Metric.Observe(time.Duration(stat.BlockIo.LatencyNs).Seconds())
	}
	// A failed discard released nothing, so only successful ones add bytes;
	// the failure itself is on the duration histogram.
	if r.diskDiscardIOBytes == nil || stat.BlockIo.Error != 0 {
		return
	}
	r.diskDiscardIOBytes.WithLabelValues(labelValues(stat, r.diskDiscardIOBytesAttrs)...).
		Metric.Add(float64(stat.BlockIo.Bytes))
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

func (r *statMetricsReporter) observeNFSRPC(stat *ebpf.Stat) {
	if stat.NFSRPC == nil {
		return
	}
	if r.nfsRPCDuration != nil {
		r.nfsRPCDuration.WithLabelValues(labelValues(stat, r.nfsRPCDurationAttrs)...).
			Metric.Observe(time.Duration(stat.NFSRPC.ExecuteNs).Seconds())
	}
	if r.nfsRPCErrors != nil && stat.NFSRPC.Status != 0 {
		r.nfsRPCErrors.WithLabelValues(labelValues(stat, r.nfsRPCErrorsAttrs)...).Metric.Add(1)
	}
	if r.nfsRPCRetransmits != nil && stat.NFSRPC.Retransmits != 0 {
		r.nfsRPCRetransmits.WithLabelValues(labelValues(stat, r.nfsRPCRetransmitsAttrs)...).
			Metric.Add(float64(stat.NFSRPC.Retransmits))
	}
	if r.nfsClientIO != nil {
		// One kernel key counts both directions together: project a copy
		// twice, transmit then receive, each its own direction series.
		// stat is shared with every other subscriber of the stats queue
		// (e.g. the OTel exporter, run concurrently in the parity
		// harness), so its NFSRPC is never mutated in place.
		nfs := *stat.NFSRPC
		tx, rx := nfs, nfs
		tx.Direction, rx.Direction = uint8(ebpf.CodeDirectionTransmit), uint8(ebpf.CodeDirectionReceive)
		txStat, rxStat := *stat, *stat
		txStat.NFSRPC, rxStat.NFSRPC = &tx, &rx

		r.nfsClientIO.WithLabelValues(labelValues(&txStat, r.nfsClientIOAttrs)...).
			Metric.Add(float64(nfs.TxBytes))
		r.nfsClientIO.WithLabelValues(labelValues(&rxStat, r.nfsClientIOAttrs)...).
			Metric.Add(float64(nfs.RxBytes))
	}
}

// aggregatableStat is a stat metric that a kernel map may aggregate.
type aggregatableStat struct {
	name    attributes.Name
	enabled bool
	help    string
	buckets []float64
}

// aggregatableStats lists the storage metrics that kernel aggregation may
// take over; queue depth stays per event.
func aggregatableStats(cfg *StatsPrometheusConfig) []aggregatableStat {
	f, b := cfg.CommonCfg.Features, &cfg.Config.Buckets
	return []aggregatableStat{
		{attributes.StatDiskOperationDuration, f.StorageBlockDuration(), helpDiskOperationDuration, b.StatDiskOperationDurationHistogram},
		{attributes.StatDiskIO, f.StorageBlockIo(), helpDiskIO, nil},
		{attributes.StatDiskQueueDuration, f.StorageBlockQueue(), helpDiskQueueDuration, b.StatDiskOperationDurationHistogram},
		{attributes.StatDiskOperationErrors, f.StorageBlockErrors(), helpDiskOperationErrors, nil},
		{attributes.StatDiskFlushDuration, f.StorageBlockFlush(), helpDiskFlushDuration, b.StatDiskOperationDurationHistogram},
		{attributes.StatDiskDiscardDuration, f.StorageBlockDiscard(), helpDiskDiscardDuration, b.StatDiskOperationDurationHistogram},
		{attributes.StatDiskDiscardIO, f.StorageBlockDiscard(), helpDiskDiscardIO, nil},
		// Kernel-aggregated only: blk_cg_agg counts them, in either block
		// emit mode.
		{attributes.StatDiskOperations, f.StorageBlockPod(), helpDiskOperations, nil},
		{attributes.StatDiskOperationTime, f.StorageBlockPod(), helpDiskOperationTime, nil},
		{attributes.StatFsOperationDuration, f.StorageFSDuration(), helpFsOperationDuration, b.StatFsOperationDurationHistogram},
		{attributes.StatFsIO, f.StorageFSIo(), helpFsIO, nil},
		{attributes.StatFsOperationErrors, f.StorageFSErrors(), helpFsOperationErrors, nil},
		{attributes.StatNFSClientRPCDuration, f.StorageNFSDuration(), helpNFSRPCDuration, b.StatNFSClientRPCDurationHistogram},
		{attributes.StatNFSClientRPCErrors, f.StorageNFSErrors(), helpNFSRPCErrors, nil},
		{attributes.StatNFSClientRPCRetransmits, f.StorageNFSRetransmits(), helpNFSRPCRetransmits, nil},
		{attributes.StatNFSClientIO, f.StorageNFSIo(), helpNFSClientIO, nil},
	}
}

// aggregatedStatsCollector collects the enabled metrics that kernel maps
// aggregate, with the labels and buckets their metric vectors would have.
func aggregatedStatsCollector(cfg *StatsPrometheusConfig, provider *attributes.AttrSelector) (*statagg.Collector, error) {
	c := statagg.NewCollector(cfg.Aggregated, cfg.Config.TTL)
	for _, s := range aggregatableStats(cfg) {
		if !s.enabled || !cfg.Aggregated.Handles(s.name) {
			continue
		}
		getters := attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(s.name))
		if err := c.Add(s.name, statagg.PromMetric{
			Help:       s.help,
			Bounds:     s.buckets,
			LabelNames: labelNames(getters),
			Project: func(stat *ebpf.Stat) (string, []string) {
				values := labelValues(stat, getters)
				return statagg.SeriesKey(values), values
			},
		}); err != nil {
			return nil, err
		}
	}
	return c, nil
}
