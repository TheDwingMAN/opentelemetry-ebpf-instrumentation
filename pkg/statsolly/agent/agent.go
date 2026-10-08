// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/logger"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	stats "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
	"go.opentelemetry.io/obi/pkg/netip"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func alog() *slog.Logger {
	return slog.With("component", "agent.StatsO11y")
}

// Status of the agent service. Helps on the health report as well as making some asynchronous
// tests waiting for the agent to accept stats.
type Status int

const (
	StatusNotStarted Status = iota
	StatusStarting
	StatusStarted
	StatusStopping
	StatusStopped
)

func (s Status) String() string {
	switch s {
	case StatusNotStarted:
		return "StatusNotStarted"
	case StatusStarting:
		return "StatusStarting"
	case StatusStarted:
		return "StatusStarted"
	case StatusStopping:
		return "StatusStopping"
	case StatusStopped:
		return "StatusStopped"
	default:
		return "invalid"
	}
}

var errShutdownTimeout = errors.New("graceful shutdown has timed out while waiting for eBPF statsolly to finish")

// Stats reporting agent
type Stats struct {
	cfg     *obi.Config
	ctxInfo *global.ContextInfo
	graph   *swarm.Runner

	// elements used to decorate stats with extra information
	agentIP net.IP

	// stat metrics
	rbTracer *stats.RingBufTracer

	// focuses on TCP/UDP stack internals (kprobes/tracepoints)
	fetcher ebpFetcher

	status Status
}

type ebpFetcher interface {
	io.Closer
	StatsEventsMap() *ciliumebpf.Map
	DebugEventsMap() *ciliumebpf.Map
	DisabledStorageFeatures() []ebpf.DisabledFeature
}

func StatsAgent(ctxInfo *global.ContextInfo, cfg *obi.Config) (*Stats, error) {
	alog := alog()
	alog.Info("initializing Stats agent")

	var (
		statsFetcher ebpFetcher
		err          error
	)

	alog.Debug("acquiring Agent IP")

	agentIP, err := netip.FetchAgentIP(cfg.Stats.AgentIP, string(cfg.Stats.AgentIPIface), cfg.Stats.AgentIPType)
	if err != nil {
		return nil, fmt.Errorf("acquiring Agent IP: %w", err)
	}
	alog.Debug("agent IP: " + agentIP.String())

	selectorCfg := &attributes.SelectorConfig{
		SelectionCfg:            cfg.Attributes.Select,
		ExtraGroupAttributesCfg: cfg.Attributes.ExtraGroupAttributes,
	}
	features := cfg.Metrics.Features

	histograms, approximated := latencyHistograms(cfg)
	if len(approximated) > 0 {
		alog.Warn("more histogram buckets than the kernel can keep: these histograms are approximated",
			"histograms", approximated)
	}

	statsFetcher, err = newFetcher(&cfg.EBPF, &features, selectorCfg, histograms)
	if err != nil {
		return nil, err
	}
	if disabled := statsFetcher.DisabledStorageFeatures(); len(disabled) > 0 {
		warnDisabledStorage(disabled)
	} else if storageProbesEnabled(&features) {
		alog.Info("the probes of the enabled storage metrics are loaded")
	}

	return statsAgent(ctxInfo, cfg, statsFetcher, agentIP)
}

func newFetcher(cfg *config.EBPFTracer, features *export.Features,
	selectorCfg *attributes.SelectorConfig, histograms ebpf.LatencyHistograms,
) (ebpFetcher, error) {
	return ebpf.NewStatsFetcher(cfg, features, selectorCfg, histograms)
}

// storageProbesEnabled tells whether any enabled storage metric needs probes
func storageProbesEnabled(features *export.Features) bool {
	return features.StatsDisk()
}

// warnDisabledStorage logs the enabled storage features whose probes can't be loaded or attached
func warnDisabledStorage(disabled []ebpf.DisabledFeature) {
	for _, d := range disabled {
		alog().Warn("storage metrics disabled on this node: their probes can't be loaded. The other metrics keep working",
			"metrics", d.Feature, "reason", d.Reason)
	}
}

// latencyHistograms returns the boundaries the kernel buckets latencies with: the union of the
// boundaries of the enabled histograms in the enabled exporters, so that the kernel buckets refine
// all of them. It also returns the configuration names of the histograms that have more boundaries
// than the kernel keeps, which are approximated.
func latencyHistograms(cfg *obi.Config) (ebpf.LatencyHistograms, []string) {
	var exporters []export.Buckets
	if cfg.Prometheus.EndpointEnabled() {
		exporters = append(exporters, cfg.Prometheus.Buckets)
	}
	if cfg.OTELMetrics.EndpointEnabled() {
		exporters = append(exporters, cfg.OTELMetrics.Buckets)
	}
	features := cfg.Metrics.Features
	var histograms ebpf.LatencyHistograms
	for _, buckets := range exporters {
		if features.StatsDiskOperationDuration() {
			histograms.Disk = append(histograms.Disk, buckets.StatDiskOperationDurationHistogram...)
		}
	}
	var approximated []string
	for _, group := range []struct {
		bounds *[]float64
		names  string
	}{
		{&histograms.Disk, "stat_disk_operation_duration_histogram"},
	} {
		var exact bool
		if *group.bounds, exact = ebpf.KernelLatencyBounds(*group.bounds); !exact {
			approximated = append(approximated, group.names)
		}
	}
	return histograms, approximated
}

// statsAgent is a private constructor with injectable dependencies, usable for tests
func statsAgent(
	ctxInfo *global.ContextInfo,
	cfg *obi.Config,
	statsFetcher ebpFetcher,
	agentIP net.IP,
) (*Stats, error) {
	rbTracer := stats.NewRingBufTracer(statsFetcher.StatsEventsMap(), &cfg.EBPF)

	return &Stats{
		ctxInfo:  ctxInfo,
		cfg:      cfg,
		rbTracer: rbTracer,
		agentIP:  agentIP,
		fetcher:  statsFetcher,
	}, nil
}

// Run a Stats agent
func (s *Stats) Run(ctx context.Context) error {
	alog := alog()

	s.status = StatusStarting
	alog.Info("starting Stats agent")

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if s.cfg.EBPF.BpfDebug {
		go logger.ReadDebugEventsMap(runCtx, s.fetcher.DebugEventsMap(),
			slog.With("component", "statsolly.BPFDebug"))
	}

	graph, err := s.buildPipeline(ctx)
	if err != nil {
		return fmt.Errorf("starting processing graph: %w", err)
	}

	s.graph = graph

	s.graph.Start(ctx, swarm.WithCancelTimeout(tracefs.EffectiveShutdownTimeout(s.cfg.ShutdownTimeout)))
	s.status = StatusStarted

	alog.Info("Stats agent successfully started")

	<-ctx.Done()

	if err := s.stop(); err != nil {
		return fmt.Errorf("failed to stop Stats agent: %w", err)
	}

	return nil
}

func (s *Stats) stop() error {
	alog := alog()

	stopped := make(chan error)
	go func() {
		s.status = StatusStopping
		alog.Info("stopping Stats agent")
		if err := s.fetcher.Close(); err != nil {
			alog.Warn("eBPF resources not correctly closed", "error", err)
		}

		alog.Debug("waiting for all nodes to finish their pending work")

		err := <-s.graph.Done()

		s.status = StatusStopped

		stopped <- err

		close(stopped)

		alog.Info("Stats agent stopped")
	}()

	select {
	case <-time.After(tracefs.EffectiveShutdownTimeout(s.cfg.ShutdownTimeout)):
		return errShutdownTimeout
	case err := <-stopped:
		// err might be nil
		return err
	}
}

func (s *Stats) Status() Status {
	return s.status
}
