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
	"sync"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/logger"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
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

	// what the pipeline built that the decoration of aggregated stats shares
	aggDeps aggregationDeps
	// the kernel histogram layout of the NFS client RPC metrics
	nfsLayout *statagg.Layout
	// nfsOwner is whether a pod attribute is selected on an NFS metric
	// (step 19); nfsCgroupV1 is whether the owner it keys is a tgid
	// (task->tk_owner) resolved by the pid path, rather than a cgroup v2 id
	// resolved by cgroups.
	nfsOwner, nfsCgroupV1 bool
	// fsAccum is the kernel map the filesystem programs aggregate into, and
	// fsLayout its histogram layout; nil when they send ring buffer events.
	fsAccum  statagg.Source
	fsLayout *statagg.Layout
	// families are the kernel aggregation families the exporters read, and
	// cgroups the index their decoration shares (nil until a family needs
	// it, and on a cgroup v1 host); Run starts both.
	families []*statagg.Family
	cgroups  *statagg.CgroupIndex
	// the running families, which stop waits for before closing their maps
	familiesRunning sync.WaitGroup
	// blockLayout is the kernel histogram layout of the block aggregation
	// maps, nil when block completions are sent as events.
	blockLayout *statagg.Layout

	status Status
}

type ebpFetcher interface {
	io.Closer
	StatsEventsMap() *ciliumebpf.Map
	DebugEventsMap() *ciliumebpf.Map
	NFSRPCMap() *ciliumebpf.Map
	FsAccumMap() *ciliumebpf.Map
	BlockAggregation() *ebpf.BlockAggMaps
	KernelDropsMap() *ciliumebpf.Map
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
	nfsLayout, err := cfg.NFSHistogramLayout(cfg.OTELMetrics.EndpointEnabled())
	if err != nil {
		return nil, fmt.Errorf("NFS client RPC histogram: %w", err)
	}
	// UndefinedGroup: the NFS owner attributes (the pod trio, k8s.owner.name)
	// are direct metric attributes, not a group.
	attrSel, err := attributes.NewAttrSelector(attributes.UndefinedGroup, selectorCfg)
	if err != nil {
		return nil, fmt.Errorf("creating attr selector: %w", err)
	}
	nfsOwner := nfsOwnerWanted(attrSel)
	nfsCgroupV1Host := nfsOwner && nfsCgroupV1()
	nfsCfg := ebpf.NFSConfig{
		Exponential:  nfsLayout.Kind == statagg.LayoutExponential,
		KernelBounds: nfsLayout.KernelBounds(),
		Owner:        nfsOwner,
		CgroupV1:     nfsCgroupV1Host,
	}
	fsAgg, fsLayout := fsAggregation(cfg, alog)
	blockAgg, blockLayout := blockAggregation(cfg, alog)
	statsFetcher, err = newFetcher(&cfg.EBPF, &cfg.Metrics.Features, selectorCfg, fsAgg, nfsCfg, blockAgg, ctxInfo.Metrics)
	if err != nil {
		return nil, err
	}

	s := statsAgent(ctxInfo, cfg, statsFetcher, agentIP)
	s.nfsLayout = nfsLayout
	s.nfsOwner = nfsOwner
	s.nfsCgroupV1 = nfsCgroupV1Host
	s.blockLayout = blockLayout
	// No map when no filesystem collection could be created: the
	// filesystem metrics then have nothing to export either way.
	if m := statsFetcher.FsAccumMap(); m != nil {
		if s.fsAccum, err = newMapSource(m); err != nil {
			_ = statsFetcher.Close()
			return nil, fmt.Errorf("reading the filesystem aggregation map: %w", err)
		}
		s.fsLayout = fsLayout
	}
	return s, nil
}

func newFetcher(
	cfg *config.EBPFTracer, features *export.Features, selectorCfg *attributes.SelectorConfig, fsAgg ebpf.FsAggregation,
	nfsCfg ebpf.NFSConfig, blockAgg *ebpf.BlockAggregation, metrics imetrics.Reporter,
) (ebpFetcher, error) {
	return ebpf.NewStatsFetcher(cfg, features, selectorCfg, fsAgg, nfsCfg, blockAgg, metrics)
}

// statsAgent is a private constructor with injectable dependencies, usable for tests
func statsAgent(
	ctxInfo *global.ContextInfo,
	cfg *obi.Config,
	statsFetcher ebpFetcher,
	agentIP net.IP,
) *Stats {
	rbTracer := stats.NewRingBufTracer(statsFetcher.StatsEventsMap(), &cfg.EBPF)

	return &Stats{
		ctxInfo:  ctxInfo,
		cfg:      cfg,
		rbTracer: rbTracer,
		agentIP:  agentIP,
		fetcher:  statsFetcher,
	}
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
	// After the pipeline is built: the exporters are attached to the
	// families, so none misses a delta.
	s.runAggregation(runCtx)
	s.status = StatusStarted

	alog.Info("Stats agent successfully started")

	<-ctx.Done()
	cancel()

	if err := s.stop(); err != nil {
		return fmt.Errorf("failed to stop Stats agent: %w", err)
	}

	return nil
}

// stop waits for the families, whose context must be done, to read their
// maps a last time before it closes the eBPF objects: a family reading a
// closed map would lose what the kernel counted since its last read.
func (s *Stats) stop() error {
	alog := alog()

	stopped := make(chan error)
	go func() {
		s.status = StatusStopping
		alog.Info("stopping Stats agent")
		s.familiesRunning.Wait()
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
