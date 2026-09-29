// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"fmt"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	msgh "go.opentelemetry.io/obi/pkg/internal/helpers/msg"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/pipe/cidr"
	"go.opentelemetry.io/obi/pkg/internal/pipe/decorate"
	"go.opentelemetry.io/obi/pkg/internal/pipe/geoip"
	"go.opentelemetry.io/obi/pkg/internal/pipe/rdns"
	"go.opentelemetry.io/obi/pkg/internal/pipe/transform/dynamicpid"
	"go.opentelemetry.io/obi/pkg/internal/pipe/transform/k8s"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/export"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/selection"
)

func statAttrs(s *ebpf.Stat) *pipe.CommonAttrs { return &s.CommonAttrs }

// fsIoPID extracts the PID namespace, host PID, and filesystem superblock
// device number from a filesystem I/O stat, for Kubernetes pod and
// persistent volume attribution. Stats that don't carry FsIo are left alone.
func fsIoPID(s *ebpf.Stat) (pidNs, hostPID, sDev uint32, ok bool) {
	if s.FsIo == nil {
		return 0, 0, 0, false
	}
	return s.FsIo.PidNs, s.FsIo.HostPID, s.FsIo.SDev, true
}

// noPVCLookup reports every volume as unbound. Used when Kubernetes is
// disabled or no API client is reachable, so the decorator still attributes the
// persistent volume name from the mount path without a claim name or storage class.
func noPVCLookup(context.Context, string) (string, string, string, bool) { return "", "", "", false }

// mockable functions for testing
var newRingBufTracer = func(s *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return s.rbTracer.TraceLoop(out)
}

// buildPipeline defines the different nodes in the OBI's StatsO11y module,
// as well as how they are interconnected (in its Connect() method)
func (s *Stats) buildPipeline(ctx context.Context) (*swarm.Runner, error) {
	alog := alog()

	alog.Debug("creating stats processing graph")

	selectorCfg := &attributes.SelectorConfig{
		SelectionCfg:            s.cfg.Attributes.Select,
		ExtraGroupAttributesCfg: s.cfg.Attributes.ExtraGroupAttributes,
	}

	swi := &swarm.Instancer{}
	// Start nodes: those generating stats (reading them from eBPF)
	ebpfStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "ebpfStats")
	swi.Add(swarm.DirectInstance(newRingBufTracer(s, ebpfStats)), swarm.WithID("RingBufTracer"))

	// Middle nodes: transforming stats and passing them to the next stage in the pipeline.
	// Many of the nodes here are not mandatory. It's decision of each InstanceFunc to decide
	// whether the node needs to be instantiated or just bypass their input/output channels.
	kubeDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "kubeDecoratedStats")
	swi.Add(k8s.MetadataDecoratorProvider(ctx, &s.cfg.Attributes.Kubernetes, s.ctxInfo.K8sInformer,
		statAttrs, ebpfStats, kubeDecoratedStats), swarm.WithID("K8sMetadataDecorator"))

	var pidK8sStore *kube.Store
	if s.ctxInfo.K8sInformer.IsKubeEnabled() {
		var err error
		pidK8sStore, err = s.ctxInfo.K8sInformer.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("initializing PIDMetadataDecorator: %w", err)
		}
	}
	pvcLookup := ebpf.PVCLookup(noPVCLookup)
	if pidK8sStore != nil {
		if kubeClient, err := s.ctxInfo.K8sInformer.KubeClient(); err == nil {
			pvcLookup = ebpf.K8sPVCLookup(kubeClient)
		} else {
			alog.Warn("no Kubernetes client for PV to PVC resolution;"+
				" filesystem metrics will carry the volume name without a claim name", "error", err)
		}
	}

	if s.ctxInfo.K8sInformer.IsKubeEnabled() && s.cfg.Metrics.Features.StorageFS() {
		ebpf.WarnIfNoKubeletVolumeMounts(alog)
	}

	pidDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "pidDecoratedStats")
	swi.Add(k8s.PIDMetadataDecoratorProvider(ctx, pidK8sStore, statAttrs, fsIoPID,
		ebpf.CachedPVCLookup(pvcLookup), kubeDecoratedStats, pidDecoratedStats),
		swarm.WithID("PIDMetadataDecorator"))

	dnsDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "dnsDecoratedStats")
	swi.Add(rdns.ReverseDNSProvider(&s.cfg.Stats.ReverseDNS, statAttrs, &s.cfg.EBPF, pidDecoratedStats, dnsDecoratedStats),
		swarm.WithID("ReverseDNS"))

	geoIPDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "geoIPDecoratedStats")
	swi.Add(geoip.GeoIPProvider(&s.cfg.Stats.GeoIP, statAttrs,
		dnsDecoratedStats, geoIPDecoratedStats), swarm.WithID("GeoIPDecorator"))

	cidrDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "cidrDecoratedStats")
	swi.Add(cidr.DecoratorProvider(s.cfg.Stats.CIDRs, statAttrs, geoIPDecoratedStats, cidrDecoratedStats),
		swarm.WithID("CIDRDecorator"))

	decoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "decoratedStats")
	swi.Add(decorate.Decorate(s.agentIP, statAttrs, cidrDecoratedStats, decoratedStats),
		swarm.WithID("StatsDecorator"))

	dynamicFilteredStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "dynamicFilteredStats")
	var dynamicSelector selection.PIDSelector
	if s.ctxInfo.DynamicPIDSelector != nil {
		dynamicSelector = s.ctxInfo.DynamicPIDSelector.StatsMetrics()
	}
	dynamicDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "dynamicDecoratedStats")
	swi.Add(dynamicpid.MetadataDecoratorProvider(s.ctxInfo.DynamicPIDSelector, dynamicSelector,
		s.ctxInfo.K8sInformer, statAttrs, decoratedStats, dynamicDecoratedStats),
		swarm.WithID("DynamicPIDMetadataDecorator"))
	swi.Add(filter.ByDynamicPID(dynamicSelector, s.ctxInfo.K8sInformer,
		statAttrs, dynamicDecoratedStats, dynamicFilteredStats),
		swarm.WithID("DynamicPIDFilter"))

	filteredStats := s.ctxInfo.OverrideStatsExportQueue
	if filteredStats == nil {
		filteredStats = msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, "filteredStats")
	}
	swi.Add(filter.ByAttribute(s.cfg.Filters.Stats, nil, selectorCfg.ExtraGroupAttributesCfg, ebpf.StatStringGetters, dynamicFilteredStats, filteredStats),
		swarm.WithID("AttributeFilter"))

	// Terminal nodes export the stats record information out of the pipeline: OTEL, Prom and printer.
	// Not all the nodes are mandatory here. Is the responsibility of each Provider function to decide
	// whether each node is going to be instantiated or just ignored.
	swi.Add(otel.StatMetricsExporterProvider(s.ctxInfo, &otel.StatMetricsConfig{
		Metrics:     &s.cfg.OTELMetrics,
		SelectorCfg: selectorCfg,
		CommonCfg:   &s.cfg.Metrics,
	}, filteredStats), swarm.WithID("OTelExporter"))

	swi.Add(prom.StatsPrometheusEndpoint(s.ctxInfo, &prom.StatsPrometheusConfig{
		Config:      &s.cfg.Prometheus,
		SelectorCfg: selectorCfg,
		CommonCfg:   &s.cfg.Metrics,
	}, filteredStats), swarm.WithID("PrometheusExporter"))

	swi.Add(swarm.DirectInstance(export.StatPrinterProvider(s.cfg.Stats.Print, filteredStats)),
		swarm.WithID("StatPrinter"))

	return swi.Instance(ctx)
}
