// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
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

// isStorageStat reports block, filesystem and NFS client RPC stats. They
// carry no network endpoints, so drop_external, which keeps only items whose
// endpoints are Kubernetes objects, must not judge them: it would drop every
// one.
func isStorageStat(s *ebpf.Stat) bool {
	return s.Type == ebpf.StatTypeBlockIo || s.Type == ebpf.StatTypeFsIo || s.Type == ebpf.StatTypeNFSRPC
}

// fsIoPID extracts the PID namespace, host PID, and the mount (superblock
// device and mount root inode) from a filesystem I/O stat, for Kubernetes pod
// and persistent volume attribution. Stats that don't carry FsIo are left
// alone.
func fsIoPID(s *ebpf.Stat) (pidNs, hostPID uint32, mount ebpf.MountKey, ok bool) {
	if s.FsIo == nil {
		return 0, 0, ebpf.MountKey{}, false
	}
	return s.FsIo.PidNs, s.FsIo.HostPID, ebpf.MountKey{Dev: s.FsIo.SDev, RootIno: s.FsIo.RootIno}, true
}

// fsIoSetMount stores, on a filesystem I/O stat, the attributes of the volume
// its mount belongs to.
func fsIoSetMount(s *ebpf.Stat, mount *ebpf.MountAttrs) {
	if s.FsIo != nil {
		s.FsIo.Mount = mount
	}
}

// fsIoPodUID returns the UID of the pod a filesystem I/O stat already comes
// with, "" when it has none.
func fsIoPodUID(s *ebpf.Stat) string {
	if s.FsIo == nil {
		return ""
	}
	return s.FsIo.PodUID
}

// fsMountpoints returns which mount path attributes the user selected on a
// filesystem metric. Both are opt-in, and resolving them costs reads of
// mount tables, so nothing is resolved for one that is not selected.
func (s *Stats) fsMountpoints(selectorCfg *attributes.SelectorConfig) k8s.PIDMountpoints[*ebpf.Stat] {
	var mp k8s.PIDMountpoints[*ebpf.Stat]
	if !s.cfg.Metrics.Features.StorageFS() {
		return mp
	}
	sel, err := attributes.NewAttrSelector(s.ctxInfo.MetricAttributeGroups, selectorCfg)
	if err != nil {
		return mp
	}
	selected := func(name attr.Name) bool {
		for _, metric := range [...]attributes.Name{
			attributes.StatFsOperationDuration, attributes.StatFsIO, attributes.StatFsOperationErrors,
		} {
			if slices.Contains(sel.For(metric), name) {
				return true
			}
		}
		return false
	}
	mp.PodUID = fsIoPodUID
	mp.Host = selected(attr.FsMountpoint)
	if selected(attr.FsContainerMountpoint) {
		mp.ContainerPath = ebpf.NewMountpointResolver().ContainerPath
	}
	return mp
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
	ebpfStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "ebpfStats")
	swi.Add(swarm.DirectInstance(newRingBufTracer(s, ebpfStats)), swarm.WithID("RingBufTracer"))

	// Middle nodes: transforming stats and passing them to the next stage in the pipeline.
	// Many of the nodes here are not mandatory. It's decision of each InstanceFunc to decide
	// whether the node needs to be instantiated or just bypass their input/output channels.
	kubeDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "kubeDecoratedStats")
	swi.Add(k8s.MetadataDecoratorProviderKeeping(ctx, &s.cfg.Attributes.Kubernetes, s.ctxInfo.K8sInformer,
		statAttrs, isStorageStat, ebpfStats, kubeDecoratedStats), swarm.WithID("K8sMetadataDecorator"))

	var pidK8sStore *kube.Store
	if s.ctxInfo.K8sInformer.IsKubeEnabled() {
		var err error
		pidK8sStore, err = s.ctxInfo.K8sInformer.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("initializing PIDMetadataDecorator: %w", err)
		}
		setNodeName(ctx, s.ctxInfo.K8sInformer, alog)
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

	pidDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "pidDecoratedStats")
	mountpoints := s.fsMountpoints(selectorCfg)
	swi.Add(k8s.PIDMetadataDecoratorProviderWith(pidK8sStore, statAttrs, fsIoPID, fsIoSetMount,
		ebpf.CachedPVCLookup(pvcLookup), mountpoints, kubeDecoratedStats, pidDecoratedStats),
		swarm.WithID("PIDMetadataDecorator"))

	dnsDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "dnsDecoratedStats")
	swi.Add(rdns.ReverseDNSProvider(&s.cfg.Stats.ReverseDNS, statAttrs, &s.cfg.EBPF, pidDecoratedStats, dnsDecoratedStats),
		swarm.WithID("ReverseDNS"))

	geoIPDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "geoIPDecoratedStats")
	swi.Add(geoip.GeoIPProvider(&s.cfg.Stats.GeoIP, statAttrs,
		dnsDecoratedStats, geoIPDecoratedStats), swarm.WithID("GeoIPDecorator"))

	cidrDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "cidrDecoratedStats")
	swi.Add(cidr.DecoratorProvider(s.cfg.Stats.CIDRs, statAttrs, geoIPDecoratedStats, cidrDecoratedStats),
		swarm.WithID("CIDRDecorator"))

	decoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "decoratedStats")
	swi.Add(decorate.Decorate(s.agentIP, statAttrs, cidrDecoratedStats, decoratedStats),
		swarm.WithID("StatsDecorator"))

	dynamicFilteredStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "dynamicFilteredStats")
	// The dynamic PID trackers are built here rather than by their nodes so
	// that aggregated stats go through the same ones; the nodes run them.
	s.aggDeps = aggregationDeps{store: pidK8sStore, pvc: pvcLookup, mountpoints: mountpoints}
	if s.ctxInfo.DynamicSelector != nil {
		dynamicSelector := s.ctxInfo.DynamicSelector.StatsMetrics()
		s.aggDeps.dynamicAttrs = selection.NewDynamicFlowAttrs(s.ctxInfo.DynamicSelector, dynamicSelector, pidK8sStore)
		if dynamicSelector != nil {
			s.aggDeps.dynamicIPs = selection.NewDynamicAppIPs("stats", dynamicSelector, pidK8sStore)
		}
	}
	aggregated, err := s.buildAggregation(ctx)
	if err != nil {
		return nil, err
	}

	dynamicDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "dynamicDecoratedStats")
	swi.Add(dynamicpid.MetadataDecoratorProviderFor(s.aggDeps.dynamicAttrs, statAttrs, decoratedStats, dynamicDecoratedStats),
		swarm.WithID("DynamicPIDMetadataDecorator"))
	swi.Add(filter.ByDynamicPIDTracker(s.aggDeps.dynamicIPs, statAttrs, dynamicDecoratedStats, dynamicFilteredStats),
		swarm.WithID("DynamicPIDFilter"))

	filteredStats := s.ctxInfo.OverrideStatsExportQueue
	if filteredStats == nil {
		filteredStats = msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "filteredStats")
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
		Aggregated:  aggregated,
	}, filteredStats), swarm.WithID("OTelExporter"))

	swi.Add(prom.StatsPrometheusEndpoint(s.ctxInfo, &prom.StatsPrometheusConfig{
		Config:      &s.cfg.Prometheus,
		SelectorCfg: selectorCfg,
		CommonCfg:   &s.cfg.Metrics,
		Aggregated:  aggregated,
	}, filteredStats), swarm.WithID("PrometheusExporter"))

	swi.Add(swarm.DirectInstance(export.StatPrinterProvider(s.cfg.Stats.Print, filteredStats)),
		swarm.WithID("StatPrinter"))

	return swi.Instance(ctx)
}

// nodeNameTimeout bounds the node name lookup, as for the node's host.id.
var nodeNameTimeout = 30 * time.Second

// setNodeName records the node the agent runs on. k8s.node.name is the same
// for every stat: the exporters' getters read it once, when they are built.
// A node name that cannot be read in time leaves it unset rather than hold
// up the pipeline.
func setNodeName(ctx context.Context, informer *kube.MetadataProvider, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(ctx, nodeNameTimeout)
	defer cancel()
	nodeName, err := informer.CurrentNodeName(ctx)
	if err != nil {
		log.Debug("can't get the Kubernetes node name", "error", err)
		return
	}
	ebpf.SetNodeName(nodeName)
}
