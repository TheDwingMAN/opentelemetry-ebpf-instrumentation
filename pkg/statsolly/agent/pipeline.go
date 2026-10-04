// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"context"
	"fmt"
	"sync"

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
	"go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/selection"
)

func statAttrs(s *ebpf.Stat) *pipe.CommonAttrs { return &s.CommonAttrs }

// mockable functions for testing
var newRingBufTracer = func(s *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return s.rbTracer.TraceLoop(out)
}

var newDiskTracer = func(s *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	if s.diskTracer == nil {
		return func(_ context.Context) { out.MarkCloseable() }
	}
	return s.diskTracer.TraceLoop(out)
}

// newPodVolumesTracer reports the devices of the volumes of the pods of the node. It needs the
// Kubernetes metadata.
var newPodVolumesTracer = func(ctx context.Context, s *Stats, out *msg.Queue[[]*ebpf.Stat]) (swarm.RunFunc, error) {
	closeOutput := func(_ context.Context) { out.MarkCloseable() }
	if !s.cfg.Metrics.Features.StatsDiskPodVolumes() {
		return closeOutput, nil
	}
	k8sInformer := s.ctxInfo.K8sInformer
	if k8sInformer == nil || !k8sInformer.IsKubeEnabled() {
		alog().Warn("the devices of the pod volumes are not reported: they need Kubernetes metadata")
		return closeOutput, nil
	}
	store, err := k8sInformer.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting the Kubernetes metadata of the pod volumes: %w", err)
	}
	nodeName, err := k8sInformer.CurrentNodeName(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting the node of the pod volumes: %w", err)
	}
	return stats.NewPodVolumesTracer(store, nodeName).TraceLoop(out), nil
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
	swi.Add(k8s.MetadataDecoratorProvider(ctx, &s.cfg.Attributes.Kubernetes, s.ctxInfo.K8sInformer,
		statAttrs, ebpfStats, kubeDecoratedStats), swarm.WithID("K8sMetadataDecorator"))

	dnsDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "dnsDecoratedStats")
	swi.Add(rdns.ReverseDNSProvider(&s.cfg.Stats.ReverseDNS, statAttrs, &s.cfg.EBPF, kubeDecoratedStats, dnsDecoratedStats),
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
	var dynamicSelector selection.PIDSelector
	if s.ctxInfo.DynamicSelector != nil {
		dynamicSelector = s.ctxInfo.DynamicSelector.StatsMetrics()
	}
	dynamicDecoratedStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "dynamicDecoratedStats")
	swi.Add(dynamicpid.MetadataDecoratorProvider(s.ctxInfo.DynamicSelector, dynamicSelector,
		s.ctxInfo.K8sInformer, statAttrs, decoratedStats, dynamicDecoratedStats),
		swarm.WithID("DynamicPIDMetadataDecorator"))
	swi.Add(filter.ByDynamicPID("stats", dynamicSelector, s.ctxInfo.K8sInformer,
		statAttrs, dynamicDecoratedStats, dynamicFilteredStats),
		swarm.WithID("DynamicPIDFilter"))

	allStats := dynamicFilteredStats
	if s.storageStatsEnabled() {
		// Block I/O stats have no network endpoints, so they skip the IP-based nodes above and join
		// the rest of the stats before the attribute filter.
		diskStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "diskStats")
		swi.Add(swarm.DirectInstance(newDiskTracer(s, diskStats)), swarm.WithID("DiskMapTracer"))

		podVolumeStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "podVolumeStats")
		swi.Add(func(ctx context.Context) (swarm.RunFunc, error) { return newPodVolumesTracer(ctx, s, podVolumeStats) },
			swarm.WithID("PodVolumesTracer"))

		storageStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "storageStats")
		swi.Add(mergeStats(diskStats, podVolumeStats, storageStats), swarm.WithID("StorageStatsMerger"))

		selectedStorageStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "selectedStorageStats")
		swi.Add(filter.ByDynamicContainer(dynamicSelector, s.ctxInfo.K8sInformer, selectsStorageStat,
			storageStats, selectedStorageStats), swarm.WithID("DynamicContainerFilter"))

		kubeDecoratedDiskStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "kubeDecoratedDiskStats")
		swi.Add(k8s.ContainerMetadataDecoratorProvider(ctx, &s.cfg.Attributes.Kubernetes, s.ctxInfo.K8sInformer,
			(*ebpf.Stat).ContainerID, statAttrs, selectedStorageStats, kubeDecoratedDiskStats),
			swarm.WithID("DiskKubeDecorator"))

		decoratedDiskStats := msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "decoratedDiskStats")
		swi.Add(decorate.Decorate(s.agentIP, statAttrs, kubeDecoratedDiskStats, decoratedDiskStats),
			swarm.WithID("DiskStatsDecorator"))

		allStats = msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "allStats")
		swi.Add(mergeStats(dynamicFilteredStats, decoratedDiskStats, allStats), swarm.WithID("StatsMerger"))
	}

	filteredStats := s.ctxInfo.OverrideStatsExportQueue
	if filteredStats == nil {
		filteredStats = msgh.QueueFromConfig[[]*ebpf.Stat](s.cfg, s.ctxInfo.Metrics, "filteredStats")
	}
	swi.Add(filter.ByAttribute(s.cfg.Filters.Stats, nil, selectorCfg.ExtraGroupAttributesCfg, ebpf.StatStringGetters, allStats, filteredStats),
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

// storageStatsEnabled tells whether any disk, file sync, NFS or pod volume stat is enabled. Their
// branch of the pipeline, and its Kubernetes decorator, is only added then.
func (s *Stats) storageStatsEnabled() bool {
	features := s.cfg.Metrics.Features
	return features.StatsDisk() || features.StatsFsSyncDuration() || features.StatsNFS() || features.StatsDiskPodVolumes()
}

// selectsStorageStat tells whether a storage stat belongs to a dynamically selected application: a
// pod volume, to a selected pod, and any other stat, to a selected container. The stats of devices,
// like their requests in flight, belong to no application.
func selectsStorageStat(containers *selection.DynamicAppContainers, stat *ebpf.Stat) bool {
	if volume := stat.PodVolume; volume != nil {
		owner := kube.WorkloadOwner{Namespace: volume.Namespace, Kind: volume.OwnerKind, Name: volume.OwnerName}
		return containers.AllowsPod(volume.Namespace, volume.PodName, owner)
	}
	return containers.AllowsContainer(stat.ContainerID())
}

// mergeStats forwards the stats of both inputs to the output, and closes the output once both
// inputs are closed.
func mergeStats(first, second, out *msg.Queue[[]*ebpf.Stat]) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		inputs := []<-chan []*ebpf.Stat{
			first.Subscribe(msg.SubscriberName("StatsMerger")),
			second.Subscribe(msg.SubscriberName("StatsMerger")),
		}
		return func(ctx context.Context) {
			defer out.Close()
			var wg sync.WaitGroup
			for _, in := range inputs {
				wg.Go(func() {
					swarms.ForEachInput(ctx, in, nil, func(stats []*ebpf.Stat) {
						out.SendCtx(ctx, stats)
					})
				})
			}
			wg.Wait()
		}, nil
	}
}
