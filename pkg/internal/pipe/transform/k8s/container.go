// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s // import "go.opentelemetry.io/obi/pkg/internal/pipe/transform/k8s"

import (
	"context"
	"fmt"
	"log/slog"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/transform"
)

func clog() *slog.Logger { return slog.With("component", "k8s.ContainerMetadataDecorator") }

// ContainerMetadataDecoratorProvider decorates items with the metadata of the Kubernetes pod and
// container whose ID containerID returns. It is meant for items that have no network endpoints
// to look up, like the block I/O charged to a container.
func ContainerMetadataDecoratorProvider[T any](
	ctx context.Context,
	cfg *transform.KubernetesDecorator,
	k8sInformer *kube.MetadataProvider,
	containerID func(T) string,
	attrs func(T) *pipe.CommonAttrs,
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !k8sInformer.IsKubeEnabled() {
			return swarm.Bypass(input, output)
		}
		store, err := k8sInformer.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("instantiating k8s.ContainerMetadataDecorator: %w", err)
		}
		dec := containerDecorator{
			store:       store,
			clusterName: transform.KubeClusterName(ctx, cfg, k8sInformer),
		}
		in := input.Subscribe(msg.SubscriberName("k8s.ContainerMetadataDecorator"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, clog().Debug, func(items []T) {
				for _, item := range items {
					dec.decorate(attrs(item), containerID(item))
				}
				output.Send(items)
			})
		}, nil
	}
}

type containerDecorator struct {
	store       *kube.Store
	clusterName string
}

// decorate adds the pod and container metadata of the container, if it belongs to a pod
func (d *containerDecorator) decorate(a *pipe.CommonAttrs, containerID string) {
	if a.Metadata == nil {
		a.Metadata = map[attr.Name]string{}
	}
	if d.clusterName != "" {
		a.Metadata[attr.K8sClusterName] = d.clusterName
	}
	if containerID == "" {
		return
	}
	cached := d.store.PodByContainerID(containerID)
	if cached == nil || cached.Meta.Pod == nil {
		return
	}

	meta := cached.Meta
	ownerName, ownerKind := meta.Name, meta.Kind
	if owner := ikube.TopOwner(meta.Pod); owner != nil {
		ownerName, ownerKind = owner.Name, owner.Kind
	}
	a.Metadata[attr.K8sNamespaceName] = meta.Namespace
	a.Metadata[attr.K8sPodName] = meta.Name
	a.Metadata[attr.K8sContainerName] = containerName(meta.Pod, containerID)
	a.Metadata[attr.K8sOwnerName] = ownerName
	a.Metadata[attr.K8sKind] = ownerKind
}

func containerName(pod *informer.PodInfo, containerID string) string {
	for _, c := range pod.Containers {
		if c.Id == containerID {
			return c.Name
		}
	}
	return ""
}
