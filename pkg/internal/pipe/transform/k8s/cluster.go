// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s // import "go.opentelemetry.io/obi/pkg/internal/pipe/transform/k8s"

import (
	"context"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/transform"
)

// ClusterNameDecoratorProvider decorates items with the name of the Kubernetes cluster. It is meant
// for items that have no network endpoints to look the rest of the metadata up with, like the block
// I/O of a device.
func ClusterNameDecoratorProvider[T any](
	ctx context.Context,
	cfg *transform.KubernetesDecorator,
	k8sInformer *kube.MetadataProvider,
	attrs func(T) *pipe.CommonAttrs,
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !k8sInformer.IsKubeEnabled() {
			return swarm.Bypass(input, output)
		}
		clusterName := transform.KubeClusterName(ctx, cfg, k8sInformer)
		if clusterName == "" {
			return swarm.Bypass(input, output)
		}
		in := input.Subscribe(msg.SubscriberName("k8s.ClusterNameDecorator"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, nil, func(items []T) {
				for _, item := range items {
					a := attrs(item)
					if a.Metadata == nil {
						a.Metadata = map[attr.Name]string{}
					}
					a.Metadata[attr.K8sClusterName] = clusterName
				}
				output.SendCtx(ctx, items)
			})
		}, nil
	}
}
