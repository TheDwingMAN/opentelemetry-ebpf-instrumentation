// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package filter // import "go.opentelemetry.io/obi/pkg/filter"

import (
	"context"
	"slices"

	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/selection"
)

// ByDynamicContainer provides a pipeline node that keeps only the records charged to the containers
// of the dynamically selected applications (via DynamicSelector), for the records without network
// endpoints to match them by, like the block I/O. When the selector is nil, the node is bypassed.
func ByDynamicContainer[T any](
	selector selection.PIDSelector,
	k8sInformer *kube.MetadataProvider,
	containerID func(T) string,
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(instantiateCtx context.Context) (swarm.RunFunc, error) {
		if selector == nil {
			return swarm.Bypass(input, output)
		}
		var store *kube.Store
		if k8sInformer != nil && k8sInformer.IsKubeEnabled() {
			var err error
			store, err = k8sInformer.Get(instantiateCtx)
			if err != nil {
				return nil, err
			}
		}
		tracker := selection.NewDynamicAppContainers(selector, store)
		in := input.Subscribe(msg.SubscriberName("filter.ByDynamicContainer"))
		return func(loopCtx context.Context) {
			tracker.Run(loopCtx)
			defer output.Close()
			swarms.ForEachInput(loopCtx, in, nil, func(items []T) {
				out := slices.DeleteFunc(items, func(item T) bool { return !tracker.AllowsContainer(containerID(item)) })
				if len(out) > 0 {
					output.SendCtx(loopCtx, out)
				}
			})
		}, nil
	}
}
