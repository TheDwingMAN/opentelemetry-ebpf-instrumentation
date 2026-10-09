// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package filter // import "go.opentelemetry.io/obi/pkg/filter"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/selection"
)

// ByDynamicContainer provides a pipeline node that keeps only the records of the containers and
// pods of the dynamically selected applications (via DynamicSelector), for records that are charged
// to containers instead of network endpoints. allows tells whether the tracker of the selected
// containers lets a record through. When the selector is nil, the node is bypassed.
func ByDynamicContainer[T any](
	selector selection.PIDSelector,
	k8sInformer *kube.MetadataProvider,
	allows func(*selection.DynamicAppContainers, T) bool,
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
				out := filterByDynamicContainer(items, allows, tracker)
				if len(out) > 0 {
					output.SendCtx(loopCtx, out)
				}
			})
		}, nil
	}
}

func filterByDynamicContainer[T any](items []T, allows func(*selection.DynamicAppContainers, T) bool,
	tracker *selection.DynamicAppContainers,
) []T {
	writeIdx := 0
	for readIdx := range items {
		if allows(tracker, items[readIdx]) {
			items[writeIdx] = items[readIdx]
			writeIdx++
		}
	}
	return items[:writeIdx]
}
