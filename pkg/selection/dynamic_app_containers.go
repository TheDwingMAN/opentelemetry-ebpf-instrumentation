// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection // import "go.opentelemetry.io/obi/pkg/selection"

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/kube"
)

func containersLog() *slog.Logger {
	return slog.With("component", "selection.DynamicAppContainers")
}

// DynamicAppContainers tracks the containers of the applications that a DynamicSelector selects:
// those of the selected PIDs, and those of the pods of the selected Kubernetes workloads. StatsO11y
// uses it for the stats that the kernel charges to containers instead of network endpoints, like
// the block I/O.
type DynamicAppContainers struct {
	selector PIDSelector
	store    *kube.Store

	mu            sync.RWMutex
	pidContainers map[app.PID]string
	// containers counts the selected PIDs of each container
	containers map[string]int
}

// NewDynamicAppContainers creates a tracker for the given selector and optional Kubernetes store,
// which selecting Kubernetes workloads needs
func NewDynamicAppContainers(selector PIDSelector, store *kube.Store) *DynamicAppContainers {
	return &DynamicAppContainers{
		selector:      selector,
		store:         store,
		pidContainers: map[app.PID]string{},
		containers:    map[string]int{},
	}
}

// containerOfPID returns the ID of the container that the block I/O of a process is charged to, as
// the disk reader names it. Injectable for tests.
var containerOfPID = container.IDFromIOCgroupOfPID

// Run follows the PIDs that the selector adds and removes, from those that it already selects
func (d *DynamicAppContainers) Run(ctx context.Context) {
	// subscribe before reading the selected PIDs, so that none added in between is missed
	added := AddedPIDsNotifyContext(ctx, d.selector)
	removed := RemovedNotifyContext(ctx, d.selector)
	if pids, ok := d.selector.GetPIDs(); ok {
		d.update(pids)
	}
	go func() {
		for {
			var pids []app.PID
			var ok bool
			select {
			case <-ctx.Done():
				return
			case pids, ok = <-added:
			case pids, ok = <-removed:
			}
			if !ok {
				return
			}
			d.update(pids)
		}
	}()
}

// update counts the containers of the PIDs that the selector selects, and forgets the others. The
// selector notifies the added and the removed PIDs through two channels, so a notification can be
// older than another one about the same PID: the selector tells what it selects now.
func (d *DynamicAppContainers) update(pids []app.PID) {
	for _, pid := range pids {
		var containerID string
		if d.selector.IncludesPID(pid) {
			var ok bool
			if containerID, ok = containerOfPID(pid); !ok {
				containersLog().Debug("the stats charged to containers are not reported for a dynamically "+
					"selected PID outside containers", "pid", pid)
			}
		}
		d.mu.Lock()
		if previous, ok := d.pidContainers[pid]; ok {
			delete(d.pidContainers, pid)
			if d.containers[previous]--; d.containers[previous] == 0 {
				delete(d.containers, previous)
			}
		}
		if containerID != "" {
			d.pidContainers[pid] = containerID
			d.containers[containerID]++
		}
		d.mu.Unlock()
	}
}

// AllowsContainer tells whether the stats charged to a container belong to a selected application:
// to the container of a selected PID, or to a container of a pod of a selected workload. The stats
// charged to no container never do.
func (d *DynamicAppContainers) AllowsContainer(containerID string) bool {
	if containerID == "" {
		return false
	}
	d.mu.RLock()
	_, selected := d.containers[containerID]
	d.mu.RUnlock()
	if selected {
		return true
	}
	workloads, ok := d.selector.(K8sWorkloadSelector)
	if !ok || d.store == nil {
		return false
	}
	cached := d.store.PodByContainerID(containerID)
	if cached == nil || cached.Meta.Pod == nil {
		return false
	}
	pod := cached.Meta
	for _, ref := range workloads.GetK8sWorkloads() {
		if ref.Namespace != pod.Namespace {
			continue
		}
		if ref.Kind == "Pod" && ref.Name == pod.Name {
			return true
		}
		for _, owner := range pod.Pod.Owners {
			if ref.Kind == owner.Kind && ref.Name == owner.Name {
				return true
			}
		}
	}
	return false
}
