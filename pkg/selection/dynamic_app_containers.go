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
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

func containersLog() *slog.Logger {
	return slog.With("component", "selection.DynamicAppContainers")
}

// DynamicAppContainers tracks the containers of the PIDs in a DynamicSelector. StatsO11y uses it to
// restrict the storage stats, which the kernel charges to containers instead of network endpoints,
// to the dynamically selected applications: the containers of the selected PIDs, and the pods of
// the selected Kubernetes workloads.
type DynamicAppContainers struct {
	selector PIDSelector
	store    *kube.Store

	mu            sync.RWMutex
	pidContainers map[app.PID]string
	// containers counts the selected PIDs of each container
	containers map[string]int
}

// NewDynamicAppContainers creates a tracker for the given selector and optional Kubernetes store,
// which is needed to select the pods of Kubernetes workloads.
func NewDynamicAppContainers(selector PIDSelector, store *kube.Store) *DynamicAppContainers {
	return &DynamicAppContainers{
		selector:      selector,
		store:         store,
		pidContainers: map[app.PID]string{},
		containers:    map[string]int{},
	}
}

// Run keeps the containers of the selected PIDs in sync with the PIDs that are added to and removed
// from the selector, starting with the PIDs already in it.
func (d *DynamicAppContainers) Run(ctx context.Context) {
	if d.selector == nil {
		return
	}
	// subscribe before reading the current PIDs, so that no PID added in between is missed
	added := AddedPIDsNotifyContext(ctx, d.selector)
	removed := RemovedNotifyContext(ctx, d.selector)
	if pids, ok := d.selector.GetPIDs(); ok {
		d.add(pids)
	}
	go d.loop(ctx, added, removed)
}

// loop handles additions and removals in a single goroutine. The selector notifies them through
// separate channels, so a PID removed right after being added can be removed before its addition
// is handled: add and remove check the PID against the current selection.
func (d *DynamicAppContainers) loop(ctx context.Context, added, removed <-chan []app.PID) {
	for {
		select {
		case <-ctx.Done():
			return
		case pids, ok := <-added:
			if !ok {
				return
			}
			d.add(pids)
		case pids, ok := <-removed:
			if !ok {
				return
			}
			d.remove(pids)
		}
	}
}

func (d *DynamicAppContainers) add(pids []app.PID) {
	for _, pid := range pids {
		containerID, err := containerOfPID(pid)
		if err != nil {
			containersLog().Debug("no container for dynamically selected PID: its storage stats are not reported",
				"pid", pid, "error", err)
			continue
		}
		d.mu.Lock()
		d.removeLocked(pid)
		// removed since it was added
		if d.selector.IncludesPID(pid) {
			d.pidContainers[pid] = containerID
			d.containers[containerID]++
		}
		d.mu.Unlock()
	}
}

func (d *DynamicAppContainers) remove(pids []app.PID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, pid := range pids {
		// added again since it was removed
		if d.selector.IncludesPID(pid) {
			continue
		}
		d.removeLocked(pid)
	}
}

func (d *DynamicAppContainers) removeLocked(pid app.PID) {
	containerID, ok := d.pidContainers[pid]
	if !ok {
		return
	}
	delete(d.pidContainers, pid)
	d.containers[containerID]--
	if d.containers[containerID] <= 0 {
		delete(d.containers, containerID)
	}
}

// containerOfPID returns the ID of the container that the kernel charges the storage operations of
// a process to, as the storage stats name it. Injectable for tests.
var containerOfPID = container.IDFromIOCgroupOfPID

// AllowsContainer tells whether the stats charged to a container are exported for the current
// dynamic selection: those of the container of a selected PID, or of a container of a pod of a
// selected workload. Stats charged to no container are never exported, and neither is anything
// while the selection is empty (exclusive mode, as in DynamicAppIPs).
func (d *DynamicAppContainers) AllowsContainer(containerID string) bool {
	if d.selector == nil {
		return true
	}
	if containerID == "" {
		return false
	}
	d.mu.RLock()
	_, selected := d.containers[containerID]
	d.mu.RUnlock()
	if selected {
		return true
	}
	if d.store == nil {
		return false
	}
	pod := d.store.PodByContainerID(containerID)
	return pod != nil && d.selectsWorkloadOf(pod.Meta)
}

// selectsWorkloadOf tells whether a pod belongs to a selected workload: any of its owners, or the
// pod itself
func (d *DynamicAppContainers) selectsWorkloadOf(pod *informer.ObjectMeta) bool {
	if pod == nil || pod.Pod == nil {
		return false
	}
	if d.selectsWorkload(kube.WorkloadOwner{Namespace: pod.Namespace, Kind: "Pod", Name: pod.Name}) {
		return true
	}
	for _, owner := range pod.Pod.Owners {
		if d.selectsWorkload(kube.WorkloadOwner{Namespace: pod.Namespace, Kind: owner.Kind, Name: owner.Name}) {
			return true
		}
	}
	return false
}

func (d *DynamicAppContainers) selectsWorkload(owner kube.WorkloadOwner) bool {
	ws, ok := d.selector.(K8sWorkloadSelector)
	if !ok {
		return false
	}
	for _, ref := range ws.GetK8sWorkloads() {
		if ref.Namespace == owner.Namespace && ref.Kind == owner.Kind && ref.Name == owner.Name {
			return true
		}
	}
	return false
}
