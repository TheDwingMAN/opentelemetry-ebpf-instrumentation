// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

// stubWorkloadSelector selects PIDs and Kubernetes workloads
type stubWorkloadSelector struct {
	stubPIDSelector
	workloads []K8sWorkloadRef
}

func (s *stubWorkloadSelector) GetK8sWorkloads() []K8sWorkloadRef { return s.workloads }

func (s *stubWorkloadSelector) WorkloadsChangedNotifyContext(context.Context) <-chan struct{} {
	return make(chan struct{})
}

func stubContainersOfPIDs(t *testing.T, containers map[app.PID]string) {
	t.Helper()
	orig := containerOfPID
	t.Cleanup(func() { containerOfPID = orig })
	containerOfPID = func(pid app.PID) (string, error) {
		if containerID, ok := containers[pid]; ok {
			return containerID, nil
		}
		return "", errors.New("not in a container")
	}
}

// syncedPIDSelector is a PIDSelector that, as the DynamicSelector, changes its PIDs before it
// notifies the change, through a channel for the added PIDs and another for the removed ones
type syncedPIDSelector struct {
	mu      sync.Mutex
	pids    map[app.PID]struct{}
	added   chan []app.PID
	removed chan []app.PID
}

func newSyncedPIDSelector(pids ...app.PID) *syncedPIDSelector {
	s := &syncedPIDSelector{pids: map[app.PID]struct{}{}, added: make(chan []app.PID), removed: make(chan []app.PID)}
	s.include(pids...)
	return s
}

func (s *syncedPIDSelector) GetPIDs() ([]app.PID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Collect(maps.Keys(s.pids)), len(s.pids) > 0
}

func (s *syncedPIDSelector) IncludesPID(pid app.PID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.pids[pid]
	return ok
}

func (s *syncedPIDSelector) AddedPIDsNotify() <-chan []app.PID { return s.added }
func (s *syncedPIDSelector) RemovedNotify() <-chan []app.PID   { return s.removed }

func (s *syncedPIDSelector) include(pids ...app.PID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pid := range pids {
		s.pids[pid] = struct{}{}
	}
}

func (s *syncedPIDSelector) exclude(pids ...app.PID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pid := range pids {
		delete(s.pids, pid)
	}
}

// add selects PIDs and notifies it, and returns once the tracker received the notification
func (s *syncedPIDSelector) add(pids ...app.PID) {
	s.include(pids...)
	s.added <- pids
}

// remove unselects PIDs and notifies it, and returns once the tracker received the notification
func (s *syncedPIDSelector) remove(pids ...app.PID) {
	s.exclude(pids...)
	s.removed <- pids
}

func TestDynamicAppContainers_AllowsTheContainersOfTheSelectedPIDs(t *testing.T) {
	stubContainersOfPIDs(t, map[app.PID]string{1: "aaaa", 2: "aaaa", 3: "bbbb"})
	selector := newSyncedPIDSelector(1, 2)
	tracker := NewDynamicAppContainers(selector, nil)
	tracker.Run(t.Context())

	assert.True(t, tracker.AllowsContainer("aaaa"))
	assert.False(t, tracker.AllowsContainer("bbbb"))
	assert.False(t, tracker.AllowsContainer(""), "stats charged to no container belong to no selected application")

	selector.remove(1)
	selector.add(3)
	assert.Eventually(t, func() bool { return tracker.AllowsContainer("bbbb") }, time.Second, time.Millisecond)
	assert.True(t, tracker.AllowsContainer("aaaa"), "PID 2 is still selected in the container")

	selector.remove(2)
	assert.Eventually(t, func() bool { return !tracker.AllowsContainer("aaaa") }, time.Second, time.Millisecond)
	assert.True(t, tracker.AllowsContainer("bbbb"))
}

// The selector notifies the additions and the removals through separate channels, so the tracker
// can receive them in another order than they happened: what it keeps follows the selection
func TestDynamicAppContainers_FollowsTheSelectionWhateverTheOrderOfTheNotifications(t *testing.T) {
	stubContainersOfPIDs(t, map[app.PID]string{4: "cccc", 5: "dddd", 6: "eeee"})
	selector := newSyncedPIDSelector(6)
	tracker := NewDynamicAppContainers(selector, nil)
	tracker.Run(t.Context())

	// PID 4 added and removed, but its removal received first
	selector.removed <- []app.PID{4}
	selector.added <- []app.PID{4}
	// PID 6 removed and added again, but its removal received last
	selector.added <- []app.PID{6}
	selector.removed <- []app.PID{6}

	// the tracker handles the notifications one at a time, in the order it received them
	selector.add(5)
	assert.Eventually(t, func() bool { return tracker.AllowsContainer("dddd") }, time.Second, time.Millisecond)
	assert.False(t, tracker.AllowsContainer("cccc"), "PID 4 is no longer selected")
	assert.True(t, tracker.AllowsContainer("eeee"), "PID 6 is selected again")
}

func TestDynamicAppContainers_PIDOutsideContainersSelectsNothing(t *testing.T) {
	stubContainersOfPIDs(t, map[app.PID]string{})
	tracker := NewDynamicAppContainers(&stubPIDSelector{pids: []app.PID{1}}, nil)
	tracker.Run(t.Context())

	assert.False(t, tracker.AllowsContainer("aaaa"))
	assert.False(t, tracker.AllowsContainer(""))
}

func TestDynamicAppContainers_EmptySelectionAllowsNothing(t *testing.T) {
	tracker := NewDynamicAppContainers(&stubPIDSelector{}, newTestKubeStore(t))
	tracker.Run(t.Context())

	assert.False(t, tracker.AllowsContainer("aaaa"))
}

func TestDynamicAppContainers_NoSelectorAllowsEverything(t *testing.T) {
	tracker := NewDynamicAppContainers(nil, nil)
	tracker.Run(t.Context())

	assert.True(t, tracker.AllowsContainer("aaaa"))
	assert.True(t, tracker.AllowsContainer(""))
}

func TestDynamicAppContainers_AllowsThePodsOfTheSelectedWorkloads(t *testing.T) {
	stubContainersOfPIDs(t, map[app.PID]string{})
	store := newTestKubeStore(t)
	addTestPod(store, "shop", "web-1", "cccc", &informer.Owner{Kind: "ReplicaSet", Name: "web-5d8f"},
		&informer.Owner{Kind: "Deployment", Name: "web"})
	addTestPod(store, "shop", "db-0", "dddd", &informer.Owner{Kind: "StatefulSet", Name: "db"})
	addTestPod(store, "other", "web-1", "eeee", &informer.Owner{Kind: "Deployment", Name: "web"})
	selector := &stubWorkloadSelector{workloads: []K8sWorkloadRef{{Kind: "Deployment", Namespace: "shop", Name: "web"}}}
	tracker := NewDynamicAppContainers(selector, store)
	tracker.Run(t.Context())

	assert.True(t, tracker.AllowsContainer("cccc"))
	assert.False(t, tracker.AllowsContainer("dddd"))
	assert.False(t, tracker.AllowsContainer("eeee"), "a workload of the same name in another namespace")
	assert.False(t, tracker.AllowsContainer("ffff"), "a container the store doesn't know")
}

// A selected PID selects its own container, not the other pods of its workload
func TestDynamicAppContainers_AllowsTheContainerOfTheSelectedPIDOnly(t *testing.T) {
	stubContainersOfPIDs(t, map[app.PID]string{7: "dddd"})
	store := newTestKubeStore(t)
	addTestPod(store, "shop", "db-0", "dddd", &informer.Owner{Kind: "StatefulSet", Name: "db"})
	addTestPod(store, "shop", "db-1", "ffff", &informer.Owner{Kind: "StatefulSet", Name: "db"})
	tracker := NewDynamicAppContainers(&stubPIDSelector{pids: []app.PID{7}}, store)
	tracker.Run(t.Context())

	assert.True(t, tracker.AllowsContainer("dddd"))
	assert.False(t, tracker.AllowsContainer("ffff"), "another pod of the same workload")
}

func addTestPod(store *kube.Store, namespace, name, containerID string, owners ...*informer.Owner) {
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners:     owners,
			Containers: []*informer.ContainerInfo{{Id: containerID}},
		},
	}})
}
