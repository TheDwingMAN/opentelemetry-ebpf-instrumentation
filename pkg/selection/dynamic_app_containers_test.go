// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection

import (
	"context"
	"errors"
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

func TestDynamicAppContainers_AllowsTheContainersOfTheSelectedPIDs(t *testing.T) {
	stubContainersOfPIDs(t, map[app.PID]string{1: "aaaa", 2: "aaaa", 3: "bbbb"})
	selector := &stubPIDSelector{
		pids:    []app.PID{1, 2},
		addedCh: make(chan []app.PID),
		removed: make(chan []app.PID),
	}
	tracker := NewDynamicAppContainers(selector, nil)
	tracker.Run(t.Context())

	assert.True(t, tracker.AllowsContainer("aaaa"))
	assert.False(t, tracker.AllowsContainer("bbbb"))
	assert.False(t, tracker.AllowsContainer(""), "stats charged to no container belong to no selected application")

	selector.removed <- []app.PID{1}
	selector.addedCh <- []app.PID{3}
	assert.Eventually(t, func() bool { return tracker.AllowsContainer("bbbb") }, time.Second, time.Millisecond)
	assert.True(t, tracker.AllowsContainer("aaaa"), "PID 2 is still selected in the container")

	selector.removed <- []app.PID{2}
	assert.Eventually(t, func() bool { return !tracker.AllowsContainer("aaaa") }, time.Second, time.Millisecond)
	assert.True(t, tracker.AllowsContainer("bbbb"))
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
	assert.False(t, tracker.AllowsPod("default", "web-1", kube.WorkloadOwner{Namespace: "default", Kind: "Deployment", Name: "web"}))
}

func TestDynamicAppContainers_NoSelectorAllowsEverything(t *testing.T) {
	tracker := NewDynamicAppContainers(nil, nil)
	tracker.Run(t.Context())

	assert.True(t, tracker.AllowsContainer("aaaa"))
	assert.True(t, tracker.AllowsContainer(""))
	assert.True(t, tracker.AllowsPod("default", "web-1", kube.WorkloadOwner{}))
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

	assert.True(t, tracker.AllowsPod("shop", "web-1", kube.WorkloadOwner{Namespace: "shop", Kind: "Deployment", Name: "web"}))
	assert.False(t, tracker.AllowsPod("shop", "db-0", kube.WorkloadOwner{Namespace: "shop", Kind: "StatefulSet", Name: "db"}))
	assert.False(t, tracker.AllowsPod("other", "web-1", kube.WorkloadOwner{Namespace: "other", Kind: "Deployment", Name: "web"}),
		"a workload of the same name in another namespace")
}

func TestDynamicAppContainers_AllowsThePodsOfTheSelectedPIDs(t *testing.T) {
	stubContainersOfPIDs(t, map[app.PID]string{7: "dddd"})
	store := newTestKubeStore(t)
	addTestPod(store, "shop", "db-0", "dddd", &informer.Owner{Kind: "StatefulSet", Name: "db"})
	addTestPod(store, "shop", "db-1", "ffff", &informer.Owner{Kind: "StatefulSet", Name: "db"})
	tracker := NewDynamicAppContainers(&stubPIDSelector{pids: []app.PID{7}}, store)
	tracker.Run(t.Context())

	owner := kube.WorkloadOwner{Namespace: "shop", Kind: "StatefulSet", Name: "db"}
	assert.True(t, tracker.AllowsPod("shop", "db-0", owner))
	assert.False(t, tracker.AllowsPod("shop", "db-1", owner), "another pod of the same workload")
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
