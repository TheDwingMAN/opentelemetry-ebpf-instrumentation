// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

func stubContainersOfPIDs(t *testing.T, containers map[app.PID]string) {
	t.Helper()
	orig := containerOfPID
	t.Cleanup(func() { containerOfPID = orig })
	containerOfPID = func(pid app.PID) (string, bool) {
		containerID, ok := containers[pid]
		return containerID, ok
	}
}

func TestDynamicAppContainersOfPIDs(t *testing.T) {
	stubContainersOfPIDs(t, map[app.PID]string{1: "aaaa", 2: "aaaa", 3: "bbbb"})
	selector := &stubPIDSelector{addedCh: make(chan []app.PID), removed: make(chan []app.PID)}
	tracker := NewDynamicAppContainers(selector, nil)
	allowed := func() []string {
		var containers []string
		for _, containerID := range []string{"aaaa", "bbbb", ""} {
			if tracker.AllowsContainer(containerID) {
				containers = append(containers, containerID)
			}
		}
		return containers
	}

	tracker.update([]app.PID{1})
	assert.Empty(t, allowed(), "nothing is selected")

	// PID 4 is outside containers
	selector.pids = []app.PID{1, 2, 3, 4}
	tracker.update(selector.pids)
	assert.Equal(t, []string{"aaaa", "bbbb"}, allowed(), "never the stats charged to no container")

	selector.pids = []app.PID{2}
	tracker.update([]app.PID{1, 3})
	assert.Equal(t, []string{"aaaa"}, allowed(), "PID 2 is still selected in aaaa")

	tracker.update([]app.PID{3})
	assert.Equal(t, []string{"aaaa"}, allowed(), "a notification of PID 3 added, older than its removal")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tracker.Run(ctx)
	selector.pids = []app.PID{2, 3}
	selector.addedCh <- []app.PID{3}
	assert.Eventually(t, func() bool { return tracker.AllowsContainer("bbbb") }, time.Second, time.Millisecond)
	selector.pids = []app.PID{3}
	selector.removed <- []app.PID{2}
	assert.Eventually(t, func() bool { return !tracker.AllowsContainer("aaaa") }, time.Second, time.Millisecond)
}

type stubWorkloadSelector struct {
	stubPIDSelector
	workloads []K8sWorkloadRef
}

func (s *stubWorkloadSelector) GetK8sWorkloads() []K8sWorkloadRef { return s.workloads }

func (s *stubWorkloadSelector) WorkloadsChangedNotifyContext(context.Context) <-chan struct{} {
	return make(chan struct{})
}

func TestDynamicAppContainersOfWorkloads(t *testing.T) {
	store := newTestKubeStore(t)
	for _, pod := range []*informer.ObjectMeta{{
		Name: "db-0", Namespace: "storage", Kind: "Pod",
		Pod: &informer.PodInfo{
			Owners:     []*informer.Owner{{Kind: "StatefulSet", Name: "db"}},
			Containers: []*informer.ContainerInfo{{Id: "aaaa"}},
		},
	}, {
		Name: "debug", Namespace: "storage", Kind: "Pod",
		Pod: &informer.PodInfo{Containers: []*informer.ContainerInfo{{Id: "bbbb"}}},
	}, {
		Name: "db-0", Namespace: "other", Kind: "Pod",
		Pod: &informer.PodInfo{
			Owners:     []*informer.Owner{{Kind: "StatefulSet", Name: "db"}},
			Containers: []*informer.ContainerInfo{{Id: "cccc"}},
		},
	}} {
		require.NoError(t, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: pod}))
	}
	selector := &stubWorkloadSelector{workloads: []K8sWorkloadRef{
		{Kind: "StatefulSet", Namespace: "storage", Name: "db"},
		{Kind: "Pod", Namespace: "storage", Name: "debug"},
	}}

	tracker := NewDynamicAppContainers(selector, store)
	assert.True(t, tracker.AllowsContainer("aaaa"), "a pod of a selected workload")
	assert.True(t, tracker.AllowsContainer("bbbb"), "a selected pod")
	assert.False(t, tracker.AllowsContainer("cccc"), "a workload of the same name in another namespace")
	assert.False(t, tracker.AllowsContainer("dddd"), "no pod")
	assert.False(t, NewDynamicAppContainers(selector, nil).AllowsContainer("aaaa"), "without the Kubernetes metadata")
}
