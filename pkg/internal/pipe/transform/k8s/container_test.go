// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

func testContainerStore() *kube.Store {
	store := kube.NewStore(&fakeNotifier{}, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name:      "db-0",
		Namespace: "storage",
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners: []*informer.Owner{{Kind: "StatefulSet", Name: "db"}},
			Containers: []*informer.ContainerInfo{
				{Id: "aaaa", Name: "postgres"},
				{Id: "bbbb", Name: "exporter"},
			},
		},
	}})
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name:      "debug",
		Namespace: "default",
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Containers: []*informer.ContainerInfo{{Id: "cccc", Name: "shell"}},
		},
	}})
	return store
}

func TestContainerDecorator(t *testing.T) {
	dec := &containerDecorator{store: testContainerStore(), clusterName: "prod"}

	a := &pipe.CommonAttrs{}
	dec.decorate(a, "bbbb")
	assert.Equal(t, map[attr.Name]string{
		attr.K8sNamespaceName: "storage",
		attr.K8sPodName:       "db-0",
		attr.K8sContainerName: "exporter",
		attr.K8sOwnerName:     "db",
		attr.K8sKind:          "StatefulSet",
		attr.K8sClusterName:   "prod",
	}, a.Metadata)

	a = &pipe.CommonAttrs{}
	dec.decorate(a, "cccc")
	assert.Equal(t, "debug", a.Metadata[attr.K8sOwnerName], "a pod without owner is its own owner")
	assert.Equal(t, "Pod", a.Metadata[attr.K8sKind])
}

func TestContainerDecorator_Unattributed(t *testing.T) {
	dec := &containerDecorator{store: testContainerStore(), clusterName: "prod"}
	for _, containerID := range []string{"", "not-a-pod-container"} {
		a := &pipe.CommonAttrs{}
		dec.decorate(a, containerID)
		assert.Equal(t, map[attr.Name]string{attr.K8sClusterName: "prod"}, a.Metadata,
			"the node is still in the cluster, even if the I/O is not charged to a pod")
	}
}
