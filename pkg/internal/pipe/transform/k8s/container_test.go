// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/transform"
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
	// the informers give a pod without owner references itself as its owner
	_ = store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name:      "debug",
		Namespace: "default",
		Kind:      "Pod",
		Pod: &informer.PodInfo{
			Owners:     []*informer.Owner{{Kind: "Pod", Name: "debug"}},
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
	assert.Equal(t, map[attr.Name]string{
		attr.K8sNamespaceName: "default",
		attr.K8sPodName:       "debug",
		attr.K8sContainerName: "shell",
		attr.K8sOwnerName:     "debug",
		attr.K8sKind:          "Pod",
		attr.K8sClusterName:   "prod",
	}, a.Metadata, "a pod without owner is its own owner, as with the other Kubernetes decorators")
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

func TestContainerDecoratorWithoutKubernetes(t *testing.T) {
	in := msg.NewQueue[[]*pipe.CommonAttrs](msg.ChannelBufferLen(10))
	out := msg.NewQueue[[]*pipe.CommonAttrs](msg.ChannelBufferLen(10))
	outCh := out.Subscribe()
	informer := kube.NewMetadataProvider(kube.MetadataConfig{Enable: kubeflags.EnabledFalse}, imetrics.NoopReporter{})
	decorator, err := ContainerMetadataDecoratorProvider(t.Context(), &transform.KubernetesDecorator{ClusterName: "c1"},
		informer, func(*pipe.CommonAttrs) string { return "aaaa" }, func(a *pipe.CommonAttrs) *pipe.CommonAttrs { return a },
		in, out)(t.Context())
	require.NoError(t, err)
	go decorator(t.Context())

	in.Send([]*pipe.CommonAttrs{{}})

	decorated := testutil.ReadChannel(t, outCh, 5*time.Second)
	require.Len(t, decorated, 1)
	assert.Nil(t, decorated[0].Metadata)
}
