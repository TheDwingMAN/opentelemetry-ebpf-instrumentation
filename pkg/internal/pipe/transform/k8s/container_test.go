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

func TestContainerDecorator(t *testing.T) {
	store := kube.NewStore(&fakeNotifier{}, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})
	for _, pod := range []*informer.ObjectMeta{{
		Name: "db-0", Namespace: "storage", Kind: "Pod",
		Pod: &informer.PodInfo{
			Owners:     []*informer.Owner{{Kind: "StatefulSet", Name: "db"}},
			Containers: []*informer.ContainerInfo{{Id: "aaaa", Name: "postgres"}, {Id: "bbbb", Name: "exporter"}},
		},
	}, {
		Name: "debug", Namespace: "default", Kind: "Pod",
		Pod: &informer.PodInfo{Containers: []*informer.ContainerInfo{{Id: "cccc", Name: "shell"}}},
	}} {
		require.NoError(t, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: pod}))
	}
	dec := &containerDecorator{store: store, clusterName: "prod"}

	for _, tc := range []struct {
		containerID string
		want        map[attr.Name]string
	}{{
		containerID: "bbbb",
		want: map[attr.Name]string{
			attr.K8sClusterName: "prod", attr.K8sNamespaceName: "storage", attr.K8sPodName: "db-0",
			attr.K8sContainerName: "exporter", attr.K8sOwnerName: "db", attr.K8sKind: "StatefulSet",
		},
	}, {
		// a pod without owner is its own owner
		containerID: "cccc",
		want: map[attr.Name]string{
			attr.K8sClusterName: "prod", attr.K8sNamespaceName: "default", attr.K8sPodName: "debug",
			attr.K8sContainerName: "shell", attr.K8sOwnerName: "debug", attr.K8sKind: "Pod",
		},
	}, {
		// the I/O charged to no pod is still the cluster's
		containerID: "", want: map[attr.Name]string{attr.K8sClusterName: "prod"},
	}, {
		containerID: "dddd", want: map[attr.Name]string{attr.K8sClusterName: "prod"},
	}} {
		a := &pipe.CommonAttrs{}
		dec.decorate(a, tc.containerID)
		assert.Equal(t, tc.want, a.Metadata, tc.containerID)
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
