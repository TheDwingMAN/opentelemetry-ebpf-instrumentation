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
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/transform"
)

func TestClusterNameDecorator(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enable  kubeflags.EnableFlag
		cluster string
		want    map[attr.Name]string
	}{
		{"with Kubernetes metadata", kubeflags.EnabledTrue, "c1", map[attr.Name]string{attr.K8sClusterName: "c1"}},
		{"without Kubernetes metadata", kubeflags.EnabledFalse, "c1", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := msg.NewQueue[[]*pipe.CommonAttrs](msg.ChannelBufferLen(10))
			out := msg.NewQueue[[]*pipe.CommonAttrs](msg.ChannelBufferLen(10))
			outCh := out.Subscribe()
			informer := kube.NewMetadataProvider(kube.MetadataConfig{Enable: tc.enable}, imetrics.NoopReporter{})
			decorator, err := ClusterNameDecoratorProvider(t.Context(), &transform.KubernetesDecorator{ClusterName: tc.cluster},
				informer, func(a *pipe.CommonAttrs) *pipe.CommonAttrs { return a }, in, out)(t.Context())
			require.NoError(t, err)
			go decorator(t.Context())

			in.Send([]*pipe.CommonAttrs{{}})

			decorated := testutil.ReadChannel(t, outCh, 5*time.Second)
			require.Len(t, decorated, 1)
			assert.Equal(t, tc.want, decorated[0].Metadata)
		})
	}
}
