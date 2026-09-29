// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
)

// kubeProvider returns a metadata provider whose API server is handler.
func kubeProvider(t *testing.T, handler http.HandlerFunc) *kube.MetadataProvider {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: `+srv.URL+`
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
users:
- name: test
  user: {}
`), 0o600))

	old := slog.Default()
	// Outside a pod the namespace lookup warns; keep it out of the test log.
	slog.SetDefault(slog.New(slog.DiscardHandler))
	t.Cleanup(func() { slog.SetDefault(old) })
	t.Cleanup(func() { ebpf.SetNodeName("") })

	return kube.NewMetadataProvider(kube.MetadataConfig{Enable: kubeflags.EnabledTrue, KubeConfigPath: kubeconfig}, nil)
}

func TestSetNodeName(t *testing.T) {
	mp := kubeProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"kind":"PodList","apiVersion":"v1","items":[`+
			`{"metadata":{"name":"obi-abcde"},"spec":{"nodeName":"node-1"}}]}`)
	})

	setNodeName(t.Context(), mp, slog.Default())

	assert.Equal(t, "node-1", ebpf.NodeName())
}

// An API server that does not answer must not hold up the stats pipeline:
// the node name is then left unset.
func TestSetNodeNameTimesOut(t *testing.T) {
	old := nodeNameTimeout
	nodeNameTimeout = 100 * time.Millisecond
	t.Cleanup(func() { nodeNameTimeout = old })
	mp := kubeProvider(t, func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})

	done := make(chan struct{})
	go func() {
		setNodeName(t.Context(), mp, slog.Default())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the node name lookup did not time out")
	}
	assert.Empty(t, ebpf.NodeName())
}
