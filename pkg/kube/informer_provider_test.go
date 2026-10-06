// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
)

// fakeAPIServer answers the pod and node lists the node and cluster name
// lookups make, and returns a kubeconfig pointing at it.
func fakeAPIServer(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/nodes") {
			_, _ = io.WriteString(w, `{"kind":"NodeList","apiVersion":"v1","items":[`+
				`{"metadata":{"name":"node-1","labels":{"cluster.x-k8s.io/cluster-name":"cluster-1"}}}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"kind":"PodList","apiVersion":"v1","items":[`+
			`{"metadata":{"name":"obi-abcde"},"spec":{"nodeName":"node-1"}}]}`)
	}))
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
	return kubeconfig
}

// The node and cluster names are looked up once and cached, by callers on
// several goroutines at once (the stats pipeline, the node metadata, the
// cluster name of each decorator). Run with -race.
func TestCurrentNodeNameConcurrentCallers(t *testing.T) {
	old := slog.Default()
	// Outside a pod the namespace lookup warns; keep it out of the test log.
	slog.SetDefault(slog.New(slog.DiscardHandler))
	t.Cleanup(func() { slog.SetDefault(old) })

	mp := NewMetadataProvider(MetadataConfig{
		Enable:         kubeflags.EnabledTrue,
		KubeConfigPath: fakeAPIServer(t),
	}, nil)

	const callers = 8
	var (
		wg       sync.WaitGroup
		nodes    [callers]string
		clusters [callers]string
		errs     [2 * callers]error
	)
	for i := range callers {
		wg.Go(func() { nodes[i], errs[i] = mp.CurrentNodeName(t.Context()) })
		wg.Go(func() { clusters[i], errs[callers+i] = mp.ClusterName(t.Context()) })
	}
	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
	for i := range callers {
		assert.Equal(t, "node-1", nodes[i])
		assert.Equal(t, "cluster-1", clusters[i])
	}
}
