// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"testing"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

// BenchmarkPIDDecorator_FsEventMountpoints is the per-event cost of the mount
// path attributes over BenchmarkPIDDecorator_FsEvent's: the stat comes with
// its pod, as a kernel-aggregated key does, and every cache is warm.
func BenchmarkPIDDecorator_FsEventMountpoints(b *testing.B) {
	original := resolveMount
	b.Cleanup(func() { resolveMount = original })

	store := newPIDTestStore(b)
	require.NoError(b, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "writer-0", Namespace: "storage-test", Kind: "Pod", Pod: &informer.PodInfo{Uid: "pod-uid-writer"},
	}}))
	shared := ebpf.MountInfo{PodUID: "pod-uid-writer", PVName: "pvc-rwx", Shared: true}.
		WithPodHostPaths(map[string]string{"pod-uid-writer": "/host/writer", "pod-uid-other": "/host/other"})
	single := ebpf.MountInfo{PodUID: "pod-uid-writer", PVName: "pvc-1", HostPath: "/host/writer"}
	containerPath := func(uint32, uint32, string, ebpf.MountKey) string { return "/data" }

	for _, tc := range []struct {
		name string
		info ebpf.MountInfo
		mp   func(d *pidDecorator)
	}{
		{"off", single, func(*pidDecorator) {}},
		{"host path", single, func(d *pidDecorator) { d.hostPath = true }},
		{"host path of a shared volume", shared, func(d *pidDecorator) { d.hostPath = true }},
		{"host and container path", shared, func(d *pidDecorator) { d.hostPath, d.containerPath = true, containerPath }},
	} {
		b.Run(tc.name, func(b *testing.B) {
			resolveMount = func(ebpf.MountKey) (ebpf.MountInfo, bool) { return tc.info, true }
			d := &pidDecorator{
				store: store,
				pvc: ebpf.CachedPVCLookup(func(context.Context, string) (string, string, string, bool) {
					return "storage-test", "data", "fast", true
				}),
				containers: expirable.NewLRU[app.PID, cgroupIdentity](untrackedPIDCacheSize, nil, untrackedPIDCacheTTL),
				namespaces: expirable.NewLRU[uint32, cgroupIdentity](untrackedPIDCacheSize, nil, untrackedPIDCacheTTL),
				volumes:    map[ebpf.MountKey]volumeEntry{},
			}
			tc.mp(d)
			key := ebpf.MountKey{Dev: 253<<20 | 4, RootIno: 128}
			ctx := context.Background()
			preset := map[attr.Name]string{attr.K8sPodName: "writer-0", attr.K8sNamespaceName: "storage-test", attr.K8sContainerName: "app"}

			a := pipe.CommonAttrs{Metadata: preset}
			require.NotNil(b, d.decorateItem(ctx, &a, 1, 2, key, "pod-uid-writer"))

			b.ReportAllocs()
			for b.Loop() {
				a := pipe.CommonAttrs{Metadata: preset}
				d.decorateItem(ctx, &a, 1, 2, key, "pod-uid-writer")
			}
		})
	}
}
