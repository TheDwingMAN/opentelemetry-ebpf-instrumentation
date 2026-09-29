// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"testing"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

// BenchmarkPIDDecorator_FsEvent measures the steady-state per-event cost of
// decorating one filesystem stat: a process of a pod the Store does not track
// by PID (the case with storage metrics alone), writing to a persistent
// volume bound to a claim. Every cache is warm, as it is after the first
// event of each process and mount.
func BenchmarkPIDDecorator_FsEvent(b *testing.B) {
	originalInfoForPID := kube.InfoForPID
	originalResolveMount := resolveMount
	b.Cleanup(func() {
		kube.InfoForPID = originalInfoForPID
		resolveMount = originalResolveMount
	})

	const (
		pidNs   = uint32(4026532000)
		hostPID = app.PID(4321)
	)
	kube.InfoForPID = func(app.PID) (container.Info, error) {
		return container.Info{ContainerID: "cid-writer", PIDNamespace: pidNs}, nil
	}
	resolveMount = func(ebpf.MountKey) (ebpf.MountInfo, bool) {
		return ebpf.MountInfo{
			PodUID: "pod-uid-writer", PVName: "pvc-b3befffd-ae0d-4fa0-8cef-4949329d8c3f", VolumeType: "csi",
		}, true
	}

	store := newPIDTestStore(b)
	require.NoError(b, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "writer-7d9f8b6c4-x2x7z", Namespace: "storage-test", Kind: "Pod",
		Pod: &informer.PodInfo{
			Uid:        "pod-uid-writer",
			Containers: []*informer.ContainerInfo{{Id: "cid-writer", Name: "writer"}},
		},
	}}))

	d := &pidDecorator{
		store: store,
		pvc: ebpf.CachedPVCLookup(func(context.Context, string) (string, string, string, bool) {
			return "storage-test", "data-writer-0", "topolvm-provisioner", true
		}),
		containers: expirable.NewLRU[app.PID, cgroupIdentity](untrackedPIDCacheSize, nil, untrackedPIDCacheTTL),
		namespaces: expirable.NewLRU[uint32, cgroupIdentity](untrackedPIDCacheSize, nil, untrackedPIDCacheTTL),
		volumes:    map[ebpf.MountKey]volumeEntry{},
	}
	key := ebpf.MountKey{Dev: 253<<20 | 4, RootIno: 128}
	ctx := context.Background()

	var a pipe.CommonAttrs
	d.decorate(ctx, &a, pidNs, uint32(hostPID), key)
	require.Equal(b, "writer-7d9f8b6c4-x2x7z", a.Metadata["k8s.pod.name"])

	b.ReportAllocs()
	for b.Loop() {
		// Every event is a new Stat, with no metadata yet.
		a := pipe.CommonAttrs{}
		d.decorate(ctx, &a, pidNs, uint32(hostPID), key)
	}
}
