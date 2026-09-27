// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const pidTestTimeout = 5 * time.Second

type pidTestItem struct {
	pipe.CommonAttrs
	pidNs   uint32
	hostPID uint32
	sDev    uint32
	hasPID  bool
}

func pidTestAttrs(item *pidTestItem) *pipe.CommonAttrs { return &item.CommonAttrs }

func pidTestPidOf(item *pidTestItem) (uint32, uint32, uint32, bool) {
	return item.pidNs, item.hostPID, item.sDev, item.hasPID
}

func noopPVCLookup(context.Context, string) (string, string, string, bool) { return "", "", "", false }

func newPIDTestStore(t *testing.T) *kube.Store {
	t.Helper()
	n := meta.NewBaseNotifier(slog.Default())
	return kube.NewStore(&n, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})
}

func TestPIDMetadataDecorator_PassesThroughItemsWithoutPID(t *testing.T) {
	store := newPIDTestStore(t)

	input := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()

	run, err := PIDMetadataDecoratorProvider[*pidTestItem](
		store, pidTestAttrs, pidTestPidOf, noopPVCLookup, input, output,
	)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	item := &pidTestItem{hasPID: false}
	input.Send([]*pidTestItem{item})

	got := testutil.ReadChannel(t, outCh, pidTestTimeout)
	require.Len(t, got, 1)
	assert.Same(t, item, got[0])
	assert.Nil(t, got[0].Metadata)
}

func TestPIDMetadataDecorator_DecoratesFromPIDPath(t *testing.T) {
	originalInfoForPID := kube.InfoForPID
	defer func() { kube.InfoForPID = originalInfoForPID }()

	store := newPIDTestStore(t)

	const pidNs = uint32(5000)
	const hostPID = app.PID(1234)

	kube.InfoForPID = func(pid app.PID) (container.Info, error) {
		if pid == hostPID {
			return container.Info{ContainerID: "cid-1", PIDNamespace: pidNs}, nil
		}
		return container.Info{}, assert.AnError
	}
	store.AddProcess(hostPID)

	podMeta := &informer.ObjectMeta{
		Name: "my-pod", Namespace: "my-ns", Kind: "Pod",
		Pod: &informer.PodInfo{
			Uid:        "pod-uid-1",
			Containers: []*informer.ContainerInfo{{Id: "cid-1", Name: "my-container"}},
		},
	}
	require.NoError(t, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: podMeta}))

	input := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()

	run, err := PIDMetadataDecoratorProvider[*pidTestItem](
		store, pidTestAttrs, pidTestPidOf, noopPVCLookup, input, output,
	)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	input.Send([]*pidTestItem{{pidNs: pidNs, hostPID: uint32(hostPID), hasPID: true}})

	got := testutil.ReadChannel(t, outCh, pidTestTimeout)
	require.Len(t, got, 1)
	assert.Equal(t, "my-pod", got[0].Metadata[attr.K8sPodName])
	assert.Equal(t, "my-ns", got[0].Metadata[attr.K8sNamespaceName])
	assert.Equal(t, "my-container", got[0].Metadata[attr.K8sContainerName])
}

func TestPIDMetadataDecorator_FallsBackToMountPodWhenPIDUnresolved(t *testing.T) {
	originalResolveMount := resolveMount
	defer func() { resolveMount = originalResolveMount }()

	store := newPIDTestStore(t)

	podMeta := &informer.ObjectMeta{
		Name: "vol-pod", Namespace: "vol-ns", Kind: "Pod",
		Pod: &informer.PodInfo{Uid: "pod-uid-2"},
	}
	require.NoError(t, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: podMeta}))

	resolveMount = func(_ uint32) (ebpf.MountInfo, bool) {
		return ebpf.MountInfo{PodUID: "pod-uid-2", PVName: "pvc-abc", VolumeType: "nfs"}, true
	}

	input := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()

	pvc := func(_ context.Context, pvName string) (string, string, string, bool) {
		assert.Equal(t, "pvc-abc", pvName)
		return "vol-ns", "my-claim", "", true
	}

	run, err := PIDMetadataDecoratorProvider[*pidTestItem](
		store, pidTestAttrs, pidTestPidOf, pvc, input, output,
	)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	// pidNs/hostPID that don't resolve to any tracked process via the PID path.
	input.Send([]*pidTestItem{{pidNs: 1, hostPID: 1, sDev: 42, hasPID: true}})

	got := testutil.ReadChannel(t, outCh, pidTestTimeout)
	require.Len(t, got, 1)
	assert.Equal(t, "vol-pod", got[0].Metadata[attr.K8sPodName])
	assert.Equal(t, "vol-ns", got[0].Metadata[attr.K8sNamespaceName])
	assert.Empty(t, got[0].Metadata[attr.K8sContainerName])
	assert.Equal(t, "pvc-abc", got[0].Metadata[attr.K8sPersistentVolumeName])
	assert.Equal(t, "my-claim", got[0].Metadata[attr.K8sPersistentVolumeClaimName])
	// Storage class attribute must be absent when PVC lookup returns empty string
	assert.Empty(t, got[0].Metadata[attr.K8sStorageClassName])
}

func TestPIDMetadataDecorator_AttributesStorageClass(t *testing.T) {
	originalResolveMount := resolveMount
	defer func() { resolveMount = originalResolveMount }()

	store := newPIDTestStore(t)

	podMeta := &informer.ObjectMeta{
		Name: "vol-pod", Namespace: "vol-ns", Kind: "Pod",
		Pod: &informer.PodInfo{Uid: "pod-uid-3"},
	}
	require.NoError(t, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: podMeta}))

	resolveMount = func(_ uint32) (ebpf.MountInfo, bool) {
		return ebpf.MountInfo{PodUID: "pod-uid-3", PVName: "pvc-def", VolumeType: "nfs"}, true
	}

	input := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()

	pvc := func(_ context.Context, pvName string) (string, string, string, bool) {
		assert.Equal(t, "pvc-def", pvName)
		return "vol-ns", "my-claim", "fast-ssd", true
	}

	run, err := PIDMetadataDecoratorProvider[*pidTestItem](
		store, pidTestAttrs, pidTestPidOf, pvc, input, output,
	)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	input.Send([]*pidTestItem{{pidNs: 1, hostPID: 1, sDev: 43, hasPID: true}})

	got := testutil.ReadChannel(t, outCh, pidTestTimeout)
	require.Len(t, got, 1)
	assert.Equal(t, "vol-pod", got[0].Metadata[attr.K8sPodName])
	assert.Equal(t, "vol-ns", got[0].Metadata[attr.K8sNamespaceName])
	assert.Equal(t, "pvc-def", got[0].Metadata[attr.K8sPersistentVolumeName])
	assert.Equal(t, "my-claim", got[0].Metadata[attr.K8sPersistentVolumeClaimName])
	// Storage class attribute must be present and equal to the non-empty value returned by PVC lookup
	assert.Equal(t, "fast-ssd", got[0].Metadata[attr.K8sStorageClassName])
}

func TestPIDMetadataDecorator_NoMountFoundSkipsVolumeAttrs(t *testing.T) {
	originalResolveMount := resolveMount
	defer func() { resolveMount = originalResolveMount }()
	resolveMount = func(_ uint32) (ebpf.MountInfo, bool) { return ebpf.MountInfo{}, false }

	store := newPIDTestStore(t)

	input := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()

	run, err := PIDMetadataDecoratorProvider[*pidTestItem](
		store, pidTestAttrs, pidTestPidOf, noopPVCLookup, input, output,
	)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	input.Send([]*pidTestItem{{pidNs: 1, hostPID: 1, sDev: 42, hasPID: true}})

	got := testutil.ReadChannel(t, outCh, pidTestTimeout)
	require.Len(t, got, 1)
	assert.Empty(t, got[0].Metadata[attr.K8sPersistentVolumeName])
	assert.Empty(t, got[0].Metadata[attr.K8sPersistentVolumeClaimName])
}

func TestPIDMetadataDecoratorProvider_BypassesWhenStoreNil(t *testing.T) {
	input := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()

	run, err := PIDMetadataDecoratorProvider[*pidTestItem](
		nil, pidTestAttrs, pidTestPidOf, noopPVCLookup, input, output,
	)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	item := &pidTestItem{hasPID: true, pidNs: 1, hostPID: 1}
	input.Send([]*pidTestItem{item})

	got := testutil.ReadChannel(t, outCh, pidTestTimeout)
	require.Len(t, got, 1)
	assert.Same(t, item, got[0])
}

// On a ReadWriteMany volume the mount's pod is one of several. When the PID
// path cannot name the process, the volume and claim are still certain and
// must be reported; the pod must not be guessed from the mount.
func TestPIDMetadataDecorator_SharedVolumeKeepsVolumeButNotPod(t *testing.T) {
	originalResolveMount := resolveMount
	defer func() { resolveMount = originalResolveMount }()

	store := newPIDTestStore(t)
	podMeta := &informer.ObjectMeta{
		Name: "first-mounter", Namespace: "vol-ns", Kind: "Pod",
		Pod: &informer.PodInfo{Uid: "pod-uid-2"},
	}
	require.NoError(t, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: podMeta}))

	resolveMount = func(_ uint32) (ebpf.MountInfo, bool) {
		return ebpf.MountInfo{PodUID: "pod-uid-2", PVName: "pvc-shared", VolumeType: "nfs", Shared: true}, true
	}

	input := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()

	pvc := func(_ context.Context, _ string) (string, string, string, bool) {
		return "vol-ns", "shared-claim", "obi-nfs", true
	}

	run, err := PIDMetadataDecoratorProvider[*pidTestItem](
		store, pidTestAttrs, pidTestPidOf, pvc, input, output,
	)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	input.Send([]*pidTestItem{{pidNs: 1, hostPID: 1, sDev: 42, hasPID: true}})

	got := testutil.ReadChannel(t, outCh, pidTestTimeout)
	require.Len(t, got, 1)
	assert.Empty(t, got[0].Metadata[attr.K8sPodName], "a shared volume must not name the first mounter")
	assert.Equal(t, "pvc-shared", got[0].Metadata[attr.K8sPersistentVolumeName])
	assert.Equal(t, "shared-claim", got[0].Metadata[attr.K8sPersistentVolumeClaimName])
	assert.Equal(t, "obi-nfs", got[0].Metadata[attr.K8sStorageClassName])
	assert.Equal(t, "vol-ns", got[0].Metadata[attr.K8sNamespaceName], "the claim's namespace is still certain")
}
