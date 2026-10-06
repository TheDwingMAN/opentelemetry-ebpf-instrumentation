// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"log/slog"
	"strings"
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

func pidTestPidOf(item *pidTestItem) (uint32, uint32, ebpf.MountKey, bool) {
	return item.pidNs, item.hostPID, ebpf.MountKey{Dev: item.sDev}, item.hasPID
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

	resolveMount = func(_ ebpf.MountKey) (ebpf.MountInfo, bool) {
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

	resolveMount = func(_ ebpf.MountKey) (ebpf.MountInfo, bool) {
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
	resolveMount = func(_ ebpf.MountKey) (ebpf.MountInfo, bool) { return ebpf.MountInfo{}, false }

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

	resolveMount = func(_ ebpf.MountKey) (ebpf.MountInfo, bool) {
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

// With storage metrics alone nothing registers processes in the Store, so a
// process on a shared volume, where the mount cannot name the pod, is still
// attributed through its cgroup.
func TestPIDMetadataDecorator_UntrackedPIDResolvedFromCgroup(t *testing.T) {
	originalInfoForPID := kube.InfoForPID
	defer func() { kube.InfoForPID = originalInfoForPID }()
	originalResolveMount := resolveMount
	defer func() { resolveMount = originalResolveMount }()

	store := newPIDTestStore(t)
	const hostPID = app.PID(4321)

	reads := 0
	kube.InfoForPID = func(pid app.PID) (container.Info, error) {
		reads++
		if pid == hostPID {
			return container.Info{ContainerID: "cid-writer", PIDNamespace: 7000}, nil
		}
		return container.Info{}, assert.AnError
	}
	for _, podMeta := range []*informer.ObjectMeta{
		{
			Name: "first-mounter", Namespace: "vol-ns", Kind: "Pod",
			Pod: &informer.PodInfo{Uid: "pod-uid-1"},
		},
		{
			Name: "writer", Namespace: "vol-ns", Kind: "Pod",
			Pod: &informer.PodInfo{
				Uid:        "pod-uid-2",
				Containers: []*informer.ContainerInfo{{Id: "cid-writer", Name: "io"}},
			},
		},
	} {
		require.NoError(t, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: podMeta}))
	}
	resolveMount = func(_ ebpf.MountKey) (ebpf.MountInfo, bool) {
		return ebpf.MountInfo{PodUID: "pod-uid-1", PVName: "pvc-shared", VolumeType: "nfs", Shared: true}, true
	}

	input := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()

	run, err := PIDMetadataDecoratorProvider[*pidTestItem](
		store, pidTestAttrs, pidTestPidOf, noopPVCLookup, input, output,
	)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	// Two items from the same process: the cgroup is read once.
	input.Send([]*pidTestItem{
		{pidNs: 7000, hostPID: uint32(hostPID), sDev: 42, hasPID: true},
		{pidNs: 7000, hostPID: uint32(hostPID), sDev: 42, hasPID: true},
	})

	got := testutil.ReadChannel(t, outCh, pidTestTimeout)
	require.Len(t, got, 2)
	for _, item := range got {
		assert.Equal(t, "writer", item.Metadata[attr.K8sPodName])
		assert.Equal(t, "vol-ns", item.Metadata[attr.K8sNamespaceName])
		assert.Equal(t, "io", item.Metadata[attr.K8sContainerName])
		assert.Equal(t, "pvc-shared", item.Metadata[attr.K8sPersistentVolumeName])
	}
	assert.Equal(t, 1, reads, "the container ID is cached per PID")
}

// A writer that exits before its events are decorated, like a dd spawned by a
// shell loop, is still attributed to its container through its PID namespace,
// which the container's other processes keep alive.
func TestPIDMetadataDecorator_ExitedPIDResolvedThroughItsNamespace(t *testing.T) {
	originalInfoForPID := kube.InfoForPID
	defer func() { kube.InfoForPID = originalInfoForPID }()
	originalPidsInNamespace := pidsInNamespace
	defer func() { pidsInNamespace = originalPidsInNamespace }()
	originalResolveMount := resolveMount
	defer func() { resolveMount = originalResolveMount }()

	store := newPIDTestStore(t)
	const (
		exitedPID = app.PID(5001)
		shellPID  = app.PID(4000)
		podNs     = uint32(7100)
	)

	kube.InfoForPID = func(pid app.PID) (container.Info, error) {
		if pid == shellPID {
			return container.Info{ContainerID: "cid-writer", PIDNamespace: podNs}, nil
		}
		return container.Info{}, assert.AnError // exitedPID is gone
	}
	scans := 0
	pidsInNamespace = func(ns uint32) []app.PID {
		scans++
		if ns == podNs {
			return []app.PID{shellPID}
		}
		return nil
	}
	require.NoError(t, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "writer", Namespace: "vol-ns", Kind: "Pod",
		Pod: &informer.PodInfo{
			Uid:        "pod-uid-2",
			Containers: []*informer.ContainerInfo{{Id: "cid-writer", Name: "io"}},
		},
	}}))
	resolveMount = func(_ ebpf.MountKey) (ebpf.MountInfo, bool) {
		return ebpf.MountInfo{PodUID: "pod-uid-2", PVName: "pvc-a", VolumeType: "nfs", Shared: true}, true
	}

	input := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()

	run, err := PIDMetadataDecoratorProvider[*pidTestItem](
		store, pidTestAttrs, pidTestPidOf, noopPVCLookup, input, output,
	)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	// Two short-lived writers in the same container: the namespace is scanned once.
	input.Send([]*pidTestItem{
		{pidNs: podNs, hostPID: uint32(exitedPID), sDev: 42, hasPID: true},
		{pidNs: podNs, hostPID: uint32(exitedPID + 1), sDev: 42, hasPID: true},
	})

	got := testutil.ReadChannel(t, outCh, pidTestTimeout)
	require.Len(t, got, 2)
	for _, item := range got {
		assert.Equal(t, "writer", item.Metadata[attr.K8sPodName])
		assert.Equal(t, "io", item.Metadata[attr.K8sContainerName])
	}
	assert.Equal(t, 1, scans, "the namespace's container is cached")
}

// A pod doing I/O in its first seconds is attributed even before the Store
// has heard of its container: the pod UID in the cgroup path names the pod.
func TestPIDMetadataDecorator_NewContainerResolvedByPodUID(t *testing.T) {
	originalInfoForPID := kube.InfoForPID
	defer func() { kube.InfoForPID = originalInfoForPID }()
	originalPodUIDForPID := podUIDForPID
	defer func() { podUIDForPID = originalPodUIDForPID }()
	originalResolveMount := resolveMount
	defer func() { resolveMount = originalResolveMount }()

	store := newPIDTestStore(t)
	const hostPID = app.PID(6001)
	kube.InfoForPID = func(pid app.PID) (container.Info, error) {
		if pid == hostPID {
			return container.Info{ContainerID: "cid-not-yet-reported", PIDNamespace: 8100}, nil
		}
		return container.Info{}, assert.AnError
	}
	podUIDForPID = func(pid app.PID) string {
		if pid == hostPID {
			return "0e0c38ef-d14c-4ca4-8810-5b6360663f4b"
		}
		return ""
	}
	// Scheduled, but its status does not list the container yet.
	require.NoError(t, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: &informer.ObjectMeta{
		Name: "early-writer", Namespace: "jobs", Kind: "Pod",
		Pod: &informer.PodInfo{Uid: "0e0c38ef-d14c-4ca4-8810-5b6360663f4b"},
	}}))
	resolveMount = func(_ ebpf.MountKey) (ebpf.MountInfo, bool) {
		return ebpf.MountInfo{PodUID: "someone-else", PVName: "pvc-shared", VolumeType: "nfs", Shared: true}, true
	}

	input := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()

	run, err := PIDMetadataDecoratorProvider[*pidTestItem](
		store, pidTestAttrs, pidTestPidOf, noopPVCLookup, input, output,
	)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	input.Send([]*pidTestItem{{pidNs: 8100, hostPID: uint32(hostPID), sDev: 42, hasPID: true}})

	got := testutil.ReadChannel(t, outCh, pidTestTimeout)
	require.Len(t, got, 1)
	assert.Equal(t, "early-writer", got[0].Metadata[attr.K8sPodName])
	assert.Equal(t, "jobs", got[0].Metadata[attr.K8sNamespaceName])
	assert.Empty(t, got[0].Metadata[attr.K8sContainerName], "the container name is not known yet")
}

func TestPodUIDPatternMatchesBothCgroupDrivers(t *testing.T) {
	for _, line := range []string{
		"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod44c76ce5_f953_4bd3_bc89_12621681af49.slice/crio-40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9.scope",
		"0::/kubepods/burstable/pod44c76ce5-f953-4bd3-bc89-12621681af49/40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9",
	} {
		m := podUIDPattern.FindStringSubmatch(line)
		require.NotNil(t, m, line)
		assert.Equal(t, "44c76ce5-f953-4bd3-bc89-12621681af49", strings.ReplaceAll(m[1], "_", "-"))
	}
}

// Several PVs on one superblock (an NFS export shared by a subdirectory
// provisioner) leave the PV unnamed; no claim is guessed for it.
func TestPIDMetadataDecorator_AmbiguousVolumeSkipsVolumeAttrs(t *testing.T) {
	originalResolveMount := resolveMount
	defer func() { resolveMount = originalResolveMount }()
	resolveMount = func(_ ebpf.MountKey) (ebpf.MountInfo, bool) {
		return ebpf.MountInfo{PodUID: "55293f39-c745-4578-accb-f3e5cfc7b303", VolumeType: "csi"}, true
	}
	lookups := 0
	pvcLookup := func(context.Context, string) (string, string, string, bool) {
		lookups++
		return "ns", "claim", "class", true
	}

	store := newPIDTestStore(t)

	input := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	defer input.Close()
	output := msg.NewQueue[[]*pidTestItem](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()

	run, err := PIDMetadataDecoratorProvider[*pidTestItem](
		store, pidTestAttrs, pidTestPidOf, pvcLookup, input, output,
	)(t.Context())
	require.NoError(t, err)
	go run(t.Context())

	input.Send([]*pidTestItem{{pidNs: 1, hostPID: 1, sDev: 77, hasPID: true}})

	got := testutil.ReadChannel(t, outCh, pidTestTimeout)
	require.Len(t, got, 1)
	assert.Empty(t, got[0].Metadata[attr.K8sPersistentVolumeName])
	assert.Empty(t, got[0].Metadata[attr.K8sPersistentVolumeClaimName])
	assert.Zero(t, lookups, "no claim lookup for an unnamed volume")
}
