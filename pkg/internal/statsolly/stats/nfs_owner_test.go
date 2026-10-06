// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
)

func newNFSOwnerTestStore(tb testing.TB) *kube.Store {
	tb.Helper()
	n := meta.NewBaseNotifier(slog.Default())
	return kube.NewStore(&n, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})
}

// addNFSOwnerTestPod registers a pod with one container and, optionally, a
// top owner (a Deployment, say), the way the k8s-cache informer would.
func addNFSOwnerTestPod(tb testing.TB, store *kube.Store, uid, namespace, name, containerID, containerName, ownerName string) {
	tb.Helper()
	pod := &informer.PodInfo{
		Uid:        uid,
		Containers: []*informer.ContainerInfo{{Id: containerID, Name: containerName}},
	}
	if ownerName != "" {
		pod.Owners = []*informer.Owner{{Name: "rs-" + ownerName, Kind: "ReplicaSet"}, {Name: ownerName, Kind: "Deployment"}}
	}
	objMeta := &informer.ObjectMeta{Name: name, Namespace: namespace, Kind: "Pod", Pod: pod}
	require.NoError(tb, store.On(&informer.Event{Type: informer.EventType_CREATED, Resource: objMeta}))
}

func TestNewNFSOwnerDecoratorNilWithoutStore(t *testing.T) {
	assert.Nil(t, NewNFSOwnerDecorator(nil, nil, false))
}

// A stat with no NFSRPC payload, or whose owner was never set (no pod
// attribute selected, or the kernel could not read one, 2.5), is left alone:
// the decorator must not even try to resolve owner 0.
func TestNFSOwnerDecoratorSkipsStatsWithNoOwner(t *testing.T) {
	store := newNFSOwnerTestStore(t)
	decorate := NewNFSOwnerDecorator(store, nil, true)
	require.NotNil(t, decorate)

	noRPC := &ebpf.Stat{}
	decorate(noRPC)
	assert.Nil(t, noRPC.CommonAttrs.Metadata)

	zeroOwner := &ebpf.Stat{NFSRPC: &ebpf.NFSRPC{Owner: 0}}
	decorate(zeroOwner)
	assert.Nil(t, zeroOwner.CommonAttrs.Metadata)
}

// On a cgroup v1 host the owner is a tgid (task->tk_owner), resolved by the
// same /proc/<pid>/cgroup path the PID decorator uses for an untracked
// process: the pod trio, the container and the top owner's name.
func TestNFSOwnerDecoratorCgroupV1ResolvesByPID(t *testing.T) {
	originalInfoForPID := kube.InfoForPID
	defer func() { kube.InfoForPID = originalInfoForPID }()

	store := newNFSOwnerTestStore(t)
	addNFSOwnerTestPod(t, store, "pod-uid-1", "my-ns", "my-pod", "cid-1", "my-container", "my-deploy")

	const tgid = 4242
	kube.InfoForPID = func(pid app.PID) (container.Info, error) {
		if pid == app.PID(tgid) {
			return container.Info{ContainerID: "cid-1"}, nil
		}
		return container.Info{}, assert.AnError
	}

	decorate := NewNFSOwnerDecorator(store, nil, true)
	require.NotNil(t, decorate)

	s := &ebpf.Stat{NFSRPC: &ebpf.NFSRPC{Owner: tgid}}
	decorate(s)
	require.NotNil(t, s.CommonAttrs.Metadata)
	assert.Equal(t, "my-ns", s.CommonAttrs.Metadata[attr.K8sNamespaceName])
	assert.Equal(t, "my-pod", s.CommonAttrs.Metadata[attr.K8sPodName])
	assert.Equal(t, "my-container", s.CommonAttrs.Metadata[attr.K8sContainerName])
	assert.Equal(t, "my-deploy", s.CommonAttrs.Metadata[attr.K8sOwnerName], "the top owner, not the pod name")
}

// A cgroup v1 owner the /proc path cannot resolve (the thread has already
// exited: cgroup v1 keeps no equivalent of the cgroup v2 side map's
// survives-exit property, 2.5) leaves the stat without pod metadata.
func TestNFSOwnerDecoratorCgroupV1MissLeavesStatAlone(t *testing.T) {
	originalInfoForPID := kube.InfoForPID
	defer func() { kube.InfoForPID = originalInfoForPID }()
	kube.InfoForPID = func(app.PID) (container.Info, error) { return container.Info{}, assert.AnError }

	store := newNFSOwnerTestStore(t)
	decorate := NewNFSOwnerDecorator(store, nil, true)
	require.NotNil(t, decorate)

	s := &ebpf.Stat{NFSRPC: &ebpf.NFSRPC{Owner: 999}}
	decorate(s)
	assert.Nil(t, s.CommonAttrs.Metadata)
}

// On a cgroup v2 host without an index (not built yet, or Run has not
// scanned), the owner resolves to nothing rather than panicking.
func TestNFSOwnerDecoratorCgroupV2WithoutIndexResolvesToNothing(t *testing.T) {
	store := newNFSOwnerTestStore(t)
	decorate := NewNFSOwnerDecorator(store, nil, false)
	require.NotNil(t, decorate)

	s := &ebpf.Stat{NFSRPC: &ebpf.NFSRPC{Owner: 123}}
	decorate(s)
	assert.Nil(t, s.CommonAttrs.Metadata)
}

// inoOf returns path's inode, the id CgroupIndex keys its entries by.
func inoOf(tb testing.TB, path string) uint64 {
	tb.Helper()
	info, err := os.Stat(path)
	require.NoError(tb, err)
	return info.Sys().(*syscall.Stat_t).Ino
}

// On a cgroup v2 host, the owner is the submitting thread's cgroup id
// (bpf_get_current_cgroup_id(), step 19), resolved through the shared
// step 5 cgroup index to the pod it belongs to; a container not known to
// the index yet (the usual case: the cgroup index learns no container
// names) falls back to the pod by UID, as ResolvePod documents.
func TestNFSOwnerDecoratorCgroupV2ResolvesThroughCgroupIndex(t *testing.T) {
	root := t.TempDir()
	const podDir = "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod90b1ecb8_b850_451a_97c6_c073b5ddbb53.slice"
	require.NoError(t, os.MkdirAll(filepath.Join(root, podDir), 0o755))

	index := statagg.NewCgroupIndex(statagg.WithCgroupRoots(root))
	require.NoError(t, index.Scan())
	cgid := inoOf(t, filepath.Join(root, podDir))

	store := newNFSOwnerTestStore(t)
	addNFSOwnerTestPod(t, store, "90b1ecb8-b850-451a-97c6-c073b5ddbb53", "default", "io-nfs", "cid-1", "my-container", "")

	decorate := NewNFSOwnerDecorator(store, index, false)
	require.NotNil(t, decorate)

	s := &ebpf.Stat{NFSRPC: &ebpf.NFSRPC{Owner: cgid}}
	decorate(s)
	require.NotNil(t, s.CommonAttrs.Metadata)
	assert.Equal(t, "default", s.CommonAttrs.Metadata[attr.K8sNamespaceName])
	assert.Equal(t, "io-nfs", s.CommonAttrs.Metadata[attr.K8sPodName])
	assert.Empty(t, s.CommonAttrs.Metadata[attr.K8sContainerName], "the cgroup index resolved the pod slice only, not a container")
	assert.Equal(t, "io-nfs", s.CommonAttrs.Metadata[attr.K8sOwnerName], "no owner reference: falls back to the pod's own name")
}

// A cgroup id the index never found a pod for (the root cgroup, a
// non-Kubernetes cgroup, or one the scan has not reached yet) leaves the
// stat without pod metadata rather than setting empty strings.
func TestNFSOwnerDecoratorCgroupV2UnknownCgroupLeavesStatAlone(t *testing.T) {
	root := t.TempDir()
	index := statagg.NewCgroupIndex(statagg.WithCgroupRoots(root))
	require.NoError(t, index.Scan())

	store := newNFSOwnerTestStore(t)
	decorate := NewNFSOwnerDecorator(store, index, false)
	require.NotNil(t, decorate)

	s := &ebpf.Stat{NFSRPC: &ebpf.NFSRPC{Owner: 1 << 20}}
	decorate(s)
	assert.Nil(t, s.CommonAttrs.Metadata)
}

// A cgroup the index has not scanned yet (a freshly started pod), or a pod
// the Store has not learned yet, leaves the stat pending so the family
// decorates the key again on its next count instead of after RedecorateAfter.
func TestNFSOwnerDecoratorPendingUntilResolved(t *testing.T) {
	root := t.TempDir()
	const podDir = "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod90b1ecb8_b850_451a_97c6_c073b5ddbb53.slice"
	require.NoError(t, os.MkdirAll(filepath.Join(root, podDir), 0o755))
	cgid := inoOf(t, filepath.Join(root, podDir))

	index := statagg.NewCgroupIndex(statagg.WithCgroupRoots(root))
	store := newNFSOwnerTestStore(t)
	decorate := NewNFSOwnerDecorator(store, index, false)

	run := func() *ebpf.Stat {
		s := &ebpf.Stat{NFSRPC: &ebpf.NFSRPC{Owner: cgid}}
		decorate(s)
		return s
	}

	s := run()
	assert.True(t, s.NFSRPC.OwnerPending, "the index has not scanned the cgroup")
	assert.Nil(t, s.CommonAttrs.Metadata)

	require.NoError(t, index.Scan())
	s = run()
	assert.True(t, s.NFSRPC.OwnerPending, "the index knows the pod, the Store does not yet")
	assert.Nil(t, s.CommonAttrs.Metadata)

	addNFSOwnerTestPod(t, store, "90b1ecb8-b850-451a-97c6-c073b5ddbb53", "default", "io-nfs", "cid-2", "c", "")
	s = run()
	assert.False(t, s.NFSRPC.OwnerPending)
	assert.Equal(t, "io-nfs", s.CommonAttrs.Metadata[attr.K8sPodName])
}

// A cgroup the finished scan did not find a pod for is final: no retries.
func TestNFSOwnerDecoratorNotPendingForNonPodCgroup(t *testing.T) {
	root := t.TempDir()
	index := statagg.NewCgroupIndex(statagg.WithCgroupRoots(root))
	require.NoError(t, index.Scan())
	decorate := NewNFSOwnerDecorator(newNFSOwnerTestStore(t), index, false)

	s := &ebpf.Stat{NFSRPC: &ebpf.NFSRPC{Owner: 1 << 20}}
	decorate(s) // first lookup asks for a rescan
	require.NoError(t, index.Scan())
	s = &ebpf.Stat{NFSRPC: &ebpf.NFSRPC{Owner: 1 << 20}}
	decorate(s)
	assert.False(t, s.NFSRPC.OwnerPending)
}

// The decorator runs once per aggregation key per poll, never per RPC: this
// measures that cost for a key whose owner resolves to a pod (the map write
// of the metadata included).
func BenchmarkNFSOwnerDecorator(b *testing.B) {
	root := b.TempDir()
	const podDir = "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod90b1ecb8_b850_451a_97c6_c073b5ddbb53.slice"
	require.NoError(b, os.MkdirAll(filepath.Join(root, podDir), 0o755))
	index := statagg.NewCgroupIndex(statagg.WithCgroupRoots(root))
	require.NoError(b, index.Scan())
	cgid := inoOf(b, filepath.Join(root, podDir))

	store := newNFSOwnerTestStore(b)
	addNFSOwnerTestPod(b, store, "90b1ecb8-b850-451a-97c6-c073b5ddbb53", "default", "io-nfs", "cid-1", "my-container", "web")
	decorate := NewNFSOwnerDecorator(store, index, false)
	require.NotNil(b, decorate)

	b.ReportAllocs()
	for b.Loop() {
		decorate(&ebpf.Stat{NFSRPC: &ebpf.NFSRPC{Owner: cgid}})
	}
}
