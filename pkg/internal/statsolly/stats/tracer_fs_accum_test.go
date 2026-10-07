// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

// The layout the decoder reads, pinned against bpf/statsolly/fs_io.h as
// bpf/tests/test_fs_io.c checks it on the C side.
func TestFsAccumLayout(t *testing.T) {
	assert.Equal(t, 32, fsKeySize)
	assert.Equal(t, []int{0, 8, 16, 20, 24, 25, 26},
		[]int{fsKeyCgid, fsKeyRootIno, fsKeySDev, fsKeyPidNs, fsKeyFs, fsKeyOp, fsKeyErr})
	assert.Equal(t, 148, fsValSampleTgid, "after 2 u64 and 33 u32")
	assert.Equal(t, 532, fsExpValSampleTgid, "after 2 u64 and 129 u32")
}

// fsKey packs a key as fs_accum_key_init does.
func fsKey(cgid uint64, s *ebpf.FsIo) []byte {
	k := make([]byte, fsKeySize)
	binary.NativeEndian.PutUint64(k[0:], cgid)
	binary.NativeEndian.PutUint64(k[8:], s.RootIno)
	binary.NativeEndian.PutUint32(k[16:], s.SDev)
	binary.NativeEndian.PutUint32(k[20:], s.PidNs)
	k[24], k[25] = s.Fs, s.Op
	binary.NativeEndian.PutUint16(k[26:], uint16(-s.Error))
	return k
}

type fsTestMap struct {
	m      *stataggtest.MemMap
	layout *statagg.Layout
}

func newFsTestMap(tb testing.TB, layout *statagg.Layout) *fsTestMap {
	tb.Helper()
	size := 152
	if layout.Kind == statagg.LayoutExponential {
		size = 536
	}
	return &fsTestMap{m: stataggtest.NewMemMap(fsKeySize, size, 1), layout: layout}
}

// record counts an operation as fs_aggregate does.
func (f *fsTestMap) record(cgid uint64, s *ebpf.FsIo) {
	key := fsKey(cgid, s)
	f.m.AddU64(key, 0, 0, s.LatencyNs)
	f.m.AddU64(key, 0, 8, s.Bytes)
	idx := sort.Search(len(f.layout.BoundsNs), func(i int) bool { return s.LatencyNs <= f.layout.BoundsNs[i] })
	f.m.AddU32(key, 0, 16+4*idx, 1)
	sample := fsValSampleTgid
	if f.layout.Kind == statagg.LayoutExponential {
		sample = fsExpValSampleTgid
	}
	f.m.SetU32(key, 0, sample, s.HostPID)
}

func fsLayout(tb testing.TB) *statagg.Layout {
	tb.Helper()
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatFsOperationDurationHistogram)
	require.NoError(tb, err)
	return layout
}

// A key becomes the stat of its operations: identity from the key, a
// failure's errno negative as in the ring buffer event, and the process
// that counted into it last.
func TestFsAccumStat(t *testing.T) {
	for _, layout := range []*statagg.Layout{fsLayout(t), must(statagg.NewExponentialLayout(statagg.DefaultExponentialScale))} {
		m := newFsTestMap(t, layout)
		io := &ebpf.FsIo{
			Fs: uint8(ebpf.CodeFsXFS), Op: uint8(ebpf.CodeFsOpWrite), SDev: 253<<20 | 4, PidNs: 4026532000,
			HostPID: 4242, Error: -28, RootIno: 128, LatencyNs: 5000,
		}
		m.record(77, io)

		d := fsDecoder{sampleTgid: fsValSampleTgid}
		if layout.Kind == statagg.LayoutExponential {
			d.sampleTgid = fsExpValSampleTgid
		}
		var stat *ebpf.Stat
		var final bool
		require.NoError(t, m.m.ForEach(func(key, values []byte) { stat, final = d.stat(key, values) }))
		require.NotNil(t, stat)
		assert.True(t, final)
		assert.Equal(t, ebpf.StatTypeFsIo, stat.Type)
		assert.Equal(t, ebpf.FsIo{
			Fs: io.Fs, Op: io.Op, SDev: io.SDev, PidNs: io.PidNs, HostPID: io.HostPID, Error: -28, RootIno: 128,
		}, *stat.FsIo)
		assert.Nil(t, stat.CommonAttrs.Metadata, "no cgroup index: the PID decorator finds the pod")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// fakePods is a Kubernetes store of one pod with one container.
type fakePods struct{ podUID, containerID string }

func (p fakePods) PodContainerByContainerID(id string) (*ikube.CachedObjMeta, string) {
	if id != p.containerID {
		return nil, ""
	}
	return p.meta(), "app"
}

func (p fakePods) PodByUID(uid string) *ikube.CachedObjMeta {
	if uid != p.podUID {
		return nil
	}
	return p.meta()
}

func (p fakePods) meta() *ikube.CachedObjMeta {
	return &ikube.CachedObjMeta{Meta: &informer.ObjectMeta{
		Name: "db-0", Namespace: "prod", Kind: "Pod", Pod: &informer.PodInfo{
			Uid: p.podUID,
			Owners: []*informer.Owner{
				{Name: "db", Kind: "ReplicaSet"},
				{Name: "db", Kind: "StatefulSet"},
			},
		},
	}}
}

// cgroupTree makes a kubelet cgroup hierarchy (systemd driver, CRI-O) in a
// temporary directory and returns its root and the ids of the pod slice, the
// container scope and a system service.
func cgroupTree(tb testing.TB, podUID, containerID string) (root string, pod, container, system uint64) {
	tb.Helper()
	root = tb.TempDir()
	podDir := filepath.Join(root, "kubepods.slice", "kubepods-besteffort.slice",
		"kubepods-besteffort-pod"+strings.ReplaceAll(podUID, "-", "_")+".slice")
	containerDir := filepath.Join(podDir, "crio-"+containerID+".scope")
	systemDir := filepath.Join(root, "system.slice", "kubelet.service")
	for _, d := range []string{containerDir, systemDir} {
		require.NoError(tb, os.MkdirAll(d, 0o755))
	}
	ino := func(dir string) uint64 {
		info, err := os.Stat(dir)
		require.NoError(tb, err)
		return info.Sys().(*syscall.Stat_t).Ino
	}
	return root, ino(podDir), ino(containerDir), ino(systemDir)
}

// On a cgroup v2 host the pod and container come from the key's cgroup:
// every process of the container counts into one key and names it. A cgroup
// of no pod, and one the index does not know yet, leave the pod to the PID
// decorator; the latter asks to be decorated again.
func TestFsAccumCgroupAttribution(t *testing.T) {
	const podUID = "8c1d0a4e-7b1f-4a52-9d57-0c2f3b6a9e11"
	containerID := strings.Repeat("ab", 32)
	root, pod, container, system := cgroupTree(t, podUID, containerID)
	index := statagg.NewCgroupIndex(statagg.WithCgroupRoots(root))
	require.NoError(t, index.Scan())
	d := fsDecoder{cgroups: index, pods: fakePods{podUID: podUID, containerID: containerID}, sampleTgid: fsValSampleTgid}
	values := make([]byte, 152)

	for _, tc := range []struct {
		name  string
		cgid  uint64
		want  map[attr.Name]string
		final bool
	}{
		{"container", container, map[attr.Name]string{
			attr.K8sPodName: "db-0", attr.K8sNamespaceName: "prod", attr.K8sContainerName: "app",
			attr.K8sOwnerName: "db", attr.K8sKind: "StatefulSet",
		}, true},
		{"pod slice", pod, map[attr.Name]string{
			attr.K8sPodName: "db-0", attr.K8sNamespaceName: "prod",
			attr.K8sOwnerName: "db", attr.K8sKind: "StatefulSet",
		}, true},
		{"system service", system, nil, true},
		{"root", 1, nil, true},
		{"unknown cgroup", 999_999_999, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stat, final := d.stat(fsKey(tc.cgid, &ebpf.FsIo{Op: uint8(ebpf.CodeFsOpRead)}), values)
			assert.Equal(t, tc.want, stat.CommonAttrs.Metadata)
			assert.Equal(t, tc.final, final)
			if tc.want == nil {
				assert.Empty(t, stat.FsIo.PodUID)
				return
			}
			assert.Equal(t, podUID, stat.FsIo.PodUID, "a shared volume's host path is the pod's own")
		})
	}

	t.Run("container not in the store yet", func(t *testing.T) {
		d := d
		d.pods = fakePods{podUID: podUID}
		stat, final := d.stat(fsKey(container, &ebpf.FsIo{}), values)
		assert.Equal(t, "db-0", stat.CommonAttrs.Metadata[attr.K8sPodName], "its pod, by UID")
		assert.NotContains(t, stat.CommonAttrs.Metadata, attr.K8sContainerName)
		assert.False(t, final, "decorated again once the store knows the container")
	})

	t.Run("pod not in the store yet", func(t *testing.T) {
		d := d
		d.pods = fakePods{}
		stat, final := d.stat(fsKey(container, &ebpf.FsIo{}), values)
		assert.Nil(t, stat.CommonAttrs.Metadata)
		assert.False(t, final, "decorated again once the store knows the pod")
	})
}

// fsFamilyHarness runs a filesystem family on an in-memory map, exported by
// a Prometheus collector.
type fsFamilyHarness struct {
	m         *fsTestMap
	family    *statagg.Family
	collector *statagg.Collector
	decorated atomic.Int32
}

func newFsFamilyHarness(t *testing.T, cgroups *statagg.CgroupIndex) *fsFamilyHarness {
	t.Helper()
	h := &fsFamilyHarness{m: newFsTestMap(t, fsLayout(t))}
	family, err := NewFsAccumFamily(FsAccum{
		Source: h.m.m, Layout: h.m.layout, Cgroups: cgroups,
		Decorate: func(*ebpf.Stat) bool { h.decorated.Add(1); return true },
	})
	require.NoError(t, err)
	registry, err := statagg.NewRegistry(family)
	require.NoError(t, err)
	h.family = family
	h.collector = statagg.NewCollector(registry, time.Hour)
	fsOp, ok := ebpf.StatStringGetters(attr.FsOperation)
	require.True(t, ok)
	require.NoError(t, h.collector.Add(attributes.StatFsIO, statagg.PromMetric{
		LabelNames: []string{"fs_operation"},
		Project: func(s *ebpf.Stat) (string, []string) {
			v := []string{fsOp(s)}
			return statagg.SeriesKey(v), v
		},
	}))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go family.Run(ctx)
	return h
}

// collect scrapes the collector until it reports a total of want bytes.
func (h *fsFamilyHarness) collect(t *testing.T, want float64) {
	t.Helper()
	require.Eventually(t, func() bool {
		ch := make(chan prometheus.Metric, 10)
		h.collector.Collect(ch)
		close(ch)
		var total float64
		for m := range ch {
			var pb dto.Metric
			require.NoError(t, m.Write(&pb))
			total += pb.GetCounter().GetValue()
		}
		return total == want
	}, 5*time.Second, 10*time.Millisecond)
}

// A key is decorated when it first counts, not on every poll it counts in:
// the per-operation userspace cost is gone.
func TestFsAccumDecoratesOncePerKey(t *testing.T) {
	h := newFsFamilyHarness(t, nil)
	io := &ebpf.FsIo{Fs: uint8(ebpf.CodeFsExt4), Op: uint8(ebpf.CodeFsOpWrite), Bytes: 4096, LatencyNs: 1000}

	h.m.record(5, io)
	h.collect(t, 4096)
	for range 100 {
		h.m.record(5, io)
	}
	time.Sleep(statagg.DefaultMinPollInterval)
	h.collect(t, 101*4096)
	assert.Equal(t, int32(1), h.decorated.Load())
}

// The kernel key of a removed cgroup is not deleted while its tombstone
// lasts: its writeback keeps counting into it, and a key created again would
// have lost its pod. Keys of live cgroups, and every key on a cgroup v1 host,
// are deleted once idle.
func TestFsAccumKeepsTombstonedCgroupKeys(t *testing.T) {
	const podUID = "8c1d0a4e-7b1f-4a52-9d57-0c2f3b6a9e11"
	containerID := strings.Repeat("cd", 32)
	root, _, container, system := cgroupTree(t, podUID, containerID)
	index := statagg.NewCgroupIndex(statagg.WithCgroupRoots(root))
	require.NoError(t, index.Scan())
	require.NoError(t, os.RemoveAll(filepath.Join(root, "kubepods.slice")))
	require.NoError(t, index.Scan())

	deletable := fsDeletable(index)
	assert.False(t, deletable(fsKey(container, &ebpf.FsIo{})), "removed container, tombstoned")
	assert.True(t, deletable(fsKey(system, &ebpf.FsIo{})), "live cgroup")
	assert.Nil(t, fsDeletable(nil), "cgroup v1: every idle key")
}

// endingPods is a Kubernetes store of one pod that completes: the store then
// deletes it.
type endingPods struct {
	fakePods
	gone atomic.Bool
}

func (p *endingPods) PodContainerByContainerID(id string) (*ikube.CachedObjMeta, string) {
	if p.gone.Load() {
		return nil, ""
	}
	return p.fakePods.PodContainerByContainerID(id)
}

func (p *endingPods) PodByUID(uid string) *ikube.CachedObjMeta {
	if p.gone.Load() {
		return nil
	}
	return p.fakePods.PodByUID(uid)
}

// A pod shorter than the gap between scrapes and background scans (the lab's
// verify-paths Job, about 15 s): the new-key check has the cgroup index learn
// its cgroup and decorates its key while it runs, so what it did is the
// pod's even though, by the first scrape, its cgroup is removed and the
// store has deleted it.
func TestFsAccumAttributesAShortLivedPod(t *testing.T) {
	const podUID = "3f0c6a2e-5d1b-4c8e-a7f9-1b2d3e4f5a6b"
	containerID := strings.Repeat("ef", 32)
	root, _, container, _ := cgroupTree(t, podUID, containerID)
	// The pod started after the last background scan: the index has not
	// seen its cgroup.
	index := statagg.NewCgroupIndex(statagg.WithCgroupRoots(root))
	store := &endingPods{fakePods: fakePods{podUID: podUID, containerID: containerID}}
	m := newFsTestMap(t, fsLayout(t))
	var decorated atomic.Int32
	config, err := fsFamilyConfig(FsAccum{
		Source: m.m, Layout: m.layout, Cgroups: index, Pods: statagg.NewPodMemory(store, 0, nil),
		Decorate: func(*ebpf.Stat) bool { decorated.Add(1); return true },
	})
	require.NoError(t, err)
	config.NewKeyInterval = 10 * time.Millisecond
	config.MinPollInterval = time.Nanosecond
	family, err := statagg.NewFamily(config)
	require.NoError(t, err)
	registry, err := statagg.NewRegistry(family)
	require.NoError(t, err)
	collector := statagg.NewCollector(registry, time.Hour)
	require.NoError(t, collector.Add(attributes.StatFsIO, statagg.PromMetric{
		LabelNames: []string{"k8s_pod_name", "k8s_container_name"},
		Project: func(s *ebpf.Stat) (string, []string) {
			v := []string{s.CommonAttrs.Metadata[attr.K8sPodName], s.CommonAttrs.Metadata[attr.K8sContainerName]}
			return statagg.SeriesKey(v), v
		},
	}))
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	go family.Run(ctx)

	io := &ebpf.FsIo{Fs: uint8(ebpf.CodeFsXFS), Op: uint8(ebpf.CodeFsOpWrite), Bytes: 4096, LatencyNs: 1000}
	m.record(container, io)
	require.Eventually(t, func() bool { return decorated.Load() == 1 }, 5*time.Second, 5*time.Millisecond)

	// The Job completes: its cgroup goes, the store deletes the pod.
	m.record(container, io)
	require.NoError(t, os.RemoveAll(filepath.Join(root, "kubepods.slice")))
	require.NoError(t, index.Scan())
	store.gone.Store(true)

	ch := make(chan prometheus.Metric, 10)
	collector.Collect(ch)
	close(ch)
	got := map[string]float64{}
	for metric := range ch {
		var pb dto.Metric
		require.NoError(t, metric.Write(&pb))
		var labels []string
		for _, l := range pb.GetLabel() {
			labels = append(labels, l.GetName()+"="+l.GetValue())
		}
		got[strings.Join(labels, " ")] = pb.GetCounter().GetValue()
	}
	assert.Equal(t, map[string]float64{"k8s_container_name=app k8s_pod_name=db-0": 2 * 4096}, got)
}
