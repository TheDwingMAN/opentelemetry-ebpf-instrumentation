// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/parity"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

// The words and key fields the family reads are where the kernel structs
// have them.
func TestBlockCgroupLayoutMatchesTheKernelStructs(t *testing.T) {
	const counter = int(unsafe.Sizeof(uint64(0)))
	v := ebpf.StatsBlkCgVal{}
	assert.Equal(t, cgWordCount*counter, int(unsafe.Offsetof(v.Count)))
	assert.Equal(t, cgWordBytes*counter, int(unsafe.Offsetof(v.Bytes)))
	assert.Equal(t, cgWordTimeNs*counter, int(unsafe.Offsetof(v.TimeNs)))
	assert.Equal(t, cgCounters*counter, int(unsafe.Sizeof(v)))
	assert.Equal(t, 24, cgKeySize)
}

// The pods of the S0-d lab (MicroShift, CRI-O with systemd cgroups): the
// writer's container leaf, its conmon scope, the pod slice, a node service
// and the root, which kernel threads such as jbd2 run in.
const (
	cgWriter  = 72286 // .../crio-<ID>.scope/container
	cgConmon  = 72132 // .../crio-conmon-<ID>.scope
	cgPodOnly = 71518 // .../kubepods-besteffort-pod<UID>.slice
	cgService = 3440  // system.slice/auditd.service
	cgRoot    = 1
	cgNew     = 99999 // not indexed yet
	podUID    = "e6576a15-9469-4c44-a03f-83cb6a89264b"
	ctrID     = "fdd59e28521f6a4f36b6e02bbdc0c589399331b28742775239f9a34400f3ad56"
)

type fakeIndex struct {
	ids        map[uint64]statagg.CgroupIdentity
	tombstoned map[uint64]bool
}

func (x *fakeIndex) Lookup(id uint64) (statagg.CgroupIdentity, bool) {
	if id <= 1 {
		return statagg.CgroupIdentity{}, true
	}
	identity, ok := x.ids[id]
	return identity, ok
}

func (x *fakeIndex) Tombstoned(id uint64) bool { return x.tombstoned[id] }

type fakeStore struct {
	byContainer map[string]*ikube.CachedObjMeta
	containers  map[string]string
	byUID       map[string]*ikube.CachedObjMeta
}

func (s *fakeStore) PodContainerByContainerID(id string) (*ikube.CachedObjMeta, string) {
	return s.byContainer[id], s.containers[id]
}

func (s *fakeStore) PodByUID(uid string) *ikube.CachedObjMeta { return s.byUID[uid] }

func ioXfsPod() *ikube.CachedObjMeta {
	return &ikube.CachedObjMeta{Meta: &informer.ObjectMeta{
		Name: "io-xfs-5f4b8c8447-6tcwr", Namespace: "default", Kind: "Pod",
		Pod: &informer.PodInfo{Uid: podUID, Owners: []*informer.Owner{
			{Kind: "ReplicaSet", Name: "io-xfs-5f4b8c8447"}, {Kind: "Deployment", Name: "io-xfs"},
		}},
	}}
}

func newPodFixture() (*fakeIndex, *fakeStore, *BlockPodResolver, *time.Time) {
	index := &fakeIndex{
		ids: map[uint64]statagg.CgroupIdentity{
			cgWriter:  {PodUID: podUID, ContainerID: ctrID},
			cgConmon:  {PodUID: podUID},
			cgPodOnly: {PodUID: podUID},
			cgService: {},
		},
		tombstoned: map[uint64]bool{},
	}
	pod := ioXfsPod()
	store := &fakeStore{
		byContainer: map[string]*ikube.CachedObjMeta{ctrID: pod},
		containers:  map[string]string{ctrID: "writer"},
		byUID:       map[string]*ikube.CachedObjMeta{podUID: pod},
	}
	now := time.Unix(1_700_000_000, 0)
	r := &BlockPodResolver{index: index, store: store, clock: func() time.Time { return now },
		keep: statagg.DefaultCgroupTombstoneTTL, known: map[uint64]*podLabels{}}
	return index, store, r, &now
}

func cgKey(cgid uint64, dev, partDev uint32, kind ebpf.BlockOpCode) []byte {
	k := make([]byte, cgKeySize)
	binary.NativeEndian.PutUint64(k[cgKeyCgid:], cgid)
	binary.NativeEndian.PutUint32(k[cgKeyDev:], dev)
	binary.NativeEndian.PutUint32(k[cgKeyPartDev:], partDev)
	k[cgKeyKind] = byte(kind)
	return k
}

const vdb = uint32(252<<20 | 16)

func TestBlockPodResolver(t *testing.T) {
	stat := func(t *testing.T, r *BlockPodResolver, cgid uint64) (map[attr.Name]string, bool) {
		t.Helper()
		s, final := r.stat(cgKey(cgid, vdb, 0, ebpf.CodeBlockWrite), nil)
		require.NotNil(t, s)
		assert.Equal(t, &ebpf.BlockIo{Dev: vdb, Op: uint8(ebpf.CodeBlockWrite)}, s.BlockIo)
		return s.CommonAttrs.Metadata, final
	}

	t.Run("container leaf", func(t *testing.T) {
		_, _, r, _ := newPodFixture()
		labels, final := stat(t, r, cgWriter)
		assert.True(t, final)
		assert.Equal(t, map[attr.Name]string{
			attr.K8sNamespaceName: "default", attr.K8sPodName: "io-xfs-5f4b8c8447-6tcwr",
			attr.K8sContainerName: "writer",
			attr.K8sOwnerName:     "io-xfs", attr.K8sKind: "Deployment",
		}, labels, "the owner is the top owner, as the network decorator names it")
	})
	t.Run("conmon scope and pod slice: pod only", func(t *testing.T) {
		_, _, r, _ := newPodFixture()
		for _, cgid := range []uint64{cgConmon, cgPodOnly} {
			labels, final := stat(t, r, cgid)
			assert.True(t, final)
			assert.Equal(t, "io-xfs-5f4b8c8447-6tcwr", labels[attr.K8sPodName])
			assert.NotContains(t, labels, attr.K8sContainerName)
		}
	})
	t.Run("a bare pod owns itself", func(t *testing.T) {
		_, store, r, _ := newPodFixture()
		bare := ioXfsPod()
		bare.Meta.Pod.Owners = nil
		store.byUID[podUID] = bare
		labels, _ := stat(t, r, cgConmon)
		assert.Equal(t, "io-xfs-5f4b8c8447-6tcwr", labels[attr.K8sOwnerName])
		assert.Equal(t, "Pod", labels[attr.K8sKind])
	})
	t.Run("no pod: node services and the root", func(t *testing.T) {
		_, _, r, _ := newPodFixture()
		for _, cgid := range []uint64{cgService, cgRoot, 0} {
			labels, final := stat(t, r, cgid)
			assert.True(t, final)
			assert.Empty(t, labels, "I/O charged to no pod has no pod attributes, never another pod's")
		}
	})
	t.Run("not indexed yet: decorated again later", func(t *testing.T) {
		index, _, r, _ := newPodFixture()
		labels, final := stat(t, r, cgNew)
		assert.False(t, final)
		assert.Empty(t, labels)

		index.ids[cgNew] = statagg.CgroupIdentity{PodUID: podUID}
		labels, final = stat(t, r, cgNew)
		assert.True(t, final)
		assert.Equal(t, "default", labels[attr.K8sNamespaceName])
	})
	t.Run("container not in the store yet: the pod now, the container later", func(t *testing.T) {
		index, store, r, _ := newPodFixture()
		delete(store.byContainer, ctrID)
		labels, final := stat(t, r, cgWriter)
		assert.False(t, final, "a live container is resolved again")
		assert.Equal(t, "io-xfs-5f4b8c8447-6tcwr", labels[attr.K8sPodName])
		assert.NotContains(t, labels, attr.K8sContainerName)

		index.tombstoned[cgWriter] = true
		_, final = stat(t, r, cgWriter)
		assert.True(t, final, "a removed container won't be named later")
	})
	t.Run("a deleted pod keeps its labels while its files are written back", func(t *testing.T) {
		index, store, r, now := newPodFixture()
		_, _ = stat(t, r, cgWriter)

		clear(store.byContainer)
		clear(store.byUID)
		index.tombstoned[cgWriter] = true
		*now = now.Add(5 * time.Minute)
		labels, final := stat(t, r, cgWriter)
		assert.True(t, final)
		assert.Equal(t, "writer", labels[attr.K8sContainerName], "S0-d: writeback after removal is the pod's")

		*now = now.Add(statagg.DefaultCgroupTombstoneTTL)
		labels, _ = stat(t, r, cgWriter)
		assert.Empty(t, labels, "forgotten with the tombstone")
	})
	t.Run("without Kubernetes metadata", func(t *testing.T) {
		r := NewBlockPodResolver(nil, nil)
		s, final := r.stat(cgKey(cgWriter, vdb, vdb|1, ebpf.CodeBlockRead), nil)
		assert.True(t, final)
		assert.Empty(t, s.CommonAttrs.Metadata)
		assert.Equal(t, vdb|1, s.BlockIo.PartDev)
		assert.True(t, r.deletable(cgKey(cgWriter, vdb, 0, ebpf.CodeBlockRead)))
	})
	t.Run("a short key counts for nothing", func(t *testing.T) {
		_, _, r, _ := newPodFixture()
		s, _ := r.stat([]byte{1, 2, 3}, nil)
		assert.Nil(t, s)
	})
}

// A key is deleted only once its cgroup's tombstone expired (spec 2.3): the
// next writeback charged to a removed pod's cgroup would otherwise create it
// again, unresolved.
func TestBlockPodResolver_KeysStayWhileTombstoned(t *testing.T) {
	index, _, r, _ := newPodFixture()
	key := cgKey(cgWriter, vdb, 0, ebpf.CodeBlockWrite)
	assert.True(t, r.deletable(key), "a live cgroup's idle key goes")
	index.tombstoned[cgWriter] = true
	assert.False(t, r.deletable(key))
	delete(index.tombstoned, cgWriter)
	assert.True(t, r.deletable(key), "the tombstone expired")
}

// The same through the family: an idle key of a tombstoned cgroup stays in
// the kernel map past the idle time, and goes once the tombstone expired.
func TestBlockCgroupFamily_IdleKeysWaitForTheTombstone(t *testing.T) {
	index, _, pods, _ := newPodFixture()
	m := stataggtest.NewMemMap(cgKeySize, int(unsafe.Sizeof(ebpf.StatsBlkCgVal{})), blockTestCPUs)
	clock := time.Unix(1_700_000_000, 0)
	f, err := blockCgroupFamily(m, export.FeatureStorageBlockPod, pods, nil, func() time.Time { return clock })
	require.NoError(t, err)
	reg, err := statagg.NewRegistry(f)
	require.NoError(t, err)
	c := statagg.NewCollector(reg, 0)
	require.NoError(t, c.Add(attributes.StatDiskOperations, statagg.PromMetric{
		Help: "ops", Project: func(*ebpf.Stat) (string, []string) { return "", nil },
	}))
	go f.Run(t.Context())

	live, removed := cgKey(cgService, vdb, 0, ebpf.CodeBlockRead), cgKey(cgWriter, vdb, 0, ebpf.CodeBlockWrite)
	m.AddU64(live, 0, cgWordCount*8, 1)
	m.AddU64(removed, 0, cgWordCount*8, 1)
	index.tombstoned[cgWriter] = true
	scrape := func() { promScrape(t, c) }
	scrape()

	clock = clock.Add(2*statagg.DefaultTickInterval + time.Second)
	scrape()
	assert.Equal(t, 1, m.Len(), "the tombstoned cgroup's key stays, the other idle one is deleted")

	delete(index.tombstoned, cgWriter)
	clock = clock.Add(time.Second)
	scrape()
	assert.Zero(t, m.Len())
}

func promScrape(t *testing.T, cs ...prometheus.Collector) string {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(cs...)
	mfs, err := reg.Gather()
	require.NoError(t, err)
	var sb strings.Builder
	for _, mf := range mfs {
		_, err := expfmt.MetricFamilyToText(&sb, mf)
		require.NoError(t, err)
	}
	return sb.String()
}

// podKernel is blk_cg_agg in memory, recording each completion as
// blk_cg_count does: a count, its bytes and its operation time (from the
// accounting start when the request has one) under its cgroup, device,
// partition and direction. Other kinds are not counted.
type podKernel struct {
	m *stataggtest.MemMap
	n int
}

func (k *podKernel) record(cgid uint64, s *ebpf.Stat) {
	io := s.BlockIo
	if !io.IsReadWrite() {
		return
	}
	key := cgKey(cgid, io.Dev, io.PartDev, ebpf.BlockOpCode(io.Op))
	cpu := k.n % blockTestCPUs
	k.n++
	k.m.AddU64(key, cpu, cgWordCount*8, 1)
	k.m.AddU64(key, cpu, cgWordBytes*8, io.Bytes)
	k.m.AddU64(key, cpu, cgWordTimeNs*8, io.LatencyNs+io.QueueNs)
}

// cgroupOf spreads events over the S0-d cgroups, the root and id 0.
func cgroupOf(i int) uint64 {
	return []uint64{cgWriter, cgConmon, cgPodOnly, cgService, cgRoot, 0}[i%6]
}

// Parity (aggregated == per-event): obi.stat.disk.io counted per cgroup and
// exported without pod attributes is the node-level series the per-event
// path exports, whatever cgroups the bytes were charged to, partitions
// selected or not.
func TestBlockCgroupParity_DiskIOPerCgroupIsTheNodeSeries(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)
	events := parity.BlockEvents(3000, layout.BoundsNs, false)
	for name, selection := range map[string]attributes.Selection{
		"default attributes": nil,
		"partition selected": {attributes.StatDiskIO.Section: attributes.InclusionLists{Include: []string{"*"}}},
	} {
		t.Run(name, func(t *testing.T) {
			parity.Run(t, parity.Setup{
				Features: export.FeatureStorageBlockIo, OTelBuckets: export.DefaultBuckets, PromBuckets: export.DefaultBuckets,
				Selection: selection,
			}, events, func(decorate func(*ebpf.Stat) bool) parity.Kernel {
				_, _, pods, _ := newPodFixture()
				k := &podKernel{m: stataggtest.NewMemMap(cgKeySize, int(unsafe.Sizeof(ebpf.StatsBlkCgVal{})), blockTestCPUs)}
				f, err := BlockCgroupFamily(k.m, export.FeatureStorageBlockIo, pods, decorate)
				require.NoError(t, err)
				reg, err := statagg.NewRegistry(f)
				require.NoError(t, err)
				i := 0
				return parity.Kernel{Registry: reg, Families: []*statagg.Family{f}, Record: func(s *ebpf.Stat) {
					k.record(cgroupOf(i), s)
					i++
				}}
			})
		})
	}
}

// With the pod attributes: one series per pod, device and direction, plus a
// series without pod attributes for the I/O charged to no pod (services,
// the root, id 0), which together add up to the node-level counts.
// operations counts the reads and writes, operation_time their time from
// the accounting start (or the issue), disk.io their bytes.
func TestBlockCgroupFamily_PodSeriesAddUpToTheNode(t *testing.T) {
	_, _, pods, _ := newPodFixture()
	k := &podKernel{m: stataggtest.NewMemMap(cgKeySize, int(unsafe.Sizeof(ebpf.StatsBlkCgVal{})), blockTestCPUs)}
	f, err := BlockCgroupFamily(k.m, export.FeatureStorageBlockPod|export.FeatureStorageBlockIo, pods, nil)
	require.NoError(t, err)
	reg, err := statagg.NewRegistry(f)
	require.NoError(t, err)
	for _, m := range []attributes.Name{attributes.StatDiskOperations, attributes.StatDiskOperationTime, attributes.StatDiskIO} {
		assert.True(t, reg.Handles(m), m.OTEL)
	}

	selector, err := attributes.NewAttrSelector(attributes.GroupKubernetes|attributes.GroupStatsBlockPod, &attributes.SelectorConfig{})
	require.NoError(t, err)
	c := statagg.NewCollector(reg, 0)
	for _, m := range []attributes.Name{attributes.StatDiskOperations, attributes.StatDiskOperationTime, attributes.StatDiskIO} {
		getters := attributes.PrometheusGetters(ebpf.StatStringGetters, selector.For(m))
		names := make([]string, len(getters))
		for i, g := range getters {
			names[i] = g.ExposedName
		}
		require.NoError(t, c.Add(m, statagg.PromMetric{
			Help: "test", LabelNames: names,
			Project: func(s *ebpf.Stat) (string, []string) {
				v := make([]string, len(getters))
				for i, g := range getters {
					v[i] = g.Get(s)
				}
				return statagg.SeriesKey(v), v
			},
		}))
	}
	go f.Run(t.Context())

	var reads, readBytes, readTimeNs uint64
	for i := range 600 {
		s := &ebpf.Stat{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{
			Dev: vdb, Op: uint8(ebpf.CodeBlockRead), Bytes: 4096, LatencyNs: 100_000, QueueNs: uint64(i % 2 * 5_000),
		}}
		k.record(cgroupOf(i), s)
		reads++
		readBytes += 4096
		readTimeNs += 100_000 + uint64(i%2*5_000)
	}
	k.record(cgService, &ebpf.Stat{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{Dev: vdb, Op: uint8(ebpf.CodeBlockFlush)}})

	text := promScrape(t, c)
	var opsSum, bytesSum float64
	var timeSum float64
	var podSeries, remainder int
	for _, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		require.NoError(t, err)
		switch {
		case strings.HasPrefix(line, "obi_stat_disk_operations_total"):
			opsSum += v
			if strings.Contains(line, `k8s_pod_name="io-xfs-5f4b8c8447-6tcwr"`) {
				podSeries++
				assert.Contains(t, line, `k8s_owner_name="io-xfs"`)
				assert.Contains(t, line, `k8s_namespace_name="default"`)
			} else {
				remainder++
				assert.NotContains(t, line, "k8s_pod_name=\"io", "no pod: no pod attributes")
			}
		case strings.HasPrefix(line, "obi_stat_disk_operation_time_seconds_total"):
			timeSum += v
		case strings.HasPrefix(line, "obi_stat_disk_io_bytes_total"):
			bytesSum += v
		}
	}
	assert.Equal(t, 1, podSeries, "the pod's container, conmon and slice cgroups are one series by default")
	assert.Equal(t, 1, remainder, "services, the root and id 0 are one series without pod attributes")
	assert.InDelta(t, float64(reads), opsSum, 0, "flushes are not counted")
	assert.InDelta(t, float64(readBytes), bytesSum, 0)
	assert.InDelta(t, time.Duration(readTimeNs).Seconds(), timeSum, 1e-9)
}
