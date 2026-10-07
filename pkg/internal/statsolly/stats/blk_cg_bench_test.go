// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

// The userspace cost of the pod counters (storage_block_pod): one Prometheus
// scrape of operations, operation_time and disk.io with the default pod
// attributes, reading blk_cg_agg. keys is what the map holds: 2730 is what
// the 8 MiB budget holds at 128 CPUs; 9000 is spec section 5's 250 pods x 3
// cgroups x 6 devices x 2 directions, which fits at 4 CPUs. "changed" counts
// every key on every CPU since the previous scrape, the worst case; "steady"
// a tenth of them, a node where most cgroups are idle between scrapes. The
// cost does not grow with the request rate.
func BenchmarkBlockCgroupFamily_Scrape(b *testing.B) {
	for _, c := range []struct {
		keys, cpus int
	}{{2730, 128}, {9000, 4}} {
		for _, changed := range []int{1, 10} {
			name := "keys=" + strconv.Itoa(c.keys) + "/cpus=" + strconv.Itoa(c.cpus) + "/changed=1of" + strconv.Itoa(changed)
			b.Run(name, func(b *testing.B) {
				cb := newCgroupBench(b, c.keys, c.cpus)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					b.StopTimer()
					cb.count(changed)
					b.StartTimer()
					cb.scrape()
				}
			})
		}
	}
}

type cgroupBench struct {
	b    *testing.B
	m    *stataggtest.MemMap
	now  time.Time
	reg  *prometheus.Registry
	keys [][]byte
	cpus int
	turn int
}

func newCgroupBench(b *testing.B, keys, cpus int) *cgroupBench {
	b.Helper()
	cb := &cgroupBench{
		b:    b,
		m:    stataggtest.NewMemMap(cgKeySize, int(unsafe.Sizeof(ebpf.StatsBlkCgVal{})), cpus),
		now:  time.Unix(1_700_000_000, 0),
		cpus: cpus,
	}

	// Pods of 3 cgroups each (a container leaf, its scope and the conmon
	// scope), on 6 devices, in both directions.
	index := &fakeIndex{ids: map[uint64]statagg.CgroupIdentity{}, tombstoned: map[uint64]bool{}}
	store := &fakeStore{
		byContainer: map[string]*ikube.CachedObjMeta{}, containers: map[string]string{},
		byUID: map[string]*ikube.CachedObjMeta{},
	}
	for i := 0; len(cb.keys) < keys; i++ {
		cgid := uint64(10_000 + i)
		pod := i / 3
		uid, ctr := "pod-"+strconv.Itoa(pod), "ctr-"+strconv.Itoa(pod)
		if i%3 == 2 {
			index.ids[cgid] = statagg.CgroupIdentity{PodUID: uid}
		} else {
			index.ids[cgid] = statagg.CgroupIdentity{PodUID: uid, ContainerID: ctr}
		}
		meta := &ikube.CachedObjMeta{Meta: &informer.ObjectMeta{
			Name: "workload-" + strconv.Itoa(pod), Namespace: "ns-" + strconv.Itoa(pod%20), Kind: "Pod",
			Pod: &informer.PodInfo{Uid: uid, Owners: []*informer.Owner{{Kind: "Deployment", Name: "workload"}}},
		}}
		store.byUID[uid], store.byContainer[ctr], store.containers[ctr] = meta, meta, "main"
		for d := range uint32(6) {
			for _, dir := range []ebpf.BlockOpCode{ebpf.CodeBlockRead, ebpf.CodeBlockWrite} {
				cb.keys = append(cb.keys, cgKey(cgid, 253<<20|d*16, 0, dir))
			}
		}
	}
	cb.keys = cb.keys[:keys]
	pods := &BlockPodResolver{
		index: index, store: store, clock: func() time.Time { return cb.now },
		keep: statagg.DefaultCgroupTombstoneTTL, known: map[uint64]*podLabels{},
	}

	features := export.FeatureStorageBlockPod | export.FeatureStorageBlockIo
	family, err := blockCgroupFamily(cb.m, features, pods, func(*ebpf.Stat) bool { return true },
		func() time.Time { return cb.now })
	require.NoError(b, err)
	registry, err := statagg.NewRegistry(family)
	require.NoError(b, err)
	selector, err := attributes.NewAttrSelector(attributes.GroupKubernetes|attributes.GroupStatsBlockPod, &attributes.SelectorConfig{})
	require.NoError(b, err)
	collector := statagg.NewCollector(registry, time.Hour)
	for _, m := range []attributes.Name{attributes.StatDiskOperations, attributes.StatDiskOperationTime, attributes.StatDiskIO} {
		getters := attributes.PrometheusGetters(ebpf.StatStringGetters, selector.For(m))
		names := make([]string, len(getters))
		for i, g := range getters {
			names[i] = g.ExposedName
		}
		require.NoError(b, collector.Add(m, statagg.PromMetric{
			Help: "h", LabelNames: names,
			Project: func(s *ebpf.Stat) (string, []string) {
				v := make([]string, len(getters))
				for i, g := range getters {
					v[i] = g.Get(s)
				}
				return statagg.SeriesKey(v), v
			},
		}))
	}
	cb.reg = prometheus.NewRegistry()
	require.NoError(b, cb.reg.Register(collector))
	go family.Run(b.Context())
	cb.count(1)
	require.Eventually(b, func() bool {
		cb.now = cb.now.Add(time.Second)
		mfs, err := cb.reg.Gather()
		return err == nil && len(mfs) > 0
	}, 5*time.Second, 10*time.Millisecond)
	return cb
}

// count adds a completion on every CPU to one key in every.
func (cb *cgroupBench) count(every int) {
	cb.turn++
	for i, k := range cb.keys {
		if (i+cb.turn)%every != 0 {
			continue
		}
		for cpu := range cb.cpus {
			cb.m.AddU64(k, cpu, cgWordCount*8, 1)
			cb.m.AddU64(k, cpu, cgWordBytes*8, 4096)
			cb.m.AddU64(k, cpu, cgWordTimeNs*8, 150_000)
		}
	}
}

// scrape is one Prometheus scrape 15 s after the previous one, which reads
// the map.
func (cb *cgroupBench) scrape() {
	cb.now = cb.now.Add(15 * time.Second)
	if _, err := cb.reg.Gather(); err != nil {
		cb.b.Fatal(err)
	}
}
