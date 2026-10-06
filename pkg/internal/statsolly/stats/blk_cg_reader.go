// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"encoding/binary"
	"time"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

// The key of blk_cg_agg (struct blk_cg_key in bpf/statsolly/blk_helpers.h),
// located through its bpf2go type.
var (
	cgKeySize    = int(unsafe.Sizeof(ebpf.StatsBlkCgKey{}))
	cgKeyCgid    = int(unsafe.Offsetof(ebpf.StatsBlkCgKey{}.Cgid))
	cgKeyDev     = int(unsafe.Offsetof(ebpf.StatsBlkCgKey{}.Dev))
	cgKeyPartDev = int(unsafe.Offsetof(ebpf.StatsBlkCgKey{}.PartDev))
	cgKeyKind    = int(unsafe.Offsetof(ebpf.StatsBlkCgKey{}.Kind))
)

// The counting words of blk_cg_agg's value (struct blk_cg_val in
// maps/blk_cg_agg.h): three u64 counters.
const (
	cgWordCount = iota
	cgWordBytes
	cgWordTimeNs
	cgCounters
)

// BlockCgroupFamily reads blk_cg_agg, the reads and writes counted per
// cgroup they were charged to, device and direction (storage_block_pod),
// into obi.stat.disk.operations and obi.stat.disk.operation_time and, with
// storage_block_io, obi.stat.disk.io, which BlockFamilies then leaves out.
// pods gives each cgroup its pod attributes and says how long its keys must
// stay in the kernel map; decorate is the pipeline's decoration and filters.
func BlockCgroupFamily(src statagg.Source, features export.Features, pods *BlockPodResolver,
	decorate func(*ebpf.Stat) bool,
) (*statagg.Family, error) {
	return blockCgroupFamily(src, features, pods, decorate, time.Now)
}

func blockCgroupFamily(src statagg.Source, features export.Features, pods *BlockPodResolver,
	decorate func(*ebpf.Stat) bool, clock func() time.Time,
) (*statagg.Family, error) {
	word := func(w int) func(statagg.Delta) uint64 {
		return func(d statagg.Delta) uint64 { return d.Counter(w) }
	}
	var metrics []*statagg.Metric
	if features.StorageBlockPod() {
		metrics = append(metrics,
			&statagg.Metric{Name: attributes.StatDiskOperations, Kind: statagg.KindCounter, Value: word(cgWordCount)},
			&statagg.Metric{Name: attributes.StatDiskOperationTime, Kind: statagg.KindDurationCounter, Value: word(cgWordTimeNs)},
		)
	}
	if features.StorageBlockIo() {
		metrics = append(metrics,
			&statagg.Metric{Name: attributes.StatDiskIO, Kind: statagg.KindCounter, Value: word(cgWordBytes)})
	}
	return statagg.NewFamily(statagg.Config{
		Name:      "blk_cg_agg",
		Source:    src,
		Layout:    statagg.ValueLayout{Counters: cgCounters, Monotonic: true},
		Stat:      pods.stat,
		Decorate:  decorate,
		Deletable: pods.deletable,
		Metrics:   metrics,
		Clock:     clock,
	})
}

// cgroupIndex is what BlockPodResolver needs of statagg.CgroupIndex.
type cgroupIndex interface {
	Lookup(id uint64) (statagg.CgroupIdentity, bool)
	Tombstoned(id uint64) bool
}

// podLabels are the Kubernetes attributes of the I/O charged to one cgroup.
type podLabels struct {
	namespace, pod, container, owner, kind string
	// resolved is when the store last named the pod.
	resolved time.Time
}

// BlockPodResolver gives the cgroups that blk_cg_agg counts for their pod
// attributes: the cgroup index maps a cgroup id to the pod UID and container
// ID its path names, at every level under kubepods (container leaf and
// scope, conmon scope, pod and QoS slices: S0-d), and the Kubernetes store
// maps those to names. Only the family of blk_cg_agg uses it, under its
// lock.
//
// A pod's labels are kept for its cgroup for statagg.DefaultCgroupTombstoneTTL
// after the store last named the pod: writeback keeps charging a deleted
// pod's files to its cgroup after the store has forgotten the pod (S0-d saw a
// removed cgroup's id on new I/O for 9 s), and that I/O is still the pod's.
type BlockPodResolver struct {
	// index and store are nil without Kubernetes metadata: no cgroup has a
	// pod then.
	index cgroupIndex
	store statagg.PodStore
	clock func() time.Time
	keep  time.Duration

	known     map[uint64]*podLabels
	lastSweep time.Time
}

// NewBlockPodResolver resolves cgroups through index and store; with either
// nil, every cgroup is without a pod.
func NewBlockPodResolver(index *statagg.CgroupIndex, store statagg.PodStore) *BlockPodResolver {
	r := &BlockPodResolver{store: store, clock: time.Now, keep: statagg.DefaultCgroupTombstoneTTL, known: map[uint64]*podLabels{}}
	if index != nil {
		r.index = index
	}
	return r
}

// stat is the Stat of a blk_cg_agg key: its device, partition and direction,
// and the pod attributes of its cgroup. final is false while the cgroup
// should be resolved again: its id is not indexed yet, its pod is not in the
// store yet, or its container is not, while the cgroup is alive.
func (r *BlockPodResolver) stat(key, _ []byte) (*ebpf.Stat, bool) {
	if len(key) < cgKeySize {
		return nil, true
	}
	stat := &ebpf.Stat{Type: ebpf.StatTypeBlockIo, BlockIo: &ebpf.BlockIo{
		Dev:     binary.NativeEndian.Uint32(key[cgKeyDev:]),
		PartDev: binary.NativeEndian.Uint32(key[cgKeyPartDev:]),
		Op:      key[cgKeyKind],
	}}
	labels, final := r.resolve(binary.NativeEndian.Uint64(key[cgKeyCgid:]))
	if labels != nil {
		setPodLabels(stat, labels)
	}
	return stat, final
}

// deletable reports whether an idle key may leave the kernel map: not while
// its cgroup is a removed pod cgroup whose tombstone lasts, or the next
// writeback charged to it would create the key again, unresolved.
func (r *BlockPodResolver) deletable(key []byte) bool {
	if r.index == nil || len(key) < cgKeySize {
		return true
	}
	return !r.index.Tombstoned(binary.NativeEndian.Uint64(key[cgKeyCgid:]))
}

func (r *BlockPodResolver) resolve(cgid uint64) (*podLabels, bool) {
	if r.index == nil || r.store == nil {
		return nil, true
	}
	now := r.clock()
	r.sweep(now)

	id, indexed := r.index.Lookup(cgid)
	if !indexed {
		return r.known[cgid], false
	}
	if id.PodUID == "" && id.ContainerID == "" {
		return nil, true
	}
	meta, container := statagg.ResolvePod(r.store, id)
	if meta == nil || meta.Meta == nil {
		// Not in the store yet, or no longer: a deleted pod whose cgroup
		// still takes writeback keeps the labels it had.
		return r.known[cgid], r.index.Tombstoned(cgid)
	}
	labels := podLabelsOf(meta, container, now)
	r.known[cgid] = labels
	complete := id.ContainerID == "" || container != ""
	return labels, complete || r.index.Tombstoned(cgid)
}

// sweep forgets, at most once a minute, the labels of cgroups whose pod the
// store has not named for longer than keep.
func (r *BlockPodResolver) sweep(now time.Time) {
	if now.Sub(r.lastSweep) < time.Minute {
		return
	}
	r.lastSweep = now
	for cgid, l := range r.known {
		if now.Sub(l.resolved) > r.keep {
			delete(r.known, cgid)
		}
	}
}

// podLabelsOf names the pod of meta, and its owner as the network decorator
// does: the top owner (the Deployment of a ReplicaSet), else the pod itself.
func podLabelsOf(meta *ikube.CachedObjMeta, container string, now time.Time) *podLabels {
	l := &podLabels{
		namespace: meta.Meta.Namespace, pod: meta.Meta.Name, container: container,
		owner: meta.Meta.Name, kind: meta.Meta.Kind, resolved: now,
	}
	if owner := ikube.TopOwner(meta.Meta.Pod); owner != nil {
		l.owner, l.kind = owner.Name, owner.Kind
	}
	return l
}

func setPodLabels(stat *ebpf.Stat, l *podLabels) {
	m := map[attr.Name]string{
		attr.K8sNamespaceName: l.namespace,
		attr.K8sPodName:       l.pod,
		attr.K8sOwnerName:     l.owner,
		attr.K8sKind:          l.kind,
	}
	if l.container != "" {
		m[attr.K8sContainerName] = l.container
	}
	stat.CommonAttrs.Metadata = m
}
