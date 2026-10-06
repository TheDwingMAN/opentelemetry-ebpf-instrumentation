// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"encoding/binary"
	"errors"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

// The filesystem aggregation map, fs_io_accum (fs_io_accum_exp), as
// bpf/statsolly/fs_io.h lays it out: offsets taken from the bpf2go types, so
// they follow the C structs.
var (
	fsKeyCgid    = int(unsafe.Offsetof(ebpf.FsIoFsIoAccumKey{}.Cgid))
	fsKeyRootIno = int(unsafe.Offsetof(ebpf.FsIoFsIoAccumKey{}.RootIno))
	fsKeySDev    = int(unsafe.Offsetof(ebpf.FsIoFsIoAccumKey{}.S_dev))
	fsKeyPidNs   = int(unsafe.Offsetof(ebpf.FsIoFsIoAccumKey{}.PidNs))
	fsKeyFs      = int(unsafe.Offsetof(ebpf.FsIoFsIoAccumKey{}.Fs))
	fsKeyOp      = int(unsafe.Offsetof(ebpf.FsIoFsIoAccumKey{}.Op))
	fsKeyErr     = int(unsafe.Offsetof(ebpf.FsIoFsIoAccumKey{}.Err))
	fsKeySize    = int(unsafe.Sizeof(ebpf.FsIoFsIoAccumKey{}))

	fsValSampleTgid    = int(unsafe.Offsetof(ebpf.FsIoFsIoAccumVal{}.SampleTgid))
	fsExpValSampleTgid = int(unsafe.Offsetof(ebpf.FsIoFsIoAccumExpVal{}.SampleTgid))
)

// The counting words of a value: two u64 sums, then the buckets.
const (
	fsWordSumNs = 0
	fsWordBytes = 1
	fsWords     = 2
)

// FsAccum is what the filesystem aggregation family needs besides the map.
type FsAccum struct {
	// Source is the kernel map the filesystem programs aggregate into.
	Source statagg.Source
	// Layout is the histogram layout the programs were loaded with.
	Layout *statagg.Layout
	// Decorate runs the stats pipeline's decorators and filters on a key's
	// stat (statagg.Config.Decorate).
	Decorate func(*ebpf.Stat) bool
	// Cgroups resolves the cgroup of a key to its pod and container. It is
	// nil on a cgroup v1 host, where every key's cgroup is the unified
	// root: those keys are decorated through their PID namespace and sample
	// process, as the per-event path decorates each operation.
	Cgroups *statagg.CgroupIndex
	// Pods is the Kubernetes metadata store; nil without Kubernetes, which
	// leaves every key without pod.
	Pods statagg.PodStore
}

// NewFsAccumFamily returns the statagg family of the filesystem metrics,
// read from the kernel's fs_io_accum map: the same three metrics, series and
// bucket counts the per-event exporters produce for the ring buffer events
// the programs would otherwise send.
func NewFsAccumFamily(cfg FsAccum) (*statagg.Family, error) {
	config, err := fsFamilyConfig(cfg)
	if err != nil {
		return nil, err
	}
	return statagg.NewFamily(config)
}

func fsFamilyConfig(cfg FsAccum) (statagg.Config, error) {
	if cfg.Source == nil || cfg.Layout == nil {
		return statagg.Config{}, errors.New("filesystem aggregation needs a map and a histogram layout")
	}
	if cfg.Source.KeySize() != fsKeySize {
		return statagg.Config{}, errors.New("filesystem aggregation map: unexpected key size")
	}
	buckets := cfg.Layout.Buckets()
	sampleTgid := fsValSampleTgid
	if cfg.Layout.Kind == statagg.LayoutExponential {
		sampleTgid = fsExpValSampleTgid
	}
	if cfg.Source.CPUs() != 1 || cfg.Source.ValueStride() < sampleTgid+4 {
		return statagg.Config{}, errors.New("filesystem aggregation map: unexpected value layout")
	}
	d := fsDecoder{cgroups: cfg.Cgroups, pods: cfg.Pods, sampleTgid: sampleTgid}

	return statagg.Config{
		Name:      "fs_io_accum",
		Source:    cfg.Source,
		Layout:    statagg.ValueLayout{Counters: fsWords, Buckets: buckets},
		Stat:      d.stat,
		Decorate:  cfg.Decorate,
		Deletable: fsDeletable(cfg.Cgroups),
		Metrics: []*statagg.Metric{
			{
				Name: attributes.StatFsOperationDuration, Kind: statagg.KindHistogram,
				SumWord: fsWordSumNs, BucketWord: fsWords, Layout: cfg.Layout,
			},
			{
				Name: attributes.StatFsIO, Kind: statagg.KindCounter, SkipZero: true,
				Value: func(d statagg.Delta) uint64 { return d.Counter(fsWordBytes) },
			},
			{
				Name: attributes.StatFsOperationErrors, Kind: statagg.KindCounter,
				Select: func(s *ebpf.Stat) bool { return s.FsIo.Error != 0 },
				Value:  func(d statagg.Delta) uint64 { return d.Sum(fsWords, buckets) },
			},
		},
	}, nil
}

// fsDeletable returns the statagg.Config.Deletable of the filesystem keys:
// a key whose cgroup is a tombstone is kept, since the writeback of the files
// it owned keeps counting into it after the container is gone.
func fsDeletable(cgroups *statagg.CgroupIndex) func([]byte) bool {
	if cgroups == nil {
		return nil
	}
	return func(key []byte) bool { return !cgroups.Tombstoned(fsKeyCgroup(key)) }
}

func fsKeyCgroup(key []byte) uint64 { return binary.NativeEndian.Uint64(key[fsKeyCgid:]) }

type fsDecoder struct {
	cgroups    *statagg.CgroupIndex
	pods       statagg.PodStore
	sampleTgid int
}

// stat returns the stat of a key as the per-event path would have seen each
// of its operations, but for the sums: the PID is a process that counted
// into the key lately. On a cgroup v2 host the pod and container come from
// the key's cgroup, and the PID decorator then only resolves the volume; a
// cgroup of no pod (the host's services, kernel threads) or one the index
// does not know yet leaves the pod to the PID decorator, as per event.
func (d *fsDecoder) stat(key, values []byte) (*ebpf.Stat, bool) {
	stat := &ebpf.Stat{
		Type: ebpf.StatTypeFsIo,
		FsIo: &ebpf.FsIo{
			Fs:      key[fsKeyFs],
			Op:      key[fsKeyOp],
			SDev:    binary.NativeEndian.Uint32(key[fsKeySDev:]),
			PidNs:   binary.NativeEndian.Uint32(key[fsKeyPidNs:]),
			HostPID: binary.NativeEndian.Uint32(values[d.sampleTgid:]),
			Error:   -int32(binary.NativeEndian.Uint16(key[fsKeyErr:])),
			RootIno: binary.NativeEndian.Uint64(key[fsKeyRootIno:]),
		},
	}
	if d.cgroups == nil {
		return stat, true
	}
	return stat, d.setPod(stat, fsKeyCgroup(key))
}

// setPod sets the pod and container of the cgroup cgid on stat, and reports
// false when they may still come: a cgroup the index does not know yet, or
// a pod the store does not know yet.
func (d *fsDecoder) setPod(stat *ebpf.Stat, cgid uint64) bool {
	identity, final := d.cgroups.Lookup(cgid)
	if identity.PodUID == "" && identity.ContainerID == "" {
		return final
	}
	if d.pods == nil {
		return final
	}
	meta, container := statagg.ResolvePod(d.pods, identity)
	if meta == nil {
		return false
	}
	stat.FsIo.PodUID = meta.Meta.GetPod().GetUid()
	// k8s.owner.name and k8s.kind follow the rule of the PID decorator,
	// which leaves a stat that comes with its pod alone.
	ownerName, ownerKind := meta.Meta.Name, meta.Meta.Kind
	if owner := ikube.TopOwner(meta.Meta.Pod); owner != nil {
		ownerName, ownerKind = owner.Name, owner.Kind
	}
	stat.CommonAttrs.Metadata = map[attr.Name]string{
		attr.K8sPodName:       meta.Meta.Name,
		attr.K8sNamespaceName: meta.Meta.Namespace,
		attr.K8sOwnerName:     ownerName,
		attr.K8sKind:          ownerKind,
	}
	if container != "" {
		stat.CommonAttrs.Metadata[attr.K8sContainerName] = container
	}
	return final
}
