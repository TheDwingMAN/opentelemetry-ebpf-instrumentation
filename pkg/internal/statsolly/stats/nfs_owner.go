// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/kube"
)

// NewNFSOwnerDecorator returns what to do to an NFS RPC stat to attribute it
// to its submitting pod (step 19): resolve NFSRPC.Owner through index on a
// cgroup v2 host, or through the pid path when cgroupV1, and set the pod
// trio and k8s.owner.name in CommonAttrs.Metadata. It is nil without a
// store: nothing to resolve an owner against. A stat with no owner (not a
// pod attribute selected, or the kernel could not read one) is left alone.
func NewNFSOwnerDecorator(store *kube.Store, index *statagg.CgroupIndex, cgroupV1 bool) func(*ebpf.Stat) {
	if store == nil {
		return nil
	}
	resolve := nfsOwnerResolver(store, index, cgroupV1)
	return func(s *ebpf.Stat) {
		if s.NFSRPC == nil || s.NFSRPC.Owner == 0 {
			return
		}
		meta, containerName, pending := resolve(s.NFSRPC.Owner)
		s.NFSRPC.OwnerPending = pending
		if meta == nil {
			return
		}
		setNFSOwnerMetadata(&s.CommonAttrs, meta, containerName)
	}
}

// nfsOwnerResolver returns the owner -> (pod, container, pending) function
// for the host's cgroup mode: the cgroup index on cgroup v2, the pid path on
// v1. pending means the answer may change: the index has not scanned the
// cgroup yet, or it names a container or pod the Store does not know yet.
func nfsOwnerResolver(store *kube.Store, index *statagg.CgroupIndex, cgroupV1 bool) func(uint64) (*ikube.CachedObjMeta, string, bool) {
	if cgroupV1 {
		return func(owner uint64) (*ikube.CachedObjMeta, string, bool) { return nfsOwnerByPID(store, owner) }
	}
	return func(owner uint64) (*ikube.CachedObjMeta, string, bool) {
		if index == nil {
			return nil, "", false
		}
		identity, final := index.Lookup(owner)
		meta, name := statagg.ResolvePod(store, identity)
		// An identity the Store cannot resolve yet is retried too: a pod
		// seen by the index before the informer delivers it. A cgroup that
		// is no pod at all (empty identity) is final.
		unresolved := meta == nil && (identity.ContainerID != "" || identity.PodUID != "")
		return meta, name, !final || unresolved
	}
}

// nfsOwnerByPID resolves a cgroup v1 owner (task->tk_owner, a host tgid) to
// its pod and container from /proc/<tgid>/cgroup, the same source the PID
// decorator reads for a process the Store does not track. A process that has
// already exited resolves to nothing: cgroup v1 keeps no equivalent of the
// cgroup v2 side map's "survives the process's exit" property (2.5).
func nfsOwnerByPID(store *kube.Store, tgid uint64) (*ikube.CachedObjMeta, string, bool) {
	info, err := kube.InfoForPID(app.PID(tgid))
	if err != nil || info.ContainerID == "" {
		return nil, "", false
	}
	meta, name := store.PodContainerByContainerID(info.ContainerID)
	// A container the Store does not know yet may arrive.
	return meta, name, meta == nil
}

// setNFSOwnerMetadata sets the pod trio and k8s.owner.name from meta, the
// same fields and TopOwner rule the k8s.MetadataDecorator uses for src/dst
// endpoints (pkg/internal/pipe/transform/k8s/kubernetes.go).
func setNFSOwnerMetadata(a *pipe.CommonAttrs, meta *ikube.CachedObjMeta, containerName string) {
	if a.Metadata == nil {
		a.Metadata = map[attr.Name]string{}
	}
	a.Metadata[attr.K8sNamespaceName] = meta.Meta.Namespace
	a.Metadata[attr.K8sPodName] = meta.Meta.Name
	if containerName != "" {
		a.Metadata[attr.K8sContainerName] = containerName
	}
	ownerName := meta.Meta.Name
	if owner := ikube.TopOwner(meta.Meta.Pod); owner != nil {
		ownerName = owner.Name
	}
	a.Metadata[attr.K8sOwnerName] = ownerName
}
