// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s // import "go.opentelemetry.io/obi/pkg/internal/pipe/transform/k8s"

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// resolveMount is an injectable indirection over ebpf.ResolveMount, so tests
// can exercise pidDecorator without a real /proc/self/mountinfo.
var resolveMount = ebpf.ResolveMount

func pidLog() *slog.Logger { return slog.With("component", "k8s.PIDMetadataDecorator") }

// The container of a process the Store does not track is read from
// /proc/<pid>/cgroup and remembered per host PID. The TTL bounds two things at
// once: how often that file is read for a long-lived process, and how long a
// recycled PID can be attributed to the process that held it before.
const (
	untrackedPIDCacheSize = 4096
	untrackedPIDCacheTTL  = 30 * time.Second
)

// PIDMetadataDecoratorProvider attributes items to their Kubernetes pod,
// namespace, container, and persistent volume/claim, using the PID triple and
// filesystem superblock device number returned by pidOf.
func PIDMetadataDecoratorProvider[T any](
	store *kube.Store,
	attrs func(T) *pipe.CommonAttrs,
	pidOf func(item T) (pidNs, hostPID, sDev uint32, ok bool),
	pvc ebpf.PVCLookup,
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if store == nil {
			return swarm.Bypass(input, output)
		}

		dec := &pidDecorator{
			store:      store,
			pvc:        pvc,
			containers: expirable.NewLRU[app.PID, string](untrackedPIDCacheSize, nil, untrackedPIDCacheTTL),
			namespaces: expirable.NewLRU[uint32, string](untrackedPIDCacheSize, nil, untrackedPIDCacheTTL),
		}
		in := input.Subscribe(msg.SubscriberName("k8s.PIDMetadataDecorator"))

		return func(runCtx context.Context) {
			defer output.Close()
			swarms.ForEachInput(runCtx, in, pidLog().Debug, func(items []T) {
				for _, item := range items {
					pidNs, hostPID, sDev, ok := pidOf(item)
					if !ok {
						continue
					}
					dec.decorate(runCtx, attrs(item), pidNs, hostPID, sDev)
				}
				output.Send(items)
			})
		}, nil
	}
}

type pidDecorator struct {
	store *kube.Store
	pvc   ebpf.PVCLookup
	// containers caches the container ID, or "" for none, of host PIDs the
	// Store does not track.
	containers *expirable.LRU[app.PID, string]
	// namespaces caches the container ID, or "" for none, owning a PID
	// namespace, for processes that exited before they were decorated.
	namespaces *expirable.LRU[uint32, string]
}

// decorate populates a's Metadata with pod/namespace/container attribution
// from the PID path, and PersistentVolume/PersistentVolumeClaim attribution
// from the mount path. Both paths are independent: a ReadWriteMany volume is
// shared by several pods over one superblock, so sDev alone cannot identify
// which pod issued this I/O.
func (d *pidDecorator) decorate(ctx context.Context, a *pipe.CommonAttrs, pidNs, hostPID, sDev uint32) {
	if a.Metadata == nil {
		a.Metadata = map[attr.Name]string{}
	}

	podMeta, containerName := d.store.PodContainerByPIDNs(pidNs, app.PID(hostPID))

	// The Store only tracks processes that application discovery has seen,
	// which with storage metrics alone is none of them. The process's cgroup
	// names its container just as well.
	if podMeta == nil {
		podMeta, containerName = d.podContainerByCgroup(pidNs, app.PID(hostPID))
	}

	mountInfo, mountFound := resolveMount(sDev)

	// A process that is gone, or that runs outside any container, leaves the
	// PID path empty. Falling back to the mount's owning pod still gives
	// pod/namespace attribution, but only when the volume has exactly one
	// owner: on a shared (ReadWriteMany) volume the mount's pod is one of
	// several and naming it would attribute this I/O to whichever pod mounted
	// first. The container is left unset in either case, since it comes from
	// the PID path alone.
	if podMeta == nil && mountFound && !mountInfo.Shared {
		podMeta = d.store.PodByUID(mountInfo.PodUID)
		containerName = ""
	}

	if podMeta != nil {
		a.Metadata[attr.K8sPodName] = podMeta.Meta.Name
		a.Metadata[attr.K8sNamespaceName] = podMeta.Meta.Namespace
		if containerName != "" {
			a.Metadata[attr.K8sContainerName] = containerName
		}
	}

	if !mountFound {
		return
	}

	a.Metadata[attr.K8sPersistentVolumeName] = mountInfo.PVName

	namespace, claimName, storageClass, ok := d.pvc(ctx, mountInfo.PVName)
	if !ok {
		return
	}

	a.Metadata[attr.K8sPersistentVolumeClaimName] = claimName
	if storageClass != "" {
		a.Metadata[attr.K8sStorageClassName] = storageClass
	}
	if a.Metadata[attr.K8sNamespaceName] == "" {
		a.Metadata[attr.K8sNamespaceName] = namespace
	}
}

// podContainerByCgroup resolves the process that issued the I/O to its pod and
// container through its cgroup, caching the container ID per host PID. A
// process that has already exited, the norm for short-lived writers such as a
// dd or a backup script, is resolved through its PID namespace instead.
func (d *pidDecorator) podContainerByCgroup(pidNs uint32, hostPID app.PID) (*ikube.CachedObjMeta, string) {
	if hostPID == 0 {
		return nil, ""
	}
	cid, ok := d.containers.Get(hostPID)
	if !ok {
		cid = containerOf(hostPID)
		if cid == "" {
			cid = d.containerOfNamespace(pidNs)
		}
		d.containers.Add(hostPID, cid)
	}
	if cid == "" {
		return nil, ""
	}
	return d.store.PodContainerByContainerID(cid)
}

// containerOfNamespace finds the container owning PID namespace pidNs through
// any process still living in it. Kubernetes gives each container its own PID
// namespace, so the namespace names the container for as long as the
// container runs, whichever of its processes did the I/O. The host's own
// namespace names no container and is never looked up.
func (d *pidDecorator) containerOfNamespace(pidNs uint32) string {
	if pidNs == 0 || pidNs == hostPIDNamespace() {
		return ""
	}
	if cid, ok := d.namespaces.Get(pidNs); ok {
		return cid
	}
	cid := ""
	for _, pid := range pidsInNamespace(pidNs) {
		if cid = containerOf(pid); cid != "" {
			break
		}
	}
	d.namespaces.Add(pidNs, cid)
	return cid
}

func containerOf(pid app.PID) string {
	info, err := kube.InfoForPID(pid)
	if err != nil {
		pidLog().Debug("no container for process", "pid", pid, "error", err)
		return ""
	}
	return info.ContainerID
}

var hostPIDNamespace = sync.OnceValue(func() uint32 {
	ns, _ := procs.FindNamespace(1)
	return ns
})

// pidsInNamespace lists the live processes in PID namespace ns. It is an
// injectable indirection for tests.
var pidsInNamespace = func(ns uint32) []app.PID {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []app.PID
	for _, e := range entries {
		n, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		if pidNs, err := procs.FindNamespace(app.PID(n)); err == nil && pidNs == ns {
			pids = append(pids, app.PID(n))
		}
	}
	return pids
}
