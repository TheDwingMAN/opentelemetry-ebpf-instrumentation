// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s // import "go.opentelemetry.io/obi/pkg/internal/pipe/transform/k8s"

import (
	"context"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
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

// maxCachedVolumes bounds the per-mount volume attributes the decorator keeps;
// the cache is simply dropped when full.
const maxCachedVolumes = 4096

// unboundVolumeRetry is how long a volume whose claim was not found keeps
// that answer, as long as the PVC lookup caches it.
const unboundVolumeRetry = 30 * time.Second

// PIDMetadataDecoratorProvider attributes items to their Kubernetes pod,
// namespace and container, using the PID pair returned by pidOf, and hands
// setMount the persistent volume/claim of the filesystem mount pidOf returns.
func PIDMetadataDecoratorProvider[T any](
	store *kube.Store,
	attrs func(T) *pipe.CommonAttrs,
	pidOf func(item T) (pidNs, hostPID uint32, mount ebpf.MountKey, ok bool),
	setMount func(item T, mount *ebpf.MountAttrs),
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
			containers: expirable.NewLRU[app.PID, cgroupIdentity](untrackedPIDCacheSize, nil, untrackedPIDCacheTTL),
			namespaces: expirable.NewLRU[uint32, cgroupIdentity](untrackedPIDCacheSize, nil, untrackedPIDCacheTTL),
			volumes:    map[ebpf.MountKey]volumeEntry{},
		}
		in := input.Subscribe(msg.SubscriberName("k8s.PIDMetadataDecorator"))

		return func(runCtx context.Context) {
			defer output.Close()
			swarms.ForEachInput(runCtx, in, pidLog().Debug, func(items []T) {
				for _, item := range items {
					pidNs, hostPID, mount, ok := pidOf(item)
					if !ok {
						continue
					}
					setMount(item, dec.decorate(runCtx, attrs(item), pidNs, hostPID, mount))
				}
				output.Send(items)
			})
		}, nil
	}
}

type pidDecorator struct {
	store *kube.Store
	pvc   ebpf.PVCLookup
	// containers caches the cgroup identity, empty for none, of host PIDs
	// the Store does not track.
	containers *expirable.LRU[app.PID, cgroupIdentity]
	// namespaces caches the cgroup identity owning a PID namespace, for
	// processes that exited before they were decorated.
	namespaces *expirable.LRU[uint32, cgroupIdentity]
	// volumes caches the attributes of the volume behind each mount, so its
	// claim is looked up once per mount resolution rather than per event.
	// Only the decorator's goroutine uses it.
	volumes map[ebpf.MountKey]volumeEntry
}

type volumeEntry struct {
	// info is the mount resolution attrs was built from; a new one rebuilds it.
	info  ebpf.MountInfo
	attrs *ebpf.MountAttrs
	// retryAt is when a volume whose claim was not found is looked up
	// again; zero once the claim is known.
	retryAt time.Time
}

// cgroupIdentity is what a process's cgroup path says about it: its container
// ID and the UID of the pod the container belongs to.
type cgroupIdentity struct {
	containerID string
	podUID      string
}

// decorate populates a's Metadata with pod/namespace/container attribution
// from the PID path, and returns the PersistentVolume/PersistentVolumeClaim
// attribution of the mount path, nil when the mount is no known volume. Both
// paths are independent: a ReadWriteMany volume is shared by several pods
// over one mount, so the mount alone cannot identify which pod issued this
// I/O.
func (d *pidDecorator) decorate(ctx context.Context, a *pipe.CommonAttrs, pidNs, hostPID uint32, mount ebpf.MountKey) *ebpf.MountAttrs {
	podMeta, containerName := d.store.PodContainerByPIDNs(pidNs, app.PID(hostPID))

	// The Store only tracks processes that application discovery has seen,
	// which with storage metrics alone is none of them. The process's cgroup
	// names its container just as well.
	if podMeta == nil {
		podMeta, containerName = d.podContainerByCgroup(pidNs, app.PID(hostPID))
	}

	mountInfo, mountFound := resolveMount(mount)

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
		setMetadata(a, attr.K8sPodName, podMeta.Meta.Name)
		setMetadata(a, attr.K8sNamespaceName, podMeta.Meta.Namespace)
		if containerName != "" {
			setMetadata(a, attr.K8sContainerName, containerName)
		}
	}

	if !mountFound || mountInfo.PVName == "" {
		return nil
	}

	volume := d.volumeOf(ctx, mount, mountInfo)
	if a.Metadata[attr.K8sNamespaceName] == "" && volume.PVCNamespace != "" {
		setMetadata(a, attr.K8sNamespaceName, volume.PVCNamespace)
	}
	return volume
}

// volumeOf returns the attributes of the volume a resolved mount belongs to,
// built once per mount resolution. A volume whose claim is not found (not
// bound yet, or no RBAC to read PVs) is asked about again after
// unboundVolumeRetry.
func (d *pidDecorator) volumeOf(ctx context.Context, mount ebpf.MountKey, info ebpf.MountInfo) *ebpf.MountAttrs {
	if e, ok := d.volumes[mount]; ok && e.info == info &&
		(e.retryAt.IsZero() || time.Now().Before(e.retryAt)) {
		return e.attrs
	}

	entry := volumeEntry{info: info, attrs: &ebpf.MountAttrs{PVName: info.PVName}}
	if namespace, claimName, storageClass, ok := d.pvc(ctx, info.PVName); ok {
		entry.attrs.PVCName, entry.attrs.StorageClass, entry.attrs.PVCNamespace = claimName, storageClass, namespace
	} else {
		entry.retryAt = time.Now().Add(unboundVolumeRetry)
	}

	if len(d.volumes) >= maxCachedVolumes {
		clear(d.volumes)
	}
	d.volumes[mount] = entry
	return entry.attrs
}

// setMetadata sets a Metadata entry, creating the map on the first one: a
// stat of a process in no pod, on no volume, then needs none.
func setMetadata(a *pipe.CommonAttrs, name attr.Name, value string) {
	if a.Metadata == nil {
		a.Metadata = map[attr.Name]string{}
	}
	a.Metadata[name] = value
}

// podContainerByCgroup resolves the process that issued the I/O to its pod and
// container through its cgroup, caching the result per host PID. A process
// that has already exited, the norm for short-lived writers such as a dd or a
// backup script, is resolved through its PID namespace instead.
//
// The Store learns a container's ID only once the pod's status reports it,
// which trails the container's first I/O; a pod doing its work in its first
// seconds would lose attribution. The pod UID in the cgroup path is known from
// the moment the pod is scheduled, so the pod is resolved by UID until the
// container ID is known, and the container label follows once it is.
func (d *pidDecorator) podContainerByCgroup(pidNs uint32, hostPID app.PID) (*ikube.CachedObjMeta, string) {
	if hostPID == 0 {
		return nil, ""
	}
	id, ok := d.containers.Get(hostPID)
	if !ok {
		id = identityOf(hostPID)
		if id.containerID == "" {
			id = d.identityOfNamespace(pidNs)
		}
		d.containers.Add(hostPID, id)
	}
	if id.containerID == "" {
		return nil, ""
	}
	if meta, name := d.store.PodContainerByContainerID(id.containerID); meta != nil {
		return meta, name
	}
	if id.podUID == "" {
		return nil, ""
	}
	return d.store.PodByUID(id.podUID), ""
}

// identityOfNamespace finds the container owning PID namespace pidNs through
// any process still living in it. Kubernetes gives each container its own PID
// namespace, so the namespace names the container for as long as the
// container runs, whichever of its processes did the I/O. The host's own
// namespace names no container and is never looked up.
func (d *pidDecorator) identityOfNamespace(pidNs uint32) cgroupIdentity {
	if pidNs == 0 || pidNs == hostPIDNamespace() {
		return cgroupIdentity{}
	}
	if id, ok := d.namespaces.Get(pidNs); ok {
		return id
	}
	var id cgroupIdentity
	for _, pid := range pidsInNamespace(pidNs) {
		if id = identityOf(pid); id.containerID != "" {
			break
		}
	}
	d.namespaces.Add(pidNs, id)
	return id
}

func identityOf(pid app.PID) cgroupIdentity {
	info, err := kube.InfoForPID(pid)
	if err != nil {
		pidLog().Debug("no container for process", "pid", pid, "error", err)
		return cgroupIdentity{}
	}
	return cgroupIdentity{containerID: info.ContainerID, podUID: podUIDForPID(pid)}
}

// podUIDPattern matches the pod UID in a kubelet cgroup path, in both the
// systemd driver's form (kubepods-burstable-pod<uid with _>.slice) and the
// cgroupfs driver's (/kubepods/burstable/pod<uid>/).
var podUIDPattern = regexp.MustCompile(`pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)

// podUIDForPID reads the pod UID from a process's cgroup path, or "" if the
// process is not in a kubelet-managed cgroup. It is an injectable indirection
// for tests.
var podUIDForPID = func(pid app.PID) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/cgroup")
	if err != nil {
		return ""
	}
	m := podUIDPattern.FindSubmatch(b)
	if m == nil {
		return ""
	}
	return strings.ReplaceAll(string(m[1]), "_", "-")
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
