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

// maxVolumeVariants bounds the per-pod and per-container variants of one
// volume, and maxCachedVariants those of all of them: the decorator holds a
// few thousand small values at most, not volumes times variants.
const (
	maxVolumeVariants = 64
	maxCachedVariants = 16384
)

// unboundVolumeRetry is how long a volume whose claim was not found keeps
// that answer before volumeOf asks the PVC lookup again, matching
// pvcCacheNegativeTTL so a newly bound claim is picked up promptly.
const unboundVolumeRetry = 30 * time.Second

// boundVolumeRetry is how long a volume's PV/PVC/storage-class and fs join
// labels are cached once resolved, before volumeOf asks again, matching
// pvcCachePositiveTTL: a Retain PV an admin re-binds to a new claim is still
// picked up, not cached forever (step 10, v2's
// TestPersistentVolumeOfARecreatedClaim race case).
const boundVolumeRetry = 10 * time.Minute

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
	return PIDMetadataDecoratorProviderWith(store, attrs, pidOf, setMount, pvc, PIDMountpoints[T]{}, input, output)
}

// PIDMountpoints selects the mount path attributes of a volume. The zero
// value selects none, and then nothing about mount paths is resolved.
type PIDMountpoints[T any] struct {
	// Host selects system.filesystem.mountpoint, which the mount resolver
	// answers from the host's mount table it has read anyway.
	Host bool
	// ContainerPath, when set, selects obi.fs.container.mountpoint: it
	// returns where the container of a process mounts the volume, "" when
	// unknown. scope is the container's name.
	ContainerPath func(pidNs, hostPID uint32, scope string, mount ebpf.MountKey) string
	// PodUID returns the UID of the pod an item already comes with, "" when
	// it has none. A shared volume has a host path per pod, and the pod of
	// such an item is not found again.
	PodUID func(item T) string
}

// PIDMetadataDecoratorProviderWith is PIDMetadataDecoratorProvider with the
// mount path attributes mountpoints selects.
func PIDMetadataDecoratorProviderWith[T any](
	store *kube.Store,
	attrs func(T) *pipe.CommonAttrs,
	pidOf func(item T) (pidNs, hostPID uint32, mount ebpf.MountKey, ok bool),
	setMount func(item T, mount *ebpf.MountAttrs),
	pvc ebpf.PVCLookup,
	mountpoints PIDMountpoints[T],
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if store == nil {
			return swarm.Bypass(input, output)
		}

		decorate := NewPIDItemDecoratorWith(store, attrs, pidOf, setMount, pvc, mountpoints)
		in := input.Subscribe(msg.SubscriberName("k8s.PIDMetadataDecorator"))

		return func(runCtx context.Context) {
			defer output.Close()
			swarms.ForEachInput(runCtx, in, pidLog().Debug, func(items []T) {
				for _, item := range items {
					decorate(runCtx, item)
				}
				output.Send(items)
			})
		}, nil
	}
}

// NewPIDItemDecorator returns what the PID metadata decorator does to an
// item. It is nil without a store. Its caches are not safe for concurrent
// use: each caller builds its own.
func NewPIDItemDecorator[T any](
	store *kube.Store,
	attrs func(T) *pipe.CommonAttrs,
	pidOf func(item T) (pidNs, hostPID uint32, mount ebpf.MountKey, ok bool),
	setMount func(item T, mount *ebpf.MountAttrs),
	pvc ebpf.PVCLookup,
) func(ctx context.Context, item T) {
	return NewPIDItemDecoratorWith(store, attrs, pidOf, setMount, pvc, PIDMountpoints[T]{})
}

// NewPIDItemDecoratorWith is NewPIDItemDecorator with the mount path
// attributes mountpoints selects.
func NewPIDItemDecoratorWith[T any](
	store *kube.Store,
	attrs func(T) *pipe.CommonAttrs,
	pidOf func(item T) (pidNs, hostPID uint32, mount ebpf.MountKey, ok bool),
	setMount func(item T, mount *ebpf.MountAttrs),
	pvc ebpf.PVCLookup,
	mountpoints PIDMountpoints[T],
) func(ctx context.Context, item T) {
	if store == nil {
		return nil
	}
	dec := &pidDecorator{
		store:         store,
		pvc:           pvc,
		hostPath:      mountpoints.Host,
		containerPath: mountpoints.ContainerPath,
		containers:    expirable.NewLRU[app.PID, cgroupIdentity](untrackedPIDCacheSize, nil, untrackedPIDCacheTTL),
		namespaces:    expirable.NewLRU[uint32, cgroupIdentity](untrackedPIDCacheSize, nil, untrackedPIDCacheTTL),
		volumes:       map[ebpf.MountKey]volumeEntry{},
	}
	return func(ctx context.Context, item T) {
		pidNs, hostPID, mount, ok := pidOf(item)
		if !ok {
			return
		}
		presetPod := ""
		if mountpoints.PodUID != nil {
			presetPod = mountpoints.PodUID(item)
		}
		setMount(item, dec.decorateItem(ctx, attrs(item), pidNs, hostPID, mount, presetPod))
	}
}

type pidDecorator struct {
	store *kube.Store
	pvc   ebpf.PVCLookup
	// hostPath and containerPath select the mount path attributes; with
	// neither, a volume's attributes are the same for every pod and process.
	hostPath      bool
	containerPath func(pidNs, hostPID uint32, scope string, mount ebpf.MountKey) string
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
	// variantCount is the variants held by volumes, all together.
	variantCount int
}

type volumeEntry struct {
	// info is the mount resolution attrs was built from; a new one rebuilds it.
	info  ebpf.MountInfo
	attrs *ebpf.MountAttrs
	// retryAt is when attrs is looked up again: unboundVolumeRetry away while
	// the claim was not found, boundVolumeRetry away once it is.
	retryAt time.Time
	// variants hold the attributes of the volume as one pod or container
	// sees it, when a mount path selected differs between them. Like attrs
	// they are never modified.
	variants map[pathVariant]*ebpf.MountAttrs
}

// pathVariant is what makes one stat's mount paths differ from another's on
// the same mount: the pod of a shared volume, whose host path is its own, and
// the path the stat's container mounts the volume at.
type pathVariant struct {
	podUID        string
	containerPath string
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
	return d.decorateItem(ctx, a, pidNs, hostPID, mount, "")
}

// decorateItem is decorate for an item that comes with the pod whose UID is
// presetPod, "" for one that does not.
func (d *pidDecorator) decorateItem(
	ctx context.Context, a *pipe.CommonAttrs, pidNs, hostPID uint32, mount ebpf.MountKey, presetPod string,
) *ebpf.MountAttrs {
	// dev_t 0 is never a real superblock: sync(2) has no file to take it
	// from (step 14, bpf/statsolly/fs_io.c fs_probe_entry_sync) and reports
	// it that way on purpose. Skip the mount table lookup rather than churn
	// the resolver's cache with a key that can never resolve; pod
	// attribution below still runs from the PID path alone.
	var mountInfo ebpf.MountInfo
	var mountFound bool
	if mount.Dev != 0 {
		mountInfo, mountFound = resolveMount(mount)
	}

	// Kernel-aggregated stats keyed by cgroup come with the pod of their
	// cgroup, which names it for every process of the key; only the volume
	// is left to resolve.
	podUID := presetPod
	if a.Metadata[attr.K8sPodName] == "" {
		podUID = d.decoratePod(a, pidNs, hostPID, mountInfo, mountFound)
	}

	if !mountFound || mountInfo.PVName == "" {
		return nil
	}

	volume := d.volumeOf(ctx, mount, mountInfo, d.pathVariantOf(a, pidNs, hostPID, mount, mountInfo, podUID))
	if a.Metadata[attr.K8sNamespaceName] == "" && volume.PVCNamespace != "" {
		setMetadata(a, attr.K8sNamespaceName, volume.PVCNamespace)
	}
	return volume
}

// pathVariantOf returns what is particular to this stat in the mount paths
// that are selected: none of them is looked at when none is.
func (d *pidDecorator) pathVariantOf(
	a *pipe.CommonAttrs, pidNs, hostPID uint32, mount ebpf.MountKey, info ebpf.MountInfo, podUID string,
) pathVariant {
	var v pathVariant
	if d.hostPath && info.Shared {
		v.podUID = podUID
	}
	if d.containerPath != nil {
		v.containerPath = d.containerPath(pidNs, hostPID, a.Metadata[attr.K8sContainerName], mount)
	}
	return v
}

// decoratePod sets the pod, namespace and container of the process that did
// the I/O, or of the mount's pod when the process has none. It returns the
// UID of that pod, "" when there is none.
func (d *pidDecorator) decoratePod(a *pipe.CommonAttrs, pidNs, hostPID uint32, mountInfo ebpf.MountInfo, mountFound bool) string {
	podMeta, containerName := d.store.PodContainerByPIDNs(pidNs, app.PID(hostPID))

	// The Store only tracks processes that application discovery has seen,
	// which with storage metrics alone is none of them. The process's cgroup
	// names its container just as well.
	if podMeta == nil {
		podMeta, containerName = d.podContainerByCgroup(pidNs, app.PID(hostPID))
	}

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

	if podMeta == nil {
		return ""
	}
	setMetadata(a, attr.K8sPodName, podMeta.Meta.Name)
	setMetadata(a, attr.K8sNamespaceName, podMeta.Meta.Namespace)
	if containerName != "" {
		setMetadata(a, attr.K8sContainerName, containerName)
	}
	ownerName, ownerKind := topOwnerNameKind(podMeta.Meta)
	setMetadata(a, attr.K8sOwnerName, ownerName)
	setMetadata(a, attr.K8sKind, ownerKind)
	return podMeta.Meta.GetPod().GetUid()
}

// volumeOf returns the attributes of the volume a resolved mount belongs to,
// built once per mount resolution, including the fs join labels of step 10
// (system.device, obi.disk.physical_device, server.address), so a getter
// never takes the block-stack or PVC-cache locks per event (3.0). A volume
// whose claim is not found (not bound yet, or no RBAC to read PVs) is asked
// about again after unboundVolumeRetry; one that is found, after
// boundVolumeRetry, so a claim rebound later is not cached forever.
func (d *pidDecorator) volumeOf(ctx context.Context, mount ebpf.MountKey, info ebpf.MountInfo, v pathVariant) *ebpf.MountAttrs {
	if e, ok := d.volumes[mount]; ok && e.info == info && time.Now().Before(e.retryAt) {
		if v == (pathVariant{}) {
			return e.attrs
		}
		attrs := d.variantOf(&e, v, info)
		d.volumes[mount] = e
		return attrs
	}

	entry := volumeEntry{info: info, attrs: &ebpf.MountAttrs{PVName: info.PVName, ServerAddress: info.Addr}}
	entry.attrs.SystemDevice, entry.attrs.PhysicalDevice = ebpf.FSJoinDevice(mount.Dev, info.Source)
	if d.hostPath {
		entry.attrs.HostPath = info.HostPathFor("")
	}

	retry := unboundVolumeRetry
	if namespace, claimName, storageClass, ok := d.pvc(ctx, info.PVName); ok {
		entry.attrs.PVCName, entry.attrs.StorageClass, entry.attrs.PVCNamespace = claimName, storageClass, namespace
		retry = boundVolumeRetry
	}
	entry.retryAt = time.Now().Add(retry)

	if len(d.volumes) >= maxCachedVolumes {
		clear(d.volumes)
		d.variantCount = 0
	}
	attrs := entry.attrs
	if v != (pathVariant{}) {
		attrs = d.variantOf(&entry, v, info)
	}
	d.volumes[mount] = entry
	return attrs
}

// variantOf returns the attributes of the volume of e as v sees it, and
// remembers them in e, which the caller stores back.
func (d *pidDecorator) variantOf(e *volumeEntry, v pathVariant, info ebpf.MountInfo) *ebpf.MountAttrs {
	if attrs, ok := e.variants[v]; ok {
		return attrs
	}
	attrs := *e.attrs
	attrs.ContainerPath = v.containerPath
	if v.podUID != "" {
		attrs.HostPath = info.HostPathFor(v.podUID)
	}
	if d.variantCount >= maxCachedVariants {
		clear(d.volumes)
		d.variantCount = 0
		e.variants = nil
	}
	if e.variants == nil || len(e.variants) >= maxVolumeVariants {
		d.variantCount -= len(e.variants)
		e.variants = map[pathVariant]*ebpf.MountAttrs{}
	}
	e.variants[v] = &attrs
	d.variantCount++
	return &attrs
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
