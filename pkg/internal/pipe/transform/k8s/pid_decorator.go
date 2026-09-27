// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8s // import "go.opentelemetry.io/obi/pkg/internal/pipe/transform/k8s"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
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

// PIDMetadataDecoratorProvider attributes items to their Kubernetes pod,
// namespace, container, and persistent volume/claim, using the PID triple and
// filesystem superblock device number returned by pidOf.
func PIDMetadataDecoratorProvider[T any](
	ctx context.Context,
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

		dec := &pidDecorator{store: store, pvc: pvc}
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

	mountInfo, mountFound := resolveMount(sDev)

	// PodContainerByPIDNs misses processes it hasn't tracked yet. Falling back
	// to the mount's owning pod still gives useful pod/namespace attribution;
	// the container is left unset since a shared (ReadWriteMany) volume's pod
	// UID does not always match the process that issued this I/O.
	if podMeta == nil && mountFound {
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
