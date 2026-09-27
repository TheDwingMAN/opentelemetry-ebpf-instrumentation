// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"context"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PVCLookup resolves the namespace and claim name of the PersistentVolumeClaim
// bound to a PersistentVolume, identified by its PV name.
type PVCLookup func(ctx context.Context, pvName string) (namespace, claimName string, ok bool)

// maxCachedPVCLookups bounds the cache built by CachedPVCLookup, so a node
// churning through many distinct PVs cannot grow it without limit.
const maxCachedPVCLookups = 4096

type pvcCacheEntry struct {
	namespace string
	claimName string
}

type pvcCache struct {
	mu      sync.RWMutex
	resolve PVCLookup
	entries map[string]pvcCacheEntry
	order   []string // insertion order, oldest first, for FIFO eviction
}

// CachedPVCLookup wraps resolve with a bounded cache of successful
// resolutions. A PV that has not yet bound to a PVC fails the underlying
// lookup; that failure is not cached, so the next call retries it instead of
// returning a stale negative result.
func CachedPVCLookup(resolve PVCLookup) PVCLookup {
	c := &pvcCache{resolve: resolve, entries: map[string]pvcCacheEntry{}}
	return c.get
}

func (c *pvcCache) get(ctx context.Context, pvName string) (string, string, bool) {
	c.mu.RLock()
	entry, ok := c.entries[pvName]
	c.mu.RUnlock()
	if ok {
		return entry.namespace, entry.claimName, true
	}

	namespace, claimName, ok := c.resolve(ctx, pvName)
	if !ok {
		return "", "", false
	}

	c.mu.Lock()
	if _, exists := c.entries[pvName]; !exists {
		if len(c.entries) >= maxCachedPVCLookups {
			// Evict the oldest entry rather than the whole cache, so filling
			// the cache doesn't force every other cached PV to be
			// re-looked-up too.
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, oldest)
		}
		c.order = append(c.order, pvName)
	}
	c.entries[pvName] = pvcCacheEntry{namespace: namespace, claimName: claimName}
	c.mu.Unlock()

	return namespace, claimName, true
}

// ResolveMount exposes resolveMount to packages outside ebpf, such as the
// PID-based Kubernetes decorator that attributes filesystem I/O to pods and
// the persistent volumes they mount.
func ResolveMount(sDev uint32) (MountInfo, bool) {
	return resolveMount(sDev)
}

// K8sPVCLookup resolves a PersistentVolume to the claim bound to it by reading
// the PV's spec.claimRef on demand.
//
// This is a lazy API read rather than a watch. A PV-to-PVC binding is fixed for
// the life of the claim, so wrapped in CachedPVCLookup it costs one GET per
// distinct volume the node ever mounts. Watching PersistentVolumes and
// PersistentVolumeClaims instead would mean two more cluster-wide informers and
// the RBAC to match, for data that never changes once bound.
func K8sPVCLookup(client kubernetes.Interface) PVCLookup {
	return func(ctx context.Context, pvName string) (string, string, bool) {
		pv, err := client.CoreV1().PersistentVolumes().Get(ctx, pvName, metav1.GetOptions{})
		if err != nil || pv.Spec.ClaimRef == nil {
			return "", "", false
		}
		return pv.Spec.ClaimRef.Namespace, pv.Spec.ClaimRef.Name, true
	}
}
