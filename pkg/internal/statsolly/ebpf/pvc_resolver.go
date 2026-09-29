// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"context"
	"log/slog"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PVCLookup resolves the namespace and claim name of the PersistentVolumeClaim
// bound to a PersistentVolume, identified by its PV name, and the storage class name.
type PVCLookup func(ctx context.Context, pvName string) (namespace, claimName, storageClass string, ok bool)

// maxCachedPVCLookups bounds the cache built by CachedPVCLookup, so a node
// churning through many distinct PVs cannot grow it without limit.
const maxCachedPVCLookups = 4096

// pvcCacheNegativeTTL bounds how long a PV that failed to resolve (not yet
// bound to a PVC, or the lookup errored, e.g. missing RBAC) is served from
// cache before resolve is retried. Without this, a cluster missing the
// persistentvolumes get grant would perform a synchronous API GET on every
// filesystem event.
const pvcCacheNegativeTTL = 30 * time.Second

// pvLookupTimeout bounds one PersistentVolume GET. It runs on the decorator's
// goroutine, so a slow API server would otherwise stall every storage event
// behind it.
const pvLookupTimeout = 2 * time.Second

type pvcCacheEntry struct {
	namespace    string
	claimName    string
	storageClass string
	found        bool
	resolvedAt   time.Time
}

type pvcCache struct {
	mu      sync.RWMutex
	resolve PVCLookup
	entries map[string]pvcCacheEntry
	order   []string // insertion order, oldest first, for FIFO eviction
	now     func() time.Time
}

// CachedPVCLookup wraps resolve with a bounded cache of resolutions, both
// positive and negative. A negative resolution (PV not yet bound to a PVC,
// or the lookup errored) is cached for pvcCacheNegativeTTL rather than
// forever, so a claim that binds later is picked up without waiting for a
// process restart.
func CachedPVCLookup(resolve PVCLookup) PVCLookup {
	c := &pvcCache{resolve: resolve, entries: map[string]pvcCacheEntry{}, now: time.Now}
	return c.get
}

func (c *pvcCache) get(ctx context.Context, pvName string) (string, string, string, bool) {
	c.mu.RLock()
	entry, ok := c.entries[pvName]
	c.mu.RUnlock()
	if ok {
		if entry.found {
			return entry.namespace, entry.claimName, entry.storageClass, true
		}
		if c.now().Sub(entry.resolvedAt) < pvcCacheNegativeTTL {
			return "", "", "", false
		}
	}

	namespace, claimName, storageClass, found := c.resolve(ctx, pvName)

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
	c.entries[pvName] = pvcCacheEntry{
		namespace:    namespace,
		claimName:    claimName,
		storageClass: storageClass,
		found:        found,
		resolvedAt:   c.now(),
	}
	c.mu.Unlock()

	return namespace, claimName, storageClass, found
}

// ResolveMount exposes resolveMount to packages outside ebpf, such as the
// PID-based Kubernetes decorator that attributes filesystem I/O to pods and
// the persistent volumes they mount.
func ResolveMount(key MountKey) (MountInfo, bool) {
	return resolveMount(key)
}

// pvcForbiddenWarnOnce ensures the RBAC warning below logs at most once per
// process, even though a missing grant makes every uncached PV lookup fail.
var pvcForbiddenWarnOnce sync.Once

// K8sPVCLookup resolves a PersistentVolume to the claim bound to it by reading
// the PV's spec.claimRef on demand, and returns the storage class name.
//
// This is a lazy API read rather than a watch. A PV-to-PVC binding is fixed for
// the life of the claim, so wrapped in CachedPVCLookup it costs one GET per
// distinct volume the node ever mounts. Watching PersistentVolumes and
// PersistentVolumeClaims instead would mean two more cluster-wide informers and
// the RBAC to match, for data that never changes once bound.
func pvcLog() *slog.Logger {
	return slog.With("component", "ebpf.PVCLookup")
}

func K8sPVCLookup(client kubernetes.Interface) PVCLookup {
	return func(ctx context.Context, pvName string) (string, string, string, bool) {
		ctx, cancel := context.WithTimeout(ctx, pvLookupTimeout)
		defer cancel()
		pv, err := client.CoreV1().PersistentVolumes().Get(ctx, pvName, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
				pvcForbiddenWarnOnce.Do(func() {
					pvcLog().Warn("persistent volume lookup forbidden; grant get on persistentvolumes to attribute claims and storage classes", "error", err)
				})
			}
			return "", "", "", false
		}
		if pv.Spec.ClaimRef == nil {
			return "", "", "", false
		}
		return pv.Spec.ClaimRef.Namespace, pv.Spec.ClaimRef.Name, pv.Spec.StorageClassName, true
	}
}
