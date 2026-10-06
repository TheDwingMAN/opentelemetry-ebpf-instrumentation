// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"context"
	"log/slog"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
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
// cache before resolve is retried.
const pvcCacheNegativeTTL = 30 * time.Second

// pvcCachePositiveTTL bounds how long a resolved claim is served from cache
// before resolve is retried, so a Retain PV an admin re-binds to a new claim
// is picked up without a process restart (v2's race case,
// TestPersistentVolumeOfARecreatedClaim, step 10).
const pvcCachePositiveTTL = 10 * time.Minute

// maxPVCLookupsInFlight bounds the background PVC GETs running at once, so a
// node churning through many distinct PVs at once (a burst of new pods)
// cannot start unbounded goroutines against the API server.
const maxPVCLookupsInFlight = 64

// pvLookupTimeout bounds one PersistentVolume GET.
const pvLookupTimeout = 2 * time.Second

type pvcCacheEntry struct {
	namespace    string
	claimName    string
	storageClass string
	found        bool
	resolvedAt   time.Time
}

type pvcCache struct {
	mu      sync.Mutex
	resolve PVCLookup
	entries map[string]pvcCacheEntry
	order   []string // insertion order, oldest first, for FIFO eviction
	// busy holds the PVs with a background fetch in flight, so a PV asked
	// about again while its fetch is running does not start a second one.
	busy    map[string]bool
	running int
	now     func() time.Time
}

// CachedPVCLookup wraps resolve with a bounded cache of resolutions, both
// positive and negative, and never runs resolve on the caller's goroutine: a
// cache miss returns not-found at once and starts resolve in the background,
// so a slow or stuck API server stalls neither the calling decorator nor any
// other PV's lookup. The claim is filled in by the next call once the
// background fetch returns (same pattern as mountRootInode, 3.0).
//
// A negative resolution (PV not yet bound to a PVC, or the lookup errored) is
// retried after pvcCacheNegativeTTL; a positive one after pvcCachePositiveTTL.
// Either way the stale entry is still returned while the retry is in flight,
// rather than reverting to not-found.
func CachedPVCLookup(resolve PVCLookup) PVCLookup {
	c := &pvcCache{resolve: resolve, entries: map[string]pvcCacheEntry{}, busy: map[string]bool{}, now: time.Now}
	return c.get
}

func (c *pvcCache) get(_ context.Context, pvName string) (string, string, string, bool) {
	c.mu.Lock()
	entry, ok := c.entries[pvName]
	fetch := (!ok || c.now().Sub(entry.resolvedAt) >= ttl(entry)) && !c.busy[pvName] && c.running < maxPVCLookupsInFlight
	if fetch {
		c.busy[pvName] = true
		c.running++
	}
	c.mu.Unlock()

	if fetch {
		// resolve runs to completion even if the request that triggered it
		// is done by the time it returns: it fills the shared cache for
		// whichever call asks about this PV next, not this one.
		go c.fetch(pvName)
	}

	return entry.namespace, entry.claimName, entry.storageClass, entry.found
}

// fetch resolves pvName and stores the result, replacing whatever was cached
// for it. It always runs on its own goroutine (get never waits for it).
func (c *pvcCache) fetch(pvName string) {
	namespace, claimName, storageClass, found := c.resolve(context.Background(), pvName)

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
	delete(c.busy, pvName)
	c.running--
	c.mu.Unlock()
}

// ttl is how long entry is served from cache before it is stale and due a
// background refresh.
func ttl(entry pvcCacheEntry) time.Duration {
	if entry.found {
		return pvcCachePositiveTTL
	}
	return pvcCacheNegativeTTL
}

// inFlight reports how many PVC lookups this cache has running in the
// background, for tests to wait on instead of sleeping.
func (c *pvcCache) inFlight() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
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
		if pv.Spec.ClaimRef == nil || pv.Status.Phase != corev1.VolumeBound {
			// A Released or Available PV's claimRef, if any, names a claim
			// that may be gone, or reused by an unrelated new claim of the
			// same name: only Bound guarantees the claim is still the one
			// that bound this volume.
			return "", "", "", false
		}
		return pv.Spec.ClaimRef.Namespace, pv.Spec.ClaimRef.Name, pv.Spec.StorageClassName, true
	}
}
