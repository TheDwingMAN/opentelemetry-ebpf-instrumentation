// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// waitIdle blocks until c has no background fetch in flight, so a test can
// assert on state right after CachedPVCLookup's async fetch (3.3, step 10)
// completes, without a fixed sleep.
func waitIdle(t *testing.T, c *pvcCache) {
	t.Helper()
	require.Eventually(t, func() bool { return c.inFlight() == 0 }, time.Second, time.Millisecond)
}

func TestCachedPVCLookup_CachesSuccess(t *testing.T) {
	var calls atomic.Int32
	lookup := func(_ context.Context, pvName string) (string, string, string, bool) {
		calls.Add(1)
		return "ns-" + pvName, "claim-" + pvName, "sc-" + pvName, true
	}
	c := &pvcCache{resolve: lookup, entries: map[string]pvcCacheEntry{}, busy: map[string]bool{}, now: time.Now}

	// A cache miss returns not-found at once; the fetch runs in the background.
	_, _, _, ok := c.get(context.Background(), "pv-a")
	assert.False(t, ok, "first call is a miss: the background fetch hasn't returned yet")
	waitIdle(t, c)

	namespace, claimName, storageClass, ok := c.get(context.Background(), "pv-a")
	require.True(t, ok)
	assert.Equal(t, "ns-pv-a", namespace)
	assert.Equal(t, "claim-pv-a", claimName)
	assert.Equal(t, "sc-pv-a", storageClass)

	c.get(context.Background(), "pv-a")
	assert.Equal(t, int32(1), calls.Load(), "a repeat hit must not call through twice")
}

func TestCachedPVCLookup_RetriesFailure(t *testing.T) {
	var calls atomic.Int32
	lookup := func(_ context.Context, _ string) (string, string, string, bool) {
		n := calls.Add(1)
		return "", "", "", n > 1
	}

	now := time.Now()
	c := &pvcCache{resolve: lookup, entries: map[string]pvcCacheEntry{}, busy: map[string]bool{}, now: func() time.Time { return now }}

	_, _, _, ok := c.get(context.Background(), "pv-b")
	assert.False(t, ok, "first lookup is a miss: the background fetch hasn't returned yet")
	waitIdle(t, c)
	require.Equal(t, int32(1), calls.Load())

	_, _, _, ok = c.get(context.Background(), "pv-b")
	assert.False(t, ok, "a failed lookup within the negative TTL must be served from cache")
	assert.Equal(t, int32(1), calls.Load(), "a cached negative result must not retry before its TTL elapses")

	now = now.Add(pvcCacheNegativeTTL)

	// Past the TTL, get starts a background refresh but still returns the
	// stale (negative) entry at once, per CachedPVCLookup's contract.
	_, _, _, ok = c.get(context.Background(), "pv-b")
	assert.False(t, ok, "the stale entry, not the in-flight result, is returned")
	waitIdle(t, c)
	assert.Equal(t, int32(2), calls.Load(), "a failed lookup must be retried once its negative TTL elapses")

	namespace, claimName, storageClass, ok := c.get(context.Background(), "pv-b")
	assert.True(t, ok)
	assert.Empty(t, namespace)
	assert.Empty(t, claimName)
	assert.Empty(t, storageClass)
	assert.Equal(t, int32(2), calls.Load())
}

// A resolved claim is not cached forever either: step 10 gives it its own,
// longer TTL (pvcCachePositiveTTL) so a Retain PV an admin re-binds to a new
// claim is picked up without a process restart (v2's race case,
// TestPersistentVolumeOfARecreatedClaim).
func TestCachedPVCLookup_ReResolvesBoundClaimAfterPositiveTTL(t *testing.T) {
	claim := "claim-1"
	lookup := func(_ context.Context, _ string) (string, string, string, bool) {
		return "ns", claim, "sc", true
	}

	now := time.Now()
	c := &pvcCache{resolve: lookup, entries: map[string]pvcCacheEntry{}, busy: map[string]bool{}, now: func() time.Time { return now }}

	c.get(context.Background(), "pv-c")
	waitIdle(t, c)

	_, claimName, _, ok := c.get(context.Background(), "pv-c")
	require.True(t, ok)
	assert.Equal(t, "claim-1", claimName)

	// The underlying claim changes, but within the positive TTL the cached
	// answer is still served: resolve is not even called again.
	claim = "claim-2"
	_, claimName, _, ok = c.get(context.Background(), "pv-c")
	require.True(t, ok)
	assert.Equal(t, "claim-1", claimName, "not re-resolved before its TTL elapses")

	now = now.Add(pvcCachePositiveTTL)
	c.get(context.Background(), "pv-c") // starts the background re-fetch
	waitIdle(t, c)

	_, claimName, _, ok = c.get(context.Background(), "pv-c")
	require.True(t, ok)
	assert.Equal(t, "claim-2", claimName, "the changed claim is picked up once the positive TTL elapses")
}

func TestCachedPVCLookup_BoundsCacheSize(t *testing.T) {
	var calls atomic.Int32
	lookup := func(_ context.Context, pvName string) (string, string, string, bool) {
		calls.Add(1)
		return "ns", pvName, "", true
	}
	c := &pvcCache{resolve: lookup, entries: map[string]pvcCacheEntry{}, busy: map[string]bool{}, now: time.Now}

	resolve := func(pvName string) {
		c.get(context.Background(), pvName)
		waitIdle(t, c)
	}

	firstPV := "pv-0"
	resolve(firstPV)
	require.Equal(t, int32(1), calls.Load())

	// Fill the cache past its bound with distinct keys.
	for i := 1; i <= maxCachedPVCLookups; i++ {
		resolve(fmt.Sprintf("pv-%d", i))
	}

	callsBeforeRecheck := calls.Load()

	// The cache must have evicted the first entry once it grew past its
	// bound, so it is no longer cached and gets resolved again.
	resolve(firstPV)
	assert.Greater(t, calls.Load(), callsBeforeRecheck, "cache should have evicted the first entry once it grew past its bound")
}

// CachedPVCLookup's whole point (3.3, step 10): the release ran resolve
// synchronously on the decorator's goroutine, so a slow or stuck API server
// stalled every storage event behind it. get must return at once regardless
// of how long resolve takes.
func TestCachedPVCLookup_NeverBlocksOnASlowResolve(t *testing.T) {
	unblock := make(chan struct{})
	lookup := func(_ context.Context, _ string) (string, string, string, bool) {
		<-unblock
		return "ns", "claim", "sc", true
	}
	cached := CachedPVCLookup(lookup)

	done := make(chan struct{})
	go func() {
		cached(context.Background(), "pv-slow")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("get blocked on a resolve call that had not returned yet")
	}

	close(unblock)
}

func TestK8sPVCLookup_BoundPVResolvesClaim(t *testing.T) {
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
		Spec: corev1.PersistentVolumeSpec{
			StorageClassName: "fast-ssd",
			ClaimRef:         &corev1.ObjectReference{Namespace: "ns-1", Name: "claim-1"},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}
	client := fake.NewSimpleClientset(pv)

	namespace, claimName, storageClass, ok := K8sPVCLookup(client)(context.Background(), "pv-1")
	require.True(t, ok)
	assert.Equal(t, "ns-1", namespace)
	assert.Equal(t, "claim-1", claimName)
	assert.Equal(t, "fast-ssd", storageClass)
}

// A Released PV's claimRef, if any, names a claim that may already be gone
// or reused by an unrelated new claim of the same name: only Bound
// guarantees the claim is still the one that bound this volume.
func TestK8sPVCLookup_ReleasedPVYieldsNoClaim(t *testing.T) {
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-2"},
		Spec: corev1.PersistentVolumeSpec{
			ClaimRef: &corev1.ObjectReference{Namespace: "ns-1", Name: "claim-1"},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased},
	}
	client := fake.NewSimpleClientset(pv)

	_, _, _, ok := K8sPVCLookup(client)(context.Background(), "pv-2")
	assert.False(t, ok)
}

func TestK8sPVCLookup_UnboundPVYieldsNoClaim(t *testing.T) {
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-3"},
		Status:     corev1.PersistentVolumeStatus{Phase: corev1.VolumeAvailable},
	}
	client := fake.NewSimpleClientset(pv)

	_, _, _, ok := K8sPVCLookup(client)(context.Background(), "pv-3")
	assert.False(t, ok)
}

func TestK8sPVCLookup_MissingPVYieldsNoClaim(t *testing.T) {
	client := fake.NewSimpleClientset()

	_, _, _, ok := K8sPVCLookup(client)(context.Background(), "does-not-exist")
	assert.False(t, ok)
}

// TestPVCLookupPicksUpARecreatedClaimAfterTTL is step 10's port of v2's
// TestPersistentVolumeOfARecreatedClaim: a Retain PV released from one claim
// and later re-bound to a differently named claim is not stuck reporting the
// first claim forever, but only once the cache's positive TTL allows a
// re-check -- not on every event.
func TestPVCLookupPicksUpARecreatedClaimAfterTTL(t *testing.T) {
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-recreated"},
		Spec: corev1.PersistentVolumeSpec{
			StorageClassName: "slow-hdd",
			ClaimRef:         &corev1.ObjectReference{Namespace: "ns-old", Name: "claim-old"},
		},
		Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
	}
	client := fake.NewSimpleClientset(pv)

	now := time.Now()
	c := &pvcCache{
		resolve: K8sPVCLookup(client),
		entries: map[string]pvcCacheEntry{},
		busy:    map[string]bool{},
		now:     func() time.Time { return now },
	}

	c.get(context.Background(), "pv-recreated")
	waitIdle(t, c)

	_, claimName, _, ok := c.get(context.Background(), "pv-recreated")
	require.True(t, ok)
	assert.Equal(t, "claim-old", claimName)

	// The old claim is deleted, the PV released, then re-bound to a
	// differently named claim -- all inside the positive TTL, so nothing
	// asks the API server about it yet.
	pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: "ns-new", Name: "claim-new"}
	_, err := client.CoreV1().PersistentVolumes().Update(context.Background(), pv, metav1.UpdateOptions{})
	require.NoError(t, err)

	_, claimName, _, ok = c.get(context.Background(), "pv-recreated")
	require.True(t, ok)
	assert.Equal(t, "claim-old", claimName, "not re-resolved before its TTL elapses")

	now = now.Add(pvcCachePositiveTTL)
	c.get(context.Background(), "pv-recreated")
	waitIdle(t, c)

	_, claimName, _, ok = c.get(context.Background(), "pv-recreated")
	require.True(t, ok)
	assert.Equal(t, "claim-new", claimName, "the re-bound claim is picked up once the positive TTL elapses")
}
