// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachedPVCLookup_CachesSuccess(t *testing.T) {
	calls := 0
	lookup := func(_ context.Context, pvName string) (string, string, string, bool) {
		calls++
		return "ns-" + pvName, "claim-" + pvName, "sc-" + pvName, true
	}
	cached := CachedPVCLookup(lookup)

	namespace, claimName, storageClass, ok := cached(context.Background(), "pv-a")
	require.True(t, ok)
	assert.Equal(t, "ns-pv-a", namespace)
	assert.Equal(t, "claim-pv-a", claimName)
	assert.Equal(t, "sc-pv-a", storageClass)

	namespace, claimName, storageClass, ok = cached(context.Background(), "pv-a")
	require.True(t, ok)
	assert.Equal(t, "ns-pv-a", namespace)
	assert.Equal(t, "claim-pv-a", claimName)
	assert.Equal(t, "sc-pv-a", storageClass)

	assert.Equal(t, 1, calls, "a repeat hit must not call through twice")
}

func TestCachedPVCLookup_RetriesFailure(t *testing.T) {
	calls := 0
	lookup := func(_ context.Context, _ string) (string, string, string, bool) {
		calls++
		return "", "", "", calls > 1
	}

	now := time.Now()
	c := &pvcCache{resolve: lookup, entries: map[string]pvcCacheEntry{}, now: func() time.Time { return now }}

	_, _, _, ok := c.get(context.Background(), "pv-b")
	assert.False(t, ok, "first lookup is expected to fail")
	require.Equal(t, 1, calls)

	_, _, _, ok = c.get(context.Background(), "pv-b")
	assert.False(t, ok, "a failed lookup within the negative TTL must be served from cache")
	assert.Equal(t, 1, calls, "a cached negative result must not retry before its TTL elapses")

	now = now.Add(pvcCacheNegativeTTL)

	namespace, claimName, storageClass, ok := c.get(context.Background(), "pv-b")
	assert.True(t, ok, "a failed lookup must be retried once its negative TTL elapses")
	assert.Empty(t, namespace)
	assert.Empty(t, claimName)
	assert.Empty(t, storageClass)
	assert.Equal(t, 2, calls)
}

func TestCachedPVCLookup_BoundsCacheSize(t *testing.T) {
	calls := 0
	lookup := func(_ context.Context, pvName string) (string, string, string, bool) {
		calls++
		return "ns", pvName, "", true
	}
	cached := CachedPVCLookup(lookup)

	firstPV := "pv-0"
	_, _, _, ok := cached(context.Background(), firstPV)
	require.True(t, ok)
	require.Equal(t, 1, calls)

	// Fill the cache past its bound with distinct keys.
	for i := 1; i <= maxCachedPVCLookups; i++ {
		_, _, _, ok := cached(context.Background(), fmt.Sprintf("pv-%d", i))
		require.True(t, ok)
	}

	callsBeforeRecheck := calls

	// The cache must have been reset at least once while filling, so the
	// very first entry is no longer cached and gets resolved again.
	_, _, _, ok = cached(context.Background(), firstPV)
	require.True(t, ok)
	assert.Greater(t, calls, callsBeforeRecheck, "cache should have evicted the first entry once it grew past its bound")
}
