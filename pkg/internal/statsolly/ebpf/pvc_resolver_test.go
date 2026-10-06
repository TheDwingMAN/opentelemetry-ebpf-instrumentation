// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachedPVCLookup_CachesSuccess(t *testing.T) {
	calls := 0
	lookup := func(_ context.Context, pvName string) (string, string, bool) {
		calls++
		return "ns-" + pvName, "claim-" + pvName, true
	}
	cached := CachedPVCLookup(lookup)

	namespace, claimName, ok := cached(context.Background(), "pv-a")
	require.True(t, ok)
	assert.Equal(t, "ns-pv-a", namespace)
	assert.Equal(t, "claim-pv-a", claimName)

	namespace, claimName, ok = cached(context.Background(), "pv-a")
	require.True(t, ok)
	assert.Equal(t, "ns-pv-a", namespace)
	assert.Equal(t, "claim-pv-a", claimName)

	assert.Equal(t, 1, calls, "a repeat hit must not call through twice")
}

func TestCachedPVCLookup_RetriesFailure(t *testing.T) {
	calls := 0
	lookup := func(_ context.Context, _ string) (string, string, bool) {
		calls++
		return "", "", calls > 1
	}
	cached := CachedPVCLookup(lookup)

	_, _, ok := cached(context.Background(), "pv-b")
	assert.False(t, ok, "first lookup is expected to fail")

	namespace, claimName, ok := cached(context.Background(), "pv-b")
	assert.True(t, ok, "a failed lookup must be retried, not cached")
	assert.Equal(t, "", namespace)
	assert.Equal(t, "", claimName)
	assert.Equal(t, 2, calls)
}

func TestCachedPVCLookup_BoundsCacheSize(t *testing.T) {
	calls := 0
	lookup := func(_ context.Context, pvName string) (string, string, bool) {
		calls++
		return "ns", pvName, true
	}
	cached := CachedPVCLookup(lookup)

	firstPV := "pv-0"
	_, _, ok := cached(context.Background(), firstPV)
	require.True(t, ok)
	require.Equal(t, 1, calls)

	// Fill the cache past its bound with distinct keys.
	for i := 1; i <= maxCachedPVCLookups; i++ {
		_, _, ok := cached(context.Background(), fmt.Sprintf("pv-%d", i))
		require.True(t, ok)
	}

	callsBeforeRecheck := calls

	// The cache must have been reset at least once while filling, so the
	// very first entry is no longer cached and gets resolved again.
	_, _, ok = cached(context.Background(), firstPV)
	require.True(t, ok)
	assert.Greater(t, calls, callsBeforeRecheck, "cache should have evicted the first entry once it grew past its bound")
}
