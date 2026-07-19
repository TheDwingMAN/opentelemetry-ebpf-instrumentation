// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"log/slog"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadWithStorageFallback(t *testing.T) {
	loadErr := errors.New("bad CO-RE relocation: invalid func unknown#195896080")
	baseDisable := []string{progObiStatsKprobeTCPCloseSrtt}

	t.Run("first load succeeds, storage stays enabled", func(t *testing.T) {
		var calls [][]string
		load := func(toDisable []string) error {
			calls = append(calls, slices.Clone(toDisable))
			return nil
		}
		storageOn, err := loadWithStorageFallback(load, baseDisable, true, slog.Default())
		require.NoError(t, err)
		assert.True(t, storageOn)
		require.Len(t, calls, 1)
		assert.Equal(t, baseDisable, calls[0])
	})

	t.Run("load fails with storage disabled: error, no retry", func(t *testing.T) {
		var calls int
		load := func([]string) error { calls++; return loadErr }
		_, err := loadWithStorageFallback(load, baseDisable, false, slog.Default())
		require.ErrorIs(t, err, loadErr)
		assert.Equal(t, 1, calls)
	})

	t.Run("load fails with storage enabled: retry with storage stubbed, degrade gracefully", func(t *testing.T) {
		var calls [][]string
		load := func(toDisable []string) error {
			calls = append(calls, slices.Clone(toDisable))
			if len(calls) == 1 {
				return loadErr
			}
			return nil
		}
		storageOn, err := loadWithStorageFallback(load, baseDisable, true, slog.Default())
		require.NoError(t, err)
		assert.False(t, storageOn, "storage must be reported disabled after fallback")
		require.Len(t, calls, 2)
		assert.Contains(t, calls[1], progObiStatsTpBlockRqIssue)
		assert.Contains(t, calls[1], progObiStatsTpBlockRqComplete)
		assert.Contains(t, calls[1], progObiStatsKprobeTCPCloseSrtt, "original disable list preserved on retry")
	})

	t.Run("both loads fail: error surfaces", func(t *testing.T) {
		var calls int
		load := func([]string) error { calls++; return loadErr }
		_, err := loadWithStorageFallback(load, baseDisable, true, slog.Default())
		require.ErrorIs(t, err, loadErr)
		assert.Equal(t, 2, calls)
	})
}
