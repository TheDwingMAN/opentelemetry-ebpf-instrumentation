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
	baseAttachTo := map[string]string{progObiStatsFentryExt4Read: "ext4_file_read_iter"}

	t.Run("first load succeeds, storage stays enabled", func(t *testing.T) {
		var calls [][]string
		load := func(toDisable []string, attachTo map[string]string) error {
			calls = append(calls, slices.Clone(toDisable))
			assert.Equal(t, baseAttachTo, attachTo)
			return nil
		}
		blockOK, fsOK, err := loadWithStorageFallback(load, baseDisable, baseAttachTo, true, slog.Default())
		require.NoError(t, err)
		assert.True(t, blockOK)
		assert.True(t, fsOK)
		require.Len(t, calls, 1)
		assert.Equal(t, baseDisable, calls[0])
	})

	t.Run("load fails with storage block disabled: skips straight to the filesystem retry", func(t *testing.T) {
		var calls [][]string
		load := func(toDisable []string, _ map[string]string) error {
			calls = append(calls, slices.Clone(toDisable))
			if len(calls) == 1 {
				return loadErr
			}
			return nil
		}
		blockOK, fsOK, err := loadWithStorageFallback(load, baseDisable, baseAttachTo, false, slog.Default())
		require.NoError(t, err)
		assert.False(t, blockOK)
		assert.False(t, fsOK, "filesystem metrics must be reported disabled after fallback")
		require.Len(t, calls, 2)
		assert.NotContains(t, calls[1], progObiStatsTpBlockRqInsert, "block programs were already disabled, no need to add them again")
		assert.Contains(t, calls[1], progObiStatsFentryExt4Read)
		assert.Contains(t, calls[1], progObiStatsKprobeNFSFsync)
	})

	t.Run("load fails with storage enabled: retry with storage stubbed, degrade gracefully", func(t *testing.T) {
		var calls [][]string
		load := func(toDisable []string, _ map[string]string) error {
			calls = append(calls, slices.Clone(toDisable))
			if len(calls) == 1 {
				return loadErr
			}
			return nil
		}
		blockOK, fsOK, err := loadWithStorageFallback(load, baseDisable, baseAttachTo, true, slog.Default())
		require.NoError(t, err)
		assert.False(t, blockOK, "storage block must be reported disabled after fallback")
		assert.True(t, fsOK)
		require.Len(t, calls, 2)
		assert.Contains(t, calls[1], progObiStatsTpBlockRqInsert)
		assert.Contains(t, calls[1], progObiStatsTpBlockRqIssue)
		assert.Contains(t, calls[1], progObiStatsTpBlockRqComplete)
		assert.Contains(t, calls[1], progObiStatsKprobeTCPCloseSrtt, "original disable list preserved on retry")
	})

	t.Run("block retry also fails: retry with filesystem stubbed and fsAttachTo cleared, degrade further", func(t *testing.T) {
		var calls [][]string
		var attachToCalls []map[string]string
		load := func(toDisable []string, attachTo map[string]string) error {
			calls = append(calls, slices.Clone(toDisable))
			attachToCalls = append(attachToCalls, attachTo)
			if len(calls) < 3 {
				return loadErr
			}
			return nil
		}
		blockOK, fsOK, err := loadWithStorageFallback(load, baseDisable, baseAttachTo, true, slog.Default())
		require.NoError(t, err)
		assert.False(t, blockOK)
		assert.False(t, fsOK, "filesystem metrics must be reported disabled after the second fallback")
		require.Len(t, calls, 3)
		assert.Contains(t, calls[2], progObiStatsTpBlockRqInsert, "block stub from the first fallback is preserved")
		assert.Contains(t, calls[2], progObiStatsFentryExt4Read)
		assert.Contains(t, calls[2], progObiStatsKprobeNFSFsync)
		assert.Nil(t, attachToCalls[2], "fsAttachTo must be cleared on the filesystem fallback")
	})

	t.Run("all three loads fail: error surfaces", func(t *testing.T) {
		var calls int
		load := func([]string, map[string]string) error { calls++; return loadErr }
		_, _, err := loadWithStorageFallback(load, baseDisable, baseAttachTo, true, slog.Default())
		require.ErrorIs(t, err, loadErr)
		assert.Equal(t, 3, calls)
	})
}

func TestAllFsProgramNames(t *testing.T) {
	names := allFsProgramNames()

	// Twelve programs per filesystem for read, write and fsync, plus four
	// more for the filesystems that have their own splice_read symbol. The
	// list feeds the loader's last-resort retry, so a name it misses is a
	// program that cannot be stubbed, and a name it invents fails the load.
	withSplice := 0
	for _, tgt := range fsTargets {
		if len(tgt.SpliceReadSyms) > 0 {
			withSplice++
		}
	}
	assert.Len(t, names, len(fsTargets)*12+withSplice*4)
	assert.Contains(t, names, progObiStatsFentryExt4Read)
	assert.Contains(t, names, progObiStatsKretprobeNFSFsync)
	assert.Contains(t, names, progObiStatsFentrySpliceNFS)
	assert.NotContains(t, names, "", "an empty name would fail fixupSpec")
}
