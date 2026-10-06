// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadWithBlockFallback(t *testing.T) {
	// The fallback's WARN is not logged: in a CI log it reads as a real load
	// of the block programs failing.
	quietLog := slog.New(slog.DiscardHandler)
	loadErr := errors.New("bad CO-RE relocation: invalid func unknown#195896080")
	baseDisable := []string{progObiStatsKprobeTCPCloseSrtt}
	layout := blockTracepointLayout{}
	tpBtf, rawTp := tpBtfBlockPrograms(layout), rawTpBlockPrograms(layout)
	stages := []blockLoadStage{{sets: []blockProgramSet{tpBtf, rawTp}}, {sets: []blockProgramSet{rawTp}}}

	t.Run("first load succeeds: tp_btf and raw_tp loaded, everything else stubbed", func(t *testing.T) {
		var calls [][]string
		load := func(toDisable []string) error {
			calls = append(calls, slices.Clone(toDisable))
			return nil
		}
		stage, err := loadWithBlockFallback(load, baseDisable, stages, quietLog)
		require.NoError(t, err)
		assert.Equal(t, 0, stage)
		require.Len(t, calls, 1)
		assert.Contains(t, calls[0], progObiStatsKprobeTCPCloseSrtt)
		for _, p := range append(tpBtf.programs(), rawTp.programs()...) {
			assert.NotContains(t, calls[0], p)
		}
		for _, p := range []string{
			progObiStatsTpBlockRqIssue, progObiStatsTpBtfBlockRqIssueLegacy, progObiStatsRawTpBlockRqIssueLegacy,
		} {
			assert.Contains(t, calls[0], p)
		}
	})

	t.Run("block off: no stage, one load with every block program stubbed", func(t *testing.T) {
		var calls [][]string
		load := func(toDisable []string) error {
			calls = append(calls, slices.Clone(toDisable))
			return nil
		}
		stage, err := loadWithBlockFallback(load, baseDisable, nil, quietLog)
		require.NoError(t, err)
		assert.Equal(t, 0, stage, "no block stage loaded")
		require.Len(t, calls, 1)
		assert.Subset(t, calls[0], allBlockProgramNames())
	})

	t.Run("load fails with block off: nothing left to degrade", func(t *testing.T) {
		calls := 0
		load := func([]string) error { calls++; return loadErr }
		_, err := loadWithBlockFallback(load, baseDisable, nil, quietLog)
		require.ErrorIs(t, err, loadErr)
		assert.Equal(t, 1, calls)
	})

	t.Run("tp_btf rejected: raw_tp alone", func(t *testing.T) {
		var calls [][]string
		load := func(toDisable []string) error {
			calls = append(calls, slices.Clone(toDisable))
			if len(calls) == 1 {
				return loadErr
			}
			return nil
		}
		stage, err := loadWithBlockFallback(load, baseDisable, stages, quietLog)
		require.NoError(t, err)
		assert.Equal(t, 1, stage)
		require.Len(t, calls, 2)
		assert.Subset(t, calls[1], tpBtf.programs(), "the tp_btf programs are stubbed on the retry")
		for _, p := range rawTp.programs() {
			assert.NotContains(t, calls[1], p)
		}
		assert.Contains(t, calls[1], progObiStatsKprobeTCPCloseSrtt, "original disable list preserved on retry")
		assert.Equal(t, []string{progObiStatsKprobeTCPCloseSrtt}, baseDisable, "the caller's list is not modified")
	})

	t.Run("every block stage rejected: degrade to no block programs", func(t *testing.T) {
		var calls [][]string
		load := func(toDisable []string) error {
			calls = append(calls, slices.Clone(toDisable))
			if len(calls) <= 2 {
				return loadErr
			}
			return nil
		}
		stage, err := loadWithBlockFallback(load, baseDisable, stages, quietLog)
		require.NoError(t, err)
		assert.Equal(t, len(stages), stage, "storage block reported off")
		require.Len(t, calls, 3)
		assert.Subset(t, calls[2], allBlockProgramNames())
	})

	t.Run("every load fails: the error surfaces", func(t *testing.T) {
		var calls int
		load := func([]string) error { calls++; return loadErr }
		_, err := loadWithBlockFallback(load, baseDisable, stages, quietLog)
		require.ErrorIs(t, err, loadErr)
		assert.Equal(t, 3, calls)
	})
}

type fakeLink struct{ closed *int }

func (f fakeLink) Close() error { *f.closed++; return nil }

func TestAttachBlockSets(t *testing.T) {
	quietLog := slog.New(slog.DiscardHandler)
	layout := blockTracepointLayout{}
	tpBtf, rawTp := tpBtfBlockPrograms(layout), rawTpBlockPrograms(layout)
	attachErr := errors.New("attach failed")

	t.Run("tp_btf attaches", func(t *testing.T) {
		var tried []blockAttach
		links, got := attachBlockSets([]blockProgramSet{tpBtf, rawTp}, func(set blockProgramSet) ([]io.Closer, error) {
			tried = append(tried, set.attach)
			return []io.Closer{fakeLink{closed: new(int)}}, nil
		}, quietLog)
		assert.Equal(t, blockAttachTpBtf, got)
		assert.Len(t, links, 1)
		assert.Equal(t, []blockAttach{blockAttachTpBtf}, tried)
	})

	t.Run("tp_btf attach fails: raw_tp, already loaded next to it", func(t *testing.T) {
		var tried []blockAttach
		_, got := attachBlockSets([]blockProgramSet{tpBtf, rawTp}, func(set blockProgramSet) ([]io.Closer, error) {
			tried = append(tried, set.attach)
			if set.attach == blockAttachTpBtf {
				return nil, attachErr
			}
			return nil, nil
		}, quietLog)
		assert.Equal(t, blockAttachRawTp, got)
		assert.Equal(t, []blockAttach{blockAttachTpBtf, blockAttachRawTp}, tried)
	})

	t.Run("nothing attaches: block off", func(t *testing.T) {
		links, got := attachBlockSets([]blockProgramSet{tpBtf, rawTp}, func(blockProgramSet) ([]io.Closer, error) {
			return nil, attachErr
		}, quietLog)
		assert.Equal(t, blockAttachNone, got)
		assert.Empty(t, links)
	})
}

// A set whose programs were not loaded does not attach.
func TestAttachBlockProgramSetMissingProgram(t *testing.T) {
	set := rawTpBlockPrograms(blockTracepointLayout{})
	_, err := attachBlockProgramSet(map[string]*ebpf.Program{}, set)
	require.Error(t, err)
}
