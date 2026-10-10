// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// When the storage programs can't be loaded, the stats go on without any of them
func TestStorageProbesDisableAll(t *testing.T) {
	storage := storageProbes{disk: true}
	assert.True(t, storage.disk)
	assert.NotContains(t, storage.programsToDisable(), progObiStatsRawTpBlockRqComplete)

	storage.disableAll(errors.New("verifier error"))

	assert.False(t, storage.disk)
	assert.Equal(t, []DisabledFeature{
		{Feature: featureDiskServiceDuration, Reason: "verifier error"},
	}, storage.disabled)
	toDisable := storage.programsToDisable()
	for _, program := range []string{
		progObiStatsRawTpBlockRqIssue, progObiStatsRawTpBlockRqIssueLegacy, progObiStatsRawTpBlockRqComplete,
	} {
		assert.Contains(t, toDisable, program)
	}
}

// When the storage programs can't be loaded, the stats programs are loaded again without them
func TestStorageProbesLoadOrDisable(t *testing.T) {
	storage := storageProbes{disk: true}
	var loads [][]string
	err := storage.loadOrDisable(func(toDisable []string) error {
		loads = append(loads, toDisable)
		if len(loads) == 1 {
			return errors.New("verifier error")
		}
		return nil
	}, []string{progObiStatsKprobeTCPCleanupRbuf})

	require.NoError(t, err)
	require.Len(t, loads, 2)
	assert.NotContains(t, loads[0], progObiStatsRawTpBlockRqComplete)
	assert.Contains(t, loads[1], progObiStatsRawTpBlockRqComplete)
	assert.Contains(t, loads[1], progObiStatsKprobeTCPCleanupRbuf)
	assert.Equal(t, []DisabledFeature{
		{Feature: featureDiskServiceDuration, Reason: "can't load their BPF programs: verifier error"},
	}, storage.disabled)
}

// When the stats programs can't be loaded without the storage ones either, both errors are returned
func TestStorageProbesLoadOrDisableReturnsBothErrors(t *testing.T) {
	withStorage, withoutStorage := errors.New("verifier error"), errors.New("operation not permitted")
	storage := storageProbes{disk: true}
	loads := 0
	err := storage.loadOrDisable(func([]string) error {
		loads++
		if loads == 1 {
			return withStorage
		}
		return withoutStorage
	}, nil)

	require.ErrorIs(t, err, withStorage)
	require.ErrorIs(t, err, withoutStorage)
	assert.Equal(t, 2, loads)
}
