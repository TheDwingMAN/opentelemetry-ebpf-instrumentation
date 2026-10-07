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
	storage := storageProbes{
		disk: true, bio: true, fsSync: true,
		nfs: nfsLoad{taskBegin: true, statsLatency: true, pgio: true},
	}
	assert.True(t, storage.any())
	assert.NotContains(t, storage.programsToDisable(), progObiStatsKprobeVfsFsyncRange)

	storage.disableAll(errors.New("verifier error"))

	assert.False(t, storage.any())
	assert.Equal(t, []DisabledFeature{
		{Feature: featureDiskRequests, Reason: "verifier error"},
		{Feature: featureStackedVolumes, Reason: "verifier error"},
		{Feature: featureFsSync, Reason: "verifier error"},
		{Feature: featureNFSProcedures, Reason: "verifier error"},
		{Feature: featureNFSIO, Reason: "verifier error"},
	}, storage.disabled)
	toDisable := storage.programsToDisable()
	for _, program := range []string{
		progObiStatsRawTpBlockRqIssue, progObiStatsRawTpBlockRqIssueLegacy, progObiStatsRawTpBlockRqComplete,
		progObiStatsRawTpBlockBioQueue, progObiStatsRawTpBlockBioQueueLegacy, progObiStatsRawTpBlockBioComplete,
		progObiStatsRawTpRPCTaskBegin, progObiStatsRawTpRPCStatsLatency,
		progObiStatsRawTpNFSReadpageDone, progObiStatsRawTpNFSWritebackDone,
	} {
		assert.Contains(t, toDisable, program)
	}
	for _, program := range fsSyncPrograms {
		assert.Contains(t, toDisable, program)
	}
}

// Only the features that were going to load programs are reported as disabled
func TestStorageProbesDisableAllOnlyTheLoadedFeatures(t *testing.T) {
	storage := storageProbes{fsSync: true}
	storage.disableAll(errors.New("no kprobes"))
	assert.Equal(t, []DisabledFeature{{Feature: featureFsSync, Reason: "no kprobes"}}, storage.disabled)
}

// When the storage programs can't be loaded, the stats programs are loaded again without them
func TestStorageProbesLoadOrDisable(t *testing.T) {
	storage := storageProbes{fsSync: true}
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
	assert.NotContains(t, loads[0], progObiStatsKprobeVfsFsyncRange)
	assert.Contains(t, loads[1], progObiStatsKprobeVfsFsyncRange)
	assert.Contains(t, loads[1], progObiStatsKprobeTCPCleanupRbuf)
	assert.Equal(t, []DisabledFeature{
		{Feature: featureFsSync, Reason: "can't load their BPF programs: verifier error"},
	}, storage.disabled)
}

// When the stats programs can't be loaded without the storage ones either, both errors are returned
func TestStorageProbesLoadOrDisableReturnsBothErrors(t *testing.T) {
	withStorage, withoutStorage := errors.New("verifier error"), errors.New("operation not permitted")
	storage := storageProbes{fsSync: true}
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
