// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
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
