// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// When the storage programs can't be loaded, the stats go on without any of them
func TestStorageProbesDisableAll(t *testing.T) {
	storage := storageProbes{
		disk: true,
		nfs:  nfsLoad{statsLatency: true, pgio: true},
	}
	assert.True(t, storage.disk)
	assert.NotContains(t, storage.programsToDisable(), progObiStatsRawTpBlockRqComplete)
	assert.NotContains(t, storage.programsToDisable(), progObiStatsRawTpRPCStatsLatency)

	storage.disableAll(errors.New("verifier error"))

	assert.False(t, storage.disk)
	assert.Equal(t, nfsLoad{}, storage.nfs)
	assert.Equal(t, []DisabledFeature{
		{Feature: featureDisk, Reason: "verifier error"},
		{Feature: featureNFSProcedures, Reason: "verifier error"},
		{Feature: featureNFSIO, Reason: "verifier error"},
	}, storage.disabled)
	toDisable := storage.programsToDisable()
	for _, program := range []string{
		progObiStatsRawTpBlockRqIssue, progObiStatsRawTpBlockRqIssueLegacy, progObiStatsRawTpBlockRqComplete,
		progObiStatsRawTpRPCStatsLatency, progObiStatsRawTpNFSReadpageDone, progObiStatsRawTpNFSWritebackDone,
	} {
		assert.Contains(t, toDisable, program)
	}
}

// An NFS client program that the kernel can't load disables the NFS client stats only
func TestStorageProbesDisableTheNFSStatsWhenTheirProgramsCantBeLoaded(t *testing.T) {
	storage := storageProbes{disk: true, nfs: nfsLoad{statsLatency: true, pgio: true}}
	failure := "program " + progObiStatsRawTpNFSWritebackDone + ": load program: invalid argument"
	var loads [][]string
	err := storage.loadOrDisable(func(toDisable []string) error {
		loads = append(loads, toDisable)
		if len(loads) == 1 {
			return errors.New(failure)
		}
		return nil
	}, nil)

	require.NoError(t, err)
	require.Len(t, loads, 2)
	assert.True(t, storage.disk)
	assert.NotContains(t, loads[1], progObiStatsRawTpBlockRqComplete)
	assert.Subset(t, loads[1], nfsLoad{}.programsToDisable())
	assert.Equal(t, []DisabledFeature{
		{Feature: featureNFSProcedures, Reason: "can't load their BPF programs: " + failure},
		{Feature: featureNFSIO, Reason: "can't load their BPF programs: " + failure},
	}, storage.disabled)
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
		{Feature: featureDisk, Reason: "can't load their BPF programs: verifier error"},
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

func TestDiskAttributeReads(t *testing.T) {
	selecting := func(metric attributes.Name, include ...string) *attributes.SelectorConfig {
		return &attributes.SelectorConfig{SelectionCfg: attributes.Selection{
			metric.Section: attributes.InclusionLists{Include: include},
		}}
	}
	readsIn := func(groups attributes.AttrGroups, features export.Features, selection *attributes.SelectorConfig,
		filtered ...attr.Name,
	) diskReads {
		attrSel, err := attributes.NewAttrSelector(groups, selection)
		require.NoError(t, err)
		return diskAttributeReads(&features, attrSel, ProbeReads{Filtered: filtered})
	}
	reads := func(features export.Features, selection *attributes.SelectorConfig, filtered ...attr.Name) diskReads {
		return readsIn(attributes.UndefinedGroup, features, selection, filtered...)
	}

	assert.Equal(t, diskReads{}, reads(export.FeatureStatsDisk, &attributes.SelectorConfig{}),
		"no default attribute of the disk metrics needs the cgroup")
	assert.Equal(t, diskReads{cgroup: true},
		reads(export.FeatureStatsDiskOperations, selecting(attributes.StatDiskOperations, "container.id")))
	assert.Equal(t, diskReads{cgroup: true},
		reads(export.FeatureStatsDiskServiceDuration, selecting(attributes.StatDiskServiceDuration, "container.*")))
	assert.Equal(t, diskReads{},
		reads(export.FeatureStatsDiskIO, selecting(attributes.StatDiskOperations, "container.id")),
		"the attributes of disabled metrics don't count")
	assert.Equal(t, diskReads{cgroup: true},
		reads(export.FeatureStatsDiskIO, &attributes.SelectorConfig{}, "container_id"),
		"the filters need the attributes that they match, with dots or underscores")
	assert.Equal(t, diskReads{},
		reads(export.FeatureStatsTCPRtt, &attributes.SelectorConfig{}, "container.id"),
		"filters don't need reads of the disabled metrics")

	// in Kubernetes, the counters report the workload by default, and the histogram the cluster
	assert.Equal(t, diskReads{cgroup: true},
		readsIn(attributes.GroupKubernetes, export.FeatureStatsDiskOperations, &attributes.SelectorConfig{}))
	assert.Equal(t, diskReads{},
		readsIn(attributes.GroupKubernetes, export.FeatureStatsDiskServiceDuration, &attributes.SelectorConfig{}),
		"the cluster name is the same for every workload")
	assert.Equal(t, diskReads{cgroup: true},
		reads(export.FeatureStatsDiskIO, &attributes.SelectorConfig{}, "k8s_namespace_name"))
	assert.Equal(t, diskReads{},
		reads(export.FeatureStatsDiskIO, &attributes.SelectorConfig{}, "k8s.cluster.name"))
	assert.Equal(t, diskReads{},
		reads(export.FeatureStatsDiskIO, &attributes.SelectorConfig{}, "k8s_src_namespace"),
		"an attribute of the TCP stats only")
}

// Under dynamic application selection, the probes read the workload of all the I/O, which the
// selection filters on
func TestDiskAttributeReadsUnderDynamicSelection(t *testing.T) {
	attrSel, err := attributes.NewAttrSelector(attributes.UndefinedGroup, &attributes.SelectorConfig{})
	require.NoError(t, err)
	features := export.FeatureStatsDiskServiceDuration
	assert.Equal(t, diskReads{}, diskAttributeReads(&features, attrSel, ProbeReads{}))
	assert.Equal(t, diskReads{cgroup: true}, diskAttributeReads(&features, attrSel, ProbeReads{Workloads: true}))
}

func TestFsSyncAttributeReads(t *testing.T) {
	reads := func(groups attributes.AttrGroups, features export.Features, selection *attributes.SelectorConfig,
		probeReads ProbeReads,
	) fsSyncReads {
		attrSel, err := attributes.NewAttrSelector(groups, selection)
		require.NoError(t, err)
		return fsSyncAttributeReads(&features, attrSel, probeReads)
	}
	selecting := func(include ...string) *attributes.SelectorConfig {
		return &attributes.SelectorConfig{SelectionCfg: attributes.Selection{
			attributes.StatFsSyncDuration.Section: attributes.InclusionLists{Include: include},
		}}
	}
	fsSync := export.FeatureStatsFsSyncDuration

	assert.Equal(t, fsSyncReads{}, reads(attributes.UndefinedGroup, fsSync, &attributes.SelectorConfig{}, ProbeReads{}),
		"no default attribute of the file sync metrics needs the cgroup")
	assert.Equal(t, fsSyncReads{cgroup: true}, reads(attributes.UndefinedGroup, fsSync, selecting("container.id"), ProbeReads{}))
	assert.Equal(t, fsSyncReads{},
		reads(attributes.UndefinedGroup, export.FeatureStatsDiskIO, selecting("container.id"), ProbeReads{}),
		"the attributes of disabled metrics don't count")
	assert.Equal(t, fsSyncReads{cgroup: true},
		reads(attributes.UndefinedGroup, fsSync, &attributes.SelectorConfig{}, ProbeReads{Filtered: []attr.Name{"k8s_owner_name"}}),
		"the filters need the attributes that they match")
	assert.Equal(t, fsSyncReads{},
		reads(attributes.GroupKubernetes, fsSync, &attributes.SelectorConfig{}, ProbeReads{}),
		"in Kubernetes, the histogram reports the cluster only by default")
	for _, counter := range []export.Features{export.FeatureStatsFsSyncOperations, export.FeatureStatsFsSyncTime} {
		assert.Equal(t, fsSyncReads{cgroup: true},
			reads(attributes.GroupKubernetes, counter, &attributes.SelectorConfig{}, ProbeReads{}),
			"in Kubernetes, the counters report the workload by default")
		assert.Equal(t, fsSyncReads{}, reads(attributes.UndefinedGroup, counter, &attributes.SelectorConfig{}, ProbeReads{}),
			"outside Kubernetes, the counters have no workload attribute by default")
	}
	assert.Equal(t, fsSyncReads{cgroup: true},
		reads(attributes.UndefinedGroup, fsSync, &attributes.SelectorConfig{}, ProbeReads{Workloads: true}),
		"dynamic application selection needs the workload of every sync")
}
