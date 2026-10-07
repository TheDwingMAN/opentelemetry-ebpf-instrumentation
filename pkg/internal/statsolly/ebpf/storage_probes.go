// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/export"
)

// The storage features that probes serve, as DisabledFeature names them
const (
	featureDiskRequests   = "the block I/O metrics (stats_disk_*)"
	featureStackedVolumes = "the I/O of the stacked volumes (stats_disk_stacked_volumes)"
	featureFsSync         = "the file sync metrics (stats_fs_sync_*)"
	featureNFSProcedures  = "the NFS client procedure metrics (stats_nfs_client_procedure_*)"
	featureNFSIO          = "the NFS client I/O metric (stats_nfs_client_io)"
)

// fsSyncPrograms are the programs of the file sync metric
var fsSyncPrograms = []string{
	progObiStatsKprobeVfsFsyncRange, progObiStatsKretprobeVfsFsyncRange,
	progObiStatsKprobeDoFsync, progObiStatsKretprobeDoFsync,
	progObiStatsKprobeSysFsync, progObiStatsKprobeSysFdatasync, progObiStatsKprobeSysSyncfs,
	progObiStatsKprobeSysSyncFileRange, progObiStatsKprobeSysSync, progObiStatsKretprobeSysFsSync,
}

// storageProbes tells which storage probes are loaded and attached. The storage features are
// optional: an enabled one whose probes can't be loaded or attached is disabled, with the reason,
// and the other stats keep working.
type storageProbes struct {
	layout blockTracepointLayout
	disk   bool
	bio    bool
	fsSync bool
	nfs    nfsLoad
	// nfsAttached tells which NFS probes could be attached
	nfsAttached nfsAttached
	disabled    []DisabledFeature
}

// planStorageProbes returns the storage probes of the enabled features that the kernel can load
func planStorageProbes(log *slog.Logger, features *export.Features) storageProbes {
	var s storageProbes
	if features.StatsDisk() {
		var err error
		if s.layout, err = kernelBlockTracepointLayout(log); err != nil {
			s.disable(featureDiskRequests, fmt.Errorf("can't tell the block tracepoint arguments from the kernel BTF: %w", err))
		} else {
			s.disk = true
		}
	}
	if s.disk && features.StatsDiskStackedVolumes() {
		if s.layout.bioUnknown {
			s.disable(featureStackedVolumes, errors.New("can't tell the block_bio_queue tracepoint arguments from the kernel BTF"))
		} else {
			s.bio = true
		}
	}
	s.fsSync = features.StatsFsSync()
	if features.StatsNFS() {
		probes := kernelNFSProbes()
		if features.StatsNFSClientProcedures() && probes.rpc != nil {
			s.disable(featureNFSProcedures, probes.rpc)
		}
		if features.StatsNFSClientIO() && probes.pgio != nil {
			s.disable(featureNFSIO, probes.pgio)
		}
		s.nfs = nfsLoadFor(features, probes)
	}
	return s
}

func (s *storageProbes) disable(feature string, reason error) {
	s.disabled = append(s.disabled, DisabledFeature{Feature: feature, Reason: reason.Error()})
}

// any tells whether any storage program is loaded
func (s *storageProbes) any() bool {
	return s.disk || s.bio || s.fsSync || s.nfs != nfsLoad{}
}

// disableAll disables every storage feature that has programs to load
func (s *storageProbes) disableAll(reason error) {
	if s.disk {
		s.disable(featureDiskRequests, reason)
	}
	if s.bio {
		s.disable(featureStackedVolumes, reason)
	}
	if s.fsSync {
		s.disable(featureFsSync, reason)
	}
	if s.nfs.statsLatency {
		s.disable(featureNFSProcedures, reason)
	}
	if s.nfs.pgio {
		s.disable(featureNFSIO, reason)
	}
	s.disk, s.bio, s.fsSync, s.nfs = false, false, false, nfsLoad{}
}

// programsToDisable returns the storage programs that must not be loaded
func (s *storageProbes) programsToDisable() []string {
	toDisable := diskProgramsToDisable(s.disk, s.layout)
	toDisable = append(toDisable, bioProgramsToDisable(s.bio, s.layout)...)
	if !s.fsSync {
		toDisable = append(toDisable, fsSyncPrograms...)
	}
	return append(toDisable, s.nfs.programsToDisable()...)
}

// attach attaches the loaded storage probes, and disables the features whose probes can't be
// attached
func (s *storageProbes) attach(log *slog.Logger, objects *StatsObjects) []io.Closer {
	var closables []io.Closer
	if s.fsSync {
		links, err := attachFsSync(log, objects)
		if err != nil {
			s.fsSync = false
			s.disable(featureFsSync, err)
		}
		closables = append(closables, links...)
	}
	if s.disk {
		// the completions are attached before the issues, so that no request is timed without
		// its completion being measured
		issue := objects.ObiStatsRawTpBlockRqIssue
		if s.layout.issueHasQueueArg {
			issue = objects.ObiStatsRawTpBlockRqIssueLegacy
		}
		links, err := attachRawTracepoints([]probe{
			{name: RawTracepointBlockRqComplete, program: objects.ObiStatsRawTpBlockRqComplete},
			{name: RawTracepointBlockRqIssue, program: issue},
		})
		if err != nil {
			s.disk = false
			s.disable(featureDiskRequests, err)
		}
		closables = append(closables, links...)
	}
	if s.bio && !s.disk {
		s.bio = false
		s.disable(featureStackedVolumes, errors.New("the block I/O probes can't be attached"))
	}
	if s.bio {
		// the completions are attached before the starts, so that no start is recorded without
		// its completion being measured: a stale start of a bio would be matched by another bio
		// that reuses its memory
		queue := objects.ObiStatsRawTpBlockBioQueue
		if s.layout.bioQueueHasQueueArg {
			queue = objects.ObiStatsRawTpBlockBioQueueLegacy
		}
		links, err := attachRawTracepoints([]probe{
			{name: RawTracepointBlockBioComplete, program: objects.ObiStatsRawTpBlockBioComplete},
			{name: RawTracepointBlockBioQueue, program: queue},
		})
		if err != nil {
			s.disable(featureStackedVolumes, err)
		}
		closables = append(closables, links...)
		s.bio = err == nil
	}
	var nfsClosables []io.Closer
	s.nfsAttached, nfsClosables = attachNFS(log, objects, s.nfs)
	closables = append(closables, nfsClosables...)
	if s.nfs.statsLatency && !s.nfsAttached.procedures {
		s.disable(featureNFSProcedures, errors.New("can't attach the rpc_stats_latency tracepoint"))
	}
	if s.nfs.pgio && !s.nfsAttached.bytes {
		s.disable(featureNFSIO, errors.New("can't attach the nfs_readpage_done and nfs_writeback_done tracepoints"))
	}
	return closables
}

// attachFsSync attaches the file sync probes. Those of vfs_fsync_range are needed, the others are
// attached when the kernel has their function.
func attachFsSync(log *slog.Logger, objects *StatsObjects) ([]io.Closer, error) {
	links, err := attachFsSyncPair(log, KprobeVfsFsyncRange, objects.ObiStatsKprobeVfsFsyncRange,
		objects.ObiStatsKretprobeVfsFsyncRange)
	if err != nil {
		return nil, fmt.Errorf("can't attach the %s probes: %w", KprobeVfsFsyncRange, err)
	}
	links = append(links, attachDoFsync(log, objects)...)
	return append(links, attachSyncSyscalls(log, objects)...), nil
}

// attachRawTracepoints attaches raw tracepoint programs, in order, or none of them
func attachRawTracepoints(probes []probe) ([]io.Closer, error) {
	var closables []io.Closer
	for _, t := range probes {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: t.name, Program: t.program})
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("can't attach the %s tracepoint: %w", t.name, err)
		}
		closables = append(closables, l)
	}
	return closables, nil
}
