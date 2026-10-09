// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"

	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// featureDisk names the disk stats features in a DisabledFeature
const featureDisk = "the block I/O metrics (the disk_* stats features)"

// storageProbes tells which storage probes are loaded and attached. The storage features are
// optional: an enabled one whose probes can't be loaded or attached is disabled, with the reason,
// and the other stats keep working.
type storageProbes struct {
	layout blockTracepointLayout
	disk   bool
	fsSync bool
	// fsSyncTracing are the file sync hooks, by function, whose fentry and fexit programs are
	// loaded: the kprobes of the others are attached instead
	fsSyncTracing map[string]bool
	// fsSyncMechanisms are the probe mechanisms of the attached file sync hooks, by function
	fsSyncMechanisms map[string]string
	disabled         []DisabledFeature
}

// planStorageProbes returns the storage probes of the enabled features that the kernel can load.
func planStorageProbes(log *slog.Logger, features *export.Features) storageProbes {
	var s storageProbes
	if features.StatsDisk() {
		var err error
		if s.layout, err = kernelBlockTracepointLayout(log); err != nil {
			s.disable(featureDisk, fmt.Errorf("can't tell the block tracepoint arguments from the kernel BTF: %w", err))
		} else {
			s.disk = true
		}
	}
	if features.StatsFsSync() {
		s.fsSync = true
		s.fsSyncTracing = kernelFsSyncTracingHooks(log)
	}
	return s
}

func (s *storageProbes) disable(feature string, reason error) {
	s.disabled = append(s.disabled, DisabledFeature{Feature: feature, Reason: reason.Error()})
}

// any tells whether any storage feature has programs to load
func (s *storageProbes) any() bool {
	return s.disk || s.fsSync
}

// disableAll disables every storage feature that has programs to load
func (s *storageProbes) disableAll(reason error) {
	if s.disk {
		s.disable(featureDisk, reason)
	}
	if s.fsSync {
		s.disable(featureFsSync, reason)
	}
	s.disk, s.fsSync = false, false
}

// programsToDisable returns the storage programs that must not be loaded
func (s *storageProbes) programsToDisable() []string {
	toDisable := diskProgramsToDisable(s.disk, s.layout)
	if !s.fsSync {
		return append(toDisable, fsSyncProgramNames()...)
	}
	return append(toDisable, fsSyncTracingProgramsToDisable(s.fsSyncTracing)...)
}

// loadOrDisable loads the stats programs with the storage ones. A file sync hook whose fentry or
// fexit program the kernel can't load is probed with kprobes, and the programs are loaded again. As
// OBI does with an optional tracer that can't be loaded, a storage feature with another program
// that the kernel can't load is disabled, and the stats programs are loaded without it. When the
// error names no storage program, it disables every storage feature and loads the stats programs
// without them. If that fails too, it returns both errors.
func (s *storageProbes) loadOrDisable(load func(toDisable []string) error, tcpToDisable []string) error {
	err := load(slices.Concat(tcpToDisable, s.programsToDisable()))
	for err != nil && s.dropProgramsOf(err) {
		err = load(slices.Concat(tcpToDisable, s.programsToDisable()))
	}
	if err == nil || !s.any() {
		return err
	}
	s.disableAll(fmt.Errorf("can't load their BPF programs: %w", err))
	if retryErr := load(slices.Concat(tcpToDisable, s.programsToDisable())); retryErr != nil {
		return errors.Join(err, retryErr)
	}
	return nil
}

// dropProgramsOf drops the storage programs of a load error that names one: the fentry and fexit
// programs of a file sync hook, which is probed with kprobes instead, or else the programs of the
// storage feature of the program. It tells whether it dropped any.
func (s *storageProbes) dropProgramsOf(err error) bool {
	if hook, ok := fsSyncTracingHookOf(err, s.fsSyncTracing); s.fsSync && ok {
		tlog().Debug("can't load the fentry and fexit programs of a file sync function: probing it with kprobes",
			"function", hook, "error", err)
		delete(s.fsSyncTracing, hook)
		return true
	}
	reason := fmt.Errorf("can't load their BPF programs: %w", err)
	if s.fsSync && loadErrorNamesAny(err, fsSyncProgramNames()) {
		s.fsSync = false
		s.disable(featureFsSync, reason)
		return true
	}
	if s.disk && loadErrorNamesAny(err, diskProgramsToDisable(false, s.layout)) {
		s.disk = false
		s.disable(featureDisk, reason)
		return true
	}
	return false
}

// attach attaches the probes of the loaded storage features. A feature whose probes can't be
// attached is disabled, and the error tells to load the stats programs again without its programs:
// then no storage probe is attached.
func (s *storageProbes) attach(log *slog.Logger, objects *StatsObjects) ([]io.Closer, error) {
	var closables []io.Closer
	if s.disk {
		links, err := attachDisk(objects, s.layout)
		if err != nil {
			s.disk = false
			s.disable(featureDisk, err)
			return nil, err
		}
		closables = append(closables, links...)
	}
	if s.fsSync {
		links, mechanisms, err := attachFsSync(log, objects, s.fsSyncTracing)
		if err != nil {
			s.fsSync = false
			s.disable(featureFsSync, err)
			closeAll(closables)
			return nil, err
		}
		closables = append(closables, links...)
		s.fsSyncMechanisms = mechanisms
		logFsSyncMechanisms(log, mechanisms)
	}
	return closables, nil
}

// attachDisk attaches the disk probes, or none of them
func attachDisk(objects *StatsObjects, layout blockTracepointLayout) ([]io.Closer, error) {
	// the completions are attached before the issues, so that no request is timed without its
	// completion being measured
	issue := objects.ObiStatsRawTpBlockRqIssue
	if layout.issueHasQueueArg {
		issue = objects.ObiStatsRawTpBlockRqIssueLegacy
	}
	return attachRawTracepoints([]probe{
		{name: RawTracepointBlockRqComplete, program: objects.ObiStatsRawTpBlockRqComplete},
		{name: RawTracepointBlockRqIssue, program: issue},
	})
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

// diskReads tells which attributes of the block I/O the disk probes read: the cgroup the I/O is
// charged to, for the container and Kubernetes attributes
type diskReads struct {
	cgroup bool
}

// diskAttributeReads returns the attributes of the block I/O that the enabled disk metrics report
// or that the filters match, and the workload of all the I/O when reads asks for it
func diskAttributeReads(features *export.Features, attrSel *attributes.AttrSelector, reads ProbeReads) diskReads {
	return diskReads{cgroup: readsWorkload([]storageMetric{
		{enabled: features.StatsDiskServiceDuration(), name: attributes.StatDiskServiceDuration},
		{enabled: features.StatsDiskIO(), name: attributes.StatDiskIO},
		{enabled: features.StatsDiskOperations(), name: attributes.StatDiskOperations},
		{enabled: features.StatsDiskServiceTime(), name: attributes.StatDiskServiceTime},
	}, attrSel, reads)}
}

// fsSyncReads tells which attributes of the file syncs the file sync probes read: the cgroup of the
// thread that syncs, for the container and Kubernetes attributes
type fsSyncReads struct {
	cgroup bool
}

// fsSyncAttributeReads returns the attributes of the file syncs that the enabled file sync metrics
// report or that the filters match, and the workload of all the syncs when reads asks for it
func fsSyncAttributeReads(features *export.Features, attrSel *attributes.AttrSelector, reads ProbeReads) fsSyncReads {
	return fsSyncReads{cgroup: readsWorkload([]storageMetric{
		{enabled: features.StatsFsSyncDuration(), name: attributes.StatFsSyncDuration},
	}, attrSel, reads)}
}

// storageMetric is a storage stat metric, and whether it is enabled
type storageMetric struct {
	enabled bool
	name    attributes.Name
}

// readsWorkload tells whether the probes of the given metrics read the workload that the kernel
// charges each operation to: when an enabled metric reports, or a filter matches, an attribute of
// the workload, or when reads asks for the workload of every operation
func readsWorkload(metrics []storageMetric, attrSel *attributes.AttrSelector, reads ProbeReads) bool {
	if reads.Workloads {
		return true
	}
	return slices.ContainsFunc(metrics, func(metric storageMetric) bool {
		return metric.enabled && slices.ContainsFunc(slices.Concat(attrSel.For(metric.name), reads.Filtered), reportsWorkload)
	})
}

// workloadAttributes are the attributes of the storage stats that describe the workload that the
// kernel charges an operation to, which the probes find from its cgroup: the container, and its pod
// and workload in Kubernetes. The cluster name is the same for every workload.
var workloadAttributes = []attr.Name{
	attr.ContainerID, attr.K8sNamespaceName, attr.K8sOwnerName, attr.K8sKind, attr.K8sPodName, attr.K8sContainerName,
}

// reportsWorkload tells whether an attribute describes the workload that the kernel charges an
// operation to
func reportsWorkload(name attr.Name) bool {
	return slices.ContainsFunc(workloadAttributes, func(workload attr.Name) bool {
		return sameAttribute(name, workload)
	})
}

// sameAttribute tells whether two attribute names, with dots or underscores, are the same
func sameAttribute(name, other attr.Name) bool {
	return name.Prom() == other.Prom()
}
