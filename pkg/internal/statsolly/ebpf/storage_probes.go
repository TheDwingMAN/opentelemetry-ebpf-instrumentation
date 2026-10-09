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
	layout   blockTracepointLayout
	disk     bool
	disabled []DisabledFeature
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
	return s
}

func (s *storageProbes) disable(feature string, reason error) {
	s.disabled = append(s.disabled, DisabledFeature{Feature: feature, Reason: reason.Error()})
}

// disableAll disables every storage feature that has programs to load
func (s *storageProbes) disableAll(reason error) {
	if s.disk {
		s.disable(featureDisk, reason)
	}
	s.disk = false
}

// programsToDisable returns the storage programs that must not be loaded
func (s *storageProbes) programsToDisable() []string {
	return diskProgramsToDisable(s.disk, s.layout)
}

// loadOrDisable loads the stats programs with the storage ones. When they can't be loaded, as OBI
// does with an optional tracer that can't be loaded, it disables the storage features and loads the
// stats programs without them. If that fails too, it returns both errors.
func (s *storageProbes) loadOrDisable(load func(toDisable []string) error, tcpToDisable []string) error {
	err := load(slices.Concat(tcpToDisable, s.programsToDisable()))
	if err == nil || !s.disk {
		return err
	}
	s.disableAll(fmt.Errorf("can't load their BPF programs: %w", err))
	if retryErr := load(slices.Concat(tcpToDisable, s.programsToDisable())); retryErr != nil {
		return errors.Join(err, retryErr)
	}
	return nil
}

// attach attaches the loaded storage probes, or none of them
func (s *storageProbes) attach(objects *StatsObjects) ([]io.Closer, error) {
	if !s.disk {
		return nil, nil
	}
	// the completions are attached before the issues, so that no request is timed without its
	// completion being measured
	issue := objects.ObiStatsRawTpBlockRqIssue
	if s.layout.issueHasQueueArg {
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
// charged to, for the container attribute
type diskReads struct {
	cgroup bool
}

// diskAttributeReads returns the attributes of the block I/O that the enabled disk metrics report
// or that the filters match
func diskAttributeReads(features *export.Features, attrSel *attributes.AttrSelector, filtered []attr.Name) diskReads {
	metrics := []struct {
		enabled bool
		name    attributes.Name
	}{
		{enabled: features.StatsDiskServiceDuration(), name: attributes.StatDiskServiceDuration},
		{enabled: features.StatsDiskIO(), name: attributes.StatDiskIO},
		{enabled: features.StatsDiskOperations(), name: attributes.StatDiskOperations},
		{enabled: features.StatsDiskServiceTime(), name: attributes.StatDiskServiceTime},
	}
	var reads diskReads
	for _, metric := range metrics {
		if metric.enabled && slices.ContainsFunc(slices.Concat(attrSel.For(metric.name), filtered), reportsWorkload) {
			reads.cgroup = true
		}
	}
	return reads
}

// reportsWorkload tells whether an attribute describes the workload that the kernel charges an
// operation to, which the probes find from its cgroup
func reportsWorkload(name attr.Name) bool {
	return sameAttribute(name, attr.ContainerID)
}

// sameAttribute tells whether two attribute names, with dots or underscores, are the same
func sameAttribute(name, other attr.Name) bool {
	return name.Prom() == other.Prom()
}
