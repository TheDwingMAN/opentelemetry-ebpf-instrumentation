// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/export"
)

// rpcTypes are the sunrpc structs that the NFS client probe reads
var rpcTypes = []string{"rpc_task", "rpc_clnt", "rpc_procinfo", "rpc_xprt"}

// kernelRPCTypes checks that the vmlinux BTF describes the sunrpc structs that the NFS client probe
// reads. The kernels whose vmlinux BTF lacks them, as Linux 5.8, whose sunrpc is a module, don't run
// the probe.
func kernelRPCTypes(kernel *btf.Spec) error {
	for _, name := range rpcTypes {
		if !hasStruct(kernel, name) {
			return fmt.Errorf("the vmlinux BTF doesn't describe the sunrpc types: it has no struct %s", name)
		}
	}
	return nil
}

// nfsRPCFeatures are the NFS client features that the probe of the completed RPCs measures
const nfsRPCFeatures = export.FeatureStatsNFSClientProcedureDuration | export.FeatureStatsNFSClientProcedureCounters

// nfsReadsCgroup tells whether the NFS client probes read the cgroup of the threads that start the
// RPCs, for the attributes of their workloads: the histogram of the node never reads it
func nfsReadsCgroup(storage export.Features, reads CgroupReads) bool {
	return reads.NFS && storage&export.FeatureStatsNFSClientWorkloads != 0
}

// nfsProgramsToDisable returns the NFS client programs that the enabled features don't run
func nfsProgramsToDisable(storage export.Features, readsCgroup bool) []string {
	var toDisable []string
	if !readsCgroup {
		toDisable = append(toDisable, StatsProgObiStatsRawTpRpcTaskBegin)
	}
	if storage&nfsRPCFeatures == 0 {
		toDisable = append(toDisable, StatsProgObiStatsRawTpRpcStatsLatency)
	}
	return toDisable
}

// nfsProbes returns the NFS client probes in their attach order, each with the features that it
// measures
func nfsProbes(objects *StatsObjects, storage export.Features, readsCgroup bool) []probe {
	return []probe{
		{
			name:    RawTracepointRPCTaskBegin,
			program: objects.ObiStatsRawTpRpcTaskBegin,
			enabled: readsCgroup,
			feature: export.FeatureStatsNFSClientWorkloads,
		},
		{
			name:    RawTracepointRPCStatsLatency,
			program: objects.ObiStatsRawTpRpcStatsLatency,
			enabled: storage&nfsRPCFeatures != 0,
			feature: nfsRPCFeatures,
		},
	}
}

// sizeNFSMaps gives the accumulation map of each disabled NFS client feature a single entry
func sizeNFSMaps(spec *ebpf.CollectionSpec, storage export.Features) {
	if !storage.StatsNFSClientProcedureDuration() {
		spec.Maps["nfs_procedure_accum"].MaxEntries = 1
	}
	if storage&export.FeatureStatsNFSClientProcedureCounters == 0 {
		spec.Maps["nfs_procedure_cgroup_accum"].MaxEntries = 1
	}
}

// attachNFS attaches the enabled NFS client probes in order, or tells that they wait for their
// kernel modules instead: the tracepoints of a module exist only while it is loaded. They are
// attached all or none: when a tracepoint doesn't exist, it closes those that it attached. Another
// failure is a storageError of the features of the probe.
func attachNFS(probes []probe) (links []io.Closer, waiting bool, err error) {
	for _, p := range probes {
		if !p.enabled {
			continue
		}
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    p.name,
			Program: p.program,
		})
		switch {
		case errors.Is(err, os.ErrNotExist):
			closeAll(links)
			return nil, true, nil
		case err != nil:
			closeAll(links)
			return nil, false, &storageError{
				features: p.feature,
				err:      fmt.Errorf("failed raw tracepoint attachment %s: %w", p.name, err),
			}
		}
		links = append(links, l)
	}
	return links, false, nil
}

// RefreshNFSProbes attaches the NFS client probes that wait for their kernel modules, if the modules
// are loaded now, and tells whether the probes still wait. It must not run concurrently with Close.
func (m *StatsFetcher) RefreshNFSProbes() bool {
	if len(m.nfsPending) == 0 {
		return false
	}
	links, waiting, err := attachNFS(m.nfsPending)
	if waiting {
		return true
	}
	m.nfsPending = nil
	if err != nil {
		m.log.Warn("the NFS client stats are disabled: their probes can't be attached",
			"features", (m.storage & export.FeatureStatsNFS).Names(), "error", err)
		return false
	}
	m.closables = append(m.closables, links...)
	m.log.Info("NFS client probes attached")
	return false
}
