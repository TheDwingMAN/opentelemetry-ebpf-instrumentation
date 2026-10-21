// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"os"

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

// nfsProgramsToDisable returns the NFS client program when the NFS client stats are disabled
func nfsProgramsToDisable(enabled bool) []string {
	if enabled {
		return nil
	}
	return []string{StatsProgObiStatsRawTpRpcStatsLatency}
}

// attachNFS attaches the NFS client probe, or tells that it waits for the sunrpc module instead: the
// tracepoints of a module exist only while it is loaded
func attachNFS(objects *StatsObjects) (l link.Link, waiting bool, err error) {
	l, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    RawTracepointRPCStatsLatency,
		Program: objects.ObiStatsRawTpRpcStatsLatency,
	})
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, true, nil
	case err != nil:
		return nil, false, fmt.Errorf("failed raw tracepoint attachment %s: %w", RawTracepointRPCStatsLatency, err)
	}
	return l, false, nil
}

// RefreshNFSProbes attaches the NFS client probe that waits for the sunrpc module, if the module is
// loaded now, and tells whether the probe still waits. It must not run concurrently with Close.
func (m *StatsFetcher) RefreshNFSProbes() bool {
	if !m.nfsWaiting {
		return false
	}
	l, waiting, err := attachNFS(m.objects)
	if waiting {
		return true
	}
	m.nfsWaiting = false
	if err != nil {
		m.log.Warn("the NFS client stats are disabled: their probe can't be attached",
			"features", export.FeatureStatsNFS.Names(), "error", err)
		return false
	}
	m.closables = append(m.closables, l)
	m.log.Info("NFS client probe attached")
	return false
}
