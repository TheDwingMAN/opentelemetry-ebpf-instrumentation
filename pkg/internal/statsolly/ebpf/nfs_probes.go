// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
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
