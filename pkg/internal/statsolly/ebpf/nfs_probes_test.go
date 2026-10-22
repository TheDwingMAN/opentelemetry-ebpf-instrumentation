// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"
)

// The NFS client probe runs where the kernel BTF describes the sunrpc structs that it reads
func TestKernelRPCTypes(t *testing.T) {
	kernel := func(structs ...string) *btf.Spec {
		types := make([]btf.Type, 0, len(structs))
		for _, name := range structs {
			types = append(types, &btf.Struct{Name: name})
		}
		return btfSpecOf(t, types...)
	}
	require.NoError(t, kernelRPCTypes(kernel("rpc_task", "rpc_clnt", "rpc_procinfo", "rpc_xprt")))
	require.EqualError(t, kernelRPCTypes(kernel("rpc_task", "rpc_clnt", "rpc_procinfo")),
		"the vmlinux BTF doesn't describe the sunrpc types: it has no struct rpc_xprt")
	require.EqualError(t, kernelRPCTypes(kernel()),
		"the vmlinux BTF doesn't describe the sunrpc types: it has no struct rpc_task", "Linux 5.8, whose sunrpc is a module")
}
