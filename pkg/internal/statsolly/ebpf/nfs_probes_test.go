// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
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

// Each NFS client probe runs for the features that it measures: the start of the RPCs only when their
// cgroup is read, which the histogram never needs. A failed attach disables the features of its probe.
func TestNFSProbeFeatures(t *testing.T) {
	attached := func(storage export.Features, reads CgroupReads) map[string]export.Features {
		readsCgroup := nfsReadsCgroup(storage, reads)
		probes := map[string]export.Features{}
		for _, p := range nfsProbes(&StatsObjects{}, storage, readsCgroup) {
			if p.enabled {
				probes[p.name] = p.feature
			}
		}
		assert.Len(t, nfsProgramsToDisable(storage, readsCgroup), len(nfsProbes(&StatsObjects{}, 0, false))-len(probes), "the others are stubs")
		return probes
	}
	rpcFeatures := export.FeatureStatsNFSClientProcedureDuration | export.FeatureStatsNFSClientProcedureCounters
	rpcs := map[string]export.Features{RawTracepointRPCStatsLatency: rpcFeatures}
	both := map[string]export.Features{
		RawTracepointRPCTaskBegin:    export.FeatureStatsNFSClientWorkloads,
		RawTracepointRPCStatsLatency: rpcFeatures,
	}
	assert.Empty(t, attached(export.FeatureStatsDisk, CgroupReads{NFS: true}))
	assert.Equal(t, rpcs, attached(export.FeatureStatsNFSClientProcedureDuration, CgroupReads{NFS: true}))
	assert.Equal(t, rpcs, attached(export.FeatureStatsNFSClientProcedureCount, CgroupReads{}))
	assert.Equal(t, both, attached(export.FeatureStatsNFSClientProcedureTime, CgroupReads{NFS: true}))
}

func TestSizeNFSMaps(t *testing.T) {
	const histogram, counters, tasks, names, beyond = 1 << 12, 1 << 13, 1 << 14, 1 << 13, 2 * lruLocalFreeTarget * 192
	reads := CgroupReads{NFS: true}
	for _, tc := range []struct {
		name    string
		storage export.Features
		reads   CgroupReads
		cpus    int
		// nfs_procedure_accum, nfs_procedure_cgroup_accum, nfs_task_cgroup and disk_cgroup_names
		want [4]uint32
	}{
		{name: "disabled", reads: reads, cpus: 64, want: [4]uint32{1, 1, 1, 1}},
		{name: "the histogram never reads the cgroups", storage: export.FeatureStatsNFSClientProcedureDuration, reads: reads, cpus: 64, want: [4]uint32{histogram, 1, 1, 1}},
		{name: "the counters of the node", storage: export.FeatureStatsNFSClientProcedureCount, cpus: 64, want: [4]uint32{1, counters, 1, 1}},
		{name: "the counters per workload", storage: export.FeatureStatsNFSClientProcedureCounters, reads: reads, cpus: 64, want: [4]uint32{1, counters, tasks, names}},
		{name: "beyond 64 CPUs", storage: export.FeatureStatsNFS, reads: reads, cpus: 192, want: [4]uint32{histogram, counters, beyond, names}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := LoadStats()
			require.NoError(t, err)
			sizeStorageMaps(spec, tc.storage, tc.reads, tc.cpus)
			var got [4]uint32
			for i, name := range []string{"nfs_procedure_accum", "nfs_procedure_cgroup_accum", "nfs_task_cgroup", "disk_cgroup_names"} {
				got[i] = spec.Maps[name].MaxEntries
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
