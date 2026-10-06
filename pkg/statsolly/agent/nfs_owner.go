// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/statsolly/agent"

import (
	"os"
	"slices"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
)

// nfsOwnerAttrs are the pod trio and k8s.owner.name: selecting any of them on
// an NFS metric (step 19) turns the owner on in the kernel key.
var nfsOwnerAttrs = []attr.Name{attr.K8sNamespaceName, attr.K8sPodName, attr.K8sContainerName, attr.K8sOwnerName}

// nfsOwnerMetrics are the NFS metrics whose opt-in attributes can select an
// owner (1.1): the three rpc.* metrics and the io metric.
var nfsOwnerMetrics = []attributes.Name{
	attributes.StatNFSClientRPCDuration, attributes.StatNFSClientRPCErrors,
	attributes.StatNFSClientRPCRetransmits, attributes.StatNFSClientIO,
}

// nfsOwnerWanted reports whether a pod attribute is selected on any NFS
// metric: the rpc_task_begin program attaches, and the kernel key keeps an
// owner, only then (2.5).
func nfsOwnerWanted(attrSel *attributes.AttrSelector) bool {
	for _, metric := range nfsOwnerMetrics {
		for _, name := range attrSel.For(metric) {
			if slices.Contains(nfsOwnerAttrs, name) {
				return true
			}
		}
	}
	return false
}

// sysFSCgroupControllers exists only on the unified (cgroup v2) hierarchy.
const sysFSCgroupControllers = "/sys/fs/cgroup/cgroup.controllers"

// nfsCgroupV1 reports whether this host has no delegated cgroup v2
// hierarchy: bpf_get_current_cgroup_id() would then return the root cgroup
// for every task (S0-d), so the NFS owner (step 19) is read from
// task->tk_owner, a thread id, resolved by the pid path instead. Checked
// once at startup; an injectable indirection for tests.
var nfsCgroupV1 = func() bool {
	_, err := os.Stat(sysFSCgroupControllers)
	return err != nil
}

// newNFSOwnerDecorate returns what newAggregatedStatDecorator does to
// attribute an NFS RPC stat to its submitting pod (step 19): nil when no
// pod attribute is selected or Kubernetes is disabled. On a cgroup v2 host
// it builds s.nfsCgroupIndex once, which Run starts scanning once the
// pipeline is up; on cgroup v1 it resolves by the pid path instead and
// needs no index.
func (s *Stats) newNFSOwnerDecorate() func(*ebpf.Stat) {
	if !s.nfsOwner || s.aggDeps.store == nil {
		return nil
	}
	if !s.nfsCgroupV1 && s.nfsCgroupIndex == nil {
		s.nfsCgroupIndex = statagg.NewCgroupIndex()
	}
	return stats.NewNFSOwnerDecorator(s.aggDeps.store, s.nfsCgroupIndex, s.nfsCgroupV1)
}
