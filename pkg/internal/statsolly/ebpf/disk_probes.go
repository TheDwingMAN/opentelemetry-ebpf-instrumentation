// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"go.opentelemetry.io/obi/pkg/export"
)

// diskLatencyBuckets is the number of buckets of the kernel histograms: one per bound of
// export.DiskLatencyBounds, then the overflow bucket
const diskLatencyBuckets = len(StatsDiskIoAccumT{}.LatencyCount)

// lruLocalFreeTarget is how many free entries each CPU keeps for itself in an LRU map
// (LOCAL_FREE_TARGET in kernel/bpf/bpf_lru_list.c)
const lruLocalFreeTarget = 128

// Parameters of the btf_trace_block_rq_issue prototype: the private data of the tracepoint, then
// its arguments
const (
	blockRqIssueParams       = 2 // data, rq
	blockRqIssueLegacyParams = 3 // data, q, rq
)

// kernelBlockRqIssueHasQueueArg tells whether block_rq_issue is (q, rq) instead of (rq) in the
// kernel BTF. The kernel version can't tell: 5.10.137 and RHEL 8.6 backported the change of 5.11.
func kernelBlockRqIssueHasQueueArg() (bool, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return false, err
	}
	var issue *btf.Typedef
	if err := spec.TypeByName("btf_trace_block_rq_issue", &issue); err != nil {
		return false, err
	}
	return blockRqIssueHasQueueArg(issue)
}

func blockRqIssueHasQueueArg(issue *btf.Typedef) (bool, error) {
	var proto *btf.FuncProto
	if pointer, ok := issue.Type.(*btf.Pointer); ok {
		proto, _ = pointer.Target.(*btf.FuncProto)
	}
	switch {
	case proto == nil:
		return false, errors.New("btf_trace_block_rq_issue is not a function pointer")
	case len(proto.Params) == blockRqIssueParams:
		return false, nil
	case len(proto.Params) == blockRqIssueLegacyParams:
		return true, nil
	}
	return false, fmt.Errorf("unexpected block_rq_issue prototype with %d parameters", len(proto.Params))
}

// diskProgramsToDisable returns the disk programs that must not be loaded: all of them when the
// disk stats are disabled, and otherwise the block_rq_issue program of the other prototype
func diskProgramsToDisable(enabled, issueHasQueueArg bool) []string {
	switch {
	case !enabled:
		return []string{progObiStatsRawTpBlockRqIssue, progObiStatsRawTpBlockRqIssueLegacy, progObiStatsRawTpBlockRqComplete}
	case issueHasQueueArg:
		return []string{progObiStatsRawTpBlockRqIssue}
	default:
		return []string{progObiStatsRawTpBlockRqIssueLegacy}
	}
}

func diskIssueProgram(objects *StatsObjects, issueHasQueueArg bool) *ebpf.Program {
	if issueHasQueueArg {
		return objects.ObiStatsRawTpBlockRqIssueLegacy
	}
	return objects.ObiStatsRawTpBlockRqIssue
}

// sizeDiskMaps gives the disk maps a single entry when the disk stats are disabled, as StatsObjects
// creates them anyway. Otherwise, it gives the LRU map of the requests in flight room for twice the
// free entries that the CPUs can keep for themselves: once those hold most of the map, a CPU that
// needs an entry evicts a request in flight, until the fix of Linux 6.16 (and 6.12.39, 6.6.99).
func sizeDiskMaps(spec *ebpf.CollectionSpec, enabled bool, cpus int) {
	inFlight := spec.Maps["disk_rq_start"]
	if !enabled {
		inFlight.MaxEntries = 1
		spec.Maps["disk_io_accum"].MaxEntries = 1
		return
	}
	inFlight.MaxEntries = max(inFlight.MaxEntries, uint32(2*lruLocalFreeTarget*cpus))
}

func diskLatencyBoundsNs() [diskLatencyBuckets - 1]uint64 {
	var boundsNs [diskLatencyBuckets - 1]uint64
	for i, bound := range export.DiskLatencyBounds {
		boundsNs[i] = uint64(math.Round(bound * float64(time.Second)))
	}
	return boundsNs
}
