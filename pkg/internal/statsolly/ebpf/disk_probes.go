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

// Parameters of the btf_trace_<tracepoint> prototypes: the private data of the tracepoint, then
// its arguments
const (
	blockRqIssueParams         = 2 // data, rq
	blockRqIssueLegacyParams   = 3 // data, q, rq
	blockRqCompleteStatusParam = 2 // data, rq, status, nr_bytes
)

// blkStatusSize is the size of a blk_status_t, a u8
const blkStatusSize = 1

// kernelBlockTracepoints reads the prototypes of the block tracepoints in the kernel BTF: whether
// block_rq_issue is (q, rq) instead of (rq), and whether block_rq_complete reports a blk_status_t
// instead of an int errno. The kernel version can't tell: 5.10.137 and RHEL 8.6 backported the
// block_rq_issue change of 5.11.
func kernelBlockTracepoints() (issueHasQueueArg, completeReportsBlkStatus bool, err error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return false, false, err
	}
	var issue, complete *btf.Typedef
	if err = spec.TypeByName("btf_trace_block_rq_issue", &issue); err != nil {
		return false, false, err
	}
	if err = spec.TypeByName("btf_trace_block_rq_complete", &complete); err != nil {
		return false, false, err
	}
	if issueHasQueueArg, err = blockRqIssueHasQueueArg(issue); err != nil {
		return false, false, err
	}
	completeReportsBlkStatus, err = blockRqCompleteReportsBlkStatus(complete)
	return issueHasQueueArg, completeReportsBlkStatus, err
}

func blockRqIssueHasQueueArg(issue *btf.Typedef) (bool, error) {
	proto := tracepointProto(issue)
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

// blockRqCompleteReportsBlkStatus tells whether the status of block_rq_complete is a blk_status_t,
// as from Linux 5.16, instead of an int errno
func blockRqCompleteReportsBlkStatus(complete *btf.Typedef) (bool, error) {
	proto := tracepointProto(complete)
	if proto == nil || len(proto.Params) <= blockRqCompleteStatusParam {
		return false, errors.New("unexpected block_rq_complete prototype")
	}
	status, ok := btf.UnderlyingType(proto.Params[blockRqCompleteStatusParam].Type).(*btf.Int)
	if !ok {
		return false, errors.New("unexpected block_rq_complete status type")
	}
	return status.Size == blkStatusSize, nil
}

// tracepointProto returns the prototype of a btf_trace_<tracepoint> function pointer, or nil
func tracepointProto(typedef *btf.Typedef) *btf.FuncProto {
	if pointer, ok := typedef.Type.(*btf.Pointer); ok {
		proto, _ := pointer.Target.(*btf.FuncProto)
		return proto
	}
	return nil
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
