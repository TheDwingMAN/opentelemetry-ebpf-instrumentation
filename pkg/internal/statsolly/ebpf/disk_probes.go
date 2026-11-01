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
	blockTracepointParams       = 2 // data, the request or bio
	blockTracepointLegacyParams = 3 // data, q, the request or bio
	blockRqCompleteStatusParam  = 2 // data, rq, status, nr_bytes
)

// blkStatusSize is the size of a blk_status_t, a u8
const blkStatusSize = 1

// blockLayout is what the block probes need to know of the kernel, from its BTF
type blockLayout struct {
	// block_rq_issue is (q, rq) instead of (rq)
	issueHasQueueArg bool
	// block_bio_queue is (q, bio) instead of (bio), read with the bio devices
	bioQueueHasQueueArg bool
	// block_rq_complete reports a blk_status_t instead of an int errno
	completeReportsBlkStatus bool
	// the RQF_IO_STAT and RQF_FLUSH_SEQ request flags, 0 where the kernel numbers them with macros
	rqfIOStat, rqfFlushSeq uint32
	// REQ_OP_ZONE_APPEND
	zoneAppendOp uint32
}

// kernelBlockLayout reads the prototypes of the block tracepoints, the request flags and the zone
// append operation in the kernel BTF. The kernel version can't tell: 5.10.137 and RHEL 8.6
// backported the block_rq_issue change of 5.11, and RHEL 9.6 numbers the request flags with the
// enum of 6.11.
func kernelBlockLayout() (blockLayout, error) {
	var layout blockLayout
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return layout, err
	}
	var issue, complete *btf.Typedef
	if err = spec.TypeByName("btf_trace_block_rq_issue", &issue); err != nil {
		return layout, err
	}
	if err = spec.TypeByName("btf_trace_block_rq_complete", &complete); err != nil {
		return layout, err
	}
	if layout.issueHasQueueArg, err = blockTracepointHasQueueArg(issue, "block_rq_issue"); err != nil {
		return layout, err
	}
	if layout.completeReportsBlkStatus, err = blockRqCompleteReportsBlkStatus(complete); err != nil {
		return layout, err
	}
	return layout, layout.readEnums(spec)
}

// readEnums reads the enumerators of the layout in one walk of the enums of the spec, named or not:
// some kernels leave the enum of the request flags anonymous, so the BPF programs can't relocate them
func (l *blockLayout) readEnums(spec *btf.Spec) error {
	for typ, err := range spec.All() {
		if err != nil {
			return err
		}
		enum, ok := typ.(*btf.Enum)
		if !ok {
			continue
		}
		for _, value := range enum.Values {
			switch value.Name {
			case "__RQF_IO_STAT":
				l.rqfIOStat = 1 << value.Value
			case "__RQF_FLUSH_SEQ":
				l.rqfFlushSeq = 1 << value.Value
			case "REQ_OP_ZONE_APPEND":
				l.zoneAppendOp = uint32(value.Value)
			}
		}
	}
	return nil
}

// blockTracepointHasQueueArg tells whether the tracepoint of a btf_trace_<name> typedef has the
// request queue before its request or bio, as block_rq_issue and block_bio_queue had before Linux 5.11
func blockTracepointHasQueueArg(typedef *btf.Typedef, name string) (bool, error) {
	proto := tracepointProto(typedef)
	switch {
	case proto == nil:
		return false, fmt.Errorf("btf_trace_%s is not a function pointer", name)
	case len(proto.Params) == blockTracepointParams:
		return false, nil
	case len(proto.Params) == blockTracepointLegacyParams:
		return true, nil
	}
	return false, fmt.Errorf("unexpected %s prototype with %d parameters", name, len(proto.Params))
}

// blockBioQueueHasQueueArg reads the prototype of block_bio_queue in the BTF of a kernel
func blockBioQueueHasQueueArg(spec *btf.Spec) (bool, error) {
	var queue *btf.Typedef
	if err := spec.TypeByName("btf_trace_block_bio_queue", &queue); err != nil {
		return false, err
	}
	return blockTracepointHasQueueArg(queue, "block_bio_queue")
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

// bioProgramsToDisable returns the programs of the bio-based devices that must not be loaded: all of
// them without the feature, and otherwise the block_bio_queue program of the other prototype
func bioProgramsToDisable(enabled, queueHasQueueArg bool) []string {
	switch {
	case !enabled:
		return []string{
			StatsProgObiStatsRawTpBlockBioQueue, StatsProgObiStatsRawTpBlockBioQueueLegacy,
			StatsProgObiStatsRawTpBlockBioComplete, StatsProgObiStatsRawTpBlockRqCompleteBios,
		}
	case queueHasQueueArg:
		return []string{StatsProgObiStatsRawTpBlockBioQueue}
	default:
		return []string{StatsProgObiStatsRawTpBlockBioQueueLegacy}
	}
}

func bioQueueProgram(objects *StatsObjects, queueHasQueueArg bool) *ebpf.Program {
	if queueHasQueueArg {
		return objects.ObiStatsRawTpBlockBioQueueLegacy
	}
	return objects.ObiStatsRawTpBlockBioQueue
}

// sizeStorageMaps gives the maps of a disabled storage feature a single entry, as StatsObjects
// creates them anyway, and the cgroup names one when no probe reads the cgroups. Otherwise, it gives
// the LRU maps of the requests and syncs in flight room for twice the free entries that the CPUs can
// keep for themselves: once those hold most of a map, a CPU that needs an entry evicts one in
// flight, until the fix of Linux 6.16 (and 6.12.39, 6.6.99).
func sizeStorageMaps(spec *ebpf.CollectionSpec, storage export.Features, reads CgroupReads, cpus int) {
	nfsReads := nfsReadsCgroup(storage, reads)
	if readsCgroup := storage.StatsDisk() && reads.Disk || storage.StatsFsSync() && reads.FsSync || nfsReads; !readsCgroup {
		spec.Maps["disk_cgroup_names"].MaxEntries = 1
	}
	for _, maps := range []struct {
		enabled         bool
		inFlight, accum string
	}{
		{enabled: storage.StatsDisk(), inFlight: "disk_rq_start", accum: "disk_io_accum"},
		{enabled: storage.StatsDiskBioDevices(), inFlight: "disk_bio_start"},
		{enabled: storage.StatsFsSync(), inFlight: "fs_sync_start", accum: "fs_sync_accum"},
		{enabled: nfsReads, inFlight: "nfs_task_cgroup"},
	} {
		inFlight := spec.Maps[maps.inFlight]
		if !maps.enabled {
			inFlight.MaxEntries = 1
			if maps.accum != "" {
				spec.Maps[maps.accum].MaxEntries = 1
			}
			continue
		}
		inFlight.MaxEntries = max(inFlight.MaxEntries, uint32(2*lruLocalFreeTarget*cpus))
	}
	sizeNFSMaps(spec, storage)
}

func diskLatencyBoundsNs() [diskLatencyBuckets - 1]uint64 {
	var boundsNs [diskLatencyBuckets - 1]uint64
	for i, bound := range export.DiskLatencyBounds {
		boundsNs[i] = uint64(math.Round(bound * float64(time.Second)))
	}
	return boundsNs
}
