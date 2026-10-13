// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
)

func TestBlockRqIssueHasQueueArg(t *testing.T) {
	param := btf.FuncParam{Type: &btf.Pointer{Target: &btf.Void{}}}
	issue := func(params int) *btf.Typedef {
		proto := &btf.FuncProto{Return: &btf.Void{}, Params: make([]btf.FuncParam, params)}
		for i := range proto.Params {
			proto.Params[i] = param
		}
		return &btf.Typedef{Name: "btf_trace_block_rq_issue", Type: &btf.Pointer{Target: proto}}
	}

	hasQueueArg, err := blockRqIssueHasQueueArg(issue(2))
	require.NoError(t, err)
	assert.False(t, hasQueueArg, "(data, rq): Linux 5.11+, 5.10.137+, RHEL 8.6+")

	hasQueueArg, err = blockRqIssueHasQueueArg(issue(3))
	require.NoError(t, err)
	assert.True(t, hasQueueArg, "(data, q, rq)")

	_, err = blockRqIssueHasQueueArg(issue(1))
	require.Error(t, err, "an unexpected prototype is an error, not a guess")
	_, err = blockRqIssueHasQueueArg(&btf.Typedef{Type: &btf.Int{Size: 4}})
	require.Error(t, err)
}

func TestBlockRqCompleteReportsBlkStatus(t *testing.T) {
	pointer := btf.FuncParam{Type: &btf.Pointer{Target: &btf.Void{}}}
	complete := func(status btf.Type) *btf.Typedef {
		proto := &btf.FuncProto{Return: &btf.Void{}, Params: []btf.FuncParam{
			pointer, pointer, {Name: "error", Type: status}, {Name: "nr_bytes", Type: &btf.Int{Size: 4}},
		}}
		return &btf.Typedef{Name: "btf_trace_block_rq_complete", Type: &btf.Pointer{Target: proto}}
	}
	blkStatus := &btf.Typedef{Name: "blk_status_t", Type: &btf.Typedef{Name: "u8", Type: &btf.Int{Size: 1}}}

	reportsBlkStatus, err := blockRqCompleteReportsBlkStatus(complete(blkStatus))
	require.NoError(t, err)
	assert.True(t, reportsBlkStatus, "(data, rq, blk_status_t error, nr_bytes): Linux 5.16+")

	reportsBlkStatus, err = blockRqCompleteReportsBlkStatus(complete(&btf.Int{Size: 4, Encoding: btf.Signed}))
	require.NoError(t, err)
	assert.False(t, reportsBlkStatus, "(data, rq, int error, nr_bytes)")

	_, err = blockRqCompleteReportsBlkStatus(complete(pointer.Type))
	require.Error(t, err, "an unexpected prototype is an error, not a guess")
	_, err = blockRqCompleteReportsBlkStatus(&btf.Typedef{Type: &btf.Pointer{Target: &btf.FuncProto{Return: &btf.Void{}}}})
	require.Error(t, err)
}

// The request flags were macros, then an enum, which some kernels leave anonymous (6.12, RHEL 9.6)
func TestBlockLayoutEnums(t *testing.T) {
	flags := []btf.EnumValue{{Name: "__RQF_STARTED", Value: 0}, {Name: "__RQF_FLUSH_SEQ", Value: 1}, {Name: "__RQF_IO_STAT", Value: 8}}
	enumFlags := blockLayout{rqfIOStat: 1 << 8, rqfFlushSeq: 1 << 1}
	for _, tc := range []struct {
		name string
		typ  btf.Type
		want blockLayout
	}{
		{name: "macros", typ: &btf.Int{Name: "int", Size: 4}},
		{name: "anonymous enum", typ: &btf.Enum{Size: 4, Values: flags}, want: enumFlags},
		{name: "named enum", typ: &btf.Enum{Name: "rqf_flags", Size: 4, Values: flags}, want: enumFlags},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder, err := btf.NewBuilder([]btf.Type{tc.typ}, nil)
			require.NoError(t, err)
			raw, err := builder.Marshal(nil, nil)
			require.NoError(t, err)
			spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
			require.NoError(t, err)
			var layout blockLayout
			require.NoError(t, layout.readEnums(spec))
			assert.Equal(t, tc.want, layout)
		})
	}
}

func TestSizeStorageMaps(t *testing.T) {
	const inFlight, accum, names, beyond = 1 << 14, 1 << 12, 1 << 13, 2 * lruLocalFreeTarget * 192
	both := export.FeatureStatsDisk | export.FeatureStatsFsSync
	for _, tc := range []struct {
		name    string
		storage export.Features
		reads   CgroupReads
		cpus    int
		// disk_rq_start, disk_io_accum, fs_sync_start, fs_sync_accum and disk_cgroup_names
		want [5]uint32
	}{
		{name: "disabled", reads: CgroupReads{Disk: true, FsSync: true}, cpus: 192, want: [5]uint32{1, 1, 1, 1, 1}},
		{name: "up to 64 CPUs", storage: both, cpus: 64, want: [5]uint32{inFlight, accum, inFlight, accum, 1}},
		{name: "beyond", storage: both, cpus: 192, want: [5]uint32{beyond, accum, beyond, accum, 1}},
		{
			name: "the disk reads the cgroups", storage: export.FeatureStatsDisk, reads: CgroupReads{Disk: true}, cpus: 64,
			want: [5]uint32{inFlight, accum, 1, 1, names},
		},
		{
			name: "the file syncs read the cgroups", storage: export.FeatureStatsFsSync, reads: CgroupReads{FsSync: true}, cpus: 64,
			want: [5]uint32{1, 1, inFlight, accum, names},
		},
		{
			name: "a disabled feature doesn't read them", storage: export.FeatureStatsDisk, reads: CgroupReads{FsSync: true}, cpus: 64,
			want: [5]uint32{inFlight, accum, 1, 1, 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := LoadStats()
			require.NoError(t, err)
			sizeStorageMaps(spec, tc.storage, tc.reads, tc.cpus)
			var got [5]uint32
			for i, name := range []string{"disk_rq_start", "disk_io_accum", "fs_sync_start", "fs_sync_accum", "disk_cgroup_names"} {
				got[i] = spec.Maps[name].MaxEntries
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDiskLatencyBoundsNs(t *testing.T) {
	require.Len(t, export.DiskLatencyBounds, diskLatencyBuckets-1, "a kernel bucket per bound, then the overflow bucket")
	boundsNs := diskLatencyBoundsNs()
	assert.Equal(t, uint64(100_000), boundsNs[0])
	assert.Equal(t, uint64(60_000_000_000), boundsNs[len(boundsNs)-1])
	assert.IsIncreasing(t, boundsNs[:])
}
