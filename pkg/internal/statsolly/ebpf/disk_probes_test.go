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

func TestSizeDiskMaps(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		enabled                 bool
		cpus                    int
		wantInFlight, wantAccum uint32
	}{
		{name: "disabled", cpus: 192, wantInFlight: 1, wantAccum: 1},
		{name: "up to 64 CPUs", enabled: true, cpus: 64, wantInFlight: 1 << 14, wantAccum: 1 << 12},
		{name: "beyond", enabled: true, cpus: 192, wantInFlight: 2 * lruLocalFreeTarget * 192, wantAccum: 1 << 12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := LoadStats()
			require.NoError(t, err)
			sizeDiskMaps(spec, tc.enabled, tc.cpus)
			assert.Equal(t, tc.wantInFlight, spec.Maps["disk_rq_start"].MaxEntries)
			assert.Equal(t, tc.wantAccum, spec.Maps["disk_io_accum"].MaxEntries)
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
