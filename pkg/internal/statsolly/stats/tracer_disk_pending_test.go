// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

type fakeRequests []ebpf.StatsDiskRqStartT

func (f *fakeRequests) requests() ([]ebpf.StatsDiskRqStartT, error) {
	return *f, nil
}

// inFlight is a request in flight on the disk 8:0
func inFlight(op ebpf.StatsDiskOp, issuedNs uint64) ebpf.StatsDiskRqStartT {
	return ebpf.StatsDiskRqStartT{Major: 8, Minor: 0, Op: op, IssuedNs: issuedNs}
}

func pendingByDevice(stats []*ebpf.Stat) map[string]int64 {
	pending := map[string]int64{}
	for _, stat := range stats {
		pending[stat.DiskPending.Device+"/"+directionOf(stat.DiskPending.Op)] = stat.DiskPending.Requests
	}
	return pending
}

func directionOf(op ebpf.DiskOpCode) string {
	if op == ebpf.CodeDiskOpRead {
		return "read"
	}
	return "write"
}

func TestPendingReaderCountsRequestsInFlight(t *testing.T) {
	const now = uint64(1000 * time.Second)
	src := &fakeRequests{
		inFlight(ebpf.StatsDiskOpDiskOpRead, now-1000),
		inFlight(ebpf.StatsDiskOpDiskOpRead, now-2000),
		inFlight(ebpf.StatsDiskOpDiskOpWrite, now-3000),
		inFlight(ebpf.StatsDiskOpDiskOpFlush, now-3000),
		// issued too long ago: a request whose completion was not seen
		inFlight(ebpf.StatsDiskOpDiskOpWrite, now-uint64(staleRequestAge)-1),
	}
	r := newPendingReader(src, &deviceNames{sysRoot: "/nonexistent"})
	r.nowNs = func() uint64 { return now }

	assert.Equal(t, map[string]int64{"8:0/read": 2, "8:0/write": 1}, pendingByDevice(r.readStats()),
		"only reads and writes count, and stale requests don't")

	// the requests completed: the device is still reported, with nothing in flight
	*src = nil
	assert.Equal(t, map[string]int64{"8:0/read": 0, "8:0/write": 0}, pendingByDevice(r.readStats()))
}

func TestPendingReaderReportsDevicesThatDidIO(t *testing.T) {
	r := newPendingReader(&fakeRequests{}, &deviceNames{sysRoot: "/nonexistent"})
	r.nowNs = func() uint64 { return 20 }
	// the device completed reads, although no request was in flight at the time of the read
	r.observe(&ebpf.DiskIO{Device: "nvme0n1", Op: ebpf.CodeDiskOpRead})
	r.observe(&ebpf.DiskIO{Device: "nvme0n1", Op: ebpf.CodeDiskOpFlush})

	assert.Equal(t, map[string]int64{"nvme0n1/read": 0}, pendingByDevice(r.readStats()),
		"flushes are not counted")
}

func TestPendingReaderForgetsIdleDevices(t *testing.T) {
	src := &fakeRequests{inFlight(ebpf.StatsDiskOpDiskOpRead, 10)}
	r := newPendingReader(src, &deviceNames{sysRoot: "/nonexistent"})
	r.nowNs = func() uint64 { return 20 }
	require.Len(t, r.readStats(), 1)

	*src = nil
	for range diskIdleReadsBeforeDelete {
		require.Len(t, r.readStats(), 1, "reported with 0 requests while idle")
	}
	assert.Empty(t, r.readStats(), "forgotten after being idle for long")
}
