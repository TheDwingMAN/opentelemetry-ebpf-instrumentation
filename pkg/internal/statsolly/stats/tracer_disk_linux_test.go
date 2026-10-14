// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func TestDiskErrorType(t *testing.T) {
	assert.Empty(t, diskErrorType(0, true))
	assert.Empty(t, diskErrorType(0, false))
	// a blk_status_t from Linux 5.16, named after the errno that the kernel maps it to
	assert.Equal(t, "EIO", diskErrorType(10, true))
	assert.Equal(t, "ETIMEDOUT", diskErrorType(2, true))
	assert.Equal(t, "_OTHER", diskErrorType(14, true), "a value renumbered between kernel versions")
	// an errno before
	assert.Equal(t, "EIO", diskErrorType(5, false))
	assert.Equal(t, "ETIMEDOUT", diskErrorType(110, false))
	assert.Equal(t, "_OTHER", diskErrorType(0xff, false), "an errno that doesn't fit in a status, like ERESTARTSYS")
}

func TestDiskReaderForwardsTheFailedRequestsApart(t *testing.T) {
	failed := writeKey(8, 0)
	failed.Status = 10
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(8, 0): accum([]uint64{2}, []uint64{100_000}),
		failed:         accum([]uint64{0, 1}, []uint64{0, 2_000_000}),
	}}
	r := newTestDiskReader(src)
	r.statusIsBlkStatus = true

	requests := map[string][]uint64{}
	for _, stat := range r.readStats() {
		requests[stat.DiskIO.ErrorType] = stat.DiskIO.Latency.BucketCounts[:2]
	}
	assert.Equal(t, map[string][]uint64{"": {2, 0}, "EIO": {0, 1}}, requests)
}
