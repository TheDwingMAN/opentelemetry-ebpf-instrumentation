// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// The reader forwards what each type, outcome and cgroup synced since the previous read, and names
// the type, the errno and the container
func TestFsSyncReaderForwardsDeltas(t *testing.T) {
	const containerID = "8e5e2d4ef4e0ec0ee80e1b7f86c2b8dbdc5a6e1db8c3d2d1b0a19f8e7d6c5b4a"
	fsync := ebpf.StatsFsSyncKeyT{Type: ebpf.StatsFsSyncTypeFsSyncTypeFsync}
	failed := ebpf.StatsFsSyncKeyT{Type: ebpf.StatsFsSyncTypeFsSyncTypeFdatasync, Status: 5}
	inContainer := ebpf.StatsFsSyncKeyT{Type: ebpf.StatsFsSyncTypeFsSyncTypeSyncFileRange, CgroupId: 10}
	// syncs is the kernel value of n syncs of 2 ms, in the bucket above 1 ms
	syncs := func(n uint64) ebpf.StatsFsSyncAccumT {
		var accum ebpf.StatsFsSyncAccumT
		accum.LatencyCount[4] = n
		accum.LatencySumNs = n * 2_000_000
		return accum
	}
	src := &fakeAccum[ebpf.StatsFsSyncKeyT, ebpf.StatsFsSyncAccumT]{entries: map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT{
		fsync: syncs(2), failed: syncs(1), inContainer: syncs(1),
	}}
	containers := newCgroupContainers(func(cgroupID uint64) (string, string, bool) {
		return "docker-" + containerID + ".scope", "system.slice", cgroupID == 10
	}, 16)
	r := newFsSyncReader(src, containers, defaultDiskReadInterval)

	type fsSync struct {
		syncType               ebpf.FsSyncTypeCode
		errorType, containerID string
		count, sumNs           uint64
	}
	read := func() []fsSync {
		var got []fsSync
		for _, stat := range r.readStats() {
			require.Equal(t, ebpf.StatTypeFsSync, stat.Type)
			got = append(got, fsSync{
				syncType: stat.FsSync.Type, errorType: stat.FsSync.ErrorType, containerID: stat.FsSync.ContainerID,
				count: stat.FsSync.Latency.Count(), sumNs: uint64(math.Round(stat.FsSync.Latency.Sum * float64(time.Second))),
			})
		}
		return got
	}
	assert.ElementsMatch(t, []fsSync{
		{syncType: ebpf.CodeFsSyncFsync, count: 2, sumNs: 4_000_000},
		{syncType: ebpf.CodeFsSyncFdatasync, errorType: "EIO", count: 1, sumNs: 2_000_000},
		{syncType: ebpf.CodeFsSyncSyncFileRange, containerID: containerID, count: 1, sumNs: 2_000_000},
	}, read())

	src.entries[fsync] = syncs(5)
	assert.Equal(t, []fsSync{{syncType: ebpf.CodeFsSyncFsync, count: 3, sumNs: 6_000_000}}, read(), "only what changed")
}
