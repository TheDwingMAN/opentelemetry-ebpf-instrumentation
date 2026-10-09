// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

type fakeFsSyncAccum struct {
	entries map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT
	deleted []ebpf.StatsFsSyncKeyT
}

func (f *fakeFsSyncAccum) read() (map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT, error) {
	return maps.Clone(f.entries), nil
}

func (f *fakeFsSyncAccum) delete(key ebpf.StatsFsSyncKeyT) error {
	f.deleted = append(f.deleted, key)
	delete(f.entries, key)
	return nil
}

func (f *fakeFsSyncAccum) lookupAndDelete(key ebpf.StatsFsSyncKeyT) (ebpf.StatsFsSyncAccumT, error) {
	last := f.entries[key]
	return last, f.delete(key)
}

// syncs builds a kernel accumulation value of file syncs: counts[i] syncs in bucket i, each taking
// latencyNs[i]
func syncs(counts []uint64, latencyNs []uint64) ebpf.StatsFsSyncAccumT {
	var a ebpf.StatsFsSyncAccumT
	for i := range counts {
		a.LatencyCount[i] = counts[i]
		a.LatencySumNs += counts[i] * latencyNs[i]
	}
	return a
}

func syncKey(syncType ebpf.StatsFsSyncType, status uint8, cgroupID uint64) ebpf.StatsFsSyncKeyT {
	return ebpf.StatsFsSyncKeyT{Type: syncType, Status: status, CgroupId: cgroupID}
}

func newTestFsSyncReader(src *fakeFsSyncAccum, names fakeCgroupNames) *fsSyncReader {
	return newFsSyncReader(src, newCgroupContainers(names), time.Second)
}

func TestFsSyncReaderForwardsDeltas(t *testing.T) {
	fsync := syncKey(ebpf.StatsFsSyncTypeFsSyncTypeFsync, 0, 0)
	src := &fakeFsSyncAccum{entries: map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT{
		fsync: syncs([]uint64{2, 1}, []uint64{50_000, 200_000}),
	}}
	r := newTestFsSyncReader(src, fakeCgroupNames{})

	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, ebpf.StatTypeFsSync, stats[0].Type)
	assert.Nil(t, stats[0].DiskIO)
	sync := stats[0].FsSync
	assert.Equal(t, ebpf.CodeFsSyncFsync, sync.Type)
	assert.Empty(t, sync.ErrorType)
	assert.Empty(t, sync.ContainerID)
	assert.Equal(t, uint64(3), sync.Operations, "the operations are the count of the histogram")
	assertLatency(t, sync.Latency, 0.0003, 2, 1)
	assert.InDelta(t, sync.Latency.Sum, sync.Time, 0, "the time is the sum of the histogram")

	assert.Empty(t, r.readStats(), "nothing grew")

	src.entries[fsync] = syncs([]uint64{2, 1, 4}, []uint64{50_000, 200_000, 400_000})
	stats = r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, uint64(4), stats[0].FsSync.Operations)
	assertLatency(t, stats[0].FsSync.Latency, 0.0016, 0, 0, 4)
}

func TestFsSyncReaderNamesTheTypesAndErrors(t *testing.T) {
	one := syncs([]uint64{1}, []uint64{50_000})
	src := &fakeFsSyncAccum{entries: map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT{
		syncKey(ebpf.StatsFsSyncTypeFsSyncTypeFdatasync, 0, 0):      one,
		syncKey(ebpf.StatsFsSyncTypeFsSyncTypeSyncfs, 5, 0):         one,
		syncKey(ebpf.StatsFsSyncTypeFsSyncTypeSyncFileRange, 28, 0): one,
		// an errno that doesn't fit in a status, e.g. ERESTARTSYS
		syncKey(ebpf.StatsFsSyncTypeFsSyncTypeSync, 0xff, 0): one,
	}}
	got := map[ebpf.FsSyncTypeCode]string{}
	for _, stat := range newTestFsSyncReader(src, fakeCgroupNames{}).readStats() {
		got[stat.FsSync.Type] = stat.FsSync.ErrorType
	}
	assert.Equal(t, map[ebpf.FsSyncTypeCode]string{
		ebpf.CodeFsSyncFdatasync:     "",
		ebpf.CodeFsSyncSyncfs:        "EIO",
		ebpf.CodeFsSyncSyncFileRange: "ENOSPC",
		ebpf.CodeFsSyncSync:          "_OTHER",
	}, got)
}

func TestFsSyncReaderResolvesContainers(t *testing.T) {
	const containerID = "40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9"
	one := syncs([]uint64{1}, []uint64{50_000})
	src := &fakeFsSyncAccum{entries: map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT{
		syncKey(ebpf.StatsFsSyncTypeFsSyncTypeFsync, 0, 0):  one,
		syncKey(ebpf.StatsFsSyncTypeFsSyncTypeFsync, 0, 10): one,
	}}
	names := fakeCgroupNames{10: {name: "cri-containerd-" + containerID + ".scope", parent: "kubepods-besteffort.slice"}}
	containers := map[string]uint64{}
	for _, stat := range newTestFsSyncReader(src, names).readStats() {
		containers[stat.FsSync.ContainerID] += stat.FsSync.Operations
	}
	assert.Equal(t, map[string]uint64{"": 1, containerID: 1}, containers)
}

func TestFsSyncReaderRestartsWhenTheEntryIsRecreated(t *testing.T) {
	fsync := syncKey(ebpf.StatsFsSyncTypeFsSyncTypeFsync, 0, 0)
	src := &fakeFsSyncAccum{entries: map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT{
		fsync: syncs([]uint64{5}, []uint64{50_000}),
	}}
	r := newTestFsSyncReader(src, fakeCgroupNames{})
	r.readStats()

	src.entries[fsync] = syncs([]uint64{2}, []uint64{50_000})
	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, uint64(2), stats[0].FsSync.Operations)
}

func TestFsSyncReaderDeletesIdleEntries(t *testing.T) {
	fsync := syncKey(ebpf.StatsFsSyncTypeFsSyncTypeFsync, 0, 0)
	src := &fakeFsSyncAccum{entries: map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT{
		fsync: syncs([]uint64{1}, []uint64{50_000}),
	}}
	r := newTestFsSyncReader(src, fakeCgroupNames{})
	r.readStats()
	for range idleReadsBeforeDelete(time.Second) {
		assert.Empty(t, r.readStats())
	}
	assert.Equal(t, []ebpf.StatsFsSyncKeyT{fsync}, src.deleted)
}

// The disk map tracer reads the maps of the probes that are attached
func TestDiskMapTracerReadsTheFileSyncs(t *testing.T) {
	disk := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(8, 0): accum([]uint64{1}, []uint64{500_000}),
	}}
	fsSync := &fakeFsSyncAccum{entries: map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT{
		syncKey(ebpf.StatsFsSyncTypeFsSyncTypeFsync, 0, 0): syncs([]uint64{1}, []uint64{50_000}),
	}}
	tracer := &DiskMapTracer{readers: []statReader{newTestDiskReader(disk), newTestFsSyncReader(fsSync, fakeCgroupNames{})}}
	types := map[ebpf.StatType]int{}
	for _, stat := range tracer.readStats() {
		types[stat.Type]++
	}
	assert.Equal(t, map[ebpf.StatType]int{ebpf.StatTypeDiskIO: 1, ebpf.StatTypeFsSync: 1}, types)

	assert.Empty(t, NewDiskMapTracer(&DiskMapTracerConfig{Interval: time.Second}).readers,
		"no reader without the maps of attached probes")
}

func TestErrnoErrorType(t *testing.T) {
	assert.Empty(t, errnoErrorType(0))
	assert.Equal(t, "EIO", errnoErrorType(5))
	assert.Equal(t, "_OTHER", errnoErrorType(0xff))
}
