// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

type fakeDiskAccum struct {
	entries map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT
	deleted []ebpf.StatsDiskIoKeyT
	// the error that read returns
	err error
}

func (f *fakeDiskAccum) read() (map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT, error) {
	return maps.Clone(f.entries), f.err
}

func (f *fakeDiskAccum) delete(key ebpf.StatsDiskIoKeyT) error {
	f.deleted = append(f.deleted, key)
	delete(f.entries, key)
	return nil
}

var testBounds = []float64{0.001, 0.01}

func writeKey(major, minor uint32) ebpf.StatsDiskIoKeyT {
	return ebpf.StatsDiskIoKeyT{Major: major, Minor: minor, Op: ebpf.StatsDiskOpDiskOpWrite}
}

// accum builds a kernel accumulation value: counts[i] requests in bucket i, each taking latencyNs[i]
func accum(counts []uint64, latencyNs []uint64) ebpf.StatsDiskIoAccumT {
	var a ebpf.StatsDiskIoAccumT
	for i := range counts {
		a.LatencyCount[i] = counts[i]
		a.LatencySumNs[i] = counts[i] * latencyNs[i]
	}
	return a
}

type fakeCgroupNames map[uint64]string

func (f fakeCgroupNames) name(cgroupID uint64) (string, bool) {
	name, ok := f[cgroupID]
	return name, ok
}

func newTestDiskReader(src *fakeDiskAccum) *accumReader[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT] {
	return newDiskReader(src, testBounds, false, &deviceNames{sysRoot: "/nonexistent"},
		newCgroupContainers(fakeCgroupNames{}))
}

func TestDiskReaderReadsFullMaps(t *testing.T) {
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(259, 0): accum([]uint64{1, 0, 0}, []uint64{500_000, 0, 0}),
		writeKey(259, 1): accum([]uint64{1, 0, 0}, []uint64{500_000, 0, 0}),
	}}
	r := newTestDiskReader(src)
	r.readStats()

	// a full map is read completely: what grew is forwarded, and entries that are gone are forgotten
	src.err = errAccumFull
	delete(src.entries, writeKey(259, 1))
	src.entries[writeKey(259, 0)] = accum([]uint64{3, 0, 0}, []uint64{500_000, 0, 0})
	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, uint64(2), stats[0].DiskIO.Operations)
	assert.True(t, r.full)
	assert.NotContains(t, r.previous, writeKey(259, 1))
}

func TestDiskReaderForwardsDeltas(t *testing.T) {
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(259, 0): accum([]uint64{0, 3, 0}, []uint64{0, 2_000_000, 0}),
	}}
	r := newTestDiskReader(src)

	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, ebpf.StatTypeDiskIO, stats[0].Type)
	assert.Equal(t, "259:0", stats[0].DiskIO.Device)
	assert.Equal(t, ebpf.CodeDiskOpWrite, stats[0].DiskIO.Op)
	assert.Empty(t, stats[0].DiskIO.ErrorType)
	assert.Equal(t, []ebpf.LatencySample{{Seconds: 0.002, Count: 3}}, stats[0].DiskIO.Latency)

	// two more requests in the same bucket, one in the overflow bucket
	src.entries[writeKey(259, 0)] = accum([]uint64{0, 5, 1}, []uint64{0, 2_000_000, 50_000_000})
	stats = r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, []ebpf.LatencySample{
		{Seconds: 0.002, Count: 2},
		{Seconds: 0.05, Count: 1},
	}, stats[0].DiskIO.Latency)

	assert.Empty(t, r.readStats(), "nothing changed, nothing forwarded")
}

func TestDiskReaderRestartsAfterEviction(t *testing.T) {
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(8, 0): accum([]uint64{10, 0, 0}, []uint64{500_000, 0, 0}),
	}}
	r := newTestDiskReader(src)
	require.Len(t, r.readStats(), 1)

	// the entry was deleted and re-created: its counters restarted from zero
	src.entries[writeKey(8, 0)] = accum([]uint64{4, 0, 0}, []uint64{500_000, 0, 0})
	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, []ebpf.LatencySample{{Seconds: 0.0005, Count: 4}}, stats[0].DiskIO.Latency)
}

func TestDiskReaderRestartsWhenOnlyTheLatencySumDecreased(t *testing.T) {
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(8, 0): accum([]uint64{2, 0, 0}, []uint64{900_000, 0, 0}),
	}}
	r := newTestDiskReader(src)
	require.Len(t, r.readStats(), 1)

	// re-created with as many requests, but faster ones: the latency sum went down
	src.entries[writeKey(8, 0)] = accum([]uint64{3, 0, 0}, []uint64{100_000, 0, 0})
	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, []ebpf.LatencySample{{Seconds: 0.0001, Count: 3}}, stats[0].DiskIO.Latency)
	assert.InDelta(t, 0.0003, stats[0].DiskIO.Time, 1e-12)
}

func TestDiskReaderDeletesIdleEntries(t *testing.T) {
	key := writeKey(8, 16)
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		key: accum([]uint64{1, 0, 0}, []uint64{100_000, 0, 0}),
	}}
	r := newTestDiskReader(src)
	require.Len(t, r.readStats(), 1)

	for range diskIdleReadsBeforeDelete - 1 {
		assert.Empty(t, r.readStats())
		assert.Empty(t, src.deleted)
	}
	assert.Empty(t, r.readStats())
	assert.Equal(t, []ebpf.StatsDiskIoKeyT{key}, src.deleted)
	assert.Empty(t, r.previous, "forgotten once deleted from the kernel map")
}

func TestLatencySampleStaysInItsBucket(t *testing.T) {
	bounds := []float64{0.001, 0.01}
	// the kernel compares nanoseconds: a mean exactly on a bound belongs to the lower bucket
	assert.InDelta(t, 0.001, latencySample(bounds, 0, 1, 1_000_000).Seconds, 1e-12)
	assert.LessOrEqual(t, latencySample(bounds, 0, 1, 1_000_000).Seconds, bounds[0])
	// a mean that rounding pushed out of its bucket is clamped back into it
	assert.LessOrEqual(t, latencySample(bounds, 0, 1, 1_000_001).Seconds, bounds[0])
	assert.Greater(t, latencySample(bounds, 1, 1, 1_000_000).Seconds, bounds[0])
	// the overflow bucket has no upper bound
	assert.InDelta(t, 3.0, latencySample(bounds, 2, 2, 6_000_000_000).Seconds, 1e-9)
	assert.False(t, math.IsInf(latencySample(bounds, 2, 1, 1).Seconds, 0))
}

func TestDeviceNames(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dev", "block", "259:0")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "uevent"),
		[]byte("MAJOR=259\nMINOR=0\nDEVNAME=nvme0n1\nDEVTYPE=disk\n"), 0o644))

	names := &deviceNames{sysRoot: root}
	assert.Equal(t, "nvme0n1", names.name(259, 0))
	assert.Equal(t, "8:0", names.name(8, 0), "falls back to major:minor when sysfs has no name")
}

// fakeSysBlock creates the sysfs entries of a disk and its partitions: /dev/block/<maj:min>/uevent
// for each device, and /block/<disk>/<partition>/partition with the partition numbers
func fakeSysBlock(t *testing.T, root string, disk string, major, minor uint32, partitions map[string][2]uint32) {
	t.Helper()
	writeUevent := func(name string, major, minor uint32) {
		dir := filepath.Join(root, "dev", "block", fmt.Sprintf("%d:%d", major, minor))
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "uevent"), []byte("DEVNAME="+name+"\n"), 0o644))
	}
	writeUevent(disk, major, minor)
	number := 0
	for name, numbers := range partitions {
		number++
		writeUevent(name, numbers[0], numbers[1])
		dir := filepath.Join(root, "block", disk, name)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "partition"), []byte(strconv.Itoa(number)+"\n"), 0o644))
	}
}

func kernelDev(major, minor uint32) uint32 {
	return major<<kernelDevMinorBits | minor
}

func TestDevicePartitions(t *testing.T) {
	root := t.TempDir()
	// NVMe partitions have extended device numbers, unrelated to the disk's
	fakeSysBlock(t, root, "nvme0n1", 259, 0, map[string][2]uint32{"nvme0n1p1": {259, 1}})
	names := &deviceNames{sysRoot: root}

	assert.Equal(t, "nvme0n1p1", names.partition(259, 0, kernelDev(259, 1), 0), "from the partition dev_t (Linux 5.12+)")
	assert.Equal(t, "nvme0n1p1", names.partition(259, 0, 0, 1), "from the partition number (older kernels)")
	assert.Empty(t, names.partition(259, 0, kernelDev(259, 0), 0), "I/O on the whole disk has no partition")
	assert.Empty(t, names.partition(259, 0, 0, 0), "requests without a bio have no partition")
	assert.Empty(t, names.partition(259, 0, 0, 7), "a partition that sysfs doesn't know")
}

func TestDiskReaderForwardsPartitionAndQueue(t *testing.T) {
	root := t.TempDir()
	fakeSysBlock(t, root, "sda", 8, 0, map[string][2]uint32{"sda1": {8, 1}})
	key := writeKey(8, 0)
	key.PartDev = kernelDev(8, 1)
	current := accum([]uint64{2, 0, 0}, []uint64{500_000, 0, 0})
	// one of the two requests waited 2 ms before its issue, the wait of the other one is unknown
	current.QueueCount[1] = 1
	current.QueueSumNs[1] = 2_000_000
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{key: current}}
	r := newDiskReader(src, testBounds, false, &deviceNames{sysRoot: root}, newCgroupContainers(fakeCgroupNames{}))

	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, "sda", stats[0].DiskIO.Device)
	assert.Equal(t, "sda1", stats[0].DiskIO.Partition)
	assert.Equal(t, uint64(2), stats[0].DiskIO.Operations)
	assert.Equal(t, []ebpf.LatencySample{{Seconds: 0.002, Count: 1}}, stats[0].DiskIO.Queue)
}

func TestDiskReaderForwardsFlushesAndDiscards(t *testing.T) {
	flush, discard := writeKey(8, 0), writeKey(8, 0)
	flush.Op, discard.Op = ebpf.StatsDiskOpDiskOpFlush, ebpf.StatsDiskOpDiskOpDiscard
	discarded := accum([]uint64{1, 0, 0}, []uint64{300_000, 0, 0})
	discarded.Bytes = 1 << 20
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		flush:   accum([]uint64{0, 4, 0}, []uint64{0, 3_000_000, 0}),
		discard: discarded,
	}}
	r := newTestDiskReader(src)

	byOp := map[ebpf.DiskOpCode]*ebpf.DiskIO{}
	for _, stat := range r.readStats() {
		byOp[stat.DiskIO.Op] = stat.DiskIO
	}
	require.Len(t, byOp, 2)
	assert.Equal(t, uint64(4), byOp[ebpf.CodeDiskOpFlush].Operations)
	assert.Equal(t, uint64(1<<20), byOp[ebpf.CodeDiskOpDiscard].Bytes)
}

func TestDiskErrorType(t *testing.T) {
	assert.Empty(t, diskErrorType(0, true))
	assert.Empty(t, diskErrorType(0, false))
	// blk_status_t since Linux 5.16, named after the errno the kernel maps it to
	assert.Equal(t, "EIO", diskErrorType(10, true))
	assert.Equal(t, "ETIMEDOUT", diskErrorType(2, true))
	assert.Equal(t, "_OTHER", diskErrorType(14, true), "values renumbered across kernel versions")
	// errno before Linux 5.16
	assert.Equal(t, "EIO", diskErrorType(5, false))
	assert.Equal(t, "ETIMEDOUT", diskErrorType(110, false))
}

func TestDiskReaderForwardsCounters(t *testing.T) {
	key := writeKey(259, 0)
	current := accum([]uint64{0, 3, 1}, []uint64{0, 2_000_000, 50_000_000})
	current.Bytes = 3 * 4096
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{key: current}}
	r := newTestDiskReader(src)

	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, uint64(4), stats[0].DiskIO.Operations)
	assert.InDelta(t, 0.056, stats[0].DiskIO.Time, 1e-12)
	assert.Equal(t, uint64(3*4096), stats[0].DiskIO.Bytes)

	next := accum([]uint64{0, 5, 1}, []uint64{0, 2_000_000, 50_000_000})
	next.Bytes = 5 * 4096
	src.entries[key] = next
	stats = r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, uint64(2), stats[0].DiskIO.Operations)
	assert.InDelta(t, 0.004, stats[0].DiskIO.Time, 1e-12)
	assert.Equal(t, uint64(2*4096), stats[0].DiskIO.Bytes)
}

func TestDiskReaderResolvesContainers(t *testing.T) {
	const containerID = "40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9"
	inContainer, inSlice, unnamed := writeKey(8, 0), writeKey(8, 0), writeKey(8, 0)
	inContainer.CgroupId, inSlice.CgroupId, unnamed.CgroupId = 100, 200, 300
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		inContainer: accum([]uint64{1, 0, 0}, []uint64{100_000, 0, 0}),
		inSlice:     accum([]uint64{1, 0, 0}, []uint64{100_000, 0, 0}),
		unnamed:     accum([]uint64{1, 0, 0}, []uint64{100_000, 0, 0}),
	}}
	r := newDiskReader(src, testBounds, false, &deviceNames{sysRoot: "/nonexistent"},
		newCgroupContainers(fakeCgroupNames{
			100: "cri-containerd-" + containerID + ".scope",
			200: "system.slice",
		}))

	containers := map[string]int{}
	for _, stat := range r.readStats() {
		containers[stat.DiskIO.ContainerID]++
	}
	assert.Equal(t, map[string]int{containerID: 1, "": 2}, containers,
		"I/O charged to a non-container cgroup, or to an unknown one, has no container")
}

type fakeFsSyncAccum struct {
	entries map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT
}

func (f *fakeFsSyncAccum) read() (map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT, error) {
	return maps.Clone(f.entries), nil
}

func (f *fakeFsSyncAccum) delete(key ebpf.StatsFsSyncKeyT) error {
	delete(f.entries, key)
	return nil
}

func TestFsSyncReader(t *testing.T) {
	const containerID = "40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9"
	ok := ebpf.StatsFsSyncKeyT{CgroupId: 100, Type: ebpf.StatsFsSyncTypeFsSyncTypeFdatasync, S_dev: kernelDev(253, 0)}
	failed := ebpf.StatsFsSyncKeyT{CgroupId: 100, Status: uint8(unix.EIO)}
	syncs := func(count, latencyNs uint64) ebpf.StatsFsSyncAccumT {
		var a ebpf.StatsFsSyncAccumT
		a.LatencyCount[1], a.LatencySumNs[1] = count, count*latencyNs
		return a
	}
	src := &fakeFsSyncAccum{entries: map[ebpf.StatsFsSyncKeyT]ebpf.StatsFsSyncAccumT{
		ok:     syncs(4, 2_000_000),
		failed: syncs(1, 2_000_000),
	}}
	r := newFsSyncReader(src, testBounds, newCgroupContainers(fakeCgroupNames{
		100: "cri-containerd-" + containerID + ".scope",
	}), fakeFilesystems(&procfs.MountInfo{MajorMinorVer: "253:0", Root: "/", MountPoint: "/data", FSType: "xfs"}))

	stats := r.readStats()
	require.Len(t, stats, 2)
	byError := map[string]*ebpf.FsSync{}
	for _, stat := range stats {
		assert.Equal(t, ebpf.StatTypeFsSync, stat.Type)
		assert.Equal(t, containerID, stat.FsSync.ContainerID)
		byError[stat.FsSync.ErrorType] = stat.FsSync
	}
	assert.Equal(t, []ebpf.LatencySample{{Seconds: 0.002, Count: 4}}, byError[""].Latency)
	assert.Equal(t, ebpf.CodeFsSyncFdatasync, byError[""].Type)
	assert.Equal(t, "/data", byError[""].Mountpoint)
	assert.Equal(t, "xfs", byError[""].FilesystemType)
	assert.Equal(t, []ebpf.LatencySample{{Seconds: 0.002, Count: 1}}, byError["EIO"].Latency)

	src.entries[ok] = syncs(6, 2_000_000)
	stats = r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, []ebpf.LatencySample{{Seconds: 0.002, Count: 2}}, stats[0].FsSync.Latency)
}
