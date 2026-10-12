// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

type fakeDiskAccum struct {
	entries map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT
	err     error
}

func (f *fakeDiskAccum) read() (map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT, error) {
	return maps.Clone(f.entries), f.err
}

func writeKey(major, minor uint32) ebpf.StatsDiskIoKeyT {
	return ebpf.StatsDiskIoKeyT{Major: major, Minor: minor, Op: ebpf.StatsDiskOpDiskOpWrite}
}

// accum is the kernel value of counts[i] requests in bucket i, each taking latencyNs[i]
func accum(counts, latencyNs []uint64) ebpf.StatsDiskIoAccumT {
	var a ebpf.StatsDiskIoAccumT
	for i := range counts {
		a.LatencyCount[i] = counts[i]
		a.LatencySumNs += counts[i] * latencyNs[i]
	}
	return a
}

// assertLatency checks the requests of each bucket, from the first one, and their latency sum
func assertLatency(t *testing.T, latency ebpf.LatencyHistogram, sumSeconds float64, counts ...uint64) {
	t.Helper()
	expected := make([]uint64, len(ebpf.StatsDiskIoAccumT{}.LatencyCount))
	copy(expected, counts)
	assert.Equal(t, expected, latency.BucketCounts)
	assert.InDelta(t, sumSeconds, latency.Sum, 1e-12)
}

func newTestDiskReader(src *fakeDiskAccum) *diskReader {
	return newDiskReader(src.read, &blockDevices{sysRoot: "/nonexistent"})
}

func TestDiskReaderForwardsDeltas(t *testing.T) {
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(259, 0): accum([]uint64{0, 3}, []uint64{0, 2_000_000}),
	}}
	r := newTestDiskReader(src)

	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, ebpf.StatTypeDiskIO, stats[0].Type)
	assert.Equal(t, "259:0", stats[0].DiskIO.Device, "named after its numbers when sysfs doesn't know it")
	assert.Equal(t, ebpf.CodeDiskOpWrite, stats[0].DiskIO.Op)
	assertLatency(t, stats[0].DiskIO.Latency, 3*0.002, 0, 3)

	// two more requests in the same bucket, one in a higher bucket
	src.entries[writeKey(259, 0)] = accum([]uint64{0, 5, 1}, []uint64{0, 2_000_000, 50_000_000})
	stats = r.readStats()
	require.Len(t, stats, 1)
	assertLatency(t, stats[0].DiskIO.Latency, 2*0.002+0.05, 0, 2, 1)

	assert.Empty(t, r.readStats(), "nothing changed, nothing forwarded")
}

// What was read of the map is forwarded when it is full, or when its read fails midway
func TestDiskReaderForwardsWhatItReads(t *testing.T) {
	src := &fakeDiskAccum{err: errAccumFull, entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(8, 16): accum([]uint64{1}, []uint64{500_000}),
	}}
	r := newTestDiskReader(src)
	require.Len(t, r.readStats(), 1)
	assert.True(t, r.warnedFull)

	src.err = errors.New("iteration aborted")
	src.entries[writeKey(8, 16)] = accum([]uint64{3}, []uint64{500_000})
	stats := r.readStats()
	require.Len(t, stats, 1)
	assertLatency(t, stats[0].DiskIO.Latency, 2*0.0005, 2)
}

// fakeBlockDevice adds a block device to a fake sysfs, linked from /sys/dev/block by its numbers
func fakeBlockDevice(t *testing.T, sysRoot, numbers, name string) {
	t.Helper()
	dir := filepath.Join(sysRoot, "dev", "block", numbers)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "uevent"), []byte("DEVNAME="+name+"\nDEVTYPE=disk\n"), 0o644))
}

func TestDeviceNames(t *testing.T) {
	now := time.Now()
	previousClock := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = previousClock })

	sysRoot := t.TempDir()
	fakeBlockDevice(t, sysRoot, "259:0", "nvme0n1")
	names := &blockDevices{sysRoot: sysRoot}
	assert.Equal(t, "nvme0n1", names.name(259, 0))
	assert.Equal(t, "8:0", names.name(8, 0), "named after its numbers when sysfs doesn't know it")

	// the device was detached, and its numbers given to another one
	fakeBlockDevice(t, sysRoot, "259:0", "nvme1n1")
	assert.Equal(t, "nvme0n1", names.name(259, 0), "cached")
	now = now.Add(blockDevicesCachePeriod)
	assert.Equal(t, "nvme1n1", names.name(259, 0), "read again once the cache expired")

	// the numbers of unknown devices are not cached: a new device is named at its first I/O
	fakeBlockDevice(t, sysRoot, "8:0", "sda")
	assert.Equal(t, "sda", names.name(8, 0))
}
