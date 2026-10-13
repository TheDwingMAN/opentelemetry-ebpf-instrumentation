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

// fakeBlockDevices is a fake sysfs, with block devices linked from /sys/dev/block by their numbers
type fakeBlockDevices struct {
	t       *testing.T
	sysRoot string
}

func newFakeBlockDevices(t *testing.T) *fakeBlockDevices {
	return &fakeBlockDevices{t: t, sysRoot: t.TempDir()}
}

func (f *fakeBlockDevices) blockDevices() *blockDevices {
	return &blockDevices{sysRoot: f.sysRoot}
}

func (f *fakeBlockDevices) add(numbers, name string) {
	f.file(name, "uevent", "DEVNAME="+name+"\nDEVTYPE=disk")
	f.link(filepath.Join("dev", "block", numbers), name)
}

// file writes a file of the sysfs directory of a device
func (f *fakeBlockDevices) file(device, path, content string) {
	file := filepath.Join(f.sysRoot, "block", device, path)
	require.NoError(f.t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(f.t, os.WriteFile(file, []byte(content+"\n"), 0o644))
}

// stack builds a device on others: sysfs lists them as its slaves, and it as their holder
func (f *fakeBlockDevices) stack(device string, below ...string) {
	for _, disk := range below {
		f.link(filepath.Join("block", device, "slaves", disk), disk)
		f.link(filepath.Join("block", disk, "holders", device), device)
	}
}

// link links a path of the fake sysfs to the directory of a device
func (f *fakeBlockDevices) link(path, device string) {
	link := filepath.Join(f.sysRoot, path)
	require.NoError(f.t, os.MkdirAll(filepath.Dir(link), 0o755))
	require.NoError(f.t, os.Symlink(filepath.Join(f.sysRoot, "block", device), link))
}

func TestDeviceNames(t *testing.T) {
	now := time.Now()
	previousClock := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = previousClock })

	fake := newFakeBlockDevices(t)
	fake.add("253:0", "dm-0")
	fake.file("dm-0", "dm/name", "vg0-data")
	devices := fake.blockDevices()
	assert.Equal(t, blockDevice{name: "dm-0", volumeName: "vg0-data", stacked: true}, devices.device(253, 0))
	assert.Equal(t, blockDevice{name: "8:0"}, devices.device(8, 0), "named after its numbers when sysfs doesn't know it")

	// the volume was removed, and its numbers given to a new one
	fake.file("dm-0", "dm/name", "vg0-new")
	assert.Equal(t, "vg0-data", devices.device(253, 0).volumeName, "cached")
	now = now.Add(blockDevicesCachePeriod)
	assert.Equal(t, "vg0-new", devices.device(253, 0).volumeName, "read again once the cache expired")

	// the numbers of unknown devices are not cached: a new device is named at its first I/O
	fake.add("8:0", "sda")
	assert.Equal(t, blockDevice{name: "sda"}, devices.device(8, 0))
}

func TestStackedDevices(t *testing.T) {
	fake := newFakeBlockDevices(t)
	fake.add("259:0", "nvme0n1")
	fake.add("8:16", "sdb")
	fake.add("8:32", "sdc")
	fake.add("8:48", "sdd")
	fake.add("7:0", "loop0")
	fake.file("loop0", "loop/backing_file", "/var/lib/images/disk.img")
	fake.add("253:0", "dm-0")
	fake.file("dm-0", "dm/name", "vg0-data")
	fake.stack("dm-0", "nvme0n1")
	fake.add("9:0", "md0")
	fake.file("md0", "md/level", "raid1")
	fake.stack("md0", "sdb", "sdc")
	fake.add("252:0", "bcache0")
	fake.stack("bcache0", "sdd")

	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{}}
	for _, numbers := range []devNum{{259, 0}, {8, 16}, {7, 0}, {253, 0}, {9, 0}, {252, 0}, {8, 99}} {
		src.entries[writeKey(numbers.major, numbers.minor)] = accum([]uint64{1}, []uint64{100_000})
	}
	type labels struct {
		volumeName string
		stacked    bool
	}
	devices := map[string]labels{}
	for _, stat := range newDiskReader(src.read, fake.blockDevices()).readStats() {
		devices[stat.DiskIO.Device] = labels{volumeName: stat.DiskIO.VolumeName, stacked: stat.DiskIO.Stacked}
	}
	assert.Equal(t, map[string]labels{
		"nvme0n1": {},
		"sdb":     {},
		"loop0":   {stacked: true},
		"dm-0":    {volumeName: "vg0-data", stacked: true},
		"md0":     {stacked: true},
		"bcache0": {stacked: true},
		"8:99":    {},
	}, devices)
}

// The paths of a measured dm-multipath device report nothing, as the multipath device reports the
// same requests, so the multipath device is not stacked
func TestDiskReaderLeavesOutTheMultipathPaths(t *testing.T) {
	fake := newFakeBlockDevices(t)
	fake.add("8:16", "sdb")
	fake.add("8:32", "sdc")
	fake.add("8:48", "sdd")
	fake.add("8:64", "sde")
	// a blk-mq dm-multipath device over sdb
	fake.add("253:1", "dm-1")
	fake.file("dm-1", "dm/uuid", "mpath-3600a098038303053453f463045727a51")
	fake.file("dm-1", "mq/0/nr_tags", "256")
	fake.stack("dm-1", "sdb")
	// a request-based one of an older kernel, without blk-mq, over sdc
	fake.add("253:3", "dm-3")
	fake.file("dm-3", "dm/uuid", "mpath-3600a098038303053453f463045727a53")
	fake.file("dm-3", "queue/scheduler", "noop deadline [cfq]")
	fake.stack("dm-3", "sdc")
	// a bio-based one over sdd
	fake.add("253:2", "dm-2")
	fake.file("dm-2", "dm/uuid", "mpath-3600a098038303053453f463045727a52")
	fake.file("dm-2", "queue/scheduler", "none")
	fake.stack("dm-2", "sdd")
	// an LVM volume over sde
	fake.add("253:0", "dm-0")
	fake.file("dm-0", "dm/uuid", "LVM-Jx5HfWYhjVTJlsk1Bm5uXPejJ6Np1HMpbTzX1bz9tJw0ZDhIrb3nG5zhpzbBgJpQ")
	fake.stack("dm-0", "sde")

	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{}}
	for _, numbers := range []devNum{{8, 16}, {8, 32}, {8, 48}, {8, 64}, {253, 0}, {253, 1}, {253, 2}, {253, 3}} {
		src.entries[writeKey(numbers.major, numbers.minor)] = accum([]uint64{1}, []uint64{100_000})
	}
	r := newDiskReader(src.read, fake.blockDevices())
	stacked := map[string]bool{}
	for _, stat := range r.readStats() {
		stacked[stat.DiskIO.Device] = stat.DiskIO.Stacked
	}
	assert.Equal(t, map[string]bool{
		"sdd": false, "sde": false, "dm-1": false, "dm-3": false,
		"dm-0": true, "dm-2": true,
	}, stacked, "the paths of dm-1 and dm-3 report nothing")
	assert.Equal(t, src.entries, r.previous, "a path reports none of the requests it served while it was one")
}
