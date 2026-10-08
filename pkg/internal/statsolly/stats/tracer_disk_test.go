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
	"time"

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
	return newDiskReader(src, testBounds, false, &deviceNames{sysRoot: "/nonexistent", procRoot: "/nonexistent"},
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

	now := time.Now()
	names := &deviceNames{sysRoot: root, procRoot: root, now: func() time.Time { return now }}
	assert.Equal(t, "nvme0n1", names.name(259, 0))
	assert.Equal(t, "8:0", names.name(8, 0), "falls back to major:minor when sysfs has no name")

	// the device was detached, and its numbers given to another one
	require.NoError(t, os.WriteFile(filepath.Join(dir, "uevent"),
		[]byte("MAJOR=259\nMINOR=0\nDEVNAME=nvme1n1\nDEVTYPE=disk\n"), 0o644))
	assert.Equal(t, "nvme0n1", names.name(259, 0), "cached")
	now = now.Add(deviceNamesCachePeriod)
	assert.Equal(t, "nvme1n1", names.name(259, 0), "read again once the cache expired")

	// a device that appears is named at its first I/O, as unknown devices are not cached
	other := filepath.Join(root, "dev", "block", "8:0")
	require.NoError(t, os.MkdirAll(other, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(other, "uevent"), []byte("DEVNAME=sda\n"), 0o644))
	assert.Equal(t, "sda", names.name(8, 0))
}

func TestDeviceNamesOfHiddenNVMePaths(t *testing.T) {
	// NVMe native multipath: sysfs links the numbers of the head, but not of its path devices
	devices := newFakeBlockDevices(t)
	devices.disk("259:2", "nvme1n1", 0, 0)
	devices.hiddenDisk("259:1", "nvme1c0n1")
	devices.hiddenDisk("259:0", "nvme1c1n1")
	// before Linux 6.1, the kernel lists the paths without their numbers
	devices.hiddenDisk("0:0", "nvme2c0n1")
	devices.hiddenDisk("0:0", "nvme2c1n1")
	now := time.Now()
	names := &deviceNames{sysRoot: devices.sysRoot, procRoot: devices.procRoot, now: func() time.Time { return now }}

	for _, tc := range []struct {
		name         string
		major, minor uint32
		want         string
	}{
		{name: "the head, from sysfs", major: 259, minor: 2, want: "nvme1n1"},
		{name: "a path, from /proc/diskstats", major: 259, minor: 1, want: "nvme1c0n1"},
		{name: "another path, from /proc/diskstats", major: 259, minor: 0, want: "nvme1c1n1"},
		{name: "a device that neither lists", major: 259, minor: 3, want: "259:3"},
		{name: "the paths listed without their numbers", major: 0, minor: 0, want: "0:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, names.name(tc.major, tc.minor))
		})
	}

	// the paths are request-based disks
	assert.False(t, names.stacked(259, 1))
	assert.Empty(t, names.partition(259, 1, kernelDev(259, 1), 0))
	assert.Empty(t, names.partition(259, 1, 0, 1))

	// /proc/diskstats is read once per cache period: a path that appears or is renamed within it
	// is named after the period
	devices.removeAll()
	devices.hiddenDisk("259:1", "nvme1c2n1")
	devices.hiddenDisk("259:3", "nvme3c0n1")
	assert.Equal(t, "nvme1c0n1", names.name(259, 1))
	assert.Equal(t, "259:3", names.name(259, 3))

	now = now.Add(deviceNamesCachePeriod)
	assert.Equal(t, "nvme1c2n1", names.name(259, 1))
	assert.Equal(t, "nvme3c0n1", names.name(259, 3))
}

// sysFile writes a file of the sysfs directory of a fake block device
func (f *fakeBlockDevices) sysFile(device, path, content string) {
	file := filepath.Join(f.sysRoot, "block", device, path)
	require.NoError(f.t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(f.t, os.WriteFile(file, []byte(content+"\n"), 0o644))
}

// blkMQ makes a fake block device request-based, as sysfs shows the devices of blk-mq
func (f *fakeBlockDevices) blkMQ(device string) {
	require.NoError(f.t, os.MkdirAll(filepath.Join(f.sysRoot, "block", device, "mq"), 0o755))
}

// holds links a fake block device from the holders of another, as sysfs does for the devices
// built on it
func (f *fakeBlockDevices) holds(holder, device string) {
	holders := filepath.Join(f.sysRoot, "block", device, "holders")
	require.NoError(f.t, os.MkdirAll(holders, 0o755))
	require.NoError(f.t, os.Symlink(filepath.Join(f.sysRoot, "block", holder), filepath.Join(holders, holder)))
}

// fakeMultipathHost has a request-based dm-multipath device over two paths, a bio-based one over
// another path, an LVM volume, and NVMe native multipath: a head over a hidden path device
func fakeMultipathHost(t *testing.T) *fakeBlockDevices {
	devices := newFakeBlockDevices(t)
	for _, disk := range []struct{ numbers, name string }{
		{"8:16", "sdb"}, {"8:32", "sdc"}, {"8:48", "sdd"}, {"8:64", "sde"}, {"259:0", "nvme0n1"},
	} {
		devices.disk(disk.numbers, disk.name, 0, 0)
		devices.blkMQ(disk.name)
	}
	devices.disk("253:1", "dm-1", 0, 0)
	devices.blkMQ("dm-1")
	devices.sysFile("dm-1", "dm/uuid", "mpath-3600a098038303053453f463045727a51")
	devices.holds("dm-1", "sdb")
	devices.holds("dm-1", "sdc")
	// with queue_mode bio, dm-multipath is bio-based
	devices.disk("253:2", "dm-2", 0, 0)
	devices.sysFile("dm-2", "queue/scheduler", "none")
	devices.sysFile("dm-2", "dm/uuid", "mpath-3600a098038303053453f463045727a52")
	devices.holds("dm-2", "sdd")
	devices.disk("253:0", "dm-0", 0, 0)
	devices.sysFile("dm-0", "queue/scheduler", "none")
	devices.sysFile("dm-0", "dm/uuid", "LVM-Jx5HfWYhjVTJlsk1Bm5uXPejJ6Np1HMpbTzX1bz9tJw0ZDhIrb3nG5zhpzbBgJpQ")
	devices.holds("dm-0", "sde")
	devices.disk("259:2", "nvme1n1", 0, 0)
	devices.sysFile("nvme1n1", "queue/scheduler", "none")
	devices.hiddenDisk("259:1", "nvme1c0n1")
	// a path whose head is gone
	devices.hiddenDisk("259:9", "nvme5c0n1")
	return devices
}

func TestMultipathPaths(t *testing.T) {
	devices := fakeMultipathHost(t)
	for _, tc := range []struct {
		name         string
		major, minor uint32
		// what the device is with the bio-based devices measured or not
		withBios, withoutBios multipathPath
	}{
		{name: "a path of a dm-multipath device", major: 8, minor: 16, withBios: dmMultipathPath, withoutBios: dmMultipathPath},
		{name: "another path of it", major: 8, minor: 32, withBios: dmMultipathPath, withoutBios: dmMultipathPath},
		{name: "a path of a bio-based dm-multipath device", major: 8, minor: 48, withBios: dmMultipathPath, withoutBios: notMultipathPath},
		{name: "a disk under an LVM volume", major: 8, minor: 64},
		{name: "a disk", major: 259, minor: 0},
		{name: "a dm-multipath device", major: 253, minor: 1},
		{name: "a path of an NVMe multipath head", major: 259, minor: 1, withBios: nvmeMultipathPath, withoutBios: notMultipathPath},
		{name: "an NVMe multipath head", major: 259, minor: 2},
		{name: "a path whose head is gone", major: 259, minor: 9},
		{name: "an unknown device", major: 8, minor: 99},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withBios := &deviceNames{sysRoot: devices.sysRoot, procRoot: devices.procRoot, bioMeasured: true}
			assert.Equal(t, tc.withBios, withBios.multipathPathOf(tc.major, tc.minor), "with the bio-based devices measured")
			withoutBios := &deviceNames{sysRoot: devices.sysRoot, procRoot: devices.procRoot}
			assert.Equal(t, tc.withoutBios, withoutBios.multipathPathOf(tc.major, tc.minor), "without the bio-based devices measured")
		})
	}
}

func TestMultipathPathsAreRefreshedWithTheDeviceNames(t *testing.T) {
	devices := fakeMultipathHost(t)
	now := time.Now()
	names := &deviceNames{sysRoot: devices.sysRoot, procRoot: devices.procRoot, now: func() time.Time { return now }}
	require.Equal(t, dmMultipathPath, names.multipathPathOf(8, 16))

	// multipathd removed the multipath device
	require.NoError(t, os.Remove(filepath.Join(devices.sysRoot, "block", "sdb", "holders", "dm-1")))
	assert.Equal(t, dmMultipathPath, names.multipathPathOf(8, 16), "cached for the cache period")
	now = now.Add(deviceNamesCachePeriod)
	assert.Equal(t, notMultipathPath, names.multipathPathOf(8, 16))
}

func TestDiskReaderReportsNoLatencyOfMultipathPaths(t *testing.T) {
	devices := fakeMultipathHost(t)
	flushKey := func(major, minor uint32) ebpf.StatsDiskIoKeyT {
		return ebpf.StatsDiskIoKeyT{Major: major, Minor: minor, Op: ebpf.StatsDiskOpDiskOpFlush}
	}
	written := accum([]uint64{2, 1, 0}, []uint64{500_000, 5_000_000, 0})
	written.Bytes = 3 * 4096
	written.QueueNs = 1_000_000
	flushed := accum([]uint64{1, 0, 0}, []uint64{200_000, 0, 0})
	entries := map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(8, 16):  written, // sdb, a path of dm-1
		writeKey(253, 1): written, // dm-1
		writeKey(259, 1): written, // nvme1c0n1, a path of nvme1n1
		flushKey(8, 16):  flushed,
		flushKey(259, 1): flushed,
	}
	type deviceOp struct {
		device string
		op     ebpf.DiskOpCode
	}
	read := func(bioMeasured bool) map[deviceOp]*ebpf.DiskIO {
		names := &deviceNames{sysRoot: devices.sysRoot, procRoot: devices.procRoot, bioMeasured: bioMeasured}
		r := newDiskReader(&fakeDiskAccum{entries: entries}, testBounds, true, names, newCgroupContainers(fakeCgroupNames{}))
		stats := map[deviceOp]*ebpf.DiskIO{}
		for _, stat := range r.readStats() {
			stats[deviceOp{device: stat.DiskIO.Device, op: stat.DiskIO.Op}] = stat.DiskIO
		}
		return stats
	}

	stats := read(true)
	require.Len(t, stats, len(entries))
	path := stats[deviceOp{"sdb", ebpf.CodeDiskOpWrite}]
	assert.Empty(t, path.Latency, "the multipath device reports the latency of the I/O of its paths")
	assert.Equal(t, uint64(3), path.Operations, "the paths keep their counters")
	assert.InDelta(t, 0.006, path.Time, 1e-12)
	assert.Equal(t, uint64(3*4096), path.Bytes)
	assert.InDelta(t, 0.001, path.QueueTime, 1e-12)
	assert.NotEmpty(t, stats[deviceOp{"dm-1", ebpf.CodeDiskOpWrite}].Latency)
	assert.Empty(t, stats[deviceOp{"sdb", ebpf.CodeDiskOpFlush}].Latency)
	assert.Empty(t, stats[deviceOp{"nvme1c0n1", ebpf.CodeDiskOpWrite}].Latency, "the bios of the head are measured")
	assert.NotEmpty(t, stats[deviceOp{"nvme1c0n1", ebpf.CodeDiskOpFlush}].Latency,
		"the path measures the cache flushes that it sends to the device, the head those submitted to it")

	stats = read(false)
	assert.Empty(t, stats[deviceOp{"sdb", ebpf.CodeDiskOpWrite}].Latency)
	assert.NotEmpty(t, stats[deviceOp{"nvme1c0n1", ebpf.CodeDiskOpWrite}].Latency, "the bios of the head are not measured")
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
	names := &deviceNames{sysRoot: root, procRoot: root}

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
	current.QueueNs = 2_000_000
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{key: current}}
	r := newDiskReader(src, testBounds, false, &deviceNames{sysRoot: root, procRoot: root}, newCgroupContainers(fakeCgroupNames{}))

	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, "sda", stats[0].DiskIO.Device)
	assert.Equal(t, "sda1", stats[0].DiskIO.Partition)
	assert.Equal(t, uint64(2), stats[0].DiskIO.Operations)
	assert.InDelta(t, 0.002, stats[0].DiskIO.QueueTime, 1e-12)
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
	current.QueueNs = 1_000_000
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{key: current}}
	r := newTestDiskReader(src)

	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, uint64(4), stats[0].DiskIO.Operations)
	assert.InDelta(t, 0.056, stats[0].DiskIO.Time, 1e-12)
	assert.Equal(t, uint64(3*4096), stats[0].DiskIO.Bytes)
	assert.InDelta(t, 0.001, stats[0].DiskIO.QueueTime, 1e-12)

	next := accum([]uint64{0, 5, 1}, []uint64{0, 2_000_000, 50_000_000})
	next.Bytes = 5 * 4096
	next.QueueNs = 1_500_000
	src.entries[key] = next
	stats = r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, uint64(2), stats[0].DiskIO.Operations)
	assert.InDelta(t, 0.004, stats[0].DiskIO.Time, 1e-12)
	assert.Equal(t, uint64(2*4096), stats[0].DiskIO.Bytes)
	assert.InDelta(t, 0.0005, stats[0].DiskIO.QueueTime, 1e-12)
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
	r := newDiskReader(src, testBounds, false, &deviceNames{sysRoot: "/nonexistent", procRoot: "/nonexistent"},
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
	assert.Equal(t, uint64(4), byError[""].Operations)
	assert.InDelta(t, 0.008, byError[""].Time, 1e-12)
	assert.Equal(t, ebpf.CodeFsSyncFdatasync, byError[""].Type)
	assert.Equal(t, "/data", byError[""].Mountpoint)
	assert.Equal(t, "xfs", byError[""].FilesystemType)
	assert.Equal(t, []ebpf.LatencySample{{Seconds: 0.002, Count: 1}}, byError["EIO"].Latency)

	src.entries[ok] = syncs(6, 2_000_000)
	stats = r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, []ebpf.LatencySample{{Seconds: 0.002, Count: 2}}, stats[0].FsSync.Latency)
	assert.Equal(t, uint64(2), stats[0].FsSync.Operations)
	assert.InDelta(t, 0.004, stats[0].FsSync.Time, 1e-12)
}
