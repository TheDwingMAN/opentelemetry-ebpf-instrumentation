// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

type fakeDiskAccum struct {
	entries map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT
	deleted []ebpf.StatsDiskIoKeyT
	// the error that read returns
	err error
	// grownBeforeDelete are the values that the kernel gives entries after their read and before
	// their deletion
	grownBeforeDelete map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT
	// noLookupAndDelete makes lookupAndDelete fail as on kernels before Linux 5.14
	noLookupAndDelete bool
	lookupAndDeletes  int
}

func (f *fakeDiskAccum) read() (map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT, error) {
	return maps.Clone(f.entries), f.err
}

func (f *fakeDiskAccum) delete(key ebpf.StatsDiskIoKeyT) error {
	f.growBeforeDelete(key)
	f.deleted = append(f.deleted, key)
	delete(f.entries, key)
	return nil
}

func (f *fakeDiskAccum) lookupAndDelete(key ebpf.StatsDiskIoKeyT) (ebpf.StatsDiskIoAccumT, error) {
	f.lookupAndDeletes++
	if f.noLookupAndDelete {
		return ebpf.StatsDiskIoAccumT{}, ciliumebpf.ErrNotSupported
	}
	f.growBeforeDelete(key)
	last := f.entries[key]
	return last, f.delete(key)
}

func (f *fakeDiskAccum) growBeforeDelete(key ebpf.StatsDiskIoKeyT) {
	if grown, ok := f.grownBeforeDelete[key]; ok {
		f.entries[key] = grown
	}
}

func writeKey(major, minor uint32) ebpf.StatsDiskIoKeyT {
	return ebpf.StatsDiskIoKeyT{Major: major, Minor: minor, Op: ebpf.StatsDiskOpDiskOpWrite}
}

// accum builds a kernel accumulation value: counts[i] requests in bucket i, each taking latencyNs[i]
func accum(counts []uint64, latencyNs []uint64) ebpf.StatsDiskIoAccumT {
	var a ebpf.StatsDiskIoAccumT
	for i := range counts {
		a.LatencyCount[i] = counts[i]
		a.LatencySumNs += counts[i] * latencyNs[i]
	}
	return a
}

// assertLatency checks the requests of each bucket of a latency histogram, from the first one, and
// the sum of their latencies
func assertLatency(t *testing.T, latency *ebpf.LatencyHistogram, sumSeconds float64, counts ...uint64) {
	t.Helper()
	require.NotNil(t, latency)
	expected := make([]uint64, len(ebpf.StatsDiskIoAccumT{}.LatencyCount))
	copy(expected, counts)
	assert.Equal(t, expected, latency.BucketCounts)
	assert.InDelta(t, sumSeconds, latency.Sum, 1e-12)
}

func newTestDiskReader(src *fakeDiskAccum) *diskReader {
	return newDiskReader(src, false, &blockDevices{sysRoot: "/nonexistent", procRoot: "/nonexistent"}, time.Second)
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
	assertLatency(t, stats[0].DiskIO.Latency, 2*0.0005, 2)
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
	assertLatency(t, stats[0].DiskIO.Latency, 3*0.002, 0, 3)

	// two more requests in the same bucket, one in a higher bucket
	src.entries[writeKey(259, 0)] = accum([]uint64{0, 5, 1}, []uint64{0, 2_000_000, 50_000_000})
	stats = r.readStats()
	require.Len(t, stats, 1)
	assertLatency(t, stats[0].DiskIO.Latency, 2*0.002+0.05, 0, 2, 1)

	assert.Empty(t, r.readStats(), "nothing changed, nothing forwarded")
}

func TestDiskReaderRestartsWhenTheEntryIsRecreated(t *testing.T) {
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(8, 0): accum([]uint64{10, 0, 0}, []uint64{500_000, 0, 0}),
	}}
	r := newTestDiskReader(src)
	require.Len(t, r.readStats(), 1)

	// the entry was deleted and re-created: its counters restarted from zero
	src.entries[writeKey(8, 0)] = accum([]uint64{4, 0, 0}, []uint64{500_000, 0, 0})
	stats := r.readStats()
	require.Len(t, stats, 1)
	assertLatency(t, stats[0].DiskIO.Latency, 4*0.0005, 4)
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
	assertLatency(t, stats[0].DiskIO.Latency, 3*0.0001, 3)
}

// The idle entries are deleted after a minute without changes, whatever the read period
func TestIdleReadsBeforeDelete(t *testing.T) {
	assert.Equal(t, 60, idleReadsBeforeDelete(time.Second))
	assert.Equal(t, 6000, idleReadsBeforeDelete(10*time.Millisecond))
	assert.Equal(t, 9, idleReadsBeforeDelete(7*time.Second), "rounded up")
	assert.Equal(t, 1, idleReadsBeforeDelete(time.Minute))
	assert.Equal(t, 1, idleReadsBeforeDelete(time.Hour), "at least one read")
}

func TestDiskReaderDeletesIdleEntries(t *testing.T) {
	key := writeKey(8, 16)
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		key: accum([]uint64{1, 0, 0}, []uint64{100_000, 0, 0}),
	}}
	r := newTestDiskReader(src)
	require.Len(t, r.readStats(), 1)

	for range r.idleReadsBeforeDelete - 1 {
		assert.Empty(t, r.readStats())
		assert.Empty(t, src.deleted)
	}
	assert.Empty(t, r.readStats())
	assert.Equal(t, []ebpf.StatsDiskIoKeyT{key}, src.deleted)
	assert.Empty(t, r.previous, "forgotten once deleted from the kernel map")
}

// The kernel can add to an idle entry between its last read and its deletion: what it added is
// reported when the entry is deleted
func TestDiskReaderReportsWhatGrewBeforeTheDeletion(t *testing.T) {
	key := writeKey(8, 16)
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		key: accum([]uint64{1, 0, 0}, []uint64{100_000, 0, 0}),
	}}
	r := newTestDiskReader(src)
	require.Len(t, r.readStats(), 1)
	for range r.idleReadsBeforeDelete - 1 {
		require.Empty(t, r.readStats())
	}

	src.grownBeforeDelete = map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		key: accum([]uint64{3, 0, 0}, []uint64{100_000, 0, 0}),
	}
	stats := r.readStats()
	assert.Equal(t, []ebpf.StatsDiskIoKeyT{key}, src.deleted)
	require.Len(t, stats, 1)
	assertLatency(t, stats[0].DiskIO.Latency, 2*0.0001, 2)
	assert.Empty(t, r.previous, "forgotten once deleted from the kernel map")
}

// Before Linux 5.14, the kernel can't look up and delete a hash map entry at once: the idle
// entries are deleted without their last value, and the reader doesn't try again
func TestDiskReaderDeletesIdleEntriesWithoutLookupAndDelete(t *testing.T) {
	first, second := writeKey(8, 16), writeKey(8, 32)
	src := &fakeDiskAccum{noLookupAndDelete: true, entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		first:  accum([]uint64{1, 0, 0}, []uint64{100_000, 0, 0}),
		second: accum([]uint64{1, 0, 0}, []uint64{100_000, 0, 0}),
	}}
	r := newTestDiskReader(src)
	require.Len(t, r.readStats(), 2)
	for range r.idleReadsBeforeDelete {
		require.Empty(t, r.readStats())
	}
	assert.ElementsMatch(t, []ebpf.StatsDiskIoKeyT{first, second}, src.deleted)
	assert.Equal(t, 1, src.lookupAndDeletes)
	assert.Empty(t, r.previous, "forgotten once deleted from the kernel map")
}

func TestDeviceNames(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dev", "block", "259:0")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "uevent"),
		[]byte("MAJOR=259\nMINOR=0\nDEVNAME=nvme0n1\nDEVTYPE=disk\n"), 0o644))

	now := time.Now()
	names := &blockDevices{sysRoot: root, procRoot: root, now: func() time.Time { return now }}
	assert.Equal(t, "nvme0n1", names.device(259, 0).name)
	assert.Equal(t, "8:0", names.device(8, 0).name, "falls back to major:minor when sysfs has no name")

	// the device was detached, and its numbers given to another one
	require.NoError(t, os.WriteFile(filepath.Join(dir, "uevent"),
		[]byte("MAJOR=259\nMINOR=0\nDEVNAME=nvme1n1\nDEVTYPE=disk\n"), 0o644))
	assert.Equal(t, "nvme0n1", names.device(259, 0).name, "cached")
	now = now.Add(blockDevicesCachePeriod)
	assert.Equal(t, "nvme1n1", names.device(259, 0).name, "read again once the cache expired")

	// a device that appears is named at its first I/O, as unknown devices are not cached
	other := filepath.Join(root, "dev", "block", "8:0")
	require.NoError(t, os.MkdirAll(other, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(other, "uevent"), []byte("DEVNAME=sda\n"), 0o644))
	assert.Equal(t, "sda", names.device(8, 0).name)
}

func TestDeviceNamesOfHiddenNVMePaths(t *testing.T) {
	// NVMe native multipath: sysfs links the numbers of the head, but not of its path devices
	devices := newFakeBlockDevices(t)
	devices.disk("259:2", "nvme1n1")
	devices.hiddenDisk("259:1", "nvme1c0n1")
	devices.hiddenDisk("259:0", "nvme1c1n1")
	// before Linux 6.1, the kernel lists the paths without their numbers
	devices.hiddenDisk("0:0", "nvme2c0n1")
	devices.hiddenDisk("0:0", "nvme2c1n1")
	now := time.Now()
	names := &blockDevices{sysRoot: devices.sysRoot, procRoot: devices.procRoot, now: func() time.Time { return now }}

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
			assert.Equal(t, tc.want, names.device(tc.major, tc.minor).name)
		})
	}

	// the paths are request-based disks
	assert.False(t, names.device(259, 1).stacked)

	// /proc/diskstats is read once per cache period: a path that appears or is renamed within it
	// is named after the period
	devices.removeAll()
	devices.hiddenDisk("259:1", "nvme1c2n1")
	devices.hiddenDisk("259:3", "nvme3c0n1")
	assert.Equal(t, "nvme1c0n1", names.device(259, 1).name)
	assert.Equal(t, "259:3", names.device(259, 3).name)

	now = now.Add(blockDevicesCachePeriod)
	assert.Equal(t, "nvme1c2n1", names.device(259, 1).name)
	assert.Equal(t, "nvme3c0n1", names.device(259, 3).name)
}

// fakeBlockDevices is a /proc and a /sys root with the block devices that the kernel reports
type fakeBlockDevices struct {
	t                 *testing.T
	procRoot, sysRoot string
	diskstats         []*diskstatsLine
}

type diskstatsLine struct {
	numbers, name string
}

func newFakeBlockDevices(t *testing.T) *fakeBlockDevices {
	root := t.TempDir()
	f := &fakeBlockDevices{t: t, procRoot: filepath.Join(root, "proc"), sysRoot: filepath.Join(root, "sys")}
	require.NoError(t, os.MkdirAll(f.procRoot, 0o755))
	f.write()
	return f
}

// disk adds a block device
func (f *fakeBlockDevices) disk(numbers, name string) {
	f.device(filepath.Join(f.sysRoot, "block", name), numbers, name)
}

// device creates the sysfs directory of a block device, linked from /sys/dev/block as the kernel
// does, and its line of /proc/diskstats
func (f *fakeBlockDevices) device(dir, numbers, name string) {
	require.NoError(f.t, os.MkdirAll(dir, 0o755))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "dev"), []byte(numbers+"\n"), 0o644))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "uevent"), []byte("DEVNAME="+name+"\n"), 0o644))
	byNumbers := filepath.Join(f.sysRoot, "dev", "block")
	require.NoError(f.t, os.MkdirAll(byNumbers, 0o755))
	require.NoError(f.t, os.Symlink(dir, filepath.Join(byNumbers, numbers)))
	f.diskstats = append(f.diskstats, &diskstatsLine{numbers: numbers, name: name})
	f.write()
}

// hiddenDisk adds a block device that /proc/diskstats lists, but that sysfs doesn't link from
// /sys/dev/block, like the path devices of NVMe native multipath
func (f *fakeBlockDevices) hiddenDisk(numbers, name string) {
	f.diskstats = append(f.diskstats, &diskstatsLine{numbers: numbers, name: name})
	f.write()
}

func (f *fakeBlockDevices) removeAll() {
	f.diskstats = nil
	f.write()
}

func (f *fakeBlockDevices) write() {
	lines := make([]string, 0, len(f.diskstats))
	for _, line := range f.diskstats {
		major, minor, _ := strings.Cut(line.numbers, ":")
		lines = append(lines, fmt.Sprintf("%4s %7s %s 0 0 80 5 0 0 160 9 0 12 14 0 0 0 0 0 0",
			major, minor, line.name))
	}
	require.NoError(f.t, os.WriteFile(filepath.Join(f.procRoot, "diskstats"), []byte(strings.Join(lines, "\n")+"\n"), 0o644))
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
		devices.disk(disk.numbers, disk.name)
		devices.blkMQ(disk.name)
	}
	devices.disk("253:1", "dm-1")
	devices.blkMQ("dm-1")
	devices.sysFile("dm-1", "dm/uuid", "mpath-3600a098038303053453f463045727a51")
	devices.holds("dm-1", "sdb")
	devices.holds("dm-1", "sdc")
	// with queue_mode bio, dm-multipath is bio-based
	devices.disk("253:2", "dm-2")
	devices.sysFile("dm-2", "queue/scheduler", "none")
	devices.sysFile("dm-2", "dm/uuid", "mpath-3600a098038303053453f463045727a52")
	devices.holds("dm-2", "sdd")
	devices.disk("253:0", "dm-0")
	devices.sysFile("dm-0", "queue/scheduler", "none")
	devices.sysFile("dm-0", "dm/uuid", "LVM-Jx5HfWYhjVTJlsk1Bm5uXPejJ6Np1HMpbTzX1bz9tJw0ZDhIrb3nG5zhpzbBgJpQ")
	devices.holds("dm-0", "sde")
	devices.disk("259:2", "nvme1n1")
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
		want         bool
	}{
		{name: "a path of a dm-multipath device", major: 8, minor: 16, want: true},
		{name: "another path of it", major: 8, minor: 32, want: true},
		{name: "a path of a bio-based dm-multipath device", major: 8, minor: 48},
		{name: "a disk under an LVM volume", major: 8, minor: 64},
		{name: "a disk", major: 259, minor: 0},
		{name: "a dm-multipath device", major: 253, minor: 1},
		{name: "a path of an NVMe multipath head", major: 259, minor: 1},
		{name: "an NVMe multipath head", major: 259, minor: 2},
		{name: "a path whose head is gone", major: 259, minor: 9},
		{name: "an unknown device", major: 8, minor: 99},
	} {
		t.Run(tc.name, func(t *testing.T) {
			names := &blockDevices{sysRoot: devices.sysRoot, procRoot: devices.procRoot}
			assert.Equal(t, tc.want, names.device(tc.major, tc.minor).dmMultipathPath)
		})
	}
}

func TestMultipathPathsAreRefreshedWithTheDeviceNames(t *testing.T) {
	devices := fakeMultipathHost(t)
	now := time.Now()
	names := &blockDevices{sysRoot: devices.sysRoot, procRoot: devices.procRoot, now: func() time.Time { return now }}
	require.True(t, names.device(8, 16).dmMultipathPath)

	// multipathd removed the multipath device
	require.NoError(t, os.Remove(filepath.Join(devices.sysRoot, "block", "sdb", "holders", "dm-1")))
	assert.True(t, names.device(8, 16).dmMultipathPath, "cached for the cache period")
	now = now.Add(blockDevicesCachePeriod)
	assert.False(t, names.device(8, 16).dmMultipathPath)
}

func TestDiskReaderReportsNoLatencyOfMultipathPaths(t *testing.T) {
	devices := fakeMultipathHost(t)
	written := accum([]uint64{2, 1, 0}, []uint64{500_000, 5_000_000, 0})
	entries := map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(8, 16):  written, // sdb, a path of dm-1
		writeKey(253, 1): written, // dm-1
		writeKey(259, 1): written, // nvme1c0n1, a path of nvme1n1
	}
	type deviceOp struct {
		device string
		op     ebpf.DiskOpCode
	}
	names := &blockDevices{sysRoot: devices.sysRoot, procRoot: devices.procRoot}
	r := newDiskReader(&fakeDiskAccum{entries: entries}, true, names, time.Second)
	stats := map[deviceOp]*ebpf.DiskIO{}
	for _, stat := range r.readStats() {
		stats[deviceOp{device: stat.DiskIO.Device, op: stat.DiskIO.Op}] = stat.DiskIO
	}

	require.Len(t, stats, len(entries))
	assert.Nil(t, stats[deviceOp{"sdb", ebpf.CodeDiskOpWrite}].Latency,
		"the multipath device reports the latency of the I/O of its paths")
	assert.NotNil(t, stats[deviceOp{"dm-1", ebpf.CodeDiskOpWrite}].Latency)
	assert.NotNil(t, stats[deviceOp{"nvme1c0n1", ebpf.CodeDiskOpWrite}].Latency, "the bios of the head are not measured")
}

func TestDeviceMapperNames(t *testing.T) {
	devices := fakeMultipathHost(t)
	devices.sysFile("dm-0", "dm/name", "vg0-data")
	devices.sysFile("dm-1", "dm/name", "mpatha")
	now := time.Now()
	names := &blockDevices{sysRoot: devices.sysRoot, procRoot: devices.procRoot, now: func() time.Time { return now }}

	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{
		writeKey(253, 0): accum([]uint64{1, 0, 0}, []uint64{100_000, 0, 0}), // dm-0, an LVM volume
		writeKey(253, 1): accum([]uint64{1, 0, 0}, []uint64{100_000, 0, 0}), // dm-1, a multipath device
		writeKey(8, 16):  accum([]uint64{1, 0, 0}, []uint64{100_000, 0, 0}), // sdb, a path of dm-1
	}}
	r := newDiskReader(src, true, names, time.Second)
	volumeNames := map[string]string{}
	for _, stat := range r.readStats() {
		volumeNames[stat.DiskIO.Device] = stat.DiskIO.VolumeName
	}
	assert.Equal(t, map[string]string{"dm-0": "vg0-data", "dm-1": "mpatha", "sdb": ""}, volumeNames)
	assert.Empty(t, names.device(8, 99).dmName, "an unknown device")

	// the multipath device was renamed
	devices.sysFile("dm-1", "dm/name", "data")
	assert.Equal(t, "mpatha", names.device(253, 1).dmName, "cached for the cache period")
	now = now.Add(blockDevicesCachePeriod)
	assert.Equal(t, "data", names.device(253, 1).dmName)
}

func TestDeviceMapperNameOfANewDevice(t *testing.T) {
	devices := newFakeBlockDevices(t)
	now := time.Now()
	names := &blockDevices{sysRoot: devices.sysRoot, procRoot: devices.procRoot, now: func() time.Time { return now }}
	assert.Empty(t, names.device(253, 3).dmName, "no device has these numbers yet")

	// a volume is created with the numbers: they were not cached, so it is named within the cache
	// period
	devices.disk("253:3", "dm-3")
	devices.sysFile("dm-3", "dm/name", "vg0-new")
	assert.Equal(t, "vg0-new", names.device(253, 3).dmName)
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
