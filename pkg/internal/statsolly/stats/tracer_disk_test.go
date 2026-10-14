// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"errors"
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

type fakeAccum[K, V comparable] struct {
	entries map[K]V
	err     error
	// afterRead replaces entries once they are read, as the kernel adds to them meanwhile
	afterRead map[K]V
	// lookupAndDeleteErr is the error of lookupAndDelete, as before Linux 5.14
	lookupAndDeleteErr error
}

type fakeDiskAccum = fakeAccum[ebpf.StatsDiskIoKeyT, ebpf.StatsDiskIoAccumT]

func (f *fakeAccum[K, V]) read() (map[K]V, error) {
	entries := maps.Clone(f.entries)
	maps.Copy(f.entries, f.afterRead)
	f.afterRead = nil
	return entries, f.err
}

func (f *fakeAccum[K, V]) lookupAndDelete(key K) (V, error) {
	if f.lookupAndDeleteErr != nil {
		var none V
		return none, f.lookupAndDeleteErr
	}
	last := f.entries[key]
	return last, f.delete(key)
}

func (f *fakeAccum[K, V]) delete(key K) error {
	if _, ok := f.entries[key]; !ok {
		return ciliumebpf.ErrKeyNotExist
	}
	delete(f.entries, key)
	return nil
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
	return newDiskReader(src, &blockDevices{sysRoot: "/nonexistent", procRoot: "/nonexistent"}, defaultDiskReadInterval)
}

func TestDiskReaderForwardsDeltas(t *testing.T) {
	written := accum([]uint64{0, 3}, []uint64{0, 2_000_000})
	written.Bytes = 3 * 4096
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{writeKey(259, 0): written}}
	r := newTestDiskReader(src)

	stats := r.readStats()
	require.Len(t, stats, 1)
	assert.Equal(t, ebpf.StatTypeDiskIO, stats[0].Type)
	assert.Equal(t, "259:0", stats[0].DiskIO.Device, "named after its numbers when sysfs doesn't know it")
	assert.Equal(t, ebpf.CodeDiskOpWrite, stats[0].DiskIO.Op)
	assertLatency(t, stats[0].DiskIO.Latency, 3*0.002, 0, 3)
	assert.Equal(t, uint64(3*4096), stats[0].DiskIO.Bytes)

	// two more requests in the same bucket, one in a higher bucket
	written = accum([]uint64{0, 5, 1}, []uint64{0, 2_000_000, 50_000_000})
	written.Bytes = 6 * 4096
	src.entries[writeKey(259, 0)] = written
	stats = r.readStats()
	require.Len(t, stats, 1)
	assertLatency(t, stats[0].DiskIO.Latency, 2*0.002+0.05, 0, 2, 1)
	assert.Equal(t, uint64(3*4096), stats[0].DiskIO.Bytes)

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

// An entry that stays unchanged is deleted, with what the kernel added to it since its last read when
// the kernel can look it up and delete it at once, and a request that creates it again counts from zero
func TestDiskReaderDeletesIdleEntries(t *testing.T) {
	for _, tc := range []struct {
		name               string
		lookupAndDeleteErr error
		lastGrowth         []uint64
	}{
		{name: "lookup and delete", lastGrowth: []uint64{1}},
		{name: "delete before Linux 5.14", lookupAndDeleteErr: ciliumebpf.ErrNotSupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := writeKey(8, 0)
			src := &fakeDiskAccum{
				entries:            map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{key: accum([]uint64{2}, []uint64{100_000})},
				lookupAndDeleteErr: tc.lookupAndDeleteErr,
			}
			r := newDiskReader(src, &blockDevices{sysRoot: "/nonexistent", procRoot: "/nonexistent"}, diskIdleTime/2)
			require.Len(t, r.readStats(), 1)
			assert.Empty(t, r.readStats())
			assert.Contains(t, src.entries, key, "idle for less than diskIdleTime")

			// a request completes after the read that finds the entry idle long enough
			src.afterRead = map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{key: accum([]uint64{3}, []uint64{100_000})}
			var lastGrowth []uint64
			for _, stat := range r.readStats() {
				lastGrowth = stat.DiskIO.Latency.BucketCounts[:1]
			}
			assert.Equal(t, tc.lastGrowth, lastGrowth)
			assert.NotContains(t, src.entries, key)
			assert.NotContains(t, r.entries, key)

			src.entries[key] = accum([]uint64{1}, []uint64{100_000})
			stats := r.readStats()
			require.Len(t, stats, 1)
			assertLatency(t, stats[0].DiskIO.Latency, 0.0001, 1)
		})
	}
}

// The reader names the container of the cgroup that I/O is charged to, from the names that the kernel
// recorded, once it recorded them
func TestDiskReaderNamesTheContainers(t *testing.T) {
	const (
		containerID      = "8e5e2d4ef4e0ec0ee80e1b7f86c2b8dbdc5a6e1db8c3d2d1b0a19f8e7d6c5b4a"
		otherContainerID = "d36686f9785534531160dc936aec9d711a26eb37f4fc7752a2ae27d0a24345c1"
	)
	chargedTo := func(cgroupID uint64) ebpf.StatsDiskIoKeyT {
		key := writeKey(8, 0)
		key.CgroupId = cgroupID
		return key
	}
	src := &fakeDiskAccum{entries: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{}}
	for _, cgroupID := range []uint64{0, 10, 11, 12} {
		src.entries[chargedTo(cgroupID)] = accum([]uint64{1}, []uint64{100_000})
	}
	names := map[uint64][2]string{10: {"docker-" + containerID + ".scope", "system.slice"}, 11: {"user.slice", ""}}
	lookups := 0
	r := newTestDiskReader(src)
	r.containers = newCgroupContainers(func(cgroupID uint64) (string, string, bool) {
		lookups++
		name, ok := names[cgroupID]
		return name[0], name[1], ok
	}, 16)
	containers := func() []string {
		var ids []string
		for _, stat := range r.readStats() {
			ids = append(ids, stat.DiskIO.ContainerID)
		}
		return ids
	}

	assert.ElementsMatch(t, []string{"", containerID, "", ""}, containers(),
		"no cgroup, the containers of 10, of 11 which isn't a container, and of 12 whose names aren't recorded yet")
	names[12] = [2]string{otherContainerID, "docker"}
	src.entries[chargedTo(10)] = accum([]uint64{2}, []uint64{100_000})
	src.entries[chargedTo(12)] = accum([]uint64{2}, []uint64{100_000})
	assert.ElementsMatch(t, []string{containerID, otherContainerID}, containers())
	assert.Equal(t, 4, lookups, "the names of a cgroup are looked up until they are recorded")
}

// fakeBlockDevices is a fake sysfs, with block devices linked from /sys/dev/block by their numbers,
// and a fake /proc/diskstats
type fakeBlockDevices struct {
	t                 *testing.T
	sysRoot, procRoot string
	diskstats         []string
}

func newFakeBlockDevices(t *testing.T) *fakeBlockDevices {
	return &fakeBlockDevices{t: t, sysRoot: t.TempDir(), procRoot: t.TempDir()}
}

func (f *fakeBlockDevices) blockDevices() *blockDevices {
	return &blockDevices{sysRoot: f.sysRoot, procRoot: f.procRoot}
}

func (f *fakeBlockDevices) add(numbers, name string) {
	f.file(name, "uevent", "DEVNAME="+name+"\nDEVTYPE=disk")
	f.link(filepath.Join("dev", "block", numbers), name)
}

// hidden adds a device that /proc/diskstats lists, but that sysfs doesn't link from /sys/dev/block,
// as the path devices of NVMe native multipath
func (f *fakeBlockDevices) hidden(numbers, name string) {
	major, minor, _ := strings.Cut(numbers, ":")
	f.diskstats = append(f.diskstats, fmt.Sprintf("%4s %7s %s 0 0 80 5 0 0 160 9 0 12 14 0 0 0 0 0 0", major, minor, name))
	diskstats := []byte(strings.Join(f.diskstats, "\n") + "\n")
	require.NoError(f.t, os.WriteFile(filepath.Join(f.procRoot, "diskstats"), diskstats, 0o644))
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

	// the volume was removed, and its numbers given to a new one, and a hidden NVMe path appeared
	fake.file("dm-0", "dm/name", "vg0-new")
	fake.hidden("259:1", "nvme1c0n1")
	assert.Equal(t, "vg0-data", devices.device(253, 0).volumeName, "cached")
	assert.Equal(t, "259:1", devices.device(259, 1).name, "/proc/diskstats is read once per cache period")
	now = now.Add(blockDevicesCachePeriod)
	assert.Equal(t, "vg0-new", devices.device(253, 0).volumeName, "read again once the cache expired")
	assert.Equal(t, "nvme1c0n1", devices.device(259, 1).name, "read again once the cache expired")

	// the numbers of unknown devices are not cached: a new device is named at its first I/O
	fake.add("8:0", "sda")
	assert.Equal(t, blockDevice{name: "sda"}, devices.device(8, 0))
}

func TestDeviceNamesOfHiddenNVMePaths(t *testing.T) {
	fake := newFakeBlockDevices(t)
	fake.add("259:2", "nvme1n1")
	fake.hidden("259:1", "nvme1c0n1")
	fake.hidden("259:0", "nvme1c1n1")
	// before Linux 6.1, the kernel lists the hidden paths without their numbers
	fake.hidden("0:0", "nvme2c0n1")
	fake.hidden("0:0", "nvme2c1n1")
	devices := fake.blockDevices()
	for numbers, name := range map[devNum]string{
		{259, 2}: "nvme1n1",
		{259, 1}: "nvme1c0n1",
		{259, 0}: "nvme1c1n1",
		{259, 3}: "259:3",
		{0, 0}:   "0:0",
	} {
		assert.Equal(t, blockDevice{name: name}, devices.device(numbers.major, numbers.minor))
	}
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
	for _, stat := range newDiskReader(src, fake.blockDevices(), defaultDiskReadInterval).readStats() {
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

// The paths of a measured dm-multipath device are marked, so that the histogram exporters leave them
// out, as the multipath device reports the same requests: the multipath device is not stacked
func TestDiskReaderMarksTheMultipathPaths(t *testing.T) {
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
	type marks struct{ stacked, multipathPath bool }
	devices := map[string]marks{}
	for _, stat := range newDiskReader(src, fake.blockDevices(), defaultDiskReadInterval).readStats() {
		devices[stat.DiskIO.Device] = marks{stacked: stat.DiskIO.Stacked, multipathPath: stat.DiskIO.MultipathPath}
	}
	assert.Equal(t, map[string]marks{
		"sdb": {multipathPath: true}, "sdc": {multipathPath: true},
		"sdd": {}, "sde": {}, "dm-1": {}, "dm-3": {},
		"dm-0": {stacked: true}, "dm-2": {stacked: true},
	}, devices, "sdb and sdc are the paths of dm-1 and dm-3")
}
