// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// fakeBlockDevices is a /proc and a /sys root with the block devices, the requests in flight and
// the completed requests that the kernel reports
type fakeBlockDevices struct {
	t                 *testing.T
	procRoot, sysRoot string
	diskstats         []*diskstatsLine
}

type diskstatsLine struct {
	numbers, name                   string
	inFlight                        int
	completedReads, completedWrites int
}

func newFakeBlockDevices(t *testing.T) *fakeBlockDevices {
	root := t.TempDir()
	f := &fakeBlockDevices{t: t, procRoot: filepath.Join(root, "proc"), sysRoot: filepath.Join(root, "sys")}
	require.NoError(t, os.MkdirAll(f.procRoot, 0o755))
	f.write()
	return f
}

// disk adds a block device with the requests it reports in flight
func (f *fakeBlockDevices) disk(numbers, name string, reads, writes int) {
	f.device(filepath.Join(f.sysRoot, "block", name), numbers, name, reads, writes)
}

// partition adds a partition of a disk with the requests it reports in flight
func (f *fakeBlockDevices) partition(disk, numbers, name string, reads, writes int) {
	dir := filepath.Join(f.sysRoot, "block", disk, name)
	f.device(dir, numbers, name, reads, writes)
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "partition"), []byte("1\n"), 0o644))
}

// device creates the sysfs directory of a block device, linked from /sys/dev/block as the kernel
// does, and its line of /proc/diskstats
func (f *fakeBlockDevices) device(dir, numbers, name string, reads, writes int) {
	require.NoError(f.t, os.MkdirAll(dir, 0o755))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "dev"), []byte(numbers+"\n"), 0o644))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "uevent"), []byte("DEVNAME="+name+"\n"), 0o644))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "inflight"), fmt.Appendf(nil, "%8d %8d\n", reads, writes), 0o644))
	byNumbers := filepath.Join(f.sysRoot, "dev", "block")
	require.NoError(f.t, os.MkdirAll(byNumbers, 0o755))
	require.NoError(f.t, os.Symlink(dir, filepath.Join(byNumbers, numbers)))
	f.diskstats = append(f.diskstats, &diskstatsLine{
		numbers: numbers, name: name, inFlight: reads + writes, completedReads: 10, completedWrites: 20,
	})
	f.write()
}

// hiddenDisk adds a block device that /proc/diskstats lists, but that sysfs doesn't link from
// /sys/dev/block, like the path devices of NVMe native multipath
func (f *fakeBlockDevices) hiddenDisk(numbers, name string) {
	f.diskstats = append(f.diskstats, &diskstatsLine{numbers: numbers, name: name})
	f.write()
}

// complete makes a device report more completed reads and writes
func (f *fakeBlockDevices) complete(name string, reads, writes int) {
	for _, line := range f.diskstats {
		if line.name == name {
			line.completedReads += reads
			line.completedWrites += writes
		}
	}
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
		lines = append(lines, fmt.Sprintf("%4s %7s %s %d 0 80 5 %d 0 160 9 %d 12 14 0 0 0 0 0 0",
			major, minor, line.name, line.completedReads, line.completedWrites, line.inFlight))
	}
	require.NoError(f.t, os.WriteFile(filepath.Join(f.procRoot, "diskstats"), []byte(strings.Join(lines, "\n")+"\n"), 0o644))
}

func (f *fakeBlockDevices) reader() *pendingReader {
	return newPendingReader(f.procRoot, &deviceNames{sysRoot: f.sysRoot, procRoot: f.procRoot})
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
	devices := newFakeBlockDevices(t)
	// since Linux 5.11, a disk counts the requests of its partitions
	devices.disk("8:0", "sda", 2, 1)
	devices.partition("sda", "8:1", "sda1", 2, 1)
	devices.disk("259:0", "nvme0n1", 0, 0)
	r := devices.reader()

	assert.Equal(t, map[string]int64{"sda/read": 2, "sda/write": 1}, pendingByDevice(r.readStats()))

	// the requests completed: the device is still reported, with nothing in flight
	devices.removeAll()
	assert.Equal(t, map[string]int64{"sda/read": 0, "sda/write": 0}, pendingByDevice(r.readStats()))
}

func TestPendingReaderReportsDevicesThatDidIO(t *testing.T) {
	devices := newFakeBlockDevices(t)
	devices.disk("259:0", "nvme0n1", 0, 0)
	devices.partition("nvme0n1", "259:1", "nvme0n1p1", 0, 0)
	r := devices.reader()
	assert.Empty(t, r.readStats(), "the I/O completed before the first read is not recent")

	// the device completed reads, although no request was in flight at the time of the read
	devices.complete("nvme0n1", 3, 0)
	assert.Equal(t, map[string]int64{"nvme0n1/read": 0}, pendingByDevice(r.readStats()))

	devices.complete("nvme0n1p1", 0, 2)
	devices.complete("nvme0n1", 0, 2)
	assert.Equal(t, map[string]int64{"nvme0n1/read": 0, "nvme0n1/write": 0}, pendingByDevice(r.readStats()),
		"the partitions are reported as their disk, which counts their I/O")
}

func TestPendingReaderReportsHiddenNVMePaths(t *testing.T) {
	devices := newFakeBlockDevices(t)
	devices.disk("259:2", "nvme1n1", 0, 0)
	devices.hiddenDisk("259:1", "nvme1c0n1")
	r := devices.reader()
	assert.Empty(t, r.readStats())

	devices.complete("nvme1c0n1", 0, 2)
	assert.Equal(t, map[string]int64{"nvme1c0n1/write": 0}, pendingByDevice(r.readStats()),
		"named from /proc/diskstats, as sysfs hides the paths of NVMe native multipath")
}

func TestPendingReaderCountsPartitionsOnOlderKernels(t *testing.T) {
	devices := newFakeBlockDevices(t)
	// before Linux 5.11, a disk only counts the requests on the whole disk
	devices.disk("8:0", "sda", 0, 1)
	devices.partition("sda", "8:1", "sda1", 3, 0)
	devices.partition("sda", "8:2", "sda2", 1, 0)

	assert.Equal(t, map[string]int64{"sda/read": 4, "sda/write": 1}, pendingByDevice(devices.reader().readStats()))
}

func TestPendingReaderForgetsIdleDevices(t *testing.T) {
	devices := newFakeBlockDevices(t)
	devices.disk("8:0", "sda", 1, 0)
	r := devices.reader()
	require.Len(t, r.readStats(), 1)

	devices.removeAll()
	for range diskIdleReadsBeforeDelete {
		require.Len(t, r.readStats(), 1, "reported with 0 requests while idle")
	}
	assert.Empty(t, r.readStats(), "forgotten after being idle for long")
}

func TestPendingReaderSkipsUnreadableCounts(t *testing.T) {
	devices := newFakeBlockDevices(t)
	devices.disk("8:0", "sda", 1, 0)
	r := devices.reader()
	require.NoError(t, os.Remove(filepath.Join(devices.sysRoot, "block", "sda", "inflight")))
	assert.Empty(t, r.readStats(), "a device removed since /proc/diskstats was read is skipped")

	require.NoError(t, os.Remove(filepath.Join(devices.procRoot, "diskstats")))
	assert.Nil(t, r.readStats())
}
