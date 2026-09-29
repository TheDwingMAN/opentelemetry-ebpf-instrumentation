// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

const (
	loopMajor = 7
	// scsi_debug's default medium_error_start.
	scsiDebugMediumErrorStart = 0x1234
	loopBlockBytes            = 4096
	loopWrites                = 64
	loopDiscardBytes          = 1 << 20
	kernelMinorBit            = 20 // MINORBITS: the programs name a device major<<20 | minor
)

// Synchronous O_DIRECT writes, each followed by fdatasync (what
// `fio --fsync=1 --direct=1` does), on a fresh loop device with the block
// programs attached and the queue depth enabled. Once the device is idle,
// every request the kernel accounted must have produced exactly one event of
// its kind, no in-flight entry may be left for the device, and its in-flight
// counter must be back at zero.
func TestBlockRequestsBalanceOnLoopDevice(t *testing.T) {
	fetcher, reader := attachBlockPrograms(t, export.FeatureStorageBlock|export.FeatureStorageBlockQueueDepth)

	// The device is created after the programs attached, so every request
	// it ever sees is seen from its issue on.
	loop := newLoopDevice(t, loopWrites*loopBlockBytes)
	events := collectBlockEvents(t, reader, loop.kernelDev)

	// udev probes a new device with reads of its own.
	before, base := loop.settle(t, events)
	writeWithFdatasync(t, loop.path, loopWrites)
	after, seen := loop.settle(t, events)
	seen = seen.since(base)

	delta := func(field int) uint64 { return after[field] - before[field] }
	require.NotZero(t, delta(diskstatWrites), "the workload reached the device")
	assert.Equal(t, delta(diskstatReads), seen.reads, "one read event per completed read request")
	require.NotZero(t, delta(diskstatFlushes), "fdatasync flushed the device's write cache")
	assert.Equal(t, delta(diskstatFlushes), seen.flushes, "one flush event per flush the device completed")
	assert.Zero(t, seen.flushBytes, "a flush moves no data")
	// fdatasync submits an empty preflush write, which the device never sees:
	// the kernel issues a flush request in its place, and diskstats counts
	// both. The flush is not a write: every write event is a write request
	// with its bytes.
	assert.Equal(t, delta(diskstatWrites)-delta(diskstatFlushes), seen.writes,
		"one write event per completed write request, and no flush among them")
	assert.Zero(t, seen.emptyWrites, "no flush is reported as an empty write")
	assert.Equal(t, delta(diskstatWriteSectors)*diskstatSectorBytes, seen.writeBytes)

	assertNothingInFlight(t, fetcher, loop.kernelDev)
	assertQueueDepthZero(t, fetcher, loop.kernelDev)
}

// O_DIRECT|O_DSYNC writes on a raw block device are FUA writes. A loop device
// has no FUA, so the flush machinery emulates it: the data write is issued and
// completes with its bytes, the machinery issues a post-flush, and only then
// ends the write, which fires block_rq_complete a second time with no bytes.
// Each write must be one write event with its bytes, the flushes must be
// flush events, and the second completion must neither count again nor take
// the in-flight counter below the issue's.
func TestBlockFUAWriteOnLoopDevice(t *testing.T) {
	fetcher, reader := attachBlockPrograms(t, export.FeatureStorageBlock|export.FeatureStorageBlockQueueDepth)

	loop := newLoopDevice(t, loopWrites*loopBlockBytes)
	if strings.TrimSpace(readString(t, loop.sysQueue("fua"))) != "0" {
		t.Skip("the loop device supports FUA: no flush sequence to exercise")
	}
	events := collectBlockEvents(t, reader, loop.kernelDev)

	before, base := loop.settle(t, events)
	writeDsync(t, loop.path, loopWrites)
	after, seen := loop.settle(t, events)
	seen = seen.since(base)

	delta := func(field int) uint64 { return after[field] - before[field] }
	t.Logf("diskstats: %d writes, %d flushes; events: %d writes, %d flushes",
		delta(diskstatWrites), delta(diskstatFlushes), seen.writes, seen.flushes)
	require.GreaterOrEqual(t, delta(diskstatFlushes), uint64(loopWrites),
		"each FUA write was emulated with a post-flush")
	assert.Equal(t, uint64(loopWrites), seen.writes, "one write event per FUA write, not one per completion")
	assert.Equal(t, uint64(loopWrites*loopBlockBytes), seen.writeBytes)
	assert.Equal(t, delta(diskstatWriteSectors)*diskstatSectorBytes, seen.writeBytes)
	assert.Zero(t, seen.emptyWrites, "the second, empty completion is not a write")
	assert.Equal(t, delta(diskstatFlushes), seen.flushes, "one flush event per flush the device completed")

	assertNothingInFlight(t, fetcher, loop.kernelDev)
	assertQueueDepthZero(t, fetcher, loop.kernelDev)
}

// A BLKDISCARD of 1 MiB on a loop device (the loop driver punches a hole in
// its backing file) is one discard event of 1 MiB, and neither a read nor a
// write.
func TestBlockDiscardOnLoopDevice(t *testing.T) {
	fetcher, reader := attachBlockPrograms(t, export.FeatureStorageBlock)

	loop := newLoopDevice(t, 4*loopDiscardBytes)
	events := collectBlockEvents(t, reader, loop.kernelDev)

	before, base := loop.settle(t, events)
	discard(t, loop.path, loopDiscardBytes, loopDiscardBytes)
	after, seen := loop.settle(t, events)
	seen = seen.since(base)

	delta := func(field int) uint64 { return after[field] - before[field] }
	require.Equal(t, uint64(1), delta(diskstatDiscards), "the device completed one discard request")
	assert.Equal(t, uint64(1), seen.discards, "one discard event per completed discard request")
	assert.Equal(t, uint64(loopDiscardBytes), seen.discardBytes, "the discard event carries the discarded bytes")
	assert.Equal(t, delta(diskstatDiscardSectors)*diskstatSectorBytes, seen.discardBytes)
	assert.Zero(t, seen.discardErrors)
	assert.Equal(t, delta(diskstatReads), seen.reads, "a discard is not a read")
	assert.Equal(t, delta(diskstatWrites), seen.writes, "a discard is not a write")

	assertNothingInFlight(t, fetcher, loop.kernelDev)
}

// With only the read/write metrics enabled, flushes and discards still release
// their in-flight entries but end in the kernel: no ring buffer event.
func TestBlockFlushAndDiscardStayInKernelWhenOff(t *testing.T) {
	fetcher, reader := attachBlockPrograms(t, export.FeatureStorageBlockDuration)

	loop := newLoopDevice(t, 4*loopDiscardBytes)
	events := collectBlockEvents(t, reader, loop.kernelDev)

	before, base := loop.settle(t, events)
	writeWithFdatasync(t, loop.path, loopWrites)
	discard(t, loop.path, loopDiscardBytes, loopDiscardBytes)
	after, seen := loop.settle(t, events)
	seen = seen.since(base)

	delta := func(field int) uint64 { return after[field] - before[field] }
	require.NotZero(t, delta(diskstatFlushes), "the device completed flushes")
	require.NotZero(t, delta(diskstatDiscards), "the device completed a discard")
	assert.Zero(t, seen.flushes, "no flush event without storage_block_flush")
	assert.Zero(t, seen.discards, "no discard event without storage_block_discard")
	assert.Equal(t, delta(diskstatWrites)-delta(diskstatFlushes), seen.writes,
		"the write events still arrive")

	assertNothingInFlight(t, fetcher, loop.kernelDev)
}

// scsi_debug fails reads of its medium error range (sectors 0x1234 to
// 0x1234+9 by default) with a MEDIUM ERROR that names the first bad sector,
// so SCSI completes a read that straddles the range start in two chunks: the
// good sectors first, then the failed rest. That must be one failed read, not
// two, and must leave nothing in flight. It loads a kernel module, so it only
// runs when asked to, on a disposable machine.
func TestBlockMediumErrorPartialCompletion(t *testing.T) {
	if os.Getenv("OBI_TEST_SCSI_DEBUG") == "" {
		t.Skip("loads scsi_debug; set OBI_TEST_SCSI_DEBUG=1 on a disposable machine")
	}
	fetcher, reader := attachBlockPrograms(t, export.FeatureStorageBlock|export.FeatureStorageBlockQueueDepth)

	disk := newScsiDebugDisk(t)
	events := collectBlockEvents(t, reader, disk.kernelDev)
	before, base := disk.settle(t, events)

	// Four good sectors, then the first bad one.
	const goodSectors = 4
	readDirect(t, disk.path, (scsiDebugMediumErrorStart-goodSectors)*diskstatSectorBytes)
	after, seen := disk.settle(t, events)
	seen = seen.since(base)

	assert.Equal(t, after[diskstatReads]-before[diskstatReads], seen.reads,
		"one read event per completed read request")
	assert.Equal(t, uint64(1), seen.failedReads, "the straddling read is one failed read")
	assert.Equal(t, uint64(goodSectors*diskstatSectorBytes), seen.failedReadBytes,
		"a failed read counts the bytes completed before the failure")

	assertNothingInFlight(t, fetcher, disk.kernelDev)
	assertQueueDepthZero(t, fetcher, disk.kernelDev)
}

// attachBlockPrograms loads and attaches the block programs the way the agent
// does, with the given metrics features.
func attachBlockPrograms(t *testing.T, features export.Features) (*StatsFetcher, *ringbuf.Reader) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs and set up block devices")
	}

	fetcher, err := NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })

	reader, err := ringbuf.NewReader(fetcher.StatsEventsMap())
	require.NoError(t, err)
	return fetcher, reader
}

// assertNothingInFlight checks an idle device has no in-flight entry left
// behind.
func assertNothingInFlight(t *testing.T, fetcher *StatsFetcher, dev uint32) {
	t.Helper()

	var (
		key   uint64
		entry StatsBlkRqInflight
	)
	iter := fetcher.objects.BlkRqInflight.Iterate()
	for iter.Next(&key, &entry) {
		assert.NotEqual(t, dev, entry.Dev, "in-flight entry left behind for request %#x", key)
	}
	require.NoError(t, iter.Err())
}

// assertQueueDepthZero checks an idle device's in-flight counter is back at
// zero; it exists only with the queue depth enabled.
func assertQueueDepthZero(t *testing.T, fetcher *StatsFetcher, dev uint32) {
	t.Helper()

	var state StatsBlkDevState
	require.NoError(t, fetcher.objects.BlkDevState.Lookup(dev, &state))
	assert.Zero(t, state.Inflight, "the device's in-flight counter is back at zero once idle")
}

// The /sys/block/<dev>/stat fields compared with the events.
const (
	diskstatReads          = 0
	diskstatWrites         = 4
	diskstatWriteSectors   = 6
	diskstatDiscards       = 11
	diskstatDiscardSectors = 13
	diskstatFlushes        = 15
	diskstatSectorBytes    = 512
)

type testDisk struct {
	path      string
	sysStat   string
	sysInfl   string
	kernelDev uint32
}

func (l *testDisk) sysQueue(name string) string {
	return filepath.Join(filepath.Dir(l.sysStat), "queue", name)
}

func newLoopDevice(t *testing.T, size int64) *testDisk {
	t.Helper()

	control, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no loop device support: %v", err)
	}
	defer control.Close()
	minor, err := unix.IoctlRetInt(int(control.Fd()), unix.LOOP_CTL_GET_FREE)
	require.NoError(t, err)

	name := fmt.Sprintf("loop%d", minor)
	path := filepath.Join("/dev", name)
	ensureBlockNode(t, path, loopMajor, uint32(minor))

	backing, err := os.Create(filepath.Join(t.TempDir(), "backing"))
	require.NoError(t, err)
	t.Cleanup(func() { backing.Close() })
	require.NoError(t, backing.Truncate(size))

	dev, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() { dev.Close() })
	require.NoError(t, unix.IoctlSetInt(int(dev.Fd()), unix.LOOP_SET_FD, int(backing.Fd())))
	t.Cleanup(func() { _ = unix.IoctlSetInt(int(dev.Fd()), unix.LOOP_CLR_FD, 0) })

	return &testDisk{
		path:      path,
		sysStat:   filepath.Join("/sys/block", name, "stat"),
		sysInfl:   filepath.Join("/sys/block", name, "inflight"),
		kernelDev: loopMajor<<kernelMinorBit | uint32(minor),
	}
}

// ensureBlockNode creates the device node when it is missing: a container's
// /dev only holds the nodes that existed when it started.
func ensureBlockNode(t *testing.T, path string, major, minor uint32) {
	t.Helper()

	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return
	}
	require.NoError(t, unix.Mknod(path, unix.S_IFBLK|0o600, int(unix.Mkdev(major, minor))))
	t.Cleanup(func() { os.Remove(path) })
}

func readUints(t *testing.T, path string) []uint64 {
	t.Helper()

	fields := strings.Fields(readString(t, path))
	values := make([]uint64, len(fields))
	for i, f := range fields {
		value, err := strconv.ParseUint(f, 10, 64)
		require.NoError(t, err)
		values[i] = value
	}
	return values
}

func (l *testDisk) diskstats(t *testing.T) []uint64 {
	t.Helper()

	stats := readUints(t, l.sysStat)
	require.Greater(t, len(stats), diskstatFlushes, "kernel without flush accounting in %s", l.sysStat)
	return stats
}

// settle waits until the device is idle and nothing more arrives, then
// returns its diskstats and the events seen up to then.
func (l *testDisk) settle(t *testing.T, events *blockEvents) ([]uint64, blockEventCounts) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		inflight := readUints(t, l.sysInfl)
		if inflight[0] != 0 || inflight[1] != 0 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		stats := l.diskstats(t)
		// Leave the completions time to cross the ring buffer.
		time.Sleep(500 * time.Millisecond)
		seen := events.counts()
		if slices.Equal(stats, l.diskstats(t)) && seen == events.counts() {
			return stats, seen
		}
	}
	t.Fatal("the loop device never settled")
	return nil, blockEventCounts{}
}

type blockEventCounts struct {
	reads       uint64
	writes      uint64
	writeBytes  uint64
	emptyWrites uint64
	flushes     uint64
	flushBytes  uint64

	discards      uint64
	discardBytes  uint64
	discardErrors uint64

	failedReads     uint64
	failedReadBytes uint64
}

type blockEvents struct {
	mu   sync.Mutex
	seen blockEventCounts
}

func (c blockEventCounts) since(base blockEventCounts) blockEventCounts {
	return blockEventCounts{
		reads:           c.reads - base.reads,
		writes:          c.writes - base.writes,
		writeBytes:      c.writeBytes - base.writeBytes,
		emptyWrites:     c.emptyWrites - base.emptyWrites,
		flushes:         c.flushes - base.flushes,
		flushBytes:      c.flushBytes - base.flushBytes,
		discards:        c.discards - base.discards,
		discardBytes:    c.discardBytes - base.discardBytes,
		discardErrors:   c.discardErrors - base.discardErrors,
		failedReads:     c.failedReads - base.failedReads,
		failedReadBytes: c.failedReadBytes - base.failedReadBytes,
	}
}

func (b *blockEvents) counts() blockEventCounts {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seen
}

// collectBlockEvents counts the block events of one device until the reader
// is closed.
func collectBlockEvents(t *testing.T, reader *ringbuf.Reader, dev uint32) *blockEvents {
	t.Helper()

	events := &blockEvents{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var record ringbuf.Record
		for {
			if err := reader.ReadInto(&record); err != nil {
				return
			}
			if len(record.RawSample) < int(unsafe.Sizeof(StatsBlockIo{})) ||
				StatType(record.RawSample[0]) != StatTypeBlockIo {
				continue
			}
			event := (*StatsBlockIo)(unsafe.Pointer(&record.RawSample[0]))
			if event.Dev != dev {
				continue
			}
			events.mu.Lock()
			switch StatsBlkIoOp(event.Op) {
			case StatsBlkIoOpBlkOpWrite:
				events.seen.writes++
				events.seen.writeBytes += event.Bytes
				if event.Bytes == 0 {
					events.seen.emptyWrites++
				}
			case StatsBlkIoOpBlkOpFlush:
				events.seen.flushes++
				events.seen.flushBytes += event.Bytes
			case StatsBlkIoOpBlkOpDiscard:
				events.seen.discards++
				events.seen.discardBytes += event.Bytes
				if event.Error != 0 {
					events.seen.discardErrors++
				}
			case StatsBlkIoOpBlkOpRead:
				events.seen.reads++
				if event.Error != 0 {
					events.seen.failedReads++
					events.seen.failedReadBytes += event.Bytes
				}
			default:
				t.Errorf("block event with unknown op %d", event.Op)
			}
			events.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		reader.Close()
		<-done
	})
	return events
}

// writeDsync writes blocks with O_DIRECT|O_DSYNC: FUA writes.
func writeDsync(t *testing.T, path string, writes int) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_WRONLY|unix.O_DIRECT|unix.O_DSYNC, 0)
	require.NoError(t, err)
	defer f.Close()

	buf, err := unix.Mmap(-1, 0, loopBlockBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	defer func() { _ = unix.Munmap(buf) }()
	for i := range buf {
		buf[i] = byte(i)
	}

	for i := range writes {
		_, err := f.WriteAt(buf, int64(i*loopBlockBytes))
		require.NoError(t, err)
	}
}

func writeWithFdatasync(t *testing.T, path string, writes int) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_WRONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()

	// O_DIRECT needs an aligned buffer; an anonymous mapping is page aligned.
	buf, err := unix.Mmap(-1, 0, loopBlockBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	defer func() { _ = unix.Munmap(buf) }()
	for i := range buf {
		buf[i] = byte(i)
	}

	for i := range writes {
		_, err := f.WriteAt(buf, int64(i*loopBlockBytes))
		require.NoError(t, err)
		require.NoError(t, unix.Fdatasync(int(f.Fd())))
	}
}

// discard issues BLKDISCARD for length bytes at offset. A backing filesystem
// that cannot punch holes leaves the loop device without discard support.
func discard(t *testing.T, path string, offset, length uint64) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	require.NoError(t, err)
	defer f.Close()

	byteRange := [2]uint64{offset, length}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKDISCARD, uintptr(unsafe.Pointer(&byteRange[0])))
	if errno == unix.EOPNOTSUPP {
		t.Skipf("the loop device's backing file cannot discard: %v", errno)
	}
	require.Zero(t, errno, "BLKDISCARD: %v", errno)
}

func newScsiDebugDisk(t *testing.T) *testDisk {
	t.Helper()

	// opts=2 turns on medium errors; one small disk.
	out, err := exec.Command("modprobe", "scsi_debug", "opts=2", "dev_size_mb=8", "num_tgts=1", "max_luns=1").CombinedOutput()
	require.NoError(t, err, "modprobe scsi_debug: %s", out)
	t.Cleanup(func() { _ = exec.Command("modprobe", "-r", "scsi_debug").Run() })

	var name string
	require.Eventually(t, func() bool {
		matches, _ := filepath.Glob("/sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/*/block/*")
		if len(matches) == 0 {
			return false
		}
		name = filepath.Base(matches[0])
		return true
	}, 30*time.Second, 100*time.Millisecond, "scsi_debug disk never appeared")

	sysDev := filepath.Join("/sys/block", name)
	numbers := strings.Split(strings.TrimSpace(readString(t, filepath.Join(sysDev, "dev"))), ":")
	require.Len(t, numbers, 2)
	major, err := strconv.ParseUint(numbers[0], 10, 32)
	require.NoError(t, err)
	minor, err := strconv.ParseUint(numbers[1], 10, 32)
	require.NoError(t, err)

	path := filepath.Join("/dev", name)
	ensureBlockNode(t, path, uint32(major), uint32(minor))

	return &testDisk{
		path:      path,
		sysStat:   filepath.Join(sysDev, "stat"),
		sysInfl:   filepath.Join(sysDev, "inflight"),
		kernelDev: uint32(major)<<kernelMinorBit | uint32(minor),
	}
}

func readString(t *testing.T, path string) string {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(raw)
}

// readDirect reads one block at offset with O_DIRECT and expects it to fail.
func readDirect(t *testing.T, path string, offset int64) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()

	buf, err := unix.Mmap(-1, 0, loopBlockBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	defer func() { _ = unix.Munmap(buf) }()

	_, err = f.ReadAt(buf, offset)
	require.Error(t, err, "the read straddling the medium error range fails")
}
