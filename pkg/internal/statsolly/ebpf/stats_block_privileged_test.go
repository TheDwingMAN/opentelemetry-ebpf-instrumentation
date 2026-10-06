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
	kernelMinorBit            = 20 // MINORBITS: the programs name a device major<<20 | minor
	blkOpWrite                = 1  // blk_op_write in bpf/statsolly/types.h
)

// Synchronous O_DIRECT writes, each followed by fdatasync (what
// `fio --fsync=1 --direct=1` does), on a fresh loop device with the block
// programs attached and the queue depth enabled. Once the device is idle,
// every request the kernel accounted must have produced exactly one event, no
// in-flight entry may be left for the device, and its in-flight counter must
// be back at zero.
func TestBlockRequestsBalanceOnLoopDevice(t *testing.T) {
	fetcher, reader := attachBlockPrograms(t)

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
	assert.Equal(t, delta(diskstatFlushes), seen.flushes, "one event per flush the device completed")
	// fdatasync submits an empty preflush write, which the device never sees:
	// the kernel issues a flush request in its place, and diskstats counts
	// both. Every other write request is one event with its bytes.
	assert.Equal(t, delta(diskstatWrites)-delta(diskstatFlushes), seen.writes-seen.flushes,
		"one write event per completed write request")
	assert.Equal(t, delta(diskstatWriteSectors)*diskstatSectorBytes, seen.writeBytes)

	assertDeviceDrained(t, fetcher, loop.kernelDev)
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
	fetcher, reader := attachBlockPrograms(t)

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

	assertDeviceDrained(t, fetcher, disk.kernelDev)
}

// attachBlockPrograms loads and attaches the block programs the way the agent
// does, with the queue depth enabled.
func attachBlockPrograms(t *testing.T) (*StatsFetcher, *ringbuf.Reader) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs and set up block devices")
	}

	features := export.FeatureStorageBlock | export.FeatureStorageBlockQueueDepth
	fetcher, err := NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })

	reader, err := ringbuf.NewReader(fetcher.StatsEventsMap())
	require.NoError(t, err)
	return fetcher, reader
}

// assertDeviceDrained checks an idle device: no in-flight entry left behind
// and its in-flight counter back at zero.
func assertDeviceDrained(t *testing.T, fetcher *StatsFetcher, dev uint32) {
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

	var state StatsBlkDevState
	require.NoError(t, fetcher.objects.BlkDevState.Lookup(dev, &state))
	assert.Zero(t, state.Inflight, "the device's in-flight counter is back at zero once idle")
}

// The /sys/block/<dev>/stat fields compared with the events.
const (
	diskstatReads        = 0
	diskstatWrites       = 4
	diskstatWriteSectors = 6
	diskstatFlushes      = 15
	diskstatSectorBytes  = 512
)

type testDisk struct {
	path      string
	sysStat   string
	sysInfl   string
	kernelDev uint32
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
	reads      uint64
	writes     uint64
	writeBytes uint64
	flushes    uint64

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
		flushes:         c.flushes - base.flushes,
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
			switch event.Op {
			case blkOpWrite:
				events.seen.writes++
				events.seen.writeBytes += event.Bytes
				if event.Bytes == 0 {
					events.seen.flushes++
				}
			default:
				events.seen.reads++
				if event.Error != 0 {
					events.seen.failedReads++
					events.seen.failedReadBytes += event.Bytes
				}
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
