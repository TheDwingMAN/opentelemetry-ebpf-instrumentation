// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

const volumeFeatures = export.FeatureStorageBlock | export.FeatureStorageBlockVolumes

// dmVolume creates a device-mapper device with the given table and returns
// it. From v2's linearVolume: without udev (DM_DISABLE_UDEV), dmsetup creates
// the device node itself, which a container whose /dev is not the host's
// needs.
func dmVolume(t *testing.T, table string) *testDisk {
	t.Helper()

	dmsetup, err := exec.LookPath("dmsetup")
	if err != nil {
		t.Skip("dmsetup is not installed")
	}
	name := fmt.Sprintf("obi-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	create := exec.Command(dmsetup, "create", name, "--table", table)
	create.Env = append(os.Environ(), "DM_DISABLE_UDEV=1")
	if out, err := create.CombinedOutput(); err != nil {
		t.Skipf("can't create a device-mapper device (%s): %v: %s", table, err, out)
	}
	t.Cleanup(func() {
		remove := exec.Command(dmsetup, "remove", "--retry", name)
		remove.Env = append(os.Environ(), "DM_DISABLE_UDEV=1")
		if out, err := remove.CombinedOutput(); err != nil {
			t.Logf("dmsetup remove %s: %v: %s", name, err, out)
		}
	})

	out, err := exec.Command(dmsetup, "info", "-c", "--noheadings", "-o", "blkdevname", name).Output()
	require.NoError(t, err)
	sysName := strings.TrimSpace(string(out))
	dev := blockDevFromSysName(t, sysName)
	path := filepath.Join("/dev/mapper", name)
	ensureBlockNode(t, path, dev>>kernelMinorBit, dev&devMinorMask)

	return &testDisk{
		path:      path,
		sysStat:   filepath.Join("/sys/block", sysName, "stat"),
		sysInfl:   filepath.Join("/sys/block", sysName, "inflight"),
		kernelDev: dev,
	}
}

// linearVolume is a dm-linear device over the whole of device.
func linearVolume(t *testing.T, device *testDisk) *testDisk {
	t.Helper()
	sectors := strings.TrimSpace(readString(t, filepath.Join(filepath.Dir(device.sysStat), "size")))
	return dmVolume(t, fmt.Sprintf("0 %s linear %s 0", sectors, device.path))
}

// trackNewVolumes runs the refresh the fetcher runs every 30 s: the test's
// volumes were created after it started.
func trackNewVolumes(t *testing.T, fetcher *StatsFetcher) {
	t.Helper()
	require.NotNil(t, fetcher.blockVolumes, "the bio programs are loaded and attached on this kernel")
	require.NoError(t, fetcher.blockVolumes.set.refresh())
}

func assertNoBioInFlight(t *testing.T, fetcher *StatsFetcher, devs ...uint32) {
	t.Helper()
	var (
		bio   uint64
		entry BlkBioBlkRqInflight
	)
	iter := fetcher.blockVolumes.objects.BlkBioInflight.Iterate()
	for iter.Next(&bio, &entry) {
		assert.NotContains(t, devs, entry.Dev, "in-flight entry left behind for bio %#x", bio)
	}
	require.NoError(t, iter.Err())
}

func trackedVolumes(t *testing.T, fetcher *StatsFetcher) []uint32 {
	t.Helper()
	devs, err := volumeDevMap{fetcher.blockVolumes.objects.BlkBioDevs}.Devs()
	require.NoError(t, err)
	return devs
}

// A stack of two linear volumes on a loop device: loop <- lower <- top. Only
// the top one, which nothing is stacked on, is a tracked volume. Its bios
// are counted once, under its own device, with the bytes diskstats accounts
// for it; the lower volume sees a clone of each bio, queued and completed
// under pointers that are not tracked, and counts nothing; the loop device,
// which issues the requests, is measured by the request programs as before.
func TestBlockVolumesOnStackedLinearDevices(t *testing.T) {
	for name, agg := range map[string]*BlockAggregation{
		"explicit":    aggForTest(false),
		"exponential": aggForTest(true),
	} {
		t.Run(name, func(t *testing.T) {
			fetcher := attachAggregatingBlockPrograms(t, volumeFeatures, agg)
			maps := fetcher.BlockAggregation()
			require.NotNil(t, maps)

			loop := newLoopDevice(t, 4*loopDiscardBytes)
			lower := linearVolume(t, loop)
			top := linearVolume(t, lower)
			trackNewVolumes(t, fetcher)

			tracked := trackedVolumes(t, fetcher)
			assert.Contains(t, tracked, top.kernelDev, "the leaf volume is tracked")
			assert.NotContains(t, tracked, lower.kernelDev, "a volume with a holder is not")
			assert.NotContains(t, tracked, loop.kernelDev, "a request-based device never is")
			require.NotNil(t, maps.PendingBios, "the bios in flight are exposed for pending_operations")

			idle := &blockEvents{}
			before, _ := top.settle(t, idle)
			loopBefore, _ := loop.settle(t, idle)
			base := aggCounts(t, maps, top.kernelDev)
			loopBase := aggCounts(t, maps, loop.kernelDev)

			writeWithFdatasync(t, top.path, loopWrites)
			readBlocks(t, top.path, loopReads)
			discard(t, top.path, loopDiscardBytes, loopDiscardBytes)

			after, _ := top.settle(t, idle)
			loopAfter, _ := loop.settle(t, idle)
			got := aggCounts(t, maps, top.kernelDev).since(base)
			delta := func(field int) uint64 { return after[field] - before[field] }

			assert.Equal(t, uint64(loopWrites), got.writes, "one count per write bio submitted to the volume")
			assert.Equal(t, uint64(loopWrites*loopBlockBytes), got.writeBytes)
			assert.Equal(t, delta(diskstatWriteSectors)*diskstatSectorBytes, got.writeBytes,
				"bytes are what diskstats accounts for the volume")
			// udev may read the new device while the workload runs.
			assert.GreaterOrEqual(t, got.reads, uint64(loopReads))
			assert.Equal(t, delta(diskstatReadSectors)*diskstatSectorBytes, got.readBytes)
			assert.Equal(t, uint64(1), got.discards)
			assert.Equal(t, uint64(loopDiscardBytes), got.discardBytes)
			assert.Equal(t, delta(diskstatDiscardSectors)*diskstatSectorBytes, got.discardBytes)
			assert.Zero(t, got.failed)
			assert.Zero(t, got.queued, "a bio has no queue wait")
			assert.NotZero(t, got.svcSumNs)

			// fdatasync on a block device submits an empty REQ_PREFLUSH
			// write bio, which reaches a volume whose queue has a
			// write-back cache: it is a flush, never a write. dm diskstats
			// counts each as a write of 0 sectors and none as a flush.
			writeCache := strings.TrimSpace(readString(t, top.sysQueue("write_cache")))
			t.Logf("write_cache=%q: %d flush bios; dm diskstats: %d writes, %d flushes",
				writeCache, got.flushes, delta(diskstatWrites), delta(diskstatFlushes))
			if writeCache == "write back" {
				assert.Equal(t, uint64(loopWrites), got.flushes, "one flush per fdatasync")
			} else {
				assert.Zero(t, got.flushes, "without a write-back cache the block layer ends a flush before it is queued")
			}
			assert.Zero(t, got.flushBytes)

			assert.Equal(t, blockAggCounts{}, aggCounts(t, maps, lower.kernelDev),
				"the lower volume's clones are not counted: one I/O, one volume series")

			// The requests the clones became are counted on the disk.
			loopGot := aggCounts(t, maps, loop.kernelDev).since(loopBase)
			loopDelta := func(field int) uint64 { return loopAfter[field] - loopBefore[field] }
			assert.Equal(t, got.writeBytes, loopGot.writeBytes, "the same bytes reach the disk below")
			assert.Equal(t, uint64(loopWrites), loopGot.writes)
			t.Logf("loop below: %d writes, %d flushes, %d queue waits counted; its diskstats: %d writes, %d sectors, %d flushes",
				loopGot.writes, loopGot.flushes, loopGot.queued, loopDelta(diskstatWrites),
				loopDelta(diskstatWriteSectors), loopDelta(diskstatFlushes))

			assertNoBioInFlight(t, fetcher, top.kernelDev, lower.kernelDev, loop.kernelDev)
			assertNothingInFlight(t, fetcher, loop.kernelDev)
			assertNoDrops(t, fetcher.KernelDropsMap())

			programs := fetcher.BlockPrograms()
			assert.Len(t, programs, 4, "the request and the bio programs, completion and issue of each")
			hasBio := false
			for name := range programs {
				hasBio = hasBio || strings.Contains(name, "block_bio_complete")
			}
			assert.True(t, hasBio, "the bio programs' recursion misses are reported")
		})
	}
}

// The error target fails every bio. Each is one failed read of the volume,
// with the errno of BLK_STS_IOERR, although dm diskstats counts none of
// them.
func TestBlockVolumesErrorCompletions(t *testing.T) {
	const reads = 8
	fetcher := attachAggregatingBlockPrograms(t, volumeFeatures, aggForTest(false))
	maps := fetcher.BlockAggregation()

	volume := dmVolume(t, "0 2048 error")
	trackNewVolumes(t, fetcher)
	require.Contains(t, trackedVolumes(t, fetcher), volume.kernelDev)
	before, _ := volume.settle(t, &blockEvents{})

	f, err := os.OpenFile(volume.path, os.O_RDONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	buf, err := unix.Mmap(-1, 0, loopBlockBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	defer func() { _ = unix.Munmap(buf) }()
	for i := range reads {
		_, err := f.ReadAt(buf, int64(i*loopBlockBytes))
		require.ErrorIs(t, err, unix.EIO)
	}
	after, _ := volume.settle(t, &blockEvents{})

	byErrno := map[uint16]uint64{}
	forEachAggValue(t, maps.Service, func(key StatsBlkAggKey, _, _ uint64, buckets []uint32) {
		if key.Dev != volume.kernelDev || StatsBlkIoOp(key.Kind) != StatsBlkIoOpBlkOpRead {
			return
		}
		for _, b := range buckets {
			byErrno[key.Err] += uint64(b)
		}
	})
	assert.GreaterOrEqual(t, byErrno[uint16(unix.EIO)], uint64(reads), "every failed bio is a read error of the volume")
	assert.Zero(t, byErrno[0], "no bio of the error target succeeds")
	// S0-b, 5.14.0-749: dm diskstats counts none of them.
	t.Logf("dm diskstats counted %d reads for %d failed bios", after[diskstatReads]-before[diskstatReads],
		byErrno[uint16(unix.EIO)])

	assertNoBioInFlight(t, fetcher, volume.kernelDev)
	assertNoDrops(t, fetcher.KernelDropsMap())
}

// mdArray assembles a raid1 md array of one member through sysfs, the way
// mdadm --build does (no superblock: metadata "none"), and returns it. The
// test image has no mdadm. Skips when the kernel has no md or no raid1.
func mdArray(t *testing.T, member string) *testDisk {
	t.Helper()

	const newArray = "/sys/module/md_mod/parameters/new_array"
	if _, err := os.Stat(newArray); err != nil {
		t.Skipf("the kernel has no md driver: %v", err)
	}
	minor := uint32(0)
	for m := uint32(200); m < 300; m++ {
		if err := os.WriteFile(newArray, []byte(fmt.Sprintf("md%d", m)), 0); err == nil {
			minor = m
			break
		}
	}
	require.NotZero(t, minor, "no free md minor")
	name := fmt.Sprintf("md%d", minor)
	md := filepath.Join("/sys/block", name, "md")
	t.Cleanup(func() {
		// udev may still hold the new array open for a moment.
		for start := time.Now(); time.Since(start) < 10*time.Second; time.Sleep(100 * time.Millisecond) {
			if os.WriteFile(filepath.Join(md, "array_state"), []byte("clear"), 0) == nil {
				return
			}
		}
		t.Logf("can't stop %s", name)
	})

	memberSys := filepath.Join("/sys/class/block", member)
	size := strings.TrimSpace(readString(t, filepath.Join(memberSys, "size"))) // in 512-byte sectors
	sectors, err := strconv.ParseUint(size, 10, 64)
	require.NoError(t, err)
	kib := strconv.FormatUint(sectors/2, 10)
	rdev := filepath.Join(md, "dev-"+member)
	for _, w := range []struct{ file, value string }{
		{filepath.Join(md, "metadata_version"), "none"},
		{filepath.Join(md, "level"), "raid1"},
		{filepath.Join(md, "raid_disks"), "1"},
		{filepath.Join(md, "new_dev"), strings.TrimSpace(readString(t, filepath.Join(memberSys, "dev")))},
		{filepath.Join(rdev, "slot"), "0"},
		{filepath.Join(rdev, "size"), kib},
		{filepath.Join(md, "component_size"), kib},
		{filepath.Join(md, "array_state"), "active"},
	} {
		if err := os.WriteFile(w.file, []byte(w.value), 0); err != nil {
			t.Skipf("can't assemble an md raid1 array (%s=%s): %v", w.file, w.value, err)
		}
	}

	dev := uint32(mdMajor)<<kernelMinorBit | minor
	path := filepath.Join("/dev", name)
	ensureBlockNode(t, path, mdMajor, minor)
	return &testDisk{
		path:      path,
		sysStat:   filepath.Join("/sys/block", name, "stat"),
		sysInfl:   filepath.Join("/sys/block", name, "inflight"),
		kernelDev: dev,
	}
}

// mdMajor is MD_MAJOR, the major of md arrays; their partitions have the
// extended block major.
const mdMajor = 9

// An md array with partitions (S0-b): a bio submitted to a partition has the
// partition's block_device, 259:N (the extended block major), and the
// array's gendisk, 9:M. The array is tracked by its gendisk, so the bios to
// its partition are counted under the array, with obi.disk.partition naming
// the partition when it is selected; bios to the whole array have none.
func TestBlockVolumesMdPartition(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs and set up block devices")
	}
	const (
		sectorSize     = 512
		firstSector    = 2048
		partitionBytes = 32 << 20
		partWrites     = 16
		wholeWrites    = 4
	)
	features := volumeFeatures
	sel := &attributes.SelectorConfig{SelectionCfg: attributes.Selection{
		attributes.StatDiskIO.Section: attributes.InclusionLists{Include: []string{"*"}},
	}}
	fetcher, err := NewStatsFetcher(&config.EBPFTracer{}, &features, sel, FsAggregation{}, NFSConfig{}, aggForTest(false), nil)
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	maps := fetcher.BlockAggregation()
	require.NotNil(t, maps)

	// The member carries the array's partition table: raid1 without a
	// superblock maps the array onto the member from its first sector. The
	// loop device does not scan it itself (no LO_FLAGS_PARTSCAN).
	mbr := make([]byte, sectorSize)
	entry := mbr[446:462]
	entry[4] = 0x83 // Linux
	binary.LittleEndian.PutUint32(entry[8:], firstSector)
	binary.LittleEndian.PutUint32(entry[12:], partitionBytes/sectorSize)
	mbr[510], mbr[511] = 0x55, 0xaa
	backing, err := os.Create(filepath.Join(t.TempDir(), "member.img"))
	require.NoError(t, err)
	t.Cleanup(func() { backing.Close() })
	require.NoError(t, backing.Truncate(firstSector*sectorSize+partitionBytes))
	_, err = backing.WriteAt(mbr, 0)
	require.NoError(t, err)
	memberPath, _ := attachLoopDeviceTo(t, backing)

	array := mdArray(t, filepath.Base(memberPath))
	f, err := os.Open(array.path)
	require.NoError(t, err)
	require.NoError(t, unix.IoctlSetInt(int(f.Fd()), unix.BLKRRPART, 0))
	f.Close()
	partName := filepath.Base(array.path) + "p1"
	require.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join("/sys/class/block", partName))
		return err == nil
	}, 5*time.Second, 50*time.Millisecond, "the array's partition table is read")
	partDev := blockDevFromSysName(t, partName)
	partPath := filepath.Join("/dev", partName)
	ensureBlockNode(t, partPath, partDev>>kernelMinorBit, partDev&devMinorMask)
	require.NotEqual(t, uint32(mdMajor), partDev>>kernelMinorBit, "the partition is not of the md major")

	trackNewVolumes(t, fetcher)
	tracked := trackedVolumes(t, fetcher)
	require.Contains(t, tracked, array.kernelDev, "the array is a leaf volume: a partition is not a holder")
	require.NotContains(t, tracked, partDev, "volumes are tracked by their whole disk")

	array.settle(t, &blockEvents{})
	for i := range partWrites {
		writeDirectAt(t, partPath, int64(i*loopBlockBytes), loopBlockBytes)
	}
	for i := range wholeWrites {
		// Between the partition table and the partition.
		writeDirectAt(t, array.path, int64(8*loopBlockBytes+i*loopBlockBytes), loopBlockBytes)
	}
	array.settle(t, &blockEvents{})

	writes := map[uint32]uint64{}
	forEachAggValue(t, maps.Service, func(key StatsBlkAggKey, bytes, _ uint64, _ []uint32) {
		if key.Dev == array.kernelDev && StatsBlkIoOp(key.Kind) == StatsBlkIoOpBlkOpWrite {
			writes[key.PartDev] += bytes
		}
		assert.NotEqual(t, partDev, key.Dev, "a partition is never a device of its own")
	})
	assert.Equal(t, uint64(partWrites*loopBlockBytes), writes[partDev], "the partition's writes, under the array")
	assert.Equal(t, uint64(wholeWrites*loopBlockBytes), writes[0], "the array's own writes have no partition")

	assertNoBioInFlight(t, fetcher, array.kernelDev)
	assertNoDrops(t, fetcher.KernelDropsMap())
}

// Without kernel aggregation the bios are sent as events, like requests:
// one per bio, with the volume's device, its kind and its bytes.
func TestBlockVolumesSendEventsWithoutAggregation(t *testing.T) {
	fetcher, reader := attachBlockPrograms(t, volumeFeatures|export.FeatureStorageBlockQueueDepth)

	loop := newLoopDevice(t, loopWrites*loopBlockBytes)
	volume := linearVolume(t, loop)
	trackNewVolumes(t, fetcher)
	events := collectBlockEvents(t, reader, volume.kernelDev)

	before, base := volume.settle(t, events)
	writeWithFdatasync(t, volume.path, loopWrites)
	after, seen := volume.settle(t, events)
	seen = seen.since(base)

	assert.Equal(t, uint64(loopWrites), seen.writes)
	assert.Equal(t, uint64(loopWrites*loopBlockBytes), seen.writeBytes)
	assert.Equal(t, (after[diskstatWriteSectors]-before[diskstatWriteSectors])*diskstatSectorBytes, seen.writeBytes)
	assert.Zero(t, seen.emptyWrites, "an empty preflush bio is a flush, not a write of 0 bytes")
	assert.Zero(t, seen.flushBytes)

	assertNoBioInFlight(t, fetcher, volume.kernelDev)
	assertQueueDepthZero(t, fetcher, volume.kernelDev)
	assertQueueDepthZero(t, fetcher, loop.kernelDev)
}

// storage_block_volumes is opt-in: the storage_block umbrella alone loads no
// bio program, and a stacked volume has no series of its own.
func TestBlockVolumesOffLoadsNoBioPrograms(t *testing.T) {
	fetcher := attachAggregatingBlockPrograms(t, export.FeatureStorageBlock, aggForTest(false))
	maps := fetcher.BlockAggregation()
	require.NotNil(t, maps)

	assert.Nil(t, fetcher.blockVolumes)
	assert.Nil(t, maps.PendingBios)
	for name := range fetcher.BlockPrograms() {
		assert.NotContains(t, name, "block_bio")
	}

	loop := newLoopDevice(t, loopWrites*loopBlockBytes)
	volume := linearVolume(t, loop)
	loopBase := aggCounts(t, maps, loop.kernelDev)
	writeWithFdatasync(t, volume.path, loopWrites)
	volume.settle(t, &blockEvents{})
	loop.settle(t, &blockEvents{})

	assert.Equal(t, blockAggCounts{}, aggCounts(t, maps, volume.kernelDev))
	assert.Equal(t, uint64(loopWrites), aggCounts(t, maps, loop.kernelDev).since(loopBase).writes,
		"its I/O is measured on the disk below")
}

// The flag adds devices to the block metrics; alone it enables none, so
// there is nothing to load.
func TestBlockVolumesNeedABlockMetric(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs")
	}
	features := export.FeatureStorageBlockVolumes
	fetcher, err := NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{}, FsAggregation{}, NFSConfig{}, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	assert.Nil(t, fetcher.blockVolumes)
	assert.Nil(t, fetcher.BlockAggregation())
}

// The sweep on the real map: entries left for longer than the stale age are
// deleted, in batches, and a volume that left many is taken out of the
// kernel set with one warning. A volume that leaves a few keeps its place.
func TestBlockVolumesSweepOnTheKernelMaps(t *testing.T) {
	fetcher := attachAggregatingBlockPrograms(t, volumeFeatures, aggForTest(false))

	loop := newLoopDevice(t, loopWrites*loopBlockBytes)
	dead := linearVolume(t, loop)
	loop2 := newLoopDevice(t, loopWrites*loopBlockBytes)
	healthy := linearVolume(t, loop2)
	trackNewVolumes(t, fetcher)

	var logged bytes.Buffer
	volumes := fetcher.blockVolumes
	volumes.set.log = slog.New(slog.NewTextHandler(&logged, nil))
	volumes.sweeper.log = volumes.set.log

	// Bios whose completion was never seen: keys no live bio has.
	inflight := volumes.objects.BlkBioInflight
	now := uint64(timing.MonoTimeNow())
	stale := now - uint64(2*BlockInflightStaleAge)
	bio := uint64(0xdead_0000)
	put := func(dev uint32, issueNs uint64, n int) {
		for range n {
			bio += 8
			require.NoError(t, inflight.Put(bio, BlkBioBlkRqInflight{IssueNs: issueNs, Dev: dev}))
		}
	}
	const staleOfDead = 3 * blkVolDeadBios
	put(dead.kernelDev, stale, staleOfDead)
	put(healthy.kernelDev, stale, blkVolDeadBios-1)
	put(healthy.kernelDev, now, 5)

	assert.Equal(t, staleOfDead+blkVolDeadBios-1, volumes.sweeper.sweep())

	left := map[uint32]int{}
	var entry BlkBioBlkRqInflight
	iter := inflight.Iterate()
	for iter.Next(&bio, &entry) {
		left[entry.Dev]++
	}
	require.NoError(t, iter.Err())
	assert.Zero(t, left[dead.kernelDev])
	assert.Equal(t, 5, left[healthy.kernelDev], "entries younger than the stale age are bios in flight")

	tracked := trackedVolumes(t, fetcher)
	assert.NotContains(t, tracked, dead.kernelDev, "a volume whose bios never complete is no longer tracked")
	assert.Contains(t, tracked, healthy.kernelDev)
	assert.Equal(t, 1, strings.Count(logged.String(), "level=WARN"), logged.String())

	// Once out of the set, the volume's bios are not inserted any more.
	base := aggCounts(t, fetcher.BlockAggregation(), dead.kernelDev)
	writeWithFdatasync(t, dead.path, loopWrites)
	dead.settle(t, &blockEvents{})
	assertNoBioInFlight(t, fetcher, dead.kernelDev)
	assert.Equal(t, blockAggCounts{}, aggCounts(t, fetcher.BlockAggregation(), dead.kernelDev).since(base))

	require.NoError(t, volumes.set.refresh())
	assert.NotContains(t, trackedVolumes(t, fetcher), dead.kernelDev, "a refresh does not bring it back")
}

// The bios in flight on a slow volume are in the map pending_operations
// reads, with the volume's device, and are gone when they complete.
func TestBlockVolumesBiosInFlightArePending(t *testing.T) {
	fetcher := attachAggregatingBlockPrograms(t, volumeFeatures, aggForTest(false))

	loop := newLoopDevice(t, loopWrites*loopBlockBytes)
	const delayMs = 300
	sectors := strings.TrimSpace(readString(t, filepath.Join(filepath.Dir(loop.sysStat), "size")))
	// The delay target holds every bio for delayMs before it passes it on;
	// dmVolume skips the test on a kernel without it.
	slow := dmVolume(t, fmt.Sprintf("0 %s delay %s 0 %d", sectors, loop.path, delayMs))
	trackNewVolumes(t, fetcher)
	slow.settle(t, &blockEvents{})

	f, err := os.OpenFile(slow.path, os.O_RDONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	buf, err := unix.Mmap(-1, 0, loopBlockBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	defer func() { _ = unix.Munmap(buf) }()
	done := make(chan error, 1)
	go func() {
		_, err := f.ReadAt(buf, 0)
		done <- err
	}()

	pending := func() int {
		n := 0
		var (
			bio   uint64
			entry BlkBioBlkRqInflight
		)
		iter := fetcher.BlockAggregation().PendingBios.Iterate()
		for iter.Next(&bio, &entry) {
			if entry.Dev == slow.kernelDev && StatsBlkIoOp(entry.Kind) == StatsBlkIoOpBlkOpRead {
				n++
			}
		}
		return n
	}
	assert.Eventually(t, func() bool { return pending() >= 1 }, delayMs*time.Millisecond, 5*time.Millisecond,
		"the delayed read is in flight on the volume")
	require.NoError(t, <-done)
	slow.settle(t, &blockEvents{})
	assert.Zero(t, pending())

	got := aggCounts(t, fetcher.BlockAggregation(), slow.kernelDev)
	require.NotZero(t, got.reads)
	assert.GreaterOrEqual(t, got.svcSumNs, uint64(delayMs*time.Millisecond),
		"the bio's duration is end to end: it includes what the volume's driver waited")
}

// The raw_tp programs are the fallback of the tp_btf ones, loaded next to
// them, and read the bio through bpf_probe_read_kernel rather than with
// direct loads. A kernel that attaches tp_btf never runs them, so they are
// put in its place here: they must count what the tp_btf programs count.
func TestBlockVolumesRawTracepointPrograms(t *testing.T) {
	fetcher := attachAggregatingBlockPrograms(t, volumeFeatures, aggForTest(false))
	maps := fetcher.BlockAggregation()
	volumes := fetcher.blockVolumes
	require.NotNil(t, volumes)
	if volumes.attached != blockAttachTpBtf {
		t.Skipf("the bio programs are already attached as %s", volumes.attached)
	}
	layout, reason := blockVolumesUnsupported(kernelBTF())
	require.Empty(t, reason)

	for _, l := range slices.Backward(volumes.links) {
		require.NoError(t, l.Close())
	}
	links, err := attachBlockProgramSet(bioPrograms(&volumes.objects.BlkBioPrograms), rawTpBioPrograms(layout))
	require.NoError(t, err)
	volumes.links = links

	loop := newLoopDevice(t, 4*loopDiscardBytes)
	lower := linearVolume(t, loop)
	top := linearVolume(t, lower)
	trackNewVolumes(t, fetcher)

	idle := &blockEvents{}
	before, _ := top.settle(t, idle)
	base := aggCounts(t, maps, top.kernelDev)
	writeWithFdatasync(t, top.path, loopWrites)
	readBlocks(t, top.path, loopReads)
	discard(t, top.path, loopDiscardBytes, loopDiscardBytes)
	after, _ := top.settle(t, idle)
	got := aggCounts(t, maps, top.kernelDev).since(base)
	delta := func(field int) uint64 { return after[field] - before[field] }

	assert.Equal(t, uint64(loopWrites), got.writes)
	assert.Equal(t, delta(diskstatWriteSectors)*diskstatSectorBytes, got.writeBytes)
	assert.GreaterOrEqual(t, got.reads, uint64(loopReads))
	assert.Equal(t, delta(diskstatReadSectors)*diskstatSectorBytes, got.readBytes)
	assert.Equal(t, uint64(1), got.discards)
	assert.Equal(t, uint64(loopDiscardBytes), got.discardBytes)
	if strings.TrimSpace(readString(t, top.sysQueue("write_cache"))) == "write back" {
		assert.Equal(t, uint64(loopWrites), got.flushes, "one flush per fdatasync")
	}
	assert.Zero(t, got.failed)
	assert.Equal(t, blockAggCounts{}, aggCounts(t, maps, lower.kernelDev), "the lower volume's clones are not counted")

	assertNoBioInFlight(t, fetcher, top.kernelDev, lower.kernelDev, loop.kernelDev)
	assertNoDrops(t, fetcher.KernelDropsMap())
}

// blockProgramRuns is what the kernel accounted for the attached block
// programs (BPF_ENABLE_STATS): runs and run time of each, by the tracepoint
// it is attached to.
type blockProgramRuns map[string]ebpf.ProgramStats

func blockProgramStats(t *testing.T, fetcher *StatsFetcher) blockProgramRuns {
	t.Helper()
	runs := blockProgramRuns{}
	for name, prog := range fetcher.BlockPrograms() {
		stats, err := prog.Stats()
		require.NoError(t, err)
		for _, tp := range []string{
			RawTracepointBlockBioQueue, RawTracepointBlockBioComplete, "block_rq_issue", "block_rq_complete",
		} {
			if strings.Contains(name, tp) {
				runs[tp] = *stats
			}
		}
	}
	require.Len(t, runs, 4, "the request and the bio programs, issue and completion of each")
	return runs
}

func (r blockProgramRuns) since(base blockProgramRuns) blockProgramRuns {
	d := blockProgramRuns{}
	for tp, now := range r {
		d[tp] = ebpf.ProgramStats{
			Runtime: now.Runtime - base[tp].Runtime, RunCount: now.RunCount - base[tp].RunCount,
			RecursionMisses: now.RecursionMisses - base[tp].RecursionMisses,
		}
	}
	return d
}

// events is how often tp fired: the runs of its program and the ones the
// kernel skipped because a program was already running on the CPU (the
// tracepoint fired in an interrupt during another run).
func (r blockProgramRuns) events(tp string) uint64 {
	return r[tp].RunCount + r[tp].RecursionMisses
}

// perRun is the mean run time of the program on tp, in nanoseconds.
func (r blockProgramRuns) perRun(tp string) float64 {
	if r[tp].RunCount == 0 {
		return 0
	}
	return float64(r[tp].Runtime.Nanoseconds()) / float64(r[tp].RunCount)
}

// readBlocksConcurrently reads n blocks of path with direct I/O from several
// goroutines, so that the device stays busy and the programs run with warm
// caches, as they do under the load their cost matters for.
func readBlocksConcurrently(t *testing.T, path string, n, readers int) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()

	errs := make(chan error, readers)
	for r := range readers {
		go func() {
			buf, err := unix.Mmap(-1, 0, loopBlockBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = unix.Munmap(buf) }()
			for i := r; i < n; i += readers {
				if _, err := f.ReadAt(buf, int64(i*loopBlockBytes)); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		}()
	}
	for range readers {
		require.NoError(t, <-errs)
	}
}

// The cost of the bio programs, as the kernel accounts it (step 20's perf
// figures; the gate itself is a lab check on the target kernel, so this test
// only reports). The workload is 4 KiB direct reads on loop devices, on the
// three paths a bio takes:
//
//   - read from the disk itself: the queue program runs once per read and
//     rejects the bio on the major of its gendisk. Every bio of every disk on
//     the node pays this one;
//   - read through a volume that is a lower layer of a stack, and so not
//     tracked: the queue program runs twice per read, for the volume's bio
//     (its major passes, the lookup in the set of tracked volumes misses) and
//     for its clone on the disk (rejected), and the completion program once,
//     finding no entry;
//   - read through a tracked volume: the same runs, the volume's bio queued,
//     completed and counted.
//
// A mean per run says little by itself: it depends on the machine and on how
// warm the caches are when the program runs, and the kernel's accounting
// adds two clock reads to each run. So the request programs of the same
// reads are reported next to the bio programs: they do the same work per
// request (an in-flight insert at issue; a lookup, a delete and the
// aggregation at completion) and are the reference the bio programs are held
// against, whatever the machine.
func TestBlockVolumesProgramCost(t *testing.T) {
	const (
		reads   = 100_000
		readers = 8
	)
	fetcher := attachAggregatingBlockPrograms(t, volumeFeatures, aggForTest(false))
	require.NotNil(t, fetcher.blockVolumes)
	stats, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		t.Skipf("can't enable BPF run time statistics: %v", err)
	}
	defer stats.Close()

	// loop1 <- lower <- top: lower has a holder and is not tracked.
	// loop2 <- single: tracked.
	loop1 := newLoopDevice(t, reads*loopBlockBytes)
	lower := linearVolume(t, loop1)
	top := linearVolume(t, lower)
	loop2 := newLoopDevice(t, reads*loopBlockBytes)
	single := linearVolume(t, loop2)
	trackNewVolumes(t, fetcher)
	tracked := trackedVolumes(t, fetcher)
	require.Contains(t, tracked, single.kernelDev)
	require.Contains(t, tracked, top.kernelDev)
	require.NotContains(t, tracked, lower.kernelDev)

	measure := func(disk *testDisk) blockProgramRuns {
		t.Helper()
		idle := &blockEvents{}
		// Warm up the device and the maps.
		readBlocksConcurrently(t, disk.path, reads/10, readers)
		disk.settle(t, idle)
		base := blockProgramStats(t, fetcher)
		readBlocksConcurrently(t, disk.path, reads, readers)
		disk.settle(t, idle)
		return blockProgramStats(t, fetcher).since(base)
	}
	const (
		bioQueue, bioComplete = RawTracepointBlockBioQueue, RawTracepointBlockBioComplete
		rqIssue, rqComplete   = "block_rq_issue", "block_rq_complete"
	)

	onDisk := measure(loop1)
	onLower := measure(lower)
	onVolume := measure(single)
	require.GreaterOrEqual(t, onDisk.events(bioQueue), uint64(reads))
	require.GreaterOrEqual(t, onLower.events(bioQueue), uint64(2*reads))
	require.GreaterOrEqual(t, onLower.events(bioComplete), uint64(reads))
	require.GreaterOrEqual(t, onVolume.events(bioQueue), uint64(2*reads))
	require.GreaterOrEqual(t, onVolume.events(bioComplete), uint64(reads))

	report := func(path string, r blockProgramRuns, queueRunsPerRead float64) {
		t.Helper()
		bio := queueRunsPerRead*r.perRun(bioQueue) + r.perRun(bioComplete)*float64(r[bioComplete].RunCount)/reads
		rq := r.perRun(rqIssue) + r.perRun(rqComplete)
		t.Logf("  %-42s bio queue %6.1f (%d runs, %d skipped)  bio complete %6.1f (%d runs, %d skipped)"+
			"  rq issue %6.1f  rq complete %6.1f | per read: bio programs %6.1f, request programs %6.1f (%.2fx)",
			path, r.perRun(bioQueue), r[bioQueue].RunCount, r[bioQueue].RecursionMisses,
			r.perRun(bioComplete), r[bioComplete].RunCount, r[bioComplete].RecursionMisses,
			r.perRun(rqIssue), r.perRun(rqComplete), bio, rq, bio/rq)
	}
	t.Logf("bio programs attached as %s; %d direct 4 KiB reads from %d readers per path; mean ns per program run:",
		fetcher.blockVolumes.attached, reads, readers)
	report("disk (bio rejected on its major):", onDisk, 1)
	report("untracked volume over a disk:", onLower, 2)
	report("tracked volume over a disk:", onVolume, 2)
	// The tracked bio alone: its queueing is what the two queue runs of a
	// read cost beyond the rejection of the clone.
	queued := 2*onVolume.perRun(bioQueue) - onDisk.perRun(bioQueue)
	completed := onVolume.perRun(bioComplete)
	t.Logf("  tracked bio alone, about: queue %.1f + complete %.1f = %.1f; a request: issue %.1f + complete %.1f = %.1f",
		queued, completed, queued+completed, onVolume.perRun(rqIssue), onVolume.perRun(rqComplete),
		onVolume.perRun(rqIssue)+onVolume.perRun(rqComplete))

	// A skipped completion leaves its bio's entry behind, for the sweep; the
	// others are gone.
	if onVolume[bioComplete].RecursionMisses == 0 && onLower[bioComplete].RecursionMisses == 0 {
		assertNoBioInFlight(t, fetcher, single.kernelDev, top.kernelDev, lower.kernelDev)
	}
	assertNoDrops(t, fetcher.KernelDropsMap())
}
