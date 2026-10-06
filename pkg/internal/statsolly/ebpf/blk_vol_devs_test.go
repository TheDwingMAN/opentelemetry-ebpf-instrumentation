// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	majorDM  = 253
	majorMD  = 9
	majorMDP = 254
)

func devT(major, minor uint32) uint32 { return major<<devMinorBits | minor }

// sysBlockDevice describes one /sys/block entry of a fixture.
type sysBlockDevice struct {
	name string
	// dev is the content of its dev file; none when empty.
	dev string
	// dirs are the directories it has: dm, md, mq, loop, multipath.
	dirs []string
	// holders are the devices stacked on it, parts its partitions.
	holders, parts []string
	// device is the target of its device link, when it has one.
	device string
}

func writeSysBlock(t *testing.T, devices ...sysBlockDevice) string {
	t.Helper()
	sysBlock := t.TempDir()
	for _, d := range devices {
		dir := filepath.Join(sysBlock, d.name)
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "holders"), 0o755))
		for _, sub := range d.dirs {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
		}
		if slices.Contains(d.dirs, "mq") {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "mq", "0"), 0o755))
		}
		for _, h := range d.holders {
			require.NoError(t, os.Symlink("../../"+h, filepath.Join(dir, "holders", h)))
		}
		for _, p := range d.parts {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, p), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, p, "partition"), []byte("1\n"), 0o644))
		}
		if d.dev != "" {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "dev"), []byte(d.dev+"\n"), 0o644))
		}
		if d.device != "" {
			require.NoError(t, os.Symlink(d.device, filepath.Join(dir, "device")))
		}
	}
	return sysBlock
}

// The device layout of the OCP lab (TopoLVM thin volumes on dm-2's pool),
// with the devices the rules exist for added to it.
func labSysBlock(t *testing.T) string {
	return writeSysBlock(t,
		sysBlockDevice{name: "vda", dev: "252:0", dirs: []string{"mq"}, parts: []string{"vda1", "vda2"}},
		sysBlockDevice{name: "loop0", dev: "7:0", dirs: []string{"mq", "loop"}},
		// A thin pool: metadata and data devices, the pool, two thin volumes.
		sysBlockDevice{name: "dm-0", dev: "253:0", dirs: []string{"dm"}, holders: []string{"dm-2"}},
		sysBlockDevice{name: "dm-1", dev: "253:1", dirs: []string{"dm"}, holders: []string{"dm-2"}},
		sysBlockDevice{name: "dm-2", dev: "253:2", dirs: []string{"dm"}, holders: []string{"dm-3", "dm-4"}},
		sysBlockDevice{name: "dm-3", dev: "253:3", dirs: []string{"dm"}},
		sysBlockDevice{name: "dm-4", dev: "253:4", dirs: []string{"dm"}},
		// dm-multipath: request-based, it has hardware queue contexts.
		sysBlockDevice{name: "dm-6", dev: "253:6", dirs: []string{"dm", "mq"}},
		// A linear volume on the multipath device is bio-based again.
		sysBlockDevice{name: "dm-7", dev: "253:7", dirs: []string{"dm"}},
		// An md array with partitions, and one that is an LVM physical volume.
		sysBlockDevice{name: "md127", dev: "9:127", dirs: []string{"md"}, parts: []string{"md127p1", "md127p2"}},
		sysBlockDevice{name: "md0", dev: "9:0", dirs: []string{"md"}, holders: []string{"dm-8"}},
		sysBlockDevice{name: "dm-8", dev: "253:8", dirs: []string{"dm"}},
		// NVMe: a multipath head by its multipath directory, one by its
		// device link, and a namespace without multipath.
		sysBlockDevice{name: "nvme0n1", dev: "259:0", dirs: []string{"multipath"}},
		sysBlockDevice{name: "nvme1n1", dev: "259:1", device: "../../nvme-subsys1"},
		sysBlockDevice{name: "nvme2n1", dev: "259:2", dirs: []string{"mq"}, device: "../../nvme2"},
		// A volume whose sysfs entry is half gone.
		sysBlockDevice{name: "dm-9", dirs: []string{"dm"}},
		sysBlockDevice{name: "zram0", dev: "251:0"},
	)
}

func TestListBlockVolumes(t *testing.T) {
	scan, err := listBlockVolumes(labSysBlock(t))
	require.NoError(t, err)

	assert.Equal(t, map[uint32]string{
		devT(majorDM, 3):   "dm-3",
		devT(majorDM, 4):   "dm-4",
		devT(majorDM, 7):   "dm-7",
		devT(majorDM, 8):   "dm-8",
		devT(majorMD, 127): "md127",
	}, scan.volumes, "the bio-based dm and md devices nothing is stacked on")

	t.Run("lower layers of a stack are left out", func(t *testing.T) {
		for _, lower := range []uint32{devT(majorDM, 0), devT(majorDM, 1), devT(majorDM, 2), devT(majorMD, 0)} {
			assert.NotContains(t, scan.volumes, lower, "a device with holders sees a clone of every bio above it")
		}
	})
	t.Run("an md array with partitions is still a leaf", func(t *testing.T) {
		assert.Contains(t, scan.volumes, devT(majorMD, 127))
	})
	t.Run("request-based dm is never inserted", func(t *testing.T) {
		assert.NotContains(t, scan.volumes, devT(majorDM, 6),
			"its bios fire block_bio_queue and never block_bio_complete")
		assert.Equal(t, []string{"dm-6"}, scan.requestBased)
	})
	t.Run("request-based disks are never inserted", func(t *testing.T) {
		for _, disk := range []uint32{devT(252, 0), devT(7, 0), devT(259, 2), devT(251, 0)} {
			assert.NotContains(t, scan.volumes, disk)
		}
	})
	t.Run("NVMe multipath heads are detected and not tracked", func(t *testing.T) {
		assert.Equal(t, []string{"nvme0n1", "nvme1n1"}, scan.nvmeHeads)
		assert.NotContains(t, scan.volumes, devT(259, 0))
		assert.NotContains(t, scan.volumes, devT(259, 1))
	})

	_, err = listBlockVolumes(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
}

func TestNVMeMultipathHead(t *testing.T) {
	sysBlock := labSysBlock(t)
	for name, want := range map[string]bool{
		"nvme0n1": true, "nvme1n1": true, "nvme2n1": false, "vda": false, "dm-3": false,
	} {
		assert.Equal(t, want, nvmeMultipathHead(filepath.Join(sysBlock, name)), name)
	}
}

func TestBlockVolumeMajors(t *testing.T) {
	t.Run("the majors of the tracked volumes, padded with 0", func(t *testing.T) {
		volumes := map[uint32]string{devT(majorDM, 3): "dm-3", devT(majorDM, 4): "dm-4", devT(majorMD, 127): "md127"}
		majors, tracked := blockVolumeMajors(volumes)
		assert.Equal(t, [blkVolMajors]uint32{majorMD, majorDM, 0}, majors)
		assert.Equal(t, volumes, tracked)
	})
	t.Run("no volume: no major", func(t *testing.T) {
		majors, tracked := blockVolumeMajors(map[uint32]string{})
		assert.Equal(t, [blkVolMajors]uint32{}, majors)
		assert.Empty(t, tracked)
	})
	t.Run("dm, md and mdp fill the filter", func(t *testing.T) {
		volumes := map[uint32]string{devT(majorDM, 0): "dm-0", devT(majorMD, 0): "md0", devT(majorMDP, 0): "md_d0"}
		majors, tracked := blockVolumeMajors(volumes)
		assert.Equal(t, [blkVolMajors]uint32{majorMD, majorDM, majorMDP}, majors)
		assert.Equal(t, volumes, tracked)
	})
	t.Run("a fourth major does not fit: its volumes are not tracked", func(t *testing.T) {
		volumes := map[uint32]string{
			devT(majorDM, 0): "dm-0", devT(majorMD, 0): "md0", devT(majorMDP, 0): "md_d0", devT(300, 0): "x0",
		}
		majors, tracked := blockVolumeMajors(volumes)
		assert.Equal(t, [blkVolMajors]uint32{majorMD, majorDM, majorMDP}, majors)
		assert.Len(t, tracked, 3)
		assert.NotContains(t, tracked, devT(300, 0), "a bio of a major the filter does not hold is never looked up")
	})
}

func TestBlockVolumeDevices(t *testing.T) {
	sysBlock := labSysBlock(t)
	assert.Equal(t, 5, blockVolumeDevices(sysBlock, false))
	assert.Equal(t, 7, blockVolumeDevices(sysBlock, true), "the partitions of md127 are keys of their own")
	assert.Zero(t, blockVolumeDevices(filepath.Join(sysBlock, "missing"), true))
}

// fakeVolumeDevs is the kernel set in memory.
type fakeVolumeDevs struct {
	devs    map[uint32]bool
	addErr  error
	readErr error
	adds    int
}

func (f *fakeVolumeDevs) Devs() ([]uint32, error) {
	return slices.Collect(maps.Keys(f.devs)), f.readErr
}

func (f *fakeVolumeDevs) Add(dev uint32) error {
	f.adds++
	if f.addErr != nil {
		return f.addErr
	}
	f.devs[dev] = true
	return nil
}

func (f *fakeVolumeDevs) Remove(dev uint32) error {
	delete(f.devs, dev)
	return nil
}

func (f *fakeVolumeDevs) sorted() []uint32 { return slices.Sorted(maps.Keys(f.devs)) }

// volumeSetFixture is a volumeSet over a scan the test edits.
type volumeSetFixture struct {
	set    *volumeSet
	kernel *fakeVolumeDevs
	scan   map[uint32]string
	majors [][blkVolMajors]uint32
	now    time.Time
	log    *bytes.Buffer
}

func newVolumeSetFixture(scan map[uint32]string) *volumeSetFixture {
	f := &volumeSetFixture{
		kernel: &fakeVolumeDevs{devs: map[uint32]bool{}}, scan: scan,
		now: time.Unix(1_000_000, 0), log: &bytes.Buffer{},
	}
	log := slog.New(slog.NewTextHandler(f.log, &slog.HandlerOptions{Level: slog.LevelInfo}))
	f.set = newVolumeSet(log,
		func() (blockVolumeScan, error) { return blockVolumeScan{volumes: maps.Clone(f.scan)}, nil },
		f.kernel,
		func(m [blkVolMajors]uint32) error { f.majors = append(f.majors, m); return nil })
	f.set.now = func() time.Time { return f.now }
	return f
}

func (f *volumeSetFixture) warnings() int { return strings.Count(f.log.String(), "level=WARN") }

// The kernel set follows sysfs: volumes are added when they appear and
// removed when they go, and the majors are written only when they change.
func TestVolumeSetSyncsTheKernelSet(t *testing.T) {
	dm3, dm4, md127 := devT(majorDM, 3), devT(majorDM, 4), devT(majorMD, 127)
	f := newVolumeSetFixture(map[uint32]string{dm3: "dm-3", dm4: "dm-4"})
	// An entry a previous run left behind.
	f.kernel.devs[devT(majorDM, 99)] = true

	require.NoError(t, f.set.refresh())
	assert.Equal(t, []uint32{dm3, dm4}, f.kernel.sorted(), "the set is what sysfs lists, nothing else")
	assert.Equal(t, [][blkVolMajors]uint32{{majorDM, 0, 0}}, f.majors)
	assert.Equal(t, []string{"dm-3", "dm-4"}, f.set.names())

	require.NoError(t, f.set.refresh())
	assert.Equal(t, 2, f.kernel.adds, "a volume already tracked is not written again")
	assert.Len(t, f.majors, 1, "unchanged majors are not written again")

	// An md array is assembled, a logical volume removed.
	f.scan[md127] = "md127"
	delete(f.scan, dm4)
	require.NoError(t, f.set.refresh())
	assert.Equal(t, []uint32{md127, dm3}, f.kernel.sorted())
	assert.Equal(t, [blkVolMajors]uint32{majorMD, majorDM, 0}, f.majors[len(f.majors)-1],
		"a new major is written to the kernel filter")

	// The last device-mapper volume goes: so does its major.
	delete(f.scan, dm3)
	require.NoError(t, f.set.refresh())
	assert.Equal(t, []uint32{md127}, f.kernel.sorted())
	assert.Equal(t, [blkVolMajors]uint32{majorMD, 0, 0}, f.majors[len(f.majors)-1])
	assert.Zero(t, f.warnings())
}

func TestVolumeSetWarnsOnceWhenTheKernelSetIsFull(t *testing.T) {
	f := newVolumeSetFixture(map[uint32]string{devT(majorDM, 3): "dm-3", devT(majorDM, 4): "dm-4"})
	f.kernel.addErr = errors.New("map full")

	require.NoError(t, f.set.refresh())
	require.NoError(t, f.set.refresh())
	assert.Empty(t, f.kernel.devs)
	assert.Empty(t, f.set.names(), "a volume the kernel does not hold is not reported as tracked")
	assert.Equal(t, 1, f.warnings())
}

func TestVolumeSetReportsAnUnreadableKernelSet(t *testing.T) {
	f := newVolumeSetFixture(map[uint32]string{devT(majorDM, 3): "dm-3"})
	f.kernel.readErr = errors.New("EPERM")
	require.Error(t, f.set.refresh())

	f.set.list = func() (blockVolumeScan, error) { return blockVolumeScan{}, errors.New("no sysfs") }
	require.Error(t, f.set.refresh())
}

// A volume whose bios are left without a completion is taken out of the set
// with one warning, and stays out while it is the same volume.
func TestVolumeSetQuarantine(t *testing.T) {
	dm3, dm4 := devT(majorDM, 3), devT(majorDM, 4)
	f := newVolumeSetFixture(map[uint32]string{dm3: "dm-3", dm4: "dm-4"})
	require.NoError(t, f.set.refresh())

	f.set.quarantine(dm3, 40)
	assert.Equal(t, []uint32{dm4}, f.kernel.sorted(), "the volume is removed from the kernel set at once")
	assert.Equal(t, 1, f.warnings())
	assert.Contains(t, f.log.String(), "device=dm-3")

	f.set.quarantine(dm3, 40)
	f.set.quarantine(devT(majorDM, 77), 40)
	assert.Equal(t, 1, f.warnings(), "a volume that is not tracked is not quarantined again")

	require.NoError(t, f.set.refresh())
	assert.Equal(t, []uint32{dm4}, f.kernel.sorted(), "a refresh does not bring a quarantined volume back")
	assert.Equal(t, []string{"dm-4"}, f.set.names())

	t.Run("the quarantine ends with the volume", func(t *testing.T) {
		// The logical volume is removed, and its number given to a new one.
		f.scan[dm3] = "dm-3-new"
		require.NoError(t, f.set.refresh())
		assert.Equal(t, []uint32{dm3, dm4}, f.kernel.sorted(), "device numbers are reused: the new volume is tracked")
	})

	t.Run("a volume is tried again after the quarantine, and warned about once", func(t *testing.T) {
		f.set.quarantine(dm4, 20)
		assert.Equal(t, 2, f.warnings())

		f.now = f.now.Add(blkVolQuarantine - time.Second)
		require.NoError(t, f.set.refresh())
		assert.Equal(t, []uint32{dm3}, f.kernel.sorted())

		f.now = f.now.Add(time.Second)
		require.NoError(t, f.set.refresh())
		assert.Equal(t, []uint32{dm3, dm4}, f.kernel.sorted())

		f.set.quarantine(dm4, 20)
		assert.Equal(t, []uint32{dm3}, f.kernel.sorted())
		assert.Equal(t, 2, f.warnings(), "the same volume is not warned about twice")
	})
}

// The majors a quarantine leaves without a volume leave the filter at the
// next refresh.
func TestVolumeSetQuarantineUpdatesTheMajors(t *testing.T) {
	dm3, md127 := devT(majorDM, 3), devT(majorMD, 127)
	f := newVolumeSetFixture(map[uint32]string{dm3: "dm-3", md127: "md127"})
	require.NoError(t, f.set.refresh())

	f.set.quarantine(md127, 16)
	require.NoError(t, f.set.refresh())
	assert.Equal(t, [blkVolMajors]uint32{majorDM, 0, 0}, f.majors[len(f.majors)-1])
}
