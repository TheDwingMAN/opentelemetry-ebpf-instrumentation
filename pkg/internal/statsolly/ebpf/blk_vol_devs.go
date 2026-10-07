// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// The stacked volumes whose bios are measured (storage_block_volumes): which
// devices they are, read from sysfs, and the kernel's copy of that set, the
// blk_bio_devs map and the majors the bio programs filter on first.

// blkVolMajors is the size of blk_vol_major (k_blk_vol_majors in
// bpf/statsolly/blk_helpers.h): device-mapper's major, md's and mdp's.
const blkVolMajors = 3

// blkVolQuarantine is how long a volume whose bios were left without a
// completion stays out of the set. Long, since a driver that does not trace
// completions never will; not forever, since a volume that hung for minutes
// (a thin pool out of space, a suspended device) and came back looks the
// same, and is worth measuring again.
const blkVolQuarantine = time.Hour

// blockVolumeScan is what a pass over /sys/block found.
type blockVolumeScan struct {
	// volumes are the devices to track, by kernel dev_t.
	volumes map[uint32]string
	// requestBased are the device-mapper devices left out because they are
	// request-based (dm-multipath), nvmeHeads the NVMe multipath heads: both
	// hand their bios to request-based devices as they are, and such a bio
	// never fires block_bio_complete.
	requestBased, nvmeHeads []string
}

// listBlockVolumes returns the bio-based leaf volumes under sysBlock
// (/sys/block): the device-mapper and md devices
//
//   - without an mq/ directory. One with it is request-based (dm-multipath):
//     it has hardware queue contexts, its requests reach the block request
//     tracepoints, and the bios submitted to it fire block_bio_queue but
//     never block_bio_complete, so every one of them would be left in the
//     in-flight map (test from v2's isBioBasedStacked);
//   - with an empty holders/ directory: nothing is stacked on them. A lower
//     layer sees a clone of every bio of the volume above it (a thin volume's
//     I/O is queued and completed again on its pool and on the pool's data
//     device, S0-b), so tracking it would measure each I/O once more and
//     export LVM internals as devices. A partition is not a holder: an md
//     array with partitions is a leaf.
//
// The second rule goes by the whole disk. An array whose partition is an LVM
// physical volume has no holder itself, so it is tracked next to the logical
// volumes on it; both report their own I/O correctly.
func listBlockVolumes(sysBlock string) (blockVolumeScan, error) {
	scan := blockVolumeScan{volumes: map[uint32]string{}}
	devices, err := os.ReadDir(sysBlock)
	if err != nil {
		return scan, fmt.Errorf("listing block devices: %w", err)
	}
	for _, d := range devices {
		name := d.Name()
		dir := filepath.Join(sysBlock, name)
		if nvmeMultipathHead(dir) {
			scan.nvmeHeads = append(scan.nvmeHeads, name)
			continue
		}
		if !isDir(filepath.Join(dir, "dm")) && !isDir(filepath.Join(dir, "md")) {
			continue
		}
		if isDir(filepath.Join(dir, "mq")) {
			scan.requestBased = append(scan.requestBased, name)
			continue
		}
		if holders, err := os.ReadDir(filepath.Join(dir, "holders")); err != nil || len(holders) > 0 {
			// Unreadable is taken for held: tracking a lower layer costs
			// more than missing a volume until the next pass.
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "dev"))
		if err != nil {
			continue
		}
		dev, ok := parseDevT(strings.TrimSpace(string(raw)))
		if !ok || dev == 0 {
			continue
		}
		scan.volumes[dev] = name
	}
	return scan, nil
}

// nvmeMultipathHead reports whether the block device at dir is the head of an
// NVMe native multipath namespace: the device applications open, which picks
// a path for each bio. Newer kernels give it a multipath/ directory listing
// its paths; on the others its device link points at the NVMe subsystem
// instead of at a controller.
//
// A head is bio-based, but it is not tracked: it does not clone a bio, it
// points it at the path's device and submits it again, so the bio ends in a
// request of the path and its completion is traced as that request's
// (block_rq_complete), never as block_bio_complete. Its I/O is measured there,
// on the path devices, by the block request programs.
func nvmeMultipathHead(dir string) bool {
	if !strings.HasPrefix(filepath.Base(dir), "nvme") {
		return false
	}
	if isDir(filepath.Join(dir, "multipath")) {
		return true
	}
	target, err := os.Readlink(filepath.Join(dir, "device"))
	return err == nil && strings.HasPrefix(filepath.Base(target), "nvme-subsys")
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// blockVolumeMajors returns the distinct majors of volumes for the kernel's
// pre-filter, padded with 0, and the volumes that can be tracked with them:
// those of a major beyond the filter's blkVolMajors are left out, lowest
// majors kept, since a bio of a major the filter does not hold is never
// looked up.
func blockVolumeMajors(volumes map[uint32]string) ([blkVolMajors]uint32, map[uint32]string) {
	var all []uint32
	for dev := range volumes {
		if major := dev >> devMinorBits; !slices.Contains(all, major) {
			all = append(all, major)
		}
	}
	slices.Sort(all)

	var majors [blkVolMajors]uint32
	if len(all) <= blkVolMajors {
		copy(majors[:], all)
		return majors, volumes
	}
	copy(majors[:], all[:blkVolMajors])
	tracked := map[uint32]string{}
	for dev, name := range volumes {
		if slices.Contains(majors[:], dev>>devMinorBits) {
			tracked[dev] = name
		}
	}
	return majors, tracked
}

// volumeDevs is the kernel's set of tracked volumes: the blk_bio_devs map.
type volumeDevs interface {
	Devs() ([]uint32, error)
	Add(dev uint32) error
	Remove(dev uint32) error
}

// blkBioDevTracked is the value of every blk_bio_devs entry: the map is a
// set.
const blkBioDevTracked uint8 = 1

type volumeDevMap struct{ m *ebpf.Map }

func (v volumeDevMap) Devs() ([]uint32, error) {
	var devs []uint32
	var dev uint32
	var value uint8
	iter := v.m.Iterate()
	for iter.Next(&dev, &value) {
		devs = append(devs, dev)
	}
	return devs, iter.Err()
}

func (v volumeDevMap) Add(dev uint32) error {
	return v.m.Update(&dev, blkBioDevTracked, ebpf.UpdateAny)
}

func (v volumeDevMap) Remove(dev uint32) error {
	if err := v.m.Delete(&dev); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// volumeSet keeps the kernel's set of tracked volumes in line with sysfs.
type volumeSet struct {
	log  *slog.Logger
	list func() (blockVolumeScan, error)
	devs volumeDevs
	// setMajors writes the kernel's major pre-filter.
	setMajors func([blkVolMajors]uint32) error
	now       func() time.Time

	mu sync.Mutex
	// tracked is the kernel set as of the last refresh.
	tracked map[uint32]string
	// quarantined are the volumes taken out because their bios were left
	// without a completion, by dev_t.
	quarantined map[uint32]volumeQuarantine
	majors      [blkVolMajors]uint32
	// warnedMajors, warnedFull and warnedDead limit their warnings to one;
	// the last by device name.
	warnedMajors, warnedFull bool
	warnedDead               map[string]bool
	skipped                  string
}

type volumeQuarantine struct {
	name  string
	until time.Time
}

func newVolumeSet(
	log *slog.Logger, list func() (blockVolumeScan, error), devs volumeDevs, setMajors func([blkVolMajors]uint32) error,
) *volumeSet {
	return &volumeSet{
		log: log, list: list, devs: devs, setMajors: setMajors, now: time.Now,
		tracked: map[uint32]string{}, quarantined: map[uint32]volumeQuarantine{}, warnedDead: map[string]bool{},
	}
}

// refresh lists the volumes and brings the kernel set in line: the loop of
// v2's bioDevices.refresh (list sysfs, diff against the kernel set), with the
// leaf rule and the quarantine added. It is called at startup and every
// blockVolumeRefreshInterval: a volume created in between is measured from
// the next pass on.
func (s *volumeSet) refresh() error {
	scan, err := s.list()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for dev, q := range s.quarantined {
		// Device numbers are reused: the quarantine is of the volume that
		// had this number, and ends with it.
		if name, present := scan.volumes[dev]; !present || name != q.name || !now.Before(q.until) {
			delete(s.quarantined, dev)
			continue
		}
		delete(scan.volumes, dev)
	}

	majors, want := blockVolumeMajors(scan.volumes)
	if len(want) < len(scan.volumes) && !s.warnedMajors {
		s.warnedMajors = true
		s.log.Warn("the stacked volumes of this node have more device majors than the kernel filter holds;"+
			" the volumes of the other majors are not measured", "majors_tracked", majors, "volumes", len(scan.volumes),
			"volumes_tracked", len(want))
	}

	have, err := s.devs.Devs()
	if err != nil {
		return fmt.Errorf("reading the tracked volumes: %w", err)
	}
	held := make(map[uint32]struct{}, len(have))
	for _, dev := range have {
		held[dev] = struct{}{}
	}
	// Additions first, then the filter, then removals: a bio that passes
	// the filter for a new major finds its volume, and one of a major on
	// its way out still does.
	for dev, name := range want {
		if _, ok := held[dev]; ok {
			continue
		}
		if err := s.devs.Add(dev); err != nil {
			delete(want, dev)
			if !s.warnedFull {
				s.warnedFull = true
				s.log.Warn("can't track a stacked volume; its I/O is not measured", "device", name, "error", err)
			}
			continue
		}
		s.log.Debug("tracking the bios of a stacked volume", "device", name, "dev", fmtDev(dev))
	}
	if majors != s.majors {
		if err := s.setMajors(majors); err != nil {
			return fmt.Errorf("writing the volume majors: %w", err)
		}
		s.majors = majors
	}
	for _, dev := range have {
		if _, ok := want[dev]; ok {
			continue
		}
		if err := s.devs.Remove(dev); err != nil {
			s.log.Debug("can't stop tracking a stacked volume", "dev", fmtDev(dev), "error", err)
			continue
		}
		s.log.Debug("no longer tracking the bios of a device", "device", s.tracked[dev], "dev", fmtDev(dev))
	}
	s.tracked = want

	if skipped := strings.Join(append(slices.Clone(scan.requestBased), scan.nvmeHeads...), ","); skipped != s.skipped {
		s.skipped = skipped
		if skipped != "" {
			s.log.Debug("stacked devices that are not bio-based volumes are measured on the devices below them only",
				"request_based_dm", scan.requestBased, "nvme_multipath_heads", scan.nvmeHeads)
		}
	}
	return nil
}

// names returns the tracked volumes, sorted by name.
func (s *volumeSet) names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Sorted(maps.Values(s.tracked))
}

// quarantine stops tracking dev, of whose bios stale were found left in the
// in-flight map (see bioSweeper), and keeps it out of the set for
// blkVolQuarantine. It warns once per volume.
func (s *volumeSet) quarantine(dev uint32, stale int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name, ok := s.tracked[dev]
	if !ok {
		return
	}
	if err := s.devs.Remove(dev); err != nil {
		s.log.Debug("can't stop tracking a stacked volume", "device", name, "error", err)
		return
	}
	delete(s.tracked, dev)
	s.quarantined[dev] = volumeQuarantine{name: name, until: s.now().Add(blkVolQuarantine)}

	log := s.log.Debug
	if !s.warnedDead[name] {
		s.warnedDead[name] = true
		log = s.log.Warn
	}
	log("bios submitted to a stacked volume were left without a completion: its driver does"+
		" not trace bio completions on this kernel, or the volume hung. It is no longer measured, and is"+
		" tried again later", "device", name, "bios", stale, "retry_after", blkVolQuarantine)
}
