// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// diskVolumesInterval is the time between two resolutions of the disks of the stacked volumes
const diskVolumesInterval = 30 * time.Second

// maxDeviceStackDepth bounds the walk from a device to the disks below it, e.g. a partition
// of an md RAID volume on LVM volumes on disk partitions
const maxDeviceStackDepth = 8

// DiskVolumesTracer periodically resolves the stacked volumes of the host, such as LVM, md RAID or
// loop devices, into the disks they are on, and forwards them as stats.
type DiskVolumesTracer struct {
	stack    *deviceStack
	interval time.Duration

	// reported are the volume disks of the previous resolution, to report the ones that are gone
	reported map[ebpf.DiskVolume]bool
}

func NewDiskVolumesTracer(bioMeasured bool) *DiskVolumesTracer {
	return &DiskVolumesTracer{
		stack:    newDeviceStack("/sys", bioMeasured),
		interval: diskVolumesInterval,
		reported: map[ebpf.DiskVolume]bool{},
	}
}

func (d *DiskVolumesTracer) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return readEvery(d.interval, d.readStats, out)
}

// readEvery forwards the stats that read returns now, and then every interval
func readEvery(interval time.Duration, read func() []*ebpf.Stat, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if stats := read(); len(stats) > 0 {
				out.SendCtx(ctx, stats)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
}

// readStats returns a stat of value 1 for each disk that each stacked volume is on, and of value 0
// for the ones that were reported before and are gone
func (d *DiskVolumesTracer) readStats() []*ebpf.Stat {
	devices, err := os.ReadDir(filepath.Join(d.stack.sysRoot, "block"))
	if err != nil {
		// without the devices, the volumes would be reported as gone: the next read reports them
		dtlog().Debug("can't list the block devices", "error", err)
		return nil
	}
	current := map[ebpf.DiskVolume]bool{}
	var stats []*ebpf.Stat
	for _, device := range devices {
		for _, volume := range d.volumeDisks(device.Name()) {
			current[volume] = true
			stats = append(stats, diskVolumeStat(volume, 1))
		}
	}
	for volume := range d.reported {
		if !current[volume] {
			stats = append(stats, diskVolumeStat(volume, 0))
		}
	}
	d.reported = current
	return stats
}

// volumeDisks resolves a block device into one DiskVolume per disk that it is on. It returns none
// for the devices that are not stacked, and for the volumes on no disk, like a loop device on a
// file of tmpfs, which the walk returns as their own disk.
func (d *DiskVolumesTracer) volumeDisks(name string) []ebpf.DiskVolume {
	dir := filepath.Join(d.stack.sysRoot, "block", name)
	if !isStacked(dir) {
		return nil
	}
	dmName := deviceMapperName(dir)
	var disks []string
	if isDMMultipath(dir) {
		// the volumes over a multipath device that OBI measures stop at it, but it is on its paths
		disks = d.stack.slaveDisks(dir, maxDeviceStackDepth)
	} else {
		disks = d.stack.physicalDisks(dir, maxDeviceStackDepth)
	}
	var volumes []ebpf.DiskVolume
	for _, disk := range disks {
		if disk == name {
			continue
		}
		volumes = append(volumes, ebpf.DiskVolume{Volume: name, Name: dmName, Device: disk})
	}
	return volumes
}

func diskVolumeStat(volume ebpf.DiskVolume, value int64) *ebpf.Stat {
	volume.Value = value
	return &ebpf.Stat{Type: ebpf.StatTypeDiskVolume, DiskVolume: &volume}
}

// deviceStack walks sysfs from the block devices of the host to the disks below them
type deviceStack struct {
	sysRoot string
	// bioMeasured tells whether OBI measures the bio-based devices (stats_disk_bio_devices), like
	// the dm-multipath devices of queue_mode bio
	bioMeasured bool
	// deviceOf returns the device of a path of the host
	deviceOf func(path string) (major, minor uint32, err error)
}

func newDeviceStack(sysRoot string, bioMeasured bool) *deviceStack {
	return &deviceStack{sysRoot: sysRoot, bioMeasured: bioMeasured, deviceOf: hostPathDevice}
}

// blockDeviceDir returns the sysfs directory of a block device, and false for the devices of the
// filesystems on no block device, like overlay, tmpfs or network filesystems
func (s *deviceStack) blockDeviceDir(major, minor uint32) (string, bool) {
	dir := filepath.Join(s.sysRoot, "dev", "block", fmt.Sprintf("%d:%d", major, minor))
	return dir, exists(dir)
}

// physicalDisks returns the names of the disks that a block device is on, from its sysfs
// directory: the disk of a partition, the disks of the filesystem that holds the file of a loop
// device, or the disks below the slaves of a stacked device. The walk stops at the dm-multipath
// devices that OBI measures, as it does at the heads of NVMe native multipath, which have no
// slaves: they report the I/O of their paths, so the I/O of a volume on a LUN is on one device. A
// bio-based dm-multipath device (queue_mode bio) reports none while OBI doesn't measure the
// bio-based devices: the walk goes on to its paths.
func (s *deviceStack) physicalDisks(dir string, depth int) []string {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || depth == 0 {
		return nil
	}
	if exists(filepath.Join(resolved, "partition")) {
		return s.physicalDisks(filepath.Dir(resolved), depth-1)
	}
	if backing, ok := s.loopBackingDevice(resolved); ok {
		return s.physicalDisks(backing, depth-1)
	}
	if isDMMultipath(resolved) && isMeasured(resolved, s.bioMeasured) {
		return []string{filepath.Base(resolved)}
	}
	return s.slaveDisks(resolved, depth)
}

// slaveDisks returns the names of the disks below the slaves of a block device, from its sysfs
// directory, or the device itself when it has no slaves
func (s *deviceStack) slaveDisks(dir string, depth int) []string {
	slaves, _ := filepath.Glob(filepath.Join(dir, "slaves", "*"))
	if len(slaves) == 0 {
		return []string{filepath.Base(dir)}
	}
	var disks []string
	for _, slave := range slaves {
		for _, disk := range s.physicalDisks(slave, depth-1) {
			if !slices.Contains(disks, disk) {
				disks = append(disks, disk)
			}
		}
	}
	return disks
}

// loopBackingDevice returns the sysfs directory of the block device of the filesystem that holds
// the file of a loop device, which it finds by its path on the host. It returns false for other
// devices, and when the file was deleted, isn't at that path on the host (e.g. a loop device set
// up in the mount namespace of a container), or is on no block device.
func (s *deviceStack) loopBackingDevice(dir string) (string, bool) {
	content, err := os.ReadFile(filepath.Join(dir, "loop", "backing_file"))
	if err != nil {
		return "", false
	}
	// the kernel appends " (deleted)" to the path of a deleted file
	path, deleted := strings.CutSuffix(strings.TrimSuffix(string(content), "\n"), " (deleted)")
	if deleted {
		return "", false
	}
	major, minor, err := s.deviceOf(path)
	if err != nil {
		return "", false
	}
	return s.blockDeviceDir(major, minor)
}
