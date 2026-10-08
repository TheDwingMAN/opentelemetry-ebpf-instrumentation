// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// diskVolumesInterval is the time between two resolutions of the disks of the stacked volumes
const diskVolumesInterval = 30 * time.Second

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

// deviceMapperName returns the name of a device mapper volume from its sysfs directory, as
// /dev/mapper names it, or an empty string for other devices
func deviceMapperName(dir string) string {
	content, err := os.ReadFile(filepath.Join(dir, "dm", "name"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(content))
}
