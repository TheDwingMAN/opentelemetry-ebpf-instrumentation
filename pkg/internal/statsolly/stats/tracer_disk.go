// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// defaultDiskReadInterval is how often the kernel map is read when ebpf.batch_timeout is 0
const defaultDiskReadInterval = time.Second

// blockDevicesCachePeriod is how long what sysfs tells of the block devices is cached: the kernel
// gives the numbers of removed devices to new ones
const blockDevicesCachePeriod = 30 * time.Second

var timeNow = time.Now

var errAccumFull = errors.New("the accumulation map is full")

func dtlog() *slog.Logger {
	return slog.With("component", "stat.DiskMapTracer")
}

// DiskMapTracer periodically reads the block request durations that the kernel accumulates, and
// forwards what each device and direction gained since the previous read.
type DiskMapTracer struct {
	reader   *diskReader
	interval time.Duration
}

func NewDiskMapTracer(accum *ciliumebpf.Map, cfg *config.EBPFTracer) *DiskMapTracer {
	interval := cfg.BatchTimeout
	if interval <= 0 {
		interval = defaultDiskReadInterval
	}
	read := func() (map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT, error) { return readDiskAccum(accum) }
	return &DiskMapTracer{
		reader:   newDiskReader(read, &blockDevices{sysRoot: "/sys"}),
		interval: interval,
	}
}

func (m *DiskMapTracer) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if stats := m.reader.readStats(); len(stats) > 0 {
					out.SendCtx(ctx, stats)
				}
			}
		}
	}
}

// readDiskAccum returns the entries of the kernel map, with errAccumFull when it is full
func readDiskAccum(accum *ciliumebpf.Map) (map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT, error) {
	entries := map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{}
	var key ebpf.StatsDiskIoKeyT
	var value ebpf.StatsDiskIoAccumT
	iter := accum.Iterate()
	for iter.Next(&key, &value) {
		entries[key] = value
	}
	if err := iter.Err(); err != nil {
		return entries, err
	}
	if len(entries) >= int(accum.MaxEntries()) {
		return entries, errAccumFull
	}
	return entries, nil
}

// diskReader forwards, as stats, what the entries of the kernel map gained since the previous read.
// The kernel never deletes them, so their values only grow.
type diskReader struct {
	log        *slog.Logger
	read       func() (map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT, error)
	devices    *blockDevices
	previous   map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT
	warnedFull bool
}

func newDiskReader(read func() (map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT, error), devices *blockDevices) *diskReader {
	return &diskReader{
		log:      dtlog(),
		read:     read,
		devices:  devices,
		previous: map[ebpf.StatsDiskIoKeyT]ebpf.StatsDiskIoAccumT{},
	}
}

func (r *diskReader) readStats() []*ebpf.Stat {
	entries, err := r.read()
	switch {
	case errors.Is(err, errAccumFull):
		if !r.warnedFull {
			r.warnedFull = true
			r.log.Warn("the disk_io_accum map is full: the I/O of the devices and directions that it "+
				"doesn't hold is not measured", "entries", len(entries))
		}
	case err != nil:
		// what was read is forwarded, and the rest at the next read
		r.log.Debug("can't read the disk_io_accum map", "error", err)
	}

	var stats []*ebpf.Stat
	for key, current := range entries {
		if previous := r.previous[key]; current != previous {
			stats = append(stats, r.stat(key, current, previous))
			r.previous[key] = current
		}
	}
	return stats
}

// stat returns the requests that completed on the device and in the direction of a key since the
// previous read
func (r *diskReader) stat(key ebpf.StatsDiskIoKeyT, current, previous ebpf.StatsDiskIoAccumT) *ebpf.Stat {
	device := r.devices.device(key.Major, key.Minor)
	latency := ebpf.LatencyHistogram{
		BucketCounts: make([]uint64, len(current.LatencyCount)),
		Sum:          float64(current.LatencySumNs-previous.LatencySumNs) / float64(time.Second),
	}
	for bucket := range current.LatencyCount {
		latency.BucketCounts[bucket] = current.LatencyCount[bucket] - previous.LatencyCount[bucket]
	}
	return &ebpf.Stat{
		Type: ebpf.StatTypeDiskIO,
		DiskIO: &ebpf.DiskIO{
			Device:     device.name,
			VolumeName: device.volumeName,
			Stacked:    device.stacked,
			Op:         ebpf.DiskOpCode(key.Op),
			Latency:    latency,
		},
	}
}

type devNum struct {
	major, minor uint32
}

type blockDevice struct {
	name       string
	volumeName string
	stacked    bool
}

type blockDevices struct {
	sysRoot  string
	cachedAt time.Time
	devices  map[devNum]blockDevice
}

// device returns what sysfs tells of a block device. A device that sysfs doesn't know, as one
// removed since its I/O, is named by its "major:minor" numbers, which are not cached, as the kernel
// can give them to a new device.
func (d *blockDevices) device(major, minor uint32) blockDevice {
	if now := timeNow(); now.Sub(d.cachedAt) >= blockDevicesCachePeriod {
		d.cachedAt = now
		d.devices = map[devNum]blockDevice{}
	}
	numbers := devNum{major: major, minor: minor}
	if device, ok := d.devices[numbers]; ok {
		return device
	}
	devNumbers := fmt.Sprintf("%d:%d", major, minor)
	dir := filepath.Join(d.sysRoot, "dev", "block", devNumbers)
	device := blockDevice{
		name:       ueventDevName(filepath.Join(dir, "uevent")),
		volumeName: deviceMapperName(dir),
		stacked:    isStacked(dir),
	}
	if device.name == "" {
		return blockDevice{name: devNumbers}
	}
	d.devices[numbers] = device
	return device
}

func ueventDevName(path string) string {
	uevent, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(uevent)) {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "DEVNAME="); ok {
			return name
		}
	}
	return ""
}
