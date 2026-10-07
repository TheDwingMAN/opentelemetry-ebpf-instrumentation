// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"log/slog"
	"math/bits"
	"os"
	"path/filepath"
	"unsafe"
)

// The kernel's bound arrays (bpf/statsolly/hist.h).
const (
	blkExplicitBounds    = 32
	blkExponentialBounds = 128
	// blkAggErrorKeys is room for the keys failed requests add: one per
	// device, kind and errno that fails.
	blkAggErrorKeys = 32
	// blkAggHotplugDevices is room for the disks attached after OBI starts:
	// on Kubernetes a CSI driver attaches a new disk for each volume it
	// places on the node (up to 25-40 per cloud instance), and the maps,
	// allocated at load, can't grow.
	blkAggHotplugDevices = 32
	// blkAggHotplugPartitions is the extra room, when obi.disk.partition is
	// selected, for the partitions of those disks (or created later): each
	// partition is a key of its own.
	blkAggHotplugPartitions = 128
)

// blkReadWriteKinds are the kinds the queue map counts.
const blkReadWriteKinds = uint8(1<<StatsBlkIoOpBlkOpRead | 1<<StatsBlkIoOpBlkOpWrite)

// blkAggMaps names the aggregation maps of a bucket layout.
type blkAggMaps struct {
	service, queue string
	// serviceValue and queueValue are the sizes of their values, which a
	// per-CPU map allocates for every possible CPU.
	serviceValue, queueValue uintptr
}

var (
	blkAggExplicit = blkAggMaps{
		service: StatsMapBlkAgg, queue: StatsMapBlkQ_agg,
		serviceValue: unsafe.Sizeof(StatsBlkAggVal{}), queueValue: unsafe.Sizeof(StatsBlkQueueAggVal{}),
	}
	blkAggExponential = blkAggMaps{
		service: StatsMapBlkAggExp, queue: StatsMapBlkQ_aggExp,
		serviceValue: unsafe.Sizeof(StatsBlkAggExpVal{}), queueValue: unsafe.Sizeof(StatsBlkQueueAggExpVal{}),
	}
)

func (m blkAggMaps) names() []string { return []string{m.service, m.queue} }

// blockAggPlan is what a load applies for kernel aggregation.
type blockAggPlan struct {
	// agg is nil in the RINGBUF emit mode.
	agg *BlockAggregation
	// maps are the maps the programs count in; their sizes are in the load
	// plan's mapEntries.
	maps blkAggMaps
	// entries and queueEntries are the sizes of the service and queue maps;
	// queue is whether the queue map is in use.
	entries, queueEntries uint32
	queue                 bool
}

// perCPUBytes is the memory a per-CPU map of n entries of value bytes
// allocates for its values: the kernel rounds each CPU's copy up to 8 bytes.
func perCPUBytes(n uint32, value uintptr, cpus int) uint64 {
	return uint64(n) * uint64((value+7)&^7) * uint64(cpus)
}

// blkAggKeys is how many keys a map counting kinds (one bit per enum
// blk_io_op) holds for devices: one per kind and device, plus the errnos.
func blkAggKeys(kinds uint8, devices int) uint64 {
	return uint64(bits.OnesCount8(kinds))*uint64(devices) + blkAggErrorKeys
}

// planBlockAgg sizes the aggregation maps. Every map a load does not count in
// gets one entry. The service map gets a key for each emitted kind of request
// on each request-based device, the queue map one for reads and writes, both
// with room for errnos and for disks attached later, capped so that together
// they fit in the memory budget, counted for every possible CPU. A key that
// does not fit is not counted, and its completions count as drops: the log
// warns when the budget can't hold the keys of the devices present now.
// With wantPart (obi.disk.partition selected) a partition is a device of its
// own in the key, so devices must count partitions too and the hotplug room
// is larger.
// volumes are the tracked stacked volumes (storage_block_volumes), whose
// bios are counted in the service map under the volume's own device. They
// have no queue wait, so the queue map gets no key for them; the budget is
// checked as if it did, which errs on the side of fitting.
func planBlockAgg(agg *BlockAggregation, queue bool, emitKinds uint8, devices, volumes, cpus int, wantPart bool, entries map[string]uint32, log *slog.Logger) blockAggPlan {
	for _, name := range append(blkAggExplicit.names(), blkAggExponential.names()...) {
		entries[name] = unusedMapEntries
	}
	if agg == nil {
		return blockAggPlan{}
	}

	maps := blkAggExplicit
	if agg.Exponential {
		maps = blkAggExponential
	}
	queueKinds := emitKinds & blkReadWriteKinds
	queue = queue && queueKinds != 0
	// Memory per unit of the scale below: one service key per emitted kind
	// and one queue key per read/write kind, for one device.
	perDevice := uint64(bits.OnesCount8(emitKinds)) * perCPUBytes(1, maps.serviceValue, cpus)
	errorKeys := perCPUBytes(blkAggErrorKeys, maps.serviceValue, cpus)
	if queue {
		perDevice += uint64(bits.OnesCount8(queueKinds)) * perCPUBytes(1, maps.queueValue, cpus)
		errorKeys += perCPUBytes(blkAggErrorKeys, maps.queueValue, cpus)
	}
	// The number of devices the budget holds keys for, beyond the error keys.
	hotplug := blkAggHotplugDevices
	if wantPart {
		hotplug += blkAggHotplugPartitions
	}
	fit := 0
	if perDevice > 0 && agg.BudgetBytes > errorKeys {
		fit = int(min((agg.BudgetBytes-errorKeys)/perDevice, uint64(devices+volumes+hotplug)))
	}
	if fit < devices+volumes {
		log.Warn("the block aggregation maps' memory budget can't hold a key for every kind of request on"+
			" each device of this node; completions of keys that do not fit are dropped and counted"+
			" (raise ebpf.storage_aggregation.block_maps_budget_bytes)",
			"devices", devices, "volumes", volumes, "devices_fit", fit, "budget_bytes", agg.BudgetBytes, "cpus", cpus)
	}

	plan := blockAggPlan{agg: agg, maps: maps, queue: queue}
	plan.entries = uint32(blkAggKeys(emitKinds, fit))
	if queue {
		plan.queueEntries = uint32(blkAggKeys(queueKinds, min(fit, devices+hotplug)))
	}
	if fit == 0 && agg.BudgetBytes < errorKeys {
		// Not even the error keys fit: as many keys as the budget holds, at
		// least one.
		perKey := perCPUBytes(1, maps.serviceValue, cpus)
		if queue {
			perKey += perCPUBytes(1, maps.queueValue, cpus)
		}
		plan.entries = uint32(max(agg.BudgetBytes/perKey, 1))
		if queue {
			plan.queueEntries = plan.entries
		}
	}
	entries[maps.service] = plan.entries
	allocated := perCPUBytes(plan.entries, maps.serviceValue, cpus)
	if queue {
		entries[maps.queue] = plan.queueEntries
		allocated += perCPUBytes(plan.queueEntries, maps.queueValue, cpus)
	}
	log.Info("block completions are counted in kernel maps", "map", maps.service,
		"keys", plan.entries, "queue_keys", plan.queueEntries, "devices", devices, "volumes", volumes, "devices_fit", fit,
		"cpus", cpus, "allocated_bytes", allocated)
	return plan
}

// constants returns the load-time constants of the plan.
func (p blockAggPlan) constants() map[string]any {
	var explicit [blkExplicitBounds]uint64
	var exponential [blkExponentialBounds]uint64
	mode, exp := uint8(StatsBlkEmitK_blkEmitRingbuf), uint8(0)
	if p.agg != nil {
		mode = uint8(StatsBlkEmitK_blkEmitAgg)
		if p.agg.Exponential {
			exp = 1
			copy(exponential[:], p.agg.BoundsNs)
		} else {
			copy(explicit[:], p.agg.BoundsNs)
		}
	}
	return map[string]any{
		"blk_emit_mode":     mode,
		"blk_hist_exp":      exp,
		"blk_bounds_ns":     explicit,
		"blk_exp_bounds_ns": exponential,
	}
}

// blockRequestDevices counts the devices whose requests reach the request
// tracepoints: those with hardware queues (mq/). Bio-based devices such as
// dm-linear never do. An unreadable sysfs counts as none.
// With partitions, the partitions of those disks count too.
func blockRequestDevices(sysBlock string, partitions bool) int {
	devices, err := os.ReadDir(sysBlock)
	if err != nil {
		return 0
	}
	n := 0
	for _, dev := range devices {
		if hwQueues, err := os.ReadDir(filepath.Join(sysBlock, dev.Name(), "mq")); err == nil && len(hwQueues) > 0 {
			n++
			if partitions {
				n += blockDevicePartitions(sysBlock, dev.Name())
			}
		}
	}
	return n
}

// blockDevicePartitions counts the partitions of the disk named disk.
func blockDevicePartitions(sysBlock, disk string) int {
	n := 0
	subs, _ := os.ReadDir(filepath.Join(sysBlock, disk))
	for _, sub := range subs {
		if _, err := os.Stat(filepath.Join(sysBlock, disk, sub.Name(), "partition")); err == nil {
			n++
		}
	}
	return n
}

// blockVolumeDevices counts the stacked volumes whose bios would be tracked
// now, for the sizing of the aggregation maps: with partitions, theirs too
// (an md array can have them). An unreadable sysfs counts as none.
func blockVolumeDevices(sysBlock string, partitions bool) int {
	scan, err := listBlockVolumes(sysBlock)
	if err != nil {
		return 0
	}
	_, volumes := blockVolumeMajors(scan.volumes)
	n := len(volumes)
	if partitions {
		for _, name := range volumes {
			n += blockDevicePartitions(sysBlock, name)
		}
	}
	return n
}
