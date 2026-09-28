// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	ciliumebpf "github.com/cilium/ebpf"
)

// bioDevicesRefreshReads is how many reads of the accumulation maps pass between two updates of
// the list of stacked volumes that the kernel measures
const bioDevicesRefreshReads = 30

// deviceSet abstracts the disk_bio_devices eBPF map, for testing
type deviceSet interface {
	devices() ([]uint32, error)
	add(dev uint32) error
	remove(dev uint32) error
}

type ebpfDeviceSet struct {
	set *ciliumebpf.Map
}

func (e ebpfDeviceSet) devices() ([]uint32, error) {
	var devices []uint32
	var dev uint32
	var present uint8
	iter := e.set.Iterate()
	for iter.Next(&dev, &present) {
		devices = append(devices, dev)
	}
	return devices, iter.Err()
}

func (e ebpfDeviceSet) add(dev uint32) error {
	return e.set.Put(dev, uint8(1))
}

func (e ebpfDeviceSet) remove(dev uint32) error {
	return e.set.Delete(dev)
}

// bioDevices keeps the set of stacked volumes whose bios the kernel measures in sync with the
// bio-based stacked devices of the host: the device mapper (LVM, dm-crypt) and md RAID volumes.
// Request-based device mapper volumes, like multipath ones, are left out: the kernel measures
// their requests.
type bioDevices struct {
	log     *slog.Logger
	sysRoot string
	set     deviceSet
}

func newBioDevices(sysRoot string, set deviceSet) *bioDevices {
	return &bioDevices{log: dtlog().With("map", "disk_bio_devices"), sysRoot: sysRoot, set: set}
}

func (b *bioDevices) refresh() {
	want := map[uint32]bool{}
	entries, err := os.ReadDir(filepath.Join(b.sysRoot, "block"))
	if err != nil {
		b.log.Debug("can't list the block devices", "error", err)
		return
	}
	for _, entry := range entries {
		dir := filepath.Join(b.sysRoot, "block", entry.Name())
		if !isBioBasedStacked(dir) {
			continue
		}
		if dev, ok := readKernelDev(dir); ok {
			want[dev] = true
		}
	}

	current, err := b.set.devices()
	if err != nil {
		b.log.Debug("can't read the stacked volumes", "error", err)
		return
	}
	for _, dev := range current {
		if want[dev] {
			delete(want, dev)
			continue
		}
		if err := b.set.remove(dev); err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
			b.log.Debug("can't forget a stacked volume", "dev", dev, "error", err)
		}
	}
	for dev := range want {
		if err := b.set.add(dev); err != nil {
			b.log.Warn("can't measure a stacked volume", "dev", dev, "error", err)
		}
	}
}

// isBioBasedStacked tells whether the sysfs directory of a block device is a device mapper or md
// RAID volume without a request queue (blk-mq devices have an "mq" directory)
func isBioBasedStacked(dir string) bool {
	if exists(filepath.Join(dir, "mq")) {
		return false
	}
	return exists(filepath.Join(dir, "dm")) || exists(filepath.Join(dir, "md"))
}

// isStacked tells whether the sysfs directory of a block device is a device built on other block
// devices, whose I/O is also reported on the devices below: a device mapper, md RAID or loop
// device, or any device that sysfs lists slaves of
func isStacked(dir string) bool {
	for _, kind := range []string{"dm", "md", "loop"} {
		if exists(filepath.Join(dir, kind)) {
			return true
		}
	}
	slaves, err := os.ReadDir(filepath.Join(dir, "slaves"))
	return err == nil && len(slaves) > 0
}

// readKernelDev reads the "major:minor" dev file of a block device as a kernel-internal dev_t
func readKernelDev(dir string) (uint32, bool) {
	content, err := os.ReadFile(filepath.Join(dir, "dev"))
	if err != nil {
		return 0, false
	}
	var major, minor uint32
	if _, err := fmt.Sscanf(strings.TrimSpace(string(content)), "%d:%d", &major, &minor); err != nil {
		return 0, false
	}
	return major<<kernelDevMinorBits | minor, true
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
