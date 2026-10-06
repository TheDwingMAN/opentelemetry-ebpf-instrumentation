// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Layout of a Linux dev_t, as encoded by the kernel's MAJOR()/MINOR() macros.
const (
	devMinorBits = 20
	devMinorMask = (1 << devMinorBits) - 1
)

// sysBlockDir is the sysfs directory whose "<major>:<minor>" entries symlink to
// each block device. It is a variable so tests can point it at a fixture dir.
var sysBlockDir = "/sys/dev/block"

// namedDev is a cached dev_t -> name resolution, keyed on the sysfs symlink
// target it was resolved from, so a cache entry a minor's reuse invalidates
// (the symlink now points elsewhere, or is gone) is never returned stale.
type namedDev struct {
	target string
	name   string
}

// devNameCache memoizes dev_t -> name resolutions, each valid only while its
// sysfs symlink target is unchanged: dm/md minors are reused, so caching by
// dev_t forever would keep naming a new device after its predecessor.
var (
	devNameMu    sync.RWMutex
	devNameCache = map[uint32]namedDev{}
)

// deviceName resolves a Linux dev_t to its block device name, for example
// "nvme0n1", so the system.device attribute is human-readable. It falls back to
// the "<major>:<minor>" form when sysfs is unavailable or the device cannot be
// resolved, so the attribute is always populated.
func deviceName(dev uint32) string {
	majMin := fmtDev(dev)
	target, _ := os.Readlink(filepath.Join(sysBlockDir, majMin))

	devNameMu.RLock()
	cached, ok := devNameCache[dev]
	devNameMu.RUnlock()
	if ok && cached.target == target && target != "" {
		return cached.name
	}

	name := nameFromTarget(majMin, target)

	if target != "" {
		devNameMu.Lock()
		devNameCache[dev] = namedDev{target: target, name: name}
		devNameMu.Unlock()
	}
	return name
}

// nameFromTarget derives a block device's name from the /sys/dev/block
// symlink target already read for it (e.g. "../../devices/virtual/block/dm-4"
// resolves to "dm-4"), falling back to majMin ("<major>:<minor>") when the
// target is empty or has no usable basename. Callers that already hold a
// device's target (block_stack.go's computeDevInfo) use this directly instead
// of calling deviceName, which would re-read the same symlink.
func nameFromTarget(majMin, target string) string {
	if base := filepath.Base(target); base != "" && base != "." && base != string(filepath.Separator) {
		return base
	}
	return majMin
}

// fmtDev formats a Linux dev_t value as "<major>:<minor>".
func fmtDev(dev uint32) string {
	return fmt.Sprintf("%d:%d", dev>>devMinorBits, dev&devMinorMask)
}

// deviceNameForFS resolves a filesystem's superblock dev_t to its
// system.device attribute (step 10): the sysfs basename of dev, like
// deviceName, but "" -- never the "<major>:<minor>" fallback -- when major is
// 0 or sysfs has no entry for it (S5). Major 0 is the kernel's
// UNNAMED_MAJOR, assigned to anonymous superblocks: nfs, cifs, ceph, fuse,
// tmpfs, and a btrfs volume spanning more than one device.
func deviceNameForFS(dev uint32) string {
	if dev>>devMinorBits == 0 {
		return ""
	}
	majMin := fmtDev(dev)
	target, _ := os.Readlink(filepath.Join(sysBlockDir, majMin))
	if target == "" {
		return ""
	}
	return nameFromTarget(majMin, target)
}
