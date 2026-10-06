// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"os"
	"path/filepath"
	"sync"
)

// sysBlockDir is the sysfs directory whose "<major>:<minor>" entries symlink to
// each block device. It is a variable so tests can point it at a fixture dir.
var sysBlockDir = "/sys/dev/block"

// devNameCache memoizes successful dev_t -> name resolutions. Device numbers are
// stable for a device's lifetime, so caching is safe; only successful lookups
// are cached, so a transient sysfs miss is retried on the next emit.
var (
	devNameMu    sync.RWMutex
	devNameCache = map[uint32]string{}
)

// deviceName resolves a Linux dev_t to its block device name (for example
// "nvme0n1" or "sda1") by reading the /sys/dev/block/<major>:<minor> symlink,
// so the system.device attribute is human-readable rather than a raw
// "<major>:<minor>" number. It falls back to the "<major>:<minor>" form when
// sysfs is unavailable or the device cannot be resolved, so the attribute is
// always populated.
func deviceName(dev uint32) string {
	devNameMu.RLock()
	name, ok := devNameCache[dev]
	devNameMu.RUnlock()
	if ok {
		return name
	}

	majMin := fmtDev(dev)
	name = majMin
	if target, err := os.Readlink(filepath.Join(sysBlockDir, majMin)); err == nil {
		if base := filepath.Base(target); base != "" && base != "." && base != string(filepath.Separator) {
			name = base
		}
	}

	if name != majMin {
		devNameMu.Lock()
		devNameCache[dev] = name
		devNameMu.Unlock()
	}
	return name
}
