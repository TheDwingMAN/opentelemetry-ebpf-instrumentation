// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"fmt"
	"path/filepath"
	"sync"
)

const (
	sysDevBlock = "/sys/dev/block"
	// include/linux/kdev_t.h: MINORBITS
	minorBits = 20
	minorMask = (1 << minorBits) - 1
)

var blockDeviceNames sync.Map

// blockDeviceName resolves a kernel dev_t to the disk name (for example nvme0n1)
// through /sys/dev/block, falling back to major:minor. Device numbers are stable
// for the lifetime of a device, so results are cached without expiry.
func blockDeviceName(dev uint32) string {
	if name, ok := blockDeviceNames.Load(dev); ok {
		return name.(string)
	}
	name := fmt.Sprintf("%d:%d", dev>>minorBits, dev&minorMask)
	if target, err := filepath.EvalSymlinks(filepath.Join(sysDevBlock, name)); err == nil {
		name = filepath.Base(target)
	}
	blockDeviceNames.Store(dev, name)
	return name
}
