// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"os"
	"path/filepath"
	"strings"
)

// isBioBased tells whether the sysfs directory of a block device is a device without a request
// queue, which never issues requests of its own. blk-mq devices have an "mq" directory, and the
// request-based devices of older kernels list their I/O schedulers, while bio-based devices have
// none: the kernel shows "none", or, on recent kernels, no scheduler file at all.
func isBioBased(dir string) bool {
	if exists(filepath.Join(dir, "mq")) {
		return false
	}
	scheduler, err := os.ReadFile(filepath.Join(dir, "queue", "scheduler"))
	return err != nil || strings.TrimSpace(string(scheduler)) == "none"
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

// dmMultipathUUIDPrefix starts the device mapper UUID of the multipath devices, which multipathd
// creates as "mpath-<WWID of the LUN>"
const dmMultipathUUIDPrefix = "mpath-"

// isDMMultipath tells whether the sysfs directory of a block device is a dm-multipath device
func isDMMultipath(dir string) bool {
	uuid, err := os.ReadFile(filepath.Join(dir, "dm", "uuid"))
	return err == nil && strings.HasPrefix(string(uuid), dmMultipathUUIDPrefix)
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

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
