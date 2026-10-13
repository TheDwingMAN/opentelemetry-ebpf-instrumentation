// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// dmMultipathUUIDPrefix starts the device mapper UUIDs that multipathd gives its devices:
// "mpath-<WWID of the LUN>"
const dmMultipathUUIDPrefix = "mpath-"

// isStacked tells whether the sysfs directory of a block device is that of a device built on other
// block devices that also report its I/O: a device mapper, md RAID or loop device, or any device
// that sysfs lists slaves of. A measured dm-multipath device is not, as OBI leaves out its paths.
func isStacked(dir string) bool {
	if isMeasuredDMMultipath(dir) {
		return false
	}
	for _, kind := range []string{"dm", "md", "loop"} {
		if exists(filepath.Join(dir, kind)) {
			return true
		}
	}
	slaves, err := os.ReadDir(filepath.Join(dir, "slaves"))
	return err == nil && len(slaves) > 0
}

// deviceMapperName returns the name of a device mapper device, as /dev/mapper lists it, from its
// sysfs directory, or an empty string for other devices
func deviceMapperName(dir string) string {
	name, err := os.ReadFile(filepath.Join(dir, "dm", "name"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(name))
}

// heldByDMMultipath tells whether the sysfs directory of a block device is that of a path of a
// measured dm-multipath device
func heldByDMMultipath(dir string) bool {
	holders, _ := filepath.Glob(filepath.Join(dir, "holders", "*"))
	return slices.ContainsFunc(holders, isMeasuredDMMultipath)
}

// isMeasuredDMMultipath tells whether the sysfs directory of a block device is that of a
// request-based dm-multipath device, which reports the requests of its paths. A bio-based one
// (queue_mode bio) issues no requests of its own: OBI doesn't measure it, so its paths report its I/O.
func isMeasuredDMMultipath(dir string) bool {
	uuid, err := os.ReadFile(filepath.Join(dir, "dm", "uuid"))
	return err == nil && strings.HasPrefix(string(uuid), dmMultipathUUIDPrefix) && isRequestBased(dir)
}

// isRequestBased tells whether the sysfs directory of a block device is that of a device that issues
// requests: blk-mq devices have an "mq" directory, and the request-based devices of older kernels
// list their I/O schedulers, while bio-based devices show "none", or no scheduler file on recent
// kernels
func isRequestBased(dir string) bool {
	if exists(filepath.Join(dir, "mq")) {
		return true
	}
	scheduler, err := os.ReadFile(filepath.Join(dir, "queue", "scheduler"))
	return err == nil && strings.TrimSpace(string(scheduler)) != "none"
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
