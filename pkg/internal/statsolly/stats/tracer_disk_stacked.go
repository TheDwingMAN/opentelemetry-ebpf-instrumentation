// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// dmMultipathUUIDPrefix starts the device mapper UUIDs that multipathd gives its devices:
// "mpath-<WWID of the LUN>"
const dmMultipathUUIDPrefix = "mpath-"

// isStacked tells whether the sysfs directory of a block device is that of a device built on other
// block devices that also report its I/O: a device mapper, md RAID or loop device, or any device
// that sysfs lists slaves of, as DRBD links its backing device. A measured dm-multipath device is
// not, as OBI leaves out its paths.
func isStacked(dir string, bioMeasured bool) bool {
	if isMeasuredDMMultipath(dir, bioMeasured) {
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
func heldByDMMultipath(dir string, bioMeasured bool) bool {
	holders, _ := filepath.Glob(filepath.Join(dir, "holders", "*"))
	return slices.ContainsFunc(holders, func(holder string) bool { return isMeasuredDMMultipath(holder, bioMeasured) })
}

// isMeasuredDMMultipath tells whether the sysfs directory of a block device is that of a dm-multipath
// device that OBI measures, which reports the I/O of its paths: a request-based one always, and a
// bio-based one (queue_mode bio), which issues no requests of its own, when the bio-based devices
// are measured. Otherwise its paths report its I/O.
func isMeasuredDMMultipath(dir string, bioMeasured bool) bool {
	uuid, err := os.ReadFile(filepath.Join(dir, "dm", "uuid"))
	return err == nil && strings.HasPrefix(string(uuid), dmMultipathUUIDPrefix) && (bioMeasured || isRequestBased(dir))
}

// nvmePathName matches the names of the hidden path devices of NVMe native multipath,
// nvme<subsystem>c<controller>n<namespace>, and captures the name of their head without the
// controller, nvme<subsystem>n<namespace>
var nvmePathName = regexp.MustCompile(`^(nvme[0-9]+)c[0-9]+(n[0-9]+)$`)

// nvmePathHead returns the head of a hidden path device of NVMe native multipath, or an empty string
// for another device
func nvmePathHead(name string) string {
	head := nvmePathName.FindStringSubmatch(name)
	if head == nil {
		return ""
	}
	return head[1] + head[2]
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
