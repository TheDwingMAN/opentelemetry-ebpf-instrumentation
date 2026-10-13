// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"os"
	"path/filepath"
	"strings"
)

// isStacked tells whether the sysfs directory of a block device is that of a device built on other
// block devices, which also report its I/O: a device mapper, md RAID or loop device, or any device
// that sysfs lists slaves of
func isStacked(dir string) bool {
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

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
