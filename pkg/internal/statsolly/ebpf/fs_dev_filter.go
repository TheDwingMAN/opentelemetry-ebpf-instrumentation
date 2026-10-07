// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"log/slog"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/prometheus/procfs"
)

// localFilesystems maps the mountinfo FSType values that back a
// PersistentVolume but are also used for the node's own root filesystem and
// every container's writable layer, which is why fs_dev_filter exists: only
// a device of one of these types actually backing a kubelet volume mount is
// allowed to record events. Their probes attach only while such a device
// exists (fsAttacher).
var localFilesystems = map[string]FsTypeCode{
	"ext4":  CodeFsExt4,
	"xfs":   CodeFsXFS,
	"btrfs": CodeFsBtrfs,
}

// fsDevFilterAllowed is the value written for every allowlisted device; the
// map is used as a set, so its content carries no meaning.
const fsDevFilterAllowed uint8 = 1

// localPVDevs returns the superblock dev_t of every kubelet volume mount
// backed by a local filesystem (ext4, xfs or btrfs), with that filesystem.
func localPVDevs(mounts []*procfs.MountInfo) map[uint32]FsTypeCode {
	devs := map[uint32]FsTypeCode{}
	for _, m := range mounts {
		fs, ok := localFilesystems[m.FSType]
		if !ok {
			continue
		}
		if _, ok := parseKubeletMount(m); !ok {
			continue
		}
		dev, ok := parseDevT(m.MajorMinorVer)
		if !ok {
			continue
		}
		devs[dev] = fs
	}
	return devs
}

// parseDevT parses a "major:minor" string, as reported in
// /proc/self/mountinfo, into the kernel dev_t encoding (major<<20 | minor)
// that bpf/statsolly/fs_io.c reads as a superblock's s_dev.
func parseDevT(majorMinor string) (uint32, bool) {
	majorStr, minorStr, ok := strings.Cut(majorMinor, ":")
	if !ok {
		return 0, false
	}

	major, err := strconv.ParseUint(majorStr, 10, 32)
	if err != nil {
		return 0, false
	}

	minor, err := strconv.ParseUint(minorStr, 10, 32)
	if err != nil {
		return 0, false
	}

	return uint32(major)<<devMinorBits | uint32(minor), true
}

// scanLocalPVs reads the node's mount table and returns the local filesystem
// types backing a kubelet volume mount, after bringing filterMap in line with
// the devices of those mounts.
func scanLocalPVs(log *slog.Logger, filterMap *ebpf.Map) (map[FsTypeCode]bool, error) {
	mounts, err := scanMounts()
	if err != nil {
		return nil, err
	}
	devs := localPVDevs(mounts)
	reconcileFsDevFilter(log, filterMap, devs)

	types := map[FsTypeCode]bool{}
	for _, fs := range devs {
		types[fs] = true
	}
	return types, nil
}

// reconcileFsDevFilter adds the devices of want missing from filterMap, and
// deletes map entries for devices no longer in want. Update failures are
// logged at debug level: a stale allowlist only means a PV-backed mount
// briefly under- or over-reports.
func reconcileFsDevFilter(log *slog.Logger, filterMap *ebpf.Map, want map[uint32]FsTypeCode) {
	have := map[uint32]struct{}{}
	var key uint32
	var value uint8
	iter := filterMap.Iterate()
	for iter.Next(&key, &value) {
		have[key] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		log.Debug("fs_dev_filter refresh: iterating map failed", "error", err)
		return
	}

	for dev := range want {
		if _, ok := have[dev]; ok {
			continue
		}
		if err := filterMap.Update(&dev, fsDevFilterAllowed, ebpf.UpdateAny); err != nil {
			log.Debug("fs_dev_filter refresh: adding device failed", "dev", dev, "error", err)
		}
	}

	for dev := range have {
		if _, ok := want[dev]; ok {
			continue
		}
		if err := filterMap.Delete(&dev); err != nil {
			log.Debug("fs_dev_filter refresh: deleting device failed", "dev", dev, "error", err)
		}
	}
}
