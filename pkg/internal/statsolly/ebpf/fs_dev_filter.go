// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/procfs"
)

// fsDevFilterRefresh is how often the fs_dev_filter allowlist is reconciled
// with the node's current kubelet volume mounts.
const fsDevFilterRefresh = 30 * time.Second

// localFilesystems are the mountinfo FSType values that back a
// PersistentVolume but are also used for the node's own root filesystem and
// every container's writable layer, which is why fs_dev_filter exists: only
// a device in this set, and actually backing a kubelet volume mount, is
// allowed to record events.
var localFilesystems = map[string]struct{}{
	"ext4":  {},
	"xfs":   {},
	"btrfs": {},
}

// fsDevFilterAllowed is the value written for every allowlisted device; the
// map is used as a set, so its content carries no meaning.
const fsDevFilterAllowed uint8 = 1

// localPVDevs returns the superblock dev_t of every kubelet volume mount
// backed by a local filesystem (ext4, xfs or btrfs). It is the pure core of
// the fs_dev_filter reconciliation loop, split out for testing.
func localPVDevs(mounts []*procfs.MountInfo) map[uint32]struct{} {
	devs := map[uint32]struct{}{}
	for _, m := range mounts {
		if _, ok := localFilesystems[m.FSType]; !ok {
			continue
		}
		if _, ok := parseKubeletMount(m.MountPoint, m.Source); !ok {
			continue
		}
		dev, ok := parseDevT(m.MajorMinorVer)
		if !ok {
			continue
		}
		devs[dev] = struct{}{}
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

// fsDevFilterRefresher periodically reconciles the fs_dev_filter allowlist
// map with the node's current PV-backed local-filesystem mounts, until
// Close is called.
type fsDevFilterRefresher struct {
	stop chan struct{}
	done chan struct{}
}

// startFsDevFilterRefresher reconciles filterMap immediately, then every
// fsDevFilterRefresh, until the returned io.Closer is closed. Map update
// failures are logged at debug level; the refresher never fails startup,
// since a stale allowlist only means a PV-backed mount briefly under- or
// over-reports, not a crash.
func startFsDevFilterRefresher(log *slog.Logger, filterMap *ebpf.Map) io.Closer {
	r := &fsDevFilterRefresher{stop: make(chan struct{}), done: make(chan struct{})}
	go r.run(log, filterMap)
	return r
}

func (r *fsDevFilterRefresher) run(log *slog.Logger, filterMap *ebpf.Map) {
	defer close(r.done)

	reconcileFsDevFilter(log, filterMap)

	ticker := time.NewTicker(fsDevFilterRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			reconcileFsDevFilter(log, filterMap)
		}
	}
}

func (r *fsDevFilterRefresher) Close() error {
	close(r.stop)
	<-r.done
	return nil
}

// reconcileFsDevFilter adds devices backing a local-filesystem PV mount that
// are missing from filterMap, and deletes map entries for devices no longer
// backing one.
func reconcileFsDevFilter(log *slog.Logger, filterMap *ebpf.Map) {
	mounts, err := scanMounts()
	if err != nil {
		log.Debug("fs_dev_filter refresh: scanning mounts failed", "error", err)
		return
	}
	want := localPVDevs(mounts)

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
