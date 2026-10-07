// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// maxPhysicalDevices caps the number of physical devices a stacked device's
// walk returns, matching the maximum the obi.disk.physical_device attribute
// (built from this cache, step 10) joins into one comma-separated value.
const maxPhysicalDevices = 8

// hostStat is unix.Stat, indirected (like procRoot, mountInfoPath and
// sysBlockDir elsewhere in this package) so tests can synthesize a host
// path's dev_t instead of depending on the real containing filesystem's
// major, which containerized test environments cannot control.
var hostStat = unix.Stat

// devInfo is a block device's place in the stacking model: whether it issues
// requests to hardware itself, and, when it does not, the physical devices
// backing it.
type devInfo struct {
	name        string
	stacked     bool
	isPartition bool
	parent      string
	// physical is nil when the device could not be resolved at all, and the
	// device's own name when it is itself physical (stacked == false); it is
	// never empty for a device this cache could resolve.
	physical []string
}

// cachedDevInfo pairs a devInfo with the sysfs symlink target it was
// computed from, so a change to that target (dm/md minors are reused) or its
// disappearance evicts the entry instead of returning a stale device model.
type cachedDevInfo struct {
	target string
	info   devInfo
}

var (
	devInfoMu    sync.RWMutex
	devInfoCache = map[uint32]cachedDevInfo{}
)

// blockStack returns dev's device model: obi.disk.stacked and, when it is
// stacked, the physical devices behind it (obi.disk.physical_device, step
// 10). Results are cached per the sysfs symlink they were resolved from.
func blockStack(dev uint32) devInfo {
	return blockStackVisiting(dev, map[uint32]bool{})
}

// blockStackVisiting is blockStack with a set of dev_t values already being
// resolved in the current call, so a cyclical slaves/multipath chain (never
// expected from the kernel, but not worth trusting) cannot recurse forever.
func blockStackVisiting(dev uint32, visiting map[uint32]bool) devInfo {
	target, _ := os.Readlink(filepath.Join(sysBlockDir, fmtDev(dev)))

	devInfoMu.RLock()
	cached, ok := devInfoCache[dev]
	devInfoMu.RUnlock()
	if ok && cached.target == target && target != "" {
		return cached.info
	}

	if visiting[dev] {
		return devInfo{name: deviceName(dev)}
	}
	visiting[dev] = true

	info := computeDevInfo(dev, target, visiting)
	if target != "" {
		devInfoMu.Lock()
		devInfoCache[dev] = cachedDevInfo{target: target, info: info}
		devInfoMu.Unlock()
	}
	return info
}

// computeDevInfo builds dev's device model from the sysfs directory its
// /sys/dev/block symlink (already read as target) points to.
func computeDevInfo(dev uint32, target string, visiting map[uint32]bool) devInfo {
	name := nameFromTarget(fmtDev(dev), target)
	if target == "" {
		return devInfo{name: name}
	}
	// target is the device's own directory (e.g. "../../devices/virtual/block/dm-4"),
	// not a file inside it: /sys/dev/block/<maj:min> symlinks straight to it.
	dir := filepath.Clean(filepath.Join(sysBlockDir, target))

	info := devInfo{name: name}
	info.isPartition = fileExists(filepath.Join(dir, "partition"))

	if info.isPartition {
		parentDir := filepath.Dir(dir)
		info.parent = filepath.Base(parentDir)
		if parentDev, ok := readDevFile(parentDir); ok {
			parent := blockStackVisiting(parentDev, visiting)
			info.stacked = parent.stacked
			info.physical = parent.physical
		}
		return info
	}

	switch {
	case isDir(filepath.Join(dir, "dm")):
		info.stacked = true
		info.physical = capPhysical(physicalFromLinks(filepath.Join(dir, "slaves"), visiting))
	case isDir(filepath.Join(dir, "md")):
		info.stacked = true
		info.physical = capPhysical(physicalFromLinks(filepath.Join(dir, "slaves"), visiting))
	case isDir(filepath.Join(dir, "multipath")):
		info.stacked = true
		info.physical = capPhysical(physicalFromLinks(filepath.Join(dir, "multipath"), visiting))
	case isDir(filepath.Join(dir, "loop")):
		info.stacked = true
		info.physical = capPhysical(physicalFromLoop(dir, visiting))
	case nonEmptyDir(filepath.Join(dir, "slaves")):
		// bcache and other stacking drivers that are neither dm, md nor loop
		// still report their backing devices through slaves/ (v2 isStacked).
		info.stacked = true
		info.physical = capPhysical(physicalFromLinks(filepath.Join(dir, "slaves"), visiting))
	default:
		info.stacked = false
		info.physical = []string{name}
	}
	return info
}

// physicalFromLinks recurses into every entry of a sysfs directory of device
// symlinks (dm/md's slaves/, or an NVMe head's multipath/), reading each
// entry's own "dev" file to find its dev_t.
func physicalFromLinks(linksDir string, visiting map[uint32]bool) []string {
	entries, err := os.ReadDir(linksDir)
	if err != nil {
		return nil
	}

	var out []string
	for _, e := range entries {
		dev, ok := readDevFile(filepath.Join(linksDir, e.Name()))
		if !ok {
			continue
		}
		out = append(out, blockStackVisiting(dev, visiting).physical...)
	}
	return out
}

// physicalFromLoop follows a loop device's backing file to the device it
// lives on. The backing file path is a host path (loop devices are set up on
// the host, not per-container), read through /proc/1/root, matching how the
// rest of this package reaches host state (mount_resolver.go).
func physicalFromLoop(dir string, visiting map[uint32]bool) []string {
	content, err := os.ReadFile(filepath.Join(dir, "loop", "backing_file"))
	if err != nil {
		return nil
	}
	backing := strings.TrimSpace(string(content))
	if backing == "" {
		return nil
	}

	dev, ok := statHostPathDevT(backing)
	if !ok {
		return nil
	}
	return blockStackVisiting(dev, visiting).physical
}

// statHostPathDevT stats an absolute host path -- a loop device's backing
// file, or a mount's source (step 10's btrfs fallback, FSJoinDevice) --
// through /proc/1/root, matching how the rest of this package reaches host
// state (mount_resolver.go), and returns its dev_t. A path that is not
// absolute, or that does not exist there, is not an error worth logging: a
// network filesystem's source ("host:/export", a ceph monitor list) is never
// a host path, and simply fails to resolve.
//
// A block special file (the mount source case: "/dev/mapper/vg-lv") names
// its device through st_rdev, not st_dev -- st_dev is the device backing the
// node itself (devtmpfs on every real host, major 0), which is never the
// device the caller means. A regular file (the loop backing-file case) has
// no st_rdev; st_dev there correctly names the host filesystem it lives on.
func statHostPathDevT(path string) (uint32, bool) {
	if !filepath.IsAbs(path) {
		return 0, false
	}
	var st unix.Stat_t
	if err := hostStat(filepath.Join(procRoot, "1", "root", path), &st); err != nil {
		return 0, false
	}
	dev := st.Dev
	if st.Mode&unix.S_IFMT == unix.S_IFBLK {
		dev = st.Rdev
	}
	return unix.Major(dev)<<devMinorBits | unix.Minor(dev), true
}

// FSJoinDevice resolves the block-backed fs join labels of step 10
// (system.device, obi.disk.physical_device) for a filesystem stat's
// superblock dev_t. Most filesystems' sb->s_dev resolves directly through
// sysfs (deviceNameForFS); an anonymous superblock -- major 0, which is also
// how a btrfs volume spanning more than one device reports -- falls back to
// statting the mount's source path, so a btrfs filesystem mounted from a
// real block device (e.g. /dev/mapper/vg-lv) still resolves. A network
// filesystem's source ("host:/export", a ceph monitor list) is not a path,
// so the stat simply fails and both labels come back "".
func FSJoinDevice(dev uint32, source string) (systemDevice, physicalDevice string) {
	name := deviceNameForFS(dev)
	if name == "" {
		if d, ok := statHostPathDevT(source); ok {
			dev, name = d, deviceNameForFS(d)
		}
	}
	if name == "" {
		return "", ""
	}
	if physical := blockStack(dev).physical; len(physical) > 0 {
		physicalDevice = strings.Join(physical, ",")
	}
	return name, physicalDevice
}

// capPhysical sorts, dedups and truncates a physical-device list to
// maxPhysicalDevices, matching the obi.disk.physical_device attribute's
// contract (step 10). Returns nil, not an empty slice, when the walk found
// nothing, so the field means "unresolved" rather than "resolved to none".
func capPhysical(names []string) []string {
	if len(names) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(names))
	uniq := make([]string, 0, len(names))
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		uniq = append(uniq, n)
	}
	sort.Strings(uniq)

	if len(uniq) > maxPhysicalDevices {
		uniq = uniq[:maxPhysicalDevices]
	}
	return uniq
}

// readDevFile reads a sysfs device directory's "dev" file ("<major>:<minor>")
// and parses it into the kernel dev_t encoding. dir may itself be a symlink
// (dm's slaves/<name>, an NVMe head's multipath/<name>): ReadFile follows it.
func readDevFile(dir string) (uint32, bool) {
	content, err := os.ReadFile(filepath.Join(dir, "dev"))
	if err != nil {
		return 0, false
	}
	return parseDevT(strings.TrimSpace(string(content)))
}

// nonEmptyDir tells whether path is a directory sysfs populated with at
// least one entry, matching v2's isStacked slaves/ check.
func nonEmptyDir(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
