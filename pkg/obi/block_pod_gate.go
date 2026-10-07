// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi // import "go.opentelemetry.io/obi/pkg/obi"

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/export"
)

// blockPodCgroupRoots are where the host's cgroup v2 hierarchy can be read:
// OBI's own /sys, or, when that is a container's cgroup namespace, PID 1's
// root, as the cgroup index that resolves the pods reads it.
var blockPodCgroupRoots = []string{"/sys/fs/cgroup", "/proc/1/root/sys/fs/cgroup"}

// blockPodUnsupported returns why storage_block_pod cannot attribute block
// I/O to pods on this host, or "" when it can: block I/O is charged to the
// cgroup of its blkcg, whose id equals the pod cgroups' only on the cgroup
// v2 hierarchy with the io controller enabled (S0-d). Under cgroup v1 the
// blkcg ids are those of the blkio hierarchy and cgroup writeback is
// inactive; without io in the root's subtree_control every request is
// charged to the root cgroup.
func blockPodUnsupported(roots []string) string {
	v2 := false
	for _, root := range roots {
		if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
			continue
		}
		v2 = true
		controllers, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
		if err == nil && slices.Contains(strings.Fields(string(controllers)), "io") {
			return ""
		}
	}
	if !v2 {
		return "the host does not use the cgroup v2 hierarchy (cgroup v1 charges block I/O to blkio cgroups" +
			" that no pod cgroup id matches)"
	}
	return "the io controller is not enabled in the root cgroup's cgroup.subtree_control, so all block I/O" +
		" is charged to the root cgroup"
}

// disableBlockPodIfUnsupported turns storage_block_pod off, with one warning,
// on a host where unsupported (blockPodUnsupported) gives a reason: its
// metrics would carry no pod.
func (c *Config) disableBlockPodIfUnsupported(unsupported func() string) {
	if unsupported == nil || !c.Metrics.Features.StorageBlockPod() {
		return
	}
	reason := unsupported()
	if reason == "" {
		return
	}
	slog.Warn("storage_block_pod is disabled: "+reason+". obi.stat.disk.operations and"+
		" obi.stat.disk.operation_time are not exported, and obi.stat.disk.io has no pod attributes",
		"feature", "storage_block_pod")
	c.Metrics.Features &^= export.FeatureStorageBlockPod
}
