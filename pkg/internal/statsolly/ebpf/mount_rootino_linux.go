// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import "golang.org/x/sys/unix"

// statRootInode reads the inode of path from cached attributes only
// (AT_STATX_DONT_SYNC), so a network filesystem is not asked, and without
// triggering an automount.
func statRootInode(path string) (uint64, error) {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_STATX_DONT_SYNC|unix.AT_NO_AUTOMOUNT, unix.STATX_INO, &stx); err != nil {
		return 0, err
	}
	return stx.Ino, nil
}
