// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// blkStatusErrno maps the blk_status_t values that are stable across kernel versions to the
// errno the kernel reports for them (blk_errors in block/blk-core.c). Higher values were
// renumbered between kernel versions.
var blkStatusErrno = map[uint8]syscall.Errno{
	1:  unix.EOPNOTSUPP,
	2:  unix.ETIMEDOUT,
	3:  unix.ENOSPC,
	4:  unix.ENOLINK,
	5:  unix.EREMOTEIO,
	6:  unix.EBADE,
	7:  unix.ENODATA,
	8:  unix.EILSEQ,
	9:  unix.ENOMEM,
	10: unix.EIO,
	11: unix.EREMCHG,
	12: unix.EAGAIN,
	13: unix.EBUSY,
}

// hostRoot is the root filesystem of the host, when OBI shares its PID namespace
const hostRoot = "/proc/1/root"

// hostPathDevice returns the device of a path of the host, e.g. of a hostPath PersistentVolume,
// which the kubelet doesn't mount
func hostPathDevice(path string) (major, minor uint32, err error) {
	info, err := os.Stat(filepath.Join(hostRoot, path))
	if err != nil {
		return 0, 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("no device for %s", path)
	}
	return unix.Major(st.Dev), unix.Minor(st.Dev), nil
}
