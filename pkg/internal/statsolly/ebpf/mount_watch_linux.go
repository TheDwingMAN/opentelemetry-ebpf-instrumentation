// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// watchMountTable calls onChange each time the mount namespace behind the
// first of paths that can be opened gains or loses a mount. The kernel
// reports that as POLLPRI on the namespace's mountinfo, so the watch costs
// nothing while the table is stable. Returns false when no path opened.
func watchMountTable(onChange func(), paths ...string) bool {
	var f *os.File
	for _, p := range paths {
		if opened, err := os.Open(p); err == nil {
			f = opened
			break
		}
	}
	if f == nil {
		return false
	}

	go func() {
		defer f.Close()
		fds := []unix.PollFd{{Fd: int32(f.Fd()), Events: unix.POLLPRI}}
		for {
			fds[0].Revents = 0
			n, err := unix.Poll(fds, -1)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				return
			}
			if n == 0 {
				continue
			}
			if fds[0].Revents&(unix.POLLNVAL|unix.POLLHUP) != 0 {
				return
			}
			onChange()
		}
	}()
	return true
}
