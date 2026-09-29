// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// watchMountTable calls onChange with the first of paths that can be opened,
// and that file, once when the watch starts and then each time the mount
// namespace behind it gains or loses a mount. The kernel reports that as
// POLLPRI on the namespace's mountinfo, so the watch costs nothing while the
// table is stable. The first call comes after the file is open, so a table
// read in it misses no change. onChange reads the table from the file it is
// given, never again by path: the open file keeps the namespace and root it
// was opened in after the process whose mountinfo it is exits. Calls are
// never concurrent. Returns false when no path opened.
func watchMountTable(onChange func(key string, table io.ReadSeeker), paths ...string) bool {
	var f *os.File
	var path string
	for _, p := range paths {
		if opened, err := os.Open(p); err == nil {
			f, path = opened, p
			break
		}
	}
	if f == nil {
		return false
	}
	onChange(path, f)

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
			onChange(path, f)
		}
	}()
	return true
}
