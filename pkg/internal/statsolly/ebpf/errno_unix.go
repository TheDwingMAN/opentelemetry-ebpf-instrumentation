// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// errnoName returns the symbolic name for a positive errno (e.g. "ENOSPC"),
// falling back to its decimal value for an errno the platform has no name for.
func errnoName(errno int32) string {
	if name := unix.ErrnoName(syscall.Errno(errno)); name != "" {
		return name
	}
	return strconv.Itoa(int(errno))
}
