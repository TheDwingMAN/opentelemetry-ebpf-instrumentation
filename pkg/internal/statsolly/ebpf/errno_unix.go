// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// platformErrnoName returns the symbolic name of a positive errno (e.g.
// "ENOSPC"), or "" when the platform has none for it.
func platformErrnoName(errno int64) string {
	return unix.ErrnoName(syscall.Errno(errno))
}
