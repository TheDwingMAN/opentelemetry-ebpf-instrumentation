// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package statagg // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"

import (
	"io/fs"
	"syscall"
)

// dirIno returns the inode of a directory: on cgroup v2, the cgroup's id.
func dirIno(info fs.FileInfo) (uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ino, true
}
