// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"errors"
	"syscall"
)

// blkStatusErrno is empty because block requests are only traced on Linux, whose errnos
// don't all exist on other systems
var blkStatusErrno = map[uint8]syscall.Errno{}

// hostPathDevice is only implemented on Linux, whose pod volumes are resolved
func hostPathDevice(_ string) (major, minor uint32, err error) {
	return 0, 0, errors.New("unsupported")
}
