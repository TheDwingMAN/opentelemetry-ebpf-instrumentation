// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import "syscall"

// blkStatusErrno is empty because block requests are only traced on Linux, whose errnos
// don't all exist on other systems
var blkStatusErrno = map[uint8]syscall.Errno{}
