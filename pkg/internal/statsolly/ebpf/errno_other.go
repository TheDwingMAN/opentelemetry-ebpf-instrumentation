// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import "strconv"

// errnoName has no symbolic errno table on non-unix platforms; the block I/O
// tracer that produces these values only runs on Linux, so this path only
// needs to compile.
func errnoName(errno int32) string {
	return strconv.Itoa(int(errno))
}
