// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

// platformErrnoName has no symbolic errno table on non-unix platforms; the
// storage tracers that produce these values only run on Linux, so this path
// only needs to compile.
func platformErrnoName(int64) string { return "" }
