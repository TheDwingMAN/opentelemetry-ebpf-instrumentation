// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

// FsAggregation is how the filesystem programs report completed operations.
// The zero value sends one ring buffer event per operation.
type FsAggregation struct {
	// Enabled adds operations into a kernel map instead, which userspace
	// reads (statagg).
	Enabled bool
	// Exponential selects the exponential histogram layout: 128 bounds
	// rather than 32.
	Exponential bool
	// BoundsNs are the histogram bounds in nanoseconds, ascending; the
	// kernel pads them with math.MaxUint64.
	BoundsNs []uint64
}
