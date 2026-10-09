// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

// diskLatencyBuckets is the number of buckets of the kernel histograms of the block request
// durations: one per bound of export.DiskLatencyBounds, then the overflow bucket
const diskLatencyBuckets = len(StatsDiskIoAccumT{}.LatencyCount)
