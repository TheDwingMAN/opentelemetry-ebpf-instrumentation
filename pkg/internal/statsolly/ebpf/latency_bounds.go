// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"math"
	"slices"
	"time"
)

// maxDiskLatencyBounds is the number of histogram boundaries the kernel can bucket latencies with:
// one less than the number of buckets, the last one being the overflow bucket.
const maxDiskLatencyBounds = len(StatsDiskIoAccumT{}.LatencyCount) - 1

// KernelLatencyBounds returns the boundaries, in seconds, that the kernel buckets latencies with,
// from the boundaries of the histograms of the exporters: sorted, positive (no latency is
// negative), distinct at the nanosecond the kernel measures with, and no more than the kernel
// keeps. With more, it keeps that many, spread across them, and exact is false: the exporters'
// histograms then place some requests in a neighboring bucket.
func KernelLatencyBounds(bounds []float64) (kernelBounds []float64, exact bool) {
	for _, bound := range bounds {
		if ns := math.Round(bound * float64(time.Second)); ns > 0 {
			kernelBounds = append(kernelBounds, ns/float64(time.Second))
		}
	}
	slices.Sort(kernelBounds)
	kernelBounds = slices.Compact(kernelBounds)
	if len(kernelBounds) <= maxDiskLatencyBounds {
		return kernelBounds, true
	}

	spread := make([]float64, maxDiskLatencyBounds)
	last := len(kernelBounds) - 1
	for i := range spread {
		spread[i] = kernelBounds[i*last/(maxDiskLatencyBounds-1)]
	}
	return spread, false
}
