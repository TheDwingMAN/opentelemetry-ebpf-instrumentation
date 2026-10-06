// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKernelLatencyBounds(t *testing.T) {
	bounds, exact := KernelLatencyBounds([]float64{0.002, 0, -1, 0.001, 0.001, 1e-10, 2e-10, 0.0005})
	assert.True(t, exact)
	assert.Equal(t, []float64{0.0005, 0.001, 0.002}, bounds,
		"sorted, without the bounds no latency is under, and without duplicates")

	bounds, exact = KernelLatencyBounds([]float64{1.0000000001, 1.0000000002})
	assert.True(t, exact)
	assert.Equal(t, []float64{1}, bounds, "bounds closer than the nanosecond the kernel measures with are one")

	bounds, exact = KernelLatencyBounds(nil)
	assert.True(t, exact)
	assert.Empty(t, bounds)

	many := make([]float64, 2*maxDiskLatencyBounds)
	for i := range many {
		many[i] = float64(i+1) / 1000
	}
	bounds, exact = KernelLatencyBounds(many)
	assert.False(t, exact)
	assert.Len(t, bounds, maxDiskLatencyBounds)
	assert.IsIncreasing(t, bounds)
	assert.InDelta(t, many[0], bounds[0], 1e-12, "the spread keeps the lowest bound")
	assert.InDelta(t, many[len(many)-1], bounds[len(bounds)-1], 1e-12, "and the highest")
}
