// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnionBounds(t *testing.T) {
	assert.Equal(t, []float64{0.001, 0.01, 0.05, 0.1, 1},
		UnionBounds([]float64{0.001, 0.1, 1}, []float64{0.01, 0.1, 0.05}))
	assert.Empty(t, UnionBounds())
	assert.Equal(t, []float64{1}, UnionBounds(nil, []float64{1, 1}))
}

func TestBase2ExponentialBounds(t *testing.T) {
	first, bounds := Base2ExponentialBounds(0, 3, 17)
	assert.Equal(t, int32(1), first)
	assert.Equal(t, []float64{2, 4, 8, 16, 32}, bounds)

	first, bounds = Base2ExponentialBounds(1, 1, 2)
	assert.Equal(t, int32(0), first)
	assert.InDeltaSlice(t, []float64{1, math.Sqrt2, 2}, bounds, 1e-15)

	// Negative scales merge octaves: base 4.
	first, bounds = Base2ExponentialBounds(-1, 1, 16)
	assert.Equal(t, int32(0), first)
	assert.Equal(t, []float64{1, 4, 16}, bounds)
}
