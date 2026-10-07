// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBlockDeviceName_unknownDeviceFallsBackToMajorMinor(t *testing.T) {
	// major 4095 is outside any registered block major, so /sys/dev/block has no entry
	const dev = uint32(4095<<minorBits | 7)
	assert.Equal(t, "4095:7", blockDeviceName(dev))
}
