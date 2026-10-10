// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/export"
)

func TestDiskLatencyBoundsFitTheKernelHistogram(t *testing.T) {
	assert.Len(t, export.DiskLatencyBounds, diskLatencyBuckets-1, "a kernel bucket per bound, then the overflow bucket")
	assert.Positive(t, export.DiskLatencyBounds[0])
	assert.IsIncreasing(t, export.DiskLatencyBounds)
}
