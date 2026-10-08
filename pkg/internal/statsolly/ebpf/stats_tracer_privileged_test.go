// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Without the kernel's REQ_OP_ZONE_APPEND, the probes would not measure zone appends
func TestKernelBlockTracepointLayoutZoneAppendOp(t *testing.T) {
	layout, err := kernelBlockTracepointLayout(slog.Default())
	require.NoError(t, err)
	assert.NotZero(t, layout.zoneAppendOp, "every supported kernel has REQ_OP_ZONE_APPEND")
}
