// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The uapi errnos keep their platform names; the NFS spike (S0-c) saw these
// on READ, OPEN and LOOKUP.
func TestErrnoNameUapi(t *testing.T) {
	assert.Equal(t, "EACCES", errnoName(-13))
	assert.Equal(t, "ENOENT", errnoName(-2))
	assert.Equal(t, "EIO", errnoName(-5))
}
