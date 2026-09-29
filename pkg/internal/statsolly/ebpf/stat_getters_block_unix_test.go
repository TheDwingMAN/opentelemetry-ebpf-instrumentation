// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// TestBlockIoErrorTypeGetterErrnoName covers the errno-name path of the
// error.type getter, which only resolves symbolic names on unix (see
// errno_unix.go / errno_other.go).
func TestBlockIoErrorTypeGetterErrnoName(t *testing.T) {
	errGetter, ok := StatGetters(attr.ErrorType)
	assert.True(t, ok)

	noSpace := &Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{Error: -int32(unix.ENOSPC)}}
	assert.Equal(t, "ENOSPC", errGetter(noSpace).Value.Emit())
}
