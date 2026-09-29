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

// TestFsIoErrorTypeGetterErrnoName covers the errno-name path of the
// error.type getter, which only resolves symbolic names on unix (see
// errno_unix.go / errno_other.go).
func TestFsIoErrorTypeGetterErrnoName(t *testing.T) {
	errGetter, ok := StatGetters(attr.ErrorType)
	assert.True(t, ok)

	staleHandle := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Error: -int32(unix.ESTALE)}}
	assert.Equal(t, "ESTALE", errGetter(staleHandle).Value.Emit())
}
