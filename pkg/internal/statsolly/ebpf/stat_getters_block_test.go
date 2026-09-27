// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestBlockIoGetters(t *testing.T) {
	// Point device-name resolution at an empty dir so it deterministically
	// falls back to the "<major>:<minor>" form regardless of the host's disks.
	withSysBlockDir(t, t.TempDir())

	s := &Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{Dev: 0x800010, Op: uint8(CodeDirectionWrite)}}

	devGetter, ok := StatGetters(attr.DiskDevice)
	assert.True(t, ok)
	assert.Equal(t, "8:16", devGetter(s).Value.Emit())

	opGetter, ok := StatGetters(attr.DiskIODirection)
	assert.True(t, ok)
	assert.Equal(t, "write", opGetter(s).Value.Emit())
}

// TestBlockIoErrorTypeGetter covers the platform-independent paths: no error,
// and a stat that carries no block I/O event. The errno-name-on-error path is
// platform-specific (errnoName only resolves names on unix); see
// stat_getters_block_unix_test.go.
func TestBlockIoErrorTypeGetter(t *testing.T) {
	errGetter, ok := StatGetters(attr.ErrorType)
	assert.True(t, ok)

	noError := &Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{Error: 0}}
	assert.Empty(t, errGetter(noError).Value.Emit())

	notBlockIo := &Stat{Type: StatTypeTCPRtt, TCPRtt: &TCPRtt{}}
	assert.Empty(t, errGetter(notBlockIo).Value.Emit())
}
