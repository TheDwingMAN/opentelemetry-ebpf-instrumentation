// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestFsIoGetters(t *testing.T) {
	s := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Fs: uint8(CodeFsNFS), Op: uint8(CodeFsOpWrite)}}

	fsGetter, ok := StatGetters(attr.FsType)
	assert.True(t, ok)
	assert.Equal(t, "nfs", fsGetter(s).Value.Emit())

	opGetter, ok := StatGetters(attr.FsOperation)
	assert.True(t, ok)
	assert.Equal(t, "write", opGetter(s).Value.Emit())
}

func TestFsIoGetters_Fsync(t *testing.T) {
	s := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Fs: uint8(CodeFsNFS), Op: uint8(CodeFsOpFsync)}}

	opGetter, ok := StatGetters(attr.FsOperation)
	assert.True(t, ok)
	assert.Equal(t, "fsync", opGetter(s).Value.Emit())
}

func TestFsIoGetters_NilFsIo(t *testing.T) {
	s := &Stat{}

	fsGetter, ok := StatGetters(attr.FsType)
	assert.True(t, ok)
	assert.Equal(t, "unknown", fsGetter(s).Value.Emit())
}

// TestFsIoErrorTypeGetter covers the platform-independent paths: no error,
// and a stat that carries no filesystem I/O event. The errno-name-on-error
// path is platform-specific (errnoName only resolves names on unix); see
// stat_getters_fs_unix_test.go.
func TestFsIoErrorTypeGetter(t *testing.T) {
	errGetter, ok := StatGetters(attr.ErrorType)
	assert.True(t, ok)

	noError := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Error: 0}}
	assert.Empty(t, errGetter(noError).Value.Emit())

	notFsIo := &Stat{Type: StatTypeTCPRtt, TCPRtt: &TCPRtt{}}
	assert.Empty(t, errGetter(notFsIo).Value.Emit())
}

// fsync(2) and fdatasync(2) reach the filesystem through the same operation
// and are told apart only by the kernel's datasync argument, which the entry
// probe turns into a distinct operation code. Reporting both as "fsync" would
// hide that a database is flushing data only.
func TestFsOpStrSeparatesFdatasync(t *testing.T) {
	getter, ok := StatGetters(attr.FsOperation)
	assert.True(t, ok)

	for _, tc := range []struct {
		op   FsOpCode
		want string
	}{
		{CodeFsOpRead, "read"},
		{CodeFsOpWrite, "write"},
		{CodeFsOpFsync, "fsync"},
		{CodeFsOpFdatasync, "fdatasync"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			s := &Stat{Type: StatTypeFsIo, FsIo: &FsIo{Fs: uint8(CodeFsNFS), Op: uint8(tc.op)}}
			assert.Equal(t, tc.want, getter(s).Value.AsString())
		})
	}
}
