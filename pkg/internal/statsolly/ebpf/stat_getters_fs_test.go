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

func TestFsIoGetters_NilFsIo(t *testing.T) {
	s := &Stat{}

	fsGetter, ok := StatGetters(attr.FsType)
	assert.True(t, ok)
	assert.Equal(t, "unknown", fsGetter(s).Value.Emit())
}
