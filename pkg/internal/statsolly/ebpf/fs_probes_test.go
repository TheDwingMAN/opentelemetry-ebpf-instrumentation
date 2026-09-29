// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModuleBTFExists(t *testing.T) {
	dir := t.TempDir()
	old := sysKernelBTFDir
	sysKernelBTFDir = dir
	t.Cleanup(func() { sysKernelBTFDir = old })

	assert.False(t, moduleBTFExists("nfs"))
	assert.NoError(t, os.WriteFile(filepath.Join(dir, "nfs"), []byte("x"), 0o644))
	assert.True(t, moduleBTFExists("nfs"))
}

func TestResolveFsSymbol(t *testing.T) {
	dir := t.TempDir()
	old := tracefsAvailableFuncs
	tracefsAvailableFuncs = filepath.Join(dir, "available_filter_functions")
	t.Cleanup(func() { tracefsAvailableFuncs = old })
	assert.NoError(t, os.WriteFile(tracefsAvailableFuncs,
		[]byte("cifs_strict_readv [cifs]\nnfs_file_read [nfs]\n"), 0o644))

	// First candidate missing, second present.
	sym, ok := resolveFsSymbol([]string{"cifs_loose_read_iter", "cifs_strict_readv"})
	assert.True(t, ok)
	assert.Equal(t, "cifs_strict_readv", sym)

	_, ok = resolveFsSymbol([]string{"does_not_exist"})
	assert.False(t, ok)
}

func TestFsTargetsCoverAllFilesystems(t *testing.T) {
	seen := map[FsTypeCode]bool{}
	for _, tgt := range fsTargets {
		seen[tgt.Fs] = true
		assert.NotEmpty(t, tgt.ReadSyms, "fs %d has no read symbols", tgt.Fs)
		assert.NotEmpty(t, tgt.WriteSyms, "fs %d has no write symbols", tgt.Fs)
		assert.NotEmpty(t, tgt.Module)
	}
	for _, want := range []FsTypeCode{CodeFsNFS, CodeFsCeph, CodeFsCIFS, CodeFsFUSE} {
		assert.True(t, seen[want], "missing target for fs code %d", want)
	}
}
