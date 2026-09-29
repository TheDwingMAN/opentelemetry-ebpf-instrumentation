// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModuleBTFExists(t *testing.T) {
	dir := t.TempDir()
	old := sysKernelBTFDir
	sysKernelBTFDir = dir
	t.Cleanup(func() { sysKernelBTFDir = old })

	assert.False(t, moduleBTFExists("nfs"))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nfs"), []byte("x"), 0o644))
	assert.True(t, moduleBTFExists("nfs"))
}

func TestResolveFsSymbol(t *testing.T) {
	dir := t.TempDir()
	old := tracefsAvailableFuncs
	tracefsAvailableFuncs = filepath.Join(dir, "available_filter_functions")
	t.Cleanup(func() { tracefsAvailableFuncs = old })
	require.NoError(t, os.WriteFile(tracefsAvailableFuncs,
		[]byte("cifs_strict_readv [cifs]\nnfs_file_read [nfs]\n"), 0o644))

	// First candidate missing, second present.
	sym, ok := resolveFsSymbol([]string{"cifs_loose_read_iter", "cifs_strict_readv"})
	assert.True(t, ok)
	assert.Equal(t, "cifs_strict_readv", sym)

	_, ok = resolveFsSymbol([]string{"does_not_exist"})
	assert.False(t, ok)
}

// Without tracefs (it is root-only), kallsyms answers, by its third column.
func TestResolveFsSymbolFallsBackToKallsyms(t *testing.T) {
	dir := t.TempDir()
	oldTracefs, oldKallsyms := tracefsAvailableFuncs, procKallsyms
	tracefsAvailableFuncs = filepath.Join(dir, "missing")
	procKallsyms = filepath.Join(dir, "kallsyms")
	t.Cleanup(func() { tracefsAvailableFuncs, procKallsyms = oldTracefs, oldKallsyms })
	require.NoError(t, os.WriteFile(procKallsyms,
		[]byte("ffffffffc0a01000 t nfs_file_read\t[nfs]\nffffffffc0a02000 T nfs_file_write\t[nfs]\n"), 0o644))

	sym, ok := resolveFsSymbol([]string{"nfs_file_read"})
	assert.True(t, ok)
	assert.Equal(t, "nfs_file_read", sym)
}

func TestFsTargetsCoverAllFilesystems(t *testing.T) {
	seen := map[FsTypeCode]bool{}
	for _, tgt := range fsTargets {
		seen[tgt.Fs] = true
		assert.NotEmpty(t, tgt.ReadSyms, "fs %d has no read symbols", tgt.Fs)
		assert.NotEmpty(t, tgt.WriteSyms, "fs %d has no write symbols", tgt.Fs)
		assert.NotEmpty(t, tgt.FsyncSyms, "fs %d has no fsync symbols", tgt.Fs)
		assert.NotEmpty(t, tgt.Module)
	}
	for _, want := range []FsTypeCode{CodeFsNFS, CodeFsCeph, CodeFsCIFS, CodeFsFUSE, CodeFsExt4, CodeFsXFS, CodeFsBtrfs} {
		assert.True(t, seen[want], "missing target for fs code %d", want)
	}
}

func TestFentryCapableModuleBTF(t *testing.T) {
	dir := t.TempDir()
	old := sysKernelBTFDir
	sysKernelBTFDir = dir
	t.Cleanup(func() { sysKernelBTFDir = old })

	// Module BTF present: fentryCapable must short-circuit on it without
	// consulting the kernel's own BTF at all.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nfs"), []byte("x"), 0o644))
	assert.True(t, fentryCapable("nfs", "nfs_file_read"))

	// No module BTF and a symbol that cannot possibly exist in vmlinux BTF
	// either: must fall through to false rather than panicking or hanging.
	assert.False(t, fentryCapable("does-not-exist", "no_such_symbol_ever"))
}

// The raw tracepoints read the device from the request's gendisk, so they
// are only usable where BTF shows where that lives: on the queue since 5.15,
// on the request before. Everything else, including a kernel with no BTF at
// all, takes the classic tracepoints.
func TestBlockRawTracepointCapableWith(t *testing.T) {
	specOf := func(types ...btf.Type) *btf.Spec {
		b, err := btf.NewBuilder(types, nil)
		require.NoError(t, err)
		spec, err := b.Spec()
		require.NoError(t, err)
		return spec
	}
	gendisk := &btf.Pointer{Target: &btf.Struct{Name: "gendisk"}}
	queueWith := func(members ...btf.Member) *btf.Struct {
		return &btf.Struct{Name: "request_queue", Members: members}
	}
	// The request points at the one queue in the spec, as the kernel's does.
	blockStructs := func(queue *btf.Struct, requestMembers ...btf.Member) []btf.Type {
		request := &btf.Struct{Name: "request", Members: append([]btf.Member{
			{Name: "q", Type: &btf.Pointer{Target: queue}},
		}, requestMembers...)}
		return []btf.Type{queue, request}
	}

	for _, tc := range []struct {
		name string
		spec *btf.Spec
		want bool
	}{
		{"no BTF", nil, false},
		{"5.15+: gendisk on the queue", specOf(blockStructs(queueWith(btf.Member{Name: "disk", Type: gendisk}))...), true},
		{"pre-5.15: gendisk on the request", specOf(blockStructs(queueWith(), btf.Member{Name: "rq_disk", Type: gendisk})...), true},
		{"neither member", specOf(blockStructs(queueWith())...), false},
		{"member of another type", specOf(blockStructs(queueWith(btf.Member{Name: "disk", Type: &btf.Int{Name: "int", Size: 4}}))...), false},
		{"no block structs at all", specOf(&btf.Struct{Name: "bio"}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, blockRawTracepointCapableWith(tc.spec))
		})
	}
}

// A burst's cache lives until the burst is released, and a renewed cache
// replaces the retained one: never more than one is held.
func TestBTFBurstReleasesCache(t *testing.T) {
	releases := 0
	b := &btfBurst{onRelease: func() { releases++ }}

	first := b.Cache()
	assert.Same(t, first, b.Cache(), "one cache per burst")
	b.Release()
	assert.Equal(t, 1, releases)
	assert.Nil(t, b.cache, "released: nothing retained")

	second := b.Cache()
	assert.NotSame(t, first, second, "the next load starts a new burst")
	renewed := b.Renew()
	assert.NotSame(t, second, renewed)
	assert.Same(t, renewed, b.cache, "the renewed cache replaces the burst's")

	b.Release()
	b.Release()
	assert.Equal(t, 2, releases, "releasing no burst is a no-op")
	assert.Nil(t, b.cache)
}

// The modules' BTF is parsed once per burst, failures included: cilium
// keeps no failed parse, so asking again must not parse a broken module
// again.
func TestBTFBurstParsesOncePerBurst(t *testing.T) {
	b := &btfBurst{}
	b.Parse()
	b.broken = []string{"obi_broken"}
	assert.True(t, b.ModuleBTFBroken(""))
	assert.True(t, b.ModuleBTFBroken("obi_broken"))
	assert.False(t, b.ModuleBTFBroken("obi_fine"))
	_, ok := b.Parse()
	assert.False(t, ok)
	assert.Equal(t, 1, b.parses)

	b.Release()
	assert.False(t, b.ModuleBTFBroken("obi_broken"), "a new burst forgets the failures of the last")
	assert.Equal(t, 2, b.parses)
	b.Renew()
	b.ModuleBTFBroken("")
	assert.Equal(t, 3, b.parses, "a renewed cache is parsed again")
}
