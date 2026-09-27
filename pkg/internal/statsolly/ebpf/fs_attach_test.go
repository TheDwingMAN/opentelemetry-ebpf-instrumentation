// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlanFsAttachPerFilesystem(t *testing.T) {
	// nfs: module BTF present -> fentry. ceph: symbols present but no module
	// BTF -> kprobe. cifs: nothing present -> skipped entirely.
	btf := func(mod string) bool { return mod == "nfs" }
	sym := func(cands []string) (string, bool) {
		for _, c := range cands {
			if c == "nfs_file_read" || c == "nfs_file_write" ||
				c == "ceph_read_iter" || c == "ceph_write_iter" {
				return c, true
			}
		}
		return "", false
	}

	plans := planFsAttachWith(fsTargets, btf, sym)

	byFs := map[FsTypeCode]fsAttachPlan{}
	for _, p := range plans {
		byFs[p.Fs] = p
	}

	require.Contains(t, byFs, CodeFsNFS)
	assert.True(t, byFs[CodeFsNFS].UseFentry, "nfs has module BTF, should use fentry")
	assert.Equal(t, "nfs_file_read", byFs[CodeFsNFS].ReadSym)

	require.Contains(t, byFs, CodeFsCeph)
	assert.False(t, byFs[CodeFsCeph].UseFentry, "ceph lacks module BTF, should use kprobe")

	assert.NotContains(t, byFs, CodeFsCIFS, "cifs symbols absent, must be skipped")
	assert.NotContains(t, byFs, CodeFsFUSE)
}

func TestPlanFsAttachRequiresBothSymbols(t *testing.T) {
	// A filesystem whose write symbol is missing must be skipped entirely
	// rather than attached read-only.
	btf := func(string) bool { return true }
	sym := func(cands []string) (string, bool) {
		for _, c := range cands {
			if c == "nfs_file_read" {
				return c, true
			}
		}
		return "", false
	}
	plans := planFsAttachWith(fsTargets[:1], btf, sym)
	assert.Empty(t, plans)
}

func TestPlanFsAttachFsyncResolvedIndependently(t *testing.T) {
	// nfs: read, write and fsync all present -> FsyncSym set.
	// ceph: read and write present, fsync candidate absent -> plan still
	// created (read/write attach), but FsyncSym is empty.
	btf := func(string) bool { return true }
	sym := func(cands []string) (string, bool) {
		for _, c := range cands {
			switch c {
			case "nfs_file_read", "nfs_file_write", "nfs_file_fsync",
				"ceph_read_iter", "ceph_write_iter":
				return c, true
			}
		}
		return "", false
	}

	plans := planFsAttachWith(fsTargets, btf, sym)

	byFs := map[FsTypeCode]fsAttachPlan{}
	for _, p := range plans {
		byFs[p.Fs] = p
	}

	require.Contains(t, byFs, CodeFsNFS)
	assert.Equal(t, "nfs_file_fsync", byFs[CodeFsNFS].FsyncSym)

	require.Contains(t, byFs, CodeFsCeph, "ceph read/write present, must still attach despite missing fsync")
	assert.Empty(t, byFs[CodeFsCeph].FsyncSym, "ceph_fsync absent, FsyncSym must stay empty")
}

// TestPlanFsToDisableFsyncIndependent asserts that an unresolvable fsync
// candidate disables only the fsync program families for that filesystem,
// leaving its read/write attachment untouched, and that a resolvable fsync
// symbol is wired into attachTo like read/write already are.
func TestPlanFsToDisableFsyncIndependent(t *testing.T) {
	plans := []fsAttachPlan{
		// fentry mode, fsync resolved.
		{Fs: CodeFsNFS, UseFentry: true, ReadSym: "nfs_file_read", WriteSym: "nfs_file_write", FsyncSym: "nfs_file_fsync"},
		// fentry mode, fsync unresolved: read/write must still attach.
		{Fs: CodeFsCeph, UseFentry: true, ReadSym: "ceph_read_iter", WriteSym: "ceph_write_iter", FsyncSym: ""},
		// kprobe mode, fsync resolved.
		{Fs: CodeFsCIFS, UseFentry: false, ReadSym: "cifs_loose_read_iter", WriteSym: "cifs_file_write_iter", FsyncSym: "cifs_fsync"},
		// CodeFsFUSE intentionally absent: module not loaded at all.
	}

	toDisable, attachTo := planFsToDisable(plans)

	nfsNames := fsProgNamesFor(CodeFsNFS)
	assert.NotContains(t, toDisable, nfsNames.FentryFsync, "nfs fsync resolved, fentry fsync must stay enabled")
	assert.NotContains(t, toDisable, nfsNames.FexitFsync)
	assert.Contains(t, toDisable, nfsNames.KprobeFsync, "nfs uses fentry mode, kprobe fsync must be stubbed")
	assert.Contains(t, toDisable, nfsNames.KretprobeFsync)
	assert.Equal(t, "nfs_file_fsync", attachTo[nfsNames.FentryFsync])
	assert.Equal(t, "nfs_file_fsync", attachTo[nfsNames.FexitFsync])

	cephNames := fsProgNamesFor(CodeFsCeph)
	assert.NotContains(t, toDisable, cephNames.FentryRead, "ceph read/write must stay enabled despite missing fsync")
	assert.NotContains(t, toDisable, cephNames.FentryWrite)
	assert.Contains(t, toDisable, cephNames.FentryFsync, "ceph fsync unresolved, fentry fsync must be disabled")
	assert.Contains(t, toDisable, cephNames.FexitFsync)
	assert.Contains(t, toDisable, cephNames.KprobeFsync, "ceph fsync unresolved, kprobe fsync must also be disabled")
	assert.Contains(t, toDisable, cephNames.KretprobeFsync)
	assert.NotContains(t, attachTo, cephNames.FentryFsync)

	cifsNames := fsProgNamesFor(CodeFsCIFS)
	assert.Contains(t, toDisable, cifsNames.FentryFsync, "cifs uses kprobe mode, fentry fsync must be stubbed")
	assert.Contains(t, toDisable, cifsNames.FexitFsync)
	assert.NotContains(t, toDisable, cifsNames.KprobeFsync, "cifs fsync resolved, kprobe fsync must stay enabled")
	assert.NotContains(t, toDisable, cifsNames.KretprobeFsync)
	assert.NotContains(t, attachTo, cifsNames.KprobeFsync, "kprobe attach target is set at Attach time, not via AttachTo")

	fuseNames := fsProgNamesFor(CodeFsFUSE)
	for _, name := range slices.Concat(fuseNames.fentryFsyncPrograms(), fuseNames.kprobeFsyncPrograms()) {
		assert.Contains(t, toDisable, name, "fuse unplanned, all its programs including fsync must be disabled")
	}
}
