// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
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
