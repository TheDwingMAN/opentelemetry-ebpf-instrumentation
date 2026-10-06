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
	capable := func(module, _ string) bool { return module == "nfs" }
	sym := func(cands []string) (string, bool) {
		for _, c := range cands {
			if c == "nfs_file_read" || c == "nfs_file_write" ||
				c == "ceph_read_iter" || c == "ceph_write_iter" {
				return c, true
			}
		}
		return "", false
	}

	plans := planFsAttachWith(fsTargets, capable, sym)

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
	capable := func(string, string) bool { return true }
	sym := func(cands []string) (string, bool) {
		for _, c := range cands {
			if c == "nfs_file_read" {
				return c, true
			}
		}
		return "", false
	}
	plans := planFsAttachWith(fsTargets[:1], capable, sym)
	assert.Empty(t, plans)
}

func TestPlanFsAttachFsyncResolvedIndependently(t *testing.T) {
	// nfs: read, write and fsync all present -> FsyncSym set.
	// ceph: read and write present, fsync candidate absent -> plan still
	// created (read/write attach), but FsyncSym is empty.
	capable := func(string, string) bool { return true }
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

	plans := planFsAttachWith(fsTargets, capable, sym)

	byFs := map[FsTypeCode]fsAttachPlan{}
	for _, p := range plans {
		byFs[p.Fs] = p
	}

	require.Contains(t, byFs, CodeFsNFS)
	assert.Equal(t, "nfs_file_fsync", byFs[CodeFsNFS].FsyncSym)

	require.Contains(t, byFs, CodeFsCeph, "ceph read/write present, must still attach despite missing fsync")
	assert.Empty(t, byFs[CodeFsCeph].FsyncSym, "ceph_fsync absent, FsyncSym must stay empty")
}

// An fsync symbol that cannot be probed drops only the fsync probes of that
// filesystem, and a probeable one is attached like read and write, through
// the family the plan chose.
func TestFsPlanProbesFsyncIndependent(t *testing.T) {
	progs := func(probes []fsProbe) map[string]string {
		m := map[string]string{}
		for _, p := range probes {
			m[p.prog] = p.sym
		}
		return m
	}

	nfs := fsProgNamesFor(CodeFsNFS)
	got := progs(fsPlanProbes(fsAttachPlan{
		Fs: CodeFsNFS, UseFentry: true,
		ReadSym: "nfs_file_read", WriteSym: "nfs_file_write", FsyncSym: "nfs_file_fsync",
	}))
	assert.Equal(t, map[string]string{
		nfs.FentryRead: "nfs_file_read", nfs.FexitRead: "nfs_file_read",
		nfs.FentryWrite: "nfs_file_write", nfs.FexitWrite: "nfs_file_write",
		nfs.FentryFsync: "nfs_file_fsync", nfs.FexitFsync: "nfs_file_fsync",
	}, got, "fentry mode: only fentry/fexit programs, fsync included")

	ceph := fsProgNamesFor(CodeFsCeph)
	got = progs(fsPlanProbes(fsAttachPlan{
		Fs: CodeFsCeph, UseFentry: true,
		ReadSym: "ceph_read_iter", WriteSym: "ceph_write_iter",
	}))
	assert.Equal(t, map[string]string{
		ceph.FentryRead: "ceph_read_iter", ceph.FexitRead: "ceph_read_iter",
		ceph.FentryWrite: "ceph_write_iter", ceph.FexitWrite: "ceph_write_iter",
	}, got, "fsync unresolved: read and write still attach")

	cifs := fsProgNamesFor(CodeFsCIFS)
	got = progs(fsPlanProbes(fsAttachPlan{
		Fs: CodeFsCIFS, UseFentry: false,
		ReadSym: "cifs_loose_read_iter", WriteSym: "cifs_file_write_iter", FsyncSym: "cifs_fsync",
	}))
	assert.Equal(t, map[string]string{
		cifs.KprobeRead: "cifs_loose_read_iter", cifs.KretprobeRead: "cifs_loose_read_iter",
		cifs.KprobeWrite: "cifs_file_write_iter", cifs.KretprobeWrite: "cifs_file_write_iter",
		cifs.KprobeFsync: "cifs_fsync", cifs.KretprobeFsync: "cifs_fsync",
	}, got, "kprobe mode: only kprobe/kretprobe programs")
}

// Every exit probe attaches before its entry probe, or a call entering in
// between would leave a start behind that no exit ever consumes.
func TestFsPlanProbesAttachExitFirst(t *testing.T) {
	for _, fentry := range []bool{true, false} {
		probes := fsPlanProbes(fsAttachPlan{
			Fs: CodeFsExt4, UseFentry: fentry,
			ReadSym: "r", WriteSym: "w", FsyncSym: "f", SpliceReadSym: "s",
		})
		require.Len(t, probes, 8)
		for i := 0; i < len(probes); i += 2 {
			assert.True(t, probes[i].exit, "probe %d (%s) must be an exit probe", i, probes[i].prog)
			assert.False(t, probes[i+1].exit, "probe %d (%s) must be an entry probe", i+1, probes[i+1].prog)
			assert.Equal(t, probes[i].sym, probes[i+1].sym)
		}
	}
}

// A filesystem whose splice_read symbol cannot be probed still gets its read
// and write probes: splice is an extra path, not a prerequisite.
func TestPlanFsAttachSpliceReadResolvedIndependently(t *testing.T) {
	targets := []fsTarget{{
		Fs: CodeFsNFS, Module: "nfs",
		ReadSyms:       []string{"nfs_file_read"},
		WriteSyms:      []string{"nfs_file_write"},
		FsyncSyms:      []string{"nfs_file_fsync"},
		SpliceReadSyms: []string{"nfs_file_splice_read"},
	}}
	resolve := func(c []string) (string, bool) {
		if len(c) == 0 || c[0] == "nfs_file_splice_read" {
			return "", false
		}
		return c[0], true
	}

	plans := planFsAttachWith(targets, func(string, string) bool { return true }, resolve)

	require.Len(t, plans, 1)
	assert.Equal(t, "nfs_file_read", plans[0].ReadSym)
	assert.Equal(t, "nfs_file_fsync", plans[0].FsyncSym)
	assert.Empty(t, plans[0].SpliceReadSym)
}

// The lab cifs.ko set (section 9, step 12): all nine file_operations symbols
// present, but cache=loose's read_iter and write_iter are static and absent
// from the module's own BTF, so only that variant falls back to kprobes.
// Every present variant attaches -- the release's first-present-wins bug
// this step fixes -- and cifs_fsync, shared by loose and direct, is claimed
// by loose alone.
func TestPlanFsAttachCIFSAttachesEveryVariant(t *testing.T) {
	const (
		strictRead, strictWrite, strictFsync = "cifs_strict_readv", "cifs_strict_writev", "cifs_strict_fsync"
		looseRead, looseWrite, sharedFsync   = "cifs_loose_read_iter", "cifs_file_write_iter", "cifs_fsync"
		directRead, directWrite              = "cifs_direct_readv", "cifs_direct_writev"
	)
	// Every symbol the lab's `nm` dump found is probeable, cifs_user_readv
	// and cifs_user_writev included: planFsAttachWith must still never ask
	// for them, since they are not in any target's candidate lists.
	probeable := map[string]bool{
		strictRead: true, strictWrite: true, strictFsync: true,
		looseRead: true, looseWrite: true, sharedFsync: true,
		directRead: true, directWrite: true,
		"cifs_user_readv": true, "cifs_user_writev": true,
	}
	resolve := func(cands []string) (string, bool) {
		for _, c := range cands {
			if probeable[c] {
				return c, true
			}
		}
		return "", false
	}
	// Only cache=loose's read_iter is missing from the module's own BTF
	// (moduleBTFExists is irrelevant here: this is the per-symbol check).
	capable := func(_, sym string) bool { return sym != looseRead }

	cifsTargets := make([]fsTarget, 0, 3)
	for _, tgt := range fsTargets {
		if tgt.Fs == CodeFsCIFS {
			cifsTargets = append(cifsTargets, tgt)
		}
	}
	require.Len(t, cifsTargets, 3, "strict, loose and direct")

	plans := planFsAttachWith(cifsTargets, capable, resolve)
	require.Len(t, plans, 3, "every variant attaches, not just the first present")

	byVariant := map[string]fsAttachPlan{}
	for _, p := range plans {
		byVariant[p.Variant] = p
	}

	strict := byVariant["strict"]
	assert.Equal(t, strictRead, strict.ReadSym)
	assert.Equal(t, strictWrite, strict.WriteSym)
	assert.Equal(t, strictFsync, strict.FsyncSym)
	assert.True(t, strict.UseFentry)

	loose := byVariant["loose"]
	assert.Equal(t, looseRead, loose.ReadSym)
	assert.Equal(t, looseWrite, loose.WriteSym)
	assert.False(t, loose.UseFentry, "cache=loose's read_iter is absent from the module's own BTF")
	assert.Equal(t, sharedFsync, loose.FsyncSym, "loose claims the shared fsync symbol")

	direct := byVariant["direct"]
	assert.Equal(t, directRead, direct.ReadSym)
	assert.Equal(t, directWrite, direct.WriteSym)
	assert.True(t, direct.UseFentry)
	assert.Empty(t, direct.FsyncSym, "cifs_fsync is attached once, by loose")

	for _, p := range plans {
		assert.NotEqual(t, "cifs_user_readv", p.ReadSym, "shared body of strict and direct, never probed")
		assert.NotEqual(t, "cifs_user_writev", p.WriteSym, "shared body of strict and direct, never probed")
	}
}

// dedupeSharedFsync only clears a later plan's FsyncSym when an earlier one
// already claimed the same symbol; an unrelated clash never happens between
// different filesystems, whose symbols are never equal, but the rule is
// symbol-based and not CIFS-specific.
func TestDedupeSharedFsyncKeepsFirstClaimOnly(t *testing.T) {
	plans := []fsAttachPlan{
		{Fs: CodeFsCIFS, Variant: "loose", FsyncSym: "cifs_fsync"},
		{Fs: CodeFsCIFS, Variant: "direct", FsyncSym: "cifs_fsync"},
		{Fs: CodeFsNFS, FsyncSym: "nfs_file_fsync"},
	}
	dedupeSharedFsync(plans)
	assert.Equal(t, "cifs_fsync", plans[0].FsyncSym)
	assert.Empty(t, plans[1].FsyncSym)
	assert.Equal(t, "nfs_file_fsync", plans[2].FsyncSym, "a different symbol is never cleared")
}

// fsPlanProbes of the three real CIFS plans together attach cifs_fsync
// exactly once, through loose's program family, even though loose and
// direct are independent collections.
func TestFsPlanProbesCIFSSharedFsyncAttachesOnce(t *testing.T) {
	cifs := fsProgNamesFor(CodeFsCIFS)
	loose := fsAttachPlan{
		Fs: CodeFsCIFS, Variant: "loose", UseFentry: false,
		ReadSym: "cifs_loose_read_iter", WriteSym: "cifs_file_write_iter", FsyncSym: "cifs_fsync",
	}
	direct := fsAttachPlan{
		Fs: CodeFsCIFS, Variant: "direct", UseFentry: true,
		ReadSym: "cifs_direct_readv", WriteSym: "cifs_direct_writev",
	}

	fsyncTargets := 0
	for _, p := range fsPlanProbes(loose) {
		if p.prog == cifs.KprobeFsync || p.prog == cifs.KretprobeFsync {
			fsyncTargets++
			assert.Equal(t, "cifs_fsync", p.sym)
		}
	}
	for _, p := range fsPlanProbes(direct) {
		assert.NotEqual(t, cifs.FentryFsync, p.prog, "direct carries no fsync symbol: it is not asked for")
		assert.NotEqual(t, cifs.FexitFsync, p.prog, "direct carries no fsync symbol: it is not asked for")
	}
	assert.Equal(t, 2, fsyncTargets, "one kprobe and one kretprobe, from loose alone")
}

// Ceph, CIFS and XFS have no dedicated splice_read symbol, so their plans
// carry none and no splice program is asked for; NFS's is attached through
// the chosen family only.
func TestFsPlanProbesSkipsAbsentSpliceFamilies(t *testing.T) {
	probes := append(
		fsPlanProbes(fsAttachPlan{Fs: CodeFsCeph, UseFentry: true, ReadSym: "ceph_read_iter", WriteSym: "ceph_write_iter"}),
		fsPlanProbes(fsAttachPlan{
			Fs: CodeFsNFS, UseFentry: true, ReadSym: "nfs_file_read", WriteSym: "nfs_file_write", SpliceReadSym: "nfs_file_splice_read",
		})...,
	)

	got := map[string]string{}
	for _, p := range probes {
		assert.NotEmpty(t, p.prog, "an empty name is not a program")
		got[p.prog] = p.sym
	}
	assert.Equal(t, "nfs_file_splice_read", got[progObiStatsFentrySpliceNFS])
	assert.Equal(t, "nfs_file_splice_read", got[progObiStatsFexitSpliceNFS])
	assert.NotContains(t, got, progObiStatsKprobeSpliceNFS, "the kprobe family loses when fentry wins")
	assert.Len(t, got, 4+6)
}
