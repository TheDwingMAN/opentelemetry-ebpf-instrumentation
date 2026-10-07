// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

// The filesystem programs live in the FsIo object only: a stats load cannot
// fail on a filesystem, and every name the planner uses is a program of FsIo.
func TestFsProgramsLiveInTheirOwnObject(t *testing.T) {
	stats, err := LoadStats()
	require.NoError(t, err)
	fsIo, err := LoadFsIo()
	require.NoError(t, err)

	named := map[string]bool{}
	for _, tgt := range fsTargets {
		for _, fentry := range []bool{true, false} {
			for _, p := range fsPlanProbes(fsAttachPlan{
				Fs: tgt.Fs, UseFentry: fentry, ReadSym: "r", WriteSym: "w", FsyncSym: "f", SpliceReadSym: splice(tgt),
			}) {
				named[p.prog] = true
			}
		}
	}
	// Step 14: the sync syscall set's programs, every fentry/kprobe
	// combination, live in the same FsIo object.
	for _, useFentry := range []bool{true, false} {
		for _, p := range fsSyncPlanProbes(fsSyncPlan{
			SyncfsSym: "syncfs", UseFentrySyncfs: useFentry,
			SyncFileRangeSym: "sync_file_range", UseFentrySyncFileRange: useFentry,
			SyncSym: "sync",
		}) {
			named[p.prog] = true
		}
	}

	for name := range named {
		assert.Contains(t, fsIo.Programs, name)
		assert.NotContains(t, stats.Programs, name)
	}
	for name := range fsIo.Programs {
		assert.True(t, named[name], "FsIo program %s is not named by the planner", name)
	}
}

func splice(tgt fsTarget) string {
	if len(tgt.SpliceReadSyms) == 0 {
		return ""
	}
	return "s"
}

// A filesystem load creates its plan's programs and no other, each tracing
// program pointed at its kernel function.
func TestKeepFsProgramsLoadsOnlyThePlan(t *testing.T) {
	spec, err := LoadFsIo()
	require.NoError(t, err)
	plan := fsAttachPlan{
		Fs: CodeFsNFS, UseFentry: true,
		ReadSym: "nfs_file_read", WriteSym: "nfs_file_write",
		FsyncSym: "nfs_file_fsync", SpliceReadSym: "nfs_file_splice_read",
	}
	probes := fsPlanProbes(plan)

	require.NoError(t, keepFsPrograms(spec, probes))

	require.Len(t, spec.Programs, len(probes))
	for _, p := range probes {
		require.Contains(t, spec.Programs, p.prog)
		assert.Equal(t, ebpf.Tracing, spec.Programs[p.prog].Type)
		assert.Equal(t, p.sym, spec.Programs[p.prog].AttachTo)
	}

	assert.Error(t, keepFsPrograms(spec, []fsProbe{{prog: "no_such_program"}}))
}

// fakeFsLoader is an fsLoader over the real FsIo spec that records its loads
// instead of creating anything in the kernel.
func fakeFsLoader(t *testing.T, consts map[string]any) (*fsLoader, *[]ebpf.CollectionOptions, *[]*ebpf.CollectionSpec) {
	t.Helper()
	// Every map a filesystem load needs already exists, as after the stats
	// load, so resolving them creates nothing.
	sharedMaps := map[string]*ebpf.Map{
		FsIoMapStatsEvents: {}, FsIoMapDebugEvents: {}, FsIoMapFsStart: {}, FsIoMapFsStartTask: {},
		FsIoMapFsDevFilter: {}, FsIoMapFsDrops: {}, FsIoMapFsIoAccum: {}, FsIoMapFsIoAccumExp: {}, FsIoMapFsAccumZero: {},
	}
	l, err := newFsLoader(slog.Default(), &config.EBPFTracer{}, consts, FsAggregation{}, sharedMaps, &sync.Mutex{})
	require.NoError(t, err)
	// A load parses the kernel BTF into the process's burst: end it, as the
	// attacher does, or a later test's startup finds it parsed already.
	t.Cleanup(l.btf.Release)

	var opts []ebpf.CollectionOptions
	var specs []*ebpf.CollectionSpec
	l.newCollection = func(spec *ebpf.CollectionSpec, o ebpf.CollectionOptions) (*ebpf.Collection, error) {
		opts = append(opts, o)
		specs = append(specs, spec)
		return &ebpf.Collection{}, nil
	}
	return l, &opts, &specs
}

// Every filesystem load of a burst uses the burst's kernel BTF cache, the one
// the stats collection loaded with at startup, so vmlinux BTF is parsed once
// per burst.
func TestFsLoaderSharesTheBTFCache(t *testing.T) {
	old := sysKernelBTFDir
	sysKernelBTFDir = t.TempDir() // ext4 and xfs: built in, no module BTF
	t.Cleanup(func() { sysKernelBTFDir = old })

	l, opts, _ := fakeFsLoader(t, nil)
	for _, fs := range []FsTypeCode{CodeFsExt4, CodeFsXFS} {
		_, err := l.load(fsAttachPlan{Fs: fs, Module: fsTypeStr(fs), UseFentry: true, ReadSym: "r", WriteSym: "w"})
		require.NoError(t, err)
	}

	require.Len(t, *opts, 2)
	assert.Same(t, kernelBTFCache, l.btf)
	for _, o := range *opts {
		assert.Same(t, kernelBTFCache.Cache(), o.Cache)
	}
}

// A filesystem collection gets the same load-time constants as the stats
// collection, from the one statsConstants map.
func TestFsLoaderConstantsMatchTheStatsCollection(t *testing.T) {
	consts := statsConstants(
		&config.EBPFTracer{BpfDebug: true, StatsWakeupDataBytes: 4096},
		blockLoadPlan{wantQueueDepth: true, emitKinds: 0x03},
		FsAggregation{Enabled: true, BoundsNs: []uint64{1000, 2000}},
	)

	stats, err := LoadStats()
	require.NoError(t, err)
	require.NoError(t, ebpfconvenience.RewriteConstants(stats, specConstants(stats, consts)))

	l, _, specs := fakeFsLoader(t, consts)
	_, err = l.load(fsAttachPlan{Fs: CodeFsNFS, Module: "nfs", ReadSym: "r", WriteSym: "w"})
	require.NoError(t, err)
	require.Len(t, *specs, 1)
	fsIo := (*specs)[0]

	shared := 0
	for name := range consts {
		fsVar, inFs := fsIo.Variables[name]
		statsVar, inStats := stats.Variables[name]
		assert.True(t, inFs || inStats, "constant %s is declared by no collection", name)
		if !inFs || !inStats {
			continue
		}
		shared++
		assert.Equal(t, statsVar.Value, fsVar.Value, "constant %s differs between the collections", name)
	}
	assert.Equal(t, 2, shared, "g_bpf_debug and stats_wakeup_data_bytes")
}

// A module whose BTF appeared after the cache listed the kernel's modules is
// only seen through a fresh cache; a filesystem without module BTF keeps the
// shared one.
func TestFsLoaderCacheForNewModule(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf"); err != nil {
		t.Skip("no /sys/kernel/btf: the cache cannot list modules")
	}
	cache := btf.NewCache()
	modules, err := cache.Modules()
	require.NoError(t, err)

	old := sysKernelBTFDir
	sysKernelBTFDir = t.TempDir()
	t.Cleanup(func() { sysKernelBTFDir = old })
	require.NoError(t, os.WriteFile(sysKernelBTFDir+"/obi_test_new_module", nil, 0o644))
	require.NotContains(t, modules, "obi_test_new_module")

	l := &fsLoader{log: slog.Default(), btf: &btfBurst{cache: cache}}
	assert.Same(t, cache, l.cacheFor("ext4"), "no module BTF: shared cache")
	fresh := l.cacheFor("obi_test_new_module")
	assert.NotSame(t, cache, fresh, "module unknown to the cache: fresh cache")
	assert.Same(t, fresh, l.btf.Cache(), "the fresh cache replaces the burst's, which is not retained")
}

// On detach every entry probe goes before any exit probe, so no call records
// a start whose exit probe is gone; then the filesystem's leftover fs_start
// entries are deleted.
func TestFsAttachmentCloseOrder(t *testing.T) {
	plan := fsAttachPlan{Fs: CodeFsExt4, ReadSym: "r", WriteSym: "w", FsyncSym: "f", SpliceReadSym: "s"}
	var closed []string
	a := &fsAttachment{
		coll:        &ebpf.Collection{},
		probes:      fsPlanProbes(plan),
		clearStarts: func() error { closed = append(closed, "clear fs_start"); return nil },
	}
	for _, p := range a.probes {
		a.links = append(a.links, closeFunc(func() error { closed = append(closed, p.prog); return nil }))
	}

	require.NoError(t, a.Close())

	require.Len(t, closed, len(a.probes)+1)
	names := fsProgNamesFor(CodeFsExt4)
	entries := []string{names.KprobeRead, names.KprobeWrite, names.KprobeFsync, names.KprobeSpliceRead}
	exits := []string{names.KretprobeRead, names.KretprobeWrite, names.KretprobeFsync, names.KretprobeSpliceRead}
	assert.ElementsMatch(t, entries, closed[:4], "entry probes first")
	assert.ElementsMatch(t, exits, closed[4:8], "exit probes next")
	assert.Equal(t, "clear fs_start", closed[8], "fs_start cleared last")
}

// A detached filesystem's fs_start entries are deleted, and no other
// filesystem's; an entry whose call returned meanwhile is no error.
func TestClearFsStarts(t *testing.T) {
	starts := map[uint64]FsIoFsStartVal{
		1: {Fs: uint8(CodeFsExt4)},
		2: {Fs: uint8(CodeFsNFS)},
		3: {Fs: uint8(CodeFsExt4), Depth: 2},
		4: {Fs: uint8(CodeFsXFS)},
	}
	del := func(id uint64) error {
		if id == 3 {
			return fmt.Errorf("delete: %w", ebpf.ErrKeyNotExist) // returned meanwhile
		}
		delete(starts, id)
		return nil
	}

	require.NoError(t, clearFsStarts(maps.All(maps.Clone(starts)), del, CodeFsExt4))
	assert.Equal(t, map[uint64]FsIoFsStartVal{
		2: {Fs: uint8(CodeFsNFS)}, 3: {Fs: uint8(CodeFsExt4), Depth: 2}, 4: {Fs: uint8(CodeFsXFS)},
	}, starts)

	failing := func(uint64) error { return errors.New("EPERM") }
	assert.Error(t, clearFsStarts(maps.All(starts), failing, CodeFsExt4))
}

// fs_start has no cache= variant field (2.4, step 12): clearFsStarts filters
// by FsTypeCode alone, so it cannot tell CIFS's cache=loose and cache=none
// apart. Closing one variant's fsAttachment -- on an attach failure or a
// retry -- clears the other's in-flight start too, although its probes are
// still attached and that call has not returned yet; sized here at the unit
// level (devdocs/metrics.md documents the residual risk this leaves, since
// fixing it needs a variant field on fs_start's value, a BPF-side change).
func TestClearFsStartsCannotDistinguishCIFSVariants(t *testing.T) {
	starts := map[uint64]FsIoFsStartVal{
		1: {Fs: uint8(CodeFsCIFS)}, // cache=loose's in-flight read
		2: {Fs: uint8(CodeFsCIFS)}, // cache=none's own in-flight write
	}
	del := func(id uint64) error { delete(starts, id); return nil }

	// cache=none's attachment closes (its own attach failed or is retried);
	// clearFsStarts, scoped only to CodeFsCIFS, wipes cache=loose's entry 1
	// too, though cache=loose's probes are untouched.
	require.NoError(t, clearFsStarts(maps.All(maps.Clone(starts)), del, CodeFsCIFS))
	assert.Empty(t, starts, "both variants' starts are gone, not only the closing attachment's own")
}

// The verifier tests load both program families of every filesystem, the
// kprobe fallback included, whatever this kernel plans; tracing programs
// point at the filesystem's own function when planned on fentry, at a
// vmlinux stand-in otherwise.
func TestVerifierFsProbesCoverEveryProgram(t *testing.T) {
	all, err := LoadFsIo()
	require.NoError(t, err)

	// No kernel BTF: no tracing program can load, every kprobe one is kept.
	spec := all.Copy()
	require.NoError(t, keepFsPrograms(spec, verifierFsProbes(nil, nil)))
	for name, prog := range all.Programs {
		if prog.Type == ebpf.Kprobe {
			assert.Contains(t, spec.Programs, name)
		} else {
			assert.NotContains(t, spec.Programs, name)
		}
	}

	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skip("no kernel BTF:", err)
	}
	nfs := fsAttachPlan{
		Fs: CodeFsNFS, UseFentry: true, ReadSym: "nfs_file_read", WriteSym: "nfs_file_write", FsyncSym: "",
	}
	spec = all.Copy()
	require.NoError(t, keepFsPrograms(spec, verifierFsProbes([]fsAttachPlan{nfs}, kernel)))
	assert.Len(t, spec.Programs, len(all.Programs), "every program of both families")

	names := fsProgNamesFor(CodeFsNFS)
	assert.Equal(t, "nfs_file_read", spec.Programs[names.FentryRead].AttachTo, "planned on fentry: its own function")
	assert.Equal(t, "nfs_file_write", spec.Programs[names.FexitWrite].AttachTo)
	for name, prog := range spec.Programs {
		if prog.Type != ebpf.Tracing {
			continue
		}
		var fn *btf.Func
		if prog.AttachTo != "nfs_file_read" && prog.AttachTo != "nfs_file_write" {
			require.NoError(t, kernel.TypeByName(prog.AttachTo, &fn), "%s: stand-in %q is not in vmlinux", name, prog.AttachTo)
		}
	}
	assert.Contains(t, fsStandIns.fsync, spec.Programs[names.FentryFsync].AttachTo, "no fsync planned: a stand-in")
	ext4 := fsProgNamesFor(CodeFsExt4)
	assert.Equal(t, "generic_file_read_iter", spec.Programs[ext4.FentryRead].AttachTo, "not planned: a stand-in")
}
