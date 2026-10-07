// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/btf"
)

// Variables rather than constants so tests can point them at fixtures.
var (
	sysKernelBTFDir       = "/sys/kernel/btf"
	tracefsAvailableFuncs = "/sys/kernel/tracing/available_filter_functions"
	procKallsyms          = "/proc/kallsyms"
	sysModuleDir          = "/sys/module"
)

// fsTarget names the file_operations read/write implementations for one
// filesystem, or for one cache= variant of a filesystem that exposes several:
// CIFS has independent vtables for cache=strict, cache=loose and cache=none,
// and every present one attaches, rather than the first-present-wins choice
// the release made (2.4, step 12).
type fsTarget struct {
	Fs FsTypeCode
	// Variant names a filesystem's cache= variant, empty for every
	// filesystem with only one. Several variants of one Fs attach side by
	// side, as independent collections (fsPlanKey tells them apart).
	Variant   string
	Module    string
	ReadSyms  []string
	WriteSyms []string
	FsyncSyms []string
	// SpliceReadSyms is the filesystem's own splice_read implementation, which
	// splice(2), sendfile(2) and copy_file_range(2) take instead of read_iter.
	// Only filesystems with a dedicated symbol are listed: ceph, cifs and xfs
	// use the generic filemap_splice_read, shared with every filesystem on the
	// node, so probing it would fire for container root filesystems too.
	SpliceReadSyms []string
}

// Key identifies tgt among the targets of the same Fs.
func (tgt fsTarget) Key() fsPlanKey { return fsPlanKey{Fs: tgt.Fs, Variant: tgt.Variant} }

var fsTargets = []fsTarget{
	{
		Fs: CodeFsNFS, Module: "nfs",
		ReadSyms:       []string{"nfs_file_read"},
		WriteSyms:      []string{"nfs_file_write"},
		FsyncSyms:      []string{"nfs_file_fsync"},
		SpliceReadSyms: []string{"nfs_file_splice_read"},
	},
	{
		Fs: CodeFsCeph, Module: "ceph",
		ReadSyms:  []string{"ceph_read_iter"},
		WriteSyms: []string{"ceph_write_iter"},
		FsyncSyms: []string{"ceph_fsync"},
	},
	// CIFS: never cifs_user_readv/cifs_user_writev, the shared body strict
	// and direct call into -- probing them would count strict's I/O twice
	// (2.4). cifs_fsync is loose's and direct's shared fsync implementation;
	// listing it on both and resolving each variant independently would
	// attach it twice, so dedupeSharedFsync (used by planFsAttachWith)
	// clears it from every target after the first that claims it.
	{
		Fs: CodeFsCIFS, Variant: "strict", Module: "cifs",
		ReadSyms:  []string{"cifs_strict_readv"},
		WriteSyms: []string{"cifs_strict_writev"},
		FsyncSyms: []string{"cifs_strict_fsync"},
	},
	{
		Fs: CodeFsCIFS, Variant: "loose", Module: "cifs",
		ReadSyms:  []string{"cifs_loose_read_iter"},
		WriteSyms: []string{"cifs_file_write_iter"},
		FsyncSyms: []string{"cifs_fsync"},
	},
	{
		Fs: CodeFsCIFS, Variant: "direct", Module: "cifs",
		ReadSyms:  []string{"cifs_direct_readv"},
		WriteSyms: []string{"cifs_direct_writev"},
		FsyncSyms: []string{"cifs_fsync"},
	},
	{
		Fs: CodeFsFUSE, Module: "fuse",
		ReadSyms:       []string{"fuse_file_read_iter"},
		WriteSyms:      []string{"fuse_file_write_iter"},
		FsyncSyms:      []string{"fuse_fsync"},
		SpliceReadSyms: []string{"fuse_splice_read"},
	},
	{
		Fs: CodeFsExt4, Module: "ext4",
		ReadSyms:       []string{"ext4_file_read_iter"},
		WriteSyms:      []string{"ext4_file_write_iter"},
		FsyncSyms:      []string{"ext4_sync_file"},
		SpliceReadSyms: []string{"ext4_file_splice_read"},
	},
	{
		Fs: CodeFsXFS, Module: "xfs",
		ReadSyms:  []string{"xfs_file_read_iter"},
		WriteSyms: []string{"xfs_file_write_iter"},
		FsyncSyms: []string{"xfs_file_fsync"},
	},
	{
		Fs: CodeFsBtrfs, Module: "btrfs",
		ReadSyms:       []string{"btrfs_file_read_iter"},
		WriteSyms:      []string{"btrfs_file_write_iter"},
		FsyncSyms:      []string{"btrfs_sync_file"},
		SpliceReadSyms: []string{"btrfs_file_splice_read"},
	},
}

// moduleBTFExists reports whether the kernel exposes BTF for a module, which is
// a precondition for attaching fentry/fexit to a function inside it. Absent on
// RHEL8-family kernels, which lack CONFIG_DEBUG_INFO_BTF_MODULES.
func moduleBTFExists(mod string) bool {
	_, err := os.Stat(filepath.Join(sysKernelBTFDir, mod))
	return err == nil
}

// kernelBTFCache holds the parsed kernel BTF of the current load burst:
// the startup loads, or one attacher refresh that loads a filesystem.
// Parsing vmlinux BTF costs tens of milliseconds and megabytes of memory,
// and every module's BTF as much again, and without a shared cache cilium
// parses them all again for each collection it loads. Kept for the life of
// the process, the parsed BTF of vmlinux and of every module would hold
// some 16 MiB for loads that happen at startup and on a few mounts.
var kernelBTFCache = &btfBurst{}

// btfBurst is the kernel BTF cache of a load burst, dropped when the burst
// ends and started again by the next load. It is safe for concurrent use.
type btfBurst struct {
	mu    sync.Mutex
	cache *btf.Cache
	// parsed is set once parse has run on cache.
	parsed bool
	// broken names the loaded modules whose BTF cannot be parsed, as parse
	// found them.
	broken []string
	// parses counts the runs of parse; onRelease is called for each cache
	// release drops. For tests.
	parses    int
	onRelease func()
}

// Cache returns the burst's cache, starting a burst if none is under way.
func (b *btfBurst) Cache() *btf.Cache {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current()
}

func (b *btfBurst) current() *btf.Cache {
	if b.cache == nil {
		b.cache = btf.NewCache()
	}
	return b.cache
}

// Renew replaces the burst's cache with an empty one, for a load that must
// see a module loaded since the cache listed them. The replaced cache is
// not retained.
func (b *btfBurst) Renew() *btf.Cache {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reset()
	return b.current()
}

// CacheFor returns the burst's cache for a load that relocates against, or
// attaches to, module. A cache lists the kernel's modules once, the first
// time it relocates a load, so a module that loaded since (nfs, on the
// node's first NFS mount) is seen only through a fresh cache, which replaces
// the burst's.
func (b *btfBurst) CacheFor(log *slog.Logger, module string) *btf.Cache {
	cache := b.Cache()
	if !moduleBTFExists(module) {
		return cache
	}
	modules, err := cache.Modules()
	if err != nil || slices.Contains(modules, module) {
		return cache
	}
	log.Debug("kernel module loaded after the BTF cache was filled; parsing the kernel BTF again", "module", module)
	return b.Renew()
}

// Release ends the burst: its cache, and every BTF parsed into it, is
// dropped, and the next load parses what it needs again.
func (b *btfBurst) Release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cache == nil {
		return
	}
	b.reset()
	if b.onRelease != nil {
		b.onRelease()
	}
}

func (b *btfBurst) reset() {
	b.cache, b.parsed, b.broken = nil, false, nil
}

// btfParseTimes is how long parsing the kernel BTF took, and the BTF of
// its loaded modules.
type btfParseTimes struct {
	kernel, modules time.Duration
	moduleCount     int
}

// Parse parses the kernel BTF and the BTF of every loaded module into the
// burst's cache, and returns how long that took. The first CO-RE load of a
// burst parses all of them anyway, as cilium relocates against every loaded
// module; parsing them here times it, and finds the modules whose BTF cannot
// be parsed once per burst. ok is false when the cache was parsed already.
func (b *btfBurst) Parse() (times btfParseTimes, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cache := b.current()
	if b.parsed {
		return btfParseTimes{}, false
	}
	b.parsed = true
	b.parses++

	start := time.Now()
	_, err := cache.Kernel()
	times.kernel = time.Since(start)
	if err != nil {
		return times, true
	}
	modules, err := cache.Modules()
	if err != nil {
		return times, true
	}
	start = time.Now()
	for _, module := range modules {
		// cilium keeps no failed parse: remember it for the burst.
		if _, err := cache.Module(module); err != nil {
			b.broken = append(b.broken, module)
		}
	}
	times.modules = time.Since(start)
	times.moduleCount = len(modules)
	return times, true
}

// ModuleBTFBroken reports whether the BTF of module, or of any loaded module
// when module is empty, cannot be parsed. The modules are parsed once per
// burst.
func (b *btfBurst) ModuleBTFBroken(module string) bool {
	b.Parse()
	b.mu.Lock()
	defer b.mu.Unlock()
	if module == "" {
		return len(b.broken) > 0
	}
	return slices.Contains(b.broken, module)
}

// kernelBTF returns the kernel's BTF, or nil when it has none: expected on
// RHEL8-family kernels, where fentryCapable is then false for every symbol
// and the filesystems attach through kprobes instead.
func kernelBTF() *btf.Spec {
	spec, err := kernelBTFCache.Cache().Kernel()
	if err != nil {
		return nil
	}
	return spec
}

// blockRawTracepointCapableWith reports whether the block raw tracepoints can
// decode a request on a kernel with this BTF. They read the device from the
// request's gendisk, which is struct request.rq_disk before 5.15 and
// struct request_queue.disk from there on; a kernel whose BTF shows neither,
// or has no usable BTF at all as on RHEL8, takes the classic tracepoints
// instead, and those need tracefs mounted in.
func blockRawTracepointCapableWith(spec *btf.Spec) bool {
	if spec == nil {
		return false
	}
	return memberPointsToStruct(spec, "request_queue", "disk", "gendisk") ||
		memberPointsToStruct(spec, "request", "rq_disk", "gendisk")
}

// memberPointsToStruct reports whether struct typ in spec has a member named
// member whose type is a pointer to struct target.
func memberPointsToStruct(spec *btf.Spec, typ, member, target string) bool {
	var st *btf.Struct
	if err := spec.TypeByName(typ, &st); err != nil {
		return false
	}
	for _, m := range st.Members {
		if m.Name != member {
			continue
		}
		ptr, ok := btf.UnderlyingType(m.Type).(*btf.Pointer)
		if !ok {
			return false
		}
		pointee, ok := btf.UnderlyingType(ptr.Target).(*btf.Struct)
		return ok && pointee.Name == target
	}
	return false
}

// fentryCapable reports whether fentry/fexit can attach to sym in module.
// A built-in filesystem such as ext4, xfs or btrfs has no
// /sys/kernel/btf/<module> of its own (moduleBTFExists is false), but its
// symbols still live in the kernel's own BTF (vmlinux) whenever BTF is
// enabled at all, so fentry is still valid there. When the module has its own
// BTF, the directory existing is not enough: a static function can be
// missing from it even though other functions of the same module are there
// -- CIFS's cache=loose read_iter and write_iter are static and absent from
// the lab's cifs module BTF, while its other eight read/write/fsync symbols
// are present (2.4, step 12) -- so the symbol is looked up by name. A module
// BTF that cannot be parsed falls back to assuming capable, as before this
// per-symbol check existed, and lets the load itself be the final word.
func fentryCapable(module, sym string) bool {
	if moduleBTFExists(module) {
		spec, err := kernelBTFCache.Cache().Module(module)
		if err != nil {
			return true
		}
		return symbolInSpec(spec, sym)
	}

	spec := kernelBTF()
	if spec == nil {
		return false
	}
	return symbolInSpec(spec, sym)
}

// symbolInSpec reports whether spec declares a function named sym.
func symbolInSpec(spec *btf.Spec, sym string) bool {
	var fn *btf.Func
	return spec.TypeByName(sym, &fn) == nil
}

// probeableAmong returns which of wanted can be probed, reading the symbol
// table once: kallsyms alone runs to hundreds of thousands of lines. tracefs
// is authoritative but root-only, so fall back to kallsyms when it cannot be
// read.
func probeableAmong(wanted map[string]bool) map[string]bool {
	if found, err := scanSymbols(tracefsAvailableFuncs, 0, wanted); err == nil {
		return found
	}
	found, _ := scanSymbols(procKallsyms, 2, wanted)
	return found
}

// scanSymbols returns the members of wanted named in the whitespace-separated
// column col of path's lines.
func scanSymbols(path string, col int, wanted map[string]bool) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	found := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > col && wanted[fields[col]] {
			found[fields[col]] = true
		}
	}
	return found, sc.Err()
}

// symbolResolver returns a resolver that picks the first probeable candidate
// among the symbols of targets, from a single read of the symbol table.
func symbolResolver(targets []fsTarget) func([]string) (string, bool) {
	wanted := map[string]bool{}
	for _, tgt := range targets {
		for _, syms := range [][]string{tgt.ReadSyms, tgt.WriteSyms, tgt.FsyncSyms, tgt.SpliceReadSyms} {
			for _, sym := range syms {
				wanted[sym] = true
			}
		}
	}
	found := probeableAmong(wanted)
	return func(candidates []string) (string, bool) {
		for _, sym := range candidates {
			if found[sym] {
				return sym, true
			}
		}
		return "", false
	}
}

// resolveFsSymbol returns the first candidate that is actually probeable.
func resolveFsSymbol(candidates []string) (string, bool) {
	return symbolResolver([]fsTarget{{ReadSyms: candidates}})(candidates)
}

// moduleLoaded reports whether a kernel module is loaded. A filesystem built
// into the kernel is there from boot, so it can only be missing at startup
// if it is a module that loads later.
func moduleLoaded(module string) bool {
	_, err := os.Stat(filepath.Join(sysModuleDir, module))
	return err == nil
}

type fsAttachPlan struct {
	Fs FsTypeCode
	// Variant is tgt.Variant of the fsTarget the plan was built from.
	Variant string
	// Module is the kernel module the filesystem lives in, or is named after
	// when built in.
	Module    string
	UseFentry bool
	ReadSym   string
	WriteSym  string
	FsyncSym  string
	// SpliceReadSym is empty when the filesystem has no dedicated symbol, or
	// the symbol is not probeable. Read and write still attach.
	SpliceReadSym string
}

// Key identifies the plan's attachment among the attacher's state: one
// filesystem, or for CIFS one cache= variant of it.
func (p fsAttachPlan) Key() fsPlanKey { return fsPlanKey{Fs: p.Fs, Variant: p.Variant} }

// fsPlanKey identifies one filesystem attachment. Every filesystem but CIFS
// has at most one live attachment at a time, keyed by Fs alone (Variant
// empty); CIFS attaches its cache=strict, cache=loose and cache=none
// variants side by side, as independent collections that load, fail, retry
// and fall back to kprobes on their own (2.4, step 12).
type fsPlanKey struct {
	Fs      FsTypeCode
	Variant string
}

// fsTargetFor returns the fsTarget key was planned from, or a zero fsTarget
// if none matches: used to look up a plan key's candidate symbols when a
// sibling claims a shared fsync symbol it did not plan for (2.4, step 12
// review fix).
func fsTargetFor(key fsPlanKey) fsTarget {
	for _, tgt := range fsTargets {
		if tgt.Key() == key {
			return tgt
		}
	}
	return fsTarget{}
}

// planFsAttachWith decides, per filesystem, whether to attach fentry/fexit or
// classic kprobes, or to skip the filesystem entirely. Detection is per
// filesystem rather than global: a node commonly has nfs loaded and ceph not.
// Fsync is resolved independently of read/write: when none of its candidates
// are probeable, FsyncSym is left empty and the caller disables only the
// fsync programs, keeping read/write attached.
func planFsAttachWith(
	targets []fsTarget,
	fentryCapable func(module, sym string) bool,
	resolve func([]string) (string, bool),
) []fsAttachPlan {
	plans := make([]fsAttachPlan, 0, len(targets))
	for _, tgt := range targets {
		readSym, readOK := resolve(tgt.ReadSyms)
		writeSym, writeOK := resolve(tgt.WriteSyms)
		if !readOK || !writeOK {
			continue
		}
		fsyncSym, _ := resolve(tgt.FsyncSyms)
		spliceReadSym, _ := resolve(tgt.SpliceReadSyms)
		plans = append(plans, fsAttachPlan{
			Fs:            tgt.Fs,
			Variant:       tgt.Variant,
			Module:        tgt.Module,
			UseFentry:     fentryCapable(tgt.Module, readSym),
			ReadSym:       readSym,
			WriteSym:      writeSym,
			FsyncSym:      fsyncSym,
			SpliceReadSym: spliceReadSym,
		})
	}
	dedupeSharedFsync(plans)
	return plans
}

// dedupeSharedFsync clears FsyncSym on every plan after the first whose
// FsyncSym names a function another plan already attaches. CIFS's
// cache=loose and cache=none variants both call cifs_fsync; it must be
// probed once, not twice, or every fsync would be counted by both (2.4,
// step 12).
func dedupeSharedFsync(plans []fsAttachPlan) {
	seen := map[string]bool{}
	for i := range plans {
		sym := plans[i].FsyncSym
		if sym == "" {
			continue
		}
		if seen[sym] {
			plans[i].FsyncSym = ""
			continue
		}
		seen[sym] = true
	}
}

func planFsAttach() []fsAttachPlan {
	return planFsTargets(fsTargets)
}

// planFsTargets plans targets from a single read of the symbol table.
func planFsTargets(targets []fsTarget) []fsAttachPlan {
	return planFsAttachWith(targets, fentryCapable, symbolResolver(targets))
}
