// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
// filesystem. Several filesystems expose more than one symbol per operation --
// CIFS selects between loose and strict variants by the cache= mount option --
// so candidates are tried in order and the first present one wins.
type fsTarget struct {
	Fs        FsTypeCode
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
	{
		Fs: CodeFsCIFS, Module: "cifs",
		ReadSyms:  []string{"cifs_strict_readv", "cifs_loose_read_iter"},
		WriteSyms: []string{"cifs_strict_writev", "cifs_file_write_iter"},
		FsyncSyms: []string{"cifs_strict_fsync", "cifs_fsync"},
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

// kernelBTFSpecOnce/kernelBTFSpec cache the parsed kernel BTF across every
// fentryCapable call: LoadKernelSpec parses the whole vmlinux BTF blob on
// each invocation, and every built-in filesystem probed here (ext4, xfs,
// btrfs) shares this one lookup.
var (
	kernelBTFSpecOnce sync.Once
	kernelBTFSpec     *btf.Spec
)

func kernelBTF() *btf.Spec {
	kernelBTFSpecOnce.Do(func() {
		// Absence of kernel BTF (or an unreadable /sys/kernel/btf/vmlinux) is
		// expected on RHEL8-family kernels; fentryCapable falls back to false
		// for such symbols, and the caller attaches via kprobe instead.
		spec, err := btf.LoadKernelSpec()
		if err == nil {
			kernelBTFSpec = spec
		}
	})
	return kernelBTFSpec
}

// blockRawTracepointCapable reports whether the block raw tracepoints can
// decode a request on this kernel. They read the device from the request's
// gendisk, which is struct request.rq_disk before 5.15 and
// struct request_queue.disk from there on; a kernel whose BTF shows neither,
// or has no usable BTF at all as on RHEL8, takes the classic tracepoints
// instead, and those need tracefs mounted in.
func blockRawTracepointCapable() bool {
	return blockRawTracepointCapableWith(kernelBTF())
}

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
// enabled at all, so fentry is still valid there.
func fentryCapable(module, sym string) bool {
	if moduleBTFExists(module) {
		return true
	}

	spec := kernelBTF()
	if spec == nil {
		return false
	}

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
	Fs        FsTypeCode
	UseFentry bool
	ReadSym   string
	WriteSym  string
	FsyncSym  string
	// SpliceReadSym is empty when the filesystem has no dedicated symbol, or
	// the symbol is not probeable. Read and write still attach.
	SpliceReadSym string
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
			UseFentry:     fentryCapable(tgt.Module, readSym),
			ReadSym:       readSym,
			WriteSym:      writeSym,
			FsyncSym:      fsyncSym,
			SpliceReadSym: spliceReadSym,
		})
	}
	return plans
}

func planFsAttach() []fsAttachPlan {
	return planFsAttachWith(fsTargets, fentryCapable, symbolResolver(fsTargets))
}

// planPendingFsAttach plans only the filesystems not in done whose module is
// loaded. With none of them loaded, as on most ticks, it reads nothing.
func planPendingFsAttach(done map[FsTypeCode]bool) []fsAttachPlan {
	var pending []fsTarget
	for _, tgt := range fsTargets {
		if !done[tgt.Fs] && moduleLoaded(tgt.Module) {
			pending = append(pending, tgt)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	return planFsAttachWith(pending, fentryCapable, symbolResolver(pending))
}
