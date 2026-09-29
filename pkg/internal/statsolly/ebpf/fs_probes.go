// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Variables rather than constants so tests can point them at fixtures.
var (
	sysKernelBTFDir       = "/sys/kernel/btf"
	tracefsAvailableFuncs = "/sys/kernel/tracing/available_filter_functions"
	procKallsyms          = "/proc/kallsyms"
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
}

var fsTargets = []fsTarget{
	{Fs: CodeFsNFS, Module: "nfs",
		ReadSyms:  []string{"nfs_file_read"},
		WriteSyms: []string{"nfs_file_write"},
		FsyncSyms: []string{"nfs_file_fsync"}},
	{Fs: CodeFsCeph, Module: "ceph",
		ReadSyms:  []string{"ceph_read_iter"},
		WriteSyms: []string{"ceph_write_iter"},
		FsyncSyms: []string{"ceph_fsync"}},
	{Fs: CodeFsCIFS, Module: "cifs",
		ReadSyms:  []string{"cifs_strict_readv", "cifs_loose_read_iter"},
		WriteSyms: []string{"cifs_strict_writev", "cifs_file_write_iter"},
		FsyncSyms: []string{"cifs_strict_fsync", "cifs_fsync"}},
	{Fs: CodeFsFUSE, Module: "fuse",
		ReadSyms:  []string{"fuse_file_read_iter"},
		WriteSyms: []string{"fuse_file_write_iter"},
		FsyncSyms: []string{"fuse_fsync"}},
}

// moduleBTFExists reports whether the kernel exposes BTF for a module, which is
// a precondition for attaching fentry/fexit to a function inside it. Absent on
// RHEL8-family kernels, which lack CONFIG_DEBUG_INFO_BTF_MODULES.
func moduleBTFExists(mod string) bool {
	_, err := os.Stat(filepath.Join(sysKernelBTFDir, mod))
	return err == nil
}

// kprobeExists reports whether a symbol can be probed. tracefs is authoritative
// but root-only, so fall back to kallsyms when it cannot be read.
func kprobeExists(sym string) bool {
	if found, err := symbolInTracefs(sym); err == nil {
		return found
	}
	return symbolInKallsyms(sym)
}

func symbolInTracefs(sym string) (bool, error) {
	f, err := os.Open(tracefsAvailableFuncs)
	if err != nil {
		return false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, _, _ := strings.Cut(sc.Text(), " ")
		if name == sym {
			return true, nil
		}
	}
	return false, sc.Err()
}

func symbolInKallsyms(sym string) bool {
	f, err := os.Open(procKallsyms)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 3 && fields[2] == sym {
			return true
		}
	}
	return false
}

// resolveFsSymbol returns the first candidate that is actually probeable.
func resolveFsSymbol(candidates []string) (string, bool) {
	for _, sym := range candidates {
		if kprobeExists(sym) {
			return sym, true
		}
	}
	return "", false
}

type fsAttachPlan struct {
	Fs        FsTypeCode
	UseFentry bool
	ReadSym   string
	WriteSym  string
	FsyncSym  string
}

// planFsAttachWith decides, per filesystem, whether to attach fentry/fexit or
// classic kprobes, or to skip the filesystem entirely. Detection is per
// filesystem rather than global: a node commonly has nfs loaded and ceph not.
// Fsync is resolved independently of read/write: when none of its candidates
// are probeable, FsyncSym is left empty and the caller disables only the
// fsync programs, keeping read/write attached.
func planFsAttachWith(
	targets []fsTarget,
	moduleBTF func(string) bool,
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
		plans = append(plans, fsAttachPlan{
			Fs:        tgt.Fs,
			UseFentry: moduleBTF(tgt.Module),
			ReadSym:   readSym,
			WriteSym:  writeSym,
			FsyncSym:  fsyncSym,
		})
	}
	return plans
}

func planFsAttach() []fsAttachPlan {
	return planFsAttachWith(fsTargets, moduleBTFExists, resolveFsSymbol)
}
