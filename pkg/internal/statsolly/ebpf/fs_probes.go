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
}

var fsTargets = []fsTarget{
	{Fs: CodeFsNFS, Module: "nfs",
		ReadSyms:  []string{"nfs_file_read"},
		WriteSyms: []string{"nfs_file_write"}},
	{Fs: CodeFsCeph, Module: "ceph",
		ReadSyms:  []string{"ceph_read_iter"},
		WriteSyms: []string{"ceph_write_iter"}},
	{Fs: CodeFsCIFS, Module: "cifs",
		ReadSyms:  []string{"cifs_loose_read_iter", "cifs_strict_readv"},
		WriteSyms: []string{"cifs_file_write_iter", "cifs_strict_writev"}},
	{Fs: CodeFsFUSE, Module: "fuse",
		ReadSyms:  []string{"fuse_file_read_iter"},
		WriteSyms: []string{"fuse_file_write_iter"}},
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
}

// planFsAttachWith decides, per filesystem, whether to attach fentry/fexit or
// classic kprobes, or to skip the filesystem entirely. Detection is per
// filesystem rather than global: a node commonly has nfs loaded and ceph not.
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
		plans = append(plans, fsAttachPlan{
			Fs:        tgt.Fs,
			UseFentry: moduleBTF(tgt.Module),
			ReadSym:   readSym,
			WriteSym:  writeSym,
		})
	}
	return plans
}

func planFsAttach() []fsAttachPlan {
	return planFsAttachWith(fsTargets, moduleBTFExists, resolveFsSymbol)
}
