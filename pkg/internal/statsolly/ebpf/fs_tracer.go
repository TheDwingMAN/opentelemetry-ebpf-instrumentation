// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

// The filesystem programs are an object of their own, apart from the stats
// object: each filesystem loads as a collection containing only its programs,
// whose maps are the PinInternal ones every stats collection shares. A
// filesystem the kernel rejects then disables only itself, and a load copies
// no TCP or block map.
// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type fs_emit_kind -type fs_drop_reason -target $BPF_TARGETS -output-stem stats_fsio FsIo ../../../../bpf/statsolly/fs_io.c -- -I../../../../bpf

// Program names of the FsIo object.
const (
	progObiStatsFentryNFSRead   = "obi_stats_fentry_nfs_read"
	progObiStatsFexitNFSRead    = "obi_stats_fexit_nfs_read"
	progObiStatsFentryNFSWrite  = "obi_stats_fentry_nfs_write"
	progObiStatsFexitNFSWrite   = "obi_stats_fexit_nfs_write"
	progObiStatsFentryNFSFsync  = "obi_stats_fentry_nfs_fsync"
	progObiStatsFexitNFSFsync   = "obi_stats_fexit_nfs_fsync"
	progObiStatsFentryCephRead  = "obi_stats_fentry_ceph_read"
	progObiStatsFexitCephRead   = "obi_stats_fexit_ceph_read"
	progObiStatsFentryCephWrite = "obi_stats_fentry_ceph_write"
	progObiStatsFexitCephWrite  = "obi_stats_fexit_ceph_write"
	progObiStatsFentryCephFsync = "obi_stats_fentry_ceph_fsync"
	progObiStatsFexitCephFsync  = "obi_stats_fexit_ceph_fsync"
	progObiStatsFentryCIFSRead  = "obi_stats_fentry_cifs_read"
	progObiStatsFexitCIFSRead   = "obi_stats_fexit_cifs_read"
	progObiStatsFentryCIFSWrite = "obi_stats_fentry_cifs_write"
	progObiStatsFexitCIFSWrite  = "obi_stats_fexit_cifs_write"
	progObiStatsFentryCIFSFsync = "obi_stats_fentry_cifs_fsync"
	progObiStatsFexitCIFSFsync  = "obi_stats_fexit_cifs_fsync"
	progObiStatsFentryFUSERead  = "obi_stats_fentry_fuse_read"
	progObiStatsFexitFUSERead   = "obi_stats_fexit_fuse_read"
	progObiStatsFentryFUSEWrite = "obi_stats_fentry_fuse_write"
	progObiStatsFexitFUSEWrite  = "obi_stats_fexit_fuse_write"
	progObiStatsFentryFUSEFsync = "obi_stats_fentry_fuse_fsync"
	progObiStatsFexitFUSEFsync  = "obi_stats_fexit_fuse_fsync"

	progObiStatsFentryExt4Read   = "obi_stats_fentry_ext4_read"
	progObiStatsFexitExt4Read    = "obi_stats_fexit_ext4_read"
	progObiStatsFentryExt4Write  = "obi_stats_fentry_ext4_write"
	progObiStatsFexitExt4Write   = "obi_stats_fexit_ext4_write"
	progObiStatsFentryExt4Fsync  = "obi_stats_fentry_ext4_fsync"
	progObiStatsFexitExt4Fsync   = "obi_stats_fexit_ext4_fsync"
	progObiStatsFentryXFSRead    = "obi_stats_fentry_xfs_read"
	progObiStatsFexitXFSRead     = "obi_stats_fexit_xfs_read"
	progObiStatsFentryXFSWrite   = "obi_stats_fentry_xfs_write"
	progObiStatsFexitXFSWrite    = "obi_stats_fexit_xfs_write"
	progObiStatsFentryXFSFsync   = "obi_stats_fentry_xfs_fsync"
	progObiStatsFexitXFSFsync    = "obi_stats_fexit_xfs_fsync"
	progObiStatsFentryBtrfsRead  = "obi_stats_fentry_btrfs_read"
	progObiStatsFexitBtrfsRead   = "obi_stats_fexit_btrfs_read"
	progObiStatsFentryBtrfsWrite = "obi_stats_fentry_btrfs_write"
	progObiStatsFexitBtrfsWrite  = "obi_stats_fexit_btrfs_write"
	progObiStatsFentryBtrfsFsync = "obi_stats_fentry_btrfs_fsync"
	progObiStatsFexitBtrfsFsync  = "obi_stats_fexit_btrfs_fsync"

	progObiStatsKprobeNFSRead        = "obi_stats_kprobe_nfs_read"
	progObiStatsKretprobeNFSRead     = "obi_stats_kretprobe_nfs_read"
	progObiStatsKprobeNFSWrite       = "obi_stats_kprobe_nfs_write"
	progObiStatsKretprobeNFSWrite    = "obi_stats_kretprobe_nfs_write"
	progObiStatsFentrySpliceNFS      = "obi_stats_fentry_nfs_splice_read"
	progObiStatsFexitSpliceNFS       = "obi_stats_fexit_nfs_splice_read"
	progObiStatsKprobeSpliceNFS      = "obi_stats_kprobe_nfs_splice_read"
	progObiStatsKretprobeSpliceNFS   = "obi_stats_kretprobe_nfs_splice_read"
	progObiStatsFentrySpliceFuse     = "obi_stats_fentry_fuse_splice_read"
	progObiStatsFexitSpliceFuse      = "obi_stats_fexit_fuse_splice_read"
	progObiStatsKprobeSpliceFuse     = "obi_stats_kprobe_fuse_splice_read"
	progObiStatsKretprobeSpliceFuse  = "obi_stats_kretprobe_fuse_splice_read"
	progObiStatsFentrySpliceExt4     = "obi_stats_fentry_ext4_splice_read"
	progObiStatsFexitSpliceExt4      = "obi_stats_fexit_ext4_splice_read"
	progObiStatsKprobeSpliceExt4     = "obi_stats_kprobe_ext4_splice_read"
	progObiStatsKretprobeSpliceExt4  = "obi_stats_kretprobe_ext4_splice_read"
	progObiStatsFentrySpliceBtrfs    = "obi_stats_fentry_btrfs_splice_read"
	progObiStatsFexitSpliceBtrfs     = "obi_stats_fexit_btrfs_splice_read"
	progObiStatsKprobeSpliceBtrfs    = "obi_stats_kprobe_btrfs_splice_read"
	progObiStatsKretprobeSpliceBtrfs = "obi_stats_kretprobe_btrfs_splice_read"
	progObiStatsKprobeNFSFsync       = "obi_stats_kprobe_nfs_fsync"
	progObiStatsKretprobeNFSFsync    = "obi_stats_kretprobe_nfs_fsync"
	progObiStatsKprobeCephRead       = "obi_stats_kprobe_ceph_read"
	progObiStatsKretprobeCephRead    = "obi_stats_kretprobe_ceph_read"
	progObiStatsKprobeCephWrite      = "obi_stats_kprobe_ceph_write"
	progObiStatsKretprobeCephWrite   = "obi_stats_kretprobe_ceph_write"
	progObiStatsKprobeCephFsync      = "obi_stats_kprobe_ceph_fsync"
	progObiStatsKretprobeCephFsync   = "obi_stats_kretprobe_ceph_fsync"
	progObiStatsKprobeCIFSRead       = "obi_stats_kprobe_cifs_read"
	progObiStatsKretprobeCIFSRead    = "obi_stats_kretprobe_cifs_read"
	progObiStatsKprobeCIFSWrite      = "obi_stats_kprobe_cifs_write"
	progObiStatsKretprobeCIFSWrite   = "obi_stats_kretprobe_cifs_write"
	progObiStatsKprobeCIFSFsync      = "obi_stats_kprobe_cifs_fsync"
	progObiStatsKretprobeCIFSFsync   = "obi_stats_kretprobe_cifs_fsync"
	progObiStatsKprobeFUSERead       = "obi_stats_kprobe_fuse_read"
	progObiStatsKretprobeFUSERead    = "obi_stats_kretprobe_fuse_read"
	progObiStatsKprobeFUSEWrite      = "obi_stats_kprobe_fuse_write"
	progObiStatsKretprobeFUSEWrite   = "obi_stats_kretprobe_fuse_write"
	progObiStatsKprobeFUSEFsync      = "obi_stats_kprobe_fuse_fsync"
	progObiStatsKretprobeFUSEFsync   = "obi_stats_kretprobe_fuse_fsync"

	progObiStatsKprobeExt4Read      = "obi_stats_kprobe_ext4_read"
	progObiStatsKretprobeExt4Read   = "obi_stats_kretprobe_ext4_read"
	progObiStatsKprobeExt4Write     = "obi_stats_kprobe_ext4_write"
	progObiStatsKretprobeExt4Write  = "obi_stats_kretprobe_ext4_write"
	progObiStatsKprobeExt4Fsync     = "obi_stats_kprobe_ext4_fsync"
	progObiStatsKretprobeExt4Fsync  = "obi_stats_kretprobe_ext4_fsync"
	progObiStatsKprobeXFSRead       = "obi_stats_kprobe_xfs_read"
	progObiStatsKretprobeXFSRead    = "obi_stats_kretprobe_xfs_read"
	progObiStatsKprobeXFSWrite      = "obi_stats_kprobe_xfs_write"
	progObiStatsKretprobeXFSWrite   = "obi_stats_kretprobe_xfs_write"
	progObiStatsKprobeXFSFsync      = "obi_stats_kprobe_xfs_fsync"
	progObiStatsKretprobeXFSFsync   = "obi_stats_kretprobe_xfs_fsync"
	progObiStatsKprobeBtrfsRead     = "obi_stats_kprobe_btrfs_read"
	progObiStatsKretprobeBtrfsRead  = "obi_stats_kretprobe_btrfs_read"
	progObiStatsKprobeBtrfsWrite    = "obi_stats_kprobe_btrfs_write"
	progObiStatsKretprobeBtrfsWrite = "obi_stats_kretprobe_btrfs_write"
	progObiStatsKprobeBtrfsFsync    = "obi_stats_kprobe_btrfs_fsync"
	progObiStatsKretprobeBtrfsFsync = "obi_stats_kretprobe_btrfs_fsync"
)

// fsProgramNames names the twelve programs -- fentry read/write/fsync, fexit
// read/write/fsync, kprobe read/write/fsync, kretprobe read/write/fsync --
// available for one filesystem.
type fsProgramNames struct {
	FentryRead, FexitRead       string
	FentryWrite, FexitWrite     string
	FentryFsync, FexitFsync     string
	KprobeRead, KretprobeRead   string
	KprobeWrite, KretprobeWrite string
	KprobeFsync, KretprobeFsync string
	// Empty for filesystems without a dedicated splice_read symbol.
	FentrySpliceRead, FexitSpliceRead     string
	KprobeSpliceRead, KretprobeSpliceRead string
}

func fsProgNamesFor(fs FsTypeCode) fsProgramNames {
	switch fs {
	case CodeFsNFS:
		return fsProgramNames{
			FentryRead: progObiStatsFentryNFSRead, FexitRead: progObiStatsFexitNFSRead,
			FentryWrite: progObiStatsFentryNFSWrite, FexitWrite: progObiStatsFexitNFSWrite,
			FentryFsync: progObiStatsFentryNFSFsync, FexitFsync: progObiStatsFexitNFSFsync,
			KprobeRead: progObiStatsKprobeNFSRead, KretprobeRead: progObiStatsKretprobeNFSRead,
			KprobeWrite: progObiStatsKprobeNFSWrite, KretprobeWrite: progObiStatsKretprobeNFSWrite,
			KprobeFsync: progObiStatsKprobeNFSFsync, KretprobeFsync: progObiStatsKretprobeNFSFsync,
			FentrySpliceRead: progObiStatsFentrySpliceNFS, FexitSpliceRead: progObiStatsFexitSpliceNFS,
			KprobeSpliceRead: progObiStatsKprobeSpliceNFS, KretprobeSpliceRead: progObiStatsKretprobeSpliceNFS,
		}
	case CodeFsCeph:
		return fsProgramNames{
			FentryRead: progObiStatsFentryCephRead, FexitRead: progObiStatsFexitCephRead,
			FentryWrite: progObiStatsFentryCephWrite, FexitWrite: progObiStatsFexitCephWrite,
			FentryFsync: progObiStatsFentryCephFsync, FexitFsync: progObiStatsFexitCephFsync,
			KprobeRead: progObiStatsKprobeCephRead, KretprobeRead: progObiStatsKretprobeCephRead,
			KprobeWrite: progObiStatsKprobeCephWrite, KretprobeWrite: progObiStatsKretprobeCephWrite,
			KprobeFsync: progObiStatsKprobeCephFsync, KretprobeFsync: progObiStatsKretprobeCephFsync,
		}
	case CodeFsCIFS:
		return fsProgramNames{
			FentryRead: progObiStatsFentryCIFSRead, FexitRead: progObiStatsFexitCIFSRead,
			FentryWrite: progObiStatsFentryCIFSWrite, FexitWrite: progObiStatsFexitCIFSWrite,
			FentryFsync: progObiStatsFentryCIFSFsync, FexitFsync: progObiStatsFexitCIFSFsync,
			KprobeRead: progObiStatsKprobeCIFSRead, KretprobeRead: progObiStatsKretprobeCIFSRead,
			KprobeWrite: progObiStatsKprobeCIFSWrite, KretprobeWrite: progObiStatsKretprobeCIFSWrite,
			KprobeFsync: progObiStatsKprobeCIFSFsync, KretprobeFsync: progObiStatsKretprobeCIFSFsync,
		}
	case CodeFsFUSE:
		return fsProgramNames{
			FentryRead: progObiStatsFentryFUSERead, FexitRead: progObiStatsFexitFUSERead,
			FentryWrite: progObiStatsFentryFUSEWrite, FexitWrite: progObiStatsFexitFUSEWrite,
			FentryFsync: progObiStatsFentryFUSEFsync, FexitFsync: progObiStatsFexitFUSEFsync,
			KprobeRead: progObiStatsKprobeFUSERead, KretprobeRead: progObiStatsKretprobeFUSERead,
			KprobeWrite: progObiStatsKprobeFUSEWrite, KretprobeWrite: progObiStatsKretprobeFUSEWrite,
			KprobeFsync: progObiStatsKprobeFUSEFsync, KretprobeFsync: progObiStatsKretprobeFUSEFsync,
			FentrySpliceRead: progObiStatsFentrySpliceFuse, FexitSpliceRead: progObiStatsFexitSpliceFuse,
			KprobeSpliceRead: progObiStatsKprobeSpliceFuse, KretprobeSpliceRead: progObiStatsKretprobeSpliceFuse,
		}
	case CodeFsExt4:
		return fsProgramNames{
			FentryRead: progObiStatsFentryExt4Read, FexitRead: progObiStatsFexitExt4Read,
			FentryWrite: progObiStatsFentryExt4Write, FexitWrite: progObiStatsFexitExt4Write,
			FentryFsync: progObiStatsFentryExt4Fsync, FexitFsync: progObiStatsFexitExt4Fsync,
			KprobeRead: progObiStatsKprobeExt4Read, KretprobeRead: progObiStatsKretprobeExt4Read,
			KprobeWrite: progObiStatsKprobeExt4Write, KretprobeWrite: progObiStatsKretprobeExt4Write,
			KprobeFsync: progObiStatsKprobeExt4Fsync, KretprobeFsync: progObiStatsKretprobeExt4Fsync,
			FentrySpliceRead: progObiStatsFentrySpliceExt4, FexitSpliceRead: progObiStatsFexitSpliceExt4,
			KprobeSpliceRead: progObiStatsKprobeSpliceExt4, KretprobeSpliceRead: progObiStatsKretprobeSpliceExt4,
		}
	case CodeFsXFS:
		return fsProgramNames{
			FentryRead: progObiStatsFentryXFSRead, FexitRead: progObiStatsFexitXFSRead,
			FentryWrite: progObiStatsFentryXFSWrite, FexitWrite: progObiStatsFexitXFSWrite,
			FentryFsync: progObiStatsFentryXFSFsync, FexitFsync: progObiStatsFexitXFSFsync,
			KprobeRead: progObiStatsKprobeXFSRead, KretprobeRead: progObiStatsKretprobeXFSRead,
			KprobeWrite: progObiStatsKprobeXFSWrite, KretprobeWrite: progObiStatsKretprobeXFSWrite,
			KprobeFsync: progObiStatsKprobeXFSFsync, KretprobeFsync: progObiStatsKretprobeXFSFsync,
		}
	case CodeFsBtrfs:
		return fsProgramNames{
			FentryRead: progObiStatsFentryBtrfsRead, FexitRead: progObiStatsFexitBtrfsRead,
			FentryWrite: progObiStatsFentryBtrfsWrite, FexitWrite: progObiStatsFexitBtrfsWrite,
			FentryFsync: progObiStatsFentryBtrfsFsync, FexitFsync: progObiStatsFexitBtrfsFsync,
			KprobeRead: progObiStatsKprobeBtrfsRead, KretprobeRead: progObiStatsKretprobeBtrfsRead,
			KprobeWrite: progObiStatsKprobeBtrfsWrite, KretprobeWrite: progObiStatsKretprobeBtrfsWrite,
			KprobeFsync: progObiStatsKprobeBtrfsFsync, KretprobeFsync: progObiStatsKretprobeBtrfsFsync,
			FentrySpliceRead: progObiStatsFentrySpliceBtrfs, FexitSpliceRead: progObiStatsFexitSpliceBtrfs,
			KprobeSpliceRead: progObiStatsKprobeSpliceBtrfs, KretprobeSpliceRead: progObiStatsKretprobeSpliceBtrfs,
		}
	default:
		return fsProgramNames{}
	}
}

// fsProbe is one program of a filesystem's attach plan: the program name in
// the FsIo object and the kernel function it attaches to.
type fsProbe struct {
	prog string
	sym  string
	// exit is set for fexit and kretprobe programs.
	exit bool
}

// fsPlanProbes returns the probes of plan in attach order. Every exit probe
// comes before its entry probe: a call that enters between the two would
// otherwise record a start whose exit never runs.
func fsPlanProbes(plan fsAttachPlan) []fsProbe {
	names := fsProgNamesFor(plan.Fs)
	ops := []struct {
		sym, fentry, fexit, kprobe, kretprobe string
	}{
		{plan.ReadSym, names.FentryRead, names.FexitRead, names.KprobeRead, names.KretprobeRead},
		{plan.WriteSym, names.FentryWrite, names.FexitWrite, names.KprobeWrite, names.KretprobeWrite},
		// Empty FsyncSym or SpliceReadSym: nothing probeable, read and write
		// still attach.
		{plan.FsyncSym, names.FentryFsync, names.FexitFsync, names.KprobeFsync, names.KretprobeFsync},
		{plan.SpliceReadSym, names.FentrySpliceRead, names.FexitSpliceRead, names.KprobeSpliceRead, names.KretprobeSpliceRead},
	}

	var probes []fsProbe
	for _, op := range ops {
		if op.sym == "" {
			continue
		}
		entry, exit := op.kprobe, op.kretprobe
		if plan.UseFentry {
			entry, exit = op.fentry, op.fexit
		}
		probes = append(probes, fsProbe{prog: exit, sym: op.sym, exit: true}, fsProbe{prog: entry, sym: op.sym})
	}
	return probes
}

// keepFsPrograms removes from spec every program no probe uses, so that a
// load creates only those, and points the fentry/fexit ones at their kernel
// function: the kernel checks a tracing program against its target at load
// time.
func keepFsPrograms(spec *ebpf.CollectionSpec, probes []fsProbe) error {
	targets := make(map[string]string, len(probes))
	for _, p := range probes {
		if spec.Programs[p.prog] == nil {
			return fmt.Errorf("unknown program name %q", p.prog)
		}
		targets[p.prog] = p.sym
	}

	for name, prog := range spec.Programs {
		sym, keep := targets[name]
		if !keep {
			delete(spec.Programs, name)
			continue
		}
		if prog.Type == ebpf.Tracing {
			prog.AttachTo = sym
		}
	}
	return nil
}

// fsStandIns are vmlinux functions with the prototypes of the filesystem
// operations, first present first, for the fentry/fexit programs of a
// filesystem this kernel cannot point at its own functions. The verifier
// checks a tracing program against its target's prototype only.
var fsStandIns = struct{ read, write, fsync, spliceRead []string }{
	read:       []string{"generic_file_read_iter"},
	write:      []string{"generic_file_write_iter"},
	fsync:      []string{"generic_file_fsync", "noop_fsync"},
	spliceRead: []string{"filemap_splice_read", "generic_file_splice_read"},
}

// verifierFsProbes returns, for the verifier tests, the fentry/fexit and the
// kprobe/kretprobe probes of every filesystem and operation, whichever this
// kernel would plan: a filesystem falls back to kprobes at run time, and a
// CI kernel without a filesystem's module must still verify its programs. A
// tracing program points at the filesystem's own function when plans has it
// on fentry, at a vmlinux stand-in otherwise; with no kernel BTF there is no
// target at all, and only the kprobe programs are kept.
func verifierFsProbes(plans []fsAttachPlan, kernel *btf.Spec) []fsProbe {
	inKernel := func(candidates []string) string {
		for _, sym := range candidates {
			var fn *btf.Func
			if kernel != nil && kernel.TypeByName(sym, &fn) == nil {
				return sym
			}
		}
		return ""
	}
	standIn := fsAttachPlan{
		ReadSym:       inKernel(fsStandIns.read),
		WriteSym:      inKernel(fsStandIns.write),
		FsyncSym:      inKernel(fsStandIns.fsync),
		SpliceReadSym: inKernel(fsStandIns.spliceRead),
	}
	planned := map[fsPlanKey]fsAttachPlan{}
	for _, plan := range plans {
		planned[plan.Key()] = plan
	}
	or := func(sym, standIn string) string {
		if sym != "" {
			return sym
		}
		return standIn
	}

	var probes []fsProbe
	for _, tgt := range fsTargets {
		fentry := standIn
		if plan, ok := planned[tgt.Key()]; ok && plan.UseFentry {
			fentry = fsAttachPlan{
				ReadSym: plan.ReadSym, WriteSym: plan.WriteSym,
				FsyncSym:      or(plan.FsyncSym, standIn.FsyncSym),
				SpliceReadSym: or(plan.SpliceReadSym, standIn.SpliceReadSym),
			}
		}
		fentry.Fs, fentry.UseFentry = tgt.Fs, true
		// A kprobe program is only named here; it takes its function at
		// attach time.
		kprobe := fsAttachPlan{Fs: tgt.Fs, ReadSym: "read", WriteSym: "write", FsyncSym: "fsync", SpliceReadSym: "splice_read"}
		if len(tgt.SpliceReadSyms) == 0 {
			fentry.SpliceReadSym, kprobe.SpliceReadSym = "", ""
		}
		if kernel != nil {
			probes = append(probes, fsPlanProbes(fentry)...)
		}
		probes = append(probes, fsPlanProbes(kprobe)...)
	}
	return append(probes, verifierFsSyncProbes(kernel)...)
}

// fsVerifierLogSize is the initial verifier log buffer of a filesystem load,
// the one ebpfconvenience.LoadSpec uses for every other collection.
const fsVerifierLogSize = 640 * 1024

// fsLoader loads the collection of one filesystem's attach plan. Every load
// shares the PinInternal maps of the stats collection (the event ring
// buffer) and of the other filesystems (the in-flight map, the device
// allowlist), the kernel BTF cache and the load-time constants. It is used
// from one goroutine at a time.
type fsLoader struct {
	log *slog.Logger
	// spec is parsed and sized once; each load works on a copy.
	spec       *ebpf.CollectionSpec
	consts     map[string]any
	sharedMaps map[string]*ebpf.Map
	mu         *sync.Mutex
	btf        *btfBurst
	// taskBTF is fs_task_btf: fentry/fexit programs keep their start in
	// task storage. Cleared for good the first time a load that uses it
	// fails and one without it succeeds.
	taskBTF bool
	// newCollection is ebpf.NewCollectionWithOptions, replaceable in tests
	// that cannot load BPF.
	newCollection func(*ebpf.CollectionSpec, ebpf.CollectionOptions) (*ebpf.Collection, error)
}

func newFsLoader(
	log *slog.Logger, cfg *config.EBPFTracer, consts map[string]any, fsAgg FsAggregation,
	sharedMaps map[string]*ebpf.Map, mu *sync.Mutex,
) (*fsLoader, error) {
	spec, err := LoadFsIo()
	if err != nil {
		return nil, fmt.Errorf("loading filesystem BPF data: %w", err)
	}
	// Sized as the stats collection sizes its maps, or the shared ring
	// buffer it created would not match this spec's.
	ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)
	if err := setMapEntries(spec, fsAccumEntries(fsAgg)); err != nil {
		return nil, fmt.Errorf("sizing filesystem maps: %w", err)
	}

	taskBTF := haveTaskStorage()
	if !taskBTF {
		stubTaskStorage(spec)
	}

	return &fsLoader{
		log:           log,
		spec:          spec,
		consts:        consts,
		sharedMaps:    sharedMaps,
		mu:            mu,
		btf:           kernelBTFCache,
		taskBTF:       taskBTF,
		newCollection: ebpf.NewCollectionWithOptions,
	}, nil
}

// fsAccumEntries sizes the aggregation map not in use, or both in
// per-event mode, at one entry: nothing touches them.
func fsAccumEntries(fsAgg FsAggregation) map[string]uint32 {
	entries := map[string]uint32{}
	switch {
	case !fsAgg.Enabled:
		entries[FsIoMapFsIoAccum] = unusedMapEntries
		entries[FsIoMapFsIoAccumExp] = unusedMapEntries
	case fsAgg.Exponential:
		entries[FsIoMapFsIoAccum] = unusedMapEntries
	default:
		entries[FsIoMapFsIoAccumExp] = unusedMapEntries
	}
	return entries
}

// fsAccumMapName is the aggregation map the programs add into.
func fsAccumMapName(fsAgg FsAggregation) string {
	if fsAgg.Exponential {
		return FsIoMapFsIoAccumExp
	}
	return FsIoMapFsIoAccum
}

// haveTaskStorage reports whether the kernel has task storage maps (5.11).
// Whether tracing programs may use them is only known once one loads.
var haveTaskStorage = func() bool {
	return features.HaveMapType(ebpf.TaskStorage) == nil
}

// stubTaskStorage replaces fs_start_task with a one-entry hash map, for a
// kernel that cannot create task storage: with fs_task_btf clear no program
// reaches it, but every load still creates the maps its programs reference.
func stubTaskStorage(spec *ebpf.CollectionSpec) {
	m := spec.Maps[FsIoMapFsStartTask]
	m.Type = ebpf.Hash
	m.Flags = 0
	m.MaxEntries = unusedMapEntries
}

// sharedMap returns one of the PinInternal maps of the filesystem
// collections, creating them if no filesystem has loaded yet.
func (l *fsLoader) sharedMap(name string) (*ebpf.Map, error) {
	opts, err := ebpfconvenience.ResolveMaps(l.spec.Copy(), l.sharedMaps, l.mu)
	if err != nil {
		return nil, err
	}
	m := opts.MapReplacements[name]
	if m == nil {
		return nil, fmt.Errorf("no shared map %s", name)
	}
	return m, nil
}

// attach loads plan's collection and attaches its probes.
func (l *fsLoader) attach(plan fsAttachPlan) (io.Closer, error) {
	coll, err := l.load(plan)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	starts := l.sharedMaps[FsIoMapFsStart]
	l.mu.Unlock()

	a := &fsAttachment{
		coll:      coll,
		startHash: l.startsInHash(plan),
		// Task storage cannot be walked from userspace; its leftover
		// starts go stale after k_fs_start_stale_ns, or with their thread.
		// fs_start has no variant field (2.4), so this clears every start of
		// plan.Fs: harmless when plan is the only attachment of that Fs, but
		// a failure of one CIFS variant mid-setup, while a sibling variant
		// is already live, can wipe a start the sibling's threads are about
		// to look up -- that in-flight call then loses its one sample, the
		// same degradation an exit probe detaching mid-call already causes
		// (fsAttachment.Close above). Narrow and failure-path-only: left
		// undone pending real-world CIFS traffic to size it (UNVERIFIED,
		// step 12).
		clearStarts: func() error { return clearMapFsStarts(starts, plan.Fs) },
	}
	a.probes, a.links, err = attachFsProbes(l.log, coll.Programs, plan)
	if err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

// startsInHash reports whether plan's programs keep their starts in the
// fs_start hash map rather than in task storage.
func (l *fsLoader) startsInHash(plan fsAttachPlan) bool {
	return !plan.UseFentry || !l.taskBTF
}

func (l *fsLoader) load(plan fsAttachPlan) (*ebpf.Collection, error) {
	coll, err := l.loadOnce(plan)
	if err == nil || !plan.UseFentry || !l.taskBTF {
		return coll, err
	}

	// Task storage for tracing programs came after fentry (5.11 and later):
	// a kernel may run the programs without it.
	l.taskBTF = false
	coll, retryErr := l.loadOnce(plan)
	if retryErr != nil {
		l.taskBTF = true
		return nil, err
	}
	l.log.Info("filesystem fentry/fexit programs cannot use task storage on this kernel;"+
		" their starts go to the fs_start hash map", "fs", fsTypeStr(plan.Fs), "error", err)
	return coll, nil
}

func (l *fsLoader) loadOnce(plan fsAttachPlan) (*ebpf.Collection, error) {
	spec, opts, err := l.prepare(plan)
	if err != nil {
		return nil, err
	}
	coll, err := l.newCollection(spec, opts)
	if err == nil {
		return coll, nil
	}

	// cilium relocates a load against the BTF of every loaded module, so a
	// single module whose BTF cannot be parsed fails every load. Only then,
	// retry against vmlinux and the filesystem's own module.
	kernel, modules, ok := l.relocationTargets(plan.Module)
	if !ok {
		return nil, err
	}
	l.log.Warn("the BTF of a kernel module cannot be parsed; relocating the filesystem probes"+
		" against the kernel and the filesystem's own module only", "fs", fsTypeStr(plan.Fs), "error", err)
	spec, opts, err = l.prepare(plan)
	if err != nil {
		return nil, err
	}
	opts.Programs.KernelTypes = kernel
	opts.Programs.ExtraRelocationTargets = modules
	coll, err = l.newCollection(spec, opts)
	if err != nil && plan.UseFentry {
		// cilium looks the fentry/fexit target up in every loaded module's
		// BTF, the unparsable one included; kprobes need no such lookup.
		return nil, fmt.Errorf("%w: a module's BTF cannot be parsed: %w", errFentryUnsupported, err)
	}
	return coll, err
}

// prepare returns the spec and options of a load of plan's programs.
func (l *fsLoader) prepare(plan fsAttachPlan) (*ebpf.CollectionSpec, ebpf.CollectionOptions, error) {
	spec := l.spec.Copy()
	if err := keepFsPrograms(spec, fsPlanProbes(plan)); err != nil {
		return nil, ebpf.CollectionOptions{}, err
	}
	consts := specConstants(spec, l.consts)
	consts[fsTaskBTFConst] = boolConst(l.taskBTF)
	if err := ebpfconvenience.RewriteConstants(spec, consts); err != nil {
		return nil, ebpf.CollectionOptions{}, fmt.Errorf("rewriting filesystem BPF constants: %w", err)
	}
	opts, err := ebpfconvenience.ResolveMaps(spec, l.sharedMaps, l.mu)
	if err != nil {
		return nil, ebpf.CollectionOptions{}, fmt.Errorf("resolving filesystem maps: %w", err)
	}
	opts.Programs = ebpf.ProgramOptions{LogSizeStart: fsVerifierLogSize}
	opts.Cache = l.cacheFor(plan.Module)
	if times, ok := l.btf.Parse(); ok {
		l.log.Debug("kernel BTF parsed for a filesystem load", "fs", fsTypeStr(plan.Fs),
			"kernel_btf_parse", times.kernel, "module_btf_parse", times.modules, "btf_modules", times.moduleCount)
	}
	return spec, *opts, nil
}

// cacheFor returns the BTF cache for a load of a filesystem in module.
func (l *fsLoader) cacheFor(module string) *btf.Cache {
	return l.btf.CacheFor(l.log, module)
}

// relocationTargets returns the kernel BTF and the BTF of module, when some
// loaded module's BTF cannot be parsed.
func (l *fsLoader) relocationTargets(module string) (*btf.Spec, []*btf.Spec, bool) {
	if !l.btf.ModuleBTFBroken("") {
		return nil, nil, false
	}
	cache := l.btf.Cache()
	kernel, err := cache.Kernel()
	if err != nil {
		return nil, nil, false
	}
	if !moduleBTFExists(module) {
		return kernel, nil, true
	}
	if l.btf.ModuleBTFBroken(module) {
		return nil, nil, false
	}
	spec, err := cache.Module(module)
	if err != nil {
		return nil, nil, false
	}
	return kernel, []*btf.Spec{spec}, true
}

// fsTaskBTFConst names fs_task_btf, the one filesystem constant the loader
// sets rather than statsConstants.
const fsTaskBTFConst = "fs_task_btf"

// fsAttachment is one filesystem's collection and the links of its probes.
type fsAttachment struct {
	coll *ebpf.Collection
	// startHash is set when the programs keep their starts in fs_start.
	startHash bool
	// probes[i] is the probe links[i] attached.
	probes []fsProbe
	links  []io.Closer
	// clearStarts deletes the filesystem's fs_start entries.
	clearStarts func() error
	// missed[i] is the kprobe "missed" count links[i] last reported, kept
	// only for kretprobe-mode exit links (pollMissedKretprobes). nil until
	// the first poll.
	missed []uint64
	// recMiss keeps the recursion misses coll's programs last reported.
	recMiss recursionMisses
}

// pollRecursionMisses reports the recursion misses of the filesystem's programs.
func (a *fsAttachment) pollRecursionMisses(metrics imetrics.Reporter) {
	a.recMiss.poll(a.coll.Programs, metrics)
}

// pollMissedKretprobes reports the kretprobe misses (kprobe nmissed) this
// filesystem's kprobe-mode return probes (the step 3 fentry -> kprobe
// re-plan) accumulated since the last call: new misses since the last poll,
// summed across every return probe. A fentry/fexit attachment reports 0,
// since a tracing link's Info() is not a PerfEvent one.
func (a *fsAttachment) pollMissedKretprobes() uint64 {
	if a.missed == nil {
		a.missed = make([]uint64, len(a.links))
	}
	return pollMissedKretprobes(a.probes, a.links, a.missed)
}

// Close detaches the entry probes, then the exit probes, unloads the
// collection and deletes the fs_start entries the filesystem left. With the
// entry probes gone first, no call records a start after its exit probe is
// gone; but a call in flight when its exit probe detaches -- a kretprobe
// drops its pending returns -- leaves its entry behind, and until that entry
// goes stale it would make every later filesystem call on the thread count
// as nested, and report nothing.
func (a *fsAttachment) Close() error {
	var errs []error
	for _, exits := range []bool{false, true} {
		for i, l := range a.links {
			if a.probes[i].exit == exits {
				errs = append(errs, l.Close())
			}
		}
	}
	a.coll.Close()
	if err := a.clearStarts(); err != nil {
		errs = append(errs, fmt.Errorf("clearing fs_start: %w", err))
	}
	return errors.Join(errs...)
}

// clearMapFsStarts deletes the entries of fs from the fs_start map m.
func clearMapFsStarts(m *ebpf.Map, fs FsTypeCode) error {
	if m == nil {
		return nil
	}
	var (
		id  uint64
		val FsIoFsStartVal
	)
	it := m.Iterate()
	entries := func(yield func(uint64, FsIoFsStartVal) bool) {
		for it.Next(&id, &val) {
			if !yield(id, val) {
				return
			}
		}
	}
	err := clearFsStarts(entries, func(id uint64) error { return m.Delete(id) }, fs)
	return errors.Join(err, it.Err())
}

// clearFsStarts deletes, through del, the fs_start entries of fs among
// entries, which are keyed by pid_tgid. An entry whose call returned in the
// meantime is already gone, which is no error.
func clearFsStarts(entries iter.Seq2[uint64, FsIoFsStartVal], del func(uint64) error, fs FsTypeCode) error {
	var ids []uint64
	for id, val := range entries {
		if FsTypeCode(val.Fs) == fs {
			ids = append(ids, id)
		}
	}
	var errs []error
	for _, id := range ids {
		if err := del(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// StartsInHash reports whether the attachment's programs keep their starts in
// the fs_start hash map, which then needs sweeping.
func (a *fsAttachment) StartsInHash() bool { return a.startHash }

// fsStartMaxAge is how old an fs_start entry must be before the sweep deletes
// it: its thread died mid-call, or its exit probe was lost. The programs
// already treat a start older than k_fs_start_stale_ns (30 s) as an orphan
// on the thread's next call, but only the sweep frees the entry of a thread
// that makes no further call; without it, a node whose threads die inside
// filesystem calls (a hung NFS server, a wedged FUSE daemon) would fill the
// map and stop timing new calls. A call really in flight for this long
// loses its one sample.
const fsStartMaxAge = 10 * time.Minute

// sweepMapFsStarts deletes the entries of the fs_start map m older than
// maxAge at now, a CLOCK_MONOTONIC time as bpf_ktime_get_ns returns it.
func sweepMapFsStarts(m *ebpf.Map, now uint64, maxAge time.Duration) (int, error) {
	var (
		id  uint64
		val FsIoFsStartVal
	)
	it := m.Iterate()
	entries := func(yield func(uint64, FsIoFsStartVal) bool) {
		for it.Next(&id, &val) {
			if !yield(id, val) {
				return
			}
		}
	}
	n, err := sweepFsStarts(entries, func(id uint64) error { return m.Delete(id) }, now, maxAge)
	return n, errors.Join(err, it.Err())
}

// sweepFsStarts deletes, through del, the fs_start entries among entries that
// are older than maxAge at now, and returns how many it deleted.
func sweepFsStarts(
	entries iter.Seq2[uint64, FsIoFsStartVal], del func(uint64) error, now uint64, maxAge time.Duration,
) (int, error) {
	var stale []uint64
	for id, val := range entries {
		if val.Ts != 0 && now > val.Ts && now-val.Ts > uint64(maxAge) {
			stale = append(stale, id)
		}
	}
	var errs []error
	deleted := 0
	for _, id := range stale {
		switch err := del(id); {
		case err == nil:
			deleted++
		case !errors.Is(err, ebpf.ErrKeyNotExist):
			errs = append(errs, err)
		}
	}
	return deleted, errors.Join(errs...)
}

// monotonicNow returns CLOCK_MONOTONIC in nanoseconds, the clock of
// bpf_ktime_get_ns.
func monotonicNow() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Nano())
}

// readFsDrops returns the fs_drops counters, summed across CPUs, indexed by
// enum fs_drop_reason.
func readFsDrops(m *ebpf.Map) ([]uint64, error) {
	drops := make([]uint64, FsIoFsDropReasonFsDropReasons)
	var perCPU []uint64
	for reason := range drops {
		if err := m.Lookup(uint32(reason), &perCPU); err != nil {
			return nil, err
		}
		for _, n := range perCPU {
			drops[reason] += n
		}
	}
	return drops, nil
}

// attachFsProbes attaches plan's probes to the loaded programs, and returns
// the probes it attached and their links. On a failure, those are the ones
// attached before it, for the caller to close.
func attachFsProbes(log *slog.Logger, programs map[string]*ebpf.Program, plan fsAttachPlan) ([]fsProbe, []io.Closer, error) {
	probes := fsPlanProbes(plan)
	links := make([]io.Closer, 0, len(probes))
	for i, p := range probes {
		l, err := attachFsProbe(log, programs[p.prog], p, plan.UseFentry)
		if err != nil {
			return probes[:i], links, fmt.Errorf("attaching %s to %s: %w", p.prog, p.sym, err)
		}
		links = append(links, l)
	}
	return probes, links, nil
}

// attachFsProbe attaches one probe. A kprobe-mode return probe goes through
// attachKretprobe (2.4, step 14): it needs the same RetprobeMaxActive
// headroom as the sync syscalls' kretprobes, for the same reason.
func attachFsProbe(log *slog.Logger, prog *ebpf.Program, p fsProbe, fentry bool) (link.Link, error) {
	if prog == nil {
		return nil, errors.New("program not loaded")
	}
	switch {
	case fentry && p.exit:
		return link.AttachTracing(link.TracingOptions{Program: prog, AttachType: ebpf.AttachTraceFExit})
	case fentry:
		return link.AttachTracing(link.TracingOptions{Program: prog, AttachType: ebpf.AttachTraceFEntry})
	case p.exit:
		return attachKretprobe(log, p.sym, prog)
	default:
		return link.Kprobe(p.sym, prog, nil)
	}
}
