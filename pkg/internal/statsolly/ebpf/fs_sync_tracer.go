// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

// Step 14 (storage_fs_sync): sync(2), syncfs(2) and sync_file_range(2)
// attach at their syscall wrappers rather than at a filesystem's own
// file_operations, so they are not per-filesystem: one attachment covers
// every filesystem's calls, resolved once at startup (unlike the per-fs
// probes, the set of syscall wrappers a kernel exposes does not change at
// run time, so it is never re-planned on the fsAttacher's 30 s tick).

// Program names of the FsIo object's sync syscall probes.
const (
	progObiStatsFentrySyncfs    = "obi_stats_fentry_syncfs"
	progObiStatsFexitSyncfs     = "obi_stats_fexit_syncfs"
	progObiStatsKprobeSyncfs    = "obi_stats_kprobe_syncfs"
	progObiStatsKretprobeSyncfs = "obi_stats_kretprobe_syncfs"

	progObiStatsFentrySyncFileRange    = "obi_stats_fentry_sync_file_range"
	progObiStatsFexitSyncFileRange     = "obi_stats_fexit_sync_file_range"
	progObiStatsKprobeSyncFileRange    = "obi_stats_kprobe_sync_file_range"
	progObiStatsKretprobeSyncFileRange = "obi_stats_kretprobe_sync_file_range"

	progObiStatsKprobeSync    = "obi_stats_kprobe_sync"
	progObiStatsKretprobeSync = "obi_stats_kretprobe_sync"
)

// fsSyncPlan is which sync syscalls are probeable on this kernel, and
// whether fentry/fexit can be used for syncfs and sync_file_range. sync(2)
// has no fentry variant (2.4): el9 has no BTF for its wrapper.
type fsSyncPlan struct {
	SyncfsSym              string
	UseFentrySyncfs        bool
	SyncFileRangeSym       string
	UseFentrySyncFileRange bool
	SyncSym                string
}

// syscallWrapperPrefix is the goarch-specific prefix of a syscall wrapper
// symbol (__x64_sys_*, __arm64_sys_*): wrapper names come from
// runtime.GOARCH (2.4), not from a kernel-reported convention.
func syscallWrapperPrefix(goarch string) string {
	if goarch == "arm64" {
		return "__arm64_sys_"
	}
	return "__x64_sys_"
}

// syscallFentryCapable reports whether fentry/fexit can attach to sym: it
// lives in vmlinux BTF, never in a module's, so unlike fentryCapable
// (fs_probes.go) there is no module BTF to prefer or that can be broken.
func syscallFentryCapable(sym string) bool {
	spec := kernelBTF()
	if spec == nil {
		return false
	}
	return symbolInSpec(spec, sym)
}

// syncBody is the arch-independent body of sync(2), the fallback probe target
// where the wrapper is in kallsyms but not in tracefs' traceable functions
// (Fedora 7.2 here: __x64_sys_sync is a bare tail call, so ftrace skips it and
// a kprobe on it fails). Only the syscall calls it, unlike ksys_sync, which
// reboot and emergency sync reach from kernel threads (2.4).
const syncBody = "__do_sys_sync"

// planFsSync resolves the sync syscalls this kernel can probe, from one read
// of the symbol table.
func planFsSync() fsSyncPlan {
	return planFsSyncWith(runtime.GOARCH, probeableAmong, syscallFentryCapable)
}

// planFsSyncWith is planFsSync with its dependencies injected, for tests
// that cannot read the real symbol table or BTF, and that must force a
// GOARCH other than the one running the test (arm64 naming, 2.4).
func planFsSyncWith(
	goarch string,
	probeable func(map[string]bool) map[string]bool,
	fentryCapable func(string) bool,
) fsSyncPlan {
	prefix := syscallWrapperPrefix(goarch)
	syncfs, syncFileRange, sync := prefix+"syncfs", prefix+"sync_file_range", prefix+"sync"
	found := probeable(map[string]bool{syncfs: true, syncFileRange: true, sync: true, syncBody: true})

	var plan fsSyncPlan
	if found[syncfs] {
		plan.SyncfsSym = syncfs
		plan.UseFentrySyncfs = fentryCapable(syncfs)
	}
	if found[syncFileRange] {
		plan.SyncFileRangeSym = syncFileRange
		plan.UseFentrySyncFileRange = fentryCapable(syncFileRange)
	}
	switch {
	case found[sync]:
		plan.SyncSym = sync
	case found[syncBody]:
		plan.SyncSym = syncBody
	}
	return plan
}

// fsSyncPlanProbes returns the probes plan needs loaded, in attach order
// (every exit probe before its entry probe, as fsPlanProbes does): every
// syscall's pair, built from the same table attachFsSyncProbes attaches
// from.
func fsSyncPlanProbes(plan fsSyncPlan) []fsProbe {
	var probes []fsProbe
	for _, a := range fsSyncAttaches(plan) {
		probes = append(probes, a.exit, a.entry)
	}
	return probes
}

// verifierFsSyncProbes returns, for the verifier tests, every sync syscall
// probe compiled into the FsIo object (step 14): the kprobe/kretprobe pair
// of sync, syncfs and sync_file_range always, and the fentry/fexit pair of
// syncfs and sync_file_range when kernel is non-nil (mirroring
// verifierFsProbes' no-kernel-BTF branch, where no tracing program is
// kept). sync(2) has no fentry pair at all: 2.4, el9 has no BTF for its
// wrapper. The fentry pair points at the real syscall wrapper when this
// kernel's BTF has it, else at another syscall wrapper of the same
// prototype (a bare "const struct pt_regs *regs"), since a CI kernel might
// be missing the specific symbol (S0-e: arm64 BTF for __arm64_sys_syncfs is
// UNVERIFIED) but every build has some syscall wrapper to stand in.
func verifierFsSyncProbes(kernel *btf.Spec) []fsProbe {
	plan := fsSyncPlan{SyncfsSym: "syncfs", SyncFileRangeSym: "sync_file_range", SyncSym: "sync"}
	probes := fsSyncPlanProbes(plan)
	if kernel == nil {
		return probes
	}

	prefix := syscallWrapperPrefix(runtime.GOARCH)
	inKernel := func(sym string) bool {
		var fn *btf.Func
		return kernel.TypeByName(sym, &fn) == nil
	}
	standIn := func(sym string) string {
		if inKernel(sym) {
			return sym
		}
		return prefix + "getpid"
	}
	fentry := fsSyncPlan{
		SyncfsSym:              standIn(prefix + "syncfs"),
		UseFentrySyncfs:        true,
		SyncFileRangeSym:       standIn(prefix + "sync_file_range"),
		UseFentrySyncFileRange: true,
	}
	return append(probes, fsSyncPlanProbes(fentry)...)
}

// demoteToKprobe returns plan with syncfs and sync_file_range forced to the
// kprobe/kretprobe fallback: the one retry a fentry/fexit load or attach
// error gets before the sync set is given up on (2.4), mirroring the
// per-filesystem fentry -> kprobe re-plan.
func (plan fsSyncPlan) demoteToKprobe() fsSyncPlan {
	plan.UseFentrySyncfs = false
	plan.UseFentrySyncFileRange = false
	return plan
}

// loadFsSync loads plan's chosen programs, sharing the same spec, consts and
// maps as the per-filesystem loads.
func (l *fsLoader) loadFsSync(plan fsSyncPlan) (*ebpf.Collection, error) {
	spec := l.spec.Copy()
	if err := keepFsPrograms(spec, fsSyncPlanProbes(plan)); err != nil {
		return nil, err
	}
	consts := specConstants(spec, l.consts)
	consts[fsTaskBTFConst] = boolConst(l.taskBTF)
	if err := ebpfconvenience.RewriteConstants(spec, consts); err != nil {
		return nil, fmt.Errorf("rewriting sync syscall BPF constants: %w", err)
	}
	opts, err := ebpfconvenience.ResolveMaps(spec, l.sharedMaps, l.mu)
	if err != nil {
		return nil, fmt.Errorf("resolving sync syscall maps: %w", err)
	}
	opts.Programs = ebpf.ProgramOptions{LogSizeStart: fsVerifierLogSize}
	return l.newCollection(spec, *opts)
}

// attachSyncPair attaches one syscall's return probe first, then its entry
// probe, and detaches both if either fails (v2's attachSyncSyscalls,
// stats_tracer.go:445-465): a sync that starts without a working return
// probe would never complete.
func attachSyncPair(log *slog.Logger, programs map[string]*ebpf.Program, fentry bool, entry, exit fsProbe) ([]fsProbe, []io.Closer, error) {
	exitLink, err := attachFsProbe(log, programs[exit.prog], exit, fentry)
	if err != nil {
		return nil, nil, fmt.Errorf("attaching %s to %s: %w", exit.prog, exit.sym, err)
	}
	entryLink, err := attachFsProbe(log, programs[entry.prog], entry, fentry)
	if err != nil {
		exitLink.Close()
		return nil, nil, fmt.Errorf("attaching %s to %s: %w", entry.prog, entry.sym, err)
	}
	return []fsProbe{exit, entry}, []io.Closer{exitLink, entryLink}, nil
}

// fsSyncAttach is one syscall's probe pair to attach, built from plan.
type fsSyncAttach struct {
	name        string
	sym         string
	fentry      bool
	entry, exit fsProbe
}

func fsSyncAttaches(plan fsSyncPlan) []fsSyncAttach {
	var attaches []fsSyncAttach
	if plan.SyncfsSym != "" {
		entry, exit := fsProbe{prog: progObiStatsKprobeSyncfs, sym: plan.SyncfsSym},
			fsProbe{prog: progObiStatsKretprobeSyncfs, sym: plan.SyncfsSym, exit: true}
		if plan.UseFentrySyncfs {
			entry, exit = fsProbe{prog: progObiStatsFentrySyncfs, sym: plan.SyncfsSym},
				fsProbe{prog: progObiStatsFexitSyncfs, sym: plan.SyncfsSym, exit: true}
		}
		attaches = append(attaches, fsSyncAttach{"syncfs", plan.SyncfsSym, plan.UseFentrySyncfs, entry, exit})
	}
	if plan.SyncFileRangeSym != "" {
		entry, exit := fsProbe{prog: progObiStatsKprobeSyncFileRange, sym: plan.SyncFileRangeSym},
			fsProbe{prog: progObiStatsKretprobeSyncFileRange, sym: plan.SyncFileRangeSym, exit: true}
		if plan.UseFentrySyncFileRange {
			entry, exit = fsProbe{prog: progObiStatsFentrySyncFileRange, sym: plan.SyncFileRangeSym},
				fsProbe{prog: progObiStatsFexitSyncFileRange, sym: plan.SyncFileRangeSym, exit: true}
		}
		attaches = append(attaches, fsSyncAttach{"sync_file_range", plan.SyncFileRangeSym, plan.UseFentrySyncFileRange, entry, exit})
	}
	if plan.SyncSym != "" {
		entry := fsProbe{prog: progObiStatsKprobeSync, sym: plan.SyncSym}
		exit := fsProbe{prog: progObiStatsKretprobeSync, sym: plan.SyncSym, exit: true}
		attaches = append(attaches, fsSyncAttach{"sync", plan.SyncSym, false, entry, exit})
	}
	return attaches
}

// attachFsSyncProbes attaches every syscall of plan independently: one
// syscall's probes failing to attach does not stop the others from being
// probed (v2's attachSyncSyscalls skips a syscall silently). fentryFailed
// is set when a fentry/fexit attach failed for a reason that rules out
// fentry/fexit on this kernel, the signal attachSync uses to retry the
// whole set on kprobes once.
func attachFsSyncProbes(log *slog.Logger, programs map[string]*ebpf.Program, plan fsSyncPlan) (probes []fsProbe, links []io.Closer, fentryFailed bool) {
	for _, a := range fsSyncAttaches(plan) {
		ps, ls, err := attachSyncPair(log, programs, a.fentry, a.entry, a.exit)
		if err != nil {
			if a.fentry && fentryUnsupported(err) {
				fentryFailed = true
			}
			log.Warn("sync system call probes failed to attach; skipping this call",
				"syscall", a.name, "symbol", a.sym, "fentry", a.fentry, "error", err)
			continue
		}
		probes = append(probes, ps...)
		links = append(links, ls...)
	}
	return probes, links, fentryFailed
}

// fsSyncAttachment is the sync set's loaded collection and the probes it
// attached. Close detaches entry probes before exit probes, same as
// fsAttachment: a call in flight when its exit probe detaches leaves its
// entry behind, which goes stale on its own (k_fs_start_stale_ns).
type fsSyncAttachment struct {
	coll   *ebpf.Collection
	probes []fsProbe
	links  []io.Closer
	// missed[i] is the kprobe "missed" count links[i] last reported, kept
	// only for kretprobe-mode exit links (pollMissedKretprobes). nil until
	// the first poll.
	missed []uint64
	// hashStarts is set when some attached program keeps its start in the
	// fs_start hash map, which fsAttacher.maintain must then sweep.
	hashStarts bool
}

// syncKeepsHashStarts reports whether any syscall of plan keeps its start
// in fs_start rather than task storage: sync(2) always (a kprobe cannot use
// task storage), syncfs and sync_file_range on kprobes, and every fentry
// program on a kernel without task storage (fs_task_btf clear).
func syncKeepsHashStarts(plan fsSyncPlan, taskBTF bool) bool {
	for _, a := range fsSyncAttaches(plan) {
		if !a.fentry || !taskBTF {
			return true
		}
	}
	return false
}

// pollMissedKretprobes reports the kretprobe misses (kprobe nmissed) the
// kprobe-mode fallback of sync, syncfs and sync_file_range accumulated
// since the last call (2.4, step 14). See fsAttachment.pollMissedKretprobes.
func (a *fsSyncAttachment) pollMissedKretprobes() uint64 {
	if a.missed == nil {
		a.missed = make([]uint64, len(a.links))
	}
	return pollMissedKretprobes(a.probes, a.links, a.missed)
}

func (a *fsSyncAttachment) Close() error {
	var errs []error
	for _, exits := range []bool{false, true} {
		for i, l := range a.links {
			if a.probes[i].exit == exits {
				errs = append(errs, l.Close())
			}
		}
	}
	a.coll.Close()
	return errors.Join(errs...)
}

// errNoSyncProbes is returned when not one sync syscall could be attached:
// every symbol was missing, or every attach failed.
var errNoSyncProbes = errors.New("no sync system call probes could be attached")

// attachSync loads and attaches the sync syscall set. On a fentry/fexit
// load or attach failure that rules out fentry/fexit on this kernel
// (fentryUnsupported, which also matches a verifier rejection of the load),
// it retries once with every syscall on kprobes (2.4); any other
// per-syscall attach failure just skips that syscall (attachFsSyncProbes).
func (l *fsLoader) attachSync(plan fsSyncPlan) (io.Closer, error) {
	usedFentry := plan.UseFentrySyncfs || plan.UseFentrySyncFileRange
	coll, err := l.loadFsSync(plan)
	if err != nil && usedFentry && fentryUnsupported(err) {
		l.log.Info("sync system call fentry/fexit programs are not supported here; retrying with kprobes",
			"error", err)
		plan = plan.demoteToKprobe()
		coll, err = l.loadFsSync(plan)
	}
	if err != nil {
		return nil, fmt.Errorf("loading sync syscall BPF programs: %w", err)
	}

	probes, links, fentryFailed := attachFsSyncProbes(l.log, coll.Programs, plan)
	if fentryFailed {
		closeAll(links)
		coll.Close()
		plan = plan.demoteToKprobe()
		coll, err = l.loadFsSync(plan)
		if err != nil {
			return nil, fmt.Errorf("loading sync syscall BPF programs on kprobes: %w", err)
		}
		l.log.Info("sync system call fentry/fexit probes are not supported here; retrying with kprobes")
		probes, links, _ = attachFsSyncProbes(l.log, coll.Programs, plan)
	}

	if len(probes) == 0 {
		coll.Close()
		return nil, errNoSyncProbes
	}
	for _, a := range fsSyncAttaches(plan) {
		l.log.Info("sync system call probes attached", "syscall", a.name, "symbol", a.sym, "fentry", a.fentry)
	}
	return &fsSyncAttachment{
		coll: coll, probes: probes, links: links,
		hashStarts: syncKeepsHashStarts(plan, l.taskBTF),
	}, nil
}

// fsKretprobeMaxActive bounds the retprobe instances of a kprobe-mode
// filesystem fallback or a sync syscall at once (v2's
// fsSyncRetprobeMaxActive, stats_tracer.go:478): needs tracefs, so
// attachKretprobe falls back to the kernel default (max(10, 2 x CPUs))
// without it.
const fsKretprobeMaxActive = 4096

// fsKretprobeFallbackLogged ensures the maxactive fallback is logged at Info
// once per process (v2 logs every fallback at Debug, step 14 fix): every
// kprobe-mode filesystem fallback and every sync syscall share one tracefs
// limitation, so one log line says enough.
var fsKretprobeFallbackLogged sync.Once

// attachKretprobe attaches a kretprobe that tracks up to fsKretprobeMaxActive
// calls in flight at once, which needs tracefs; without it, the kernel
// default is used and the fallback is logged once.
func attachKretprobe(log *slog.Logger, sym string, prog *ebpf.Program) (link.Link, error) {
	l, err := link.Kretprobe(sym, prog, &link.KprobeOptions{RetprobeMaxActive: fsKretprobeMaxActive})
	if err == nil {
		return l, nil
	}
	fsKretprobeFallbackLogged.Do(func() {
		log.Info("kretprobes cannot request extra instances (tracefs unavailable); "+
			"using the kernel default instead, which may miss returns under load",
			"wanted_max_active", fsKretprobeMaxActive, "error", err)
	})
	return link.Kretprobe(sym, prog, nil)
}
