// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

// fsAttachInterval is how often the attacher looks again at the node: for
// network filesystems whose module has loaded since (nfs, cifs, ceph and
// fuse usually load only when the node mounts its first volume of that type,
// which on a freshly started node comes after OBI), and for kubelet volumes
// of a local filesystem mounted or unmounted since.
const fsAttachInterval = 30 * time.Second

// fsAttachTries bounds how often in a row a filesystem whose probes fail to
// load or attach is tried, one tick apart, before it is left alone until OBI
// restarts. A module still initializing can fail once; a verifier rejection
// fails every time.
const fsAttachTries = 3

// fsDetachAfter is how many refreshes in a row must find no kubelet volume
// of a local filesystem before its probes detach. A volume that is unmounted
// and mounted again within a tick, as when a pod is rescheduled on the node
// or a StatefulSet pod restarts, then keeps its probes instead of paying a
// detach and a load for each move.
const fsDetachAfter = 2

// fsAttacher attaches the probes of each filesystem, as a collection of its
// own, while the filesystem is worth probing:
//   - a network filesystem (nfs, ceph, cifs, fuse) from the moment its module
//     is loaded;
//   - a local filesystem (ext4, xfs, btrfs) only while a kubelet volume of
//     that type is mounted, and until fsDetachAfter refreshes have found none. These also hold the node's root filesystem and
//     every container's writable layer, whose I/O fs_dev_filter keeps out of
//     the metrics; without a volume their probes would only add a trampoline
//     to each read and write of the node's own services.
type fsAttacher struct {
	log *slog.Logger
	// attachFn loads a plan's collection and attaches its probes.
	attachFn func(fsAttachPlan) (io.Closer, error)
	// plan returns the attach plans of the targets that are probeable.
	plan func([]fsTarget) []fsAttachPlan
	// moduleLoaded reports whether a kernel module is loaded.
	moduleLoaded func(module string) bool
	// localPVs returns the local filesystems a kubelet volume is mounted
	// from, after bringing fs_dev_filter in line with those volumes.
	localPVs func() (map[FsTypeCode]bool, error)
	// endBurst ends the kernel BTF burst of a refresh that planned a load.
	endBurst func()

	// started is false until the first refresh, which plans every network
	// filesystem: one built into the kernel may have no /sys/module entry.
	started bool
	// withPV is the result of the last successful localPVs.
	withPV map[FsTypeCode]bool
	// withoutPV counts, per local filesystem, the successful localPVs in a
	// row that found no volume of it.
	withoutPV map[FsTypeCode]int
	// attached, failures, noFentry and hashStarts are keyed by fsPlanKey
	// rather than FsTypeCode: CIFS attaches its cache=strict, cache=loose
	// and cache=none variants side by side, each loading, failing, retrying
	// and falling back to kprobes independently (2.4, step 12). Every other
	// filesystem has exactly one target, with Variant always "".
	attached map[fsPlanKey]io.Closer
	// failures counts the failed loads and attaches of each attachment since
	// it last attached.
	failures map[fsPlanKey]int
	// noFentry holds the attachments whose fentry/fexit probes this kernel
	// cannot run, which use kprobes from then on.
	noFentry map[fsPlanKey]bool
	// fentryFallbacks counts the attachments moved to kprobes.
	fentryFallbacks int
	// hashStarts holds the attached targets whose programs keep their
	// starts in the fs_start hash map (kprobes, or fentry without task
	// storage), which sweepStarts must keep clear of starts left by
	// threads that died mid-call.
	hashStarts map[fsPlanKey]bool
	// fsyncOwner maps a shared fsync symbol, such as CIFS's cifs_fsync
	// (claimed by cache=loose and cache=none alike), to the plan key
	// currently attached and probing it. dedupeSharedFsync only sees the
	// plans of one planning batch, built from the targets one refresh
	// finds pending; without this, a sibling planned alone in a later
	// refresh (because the symbol's claimant already attached, or is still
	// retrying on its own) would resolve and keep the same symbol, probing
	// it a second time (2.4, step 12 review fix).
	fsyncOwner map[string]fsPlanKey
	// sweepStarts deletes the stale fs_start entries and returns how many.
	sweepStarts func() (int, error)
	// readDrops returns fs_drops, summed across CPUs, per enum
	// fs_drop_reason; loggedDrops is what was logged and reported of them so
	// far.
	readDrops   func() ([]uint64, error)
	loggedDrops []uint64
	// metrics receives the drops as an internal metric.
	metrics imetrics.Reporter
	// accum is the kernel map the programs aggregate into, nil when they
	// send ring buffer events.
	accum *ebpf.Map
	// syncCloser detaches the sync syscall probes (storage_fs_sync, step
	// 14), nil when the feature is off or none could be attached. Resolved
	// once at startup, unlike the per-filesystem attachments: the syscall
	// wrappers a kernel exposes do not change at run time, so the sync set
	// is never re-planned on the refresh tick.
	syncCloser io.Closer
	// syncHashStarts is set when the attached sync probes keep their starts
	// in fs_start (sync(2) always; syncfs and sync_file_range on kprobes),
	// so maintain sweeps even with no per-filesystem attachment in hashStarts.
	syncHashStarts bool

	stop    chan struct{}
	stopped chan struct{}
}

func newFsAttacher(
	log *slog.Logger, attachFn func(fsAttachPlan) (io.Closer, error), localPVs func() (map[FsTypeCode]bool, error),
) *fsAttacher {
	return &fsAttacher{
		log:          log,
		attachFn:     attachFn,
		plan:         planFsTargets,
		moduleLoaded: moduleLoaded,
		localPVs:     localPVs,
		endBurst:     func() {},
		withoutPV:    map[FsTypeCode]int{},
		attached:     map[fsPlanKey]io.Closer{},
		failures:     map[fsPlanKey]int{},
		noFentry:     map[fsPlanKey]bool{},
		hashStarts:   map[fsPlanKey]bool{},
		fsyncOwner:   map[string]fsPlanKey{},
		sweepStarts:  func() (int, error) { return 0, nil },
		readDrops:    func() ([]uint64, error) { return nil, nil },
		metrics:      imetrics.NoopReporter{},
		stop:         make(chan struct{}),
		stopped:      make(chan struct{}),
	}
}

// planFsSyncFn is planFsSync, replaceable by tests that force the kprobe
// fallback.
var planFsSyncFn = planFsSync

// startFsAttacher attaches the filesystems worth probing now, then keeps
// looking every fsAttachInterval until closed. syncEnabled gates the sync
// syscall set (storage_fs_sync, step 14), attached once here rather than on
// the refresh tick (see fsAttacher.syncCloser).
func startFsAttacher(
	log *slog.Logger, cfg *config.EBPFTracer, consts map[string]any, fsAgg FsAggregation,
	sharedMaps map[string]*ebpf.Map, mu *sync.Mutex, metrics imetrics.Reporter, syncEnabled bool,
) (*fsAttacher, error) {
	a, err := newKernelFsAttacher(log, cfg, consts, fsAgg, sharedMaps, mu, syncEnabled)
	if err != nil {
		return nil, err
	}
	if metrics != nil {
		a.metrics = metrics
	}
	a.refresh()
	go a.run()
	return a, nil
}

// newKernelFsAttacher returns an fsAttacher that loads the FsIo programs and
// reads the node's kubelet volume mounts.
func newKernelFsAttacher(
	log *slog.Logger, cfg *config.EBPFTracer, consts map[string]any, fsAgg FsAggregation,
	sharedMaps map[string]*ebpf.Map, mu *sync.Mutex, syncEnabled bool,
) (*fsAttacher, error) {
	loader, err := newFsLoader(log, cfg, consts, fsAgg, sharedMaps, mu)
	if err != nil {
		return nil, err
	}
	filterMap, err := loader.sharedMap(FsIoMapFsDevFilter)
	if err != nil {
		return nil, err
	}
	starts, err := loader.sharedMap(FsIoMapFsStart)
	if err != nil {
		return nil, err
	}
	drops, err := loader.sharedMap(FsIoMapFsDrops)
	if err != nil {
		return nil, err
	}
	a := newFsAttacher(log, loader.attach, func() (map[FsTypeCode]bool, error) {
		return scanLocalPVs(log, filterMap)
	})
	a.endBurst = loader.btf.Release
	a.sweepStarts = func() (int, error) { return sweepMapFsStarts(starts, monotonicNow(), fsStartMaxAge) }
	a.readDrops = func() ([]uint64, error) { return readFsDrops(drops) }
	if fsAgg.Enabled {
		// Created now, whether or not a filesystem loads, so that userspace
		// reads the map every collection shares from startup.
		if a.accum, err = loader.sharedMap(fsAccumMapName(fsAgg)); err != nil {
			return nil, err
		}
	}
	if syncEnabled {
		if closer, syncErr := loader.attachSync(planFsSyncFn()); syncErr != nil {
			log.Warn("sync system call probes cannot be loaded; disabling storage_fs_sync", "error", syncErr)
		} else {
			a.syncCloser = closer
			if sa, ok := closer.(*fsSyncAttachment); ok {
				a.syncHashStarts = sa.hashStarts
			}
		}
	}
	return a, nil
}

func (a *fsAttacher) run() {
	defer close(a.stopped)
	ticker := time.NewTicker(fsAttachInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-ticker.C:
			a.refresh()
		}
	}
}

// refresh detaches the local filesystems no kubelet volume has used for
// fsDetachAfter refreshes, and attaches every filesystem worth probing that is not attached yet.
func (a *fsAttacher) refresh() {
	startup := !a.started
	a.maintain()
	if withPV, err := a.localPVs(); err != nil {
		a.log.Debug("scanning kubelet volume mounts failed", "error", err)
	} else {
		a.withPV = withPV
		for _, tgt := range fsTargets {
			if withPV[tgt.Fs] {
				delete(a.withoutPV, tgt.Fs)
			} else if isLocalFs(tgt.Fs) {
				a.withoutPV[tgt.Fs]++
			}
		}
	}

	var pending []fsTarget
	for _, tgt := range fsTargets {
		closer, attached := a.attached[tgt.Key()]
		switch {
		case attached && isLocalFs(tgt.Fs) && a.withoutPV[tgt.Fs] >= fsDetachAfter:
			a.detach(tgt.Key(), closer)
		case attached, a.failures[tgt.Key()] >= fsAttachTries:
		case isLocalFs(tgt.Fs):
			if a.withPV[tgt.Fs] {
				pending = append(pending, tgt)
			}
		case !a.started || a.moduleLoaded(tgt.Module):
			pending = append(pending, tgt)
		}
	}
	a.started = true

	// With nothing pending, as on most ticks, the symbol table is not read.
	if len(pending) == 0 {
		return
	}
	// Planning and loading are one BTF burst: its cache goes with it.
	defer a.endBurst()
	plans := a.plan(pending)
	a.dedupeAgainstLive(plans)
	for _, plan := range plans {
		a.attach(plan, startup)
	}
}

// dedupeAgainstLive clears a plan's FsyncSym when a different, still-attached
// key already claims it. dedupeSharedFsync (inside a.plan) only sees the
// plans of this one batch; a plan here can be a sibling retrying alone after
// the symbol's earlier claimant already attached in a previous refresh, and
// it must not probe the same symbol a second time (2.4, step 12 review fix).
func (a *fsAttacher) dedupeAgainstLive(plans []fsAttachPlan) {
	for i := range plans {
		if owner, ok := a.fsyncOwner[plans[i].FsyncSym]; ok && owner != plans[i].Key() {
			plans[i].FsyncSym = ""
		}
	}
}

// attach loads and attaches plan. startup is set for the first refresh,
// whose attaches are logged apart from the later ones.
func (a *fsAttacher) attach(plan fsAttachPlan, startup bool) {
	key := plan.Key()
	closer, fentry, err := a.loadAndAttach(plan)
	if err != nil {
		a.failures[key]++
		if a.failures[key] < fsAttachTries {
			a.log.Warn("filesystem probes failed to load or attach; retrying",
				"fs", fsTypeStr(plan.Fs), "variant", plan.Variant, "fentry", fentry, "error", err)
			return
		}
		a.log.Warn("filesystem probes failed to load or attach; disabling this filesystem",
			"fs", fsTypeStr(plan.Fs), "variant", plan.Variant, "fentry", fentry, "error", err)
		a.reclaimFsync(plan)
		return
	}
	a.attached[key] = closer
	if plan.FsyncSym != "" {
		a.fsyncOwner[plan.FsyncSym] = key
	}
	if h, ok := closer.(interface{ StartsInHash() bool }); ok && h.StartsInHash() {
		a.hashStarts[key] = true
	}
	// The tries bound failures in a row: an attachment that attached,
	// detached and fails later starts afresh.
	delete(a.failures, key)
	if startup {
		a.log.Info("filesystem probes attached", "fs", fsTypeStr(plan.Fs), "variant", plan.Variant, "fentry", fentry)
		return
	}
	// Operators and the late-mount checks grep for this message: keep it.
	a.log.Info(lateAttachMessage, "fs", fsTypeStr(plan.Fs), "variant", plan.Variant, "fentry", fentry)
}

// lateAttachMessage is logged for every filesystem attached after the
// startup pass: a network filesystem whose module loaded later, or a local
// filesystem whose first kubelet volume was mounted later.
const lateAttachMessage = "filesystem became probeable after startup; probes attached"

// reclaimFsync hands a shared fsync symbol to an already-attached sibling of
// the same filesystem when failed has just been disabled for good without
// ever claiming it. dedupeSharedFsync picks the symbol's claimant from one
// planning batch before any of that batch's plans are attached, so a sibling
// deduped out in that same batch is left with no claimant at all if the
// chosen one never attaches (2.4, step 12 review fix).
func (a *fsAttacher) reclaimFsync(failed fsAttachPlan) {
	for _, sym := range fsTargetFor(failed.Key()).FsyncSyms {
		if _, owned := a.fsyncOwner[sym]; owned {
			continue
		}
		for key := range a.attached {
			if key.Fs != failed.Fs || key == failed.Key() {
				continue
			}
			sib := fsTargetFor(key)
			if !slices.Contains(sib.FsyncSyms, sym) {
				continue
			}
			a.reattachForFsync(key, sib, sym)
			return
		}
	}
}

// reattachForFsync reloads key's collection with sym added as its fsync
// probe: a plan's programs are fixed at load time (keepFsPrograms), so
// claiming a symbol key's own plan did not resolve means detaching and
// attaching afresh.
func (a *fsAttacher) reattachForFsync(key fsPlanKey, tgt fsTarget, sym string) {
	plans := a.plan([]fsTarget{tgt})
	if len(plans) != 1 || plans[0].FsyncSym != sym {
		// The symbol table changed since key attached, or sym is no longer
		// probeable: leave key as is rather than force a claim it cannot
		// back up.
		return
	}
	closer := a.attached[key]
	delete(a.attached, key)
	delete(a.hashStarts, key)
	if err := closer.Close(); err != nil {
		a.log.Debug("detaching filesystem probes to reclaim a shared fsync symbol failed",
			"fs", fsTypeStr(key.Fs), "variant", key.Variant, "error", err)
	}
	a.attach(plans[0], false)
}

// loadAndAttach attaches plan, and reports whether it tried fentry/fexit. A
// filesystem whose fentry/fexit probes this kernel cannot run is moved to
// kprobes for good: those need the function's BTF and trampoline support,
// kprobes neither. Any other failure is returned as is, and the next try
// uses fentry/fexit again.
func (a *fsAttacher) loadAndAttach(plan fsAttachPlan) (io.Closer, bool, error) {
	key := plan.Key()
	if a.noFentry[key] {
		plan.UseFentry = false
	}
	closer, err := a.attachFn(plan)
	if err == nil || !plan.UseFentry || !fentryUnsupported(err) {
		return closer, plan.UseFentry, err
	}

	a.noFentry[key] = true
	a.fentryFallbacks++
	a.log.Warn("filesystem fentry/fexit probes are not supported here; retrying with kprobes",
		"fs", fsTypeStr(plan.Fs), "variant", plan.Variant, "error", err, "filesystems_on_kprobes", a.fentryFallbacks)
	plan.UseFentry = false
	closer, err = a.attachFn(plan)
	return closer, false, err
}

// errFentryUnsupported marks a load failure that rules out fentry/fexit for
// a filesystem on this kernel, which the kernel's error alone does not tell.
var errFentryUnsupported = errors.New("fentry/fexit unsupported")

// errnoENOTSUPP is the kernel-internal ENOTSUPP (524), returned when this
// architecture or kernel cannot build a trampoline for the function. It is
// not EOPNOTSUPP and x/sys/unix does not name it.
const errnoENOTSUPP = syscall.Errno(524)

// fentryUnsupported reports whether a failed fentry/fexit load or attach
// means these programs cannot work for the filesystem's functions on this
// kernel -- no BTF for the function, no trampoline support, a function the
// kernel will not trace or whose signature the verifier rejects -- rather
// than something a later try may not hit, such as memory pressure.
func fentryUnsupported(err error) bool {
	var verr *ebpf.VerifierError
	return errors.Is(err, errFentryUnsupported) ||
		errors.Is(err, btf.ErrNotFound) ||
		errors.Is(err, ebpf.ErrNotSupported) ||
		errors.Is(err, errnoENOTSUPP) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EINVAL) ||
		errors.As(err, &verr)
}

func (a *fsAttacher) detach(key fsPlanKey, closer io.Closer) {
	delete(a.attached, key)
	delete(a.hashStarts, key)
	a.releaseFsyncClaims(key)
	if err := closer.Close(); err != nil {
		a.log.Debug("detaching filesystem probes failed", "fs", fsTypeStr(key.Fs), "error", err)
	}
	a.log.Info("no kubelet volume of this filesystem is mounted; probes detached", "fs", fsTypeStr(key.Fs))
}

// releaseFsyncClaims drops any shared fsync symbol key owns, so a sibling
// can claim it once key is gone.
func (a *fsAttacher) releaseFsyncClaims(key fsPlanKey) {
	for sym, owner := range a.fsyncOwner {
		if owner == key {
			delete(a.fsyncOwner, sym)
		}
	}
}

func (a *fsAttacher) Close() error {
	close(a.stop)
	<-a.stopped
	var errs []error
	for _, closer := range a.attached {
		errs = append(errs, closer.Close())
	}
	if a.syncCloser != nil {
		errs = append(errs, a.syncCloser.Close())
	}
	return errors.Join(errs...)
}

func isLocalFs(fs FsTypeCode) bool {
	return fs == CodeFsExt4 || fs == CodeFsXFS || fs == CodeFsBtrfs
}

// maintain does what the kernel maps shared by the filesystem programs need
// from userspace on every refresh: stale starts deleted from fs_start, only
// while a filesystem or the sync probes keep their starts there, the programs' drops logged and
// reported, and kretprobe misses of any kprobe-mode return probe (step 3
// re-plan, step 14 sync syscalls) reported the same way.
func (a *fsAttacher) maintain() {
	if len(a.hashStarts) > 0 || a.syncHashStarts {
		if n, err := a.sweepStarts(); err != nil {
			a.log.Debug("sweeping stale fs_start entries failed", "error", err)
		} else if n > 0 {
			a.log.Debug("deleted stale fs_start entries of threads that never returned", "entries", n)
		}
	}
	a.logDrops()
	a.logMissedKretprobes()
	a.logRecursionMisses()
}

// logRecursionMisses reports the recursion misses of every attached program
// as the obi.bpf.storage.program.recursion.misses internal metric.
func (a *fsAttacher) logRecursionMisses() {
	for _, closer := range a.attached {
		if r, ok := closer.(recursionMissReporter); ok {
			r.pollRecursionMisses(a.metrics)
		}
	}
	if r, ok := a.syncCloser.(recursionMissReporter); ok {
		r.pollRecursionMisses(a.metrics)
	}
}

// kretprobeMissReporter is implemented by an attachment that keeps
// kprobe-mode return probes and can report the kprobe "missed" count
// (nmissed) they accumulated since the last call: fsAttachment's kprobe-mode
// filesystems (the step 3 fentry -> kprobe re-plan) and fsSyncAttachment's
// kprobe-mode sync syscalls (step 14). A fentry/fexit-only attachment
// implements it trivially (0 every time): a tracing link's Info() is not a
// PerfEvent one, so pollMissedKretprobes below finds nothing to report.
type kretprobeMissReporter interface {
	pollMissedKretprobes() uint64
}

// pollMissedKretprobes sums the new kprobe "missed" count across probes'
// exit (kretprobe) links since the last call: a miss means every
// RetprobeMaxActive instance (or, without tracefs, the kernel default) was
// already in use when a call returned, so that call's latency, and for an
// aggregated key its sample, never reached fs_probe_exit at all. prev[i]
// holds links[i]'s last reported count, and must be sized to len(links)
// before the first call (the caller allocates it once, since a link's
// Missed count is cumulative for its own lifetime, not reset between
// polls). Entry probes and every fentry/fexit link report nothing: their
// Info().PerfEvent() is nil, which this function must check before calling
// Kprobe() on it (*PerfEventInfo.Kprobe dereferences its receiver, so
// calling it on a nil *PerfEventInfo panics).
func pollMissedKretprobes(probes []fsProbe, links []io.Closer, prev []uint64) uint64 {
	var total uint64
	for i, p := range probes {
		if !p.exit {
			continue
		}
		lk, ok := links[i].(link.Link)
		if !ok {
			continue
		}
		info, err := lk.Info()
		if err != nil {
			continue
		}
		pe := info.PerfEvent()
		if pe == nil {
			// This kernel's kretprobe link is not perf-event-backed (or
			// cilium/ebpf reports it under another Info variant): nothing
			// to query. *PerfEventInfo.Kprobe() dereferences its receiver,
			// so calling it on a nil *PerfEventInfo panics -- confirmed
			// against a real kprobe-mode fallback link, not only a
			// theoretical case.
			continue
		}
		kp := pe.Kprobe()
		if kp == nil || kp.Missed <= prev[i] {
			continue
		}
		total += kp.Missed - prev[i]
		prev[i] = kp.Missed
	}
	return total
}

// logMissedKretprobes reports as the obi.bpf.storage.dropped.operations
// internal metric (reason "kretprobe_miss") the kretprobe returns a
// kprobe-mode fallback missed since the last refresh: unlike fs_drops, a
// miss never reaches a BPF program, so the kernel map the rest of logDrops
// reads has no counter for it. Misses are biased toward long calls in
// flight during a storage stall (2.4, step 14), so they are worth tracking
// even though they are rare in practice.
func (a *fsAttacher) logMissedKretprobes() {
	var total uint64
	for _, closer := range a.attached {
		if r, ok := closer.(kretprobeMissReporter); ok {
			total += r.pollMissedKretprobes()
		}
	}
	if r, ok := a.syncCloser.(kretprobeMissReporter); ok {
		total += r.pollMissedKretprobes()
	}
	if total == 0 {
		return
	}
	a.metrics.BpfStorageDrops("kretprobe_miss", total)
	a.log.Debug("kretprobes missed returns under load", "count", total)
}

// logDrops reports as the obi.bpf.storage.dropped.operations internal metric,
// and logs at Warn the first time and at Debug after, the filesystem
// operations the programs could not record since the last refresh.
func (a *fsAttacher) logDrops() {
	drops, err := a.readDrops()
	if err != nil {
		a.log.Debug("reading fs_drops failed", "error", err)
		return
	}
	for reason, n := range drops {
		if reason >= len(a.loggedDrops) {
			a.loggedDrops = append(a.loggedDrops, 0)
		}
		logged := a.loggedDrops[reason]
		if n <= logged {
			continue
		}
		a.loggedDrops[reason] = n
		a.metrics.BpfStorageDrops(fsDropReasonLabel(FsIoFsDropReason(reason)), n-logged)
		msg, level := fsDropMessage(FsIoFsDropReason(reason)), slog.LevelDebug
		if logged == 0 {
			level = slog.LevelWarn
		}
		a.log.Log(context.Background(), level, msg, "operations", n-logged, "total", n)
	}
}

// fsDropReasonLabel is the bpf.drop.reason value of a filesystem drop reason.
func fsDropReasonLabel(reason FsIoFsDropReason) string {
	switch reason {
	case FsIoFsDropReasonFsDropAccumFull:
		return "fs_accum_full"
	case FsIoFsDropReasonFsDropStart:
		return "fs_start_failed"
	default:
		return "fs_unknown"
	}
}

func fsDropMessage(reason FsIoFsDropReason) string {
	switch reason {
	case FsIoFsDropReasonFsDropAccumFull:
		return "the filesystem aggregation map is full; operations of new series are not recorded"
	case FsIoFsDropReasonFsDropStart:
		return "the start of filesystem operations could not be stored; they are not recorded"
	default:
		return "filesystem operations were not recorded"
	}
}
