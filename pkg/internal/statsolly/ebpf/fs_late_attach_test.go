// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type attachAttempt struct {
	fs     FsTypeCode
	fentry bool
}

// fakeNode is the part of the node an fsAttacher looks at: loaded modules,
// probeable filesystems and kubelet volumes, plus a loader that fails for
// chosen filesystems.
type fakeNode struct {
	loaded    map[string]bool
	probeable map[FsTypeCode]bool
	// probeableVariant overrides probeable for one (Fs, Variant), for tests
	// where CIFS's cache=strict/loose/none variants must differ: every
	// other filesystem has one target, so probeable alone is enough there.
	probeableVariant map[fsPlanKey]bool
	pvs              map[FsTypeCode]bool
	pvErr            error
	// reject fails every attach of a filesystem; rejectFentry only its
	// fentry/fexit attaches, with the error given. rejectVariant overrides
	// reject for one (Fs, Variant).
	reject        map[FsTypeCode]bool
	rejectVariant map[fsPlanKey]bool
	rejectFentry  map[FsTypeCode]error

	// log receives the attacher's logs; slog.Default() when nil.
	log *slog.Logger

	planned  [][]FsTypeCode
	attempts []attachAttempt
	open     map[FsTypeCode]int
	closed   int
	// fsyncClaimed records, for each key that attached successfully, the
	// FsyncSym its plan carried (including empty), so a test can tell
	// whether a shared fsync symbol was claimed once, never, or twice.
	fsyncClaimed map[fsPlanKey]string
}

func newFakeNode() *fakeNode {
	return &fakeNode{
		loaded: map[string]bool{}, probeable: map[FsTypeCode]bool{}, probeableVariant: map[fsPlanKey]bool{},
		pvs: map[FsTypeCode]bool{}, reject: map[FsTypeCode]bool{}, rejectVariant: map[fsPlanKey]bool{},
		rejectFentry: map[FsTypeCode]error{}, open: map[FsTypeCode]int{},
		fsyncClaimed: map[fsPlanKey]string{},
	}
}

func (n *fakeNode) attacher() *fsAttacher {
	log := n.log
	if log == nil {
		log = slog.Default()
	}
	a := newFsAttacher(log, n.attach, func() (map[FsTypeCode]bool, error) {
		if n.pvErr != nil {
			return nil, n.pvErr
		}
		return maps.Clone(n.pvs), nil
	})
	a.plan = n.plan
	a.moduleLoaded = func(module string) bool { return n.loaded[module] }
	return a
}

func (n *fakeNode) plan(targets []fsTarget) []fsAttachPlan {
	var fss []FsTypeCode
	var plans []fsAttachPlan
	for _, tgt := range targets {
		fss = append(fss, tgt.Fs)
		probeable := n.probeable[tgt.Fs]
		if v, ok := n.probeableVariant[tgt.Key()]; ok {
			probeable = v
		}
		if probeable {
			plan := fsAttachPlan{Fs: tgt.Fs, Variant: tgt.Variant, Module: tgt.Module, UseFentry: true}
			// Real resolution picks the first probeable candidate; here
			// every target is wholly probeable or not (probeable/
			// probeableVariant), so the first candidate stands in for it.
			if len(tgt.FsyncSyms) > 0 {
				plan.FsyncSym = tgt.FsyncSyms[0]
			}
			plans = append(plans, plan)
		}
	}
	n.planned = append(n.planned, fss)
	// The real attacher dedupes a shared fsync symbol within its own
	// planning batch the same way, before any plan here is attached.
	dedupeSharedFsync(plans)
	return plans
}

func (n *fakeNode) attach(plan fsAttachPlan) (io.Closer, error) {
	n.attempts = append(n.attempts, attachAttempt{plan.Fs, plan.UseFentry})
	reject := n.reject[plan.Fs]
	if v, ok := n.rejectVariant[plan.Key()]; ok {
		reject = v
	}
	if reject {
		return nil, errors.New("rejected")
	}
	if err := n.rejectFentry[plan.Fs]; err != nil && plan.UseFentry {
		return nil, err
	}
	n.open[plan.Fs]++
	n.fsyncClaimed[plan.Key()] = plan.FsyncSym
	// As on a kernel whose tracing programs can use task storage: only the
	// kprobe programs keep their starts in the fs_start hash map.
	return fakeAttachment{
		closeFunc: func() error { n.open[plan.Fs]--; n.closed++; return nil },
		hash:      !plan.UseFentry,
	}, nil
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

type fakeAttachment struct {
	closeFunc
	hash bool
}

func (a fakeAttachment) StartsInHash() bool { return a.hash }

func attachedSet(a *fsAttacher) map[FsTypeCode]bool {
	set := map[FsTypeCode]bool{}
	for key := range a.attached {
		set[key.Fs] = true
	}
	return set
}

// refreshToDetach runs the refreshes that detach a local filesystem gone
// from every volume.
func refreshToDetach(a *fsAttacher) {
	for range fsDetachAfter {
		a.refresh()
	}
}

func closeAttacher(t *testing.T, a *fsAttacher) {
	t.Helper()
	close(a.stopped) // run() was never started
	require.NoError(t, a.Close())
}

// A network filesystem that appears after startup is attached exactly once,
// and one whose probes keep failing is tried fsAttachTries times, then left
// alone.
func TestFsAttacherAttachesNewFilesystemsOnce(t *testing.T) {
	n := newFakeNode()
	n.reject[CodeFsFUSE] = true
	a := n.attacher()

	// Startup: nothing is probeable yet.
	a.refresh()
	assert.Empty(t, n.attempts)
	assert.Empty(t, a.attached)

	// nfs and fuse load later.
	n.loaded["nfs"], n.loaded["fuse"] = true, true
	n.probeable[CodeFsNFS], n.probeable[CodeFsFUSE] = true, true
	for range fsAttachTries + 2 {
		a.refresh()
	}

	nfsAttempts, fuseAttempts := 0, 0
	for _, at := range n.attempts {
		switch at.fs {
		case CodeFsNFS:
			nfsAttempts++
		case CodeFsFUSE:
			fuseAttempts++
		}
	}
	assert.Equal(t, 1, nfsAttempts, "nfs is attached once")
	assert.Equal(t, fsAttachTries, fuseAttempts, "fuse is given up on after fsAttachTries tries")
	assert.Equal(t, map[FsTypeCode]bool{CodeFsNFS: true}, attachedSet(a))

	closeAttacher(t, a)
	assert.Equal(t, 1, n.closed, "the nfs attachment is closed with the attacher")
}

// After startup, only filesystems whose module is loaded are planned, and
// with none pending the symbol table is not read at all. CIFS's three
// cache= variants (2.4, step 12) are each their own target, so the startup
// pass plans CodeFsCIFS three times.
func TestFsAttacherPlansOnlyLoadedModules(t *testing.T) {
	n := newFakeNode()
	a := n.attacher()

	a.refresh()
	require.Len(t, n.planned, 1)
	assert.ElementsMatch(t,
		[]FsTypeCode{CodeFsNFS, CodeFsCeph, CodeFsCIFS, CodeFsCIFS, CodeFsCIFS, CodeFsFUSE}, n.planned[0],
		"the startup pass plans every network filesystem: a built-in one may have no /sys/module entry")

	a.refresh()
	assert.Len(t, n.planned, 1, "nothing loaded: the symbol table is not read")

	n.loaded["ceph"] = true
	a.refresh()
	require.Len(t, n.planned, 2)
	assert.Equal(t, []FsTypeCode{CodeFsCeph}, n.planned[1])

	closeAttacher(t, a)
}

// ext4, xfs and btrfs attach only while a kubelet volume of their type is
// mounted, and detach when the last one goes away.
func TestFsAttacherAttachesLocalFilesystemsOnDemand(t *testing.T) {
	n := newFakeNode()
	for _, fs := range []FsTypeCode{CodeFsExt4, CodeFsXFS, CodeFsBtrfs} {
		n.probeable[fs] = true
	}
	a := n.attacher()

	a.refresh()
	assert.Empty(t, a.attached, "no volume: no local filesystem probe, however probeable")

	n.pvs = map[FsTypeCode]bool{CodeFsXFS: true}
	a.refresh()
	assert.Equal(t, map[FsTypeCode]bool{CodeFsXFS: true}, attachedSet(a))

	n.pvs = map[FsTypeCode]bool{CodeFsXFS: true, CodeFsExt4: true}
	a.refresh()
	assert.Equal(t, map[FsTypeCode]bool{CodeFsXFS: true, CodeFsExt4: true}, attachedSet(a))

	// A failed scan changes nothing.
	n.pvErr = errors.New("mountinfo unreadable")
	a.refresh()
	assert.Equal(t, map[FsTypeCode]bool{CodeFsXFS: true, CodeFsExt4: true}, attachedSet(a))
	n.pvErr = nil

	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	refreshToDetach(a)
	assert.Equal(t, map[FsTypeCode]bool{CodeFsExt4: true}, attachedSet(a))
	assert.Zero(t, n.open[CodeFsXFS], "the last xfs volume went away: its probes are detached")

	n.pvs = map[FsTypeCode]bool{CodeFsXFS: true}
	refreshToDetach(a)
	assert.Equal(t, map[FsTypeCode]bool{CodeFsXFS: true}, attachedSet(a), "xfs comes back, ext4 goes")
	assert.Equal(t, 1, n.open[CodeFsXFS])
	assert.Zero(t, n.open[CodeFsExt4])

	closeAttacher(t, a)
	for fs, open := range n.open {
		assert.Zero(t, open, "fs %d still attached after Close", fs)
	}
}

// A filesystem the kernel rejects disables only itself: the others attach.
func TestFsAttacherIsolatesFailingFilesystem(t *testing.T) {
	n := newFakeNode()
	n.loaded["nfs"] = true
	for _, fs := range []FsTypeCode{CodeFsNFS, CodeFsExt4, CodeFsXFS} {
		n.probeable[fs] = true
	}
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true, CodeFsXFS: true}
	n.reject[CodeFsXFS] = true
	a := n.attacher()

	a.refresh()
	assert.Equal(t, map[FsTypeCode]bool{CodeFsNFS: true, CodeFsExt4: true}, attachedSet(a))
	assert.Equal(t, 1, a.failures[fsPlanKey{Fs: CodeFsXFS}])

	closeAttacher(t, a)
}

// A filesystem whose fentry/fexit probes this kernel cannot run is tried once
// with kprobes, and stays on kprobes afterwards.
func TestFsAttacherFallsBackToKprobes(t *testing.T) {
	n := newFakeNode()
	n.probeable[CodeFsExt4] = true
	n.rejectFentry[CodeFsExt4] = fmt.Errorf("find target in vmlinux: %w", btf.ErrNotFound)
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	a := n.attacher()

	a.refresh()
	assert.Equal(t, []attachAttempt{{CodeFsExt4, true}, {CodeFsExt4, false}}, n.attempts)
	assert.Equal(t, map[FsTypeCode]bool{CodeFsExt4: true}, attachedSet(a))
	assert.Zero(t, a.failures[fsPlanKey{Fs: CodeFsExt4}], "the kprobe fallback succeeded")
	assert.Equal(t, 1, a.fentryFallbacks)

	// Detached and attached again: straight to kprobes.
	n.pvs = map[FsTypeCode]bool{}
	refreshToDetach(a)
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	a.refresh()
	assert.Equal(t, attachAttempt{CodeFsExt4, false}, n.attempts[len(n.attempts)-1])
	assert.Len(t, n.attempts, 3)

	closeAttacher(t, a)
}

// Every filesystem attached after the startup pass is logged with the
// message operators and the late-mount checks grep for, with its fs; the
// startup attaches are not.
func TestFsAttacherLogsLateAttaches(t *testing.T) {
	var out bytes.Buffer
	n := newFakeNode()
	n.log = slog.New(slog.NewTextHandler(&out, nil))
	n.probeable[CodeFsNFS], n.probeable[CodeFsExt4] = true, true
	n.loaded["nfs"] = true
	a := n.attacher()

	// grep -c 'filesystem became probeable after startup; probes attached.*fs=<fs>'
	lateAttaches := func(fs string) int {
		re := regexp.MustCompile(regexp.QuoteMeta(lateAttachMessage) + ".*fs=" + fs + "( |$)")
		count := 0
		for line := range strings.SplitSeq(out.String(), "\n") {
			if re.MatchString(line) {
				count++
			}
		}
		return count
	}

	a.refresh()
	require.Contains(t, a.attached, fsPlanKey{Fs: CodeFsNFS})
	assert.Zero(t, lateAttaches("nfs"), "nfs attached at startup")
	assert.Contains(t, out.String(), `msg="filesystem probes attached" fs=nfs`)

	// cifs's module loads, then an ext4 kubelet volume is mounted. CIFS's
	// three cache= variants (2.4, step 12) each attach and log on their own.
	n.loaded["cifs"], n.probeable[CodeFsCIFS] = true, true
	a.refresh()
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	a.refresh()
	assert.Equal(t, 3, lateAttaches("cifs"))
	assert.Equal(t, 1, lateAttaches("ext4"))
	assert.Equal(t, "filesystem became probeable after startup; probes attached", lateAttachMessage)

	closeAttacher(t, a)
}

// A failure that does not rule fentry/fexit out, such as memory pressure,
// leaves the filesystem on fentry/fexit: the next tick tries them again.
func TestFsAttacherRetriesFentryAfterOtherFailures(t *testing.T) {
	n := newFakeNode()
	n.probeable[CodeFsExt4] = true
	n.rejectFentry[CodeFsExt4] = fmt.Errorf("creating map: %w", unix.ENOMEM)
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	a := n.attacher()

	a.refresh()
	assert.Equal(t, []attachAttempt{{CodeFsExt4, true}}, n.attempts, "no kprobe try")
	assert.Empty(t, a.attached)
	assert.False(t, a.noFentry[fsPlanKey{Fs: CodeFsExt4}])

	delete(n.rejectFentry, CodeFsExt4)
	a.refresh()
	assert.Equal(t, []attachAttempt{{CodeFsExt4, true}, {CodeFsExt4, true}}, n.attempts)
	assert.Equal(t, map[FsTypeCode]bool{CodeFsExt4: true}, attachedSet(a))
	assert.Zero(t, a.fentryFallbacks)

	closeAttacher(t, a)
}

func TestFentryUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"no BTF for the function", fmt.Errorf("find target in modules: %w", btf.ErrNotFound), true},
		{"no tracing support", fmt.Errorf("attach: %w", ebpf.ErrNotSupported), true},
		{"no trampoline (ENOTSUPP)", fmt.Errorf("attach: %w", errnoENOTSUPP), true},
		{"EOPNOTSUPP", fmt.Errorf("attach: %w", unix.EOPNOTSUPP), true},
		{"EINVAL from a tracing attach", fmt.Errorf("attaching x to y: %w", unix.EINVAL), true},
		{"verifier rejection", &ebpf.VerifierError{}, true},
		{"unparsable module BTF", fmt.Errorf("%w: %w", errFentryUnsupported, errors.New("bad")), true},
		{"out of memory", fmt.Errorf("creating map: %w", unix.ENOMEM), false},
		{"busy", unix.EBUSY, false},
		{"target not found yet", unix.ENOENT, false},
		{"other", errors.New("program not loaded"), false},
	} {
		assert.Equal(t, tc.want, fentryUnsupported(tc.err), tc.name)
	}
}

// The tries bound failures in a row: a filesystem that attached starts
// afresh, so one that detaches and later fails is still tried
// fsAttachTries times.
func TestFsAttacherResetsFailuresOnAttach(t *testing.T) {
	n := newFakeNode()
	n.probeable[CodeFsExt4] = true
	n.reject[CodeFsExt4] = true
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	a := n.attacher()

	for range fsAttachTries - 1 {
		a.refresh()
	}
	assert.Equal(t, fsAttachTries-1, a.failures[fsPlanKey{Fs: CodeFsExt4}])

	n.reject[CodeFsExt4] = false
	a.refresh()
	require.Contains(t, a.attached, fsPlanKey{Fs: CodeFsExt4})
	assert.Zero(t, a.failures[fsPlanKey{Fs: CodeFsExt4}], "the count is reset on attach")

	// The volume goes away, comes back, and the filesystem fails again.
	n.pvs = map[FsTypeCode]bool{}
	refreshToDetach(a)
	require.NotContains(t, a.attached, fsPlanKey{Fs: CodeFsExt4})
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	n.reject[CodeFsExt4] = true
	attempts := len(n.attempts)
	for range fsAttachTries + 1 {
		a.refresh()
	}
	assert.Equal(t, fsAttachTries, len(n.attempts)-attempts, "tried fsAttachTries times again")

	closeAttacher(t, a)
}

// A local filesystem detaches only once fsDetachAfter refreshes in a row
// have found no volume of it: a volume unmounted and mounted again in
// between keeps its probes, and a failed scan counts for nothing.
func TestFsAttacherDetachHysteresis(t *testing.T) {
	require.Equal(t, 2, fsDetachAfter)
	n := newFakeNode()
	n.probeable[CodeFsExt4] = true
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	a := n.attacher()

	a.refresh()
	require.Contains(t, a.attached, fsPlanKey{Fs: CodeFsExt4})

	// Gone for one refresh, back on the next: never detached.
	n.pvs = map[FsTypeCode]bool{}
	a.refresh()
	assert.Contains(t, a.attached, fsPlanKey{Fs: CodeFsExt4}, "gone for one refresh only")
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	a.refresh()
	assert.Contains(t, a.attached, fsPlanKey{Fs: CodeFsExt4})

	// Gone, a failed scan, gone again: the failed scan does not count.
	n.pvs = map[FsTypeCode]bool{}
	a.refresh()
	n.pvErr = errors.New("mountinfo unreadable")
	a.refresh()
	assert.Contains(t, a.attached, fsPlanKey{Fs: CodeFsExt4}, "a failed scan is not a refresh without the volume")
	n.pvErr = nil
	a.refresh()
	assert.NotContains(t, a.attached, fsPlanKey{Fs: CodeFsExt4}, "gone for two refreshes in a row")
	assert.Zero(t, n.open[CodeFsExt4])
	assert.Len(t, n.attempts, 1, "attached once, never reloaded")

	closeAttacher(t, a)
}

// A refresh that plans a load ends the kernel BTF burst when done, so the
// parsed BTF is not kept between loads; an idle refresh has none to end.
func TestFsAttacherEndsBTFBurst(t *testing.T) {
	n := newFakeNode()
	n.probeable[CodeFsNFS] = true
	n.loaded["nfs"] = true
	a := n.attacher()
	bursts := 0
	a.endBurst = func() { bursts++ }

	a.refresh()
	assert.Equal(t, 1, bursts, "the startup pass")
	a.refresh()
	assert.Equal(t, 1, bursts, "nothing to load")

	n.loaded["cifs"], n.probeable[CodeFsCIFS] = true, true
	a.refresh()
	assert.Equal(t, 2, bursts, "cifs loaded")
	assert.Contains(t, a.attached, fsPlanKey{Fs: CodeFsCIFS, Variant: "strict"})

	closeAttacher(t, a)
}

// cifs_fsync is shared by cache=loose and cache=none: dedupeSharedFsync
// claims it for loose when both are planned together at startup, but a
// retry batch built later for direct alone (loose and strict already
// attached) has no sibling to dedupe against. Without fsyncOwner tracking
// live claims across refreshes, direct would resolve and keep cifs_fsync
// too, probing the same fsync call a second time (2.4, step 12 review fix).
func TestFsAttacherDoesNotReclaimAFsyncSymbolAlreadyLive(t *testing.T) {
	n := newFakeNode()
	n.loaded["cifs"] = true
	n.probeable[CodeFsCIFS] = true
	looseKey := fsPlanKey{Fs: CodeFsCIFS, Variant: "loose"}
	directKey := fsPlanKey{Fs: CodeFsCIFS, Variant: "direct"}
	// direct's own read/write probes fail once, for a reason unrelated to
	// fsync (e.g. a transient ENOMEM on its program load).
	n.rejectVariant[directKey] = true
	a := n.attacher()

	a.refresh()
	require.Contains(t, a.attached, looseKey)
	require.NotContains(t, a.attached, directKey)
	assert.Equal(t, "cifs_fsync", n.fsyncClaimed[looseKey], "loose claims the shared symbol in the startup batch")

	// direct is retried alone on the next tick: it must not re-resolve and
	// keep cifs_fsync, which loose's live probes already cover.
	n.rejectVariant[directKey] = false
	a.refresh()
	require.Contains(t, a.attached, directKey)
	assert.Empty(t, n.fsyncClaimed[directKey], "cifs_fsync is already probed by loose; direct must not claim it too")
	assert.Equal(t, "cifs_fsync", n.fsyncClaimed[looseKey], "loose's claim is unaffected")

	closeAttacher(t, a)
}

// When the claimant dedupeSharedFsync picked for cifs_fsync (loose) never
// attaches at all -- every attach of its own probes is rejected, not just
// the fsync one -- and the sibling it was deduped against (direct) already
// attached in the same startup batch with FsyncSym cleared, the symbol must
// be handed to direct once loose is disabled for good: without this
// reclaim, cifs_fsync would never be probed by anyone again for the life of
// the process (2.4, step 12 review fix).
func TestFsAttacherReclaimsFsyncFromAPermanentlyFailedSibling(t *testing.T) {
	n := newFakeNode()
	n.loaded["cifs"] = true
	n.probeable[CodeFsCIFS] = true
	looseKey := fsPlanKey{Fs: CodeFsCIFS, Variant: "loose"}
	directKey := fsPlanKey{Fs: CodeFsCIFS, Variant: "direct"}
	n.rejectVariant[looseKey] = true
	a := n.attacher()

	// Startup: direct attaches with cifs_fsync deduped away (loose precedes
	// it in fsTargets and would have claimed it); loose itself keeps
	// failing.
	a.refresh()
	require.Contains(t, a.attached, directKey)
	require.NotContains(t, a.attached, looseKey)
	assert.Empty(t, n.fsyncClaimed[directKey], "deduped against loose, which has not attached yet")

	// loose is retried alone until fsAttachTries gives up on it for good.
	for range fsAttachTries - 1 {
		a.refresh()
	}
	require.NotContains(t, a.attached, looseKey, "loose is disabled for good")
	require.Equal(t, fsAttachTries, a.failures[looseKey])

	// direct is reattached, reclaiming cifs_fsync on its own.
	require.Contains(t, a.attached, directKey, "direct stays attached, through a fresh collection")
	assert.Equal(t, "cifs_fsync", n.fsyncClaimed[directKey], "direct reclaims the orphaned fsync symbol")

	closeAttacher(t, a)
}
