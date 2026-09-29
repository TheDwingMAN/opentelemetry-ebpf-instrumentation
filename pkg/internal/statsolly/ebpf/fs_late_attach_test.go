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
	pvs       map[FsTypeCode]bool
	pvErr     error
	// reject fails every attach of a filesystem; rejectFentry only its
	// fentry/fexit attaches, with the error given.
	reject       map[FsTypeCode]bool
	rejectFentry map[FsTypeCode]error

	// log receives the attacher's logs; slog.Default() when nil.
	log *slog.Logger

	planned  [][]FsTypeCode
	attempts []attachAttempt
	open     map[FsTypeCode]int
	closed   int
}

func newFakeNode() *fakeNode {
	return &fakeNode{
		loaded: map[string]bool{}, probeable: map[FsTypeCode]bool{}, pvs: map[FsTypeCode]bool{},
		reject: map[FsTypeCode]bool{}, rejectFentry: map[FsTypeCode]error{}, open: map[FsTypeCode]int{},
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
		if n.probeable[tgt.Fs] {
			plans = append(plans, fsAttachPlan{Fs: tgt.Fs, Module: tgt.Module, UseFentry: true})
		}
	}
	n.planned = append(n.planned, fss)
	return plans
}

func (n *fakeNode) attach(plan fsAttachPlan) (io.Closer, error) {
	n.attempts = append(n.attempts, attachAttempt{plan.Fs, plan.UseFentry})
	if n.reject[plan.Fs] {
		return nil, errors.New("rejected")
	}
	if err := n.rejectFentry[plan.Fs]; err != nil && plan.UseFentry {
		return nil, err
	}
	n.open[plan.Fs]++
	return closeFunc(func() error { n.open[plan.Fs]--; n.closed++; return nil }), nil
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

func attachedSet(a *fsAttacher) map[FsTypeCode]bool {
	set := map[FsTypeCode]bool{}
	for fs := range a.attached {
		set[fs] = true
	}
	return set
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
	n.reject[CodeFsCIFS] = true
	a := n.attacher()

	// Startup: nothing is probeable yet.
	a.refresh()
	assert.Empty(t, n.attempts)
	assert.Empty(t, a.attached)

	// nfs and cifs load later.
	n.loaded["nfs"], n.loaded["cifs"] = true, true
	n.probeable[CodeFsNFS], n.probeable[CodeFsCIFS] = true, true
	for range fsAttachTries + 2 {
		a.refresh()
	}

	nfsAttempts, cifsAttempts := 0, 0
	for _, at := range n.attempts {
		switch at.fs {
		case CodeFsNFS:
			nfsAttempts++
		case CodeFsCIFS:
			cifsAttempts++
		}
	}
	assert.Equal(t, 1, nfsAttempts, "nfs is attached once")
	assert.Equal(t, fsAttachTries, cifsAttempts, "cifs is given up on after fsAttachTries tries")
	assert.Equal(t, map[FsTypeCode]bool{CodeFsNFS: true}, attachedSet(a))

	closeAttacher(t, a)
	assert.Equal(t, 1, n.closed, "the nfs attachment is closed with the attacher")
}

// After startup, only filesystems whose module is loaded are planned, and
// with none pending the symbol table is not read at all.
func TestFsAttacherPlansOnlyLoadedModules(t *testing.T) {
	n := newFakeNode()
	a := n.attacher()

	a.refresh()
	require.Len(t, n.planned, 1)
	assert.ElementsMatch(t, []FsTypeCode{CodeFsNFS, CodeFsCeph, CodeFsCIFS, CodeFsFUSE}, n.planned[0],
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
	a.refresh()
	assert.Equal(t, map[FsTypeCode]bool{CodeFsExt4: true}, attachedSet(a))
	assert.Zero(t, n.open[CodeFsXFS], "the last xfs volume went away: its probes are detached")

	n.pvs = map[FsTypeCode]bool{CodeFsXFS: true}
	a.refresh()
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
	assert.Equal(t, 1, a.failures[CodeFsXFS])

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
	assert.Zero(t, a.failures[CodeFsExt4], "the kprobe fallback succeeded")
	assert.Equal(t, 1, a.fentryFallbacks)

	// Detached and attached again: straight to kprobes.
	n.pvs = map[FsTypeCode]bool{}
	a.refresh()
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
	require.Contains(t, a.attached, CodeFsNFS)
	assert.Zero(t, lateAttaches("nfs"), "nfs attached at startup")
	assert.Contains(t, out.String(), `msg="filesystem probes attached" fs=nfs`)

	// cifs's module loads, then an ext4 kubelet volume is mounted.
	n.loaded["cifs"], n.probeable[CodeFsCIFS] = true, true
	a.refresh()
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	a.refresh()
	assert.Equal(t, 1, lateAttaches("cifs"))
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
	assert.False(t, a.noFentry[CodeFsExt4])

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
	assert.Equal(t, fsAttachTries-1, a.failures[CodeFsExt4])

	n.reject[CodeFsExt4] = false
	a.refresh()
	require.Contains(t, a.attached, CodeFsExt4)
	assert.Zero(t, a.failures[CodeFsExt4], "the count is reset on attach")

	// The volume goes away, comes back, and the filesystem fails again.
	n.pvs = map[FsTypeCode]bool{}
	a.refresh()
	require.NotContains(t, a.attached, CodeFsExt4)
	n.pvs = map[FsTypeCode]bool{CodeFsExt4: true}
	n.reject[CodeFsExt4] = true
	attempts := len(n.attempts)
	for range fsAttachTries + 1 {
		a.refresh()
	}
	assert.Equal(t, fsAttachTries, len(n.attempts)-attempts, "tried fsAttachTries times again")

	closeAttacher(t, a)
}
