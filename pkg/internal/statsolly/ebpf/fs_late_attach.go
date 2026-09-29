// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
)

// fsAttachInterval is how often the attacher looks again at the node: for
// network filesystems whose module has loaded since (nfs, cifs, ceph and
// fuse usually load only when the node mounts its first volume of that type,
// which on a freshly started node comes after OBI), and for kubelet volumes
// of a local filesystem mounted or unmounted since.
const fsAttachInterval = 30 * time.Second

// fsAttachTries bounds how often a filesystem whose probes fail to load or
// attach is tried, one tick apart, before it is left alone until OBI
// restarts. A module still initializing can fail once; a verifier rejection
// fails every time.
const fsAttachTries = 3

// fsAttacher attaches the probes of each filesystem, as a collection of its
// own, while the filesystem is worth probing:
//   - a network filesystem (nfs, ceph, cifs, fuse) from the moment its module
//     is loaded;
//   - a local filesystem (ext4, xfs, btrfs) only while a kubelet volume of
//     that type is mounted. These also hold the node's root filesystem and
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

	// started is false until the first refresh, which plans every network
	// filesystem: one built into the kernel may have no /sys/module entry.
	started bool
	// withPV is the result of the last successful localPVs.
	withPV   map[FsTypeCode]bool
	attached map[FsTypeCode]io.Closer
	// failures counts failed loads and attaches per filesystem.
	failures map[FsTypeCode]int
	// noFentry holds the filesystems whose fentry/fexit probes failed, which
	// use kprobes from then on.
	noFentry map[FsTypeCode]bool
	// fentryFallbacks counts the filesystems moved to kprobes.
	fentryFallbacks int

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
		attached:     map[FsTypeCode]io.Closer{},
		failures:     map[FsTypeCode]int{},
		noFentry:     map[FsTypeCode]bool{},
		stop:         make(chan struct{}),
		stopped:      make(chan struct{}),
	}
}

// startFsAttacher attaches the filesystems worth probing now, then keeps
// looking every fsAttachInterval until closed.
func startFsAttacher(
	log *slog.Logger, cfg *config.EBPFTracer, consts map[string]any, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex,
) (io.Closer, error) {
	a, err := newKernelFsAttacher(log, cfg, consts, sharedMaps, mu)
	if err != nil {
		return nil, err
	}
	a.refresh()
	go a.run()
	return a, nil
}

// newKernelFsAttacher returns an fsAttacher that loads the FsIo programs and
// reads the node's kubelet volume mounts.
func newKernelFsAttacher(
	log *slog.Logger, cfg *config.EBPFTracer, consts map[string]any, sharedMaps map[string]*ebpf.Map, mu *sync.Mutex,
) (*fsAttacher, error) {
	loader, err := newFsLoader(log, cfg, consts, sharedMaps, mu)
	if err != nil {
		return nil, err
	}
	filterMap, err := loader.sharedMap(FsIoMapFsDevFilter)
	if err != nil {
		return nil, err
	}
	return newFsAttacher(log, loader.attach, func() (map[FsTypeCode]bool, error) {
		return scanLocalPVs(log, filterMap)
	}), nil
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

// refresh detaches the local filesystems no kubelet volume uses any more,
// and attaches every filesystem worth probing that is not attached yet.
func (a *fsAttacher) refresh() {
	startup := !a.started
	if withPV, err := a.localPVs(); err != nil {
		a.log.Debug("scanning kubelet volume mounts failed", "error", err)
	} else {
		a.withPV = withPV
	}

	var pending []fsTarget
	for _, tgt := range fsTargets {
		closer, attached := a.attached[tgt.Fs]
		switch {
		case attached && isLocalFs(tgt.Fs) && !a.withPV[tgt.Fs]:
			a.detach(tgt.Fs, closer)
		case attached, a.failures[tgt.Fs] >= fsAttachTries:
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
	for _, plan := range a.plan(pending) {
		a.attach(plan, startup)
	}
}

// attach loads and attaches plan. startup is set for the first refresh,
// whose attaches are logged apart from the later ones.
func (a *fsAttacher) attach(plan fsAttachPlan, startup bool) {
	closer, err := a.loadAndAttach(plan)
	if err != nil {
		a.failures[plan.Fs]++
		if a.failures[plan.Fs] < fsAttachTries {
			a.log.Warn("filesystem probes failed to load or attach; retrying",
				"fs", fsTypeStr(plan.Fs), "error", err)
			return
		}
		a.log.Warn("filesystem probes failed to load or attach; disabling this filesystem",
			"fs", fsTypeStr(plan.Fs), "error", err)
		return
	}
	a.attached[plan.Fs] = closer
	fentry := plan.UseFentry && !a.noFentry[plan.Fs]
	if startup {
		a.log.Info("filesystem probes attached", "fs", fsTypeStr(plan.Fs), "fentry", fentry)
		return
	}
	// Operators and the late-mount checks grep for this message: keep it.
	a.log.Info(lateAttachMessage, "fs", fsTypeStr(plan.Fs), "fentry", fentry)
}

// lateAttachMessage is logged for every filesystem attached after the
// startup pass: a network filesystem whose module loaded later, or a local
// filesystem whose first kubelet volume was mounted later.
const lateAttachMessage = "filesystem became probeable after startup; probes attached"

// loadAndAttach attaches plan, moving the filesystem to kprobes when its
// fentry/fexit probes fail: those need the function's BTF and trampoline
// support, kprobes neither.
func (a *fsAttacher) loadAndAttach(plan fsAttachPlan) (io.Closer, error) {
	if a.noFentry[plan.Fs] {
		plan.UseFentry = false
	}
	closer, err := a.attachFn(plan)
	if err == nil || !plan.UseFentry {
		return closer, err
	}

	a.noFentry[plan.Fs] = true
	a.fentryFallbacks++
	a.log.Warn("filesystem fentry/fexit probes failed; retrying with kprobes",
		"fs", fsTypeStr(plan.Fs), "error", err, "filesystems_on_kprobes", a.fentryFallbacks)
	plan.UseFentry = false
	return a.attachFn(plan)
}

func (a *fsAttacher) detach(fs FsTypeCode, closer io.Closer) {
	delete(a.attached, fs)
	if err := closer.Close(); err != nil {
		a.log.Debug("detaching filesystem probes failed", "fs", fsTypeStr(fs), "error", err)
	}
	a.log.Info("no kubelet volume of this filesystem is mounted; probes detached", "fs", fsTypeStr(fs))
}

func (a *fsAttacher) Close() error {
	close(a.stop)
	<-a.stopped
	var errs []error
	for _, closer := range a.attached {
		errs = append(errs, closer.Close())
	}
	return errors.Join(errs...)
}

func isLocalFs(fs FsTypeCode) bool {
	return fs == CodeFsExt4 || fs == CodeFsXFS || fs == CodeFsBtrfs
}
