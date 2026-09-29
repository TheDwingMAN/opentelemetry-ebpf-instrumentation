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

// fsLateAttachInterval is how often filesystems that were not probeable at
// startup are looked for again. A network filesystem's module (nfs, cifs,
// ceph, fuse) is usually loaded only when the node mounts its first volume of
// that type, which on a freshly started node comes after OBI.
const fsLateAttachInterval = 30 * time.Second

// fsLateAttachTries bounds how often a filesystem whose probes fail to attach
// is tried again, one tick apart, before it is left alone until OBI restarts.
// A module still initializing can fail once; a verifier rejection fails every
// time.
const fsLateAttachTries = 3

// lateFsAttacher attaches the probes of a filesystem that became probeable
// after the stats collection was loaded. Each such filesystem gets a small
// collection of its own, containing only its programs; the maps they write
// (the event ring buffer, the in-flight map, the device allowlist) are the
// shared ones, so its events reach the same reader.
type lateFsAttacher struct {
	log  *slog.Logger
	load func(toDisable []string, attachTo map[string]string, objects *StatsObjects) error
	// plan returns the filesystems probeable now among those not in done.
	plan func(done map[FsTypeCode]bool) []fsAttachPlan
	// attachFn is attach, replaceable in tests that cannot load BPF.
	attachFn func(fsAttachPlan) ([]io.Closer, error)

	// done holds every filesystem already attached or given up on, so a
	// filesystem that keeps failing to attach is not retried on every tick.
	done map[FsTypeCode]bool
	// failures counts failed attach attempts per filesystem.
	failures map[FsTypeCode]int
	// startLocalFilter starts the ext4/xfs/btrfs device allowlist refresher
	// the first time a local filesystem attaches late; nil when it already
	// runs.
	startLocalFilter func() io.Closer

	mu        sync.Mutex
	closables []io.Closer
	stop      chan struct{}
	stopped   chan struct{}
}

func (a *lateFsAttacher) run() {
	defer close(a.stopped)
	ticker := time.NewTicker(fsLateAttachInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-ticker.C:
			a.attachNew()
		}
	}
}

// attachNew attaches every planned filesystem not attached or tried yet.
func (a *lateFsAttacher) attachNew() {
	for _, plan := range a.plan(a.done) {
		if a.done[plan.Fs] {
			continue
		}

		closables, err := a.attachFn(plan)
		if err != nil {
			if a.failures == nil {
				a.failures = map[FsTypeCode]int{}
			}
			a.failures[plan.Fs]++
			if a.failures[plan.Fs] < fsLateAttachTries {
				a.log.Warn("filesystem became probeable but its probes failed to attach; retrying",
					"fs", fsTypeStr(plan.Fs), "fentry", plan.UseFentry, "error", err)
				continue
			}
			a.done[plan.Fs] = true
			a.log.Warn("filesystem became probeable but its probes failed to attach; not retrying",
				"fs", fsTypeStr(plan.Fs), "fentry", plan.UseFentry, "error", err)
			continue
		}
		a.done[plan.Fs] = true
		a.mu.Lock()
		a.closables = append(a.closables, closables...)
		a.mu.Unlock()
		a.log.Info("filesystem became probeable after startup; probes attached",
			"fs", fsTypeStr(plan.Fs), "fentry", plan.UseFentry)
	}
}

func (a *lateFsAttacher) attach(plan fsAttachPlan) ([]io.Closer, error) {
	toDisable, attachTo := onlyFsPrograms(plan)
	var objects StatsObjects
	if err := a.load(toDisable, attachTo, &objects); err != nil {
		return nil, err
	}
	closables, err := attachFsPlan(&objects, plan)
	if err != nil {
		return nil, errors.Join(err, objects.Close())
	}
	closables = append(closables, &objects)
	if isLocalFs(plan.Fs) && a.startLocalFilter != nil {
		closables = append(closables, a.startLocalFilter())
		a.startLocalFilter = nil
	}
	return closables, nil
}

func (a *lateFsAttacher) Close() error {
	close(a.stop)
	<-a.stopped
	a.mu.Lock()
	defer a.mu.Unlock()
	var errs []error
	for _, c := range a.closables {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// onlyFsPrograms returns the programs to stub, and the attach targets to set,
// so that a load of the stats spec contains nothing but plan's filesystem
// programs.
func onlyFsPrograms(plan fsAttachPlan) (toDisable []string, attachTo map[string]string) {
	fsDisable, attachTo := planFsToDisable([]fsAttachPlan{plan})
	stubbed := make(map[string]bool, len(fsDisable))
	for _, name := range fsDisable {
		stubbed[name] = true
	}
	keep := map[string]bool{}
	for _, name := range fsProgNamesFor(plan.Fs).all() {
		if !stubbed[name] {
			keep[name] = true
		}
	}
	for name := range statsProgramNames() {
		if !keep[name] {
			toDisable = append(toDisable, name)
		}
	}
	return toDisable, attachTo
}

// statsProgramNames lists every program in the stats collection.
var statsProgramNames = sync.OnceValue(func() map[string]bool {
	names := map[string]bool{}
	spec, err := LoadStats()
	if err != nil {
		return names
	}
	for name := range spec.Programs {
		names[name] = true
	}
	return names
})

func isLocalFs(fs FsTypeCode) bool {
	return fs == CodeFsExt4 || fs == CodeFsXFS || fs == CodeFsBtrfs
}

// startLateFsAttacher starts looking for filesystems that become probeable
// after startup. attached lists the filesystems planned at startup.
func startLateFsAttacher(
	log *slog.Logger, cfg *config.EBPFTracer, blockLoad blockLoadPlan, attached []fsAttachPlan, localFilterRunning bool,
	sharedMaps map[string]*ebpf.Map, mu *sync.Mutex, filterMap *ebpf.Map,
) io.Closer {
	a := &lateFsAttacher{
		log: log,
		load: func(toDisable []string, attachTo map[string]string, objects *StatsObjects) error {
			return loadStatsObjects(cfg, blockLoad, toDisable, attachTo, objects, sharedMaps, mu)
		},
		plan:    planPendingFsAttach,
		done:    map[FsTypeCode]bool{},
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	a.attachFn = a.attach
	for _, p := range attached {
		a.done[p.Fs] = true
	}
	if !localFilterRunning {
		a.startLocalFilter = func() io.Closer { return startFsDevFilterRefresher(log, filterMap) }
	}
	go a.run()
	return a
}
