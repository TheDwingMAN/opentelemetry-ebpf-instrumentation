// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyscallWrapperPrefix(t *testing.T) {
	assert.Equal(t, "__x64_sys_", syscallWrapperPrefix("amd64"))
	assert.Equal(t, "__arm64_sys_", syscallWrapperPrefix("arm64"))
	// Everything else falls back to the x86_64 prefix: GOARCH is one of a
	// known, fixed set, and OBI only ships amd64 and arm64 builds.
	assert.Equal(t, "__x64_sys_", syscallWrapperPrefix("riscv64"))
}

// everyFound is a fake probeable func (planFsSyncWith's second argument)
// that reports every requested symbol present.
func everyFound(wanted map[string]bool) map[string]bool {
	found := make(map[string]bool, len(wanted))
	for sym := range wanted {
		found[sym] = true
	}
	return found
}

func noneFound(map[string]bool) map[string]bool { return map[string]bool{} }

func TestPlanFsSyncWith(t *testing.T) {
	t.Run("every symbol present, fentry capable", func(t *testing.T) {
		plan := planFsSyncWith("amd64", everyFound, func(string) bool { return true })
		assert.Equal(t, "__x64_sys_syncfs", plan.SyncfsSym)
		assert.True(t, plan.UseFentrySyncfs)
		assert.Equal(t, "__x64_sys_sync_file_range", plan.SyncFileRangeSym)
		assert.True(t, plan.UseFentrySyncFileRange)
		assert.Equal(t, "__x64_sys_sync", plan.SyncSym, "sync(2) is named here regardless of fentryCapable")
	})

	t.Run("arm64 naming, no module BTF: forced to kprobes", func(t *testing.T) {
		// 2.4, S0-e: fentry on RHCOS aarch64 is UNVERIFIED, so a kernel that
		// cannot prove fentry capability must fall back to kprobes, exactly
		// as if this were an arm64 host without the wrapper's BTF.
		plan := planFsSyncWith("arm64", everyFound, func(string) bool { return false })
		assert.Equal(t, "__arm64_sys_syncfs", plan.SyncfsSym)
		assert.False(t, plan.UseFentrySyncfs)
		assert.Equal(t, "__arm64_sys_sync_file_range", plan.SyncFileRangeSym)
		assert.False(t, plan.UseFentrySyncFileRange)
		assert.Equal(t, "__arm64_sys_sync", plan.SyncSym)
	})

	t.Run("sync wrapper not traceable: its body is probed", func(t *testing.T) {
		only := func(syms ...string) func(map[string]bool) map[string]bool {
			return func(wanted map[string]bool) map[string]bool {
				found := map[string]bool{}
				for _, s := range syms {
					found[s] = wanted[s]
				}
				return found
			}
		}
		plan := planFsSyncWith("amd64", only("__do_sys_sync"), func(string) bool { return true })
		assert.Equal(t, "__do_sys_sync", plan.SyncSym)
		plan = planFsSyncWith("amd64", only("__do_sys_sync", "__x64_sys_sync"), func(string) bool { return true })
		assert.Equal(t, "__x64_sys_sync", plan.SyncSym, "the wrapper wins when both are traceable")
	})

	t.Run("no syscall wrappers found: nothing probeable", func(t *testing.T) {
		plan := planFsSyncWith("amd64", noneFound, func(string) bool { return true })
		assert.Empty(t, plan.SyncfsSym)
		assert.Empty(t, plan.SyncFileRangeSym)
		assert.Empty(t, plan.SyncSym)
	})

	t.Run("syncfs missing, sync_file_range present: independent per syscall", func(t *testing.T) {
		found := func(wanted map[string]bool) map[string]bool {
			out := everyFound(wanted)
			delete(out, "__x64_sys_syncfs")
			return out
		}
		plan := planFsSyncWith("amd64", found, func(string) bool { return true })
		assert.Empty(t, plan.SyncfsSym, "a missing symbol is not planned")
		assert.Equal(t, "__x64_sys_sync_file_range", plan.SyncFileRangeSym)
		assert.True(t, plan.UseFentrySyncFileRange)
	})
}

func TestFsSyncPlanDemoteToKprobe(t *testing.T) {
	plan := fsSyncPlan{
		SyncfsSym: "syncfs", UseFentrySyncfs: true,
		SyncFileRangeSym: "sync_file_range", UseFentrySyncFileRange: true,
		SyncSym: "sync",
	}
	demoted := plan.demoteToKprobe()
	assert.False(t, demoted.UseFentrySyncfs)
	assert.False(t, demoted.UseFentrySyncFileRange)
	assert.Equal(t, "syncfs", demoted.SyncfsSym, "the symbol itself is unchanged, only the attach kind")
	assert.Equal(t, "sync_file_range", demoted.SyncFileRangeSym)
	assert.Equal(t, "sync", demoted.SyncSym)
}

// Every exit (kretprobe/fexit) probe comes before its entry probe, same
// rule as fsPlanProbes and for the same reason: attachSyncPair attaches the
// return probe first.
func TestFsSyncPlanProbesOrder(t *testing.T) {
	plan := fsSyncPlan{
		SyncfsSym: "__x64_sys_syncfs", UseFentrySyncfs: true,
		SyncFileRangeSym: "__x64_sys_sync_file_range", UseFentrySyncFileRange: false,
		SyncSym: "__x64_sys_sync",
	}
	probes := fsSyncPlanProbes(plan)
	require := assert.New(t)
	require.Len(probes, 6, "3 syscalls x (entry, exit)")

	byProg := make(map[string]fsProbe, len(probes))
	for _, p := range probes {
		byProg[p.prog] = p
	}

	pairs := []struct {
		entry, exit string
		fentry      bool
	}{
		{progObiStatsFentrySyncfs, progObiStatsFexitSyncfs, true},
		{progObiStatsKprobeSyncFileRange, progObiStatsKretprobeSyncFileRange, false},
		{progObiStatsKprobeSync, progObiStatsKretprobeSync, false},
	}
	for _, pair := range pairs {
		entryIdx, exitIdx := -1, -1
		for i, p := range probes {
			if p.prog == pair.entry {
				entryIdx = i
			}
			if p.prog == pair.exit {
				exitIdx = i
			}
		}
		require.GreaterOrEqual(entryIdx, 0, pair.entry)
		require.GreaterOrEqual(exitIdx, 0, pair.exit)
		require.Less(exitIdx, entryIdx, "%s (exit) must attach before %s (entry)", pair.exit, pair.entry)
		require.True(byProg[pair.exit].exit)
		require.False(byProg[pair.entry].exit)
	}
}

// pollMissedKretprobes must skip every link that is not a kretprobe-mode
// exit probe without panicking: entry probes, fentry/fexit links (not
// link.Link-backed kprobes here, but a plain io.Closer stands in for "not a
// kprobe link" just as well, since the type assertion is what matters), and
// an empty set.
func TestPollMissedKretprobesSkipsNonKretprobeLinks(t *testing.T) {
	probes := []fsProbe{
		{prog: "entry", sym: "sym"},
		{prog: "exit", sym: "sym", exit: true},
	}
	// Neither closer implements link.Link (it is sealed against external
	// implementations by its unexported isLink method), so there is
	// nothing to query: pollMissedKretprobes must return 0, not panic on
	// the failed type assertion.
	links := []io.Closer{ioCloserFunc(func() error { return nil }), ioCloserFunc(func() error { return nil })}
	prev := make([]uint64, len(links))
	assert.Equal(t, uint64(0), pollMissedKretprobes(probes, links, prev))

	assert.Equal(t, uint64(0), pollMissedKretprobes(nil, nil, nil), "empty input")
}

// ioCloserFunc adapts a func() error to io.Closer, for a minimal fake that
// is deliberately not a link.Link (link.Link seals external
// implementations via its unexported isLink method, so it cannot be faked
// directly; pollMissedKretprobes's safe handling of a non-link.Link closer
// is what this test exercises).
type ioCloserFunc func() error

func (f ioCloserFunc) Close() error { return f() }

// Without tracefs a kretprobe cannot request extra instances: the fallback to
// the kernel default is logged once per process at Info, not on every
// attach (v2 logged each at Debug).
func TestAttachKretprobeFallbackLogsOnce(t *testing.T) {
	fsKretprobeFallbackLogged = sync.Once{}
	t.Cleanup(func() { fsKretprobeFallbackLogged = sync.Once{} })

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	// A nil program fails both the maxactive and the default attempt, which
	// is all the log-once behavior needs.
	for range 3 {
		_, err := attachKretprobe(log, "__x64_sys_sync", nil)
		require.Error(t, err)
	}
	assert.Equal(t, 1, strings.Count(buf.String(), "kretprobes cannot request extra instances"))
}

// sync(2) always keeps its start in fs_start; syncfs and sync_file_range do
// only on kprobes, or on fentry without task storage.
func TestSyncKeepsHashStarts(t *testing.T) {
	fentryOnly := fsSyncPlan{
		SyncfsSym: "syncfs", UseFentrySyncfs: true,
		SyncFileRangeSym: "sfr", UseFentrySyncFileRange: true,
	}
	assert.False(t, syncKeepsHashStarts(fentryOnly, true))
	assert.True(t, syncKeepsHashStarts(fentryOnly, false), "no task storage")
	withSync := fentryOnly
	withSync.SyncSym = "sync"
	assert.True(t, syncKeepsHashStarts(withSync, true), "sync(2) is a kprobe")
	assert.True(t, syncKeepsHashStarts(fentryOnly.demoteToKprobe(), true))
	assert.False(t, syncKeepsHashStarts(fsSyncPlan{}, false))
}
