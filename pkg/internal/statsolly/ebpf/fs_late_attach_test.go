// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A late load must contain one filesystem's winning programs and nothing
// else: every other program in the stats collection is stubbed, so it can
// neither attach twice nor load code the plan did not choose.
func TestOnlyFsProgramsKeepsOneFilesystemFamily(t *testing.T) {
	plan := fsAttachPlan{
		Fs: CodeFsNFS, UseFentry: true,
		ReadSym: "nfs_file_read", WriteSym: "nfs_file_write",
		FsyncSym: "nfs_file_fsync", SpliceReadSym: "nfs_file_splice_read",
	}
	names := fsProgNamesFor(CodeFsNFS)
	kept := append(names.fentryPrograms(), names.fentryFsyncPrograms()...)
	kept = append(kept, names.fentrySplicePrograms()...)

	toDisable, attachTo := onlyFsPrograms(plan)

	all := statsProgramNames()
	require.NotEmpty(t, all)
	for name := range all {
		if slices.Contains(kept, name) {
			assert.NotContains(t, toDisable, name, "the plan's program must load")
		} else {
			assert.Contains(t, toDisable, name, "every other program must be stubbed")
		}
	}
	assert.Equal(t, "nfs_file_read", attachTo[names.FentryRead])
	assert.Equal(t, "nfs_file_fsync", attachTo[names.FentryFsync])
	assert.Equal(t, "nfs_file_splice_read", attachTo[names.FentrySpliceRead])
	assert.Len(t, attachTo, len(kept))
}

type closeCounter struct{ n *int }

func (c closeCounter) Close() error { *c.n++; return nil }

// A filesystem that appears after startup is attached exactly once; the ones
// attached at startup are never attached again, and one that fails is retried
// a few times, then left alone.
func TestLateFsAttacherAttachesNewFilesystemsOnce(t *testing.T) {
	var planned []fsAttachPlan
	var attempts []FsTypeCode
	closed := 0
	a := &lateFsAttacher{
		log:  slog.Default(),
		plan: func(map[FsTypeCode]bool) []fsAttachPlan { return planned },
		done: map[FsTypeCode]bool{CodeFsXFS: true}, // attached at startup
		attachFn: func(p fsAttachPlan) ([]io.Closer, error) {
			attempts = append(attempts, p.Fs)
			if p.Fs == CodeFsCIFS {
				return nil, errors.New("attach failed")
			}
			return []io.Closer{closeCounter{&closed}}, nil
		},
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}

	// Startup state: only xfs is probeable.
	planned = []fsAttachPlan{{Fs: CodeFsXFS}}
	a.attachNew()
	assert.Empty(t, attempts)

	// nfs and cifs load later.
	planned = []fsAttachPlan{{Fs: CodeFsXFS}, {Fs: CodeFsNFS}, {Fs: CodeFsCIFS}}
	a.attachNew()
	assert.Equal(t, []FsTypeCode{CodeFsNFS, CodeFsCIFS}, attempts)

	// cifs is retried on the following ticks, then given up on.
	for range fsLateAttachTries + 2 {
		a.attachNew()
	}
	assert.Equal(t, []FsTypeCode{CodeFsNFS, CodeFsCIFS, CodeFsCIFS, CodeFsCIFS}, attempts)

	close(a.stopped) // run() was never started
	require.NoError(t, a.Close())
	assert.Equal(t, 1, closed, "the late nfs attachment is closed with the attacher")
}
