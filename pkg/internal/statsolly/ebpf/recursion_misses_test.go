// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"io"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

type recursionRecorder struct {
	imetrics.NoopReporter
	misses map[string]uint64
}

func (r *recursionRecorder) BpfStorageRecursionMisses(program string, misses uint64) {
	r.misses[program] += misses
}

// missReporterCloser is an attachment that reports one recursion miss per poll.
type missReporterCloser struct {
	io.Closer
	name string
}

func (m missReporterCloser) pollRecursionMisses(metrics imetrics.Reporter) {
	metrics.BpfStorageRecursionMisses(m.name, 1)
}

// maintain reports the recursion misses of the filesystem attachments and of
// the sync one, and skips an attachment that cannot report any.
func TestFsAttacherReportsRecursionMisses(t *testing.T) {
	n := newFakeNode()
	a := n.attacher()
	metrics := &recursionRecorder{misses: map[string]uint64{}}
	a.metrics = metrics
	a.attached[fsPlanKey{}] = missReporterCloser{Closer: &fakeCloser{}, name: "fs_prog"}
	a.attached[fsPlanKey{Fs: CodeFsXFS}] = &fakeCloser{}
	a.syncCloser = missReporterCloser{Closer: &fakeCloser{}, name: "sync_prog"}

	a.maintain()
	a.maintain()
	assert.Equal(t, map[string]uint64{"fs_prog": 2, "sync_prog": 2}, metrics.misses)
	closeAttacher(t, a)
}

// A program that is not loaded (nil) reports nothing and does not panic.
func TestRecursionMissesSkipsNilPrograms(t *testing.T) {
	var r recursionMisses
	metrics := &recursionRecorder{misses: map[string]uint64{}}
	r.poll(map[string]*ebpf.Program{"absent": nil}, metrics)
	assert.Empty(t, metrics.misses)
}
