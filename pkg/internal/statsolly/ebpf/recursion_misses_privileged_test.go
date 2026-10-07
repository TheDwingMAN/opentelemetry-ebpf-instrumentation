// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// poll reads the recursion_misses of a loaded program without failing, on
// kernels that fill it in (5.12+) as on those that read 0, and reports only
// growth: nothing for a program that never recursed.
func TestRecursionMissesPollsLoadedProgram(t *testing.T) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	require.NoError(t, err)
	defer prog.Close()

	stats, err := prog.Stats()
	require.NoError(t, err)
	assert.Zero(t, stats.RecursionMisses)

	var r recursionMisses
	metrics := &recursionRecorder{misses: map[string]uint64{}}
	r.poll(map[string]*ebpf.Program{"prog": prog, "absent": nil}, metrics)
	assert.Empty(t, metrics.misses)
}
