// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

// recursionMissReporter is implemented by what holds loaded storage programs
// and can report their recursion misses to the internal metrics.
type recursionMissReporter interface {
	pollRecursionMisses(metrics imetrics.Reporter)
}

// recursionMisses keeps the recursion_misses each program last reported: the
// kernel's count is cumulative for the program's lifetime.
type recursionMisses struct {
	prev map[string]uint64
}

// poll reports as the obi.bpf.storage.program.recursion.misses internal
// metric the executions the kernel skipped of each program in progs since
// the last call (spec 2.0): another eBPF program was already running on the
// CPU, so the event never reached this one. The count is read from the
// program's info, once per call and not per event. Kernels before 5.12 do
// not fill it in, and read as 0: nothing is exported. A nil program (not
// loaded) or one whose info cannot be read is skipped.
func (r *recursionMisses) poll(progs map[string]*ebpf.Program, metrics imetrics.Reporter) {
	for name, p := range progs {
		if p == nil {
			continue
		}
		stats, err := p.Stats()
		if err != nil || stats.RecursionMisses <= r.prev[name] {
			continue
		}
		if r.prev == nil {
			r.prev = map[string]uint64{}
		}
		metrics.BpfStorageRecursionMisses(name, stats.RecursionMisses-r.prev[name])
		r.prev[name] = stats.RecursionMisses
	}
}
