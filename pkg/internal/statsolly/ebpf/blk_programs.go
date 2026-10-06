// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// Block program names. Every program is compiled into the stats collection;
// the ones a load does not use are stubbed out before it (fixupSpec).
const (
	progObiStatsTpBlockRqIssue    = "obi_stats_tp_block_rq_issue"
	progObiStatsTpBlockRqComplete = "obi_stats_tp_block_rq_complete"

	progObiStatsRawTpBlockRqIssue       = "obi_stats_raw_tp_block_rq_issue"
	progObiStatsRawTpBlockRqIssueLegacy = "obi_stats_raw_tp_block_rq_issue_legacy"
	progObiStatsRawTpBlockRqComplete    = "obi_stats_raw_tp_block_rq_complete"

	progObiStatsTpBtfBlockRqIssue       = "obi_stats_tp_btf_block_rq_issue"
	progObiStatsTpBtfBlockRqIssueLegacy = "obi_stats_tp_btf_block_rq_issue_legacy"
	progObiStatsTpBtfBlockRqComplete    = "obi_stats_tp_btf_block_rq_complete"
)

// blockAttach is how the block request tracepoints are attached.
type blockAttach uint8

const (
	blockAttachNone blockAttach = iota
	// blockAttachClassic: tracefs tracepoints, requests keyed by (dev,
	// sector), for kernels whose BTF cannot decode a request.
	blockAttachClassic
	// blockAttachRawTp: raw tracepoints reading the request through
	// bpf_probe_read_kernel.
	blockAttachRawTp
	// blockAttachTpBtf: BTF-typed raw tracepoints reading the request with
	// direct loads, the default (S0-f: 101.8 ns vs 136.7 ns per completion
	// for raw_tp).
	blockAttachTpBtf
)

func (a blockAttach) String() string {
	switch a {
	case blockAttachClassic:
		return "tracepoint"
	case blockAttachRawTp:
		return "raw_tp"
	case blockAttachTpBtf:
		return "tp_btf"
	default:
		return "none"
	}
}

// blockProgramSet is one way to attach the block programs: its program for
// each tracepoint. There is no insert program: the queue wait is read from
// the request at issue.
type blockProgramSet struct {
	attach          blockAttach
	issue, complete string
	issueTP, compTP string
}

func (s blockProgramSet) programs() []string {
	var out []string
	for _, p := range []string{s.complete, s.issue} {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func classicBlockPrograms() blockProgramSet {
	s := blockProgramSet{
		attach:   blockAttachClassic,
		issue:    progObiStatsTpBlockRqIssue,
		complete: progObiStatsTpBlockRqComplete,
		issueTP:  TracepointBlockRqIssue, compTP: TracepointBlockRqComplete,
	}
	return s
}

func rawTpBlockPrograms(layout blockTracepointLayout) blockProgramSet {
	s := blockProgramSet{
		attach:   blockAttachRawTp,
		issue:    pick(layout.issueLegacy, progObiStatsRawTpBlockRqIssueLegacy, progObiStatsRawTpBlockRqIssue),
		complete: progObiStatsRawTpBlockRqComplete,
		issueTP:  RawTracepointBlockRqIssue, compTP: RawTracepointBlockRqComplete,
	}
	return s
}

func tpBtfBlockPrograms(layout blockTracepointLayout) blockProgramSet {
	s := blockProgramSet{
		attach:   blockAttachTpBtf,
		issue:    pick(layout.issueLegacy, progObiStatsTpBtfBlockRqIssueLegacy, progObiStatsTpBtfBlockRqIssue),
		complete: progObiStatsTpBtfBlockRqComplete,
		issueTP:  RawTracepointBlockRqIssue, compTP: RawTracepointBlockRqComplete,
	}
	return s
}

func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

func allBlockProgramNames() []string {
	return []string{
		progObiStatsTpBlockRqIssue, progObiStatsTpBlockRqComplete,
		progObiStatsRawTpBlockRqIssue, progObiStatsRawTpBlockRqIssueLegacy, progObiStatsRawTpBlockRqComplete,
		progObiStatsTpBtfBlockRqIssue, progObiStatsTpBtfBlockRqIssueLegacy, progObiStatsTpBtfBlockRqComplete,
	}
}

// blockLoadStage is one attempt at loading the stats collection with block
// programs: the program sets it loads, in the order they are tried at
// attach time.
type blockLoadStage struct {
	sets []blockProgramSet
}

func (s blockLoadStage) programs() []string {
	var out []string
	for _, set := range s.sets {
		out = append(out, set.programs()...)
	}
	return out
}

// toDisable is every block program the stage does not load.
func (s blockLoadStage) toDisable() []string {
	return programsNotIn(allBlockProgramNames(), s.programs())
}

// programsNotIn returns the programs of all that are not in keep.
func programsNotIn(all, keep []string) []string {
	var out []string
	for _, p := range all {
		if !slices.Contains(keep, p) {
			out = append(out, p)
		}
	}
	return out
}

// storagePlan is how the block programs are loaded on this kernel: the
// stages tried in order, then none. The filesystem programs are not in the
// stats spec; they load as collections of their own (fs_tracer.go).
type storagePlan struct {
	stages []blockLoadStage
	layout blockTracepointLayout
}

// planStorage chooses the block programs for this kernel. Where the BTF
// decodes a request and gives the tracepoint prototypes, the first stage
// loads the tp_btf programs with the raw_tp ones next to them (both verified
// in one load, so an attach failure of the first can fall back to the
// second without reloading the collection), and the second the raw_tp ones
// alone, for a kernel that rejects the tp_btf programs. Elsewhere the
// classic tracepoints, which need tracefs.
func planStorage(block bool, kernel *btf.Spec, log *slog.Logger) storagePlan {
	var plan storagePlan
	if !block {
		return plan
	}
	if !blockRawTracepointCapableWith(kernel) {
		plan.stages = []blockLoadStage{{sets: []blockProgramSet{classicBlockPrograms()}}}
		return plan
	}
	layout, err := blockTracepointLayoutFrom(kernel)
	if err != nil {
		log.Warn("can't tell the block tracepoints' arguments from the kernel BTF;"+
			" using the classic block tracepoints, which need tracefs", "error", err)
		plan.stages = []blockLoadStage{{sets: []blockProgramSet{classicBlockPrograms()}}}
		return plan
	}
	plan.layout = layout
	tpBtf, rawTp := tpBtfBlockPrograms(layout), rawTpBlockPrograms(layout)
	plan.stages = []blockLoadStage{
		{sets: []blockProgramSet{tpBtf, rawTp}},
		{sets: []blockProgramSet{rawTp}},
	}
	return plan
}

// blockQueueUnsupported says why obi.stat.disk.queue.duration can't be fed on
// this kernel, or "" when it can. The queue time comes from rq->start_time_ns,
// read at block_rq_issue by the request-keyed programs, and used only where
// the request flags say it is fresh; those flags are CO-RE resolved from
// enum rqf_flags, which a kernel without it (older kernels and the RHEL 8
// family, where they are macros) does not have. Hard-coding the bit numbers
// per kernel version would risk silently wrong data, so no queue time is
// recorded there. The classic tracepoints key requests by (dev, sector) and
// never read the field.
func blockQueueUnsupported(block bool, storage storagePlan, kernel *btf.Spec) string {
	if !block || len(storage.stages) == 0 {
		return ""
	}
	if storage.stages[0].sets[0].attach == blockAttachClassic {
		return "the classic block tracepoints in use don't read the request's start time"
	}
	if kernel == nil {
		return "the kernel has no BTF"
	}
	if _, err := kernel.AnyTypeByName("rqf_flags"); err != nil {
		return "the kernel BTF has no enum rqf_flags, so the freshness of the request's start time can't be told"
	}
	return ""
}

// firstLoadDisable is what the first load stubs out: every block program
// when block metrics are off.
func (p storagePlan) firstLoadDisable() []string {
	if len(p.stages) == 0 {
		return allBlockProgramNames()
	}
	return p.stages[0].toDisable()
}

// loadWithBlockFallback loads the stats spec with the block programs of each
// stage in turn, and last with none, so that a kernel that rejects one set of
// block programs degrades to the next rather than losing every stat metric.
// It returns the stage that loaded, len(stages) when the block programs are
// off. The filesystem programs are not part of this load, so a filesystem the
// kernel rejects can never take block or TCP metrics down with it.
func loadWithBlockFallback(
	load func(toDisable []string) error,
	base []string,
	stages []blockLoadStage,
	log *slog.Logger,
) (int, error) {
	for i, stage := range stages {
		err := load(append(slices.Clone(base), stage.toDisable()...))
		if err == nil {
			return i, nil
		}
		next := "no block programs"
		if i+1 < len(stages) {
			next = strings.Join(stages[i+1].setNames(), ", ")
		}
		log.Warn("loading the stats eBPF spec failed with the block programs of "+
			strings.Join(stage.setNames(), ", ")+"; retrying with "+next+" (likely kernel incompatibility)",
			"error", err)
	}
	return len(stages), load(append(slices.Clone(base), allBlockProgramNames()...))
}

func (s blockLoadStage) setNames() []string {
	names := make([]string, len(s.sets))
	for i, set := range s.sets {
		names[i] = set.attach.String()
	}
	return names
}

// attachBlockSets attaches the first program set that attaches whole. On a
// failure it detaches what it managed of that set and tries the next; when
// none attaches, block metrics are off and the rest of the agent keeps
// running.
func attachBlockSets(
	sets []blockProgramSet,
	attach func(set blockProgramSet) ([]io.Closer, error),
	log *slog.Logger,
) ([]io.Closer, blockAttach) {
	for i, set := range sets {
		links, err := attach(set)
		if err == nil {
			return links, set.attach
		}
		if i+1 < len(sets) {
			log.Warn("failed block tracepoint attachment; falling back to "+sets[i+1].attach.String(),
				"attach", set.attach, "error", err)
			continue
		}
		log.Warn("failed block tracepoint attachment; disabling storage block metrics",
			"attach", set.attach, "error", err)
	}
	return nil, blockAttachNone
}

// attachBlockProgramSet attaches one set, completion first: a request issued
// before the issue program attached has no in-flight entry and its
// completion is ignored, while issue attached first would leave behind the
// entries of requests that complete before the completion program attaches.
func attachBlockProgramSet(programs map[string]*ebpf.Program, set blockProgramSet) ([]io.Closer, error) {
	var links []io.Closer
	for _, p := range []struct{ prog, tp string }{
		{set.complete, set.compTP}, {set.issue, set.issueTP},
	} {
		if p.prog == "" {
			continue
		}
		prog := programs[p.prog]
		if prog == nil {
			closeAll(links)
			return nil, fmt.Errorf("block program %s was not loaded", p.prog)
		}
		l, err := attachBlockProgram(set.attach, prog, p.tp)
		if err != nil {
			closeAll(links)
			return nil, fmt.Errorf("%s %s: %w", set.attach, p.tp, err)
		}
		links = append(links, l)
	}
	return links, nil
}

func attachBlockProgram(attach blockAttach, prog *ebpf.Program, tracepoint string) (link.Link, error) {
	switch attach {
	case blockAttachTpBtf:
		return link.AttachTracing(link.TracingOptions{Program: prog})
	case blockAttachRawTp:
		return link.AttachRawTracepoint(link.RawTracepointOptions{Name: tracepoint, Program: prog})
	case blockAttachClassic:
		group, name, _ := strings.Cut(tracepoint, "/")
		return link.Tracepoint(group, name, prog, nil)
	default:
		return nil, errors.New("no block attach mode")
	}
}

// blockPrograms indexes the loaded block programs by name.
func blockPrograms(p *StatsPrograms) map[string]*ebpf.Program {
	return map[string]*ebpf.Program{
		progObiStatsTpBlockRqIssue:          p.ObiStatsTpBlockRqIssue,
		progObiStatsTpBlockRqComplete:       p.ObiStatsTpBlockRqComplete,
		progObiStatsRawTpBlockRqIssue:       p.ObiStatsRawTpBlockRqIssue,
		progObiStatsRawTpBlockRqIssueLegacy: p.ObiStatsRawTpBlockRqIssueLegacy,
		progObiStatsRawTpBlockRqComplete:    p.ObiStatsRawTpBlockRqComplete,
		progObiStatsTpBtfBlockRqIssue:       p.ObiStatsTpBtfBlockRqIssue,
		progObiStatsTpBtfBlockRqIssueLegacy: p.ObiStatsTpBtfBlockRqIssueLegacy,
		progObiStatsTpBtfBlockRqComplete:    p.ObiStatsTpBtfBlockRqComplete,
	}
}
