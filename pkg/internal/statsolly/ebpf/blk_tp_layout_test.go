// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"log/slog"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The block tracepoint prototypes, as the btf_trace_<name> typedefs of the
// kernels OBI meets give them.
func TestBlockTracepointLayoutFrom(t *testing.T) {
	var (
		voidPtr     = &btf.Pointer{Target: &btf.Void{}}
		request     = &btf.Pointer{Target: &btf.Struct{Name: "request"}}
		queue       = &btf.Pointer{Target: &btf.Struct{Name: "request_queue"}}
		bio         = &btf.Pointer{Target: &btf.Struct{Name: "bio"}}
		u8          = &btf.Int{Name: "u8", Size: 1}
		blkSts      = &btf.Typedef{Name: "blk_status_t", Type: u8}
		errnoInt    = &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
		unsignedInt = &btf.Int{Name: "unsigned int", Size: 4}
		u64         = &btf.Int{Name: "long long unsigned int", Size: 8}
	)
	tracepoint := func(name string, args ...btf.Type) btf.Type {
		params := []btf.FuncParam{{Type: voidPtr}}
		for _, a := range args {
			params = append(params, btf.FuncParam{Type: a})
		}
		return &btf.Typedef{Name: "btf_trace_" + name, Type: &btf.Pointer{
			Target: &btf.FuncProto{Return: &btf.Void{}, Params: params},
		}}
	}
	specOf := func(types ...btf.Type) *btf.Spec {
		b, err := btf.NewBuilder(types, nil)
		require.NoError(t, err)
		spec, err := b.Spec()
		require.NoError(t, err)
		return spec
	}
	// RHEL 9 (5.14.0-687, -749) and upstream 5.16+.
	modern := []btf.Type{
		tracepoint("block_rq_issue", request),
		tracepoint("block_rq_complete", request, blkSts, unsignedInt),
		tracepoint("block_bio_queue", bio),
		tracepoint("block_bio_complete", queue, bio),
	}
	// Upstream 5.11 to 5.15: the queue argument is gone, the error still an
	// errno.
	errnoKernel := []btf.Type{
		tracepoint("block_rq_issue", request),
		tracepoint("block_rq_complete", request, errnoInt, unsignedInt),
		tracepoint("block_bio_queue", bio),
		tracepoint("block_bio_complete", queue, bio),
	}
	// Upstream before 5.11 (5.8 to 5.10.136).
	legacy := []btf.Type{
		tracepoint("block_rq_issue", queue, request),
		tracepoint("block_rq_complete", request, errnoInt, unsignedInt),
		tracepoint("block_bio_queue", queue, bio),
		tracepoint("block_bio_complete", queue, bio),
	}
	// 5.10.137: the request tracepoints backported, block_bio_queue not.
	backported := []btf.Type{
		tracepoint("block_rq_issue", request),
		tracepoint("block_rq_complete", request, errnoInt, unsignedInt),
		tracepoint("block_bio_queue", queue, bio),
		tracepoint("block_bio_complete", queue, bio),
	}
	without := func(types []btf.Type, name string) []btf.Type {
		var out []btf.Type
		for _, typ := range types {
			if typ.TypeName() != "btf_trace_"+name {
				out = append(out, typ)
			}
		}
		return out
	}
	with := func(types []btf.Type, typ btf.Type) []btf.Type {
		return append(without(types, typ.TypeName()[len("btf_trace_"):]), typ)
	}

	for _, tc := range []struct {
		name  string
		spec  *btf.Spec
		want  blockTracepointLayout
		error bool
	}{
		{name: "RHEL 9 and 5.16+: (rq), blk_status_t", spec: specOf(modern...)},
		{
			name: "5.11 to 5.15: (rq), int errno",
			spec: specOf(errnoKernel...),
			want: blockTracepointLayout{completeErrno: true},
		},
		{
			name: "before 5.11: (q, rq), int errno, (q, bio)",
			spec: specOf(legacy...),
			want: blockTracepointLayout{issueLegacy: true, completeErrno: true, bioQueueLegacy: true},
		},
		{
			name: "5.10.137: request tracepoints backported, bio queue legacy",
			spec: specOf(backported...),
			want: blockTracepointLayout{completeErrno: true, bioQueueLegacy: true},
		},
		{
			name: "no block_bio_queue prototype: the bio side only is unknown",
			spec: specOf(without(modern, "block_bio_queue")...),
			want: blockTracepointLayout{bioUnknown: true},
		},
		{
			name: "a block_bio_queue of another shape: the bio side only is unknown",
			spec: specOf(with(modern, tracepoint("block_bio_queue", queue, bio, u64))...),
			want: blockTracepointLayout{bioUnknown: true},
		},
		{
			name: "no block_bio_complete prototype: the bio side only is unknown",
			spec: specOf(without(modern, "block_bio_complete")...),
			want: blockTracepointLayout{bioUnknown: true},
		},
		{
			name: "a block_bio_complete with an error argument (before 4.8): the bio side only is unknown",
			spec: specOf(with(modern, tracepoint("block_bio_complete", queue, bio, errnoInt))...),
			want: blockTracepointLayout{bioUnknown: true},
		},
		{name: "no kernel BTF", spec: nil, error: true},
		{name: "no block_rq_issue prototype", spec: specOf(without(modern, "block_rq_issue")...), error: true},
		{name: "no block_rq_complete prototype", spec: specOf(without(modern, "block_rq_complete")...), error: true},
		{
			name:  "block_rq_issue with four arguments",
			spec:  specOf(with(modern, tracepoint("block_rq_issue", queue, request, u64))...),
			error: true,
		},
		{
			name:  "block_rq_complete without nr_bytes",
			spec:  specOf(with(modern, tracepoint("block_rq_complete", request, blkSts))...),
			error: true,
		},
		{
			name:  "block_rq_complete with a pointer for the error",
			spec:  specOf(with(modern, tracepoint("block_rq_complete", request, request, unsignedInt))...),
			error: true,
		},
		{
			name:  "block_rq_complete with an 8-byte error",
			spec:  specOf(with(modern, tracepoint("block_rq_complete", request, u64, unsignedInt))...),
			error: true,
		},
		{
			name:  "btf_trace typedef that is not a function pointer",
			spec:  specOf(with(modern, &btf.Typedef{Name: "btf_trace_block_rq_issue", Type: u64})...),
			error: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := blockTracepointLayoutFrom(tc.spec)
			if tc.error {
				require.ErrorIs(t, err, errUnknownBlockLayout)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// The loader tries tp_btf with raw_tp loaded next to it, then raw_tp alone,
// in the variants the kernel's prototypes take; the classic tracepoints only
// where the BTF cannot decode a request or give its tracepoint prototypes.
func TestPlanStorage(t *testing.T) {
	quietLog := slog.New(slog.DiscardHandler)
	var (
		voidPtr     = &btf.Pointer{Target: &btf.Void{}}
		gendisk     = &btf.Pointer{Target: &btf.Struct{Name: "gendisk"}}
		queue       = &btf.Struct{Name: "request_queue", Members: []btf.Member{{Name: "disk", Type: gendisk}}}
		request     = &btf.Struct{Name: "request", Members: []btf.Member{{Name: "q", Type: &btf.Pointer{Target: queue}}}}
		rqPtr       = &btf.Pointer{Target: request}
		qPtr        = &btf.Pointer{Target: queue}
		errno       = &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
		unsignedInt = &btf.Int{Name: "unsigned int", Size: 4}
	)
	tracepoint := func(name string, args ...btf.Type) btf.Type {
		params := []btf.FuncParam{{Type: voidPtr}}
		for _, a := range args {
			params = append(params, btf.FuncParam{Type: a})
		}
		return &btf.Typedef{Name: "btf_trace_" + name, Type: &btf.Pointer{
			Target: &btf.FuncProto{Return: &btf.Void{}, Params: params},
		}}
	}
	specOf := func(types ...btf.Type) *btf.Spec {
		b, err := btf.NewBuilder(types, nil)
		require.NoError(t, err)
		spec, err := b.Spec()
		require.NoError(t, err)
		return spec
	}
	legacyKernel := specOf(queue, request,
		tracepoint("block_rq_issue", qPtr, rqPtr),
		tracepoint("block_rq_complete", rqPtr, errno, unsignedInt))

	t.Run("block off: nothing to load", func(t *testing.T) {
		plan := planStorage(false, legacyKernel, quietLog)
		assert.Empty(t, plan.stages)
		assert.ElementsMatch(t, allBlockProgramNames(), plan.firstLoadDisable())
	})

	t.Run("legacy prototypes: the legacy variants of tp_btf, then raw_tp", func(t *testing.T) {
		plan := planStorage(true, legacyKernel, quietLog)
		require.Len(t, plan.stages, 2)
		assert.Equal(t, []string{
			progObiStatsTpBtfBlockRqComplete, progObiStatsTpBtfBlockRqIssueLegacy,
			progObiStatsRawTpBlockRqComplete, progObiStatsRawTpBlockRqIssueLegacy,
		}, plan.stages[0].programs())
		assert.Equal(t, []string{
			progObiStatsRawTpBlockRqComplete, progObiStatsRawTpBlockRqIssueLegacy,
		}, plan.stages[1].programs())
		assert.True(t, plan.layout.completeErrno)
	})

	t.Run("unknown prototypes: classic tracepoints", func(t *testing.T) {
		plan := planStorage(true, specOf(queue, request), quietLog)
		require.Len(t, plan.stages, 1)
		assert.Equal(t, []string{progObiStatsTpBlockRqComplete, progObiStatsTpBlockRqIssue},
			plan.stages[0].programs())
	})

	t.Run("no BTF: classic tracepoints", func(t *testing.T) {
		plan := planStorage(true, nil, quietLog)
		require.Len(t, plan.stages, 1)
		assert.Equal(t, blockAttachClassic, plan.stages[0].sets[0].attach)
	})
}
