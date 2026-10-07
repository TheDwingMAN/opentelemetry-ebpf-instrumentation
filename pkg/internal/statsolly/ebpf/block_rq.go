// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

const btfTraceBlockRqIssue = "btf_trace_block_rq_issue"

// blockRqIssueRqArgIndex returns the position of the struct request argument of
// the block_rq_issue tracepoint. Kernels before 5.11 pass (request_queue *q,
// request *rq); 5.11 removed q, so rq moved to the first position.
func blockRqIssueRqArgIndex() (uint32, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return 0, fmt.Errorf("loading kernel BTF: %w", err)
	}
	var tp *btf.Typedef
	if err := spec.TypeByName(btfTraceBlockRqIssue, &tp); err != nil {
		return 0, fmt.Errorf("looking up %s: %w", btfTraceBlockRqIssue, err)
	}
	ptr, ok := btf.UnderlyingType(tp.Type).(*btf.Pointer)
	if !ok {
		return 0, fmt.Errorf("%s is not a function pointer", btfTraceBlockRqIssue)
	}
	proto, ok := ptr.Target.(*btf.FuncProto)
	if !ok {
		return 0, fmt.Errorf("%s is not a function pointer", btfTraceBlockRqIssue)
	}
	// The first parameter is the tracepoint context, not a tracepoint argument.
	switch len(proto.Params) {
	case 2:
		return 0, nil
	case 3:
		return 1, nil
	}
	return 0, fmt.Errorf("%s has %d parameters, expected 2 or 3", btfTraceBlockRqIssue, len(proto.Params))
}
