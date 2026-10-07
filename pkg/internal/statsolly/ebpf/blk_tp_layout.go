// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/btf"
)

// blockTracepointLayout is how this kernel passes its arguments to the block
// tracepoints. The kernel version cannot tell: Linux 5.11 dropped the request
// queue argument of the request tracepoints, and 5.10.137 and RHEL 8.6
// backported that change. So the loader reads the prototypes the kernel BTF
// gives each tracepoint (the btf_trace_<name> typedefs) and loads the program
// variants that match them.
type blockTracepointLayout struct {
	// issueLegacy is set when block_rq_issue passes (q, rq) instead of
	// (rq).
	issueLegacy bool
	// completeErrno is set when block_rq_complete passes an int errno
	// instead of a blk_status_t, as kernels before 5.16 did: the programs
	// then read the error as an errno (the const blk_complete_errno).
	completeErrno bool
	// bioQueueLegacy is set when block_bio_queue passes (q, bio) instead of
	// (bio); bioUnknown when its prototype, or that of block_bio_complete
	// (q, bio), could not be told. The bio tracepoints serve stacked volumes
	// only, so an unknown bio prototype never disables the request metrics.
	bioQueueLegacy bool
	bioUnknown     bool
}

// Parameter counts of the btf_trace_<tracepoint> prototypes: the
// tracepoint's private data pointer, then the tracepoint arguments.
const (
	blockRqParams           = 2 // data, rq
	blockRqLegacyParams     = 3 // data, q, rq
	blockRqCompleteParams   = 4 // data, rq, error, nr_bytes
	blockRqCompleteErrorArg = 2
	blockBioQueueParams     = 2 // data, bio
	blockBioQueueLegacy     = 3 // data, q, bio
	blockBioCompleteParams  = 3 // data, q, bio
)

// errUnknownBlockLayout is returned when the kernel BTF lacks a block
// tracepoint prototype, or has one of an unexpected shape.
var errUnknownBlockLayout = errors.New("unknown block tracepoint prototype")

// blockTracepointLayoutFrom reads the layout from the kernel BTF.
func blockTracepointLayoutFrom(spec *btf.Spec) (blockTracepointLayout, error) {
	var layout blockTracepointLayout
	if spec == nil {
		return layout, fmt.Errorf("%w: no kernel BTF", errUnknownBlockLayout)
	}

	var err error
	if layout.issueLegacy, err = requestTracepointLegacy(spec, "block_rq_issue"); err != nil {
		return layout, err
	}

	complete, err := tracepointProto(spec, "block_rq_complete")
	if err != nil {
		return layout, err
	}
	if len(complete.Params) != blockRqCompleteParams {
		return layout, fmt.Errorf("%w: block_rq_complete with %d parameters", errUnknownBlockLayout, len(complete.Params))
	}
	errType, ok := btf.UnderlyingType(complete.Params[blockRqCompleteErrorArg].Type).(*btf.Int)
	if !ok {
		return layout, fmt.Errorf("%w: block_rq_complete error argument is not an integer", errUnknownBlockLayout)
	}
	switch errType.Size {
	case 1: // blk_status_t
	case 4: // int errno
		layout.completeErrno = true
	default:
		return layout, fmt.Errorf("%w: block_rq_complete error argument of %d bytes", errUnknownBlockLayout, errType.Size)
	}

	bioQueue, err := tracepointProto(spec, "block_bio_queue")
	switch {
	case err != nil:
		layout.bioUnknown = true
	case len(bioQueue.Params) == blockBioQueueLegacy:
		layout.bioQueueLegacy = true
	case len(bioQueue.Params) != blockBioQueueParams:
		layout.bioUnknown = true
	}
	// block_bio_complete has passed (q, bio) since Linux 4.8, which dropped
	// its error argument.
	if bioComplete, err := tracepointProto(spec, "block_bio_complete"); err != nil ||
		len(bioComplete.Params) != blockBioCompleteParams {
		layout.bioUnknown = true
	}
	return layout, nil
}

// requestTracepointLegacy reports whether a request tracepoint passes the
// request queue before the request.
func requestTracepointLegacy(spec *btf.Spec, name string) (bool, error) {
	proto, err := tracepointProto(spec, name)
	if err != nil {
		return false, err
	}
	switch len(proto.Params) {
	case blockRqParams:
		return false, nil
	case blockRqLegacyParams:
		return true, nil
	default:
		return false, fmt.Errorf("%w: %s with %d parameters", errUnknownBlockLayout, name, len(proto.Params))
	}
}

// tracepointProto returns the prototype of a tracepoint's probes, from its
// btf_trace_<name> typedef: a pointer to a function whose first parameter is
// the tracepoint's data.
func tracepointProto(spec *btf.Spec, name string) (*btf.FuncProto, error) {
	var typedef *btf.Typedef
	if err := spec.TypeByName("btf_trace_"+name, &typedef); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errUnknownBlockLayout, name, err)
	}
	if ptr, ok := btf.UnderlyingType(typedef.Type).(*btf.Pointer); ok {
		if proto, ok := btf.UnderlyingType(ptr.Target).(*btf.FuncProto); ok {
			return proto, nil
		}
	}
	return nil, fmt.Errorf("%w: btf_trace_%s is not a function pointer", errUnknownBlockLayout, name)
}
