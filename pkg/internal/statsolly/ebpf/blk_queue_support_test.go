// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlockQueueUnsupported(t *testing.T) {
	specOf := func(types ...btf.Type) *btf.Spec {
		b, err := btf.NewBuilder(types, nil)
		require.NoError(t, err)
		raw, err := b.Marshal(nil, nil)
		require.NoError(t, err)
		spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
		require.NoError(t, err)
		return spec
	}
	withEnum := specOf(&btf.Enum{Name: "rqf_flags", Size: 4, Values: []btf.EnumValue{{Name: "__RQF_IO_STAT", Value: 8}}})
	noEnum := specOf(&btf.Struct{Name: "request"})

	requestKeyed := storagePlan{stages: []blockLoadStage{{sets: []blockProgramSet{rawTpBlockPrograms(blockTracepointLayout{})}}}}
	classic := storagePlan{stages: []blockLoadStage{{sets: []blockProgramSet{classicBlockPrograms()}}}}

	assert.Empty(t, blockQueueUnsupported(true, requestKeyed, withEnum))
	assert.Empty(t, blockQueueUnsupported(false, storagePlan{}, nil), "block off: nothing to warn about")
	assert.NotEmpty(t, blockQueueUnsupported(true, requestKeyed, noEnum), "no enum rqf_flags")
	assert.NotEmpty(t, blockQueueUnsupported(true, requestKeyed, nil), "no BTF")
	assert.NotEmpty(t, blockQueueUnsupported(true, classic, withEnum), "classic tracepoints")

	// An unsupported kernel gets the queue map shrunk, as with queue off.
	entries := map[string]uint32{}
	plan := planBlockAgg(explicitAgg(8<<20), false, 3, 4, 0, 4, false, entries, quietLog)
	assert.False(t, plan.queue)
	assert.Equal(t, unusedMapEntries, entries[blkAggExplicit.queue])
}
