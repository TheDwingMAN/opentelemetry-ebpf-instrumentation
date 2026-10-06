// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package statagg

import (
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerCPUMap(t *testing.T) {
	for typ, want := range map[cebpf.MapType]bool{
		cebpf.PerCPUHash: true, cebpf.PerCPUArray: true, cebpf.Hash: false, cebpf.Array: false,
	} {
		perCPU, err := perCPUMap(typ)
		require.NoError(t, err, typ)
		assert.Equal(t, want, perCPU, typ)
	}
	// An evicted key created again would diff against its old totals.
	for _, typ := range []cebpf.MapType{cebpf.LRUHash, cebpf.LRUCPUHash, cebpf.RingBuf} {
		_, err := perCPUMap(typ)
		assert.Error(t, err, typ)
	}
}
