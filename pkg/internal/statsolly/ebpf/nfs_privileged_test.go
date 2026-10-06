// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"log/slog"
	"math"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
)

// explicitKernelBounds is a 32-entry explicit bound array with one bound.
func explicitKernelBounds() []uint64 {
	bounds := make([]uint64, 32)
	for i := range bounds {
		bounds[i] = math.MaxUint64
	}
	bounds[0] = 1_000_000
	return bounds
}

func requireSunrpc(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs")
	}
	if _, err := nfsTracepointBTF(btf.NewCache(), moduleLoaded); err != nil {
		t.Skip("no sunrpc BTF on this kernel:", err)
	}
}

// On a kernel with sunrpc, the NFS program attaches at startup as tp_btf,
// into maps created before it, sized for the layout in use.
func TestNFSAttachesAtStartup(t *testing.T) {
	requireSunrpc(t)
	defer kernelBTFCache.Release()

	nfs, err := startNFS(slog.Default(), &config.EBPFTracer{}, export.FeatureStorageNFS,
		NFSConfig{KernelBounds: explicitKernelBounds()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, nfs.Close()) })

	require.NotNil(t, nfs.attacher.attached, "attached at startup")
	assert.False(t, nfs.attacher.off)
	info, err := nfs.accum.Info()
	require.NoError(t, err)
	assert.Equal(t, ebpf.Hash, info.Type, "one value for every CPU, updated with atomics")
	assert.Equal(t, uint32(4096), info.MaxEntries)
	assert.Equal(t, uint32(NFSRPCKeySize), info.KeySize)
}

// Both programs load and attach against the running kernel's sunrpc: the
// tp_btf one, which needs its NULL check to pass the verifier on module
// tracepoints, and the raw_tp fallback.
func TestNFSBothProgramsAttach(t *testing.T) {
	requireSunrpc(t)
	defer kernelBTFCache.Release()

	for _, exponential := range []bool{false, true} {
		cfg := NFSConfig{Exponential: exponential, KernelBounds: explicitKernelBounds()}
		if exponential {
			cfg.KernelBounds = make([]uint64, 128)
		}
		l, err := newNFSLoader(slog.Default(), &config.EBPFTracer{}, export.FeatureStorageNFS, cfg)
		require.NoError(t, err)
		for _, prog := range []string{progObiStatsTpBtfRPCStatsLatency, progObiStatsRawTpRPCStatsLatency} {
			c, err := l.attachProgram(prog)
			require.NoError(t, err, "%s, exponential=%t", prog, exponential)
			require.NoError(t, c.Close())
		}
		for _, m := range l.maps {
			m.Close()
		}
	}
}

// The rpc_task_begin programs (step 19) load and attach against the running
// kernel's sunrpc the same way: tp_btf with its NULL check, and the raw_tp
// fallback, both resolving the shared nfs_task_cg map.
func TestNFSBeginProgramsAttach(t *testing.T) {
	requireSunrpc(t)
	defer kernelBTFCache.Release()

	l, err := newNFSLoader(slog.Default(), &config.EBPFTracer{}, export.FeatureStorageNFS,
		NFSConfig{KernelBounds: explicitKernelBounds(), Owner: true})
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, m := range l.maps {
			m.Close()
		}
	})

	for _, prog := range []string{progObiStatsTpBtfRPCTaskBegin, progObiStatsRawTpRPCTaskBegin} {
		c, err := l.attachProgram(prog)
		require.NoError(t, err, prog)
		require.NoError(t, c.Close())
	}
}

// On a kernel with sunrpc, selecting a pod attribute attaches the begin
// program alongside the main one at startup, and both close together.
func TestNFSAttachesBeginAtStartupWhenOwnerIsWanted(t *testing.T) {
	requireSunrpc(t)
	defer kernelBTFCache.Release()

	nfs, err := startNFS(slog.Default(), &config.EBPFTracer{}, export.FeatureStorageNFS,
		NFSConfig{KernelBounds: explicitKernelBounds(), Owner: true})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, nfs.Close()) })

	require.NotNil(t, nfs.attacher.attached)
	require.NotNil(t, nfs.attacher.beginAttached, "the begin program attaches when a pod attribute is selected")
	assert.False(t, nfs.attacher.off)
}
