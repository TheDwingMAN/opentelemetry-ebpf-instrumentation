// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stataggtest // import "go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"

import (
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
)

// NFS is the NFS client RPC aggregation map for tests: a map shared by every
// CPU, as nfs_rpc_accum is, read by the family the agent builds.
type NFS struct {
	Map      *MemMap
	Layout   *statagg.Layout
	Family   *statagg.Family
	Registry *statagg.Registry
	// WantStatus is the program's nfs_want_status: without it, every key
	// has status 0.
	WantStatus bool
}

// NewNFS returns an NFS map whose histograms use layout, read into the
// metrics features enables, whose keys go through decorate. tune changes
// the family's defaults.
func NewNFS(
	layout *statagg.Layout, features export.Features, decorate func(*ebpf.Stat) bool, tune ...func(*statagg.Config),
) (*NFS, error) {
	m := NewMemMap(ebpf.NFSRPCKeySize, ebpf.NFSRPCCounters*counterSize+layout.Buckets()*bucketSize, 1)
	f, err := stats.NewNFSRPCFamily(m, layout, features, decorate, tune...)
	if err != nil {
		return nil, err
	}
	reg, err := statagg.NewRegistry(f)
	if err != nil {
		return nil, err
	}
	return &NFS{Map: m, Layout: layout, Family: f, Registry: reg, WantStatus: features.StorageNFSErrors()}, nil
}

// Record counts an NFS RPC attempt, given as the per-event path's stat, the
// way nfs_rpc.c does.
func (n *NFS) Record(s *ebpf.Stat) {
	rpc := *s.NFSRPC
	if !n.WantStatus {
		rpc.Status = 0
	}
	key := ebpf.EncodeNFSRPCKey(&rpc)
	n.Map.AddU64(key, 0, ebpf.NFSRPCWordSumNs*counterSize, rpc.ExecuteNs)
	n.Map.AddU64(key, 0, ebpf.NFSRPCWordTxBytes*counterSize, rpc.TxBytes)
	n.Map.AddU64(key, 0, ebpf.NFSRPCWordRxBytes*counterSize, rpc.RxBytes)
	n.Map.AddU64(key, 0, ebpf.NFSRPCWordRetrans*counterSize, rpc.Retransmits)
	n.Map.AddU32(key, 0, ebpf.NFSRPCCounters*counterSize+searchBounds(n.Layout.BoundsNs, rpc.ExecuteNs)*bucketSize, 1)
}
