// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

// NFSRPCFamilyName names the NFS client RPC aggregation map in logs.
const NFSRPCFamilyName = "nfs_rpc_accum"

// NewNFSRPCFamily reads the NFS client RPC attempts the kernel counts in src
// (nfs_rpc_accum or nfs_rpc_accum_exp, whose histograms have layout) into the
// enabled NFS metrics. Each key is one server, procedure and status: its
// histogram counts its attempts, which the errors counter also takes for a
// key with an error status. decorate is the stats pipeline's decoration;
// tune, for tests and benchmarks, changes the family's defaults.
func NewNFSRPCFamily(
	src statagg.Source, layout *statagg.Layout, features export.Features, decorate func(*ebpf.Stat) bool,
	tune ...func(*statagg.Config),
) (*statagg.Family, error) {
	attempts := func(d statagg.Delta) uint64 { return d.Sum(ebpf.NFSRPCCounters, layout.Buckets()) }

	var metrics []*statagg.Metric
	if features.StorageNFSDuration() {
		metrics = append(metrics, &statagg.Metric{
			Name: attributes.StatNFSClientRPCDuration, Kind: statagg.KindHistogram,
			SumWord: ebpf.NFSRPCWordSumNs, BucketWord: ebpf.NFSRPCCounters, Layout: layout,
		})
	}
	if features.StorageNFSErrors() {
		metrics = append(metrics, &statagg.Metric{
			Name: attributes.StatNFSClientRPCErrors, Kind: statagg.KindCounter,
			Select: func(s *ebpf.Stat) bool { return s.NFSRPC.Status != 0 },
			Value:  attempts,
		})
	}
	if features.StorageNFSRetransmits() {
		metrics = append(metrics, &statagg.Metric{
			Name: attributes.StatNFSClientRPCRetransmits, Kind: statagg.KindCounter,
			Value:    func(d statagg.Delta) uint64 { return d.Counter(ebpf.NFSRPCWordRetrans) },
			SkipZero: true,
		})
	}
	if features.StorageNFSIo() {
		// The kernel counts an attempt's sent and received bytes together
		// in the same key (bpf/statsolly/nfs_rpc.h): two variants read its
		// two words, each marking the stat with its own direction before
		// its series' attributes are read.
		metrics = append(metrics, &statagg.Metric{
			Name: attributes.StatNFSClientIO, Kind: statagg.KindCounter,
			Variants: []statagg.Variant{
				{
					Value: func(d statagg.Delta) uint64 { return d.Counter(ebpf.NFSRPCWordTxBytes) },
					Mark:  func(s *ebpf.Stat) { s.NFSRPC.Direction = uint8(ebpf.CodeDirectionTransmit) },
				},
				{
					Value: func(d statagg.Delta) uint64 { return d.Counter(ebpf.NFSRPCWordRxBytes) },
					Mark:  func(s *ebpf.Stat) { s.NFSRPC.Direction = uint8(ebpf.CodeDirectionReceive) },
				},
			},
		})
	}

	cfg := statagg.Config{
		Name:     NFSRPCFamilyName,
		Source:   src,
		Layout:   statagg.ValueLayout{Counters: ebpf.NFSRPCCounters, Buckets: layout.Buckets()},
		Stat:     nfsRPCStat,
		Decorate: decorate,
		Pending:  func(s *ebpf.Stat) bool { return s.NFSRPC != nil && s.NFSRPC.OwnerPending },
		Metrics:  metrics,
	}
	for _, t := range tune {
		t(&cfg)
	}
	return statagg.NewFamily(cfg)
}

func nfsRPCStat(key, _ []byte) (*ebpf.Stat, bool) {
	return &ebpf.Stat{Type: ebpf.StatTypeNFSRPC, NFSRPC: ebpf.DecodeNFSRPCKey(key)}, true
}
