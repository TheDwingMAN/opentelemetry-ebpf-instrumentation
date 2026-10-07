// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// What decorating a new NFS kernel key costs before the pipeline decorators:
// decoding it and computing its default Prometheus label values. It runs
// when a key is new and every 30 s while it counts, never per RPC.
func BenchmarkNFSRPCKeyLabels(b *testing.B) {
	names := []attr.Name{attr.OncRPCVersion, attr.OncRPCProcedureName, attr.NFSOperationName, attr.ServerAddr, attr.ErrorType}
	getters := make([]func(*Stat) string, len(names))
	for i, n := range names {
		g, _ := StatStringGetters(n)
		getters[i] = g
	}
	for name, rpc := range map[string]*NFSRPC{
		"v3 IPv4":       {Version: 3, StatIdx: 6, Family: nfsAFInet, Addr: [16]byte{192, 168, 122, 34}},
		"v3 IPv6 error": {Version: 3, StatIdx: 3, Status: -2, Family: nfsAFInet6, Addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}},
	} {
		key := EncodeNFSRPCKey(rpc)
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				s := &Stat{Type: StatTypeNFSRPC, NFSRPC: DecodeNFSRPCKey(key)}
				for _, g := range getters {
					_ = g(s)
				}
			}
		})
	}
}
