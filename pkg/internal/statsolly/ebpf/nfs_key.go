// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import "encoding/binary"

// Layout of struct nfs_rpc_key (bpf/statsolly/nfs_rpc.h), checked against the
// generated type by TestNFSRPCKeyLayout.
const (
	NFSRPCKeySize = 40

	nfsKeyOwner   = 0
	nfsKeyStatIdx = 8
	nfsKeyVers    = 10
	nfsKeyFamily  = 11
	nfsKeyStatus  = 12
	nfsKeyAddr    = 16
	nfsKeyScopeID = 32
)

// Counter words of struct nfs_rpc_val and nfs_rpc_exp_val, in order: the
// buckets follow them.
const (
	NFSRPCWordSumNs = iota
	NFSRPCWordTxBytes
	NFSRPCWordRxBytes
	NFSRPCWordRetrans
	NFSRPCCounters
)

// DecodeNFSRPCKey returns the NFS RPC a kernel aggregation key counts.
func DecodeNFSRPCKey(key []byte) *NFSRPC {
	r := &NFSRPC{
		Owner:   binary.NativeEndian.Uint64(key[nfsKeyOwner:]),
		StatIdx: binary.NativeEndian.Uint16(key[nfsKeyStatIdx:]),
		Version: key[nfsKeyVers],
		Family:  key[nfsKeyFamily],
		Status:  int32(binary.NativeEndian.Uint32(key[nfsKeyStatus:])),
		ScopeID: binary.NativeEndian.Uint32(key[nfsKeyScopeID:]),
	}
	copy(r.Addr[:], key[nfsKeyAddr:nfsKeyAddr+len(r.Addr)])
	return r
}

// EncodeNFSRPCKey returns the kernel aggregation key the programs count r in.
func EncodeNFSRPCKey(r *NFSRPC) []byte {
	key := make([]byte, NFSRPCKeySize)
	binary.NativeEndian.PutUint64(key[nfsKeyOwner:], r.Owner)
	binary.NativeEndian.PutUint16(key[nfsKeyStatIdx:], r.StatIdx)
	key[nfsKeyVers] = r.Version
	key[nfsKeyFamily] = r.Family
	binary.NativeEndian.PutUint32(key[nfsKeyStatus:], uint32(r.Status))
	copy(key[nfsKeyAddr:], r.Addr[:])
	binary.NativeEndian.PutUint32(key[nfsKeyScopeID:], r.ScopeID)
	return key
}
