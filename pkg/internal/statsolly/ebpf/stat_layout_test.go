// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// The wire structs are maintained by hand against their C counterparts in
// bpf/statsolly/types.h. A round-trip decode test cannot catch a mirror that is
// consistently wrong in both directions, so assert the byte layout directly.
func TestStatsBlockIoLayout(t *testing.T) {
	var s StatsBlockIo
	assert.Equal(t, uintptr(48), unsafe.Sizeof(s), "sizeof block_io_t")
	assert.Equal(t, uintptr(0), unsafe.Offsetof(s.Flags))
	assert.Equal(t, uintptr(1), unsafe.Offsetof(s.Op))
	assert.Equal(t, uintptr(4), unsafe.Offsetof(s.Dev))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(s.LatencyNs))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(s.QueueNs))
	assert.Equal(t, uintptr(24), unsafe.Offsetof(s.Bytes))
	assert.Equal(t, uintptr(32), unsafe.Offsetof(s.Error))
	assert.Equal(t, uintptr(36), unsafe.Offsetof(s.Inflight))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(s.PartDev))
}

func TestStatsFsIoLayout(t *testing.T) {
	var s StatsFsIo
	assert.Equal(t, uintptr(48), unsafe.Sizeof(s), "sizeof fs_io_t")
	assert.Equal(t, uintptr(0), unsafe.Offsetof(s.Flags))
	assert.Equal(t, uintptr(1), unsafe.Offsetof(s.Fs))
	assert.Equal(t, uintptr(2), unsafe.Offsetof(s.Op))
	assert.Equal(t, uintptr(4), unsafe.Offsetof(s.SDev))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(s.HostPID))
	assert.Equal(t, uintptr(12), unsafe.Offsetof(s.PidNs))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(s.LatencyNs))
	assert.Equal(t, uintptr(24), unsafe.Offsetof(s.Bytes))
	assert.Equal(t, uintptr(32), unsafe.Offsetof(s.Error))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(s.RootIno))
}

// The C discriminator values in bpf/statsolly/types.h must match these
// generated constant values; a mismatch surfaces only at runtime as "unknown
// stats event".
func TestStatTypeDiscriminators(t *testing.T) {
	assert.Equal(t, StatTypeTCPRtt, StatType(1))
	assert.Equal(t, StatTypeBlockIo, StatType(6))
	assert.Equal(t, StatTypeFsIo, StatType(7))
	assert.Equal(t, StatTypeNFSRPC, StatType(8))
}

// The NFS aggregation key and value are read from raw map bytes by offset.
func TestNFSRPCKeyLayout(t *testing.T) {
	var k NfsRpcNfsRpcKey
	assert.Equal(t, uintptr(NFSRPCKeySize), unsafe.Sizeof(k), "sizeof struct nfs_rpc_key")
	assert.Equal(t, uintptr(0), unsafe.Offsetof(k.Owner))
	assert.Equal(t, uintptr(nfsKeyStatIdx), unsafe.Offsetof(k.Statidx))
	assert.Equal(t, uintptr(nfsKeyVers), unsafe.Offsetof(k.Vers))
	assert.Equal(t, uintptr(nfsKeyFamily), unsafe.Offsetof(k.Family))
	assert.Equal(t, uintptr(nfsKeyStatus), unsafe.Offsetof(k.Status))
	assert.Equal(t, uintptr(nfsKeyAddr), unsafe.Offsetof(k.Addr))
	assert.Equal(t, uintptr(nfsKeyScopeID), unsafe.Offsetof(k.ScopeId))

	const word = unsafe.Sizeof(uint64(0))
	var v NfsRpcNfsRpcVal
	assert.Equal(t, uintptr(168), unsafe.Sizeof(v), "sizeof struct nfs_rpc_val")
	assert.Equal(t, NFSRPCWordSumNs*word, unsafe.Offsetof(v.SumNs))
	assert.Equal(t, NFSRPCWordTxBytes*word, unsafe.Offsetof(v.TxBytes))
	assert.Equal(t, NFSRPCWordRxBytes*word, unsafe.Offsetof(v.RxBytes))
	assert.Equal(t, NFSRPCWordRetrans*word, unsafe.Offsetof(v.Retrans))
	assert.Equal(t, NFSRPCCounters*word, unsafe.Offsetof(v.Bkt))
	assert.Len(t, v.Bkt, 33)

	var e NfsRpcNfsRpcExpVal
	assert.Equal(t, NFSRPCCounters*word, unsafe.Offsetof(e.Bkt))
	assert.Len(t, e.Bkt, 129)
}

func TestNFSRPCKeyRoundTrip(t *testing.T) {
	rpc := &NFSRPC{
		Owner:   123456,
		Version: 4, StatIdx: 18, Status: -10008, Family: nfsAFInet6,
		Addr: [16]byte{0xfe, 0x80, 15: 7}, ScopeID: 3,
	}
	key := EncodeNFSRPCKey(rpc)
	assert.Len(t, key, NFSRPCKeySize)
	assert.Equal(t, rpc, DecodeNFSRPCKey(key))
}
