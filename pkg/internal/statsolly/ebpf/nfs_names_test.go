// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestNFSProcedureNames(t *testing.T) {
	for _, tc := range []struct {
		version uint8
		statIdx uint16
		want    string
	}{
		{3, 0, "NULL"},
		{3, 1, "GETATTR"},
		{3, 3, "LOOKUP"},
		{3, 6, "READ"},
		{3, 7, "WRITE"},
		{3, 17, "READDIRPLUS"},
		{3, 21, "COMMIT"},
		{3, 22, "22"},
		{2, 6, "READ"},
		{2, 8, "WRITE"},
		{2, 17, "STATFS"},
		// NFSv4's procedure is always COMPOUND: its operation is
		// nfs.operation.name, not a procedure name.
		{4, 1, ""},
	} {
		assert.Equal(t, tc.want, nfsProcedureName(tc.version, tc.statIdx), "v%d %d", tc.version, tc.statIdx)
	}
}

// nfs4OpBTF is the shape of the NFSv4 client operation enum in the nfsv4
// module BTF: anonymous, found by its NFSPROC4_CLNT_NULL member, next to
// other anonymous enums.
func nfs4OpBTF(t *testing.T) *btf.Spec {
	t.Helper()
	ops := &btf.Enum{Size: 4, Values: []btf.EnumValue{
		{Name: "NFSPROC4_CLNT_NULL", Value: 0},
		{Name: "NFSPROC4_CLNT_READ", Value: 1},
		{Name: "NFSPROC4_CLNT_WRITE", Value: 2},
		{Name: "NFSPROC4_CLNT_OPEN", Value: 4},
		{Name: "NFSPROC4_CLNT_OPEN_NOATTR", Value: 5},
		{Name: "NFSPROC4_CLNT_BIND_CONN_TO_SESSION", Value: 6},
	}}
	other := &btf.Enum{Size: 4, Values: []btf.EnumValue{{Name: "NFS4_OK", Value: 0}, {Name: "NFS4ERR_PERM", Value: 1}}}
	named := &btf.Enum{Name: "nfs_opnum4", Size: 4, Values: []btf.EnumValue{{Name: "NFSPROC4_CLNT_NULL", Value: 7}}}
	b, err := btf.NewBuilder([]btf.Type{other, named, ops}, nil)
	require.NoError(t, err)
	spec, err := b.Spec()
	require.NoError(t, err)
	return spec
}

func TestNFS4OpNamesFromBTF(t *testing.T) {
	names, err := nfs4OpNamesFrom(nfs4OpBTF(t))
	require.NoError(t, err)
	assert.Equal(t, []string{"NULL", "READ", "WRITE", "", "OPEN", "OPEN_NOATTR", "BIND_CONN_TO_SESSION"}, names)

	b, err := btf.NewBuilder([]btf.Type{&btf.Int{Name: "int", Size: 4}}, nil)
	require.NoError(t, err)
	spec, err := b.Spec()
	require.NoError(t, err)
	_, err = nfs4OpNamesFrom(spec)
	require.ErrorIs(t, err, errNoNFS4Ops)
}

func TestNFS4OperationNames(t *testing.T) {
	loads := 0
	names := &nfs4OpNames{load: func() ([]string, error) {
		loads++
		return nfs4OpNamesFrom(nfs4OpBTF(t))
	}}
	assert.Equal(t, "READ", names.name(1))
	assert.Equal(t, "OPEN_NOATTR", names.name(5))
	assert.Equal(t, "3", names.name(3), "a hole in the enum keeps its index")
	assert.Equal(t, "40", names.name(40), "an index past the enum keeps its index")
	assert.Equal(t, 1, loads, "the names are read once")

	missing := &nfs4OpNames{load: func() ([]string, error) { return nil, errors.New("no nfsv4 BTF") }}
	assert.Equal(t, "1", missing.name(1), "without the names, the index")
}

// v2/v3 series carry onc_rpc.procedure.name and no nfs.operation.name, v4
// series the reverse: the getters return "" for the other versions, which
// the storage exporters leave out.
func TestNFSRPCGetters(t *testing.T) {
	old := nfs4Names
	nfs4Names = &nfs4OpNames{load: func() ([]string, error) { return nfs4OpNamesFrom(nfs4OpBTF(t)) }}
	t.Cleanup(func() { nfs4Names = old })

	get := func(name attr.Name, s *Stat) attribute.KeyValue {
		g, ok := StatGetters(name)
		require.True(t, ok)
		return g(s)
	}
	getStr := func(name attr.Name, s *Stat) string {
		g, ok := StatStringGetters(name)
		require.True(t, ok)
		return g(s)
	}
	v3 := &Stat{Type: StatTypeNFSRPC, NFSRPC: &NFSRPC{
		Version: 3, StatIdx: 6, Family: nfsAFInet, Addr: [16]byte{10, 0, 0, 5},
	}}
	v4 := &Stat{Type: StatTypeNFSRPC, NFSRPC: &NFSRPC{
		Version: 4, StatIdx: 4, Status: -10008, Family: nfsAFInet6, Addr: [16]byte{0xfe, 0x80, 15: 1}, ScopeID: 2,
	}}

	assert.Equal(t, attribute.Int64(string(attr.OncRPCVersion), 3), get(attr.OncRPCVersion, v3), "an int on OTLP")
	assert.Equal(t, "3", getStr(attr.OncRPCVersion, v3), "a string on Prometheus")
	assert.Equal(t, "READ", getStr(attr.OncRPCProcedureName, v3))
	assert.Empty(t, getStr(attr.NFSOperationName, v3))
	assert.Equal(t, "10.0.0.5", getStr(attr.ServerAddr, v3))
	assert.Empty(t, getStr(attr.ErrorType, v3))

	assert.Empty(t, getStr(attr.OncRPCProcedureName, v4))
	assert.Equal(t, "OPEN", getStr(attr.NFSOperationName, v4))
	assert.Equal(t, "fe80::1%2", getStr(attr.ServerAddr, v4))
	assert.Equal(t, "NFS4ERR_DELAY", getStr(attr.ErrorType, v4))

	block := &Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{}}
	assert.False(t, get(attr.OncRPCVersion, block).Valid(), "no version outside NFS")
	assert.Empty(t, getStr(attr.ServerAddr, block))
}
