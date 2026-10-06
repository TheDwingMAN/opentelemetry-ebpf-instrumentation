// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestNFSClientRPCDefaultAttributes(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	names := []attr.Name{attr.NFSOperationName, attr.OncRPCProcedureName, attr.OncRPCVersion, attr.ServerAddr}
	assert.Equal(t, names, p.For(StatNFSClientRPCDuration))
	assert.Equal(t, names, p.For(StatNFSClientRPCRetransmits))
	assert.Equal(t, []attr.Name{attr.ErrorType, attr.NFSOperationName, attr.OncRPCProcedureName, attr.OncRPCVersion, attr.ServerAddr},
		p.For(StatNFSClientRPCErrors), "error.type splits the errors counter only")

	k, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{})
	require.NoError(t, err)
	assert.Contains(t, k.For(StatNFSClientRPCDuration), attr.K8sNodeName)
	assert.NotContains(t, k.For(StatNFSClientRPCDuration), attr.K8sPodName, "pod attributes are opt-in (step 19)")
}

// StatNFSClientIO's default attributes differ from the other NFS client RPC
// metrics: network.io.direction is on (the kernel counts both directions
// together in one key), and the procedure and version breakdown the others
// default on is opt-in here, to keep this metric's default series to one
// pair per server (section 5).
func TestNFSClientIODefaultAttributes(t *testing.T) {
	p, err := NewAttrSelector(0, &SelectorConfig{})
	require.NoError(t, err)
	assert.Equal(t, []attr.Name{attr.NetworkIoDirection, attr.ServerAddr}, p.For(StatNFSClientIO))

	opt, err := NewAttrSelector(0, &SelectorConfig{SelectionCfg: Selection{
		StatNFSClientIO.Section: InclusionLists{Include: []string{"onc_rpc.*", "nfs.operation.name"}},
	}})
	require.NoError(t, err)
	assert.ElementsMatch(t,
		[]attr.Name{attr.OncRPCProcedureName, attr.OncRPCVersion, attr.NFSOperationName},
		opt.For(StatNFSClientIO))

	k, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{})
	require.NoError(t, err)
	assert.Contains(t, k.For(StatNFSClientIO), attr.K8sNodeName)
}

// The NFS client RPC metrics share the onc_rpc.* attributes with the
// application-level ONC RPC metrics, not their names: selecting attributes
// for one never changes the other.
func TestNFSClientRPCCoexistsWithApplicationRPC(t *testing.T) {
	for _, n := range []Name{StatNFSClientRPCDuration, StatNFSClientRPCErrors, StatNFSClientRPCRetransmits} {
		assert.NotEqual(t, RPCClientDuration.OTEL, n.OTEL)
		assert.NotEqual(t, RPCClientDuration.Prom, n.Prom)
	}

	plain, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{})
	require.NoError(t, err)
	selected, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{SelectionCfg: Selection{
		StatNFSClientRPCDuration.Section: InclusionLists{Include: []string{"onc_rpc.*"}},
	}})
	require.NoError(t, err)
	assert.Equal(t, plain.For(RPCClientDuration), selected.For(RPCClientDuration))
	assert.Equal(t, []attr.Name{attr.OncRPCProcedureName, attr.OncRPCVersion}, selected.For(StatNFSClientRPCDuration))
}
