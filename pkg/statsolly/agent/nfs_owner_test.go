// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
)

// None of the NFS metrics select a pod attribute by default (step 19 is
// opt-in): nfsOwnerWanted must say so without the user selecting anything.
func TestNFSOwnerWantedDefaultIsFalse(t *testing.T) {
	plain, err := attributes.NewAttrSelector(attributes.GroupKubernetes, &attributes.SelectorConfig{})
	require.NoError(t, err)
	assert.False(t, nfsOwnerWanted(plain))
}

// Selecting any of the pod trio or k8s.owner.name, on any of the four NFS
// metrics step 19 lists, wants the owner.
func TestNFSOwnerWantedWhenAPodAttributeIsSelected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		metric attributes.Name
		attr   string
	}{
		{"pod name on rpc.duration", attributes.StatNFSClientRPCDuration, "k8s.pod.name"},
		{"namespace on rpc.errors", attributes.StatNFSClientRPCErrors, "k8s.namespace.name"},
		{"container name on rpc.retransmits", attributes.StatNFSClientRPCRetransmits, "k8s.container.name"},
		{"owner name on io", attributes.StatNFSClientIO, "k8s.owner.name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sel, err := attributes.NewAttrSelector(attributes.GroupKubernetes, &attributes.SelectorConfig{
				SelectionCfg: attributes.Selection{
					tc.metric.Section: attributes.InclusionLists{Include: []string{tc.attr}},
				},
			})
			require.NoError(t, err)
			assert.True(t, nfsOwnerWanted(sel))
		})
	}
}

// Selecting an unrelated attribute, such as the onc_rpc.* ones the NFS RPC
// metrics already default on, must not turn the owner on.
func TestNFSOwnerWantedIgnoresOtherAttributes(t *testing.T) {
	sel, err := attributes.NewAttrSelector(attributes.GroupKubernetes, &attributes.SelectorConfig{
		SelectionCfg: attributes.Selection{
			attributes.StatNFSClientRPCDuration.Section: attributes.InclusionLists{Include: []string{"onc_rpc.*"}},
		},
	})
	require.NoError(t, err)
	assert.False(t, nfsOwnerWanted(sel))
}

func newNFSOwnerDecorateTestStore(t *testing.T) *kube.Store {
	t.Helper()
	n := meta.NewBaseNotifier(slog.Default())
	return kube.NewStore(&n, kube.ResourceLabels{}, nil, imetrics.NoopReporter{})
}

func TestNewNFSOwnerDecorateNilCases(t *testing.T) {
	store := newNFSOwnerDecorateTestStore(t)

	s := &Stats{}
	s.aggDeps.store = store
	assert.Nil(t, s.newNFSOwnerDecorate(), "no pod attribute was selected")

	s = &Stats{nfsOwner: true}
	assert.Nil(t, s.newNFSOwnerDecorate(), "no store to resolve an owner against")
}

// On a cgroup v2 host, newNFSOwnerDecorate builds the cgroup index once and
// reuses it: Run (agent.go) starts it exactly once, after the pipeline is up.
func TestNewNFSOwnerDecorateBuildsCgroupIndexOnce(t *testing.T) {
	store := newNFSOwnerDecorateTestStore(t)
	s := &Stats{nfsOwner: true}
	s.aggDeps.store = store

	decorate := s.newNFSOwnerDecorate()
	require.NotNil(t, decorate)
	require.NotNil(t, s.cgroups)
	index := s.cgroups

	decorate = s.newNFSOwnerDecorate()
	require.NotNil(t, decorate)
	assert.Same(t, index, s.cgroups, "built once, not on every call")
}

// On a cgroup v1 host the owner is resolved by the pid path, which needs no
// cgroup index.
func TestNewNFSOwnerDecorateCgroupV1NeedsNoIndex(t *testing.T) {
	store := newNFSOwnerDecorateTestStore(t)
	s := &Stats{nfsOwner: true, nfsCgroupV1: true}
	s.aggDeps.store = store

	decorate := s.newNFSOwnerDecorate()
	require.NotNil(t, decorate)
	assert.Nil(t, s.cgroups)
}
