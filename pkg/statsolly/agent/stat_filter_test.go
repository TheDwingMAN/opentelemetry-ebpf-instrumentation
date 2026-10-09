// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// filter.ByAttribute matches every TCP stat against every filter but those on the attributes that
// the storage stat metrics have and the TCP stat metrics don't
func TestTCPStatFiltersKeepTheirSemantics(t *testing.T) {
	common := func(port uint16, cidr, country string) pipe.CommonAttrs {
		return pipe.CommonAttrs{OBIIP: "1.2.3.4", DstPort: port, Metadata: map[attr.Name]string{
			"dst.cidr": cidr, "dst.country": country, "k8s.cluster.name": "c1",
		}}
	}
	internal := common(443, "10.0.0.0/8", "US")
	external := common(80, "192.168.0.0/16", "DE")
	stats := map[string]*ebpf.Stat{
		"rtt client":    {Type: ebpf.StatTypeTCPRtt, TCPRtt: &ebpf.TCPRtt{Role: uint8(ebpf.CodeRoleClient)}, CommonAttrs: internal},
		"rtt server":    {Type: ebpf.StatTypeTCPRtt, TCPRtt: &ebpf.TCPRtt{Role: uint8(ebpf.CodeRoleServer)}, CommonAttrs: external},
		"refused":       {Type: ebpf.StatTypeTCPFailedConnection, TCPFailedConnection: &ebpf.TCPFailedConnection{Reason: uint8(ebpf.CodeConnectionRefused), Role: uint8(ebpf.CodeRoleClient)}, CommonAttrs: internal},
		"timed out":     {Type: ebpf.StatTypeTCPFailedConnection, TCPFailedConnection: &ebpf.TCPFailedConnection{Reason: uint8(ebpf.CodeTimedOut), Role: uint8(ebpf.CodeRoleServer)}, CommonAttrs: external},
		"retransmit":    {Type: ebpf.StatTypeTCPRetransmit, TCPRetransmit: true, CommonAttrs: internal},
		"transmit":      {Type: ebpf.StatTypeTCPIo, TCPIo: &ebpf.TCPIo{Direction: uint8(ebpf.CodeDirectionTransmit)}, CommonAttrs: internal},
		"receive":       {Type: ebpf.StatTypeTCPIo, TCPIo: &ebpf.TCPIo{Direction: uint8(ebpf.CodeDirectionReceive)}, CommonAttrs: external},
		"client handsh": {Type: ebpf.StatTypeTCPSuccessfulConnection, TCPSuccessfulConnection: &ebpf.TCPSuccessfulConnection{Role: uint8(ebpf.CodeRoleClient)}, CommonAttrs: internal},
		"server handsh": {Type: ebpf.StatTypeTCPSuccessfulConnection, TCPSuccessfulConnection: &ebpf.TCPSuccessfulConnection{Role: uint8(ebpf.CodeRoleServer)}, CommonAttrs: external},
	}
	all := []string{"rtt client", "rtt server", "refused", "timed out", "retransmit", "transmit", "receive", "client handsh", "server handsh"}
	internalOnes := []string{"rtt client", "refused", "retransmit", "transmit", "client handsh"}
	kept := func(matchers filter.MatcherSet[*ebpf.Stat]) []string {
		var ids []string
		for id, stat := range stats {
			if matchers.Matches(stat) {
				ids = append(ids, id)
			}
		}
		return ids
	}

	for _, tc := range []struct {
		name   string
		config filter.AttributeFamilyConfig
		// the stats that the TCP filters keep
		kept []string
		// no filter is on an attribute that the storage stat metrics have and the TCP stat metrics
		// don't, so the TCP filters keep what the matchers of the whole config keep
		sameAsUnsplitConfig bool
	}{
		{"reason: only the failed connections have it", filter.AttributeFamilyConfig{"reason": {NotMatch: "unknown"}}, []string{"refused", "timed out"}, true},
		{"reason", filter.AttributeFamilyConfig{"reason": {Match: "refused"}}, []string{"refused"}, true},
		{"network.io.direction: only the I/O has it", filter.AttributeFamilyConfig{"network.io.direction": {Match: "transmit"}}, []string{"transmit"}, true},
		{"network.io.direction not matched", filter.AttributeFamilyConfig{"network_io_direction": {NotMatch: "receive"}}, []string{"rtt client", "rtt server", "refused", "timed out", "retransmit", "transmit", "client handsh", "server handsh"}, true},
		{"network.tcp.handshake.role", filter.AttributeFamilyConfig{"network.tcp.handshake.role": {Match: "client"}}, []string{"rtt client", "refused", "client handsh"}, true},
		{"network.tcp.handshake.role not unknown", filter.AttributeFamilyConfig{"network_tcp_handshake_role": {NotMatch: "unknown"}}, []string{"rtt client", "rtt server", "refused", "timed out", "client handsh", "server handsh"}, true},
		{"dst.port", filter.AttributeFamilyConfig{"dst_port": {Equals: new(443)}}, internalOnes, true},
		{"dst.cidr, from the CIDR decorator", filter.AttributeFamilyConfig{"dst.cidr": {Match: "10.0.0.0/8"}}, internalOnes, true},
		{"dst.country, from the GeoIP decorator", filter.AttributeFamilyConfig{"dst_country": {Match: "US"}}, internalOnes, true},
		{"obi.ip, which storage metrics have too", filter.AttributeFamilyConfig{"obi.ip": {NotMatch: "1.2.3.4"}}, nil, true},
		{"k8s.cluster.name, which storage metrics have too", filter.AttributeFamilyConfig{"k8s.cluster.name": {NotMatch: "c1"}}, nil, true},
		{"http.route, which no stat metric has", filter.AttributeFamilyConfig{"http.route": {Match: "/foo"}}, nil, true},
		{"reason and dst.cidr", filter.AttributeFamilyConfig{"reason": {Match: "refused"}, "dst.cidr": {Match: "10.*"}}, []string{"refused"}, true},
		// no TCP stat is matched against the filters on the attributes that the storage stat metrics
		// have and the TCP stat metrics don't: the TCP stats lack these attributes, so a match would
		// drop them all, also on those that other metrics have, like k8s.namespace.name or container.id
		{"system.device", filter.AttributeFamilyConfig{"system.device": {Match: "sda"}}, all, false},
		{"error.type", filter.AttributeFamilyConfig{"error.type": {Match: "EIO"}}, all, false},
		{"dst.port and system.device", filter.AttributeFamilyConfig{"dst.port": {Equals: new(443)}, "system.device": {Match: "sda"}}, internalOnes, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tcpConfig, err := tcpStatFilters(tc.config, nil)
			require.NoError(t, err)
			matchers, err := filter.NewMatcherSet(tcpConfig, nil, nil, ebpf.StatStringGetters)
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.kept, kept(matchers))

			if tc.sameAsUnsplitConfig {
				unsplit, err := filter.NewMatcherSet(tc.config, nil, nil, ebpf.StatStringGetters)
				require.NoError(t, err)
				assert.ElementsMatch(t, kept(unsplit), kept(matchers))
			}
		})
	}
}

// A storage stat is only matched against the filters on the attributes of its metrics
func TestStorageStatFiltersOnlyApplyToTheStatsWithTheirAttributes(t *testing.T) {
	nvme := &ebpf.Stat{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{Device: "nvme0n1"}}
	sda := &ebpf.Stat{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{Device: "sda"}}

	filtered := func(config filter.AttributeFamilyConfig) []*ebpf.Stat {
		matchers, err := newStorageStatMatchers(config, nil)
		require.NoError(t, err)
		return filterStats(matchers, []*ebpf.Stat{nvme, sda})
	}

	assert.Equal(t, []*ebpf.Stat{nvme, sda},
		filtered(filter.AttributeFamilyConfig{"dst.port": {Equals: new(443)}}),
		"a filter on a TCP attribute keeps the storage stats")
	assert.Equal(t, []*ebpf.Stat{nvme},
		filtered(filter.AttributeFamilyConfig{"system.device": {Match: "nvme*"}}),
		"a filter on a disk attribute applies to the disk stats")
	assert.Equal(t, []*ebpf.Stat{nvme},
		filtered(filter.AttributeFamilyConfig{"dst.port": {Equals: new(443)}, "system.device": {Match: "nvme*"}}),
		"each stat is matched against all the filters of its attributes")
}

// The storage probes read only the attributes of the filters that apply to the storage stats
func TestStorageProbesReadTheAttributesOfTheStorageStatFilters(t *testing.T) {
	filters := filter.AttributeFamilyConfig{
		"dst.port":      {Equals: new(443)},
		"container_id":  {Match: "a1*"},
		"system.device": {Match: "nvme*"},
	}
	assert.ElementsMatch(t, []attr.Name{"container_id", "system.device"},
		filteredAttributes(storageStatFilters(filters, nil)))
}

func TestStatFilterOfAnUnknownAttribute(t *testing.T) {
	_, err := tcpStatFilters(filter.AttributeFamilyConfig{"not.an.attribute": {Match: "*"}}, nil)
	require.Error(t, err)
}

// Every stat metric but the TCP ones is listed with the disk stat metrics, so that the filters on its
// attributes apply to the storage stats
func TestEveryStorageStatMetricIsListed(t *testing.T) {
	sections := attributes.StatSections()
	require.Subset(t, sections, tcpStatSections)
	for _, section := range sections {
		if !slices.Contains(tcpStatSections, section) {
			assert.Contains(t, diskStatSections, section)
		}
	}
}
