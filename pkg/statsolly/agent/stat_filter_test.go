// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func TestStatFiltersOnlyApplyToTheStatsWithTheirAttributes(t *testing.T) {
	https := &ebpf.Stat{Type: ebpf.StatTypeTCPRtt, TCPRtt: &ebpf.TCPRtt{}, CommonAttrs: pipe.CommonAttrs{DstPort: 443}}
	http := &ebpf.Stat{Type: ebpf.StatTypeTCPRtt, TCPRtt: &ebpf.TCPRtt{}, CommonAttrs: pipe.CommonAttrs{DstPort: 80}}
	nvme := &ebpf.Stat{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{Device: "nvme0n1"}}
	sda := &ebpf.Stat{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{Device: "sda"}}

	filtered := func(config filter.AttributeFamilyConfig) []*ebpf.Stat {
		matchers, err := newStatMatchers(config, nil)
		require.NoError(t, err)
		return matchers.filter([]*ebpf.Stat{https, http, nvme, sda})
	}

	assert.Equal(t, []*ebpf.Stat{https, nvme, sda},
		filtered(filter.AttributeFamilyConfig{"dst.port": {Match: "443"}}),
		"a filter on a TCP attribute keeps the storage stats")
	assert.Equal(t, []*ebpf.Stat{https, http, nvme},
		filtered(filter.AttributeFamilyConfig{"system.device": {Match: "nvme*"}}),
		"a filter on a disk attribute keeps the TCP stats")
	assert.Equal(t, []*ebpf.Stat{https, nvme},
		filtered(filter.AttributeFamilyConfig{"dst_port": {Equals: new(443)}, "system.device": {Match: "nvme*"}}),
		"each stat is matched against all the filters of its attributes")
}

func TestStatFilterOfAnUnknownAttribute(t *testing.T) {
	_, err := newStatMatchers(filter.AttributeFamilyConfig{"not.an.attribute": {Match: "*"}}, nil)
	require.Error(t, err)
}

// Every stat type is matched against the filters of its own attributes
func TestEveryStatTypeHasItsMetrics(t *testing.T) {
	metrics := ebpf.StatTypeMetrics()
	for _, statType := range []ebpf.StatType{
		ebpf.StatTypeTCPRtt, ebpf.StatTypeTCPFailedConnection, ebpf.StatTypeTCPRetransmit, ebpf.StatTypeTCPIo,
		ebpf.StatTypeTCPSuccessfulConnection, ebpf.StatTypeDiskIO,
	} {
		assert.NotEmpty(t, metrics[statType], "stat type %d", statType)
	}
}
