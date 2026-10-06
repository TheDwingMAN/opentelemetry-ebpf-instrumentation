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
	nvmePartition := &ebpf.Stat{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{Device: "nvme0n1", Partition: "nvme0n1p1"}}
	sda := &ebpf.Stat{Type: ebpf.StatTypeDiskIO, DiskIO: &ebpf.DiskIO{Device: "sda"}}
	fsync := &ebpf.Stat{Type: ebpf.StatTypeFsSync, FsSync: &ebpf.FsSync{Type: ebpf.CodeFsSyncFsync}}

	filtered := func(config filter.AttributeFamilyConfig) []*ebpf.Stat {
		matchers, err := newStatMatchers(config, nil)
		require.NoError(t, err)
		return matchers.filter([]*ebpf.Stat{https, http, nvme, nvmePartition, sda, fsync})
	}

	assert.Equal(t, []*ebpf.Stat{https, nvme, nvmePartition, sda, fsync},
		filtered(filter.AttributeFamilyConfig{"dst.port": {Match: "443"}}),
		"a filter on a TCP attribute keeps the storage stats")
	assert.Equal(t, []*ebpf.Stat{https, http, nvme, nvmePartition, fsync},
		filtered(filter.AttributeFamilyConfig{"system.device": {Match: "nvme*"}}),
		"a filter on a disk attribute keeps the TCP and file sync stats")
	assert.Equal(t, []*ebpf.Stat{https, http, nvmePartition, fsync},
		filtered(filter.AttributeFamilyConfig{"obi_disk_partition": {Match: "nvme0n1p1"}}),
		"an attribute that the metrics of a stat have but the stat lacks doesn't match")
	assert.Equal(t, []*ebpf.Stat{https, nvmePartition, fsync},
		filtered(filter.AttributeFamilyConfig{"dst_port": {Equals: new(443)}, "obi.disk.partition": {Match: "nvme0n1p*"}}),
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
		ebpf.StatTypeTCPSuccessfulConnection, ebpf.StatTypeDiskIO, ebpf.StatTypeFsSync, ebpf.StatTypeDiskPending,
		ebpf.StatTypeNFSProcedure, ebpf.StatTypeNFSIO, ebpf.StatTypePodVolume, ebpf.StatTypeDiskVolume,
	} {
		assert.NotEmpty(t, metrics[statType], "stat type %d", statType)
	}
}
