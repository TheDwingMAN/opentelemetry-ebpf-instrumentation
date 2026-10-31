// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestStatGetters_DiskIO(t *testing.T) {
	write := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "nvme0n1", Op: CodeDiskOpWrite}}
	read := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "vda", Op: CodeDiskOpRead}}
	rtt := &Stat{Type: StatTypeTCPRtt, TCPRtt: &TCPRtt{}}
	for _, tc := range []struct {
		name attr.Name
		stat *Stat
		want string
	}{
		{name: attr.SystemDevice, stat: write, want: "nvme0n1"},
		{name: attr.DiskIODirection, stat: write, want: "write"},
		{name: attr.DiskIODirection, stat: read, want: "read"},
		{name: attr.SystemDevice, stat: rtt},
		{name: attr.DiskIODirection, stat: rtt},
	} {
		get, ok := StatGetters(tc.name)
		require.True(t, ok)
		assert.Equal(t, attribute.String(string(tc.name), tc.want), get(tc.stat))
	}
}
