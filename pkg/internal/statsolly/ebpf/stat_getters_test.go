// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
)

func TestStatGetters_DiskIO(t *testing.T) {
	write := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "nvme0n1", Op: CodeDiskOpWrite}}
	read := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{
		Device: "dm-0", VolumeName: "vg0-data", Stacked: true, Op: CodeDiskOpRead, ContainerID: "0123abcd",
	}}
	failed := &Stat{Type: StatTypeDiskIO, DiskIO: &DiskIO{Device: "sda", Op: CodeDiskOpRead, ErrorType: "EIO"}}
	read.CommonAttrs = pipe.CommonAttrs{Metadata: map[attr.Name]string{attr.K8sNamespaceName: "storage"}}
	rtt := &Stat{Type: StatTypeTCPRtt, TCPRtt: &TCPRtt{}}
	for _, tc := range []struct {
		name attr.Name
		stat *Stat
		want attribute.KeyValue
	}{
		{name: attr.SystemDevice, stat: write, want: attribute.String("system.device", "nvme0n1")},
		{name: attr.DiskStacked, stat: write, want: attribute.Bool("obi.disk.stacked", false)},
		{name: attr.DiskStacked, stat: read, want: attribute.Bool("obi.disk.stacked", true)},
		{name: attr.DiskVolumeName, stat: write},
		{name: attr.DiskVolumeName, stat: read, want: attribute.String("obi.disk.volume.name", "vg0-data")},
		{name: attr.DiskIODirection, stat: write, want: attribute.String("disk.io.direction", "write")},
		{name: attr.DiskIODirection, stat: read, want: attribute.String("disk.io.direction", "read")},
		{name: attr.ErrorType, stat: write},
		{name: attr.ErrorType, stat: failed, want: attribute.String("error.type", "EIO")},
		{name: attr.ContainerID, stat: write},
		{name: attr.ContainerID, stat: read, want: attribute.String("container.id", "0123abcd")},
		{name: attr.K8sNamespaceName, stat: read, want: attribute.String("k8s.namespace.name", "storage")},
		{name: attr.K8sNamespaceName, stat: write},
		{name: attr.K8sNamespaceName, stat: rtt, want: attribute.String("k8s.namespace.name", "")},
		{name: attr.SystemDevice, stat: rtt, want: attribute.String("system.device", "")},
		{name: attr.DiskStacked, stat: rtt, want: attribute.Bool("obi.disk.stacked", false)},
		{name: attr.DiskVolumeName, stat: rtt},
		{name: attr.DiskIODirection, stat: rtt, want: attribute.String("disk.io.direction", "")},
		{name: attr.ErrorType, stat: rtt},
	} {
		get, ok := StatGetters(tc.name)
		require.True(t, ok)
		assert.Equal(t, tc.want, get(tc.stat), "%s of %+v", tc.name, tc.stat.DiskIO)
	}
}
