// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// BenchmarkStatsProm_FsOperationDuration measures the per-event Prometheus
// cost of one filesystem stat on obi_stat_fs_operation_duration_seconds, with
// Kubernetes metadata on and the default attribute selection: the label
// values through the stat getters, the series lookup and the observation.
func BenchmarkStatsProm_FsOperationDuration(b *testing.B) {
	sel, err := attributes.NewAttrSelector(attributes.GroupKubernetes, &attributes.SelectorConfig{
		SelectionCfg: attributes.Selection{},
	})
	require.NoError(b, err)
	getters := attributes.PrometheusGetters(ebpf.StatStringGetters, sel.For(attributes.StatFsOperationDuration))

	for _, tc := range []struct {
		name string
		stat *ebpf.Stat
	}{
		{name: "pod_on_pv", stat: benchFsStat(true)},
		{name: "no_pod_no_pv", stat: benchFsStat(false)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			vec := NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:    attributes.StatFsOperationDuration.Prom,
				Buckets: prometheus.DefBuckets,
			}, labelNames(getters)).MetricVec, time.Now, time.Hour)
			b.ReportAllocs()
			for b.Loop() {
				vec.WithLabelValues(labelValues(tc.stat, getters)...).Metric.Observe(0.002)
			}
		})
	}
}

// benchFsStat is a filesystem stat as the PID decorator leaves it: on a pod's
// persistent volume, or from a process in no pod on a device that is no
// volume.
func benchFsStat(onPod bool) *ebpf.Stat {
	s := &ebpf.Stat{
		Type: ebpf.StatTypeFsIo,
		FsIo: &ebpf.FsIo{Fs: uint8(ebpf.CodeFsXFS), Op: uint8(ebpf.CodeFsOpWrite), LatencyNs: 2_000_000, Bytes: 4096},
	}
	if onPod {
		s.CommonAttrs = pipe.CommonAttrs{Metadata: map[attr.Name]string{
			attr.K8sPodName:       "writer-7d9f8b6c4-x2x7z",
			attr.K8sNamespaceName: "storage-test",
			attr.K8sContainerName: "writer",
		}}
		s.FsIo.Mount = &ebpf.MountAttrs{
			PVName:       "pvc-b3befffd-ae0d-4fa0-8cef-4949329d8c3f",
			PVCName:      "data-writer-0",
			StorageClass: "topolvm-provisioner",
			PVCNamespace: "storage-test",
		}
	}
	return s
}
