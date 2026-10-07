// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	metric2 "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// BenchmarkStatExpirer_FsOperationDuration measures the per-event OTLP cost of
// one filesystem stat on obi.stat.fs.operation.duration, with Kubernetes
// metadata on and the default attribute selection: building the attribute
// set through the stat getters, finding its series, and recording the value.
func BenchmarkStatExpirer_FsOperationDuration(b *testing.B) {
	// A new series is logged at debug level, which the package tests enable.
	defaultLog := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	b.Cleanup(func() { slog.SetDefault(defaultLog) })

	sel, err := attributes.NewAttrSelector(attributes.GroupKubernetes, &attributes.SelectorConfig{
		SelectionCfg: attributes.Selection{},
	})
	require.NoError(b, err)
	getters := attributes.OpenTelemetryGetters(ebpf.StatGetters, sel.For(attributes.StatFsOperationDuration))

	provider := metric.NewMeterProvider(metric.WithReader(metric.NewManualReader()))
	h, err := provider.Meter(statScopeName).Float64Histogram(attributes.StatFsOperationDuration.OTEL)
	require.NoError(b, err)

	for _, tc := range []struct {
		name string
		stat *ebpf.Stat
	}{
		{name: "pod_on_pv", stat: benchFsStat(true)},
		{name: "no_pod_no_pv", stat: benchFsStat(false)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			ex := newStorageExpirer[metric2.Float64Histogram, float64](b.Context(), h, getters, timeNow, time.Hour)
			b.ReportAllocs()
			for b.Loop() {
				m, attrs := ex.ForRecord(tc.stat)
				m.Record(b.Context(), 0.002, metric2.WithAttributeSet(attrs))
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
