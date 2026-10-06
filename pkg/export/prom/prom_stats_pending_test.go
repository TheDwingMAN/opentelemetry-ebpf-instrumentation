// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// devGetter is the real system.device getter alone, standing in for the
// full attribute selection so the test exercises pendingCollector's
// grouping, not the attribute selector.
var devGetter = attributes.PrometheusGetters(ebpf.StatStringGetters, []attr.Name{attr.DiskDevice})

// deviceAttr is the value devGetter resolves for dev: the fallback "M:m"
// name, since the test sandbox has no /sys/dev/block entry for it.
func deviceAttr(dev uint32) string {
	return labelValues(&ebpf.Stat{BlockIo: &ebpf.BlockIo{Dev: dev}}, devGetter)[0]
}

func newTestPendingCollector(snapshot func() ([]ebpf.PendingPoint, error)) *pendingCollector {
	return &pendingCollector{
		snapshot: snapshot,
		desc: prometheus.NewDesc(
			"obi_stat_disk_pending_operations", "test", labelNames(devGetter), nil,
		),
		getters: devGetter,
		log:     slog.With("component", "test"),
	}
}

func collectPending(t *testing.T, c *pendingCollector) []*dto.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 16)
	c.Collect(ch)
	close(ch)

	var out []*dto.Metric
	for m := range ch {
		var pb dto.Metric
		require.NoError(t, m.Write(&pb))
		out = append(out, &pb)
	}
	return out
}

func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

func TestPendingCollector_SumsPointsOntoOneSeriesPerDevice(t *testing.T) {
	points := []ebpf.PendingPoint{
		{Stat: &ebpf.Stat{BlockIo: &ebpf.BlockIo{Dev: 1, Op: uint8(ebpf.CodeBlockRead)}}, Value: 2},
		{Stat: &ebpf.Stat{BlockIo: &ebpf.BlockIo{Dev: 1, Op: uint8(ebpf.CodeBlockWrite)}}, Value: 3},
		{Stat: &ebpf.Stat{BlockIo: &ebpf.BlockIo{Dev: 2, Op: uint8(ebpf.CodeBlockRead)}}, Value: 5},
	}
	c := newTestPendingCollector(func() ([]ebpf.PendingPoint, error) { return points, nil })

	got := collectPending(t, c)
	require.Len(t, got, 2)

	sums := map[string]float64{}
	for _, m := range got {
		require.NotNil(t, m.GetGauge())
		sums[labelValue(m, "system_device")] = m.GetGauge().GetValue()
	}
	assert.Equal(t, map[string]float64{deviceAttr(1): 5, deviceAttr(2): 5}, sums)
}

func TestPendingCollector_CollectsNothingOnASnapshotError(t *testing.T) {
	c := newTestPendingCollector(func() ([]ebpf.PendingPoint, error) {
		return nil, errors.New("batch lookup failed")
	})
	assert.Empty(t, collectPending(t, c))
}
