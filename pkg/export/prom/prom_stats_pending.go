// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

// pendingCollector collects obi.stat.disk.pending_operations on every
// scrape: a userspace snapshot has no events to observe between scrapes, so,
// unlike the other stat metrics, it is a prometheus.Collector rather than a
// MetricVec an observeXxx method updates.
type pendingCollector struct {
	snapshot func() ([]ebpf.PendingPoint, error)
	desc     *prometheus.Desc
	getters  []attributes.Field[*ebpf.Stat, string]
	log      *slog.Logger
}

func newPendingCollector(cfg *StatsPrometheusConfig, provider *attributes.AttrSelector) *pendingCollector {
	getters := attributes.PrometheusGetters(ebpf.StatStringGetters, provider.For(attributes.StatDiskPendingOperations))
	return &pendingCollector{
		snapshot: cfg.PendingSnapshot,
		desc: prometheus.NewDesc(
			attributes.StatDiskPendingOperations.Prom,
			"count of block I/O requests still in flight on the device right now, from a snapshot of the kernel's in-flight map",
			labelNames(getters), nil,
		),
		getters: getters,
		log:     slog.With("component", "prom.PendingCollector"),
	}
}

func (c *pendingCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

// Collect groups one snapshot by label values first: an attribute selection
// can collapse several raw keys onto one series (e.g. several request kinds
// when disk.io.direction is not selected), and a Prometheus collector that
// sends the same label set twice in one Collect is invalid, so they are
// summed rather than sent twice.
func (c *pendingCollector) Collect(ch chan<- prometheus.Metric) {
	series, err := c.snapshot()
	if err != nil {
		c.log.Debug("can't snapshot pending block requests", "error", err)
		return
	}

	sums := map[string]float64{}
	labels := map[string][]string{}
	for _, s := range series {
		values := labelValues(s.Stat, c.getters)
		key := statagg.SeriesKey(values)
		sums[key] += float64(s.Value)
		labels[key] = values
	}

	for key, sum := range sums {
		m, err := prometheus.NewConstMetric(c.desc, prometheus.GaugeValue, sum, labels[key]...)
		if err != nil {
			c.log.Debug("can't build disk pending operations metric", "error", err)
			continue
		}
		ch <- m
	}
}
