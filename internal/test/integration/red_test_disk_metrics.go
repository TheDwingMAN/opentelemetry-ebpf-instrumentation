// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

// obiMetricsEndpoint is OBI's own Prometheus exposition endpoint, published to
// the host by docker-compose-disk-metrics.yml.
const obiMetricsEndpoint = "http://localhost:8999/metrics"

// diskExportPaths are the two independent routes by which OBI publishes disk
// metrics, keyed by the `exported` label that
// prometheus-config-disk-metrics.yml attaches to each scrape job.
//
// Both are asserted because they build the metric independently and can
// disagree. On the native path the series name comes straight from the `Prom`
// field of the attributes.Name definition; on the OTLP path OBI sends the
// dotted name plus a unit and the *collector* synthesizes a Prometheus name
// from them. A unit-suffix or type mismatch would show up on one path only.
var diskExportPaths = []string{"otel", "prometheus"}

// waitForDiskMetricsPipeline blocks until both export paths are actually
// carrying disk metrics.
//
// OBI and the collector start together, so OBI's first OTLP pushes are refused
// until the collector is listening. There is no instrumented HTTP service here
// to smoke-test the way waitForTestComponents does for the other suites, so we
// gate on the metrics themselves appearing on each path.
//
// Without this gate the first subtest spends its entire 60s testTimeout waiting
// on a pipeline that is still coming up and then fails on an empty result --
// which looks like "OBI is not collecting disk metrics" when collection is in
// fact working fine. Uses the same 2-minute budget as waitForTestComponents.
func waitForDiskMetricsPipeline(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, path := range diskExportPaths {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query(
				fmt.Sprintf(`obi_stat_disk_operation_duration_seconds_count{exported=%q}`, path))
			require.NoError(ct, err)
			enoughPromResults(ct, results)
		}, 2*time.Minute, time.Second, "disk metrics never arrived over the %q path", path)
	}
}

// testDiskMetricsOpDuration asserts that the `storage_block` feature emits the
// `obi_stat_disk_operation_duration_seconds` histogram with a positive `_count`, that
// its `disk_io_direction` label is one of read/write, and that a
// `system_device` label (e.g. "nvme0n1") is present. The
// block_rq_issue/complete tracepoints are node-wide, so this captures the
// diskload workload's I/O (and any other host block I/O) -- a non-empty
// response with a positive count is sufficient.
func testDiskMetricsOpDuration(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, path := range diskExportPaths {
		t.Run(path, func(t *testing.T) {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(
					fmt.Sprintf(`obi_stat_disk_operation_duration_seconds_count{exported=%q}`, path))
				require.NoError(ct, err)
				enoughPromResults(ct, results)
				assert.Positive(ct, totalPromCount(ct, results))

				for _, res := range results {
					assert.Contains(ct, []string{"read", "write"}, res.Metric["disk_io_direction"])
					assert.NotEmpty(ct, res.Metric["system_device"])
				}
			}, testTimeout, 100*time.Millisecond)
		})
	}
}

// testDiskMetricsOpDurationWrite asserts specifically on the write operation.
// The diskload workload forces its writes to the physical device with
// `conv=fdatasync`, so the "write" series is the deterministic one to gate on
// (reads depend on cache misses / O_DIRECT, which are best-effort in a
// container — see docker-compose-disk-metrics.yml).
func testDiskMetricsOpDurationWrite(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, path := range diskExportPaths {
		t.Run(path, func(t *testing.T) {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(fmt.Sprintf(
					`obi_stat_disk_operation_duration_seconds_count{exported=%q,disk_io_direction="write"}`, path))
				require.NoError(ct, err)
				enoughPromResults(ct, results)
				assert.Positive(ct, totalPromCount(ct, results))
				assert.NotEmpty(ct, results[0].Metric["system_device"])
			}, testTimeout, 100*time.Millisecond)
		})
	}
}

// testDiskMetricsIOBytes asserts that the `storage_block` feature emits the
// `obi_stat_disk_io_bytes_total` counter alongside the latency histogram, with
// the same device/direction labels. This is the disk *usage* (volume) signal:
// latency tells you how slow each request was, this tells you how much data
// actually moved.
func testDiskMetricsIOBytes(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, path := range diskExportPaths {
		t.Run(path, func(t *testing.T) {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(
					fmt.Sprintf(`obi_stat_disk_io_bytes_total{exported=%q}`, path))
				require.NoError(ct, err)
				enoughPromResults(ct, results)
				assert.Positive(ct, totalPromValue(ct, results))

				for _, res := range results {
					assert.Contains(ct, []string{"read", "write"}, res.Metric["disk_io_direction"])
					assert.NotEmpty(ct, res.Metric["system_device"])
				}
			}, testTimeout, 100*time.Millisecond)
		})
	}
}

// testDiskMetricsIOBytesWriteVolume gates on magnitude, not just presence.
// The diskload workload writes 64MiB per loop with `conv=fdatasync`, so a
// working counter must accumulate megabytes within the test window. A counter
// that is wired up but always reports the same tiny value (e.g. a single
// request's size, or a gauge-like overwrite) would pass a mere `> 0` check and
// fail this one.
//
// The floor is deliberately far below one loop iteration: block tracepoints are
// node-wide so the value also includes unrelated host I/O, and we only need to
// prove real volume is being accumulated rather than assert an exact figure.
func testDiskMetricsIOBytesWriteVolume(t *testing.T) {
	const minWrittenBytes = 4 * 1024 * 1024

	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, path := range diskExportPaths {
		t.Run(path, func(t *testing.T) {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				results, err := pq.Query(fmt.Sprintf(
					`obi_stat_disk_io_bytes_total{exported=%q,disk_io_direction="write"}`, path))
				require.NoError(ct, err)
				enoughPromResults(ct, results)
				assert.NotEmpty(ct, results[0].Metric["system_device"])
				assert.Greater(ct, totalPromValue(ct, results), float64(minWrittenBytes))
			}, testTimeout, 100*time.Millisecond)
		})
	}
}

// writeCacheWriteBack is what /sys/block/<dev>/queue/write_cache reads for a
// device with a volatile write cache. Only such a device is sent cache
// flushes: on a write-through device the kernel completes fdatasync's flush
// without issuing a request.
const writeCacheWriteBack = "write back"

// diskHasWriteBackCache reports whether the disk OBI names in system_device
// has a write-back cache. OBI names the whole disk ("sda"), or gives its
// major:minor when it cannot resolve a name. The block tracepoints are
// node-wide and this test runs on the same host, so the host's sysfs
// describes the same disk.
func diskHasWriteBackCache(device string) bool {
	dir := filepath.Join("/sys/block", device)
	if strings.Contains(device, ":") {
		dir = filepath.Join("/sys/dev/block", device)
	}
	cache, err := os.ReadFile(filepath.Join(dir, "queue", "write_cache"))
	return err == nil && strings.TrimSpace(string(cache)) == writeCacheWriteBack
}

// testDiskMetricsFlushDuration asserts that the cache flushes behind the
// diskload workload's `conv=fdatasync` reach
// `obi_stat_disk_flush_duration_seconds`, as a series of their own without a
// direction. A flush reaches the device only when it has a write-back cache,
// so the count is required to be positive across the written-to disks that
// have one; when the runner has none, there is no flush to observe and the
// subtest is skipped.
func testDiskMetricsFlushDuration(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	for _, path := range diskExportPaths {
		t.Run(path, func(t *testing.T) {
			var writeBack []string
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				writes, err := pq.Query(fmt.Sprintf(
					`obi_stat_disk_operation_duration_seconds_count{exported=%q,disk_io_direction="write"}`, path))
				require.NoError(ct, err)
				enoughPromResults(ct, writes)

				writeBack = writeBack[:0]
				for _, res := range writes {
					if device := res.Metric["system_device"]; diskHasWriteBackCache(device) {
						writeBack = append(writeBack, regexp.QuoteMeta(device))
					}
				}
				if len(writeBack) == 0 {
					return
				}

				flushes, err := pq.Query(fmt.Sprintf(
					`obi_stat_disk_flush_duration_seconds_count{exported=%q,system_device=~%q}`,
					path, strings.Join(writeBack, "|")))
				require.NoError(ct, err)
				enoughPromResults(ct, flushes)
				assert.Positive(ct, totalPromCount(ct, flushes))

				for _, res := range flushes {
					assert.Empty(ct, res.Metric["disk_io_direction"])
				}
			}, testTimeout, 100*time.Millisecond)

			if len(writeBack) == 0 {
				t.Skip("no written-to disk has a write-back cache, so none is sent flushes")
			}
		})
	}
}

// testDiskMetricsPromExposition scrapes OBI's own /metrics endpoint and asserts
// on the raw exposition text rather than on what Prometheus stored.
//
// Querying through Prometheus proves the samples arrive but says nothing about
// the HELP/TYPE metadata, and Prometheus will happily ingest a counter declared
// as a gauge. This checks the bytes metric is actually published as a counter
// and the latency metric as a histogram, which is what makes rate() and
// histogram_quantile() valid for consumers.
func testDiskMetricsPromExposition(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(obiMetricsEndpoint)
		require.NoError(ct, err)
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(ct, err)
		exposition := string(body)

		assert.Contains(ct, exposition, "# TYPE obi_stat_disk_io_bytes_total counter")
		assert.Contains(ct, exposition, "# TYPE obi_stat_disk_operation_duration_seconds histogram")
		// Sample lines carry both attributes, proving the labels survive the
		// native path and are not an artifact of the collector's conversion.
		assert.Regexp(ct, `obi_stat_disk_io_bytes_total\{[^}]*disk_io_direction="(read|write)"`, exposition)
		assert.Regexp(ct, `obi_stat_disk_io_bytes_total\{[^}]*system_device="[^"]+"`, exposition)

		// A family is only exposed once it has a series, and which flushes
		// and discards happen depends on the runner's disk (see
		// testDiskMetricsFlushDuration, which requires the flush series where
		// the disk has a write-back cache), so each family's type is checked
		// whenever its samples are there.
		for name, metricType := range map[string]string{
			"obi_stat_disk_flush_duration_seconds":   "histogram",
			"obi_stat_disk_discard_duration_seconds": "histogram",
			"obi_stat_disk_discard_io_bytes_total":   "counter",
		} {
			if strings.Contains(exposition, "\n"+name) {
				assert.Contains(ct, exposition, fmt.Sprintf("# TYPE %s %s", name, metricType))
			}
		}
	}, testTimeout, time.Second)
}
