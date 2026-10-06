// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package stats

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

const (
	aggTestBlock  = 4096
	aggTestReads  = 48
	aggTestWrites = 16
	loopMajor     = 7
)

// The whole aggregated path on real kernel maps: the block programs count in
// the per-CPU maps, the families read them through batch lookups, and a
// Prometheus collector exports histogram counts and byte counters that equal
// what diskstats accounted for the device.
func TestBlockFamiliesOnRealMaps(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to load eBPF programs and set up block devices")
	}
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatDiskOperationDurationHistogram)
	require.NoError(t, err)
	features := export.FeatureStorageBlock
	fetcher, err := ebpf.NewStatsFetcher(&config.EBPFTracer{}, &features, &attributes.SelectorConfig{},
		ebpf.FsAggregation{}, ebpf.NFSConfig{}, &ebpf.BlockAggregation{BoundsNs: layout.KernelBounds(), BudgetBytes: 8 << 20}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { fetcher.Close() })
	maps := fetcher.BlockAggregation()
	require.NotNil(t, maps)

	service, err := statagg.NewMapSource(maps.Service)
	require.NoError(t, err)
	queue, err := statagg.NewMapSource(maps.Queue)
	require.NoError(t, err)
	keep := func(*ebpf.Stat) bool { return true }
	families, err := BlockFamilies(service, queue, layout, features,
		func() (func(*ebpf.Stat) bool, error) { return keep, nil })
	require.NoError(t, err)
	registry, err := statagg.NewRegistry(families...)
	require.NoError(t, err)

	collector := statagg.NewCollector(registry, time.Hour)
	project := func(s *ebpf.Stat) (string, []string) {
		values := []string{strconv.Itoa(int(s.BlockIo.Dev)), strconv.Itoa(int(s.BlockIo.Op))}
		return statagg.SeriesKey(values), values
	}
	labels := []string{"dev", "op"}
	require.NoError(t, collector.Add(attributes.StatDiskOperationDuration, statagg.PromMetric{
		Help: "h", Bounds: export.DefaultBuckets.StatDiskOperationDurationHistogram, LabelNames: labels, Project: project,
	}))
	require.NoError(t, collector.Add(attributes.StatDiskIO, statagg.PromMetric{Help: "h", LabelNames: labels, Project: project}))
	require.NoError(t, collector.Add(attributes.StatDiskFlushDuration, statagg.PromMetric{
		Help: "h", Bounds: export.DefaultBuckets.StatDiskOperationDurationHistogram, LabelNames: labels, Project: project,
	}))
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(collector))
	for _, f := range families {
		go f.Run(t.Context())
	}

	dev, path, stat := loopDevice(t)
	devLabel := strconv.Itoa(int(dev))
	read, write, flush := strconv.Itoa(int(ebpf.CodeBlockRead)), strconv.Itoa(int(ebpf.CodeBlockWrite)),
		strconv.Itoa(int(ebpf.CodeBlockFlush))
	type counts struct{ reads, writes, flushes, writeBytes uint64 }
	gather := func() counts {
		// The families read the maps at most once a second per collection.
		time.Sleep(1100 * time.Millisecond)
		mfs, err := reg.Gather()
		require.NoError(t, err)
		return counts{
			reads:      histogramCount(mfs, attributes.StatDiskOperationDuration.Prom, devLabel, read),
			writes:     histogramCount(mfs, attributes.StatDiskOperationDuration.Prom, devLabel, write),
			flushes:    histogramCount(mfs, attributes.StatDiskFlushDuration.Prom, devLabel, flush),
			writeBytes: uint64(counterValue(mfs, attributes.StatDiskIO.Prom, devLabel, write)),
		}
	}

	before := waitIdle(t, stat)
	base := gather()
	writeAndSync(t, path, aggTestWrites)
	readDirectBlocks(t, path, aggTestReads)
	after := waitIdle(t, stat)
	got := gather()
	delta := func(field int) uint64 { return after[field] - before[field] }

	// /sys/block/<dev>/stat, 0-based: 0 reads, 4 writes, 6 sectors written, 15 flushes.
	require.GreaterOrEqual(t, delta(0), uint64(aggTestReads))
	assert.Equal(t, delta(0), got.reads-base.reads, "one count per completed read")
	assert.Equal(t, delta(4)-delta(15), got.writes-base.writes,
		"one count per completed write, less the empty preflushes diskstats counts as writes")
	assert.Equal(t, delta(15), got.flushes-base.flushes, "one count per completed flush")
	assert.Equal(t, delta(6)*512, got.writeBytes-base.writeBytes, "bytes written")
}

func histogramCount(mfs []*dto.MetricFamily, name, dev, op string) uint64 {
	for _, m := range metricsOf(mfs, name, dev, op) {
		return m.GetHistogram().GetSampleCount()
	}
	return 0
}

func counterValue(mfs []*dto.MetricFamily, name, dev, op string) float64 {
	for _, m := range metricsOf(mfs, name, dev, op) {
		return m.GetCounter().GetValue()
	}
	return 0
}

func metricsOf(mfs []*dto.MetricFamily, name, dev, op string) []*dto.Metric {
	var out []*dto.Metric
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["dev"] == dev && labels["op"] == op {
				out = append(out, m)
			}
		}
	}
	return out
}

// loopDevice attaches a fresh loop device over a temporary file and returns
// its kernel dev_t, node and diskstats file.
func loopDevice(t *testing.T) (dev uint32, path, stat string) {
	t.Helper()
	return loopDeviceOfSize(t, 1<<20)
}

// loopDeviceOfSize is loopDevice over a file of size bytes.
func loopDeviceOfSize(t *testing.T, size int64) (dev uint32, path, stat string) {
	t.Helper()

	control, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no loop device support: %v", err)
	}
	defer control.Close()
	minor, err := unix.IoctlRetInt(int(control.Fd()), unix.LOOP_CTL_GET_FREE)
	require.NoError(t, err)

	name := fmt.Sprintf("loop%d", minor)
	path = filepath.Join("/dev", name)
	if _, err := os.Stat(path); err != nil {
		require.NoError(t, unix.Mknod(path, unix.S_IFBLK|0o600, int(unix.Mkdev(loopMajor, uint32(minor)))))
		t.Cleanup(func() { os.Remove(path) })
	}
	backing, err := os.Create(filepath.Join(t.TempDir(), "backing"))
	require.NoError(t, err)
	t.Cleanup(func() { backing.Close() })
	require.NoError(t, backing.Truncate(size))

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	require.NoError(t, unix.IoctlSetInt(int(f.Fd()), unix.LOOP_SET_FD, int(backing.Fd())))
	t.Cleanup(func() { _ = unix.IoctlSetInt(int(f.Fd()), unix.LOOP_CLR_FD, 0) })
	return loopMajor<<20 | uint32(minor), path, filepath.Join("/sys/block", name, "stat")
}

// waitIdle waits until the device's diskstats stop changing and returns them.
func waitIdle(t *testing.T, stat string) []uint64 {
	t.Helper()

	read := func() []uint64 {
		raw, err := os.ReadFile(stat)
		require.NoError(t, err)
		var out []uint64
		for _, f := range strings.Fields(string(raw)) {
			v, err := strconv.ParseUint(f, 10, 64)
			require.NoError(t, err)
			out = append(out, v)
		}
		require.Greater(t, len(out), 15, "kernel without flush accounting")
		return out
	}
	prev := read()
	for range 60 {
		time.Sleep(500 * time.Millisecond)
		cur := read()
		if cur[8] == 0 && fmt.Sprint(cur) == fmt.Sprint(prev) { // field 9: in flight
			return cur
		}
		prev = cur
	}
	t.Fatal("the loop device never went idle")
	return nil
}

func writeAndSync(t *testing.T, path string, n int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	buf := alignedBlock(t)
	for i := range n {
		_, err := f.WriteAt(buf, int64(i*aggTestBlock))
		require.NoError(t, err)
		require.NoError(t, unix.Fdatasync(int(f.Fd())))
	}
}

func readDirectBlocks(t *testing.T, path string, n int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECT, 0)
	require.NoError(t, err)
	defer f.Close()
	buf := alignedBlock(t)
	for i := range n {
		_, err := f.ReadAt(buf, int64(i*aggTestBlock))
		require.NoError(t, err)
	}
}

// alignedBlock is a page-aligned buffer, as O_DIRECT needs.
func alignedBlock(t *testing.T) []byte {
	t.Helper()
	buf, err := unix.Mmap(-1, 0, aggTestBlock, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Munmap(buf) })
	return buf
}
