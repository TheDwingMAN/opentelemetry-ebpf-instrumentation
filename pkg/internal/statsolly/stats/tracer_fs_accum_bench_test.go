// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
)

// Userspace cost of kernel-aggregated filesystem metrics. It no longer grows
// with the operations: a poll costs per key that counted since the last one,
// whatever it counted, and decoding a key happens when it first counts (and
// every RedecorateAfter). Compare ns/key with the per-event cost per
// operation of BenchmarkStatExpirer_FsOperationDuration (OTel) plus
// BenchmarkStatsProm_FsOperationDuration (Prometheus).

// Decoding a key into its stat, without and with the pod from its cgroup.
func BenchmarkFsAccumStat(b *testing.B) {
	values := make([]byte, 152)
	key := fsKey(1, &ebpf.FsIo{Fs: uint8(ebpf.CodeFsXFS), Op: uint8(ebpf.CodeFsOpWrite), SDev: 253<<20 | 4, RootIno: 128})

	b.Run("pid path", func(b *testing.B) {
		d := fsDecoder{sampleTgid: fsValSampleTgid}
		b.ReportAllocs()
		for range b.N {
			d.stat(key, values)
		}
	})

	b.Run("cgroup index", func(b *testing.B) {
		const podUID = "8c1d0a4e-7b1f-4a52-9d57-0c2f3b6a9e11"
		containerID := strings.Repeat("ab", 32)
		root, _, container, _ := cgroupTree(b, podUID, containerID)
		index := statagg.NewCgroupIndex(statagg.WithCgroupRoots(root))
		require.NoError(b, index.Scan())
		d := fsDecoder{cgroups: index, pods: fakePods{podUID: podUID, containerID: containerID}, sampleTgid: fsValSampleTgid}
		key := fsKey(container, &ebpf.FsIo{Fs: uint8(ebpf.CodeFsXFS), Op: uint8(ebpf.CodeFsOpWrite)})
		b.ReportAllocs()
		for range b.N {
			d.stat(key, values)
		}
	})
}

// A collection where every key counted more operations since the last one:
// read the map, diff each key, add into the three metrics' series and build
// the Prometheus output. Keys are containers x volumes x operations.
func BenchmarkFsAccumCollect_AllChanged(b *testing.B) {
	for _, keys := range []int{1_000, 10_000} {
		b.Run(strconv.Itoa(keys), func(b *testing.B) {
			m := newFsTestMap(b, fsLayout(b))
			ios := make([]*ebpf.FsIo, keys)
			for i := range ios {
				ios[i] = &ebpf.FsIo{
					Fs: uint8(ebpf.CodeFsXFS), Op: uint8(i % 4), SDev: uint32(253<<20 | i/4%64), RootIno: 128,
					PidNs: uint32(4026532000 + i/256), HostPID: uint32(1000 + i), Bytes: 4096, LatencyNs: 200_000,
				}
				m.record(uint64(10_000+i/256), ios[i])
			}
			cfg, err := fsFamilyConfig(FsAccum{Source: m.m, Layout: m.layout})
			require.NoError(b, err)
			clock := time.Unix(1_700_000_000, 0)
			cfg.MinPollInterval = time.Nanosecond
			cfg.TickInterval = time.Hour
			cfg.Clock = func() time.Time { return clock }
			family, err := statagg.NewFamily(cfg)
			require.NoError(b, err)
			registry, err := statagg.NewRegistry(family)
			require.NoError(b, err)
			collector := benchCollector(b, registry, m.layout)
			go family.Run(b.Context())
			ch := make(chan prometheus.Metric, 3*keys)
			drain := func() {
				collector.Collect(ch)
				for len(ch) > 0 {
					<-ch
				}
			}
			time.Sleep(10 * time.Millisecond) // until Run has started: collections read the map
			drain()

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				for i, io := range ios {
					m.record(uint64(10_000+i/256), io)
				}
				clock = clock.Add(time.Second)
				b.StartTimer()
				drain()
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(keys), "ns/key")
		})
	}
}

// benchCollector exports the three filesystem metrics by filesystem type and
// operation, as the default attribute selection does without Kubernetes.
func benchCollector(tb testing.TB, registry *statagg.Registry, layout *statagg.Layout) *statagg.Collector {
	tb.Helper()
	fsType, ok := ebpf.StatStringGetters(attr.Name("system.filesystem.type"))
	require.True(tb, ok)
	fsOp, ok := ebpf.StatStringGetters(attr.FsOperation)
	require.True(tb, ok)
	project := func(s *ebpf.Stat) (string, []string) {
		v := []string{fsType(s), fsOp(s)}
		return statagg.SeriesKey(v), v
	}
	c := statagg.NewCollector(registry, time.Hour)
	labels := []string{"system_filesystem_type", "fs_operation"}
	for _, name := range []attributes.Name{attributes.StatFsOperationDuration, attributes.StatFsIO, attributes.StatFsOperationErrors} {
		require.NoError(tb, c.Add(name, statagg.PromMetric{Bounds: layout.Bounds, LabelNames: labels, Project: project}))
	}
	return c
}
