// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats_test

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
)

// Each NFS flag makes the family aggregate its metric only: the exporters
// keep no per-event instrument for it, and nothing else.
func TestNFSRPCFamilyMetricsFollowTheFlags(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatNFSClientRPCDurationHistogram)
	require.NoError(t, err)
	all := []attributes.Name{
		attributes.StatNFSClientRPCDuration, attributes.StatNFSClientRPCErrors, attributes.StatNFSClientRPCRetransmits,
	}
	for _, tc := range []struct {
		features export.Features
		want     []attributes.Name
	}{
		{export.FeatureStorageNFS, all},
		{export.FeatureStorageNFSDuration, all[:1]},
		{export.FeatureStorageNFSErrors, all[1:2]},
		{export.FeatureStorageNFSRetransmits, all[2:]},
	} {
		n, err := stataggtest.NewNFS(layout, tc.features, nil)
		require.NoError(t, err)
		for _, name := range all {
			assert.Equal(t, contains(tc.want, name), n.Registry.Handles(name), "%s with %v", name.OTEL, tc.features)
		}
	}
}

func contains(names []attributes.Name, name attributes.Name) bool {
	for _, n := range names {
		if n.OTEL == name.OTEL {
			return true
		}
	}
	return false
}

// benchClock is a clock the benchmark advances between scrapes.
type benchClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *benchClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *benchClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// nfsBenchKeys returns n distinct NFS RPC attempts: NFSv4 operations to
// servers 10.0.x.y, a tenth of them failed.
func nfsBenchKeys(n int) []*ebpf.Stat {
	stats := make([]*ebpf.Stat, n)
	for i := range stats {
		rpc := &ebpf.NFSRPC{
			Version: 4, StatIdx: uint16(i % 40), Family: 2,
			Addr:      [16]byte{10, 0, byte(i / 40 / 256), byte(i / 40 % 256)},
			ExecuteNs: 300_000,
		}
		if i%10 == 9 {
			rpc.Status = -10008
		}
		stats[i] = &ebpf.Stat{Type: ebpf.StatTypeNFSRPC, NFSRPC: rpc}
	}
	return stats
}

// A Prometheus scrape of the NFS client RPC metrics when every kernel key
// counted since the last one: reading the map, the deltas, and building the
// scrape's series with the default attributes. This is the whole userspace
// cost of the NFS metrics: it depends on the number of keys (servers x
// procedures x error statuses, 20-60 per NFSv4 server), never on the RPC
// rate, which only the kernel program sees.
func BenchmarkNFSRPCScrape(b *testing.B) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatNFSClientRPCDurationHistogram)
	require.NoError(b, err)
	selector, err := attributes.NewAttrSelector(0, &attributes.SelectorConfig{})
	require.NoError(b, err)

	for _, keys := range []int{64, 1024, 4096} {
		b.Run(strconv.Itoa(keys), func(b *testing.B) {
			clock := &benchClock{now: time.Unix(1_700_000_000, 0)}
			n, err := stataggtest.NewNFS(layout, export.FeatureStorageNFS, nil, func(c *statagg.Config) {
				c.MinPollInterval = time.Nanosecond
				c.TickInterval = time.Hour
				c.Clock = clock.Now
			})
			require.NoError(b, err)
			c := statagg.NewCollector(n.Registry, time.Hour)
			for _, name := range []attributes.Name{
				attributes.StatNFSClientRPCDuration, attributes.StatNFSClientRPCErrors, attributes.StatNFSClientRPCRetransmits,
			} {
				getters := attributes.PrometheusGetters(ebpf.StatStringGetters, selector.For(name))
				labels := make([]string, len(getters))
				for i, g := range getters {
					labels[i] = g.ExposedName
				}
				require.NoError(b, c.Add(name, statagg.PromMetric{
					Bounds:     export.DefaultBuckets.StatNFSClientRPCDurationHistogram,
					LabelNames: labels,
					Project: func(s *ebpf.Stat) (string, []string) {
						values := make([]string, len(getters))
						for i, g := range getters {
							values[i] = g.Get(s)
						}
						return statagg.SeriesKey(values), values
					},
				}))
			}
			go n.Family.Run(b.Context())

			stats := nfsBenchKeys(keys)
			ch := make(chan prometheus.Metric, 2*keys)
			scrape := func() int {
				clock.Advance(time.Second)
				c.Collect(ch)
				got := len(ch)
				for len(ch) > 0 {
					<-ch
				}
				return got
			}
			// The family reads the map once Run has started: until the
			// first scrape shows series, the keys are new.
			for _, s := range stats {
				n.Record(s)
			}
			for scrape() == 0 {
				time.Sleep(time.Millisecond)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				for _, s := range stats {
					n.Record(s)
				}
				b.StartTimer()
				scrape()
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(keys), "ns/key")
		})
	}
}
