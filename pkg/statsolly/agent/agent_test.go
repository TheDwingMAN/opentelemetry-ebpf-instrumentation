// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// closingMap is a kernel aggregation map that the fetcher closes.
type closingMap struct {
	closed      atomic.Bool
	reads       atomic.Int32
	readsClosed atomic.Int32
}

func (*closingMap) KeySize() int     { return 4 }
func (*closingMap) ValueStride() int { return 8 }
func (*closingMap) CPUs() int        { return 1 }

func (m *closingMap) ForEach(func(key, values []byte)) error {
	if m.closed.Load() {
		m.readsClosed.Add(1)
		return errors.New("map closed")
	}
	m.reads.Add(1)
	return nil
}

func (*closingMap) LookupAndDelete(_, _ []byte) (bool, error) { return false, nil }

// closingFetcher closes the map, recording how many times it was read by
// then.
type closingFetcher struct {
	m             *closingMap
	readsAtClosed int32
}

func (f *closingFetcher) Close() error {
	f.readsAtClosed = f.m.reads.Load()
	f.m.closed.Store(true)
	return nil
}

func (*closingFetcher) StatsEventsMap() *ciliumebpf.Map { return nil }
func (*closingFetcher) DebugEventsMap() *ciliumebpf.Map { return nil }
func (*closingFetcher) NFSRPCMap() *ciliumebpf.Map      { return nil }
func (*closingFetcher) FsAccumMap() *ciliumebpf.Map     { return nil }

// On shutdown, the kernel aggregation families read their maps a last time
// before the fetcher closes them, and never after.
func TestStop_FamiliesReadTheirMapsBeforeTheyAreClosed(t *testing.T) {
	m := &closingMap{}
	family, err := statagg.NewFamily(statagg.Config{
		Name:   "test",
		Source: m,
		Layout: statagg.ValueLayout{Counters: 1},
		Stat:   func(_, _ []byte) (*ebpf.Stat, bool) { return nil, true },
		// no tick before the shutdown
		TickInterval: time.Hour,
	})
	require.NoError(t, err)
	fetcher := &closingFetcher{m: m}
	s := &Stats{
		cfg:      &obi.Config{ShutdownTimeout: 10 * time.Second},
		fetcher:  fetcher,
		families: []*statagg.Family{family},
	}
	s.graph, err = (&swarm.Instancer{}).Instance(t.Context())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	s.graph.Start(ctx)
	s.runAggregation(ctx)
	cancel()
	require.NoError(t, s.stop())

	assert.Equal(t, int32(1), fetcher.readsAtClosed, "the last read, before the map was closed")
	assert.Zero(t, m.readsClosed.Load(), "no read of a closed map")
}
