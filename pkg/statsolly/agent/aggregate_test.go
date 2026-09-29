// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func blockStat(op ebpf.BlockOpCode, errno int32) *ebpf.Stat {
	return &ebpf.Stat{
		Type:    ebpf.StatTypeBlockIo,
		BlockIo: &ebpf.BlockIo{Dev: 252 << 20, Op: uint8(op), Error: errno, Bytes: 4096, LatencyNs: 100_000},
	}
}

func fsStat(op ebpf.FsOpCode, errno int32) *ebpf.Stat {
	return &ebpf.Stat{
		Type: ebpf.StatTypeFsIo,
		FsIo: &ebpf.FsIo{Fs: uint8(ebpf.CodeFsXFS), Op: uint8(op), Error: errno, Bytes: 512},
	}
}

func cloneStat(s *ebpf.Stat) *ebpf.Stat {
	c := *s
	if s.BlockIo != nil {
		b := *s.BlockIo
		c.BlockIo = &b
	}
	if s.FsIo != nil {
		f := *s.FsIo
		c.FsIo = &f
	}
	return &c
}

// The aggregated stats decorator keeps and decorates exactly the stats the
// per-event pipeline lets through to its exporters, for the same
// filters.stats rules.
func TestAggregatedStatDecorator_FiltersLikeThePipeline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		filters filter.AttributeFamilyConfig
		kept    int
	}{
		{name: "no filter", kept: 7},
		{name: "direction", kept: 2, filters: filter.AttributeFamilyConfig{
			"disk.io.direction": filter.MatchDefinition{Match: "write"},
		}},
		{name: "not error", kept: 4, filters: filter.AttributeFamilyConfig{
			"error_type": filter.MatchDefinition{NotMatch: "E*"},
		}},
		{name: "fs operation", kept: 1, filters: filter.AttributeFamilyConfig{
			"fs.operation": filter.MatchDefinition{Match: "read"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			out := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
			exported := out.Subscribe()
			s := Stats{
				agentIP: net.ParseIP("1.2.3.4"),
				ctxInfo: &global.ContextInfo{OverrideStatsExportQueue: out},
				cfg: &obi.Config{
					Metrics: perapp.GlobalMetricsConfig{Features: export.FeatureStorageBlock | export.FeatureStorageFS},
					Filters: filter.AttributesConfig{Stats: tc.filters},
				},
			}
			ringBuf := make(chan []*ebpf.Stat, 10)
			newRingBufTracer = func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
				return func(ctx context.Context) {
					for i := range ringBuf {
						out.SendCtx(ctx, i)
					}
				}
			}
			runner, err := s.buildPipeline(ctx)
			require.NoError(t, err)
			go runner.Start(ctx)

			decorate, err := s.newAggregatedStatDecorator(ctx)
			require.NoError(t, err)

			events := []*ebpf.Stat{
				blockStat(ebpf.CodeBlockRead, 0),
				blockStat(ebpf.CodeBlockWrite, 0),
				blockStat(ebpf.CodeBlockWrite, -5),
				blockStat(ebpf.CodeBlockFlush, 0),
				blockStat(ebpf.CodeBlockDiscard, -95),
				fsStat(ebpf.CodeFsOpRead, 0),
				fsStat(ebpf.CodeFsOpFsync, -5),
			}
			var want []*ebpf.Stat
			for _, e := range events {
				if c := cloneStat(e); decorate(c) {
					want = append(want, c)
				}
			}

			require.Len(t, want, tc.kept)

			ringBuf <- events
			var got []*ebpf.Stat
			deadline := time.After(timeout)
			for len(got) < len(want) {
				select {
				case batch := <-exported:
					got = append(got, batch...)
				case <-deadline:
					t.Fatalf("the pipeline exported %d stats, the decorator kept %d", len(got), len(want))
				}
			}
			select {
			case batch := <-exported:
				t.Fatalf("the pipeline exported %d more stats than the decorator kept", len(batch))
			case <-time.After(100 * time.Millisecond):
			}

			require.Len(t, got, len(want))
			for i := range want {
				assert.Equal(t, want[i].CommonAttrs, got[i].CommonAttrs)
				assert.Equal(t, want[i].BlockIo, got[i].BlockIo)
				assert.Equal(t, want[i].FsIo, got[i].FsIo)
			}
			close(ringBuf)
		})
	}
}

func TestAggregatedStatDecorator_RejectsAnUnknownFilterAttribute(t *testing.T) {
	s := Stats{
		ctxInfo: &global.ContextInfo{},
		cfg: &obi.Config{Filters: filter.AttributesConfig{Stats: filter.AttributeFamilyConfig{
			"no_such_attribute": filter.MatchDefinition{Match: "x"},
		}}},
	}
	_, err := s.newAggregatedStatDecorator(t.Context())
	require.Error(t, err)
}
