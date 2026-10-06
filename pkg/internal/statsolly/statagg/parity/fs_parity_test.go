// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package parity

import (
	"encoding/binary"
	"math"
	"math/rand/v2"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/statagg/stataggtest"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/stats"
)

var fsFeatures = export.FeatureStorageFSDuration | export.FeatureStorageFSIo | export.FeatureStorageFSErrors

// fsEvents is a deterministic stream of filesystem operations as the ring
// buffer delivers them: every filesystem and operation, on three volumes, by
// processes of four PID namespaces, some failing, latencies from 1us to 10s
// and on and next to each bound. See blockEvents for avoid.
func fsEvents(n int, bounds []uint64, avoid bool) []*ebpf.Stat {
	rnd := rand.New(rand.NewPCG(21, 22))
	type volume struct {
		fs      ebpf.FsTypeCode
		dev     uint32
		rootIno uint64
	}
	volumes := []volume{
		{ebpf.CodeFsXFS, 253<<20 | 4, 128},
		{ebpf.CodeFsExt4, 253<<20 | 5, 2},
		{ebpf.CodeFsNFS, 0<<20 | 57, 1311},
	}
	ops := []ebpf.FsOpCode{
		ebpf.CodeFsOpRead, ebpf.CodeFsOpWrite, ebpf.CodeFsOpFsync, ebpf.CodeFsOpFdatasync,
		ebpf.CodeFsOpSync, ebpf.CodeFsOpSyncfs, ebpf.CodeFsOpSyncFileRange,
	}
	latency := func() uint64 {
		for {
			v := uint64(math.Pow(10, 3+rnd.Float64()*7))
			if !avoid || !nearBound(bounds, v) {
				return v
			}
		}
	}
	var events []*ebpf.Stat
	for i := range n {
		v := volumes[rnd.IntN(len(volumes))]
		op := ops[rnd.IntN(len(ops))]
		var errno int32
		if rnd.IntN(8) == 0 {
			errno = []int32{-5, -28, -512}[rnd.IntN(3)]
		}
		// sync(2) names no volume (dev 0, root inode 0, filesystem unknown);
		// syncfs on a bad descriptor fails with EBADF and names none either.
		switch {
		case op == ebpf.CodeFsOpSync:
			v = volume{ebpf.CodeFsUnknown, 0, 0}
		case op == ebpf.CodeFsOpSyncfs && rnd.IntN(4) == 0:
			v = volume{ebpf.CodeFsUnknown, 0, 0}
			errno = -9
		}
		var bytes uint64
		if errno == 0 && (op == ebpf.CodeFsOpRead || op == ebpf.CodeFsOpWrite) {
			bytes = uint64(rnd.IntN(256) + 1)
		}
		lat := latency()
		if !avoid && i < 2*len(bounds) {
			lat = bounds[i/2] + uint64(i%2)
		}
		ns := uint32(4026532000 + rnd.IntN(4))
		events = append(events, &ebpf.Stat{Type: ebpf.StatTypeFsIo, FsIo: &ebpf.FsIo{
			Fs: uint8(v.fs), Op: uint8(op), SDev: v.dev, RootIno: v.rootIno,
			PidNs: ns, HostPID: uint32(1000 + rnd.IntN(50)),
			LatencyNs: lat, Bytes: bytes, Error: errno,
		}})
	}
	return events
}

// fsKernel counts events as bpf/statsolly/fs_io.c fs_aggregate does, into
// the key layout of fs_io.h, written here independently of the decoder's
// offsets. Each PID namespace stands for a container with its own cgroup.
func fsKernel(t *testing.T, layout *statagg.Layout) func(decorate func(*ebpf.Stat) bool) Kernel {
	valueSize, sampleTgid := 152, 148
	if layout.Kind == statagg.LayoutExponential {
		valueSize, sampleTgid = 536, 532
	}
	return func(decorate func(*ebpf.Stat) bool) Kernel {
		m := stataggtest.NewMemMap(32, valueSize, 1)
		family, err := stats.NewFsAccumFamily(stats.FsAccum{Source: m, Layout: layout, Decorate: decorate})
		require.NoError(t, err)
		registry, err := statagg.NewRegistry(family)
		require.NoError(t, err)
		return Kernel{
			Registry: registry,
			Families: []*statagg.Family{family},
			Record: func(s *ebpf.Stat) {
				io := s.FsIo
				key := make([]byte, 32)
				binary.NativeEndian.PutUint64(key[0:], uint64(io.PidNs)-4026531000)
				binary.NativeEndian.PutUint64(key[8:], io.RootIno)
				binary.NativeEndian.PutUint32(key[16:], io.SDev)
				binary.NativeEndian.PutUint32(key[20:], io.PidNs)
				key[24], key[25] = io.Fs, io.Op
				binary.NativeEndian.PutUint16(key[26:], uint16(-io.Error))

				m.AddU64(key, 0, 0, io.LatencyNs)
				m.AddU64(key, 0, 8, io.Bytes)
				idx := sort.Search(len(layout.BoundsNs), func(i int) bool { return io.LatencyNs <= layout.BoundsNs[i] })
				m.AddU32(key, 0, 16+4*idx, 1)
				m.SetU32(key, 0, sampleTgid, io.HostPID)
			},
		}
	}
}

func TestParityFs_ExplicitBuckets(t *testing.T) {
	otelBuckets := export.DefaultBuckets
	promBuckets := export.DefaultBuckets
	promBuckets.StatFsOperationDurationHistogram = []float64{0.0002, 0.001, 0.004, 0.02, 0.2, 2}
	layout, err := statagg.NewExplicitLayout(otelBuckets.StatFsOperationDurationHistogram, promBuckets.StatFsOperationDurationHistogram)
	require.NoError(t, err)

	Run(t, Setup{Features: fsFeatures, OTelBuckets: otelBuckets, PromBuckets: promBuckets},
		fsEvents(3000, layout.BoundsNs, false), fsKernel(t, layout))
}

func TestParityFs_ExponentialBuckets(t *testing.T) {
	layout, err := statagg.NewExponentialLayout(statagg.DefaultExponentialScale)
	require.NoError(t, err)
	Run(t, Setup{
		Features:    fsFeatures,
		OTelBuckets: export.DefaultBuckets,
		PromBuckets: export.DefaultBuckets,
		Exponential: true,
	}, fsEvents(3000, layout.BoundsNs, true), fsKernel(t, layout))
}

func TestParityFs_FiltersDropTheSameSeries(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatFsOperationDurationHistogram)
	require.NoError(t, err)
	for name, filters := range map[string]filter.AttributeFamilyConfig{
		"operation":  {"fs.operation": filter.MatchDefinition{Match: "write"}},
		"filesystem": {"system.filesystem.type": filter.MatchDefinition{NotMatch: "nfs"}},
		"error":      {"error.type": filter.MatchDefinition{NotMatch: "ENOSPC"}},
	} {
		t.Run(name, func(t *testing.T) {
			Run(t, Setup{
				Features:    fsFeatures,
				Filters:     filters,
				OTelBuckets: export.DefaultBuckets,
				PromBuckets: export.DefaultBuckets,
			}, fsEvents(1000, layout.BoundsNs, false), fsKernel(t, layout))
		})
	}
}

// With every attribute selected on the duration and none but the operation on
// the bytes, both paths split and merge the same series.
func TestParityFs_AttributeSelection(t *testing.T) {
	layout, err := statagg.NewExplicitLayout(export.DefaultBuckets.StatFsOperationDurationHistogram)
	require.NoError(t, err)
	Run(t, Setup{
		Features: fsFeatures,
		Selection: attributes.Selection{
			attributes.StatFsOperationDuration.Section: attributes.InclusionLists{Include: []string{"*"}},
			attributes.StatFsIO.Section:                attributes.InclusionLists{Include: []string{"fs.operation"}},
		},
		OTelBuckets: export.DefaultBuckets,
		PromBuckets: export.DefaultBuckets,
	}, fsEvents(1000, layout.BoundsNs, false), fsKernel(t, layout))
}
