// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The upkeep of storage_block_volumes runs on timers, never per I/O: the
// scan of /sys/block and the sync of the kernel set every 30 s, the sweep of
// the bio in-flight map every minute. These benchmarks size them for a node
// with many logical volumes and a full in-flight map.

// benchSysBlock is a /sys/block of 16 disks and volumes thin volumes on one
// pool: the pool and its two lower devices are listed and left out.
func benchSysBlock(b *testing.B, volumes int) string {
	b.Helper()
	sysBlock := b.TempDir()
	device := func(name, dev string, dirs ...string) string {
		dir := filepath.Join(sysBlock, name)
		for _, sub := range append(dirs, "holders") {
			if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
				b.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "dev"), []byte(dev+"\n"), 0o644); err != nil {
			b.Fatal(err)
		}
		return dir
	}
	for i := range 16 {
		device(fmt.Sprintf("sd%c", 'a'+i), fmt.Sprintf("8:%d", 16*i), "mq/0")
	}
	for i := range 3 {
		dir := device(fmt.Sprintf("dm-%d", i), fmt.Sprintf("253:%d", i), "dm")
		if err := os.Symlink("../../dm-3", filepath.Join(dir, "holders", "dm-3")); err != nil {
			b.Fatal(err)
		}
	}
	for i := range volumes {
		device(fmt.Sprintf("dm-%d", 3+i), fmt.Sprintf("253:%d", 3+i), "dm")
	}
	return sysBlock
}

func BenchmarkListBlockVolumes(b *testing.B) {
	for _, volumes := range []int{16, 256, 1024} {
		b.Run(strconv.Itoa(volumes), func(b *testing.B) {
			sysBlock := benchSysBlock(b, volumes)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				scan, err := listBlockVolumes(sysBlock)
				if err != nil || len(scan.volumes) != volumes {
					b.Fatalf("%d volumes, %v", len(scan.volumes), err)
				}
			}
		})
	}
}

// A refresh that finds the set as it left it: the steady state. The kernel
// set is in memory, so this is the diff alone, without the map syscalls.
func BenchmarkVolumeSetRefresh_Unchanged(b *testing.B) {
	for _, volumes := range []int{16, 256, 1024} {
		b.Run(strconv.Itoa(volumes), func(b *testing.B) {
			scan := map[uint32]string{}
			for i := range volumes {
				scan[devT(majorDM, uint32(i))] = "dm-" + strconv.Itoa(i)
			}
			kernel := &fakeVolumeDevs{devs: map[uint32]bool{}}
			set := newVolumeSet(slog.New(slog.DiscardHandler),
				func() (blockVolumeScan, error) { return blockVolumeScan{volumes: maps.Clone(scan)}, nil },
				kernel, func([blkVolMajors]uint32) error { return nil })
			if err := set.refresh(); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := set.refresh(); err != nil {
					b.Fatal(err)
				}
			}
			if kernel.adds != volumes {
				b.Fatalf("%d adds for %d volumes", kernel.adds, volumes)
			}
		})
	}
}

// sliceBioInflight hands the sweep its entries from a slice, as the batch
// lookups of the kernel map do.
type sliceBioInflight struct {
	bios    []uint64
	values  []BlkBioBlkRqInflight
	deleted int
}

func (s *sliceBioInflight) ForEach(fn func(bio uint64, v *BlkBioBlkRqInflight)) error {
	for i := range s.bios {
		fn(s.bios[i], &s.values[i])
	}
	return nil
}

func (s *sliceBioInflight) DeleteIfQueuedAt(uint64, uint64) error {
	s.deleted++
	return nil
}

// The sweep's pass over a full in-flight map (64Ki bios in flight on 64
// volumes): none stale, the usual case, and 1 in 1024 stale, spread so that
// no volume is taken for dead.
func BenchmarkBioSweep(b *testing.B) {
	const entries = 1 << 16
	now := time.Hour
	for name, staleEvery := range map[string]int{"none stale": 0, "1 in 1024 stale": 1024} {
		b.Run(name, func(b *testing.B) {
			inflight := &sliceBioInflight{bios: make([]uint64, entries), values: make([]BlkBioBlkRqInflight, entries)}
			stale := 0
			for i := range entries {
				inflight.bios[i] = 0xffff_8880_0000_0000 + uint64(i)*0x100
				age := time.Duration(i%1000) * time.Millisecond
				if staleEvery != 0 && i%staleEvery == 0 {
					age = 2 * BlockInflightStaleAge
					stale++
				}
				inflight.values[i] = BlkBioBlkRqInflight{IssueNs: uint64(now - age), Dev: devT(majorDM, uint32((i+i/1024)%64))}
			}
			sweeper := &bioSweeper{
				log: slog.New(slog.DiscardHandler), inflight: inflight,
				monoNow:    func() time.Duration { return now },
				quarantine: func(uint32, int) { b.Fatal("no volume left that many bios") },
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if got := sweeper.sweep(); got != stale {
					b.Fatalf("%d stale entries, want %d", got, stale)
				}
			}
		})
	}
}
