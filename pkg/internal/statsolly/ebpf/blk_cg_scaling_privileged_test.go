// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The scaling benchmark of spec 2.3 for blk_cg_agg: whether the pod
// counters can live in a map shared by every CPU (one copy of each value,
// updated with atomics) or need a per-CPU one (a copy per possible CPU).
// The question is what one hot key costs when every CPU completes I/O for
// the same pod and device: a shared value's cache line then moves between
// the CPUs on every completion.
//
// The kernel cannot test-run a tracing program on its hook, so the update
// is a program of its own with the same body as the completion's: a lookup
// by a 24-byte key and three atomic adds to a 24-byte value. It runs through
// BPF_PROG_TEST_RUN on N CPUs at once, one pinned thread per CPU, and each
// thread reads the kernel's mean time per run. "hot" is one key for every
// CPU; "spread" is a key per CPU, the shared map's best case. "empty" is the
// test-run loop with a program that does nothing, to subtract.
//
// Run with:
//
//	go test -tags privileged_tests -run '^$' -bench BlkCgAggScaling ./pkg/internal/statsolly/ebpf/
func BenchmarkBlkCgAggScaling(b *testing.B) {
	var allowed unix.CPUSet
	require.NoError(b, unix.SchedGetaffinity(0, &allowed))
	var onCPUs []int
	for cpu := range ebpf.MustPossibleCPU() {
		if allowed.IsSet(cpu) {
			onCPUs = append(onCPUs, cpu)
		}
	}
	cpus := len(onCPUs)
	counts := []int{1, 2, 4}
	for n := 8; n < cpus; n *= 2 {
		counts = append(counts, n)
	}
	if counts[len(counts)-1] != cpus {
		counts = append(counts, cpus)
	}
	for _, variant := range []struct {
		name    string
		mapType ebpf.MapType
		spread  bool
		empty   bool
	}{
		{name: "empty", empty: true},
		{name: "percpu_hot", mapType: ebpf.PerCPUHash},
		{name: "shared_hot", mapType: ebpf.Hash},
		{name: "shared_spread", mapType: ebpf.Hash, spread: true},
	} {
		prog := blkCgScalingProgram(b, variant.mapType, variant.spread, variant.empty, ebpf.MustPossibleCPU())
		for _, n := range counts {
			b.Run(fmt.Sprintf("%s/cpus=%d", variant.name, n), func(b *testing.B) {
				b.ReportMetric(float64(blkCgScalingRun(b, prog, onCPUs[:n], b.N).Nanoseconds()), "ns/run")
				// The per-run time is the metric; ns/op would be wall time
				// over b.N, which N threads in parallel divide.
				b.ReportMetric(0, "ns/op")
			})
		}
	}
}

// blkCgScalingProgram returns the update program over a fresh map of
// mapType holding its keys, or the empty program.
func blkCgScalingProgram(b *testing.B, mapType ebpf.MapType, spread, empty bool, cpus int) *ebpf.Program {
	b.Helper()
	insns := asm.Instructions{}
	if !empty {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Type: mapType, KeySize: 24, ValueSize: 24, MaxEntries: uint32(cpus),
		})
		require.NoError(b, err)
		b.Cleanup(func() { m.Close() })
		// The keys exist beforehand, as they do after the first completion.
		for id := range cpus {
			key := make([]byte, 24)
			key[0] = byte(id)
			binary.NativeEndian.PutUint32(key[8:], 8<<20|16)
			key[16] = 1
			var value any = make([]byte, 24)
			if mapType == ebpf.PerCPUHash {
				value = make([][]byte, ebpf.MustPossibleCPU())
				for i := range value.([][]byte) {
					value.([][]byte)[i] = make([]byte, 24)
				}
			}
			require.NoError(b, m.Put(key, value))
		}

		// key = {cgid, dev, part_dev, dir}: cgid 0 (hot) or the CPU number
		// (spread), dev 8:16, no partition, write. An immediate is stored
		// through a register: BPF has no 64-bit store of an immediate.
		if spread {
			insns = append(insns, asm.FnGetSmpProcessorId.Call())
		} else {
			insns = append(insns, asm.Mov.Imm(asm.R0, 0))
		}
		insns = append(insns,
			asm.StoreMem(asm.RFP, -24, asm.R0, asm.DWord),
			asm.Mov.Imm(asm.R1, 8<<20|16),
			asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord),
			asm.Mov.Imm(asm.R1, 1),
			asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord),
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -24),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "out"),
			// count += 1, bytes += 4096, time_ns += 100000
			asm.Mov.Imm(asm.R1, 1),
			asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			asm.Add.Imm(asm.R0, 8),
			asm.Mov.Imm(asm.R1, 4096),
			asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			asm.Add.Imm(asm.R0, 8),
			asm.Mov.Imm(asm.R1, 100000),
			asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		)
	}
	insns = append(insns,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
		asm.Return(),
	)
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter, Instructions: insns, License: "Dual MIT/GPL",
	})
	require.NoError(b, err, "%+v", err)
	b.Cleanup(func() { prog.Close() })
	return prog
}

// blkCgScalingRun runs prog repeat times on each of cpus at once and
// returns the mean of their per-run times.
func blkCgScalingRun(b *testing.B, prog *ebpf.Program, cpus []int, repeat int) time.Duration {
	b.Helper()
	repeat = max(repeat, 100000)
	in := make([]byte, 14)
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		total time.Duration
		errs  []error
	)
	start := make(chan struct{})
	for _, cpu := range cpus {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var set unix.CPUSet
			set.Set(cpu)
			if err := unix.SchedSetaffinity(0, &set); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("pin to CPU %d: %w", cpu, err))
				mu.Unlock()
				return
			}
			<-start
			_, perRun, err := prog.Benchmark(in, repeat, nil)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("test run on CPU %d: %w", cpu, err))
				return
			}
			total += perRun
		}()
	}
	b.ResetTimer()
	close(start)
	wg.Wait()
	require.Empty(b, errs)
	return total / time.Duration(len(cpus))
}
