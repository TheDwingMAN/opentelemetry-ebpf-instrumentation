// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"log/slog"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
)

// the kernel functions of every file sync hook
func allFsSyncFunctions() []string {
	var functions []string
	for _, hook := range fsSyncHooks {
		functions = append(functions, hook.kernelFunction())
	}
	return functions
}

func without(functions []string, removed ...string) []string {
	return slices.DeleteFunc(slices.Clone(functions), func(function string) bool {
		return slices.Contains(removed, function)
	})
}

// kernelWith builds a kernel BTF with the given functions, and the struct of the kernels whose BPF
// trampolines are safe for the functions that sleep if safe is set
func kernelWith(t *testing.T, safe bool, functions []string) *btf.Spec {
	t.Helper()
	var types []btf.Type
	if safe {
		types = append(types, &btf.Struct{Name: safeTrampolineStruct})
	}
	for _, function := range functions {
		types = append(types, kernelFunc(function))
	}
	return btfSpecOfTypes(t, types...)
}

func TestFsSyncTracingHooks(t *testing.T) {
	assert.Equal(t, allFsSyncHooks(), fsSyncTracingHooks(kernelWith(t, true, allFsSyncFunctions())),
		"every hook is timed with fentry and fexit programs where the kernel has their functions")
	assert.Empty(t, fsSyncTracingHooks(kernelWith(t, false, allFsSyncFunctions())),
		"the trampolines of the kernels without bpf_tramp_image (e.g. 5.8) are unsafe for the functions that sleep")

	// a function that the kernel inlined, or whose system call wrapper is not in its BTF, falls back
	// to its kprobes, and only it
	for _, missing := range []string{"do_fsync", "vfs_fsync_range", kprobe.SyscallPrefix() + "sys_fdatasync"} {
		tracing := fsSyncTracingHooks(kernelWith(t, true, without(allFsSyncFunctions(), missing)))
		assert.Len(t, tracing, len(fsSyncHooks)-1, missing)
		for _, hook := range fsSyncHooks {
			assert.Equal(t, hook.kernelFunction() != missing, tracing[hook.function], hook.function)
		}
	}
}

// sync(2) is timed at ksys_sync, which its system call wrapper calls: the wrapper isn't in the BTF of
// most kernels, and timing both would count each sync twice
func TestFsSyncHooksTimeSyncAtKsysSync(t *testing.T) {
	functions := make([]string, 0, len(fsSyncHooks))
	for _, hook := range fsSyncHooks {
		functions = append(functions, hook.function)
	}
	assert.Contains(t, functions, "ksys_sync")
	assert.NotContains(t, functions, "sys_sync")
	assert.Contains(t, functions, fsSyncRequiredHook)
}

func TestFsSyncKernelFunctions(t *testing.T) {
	kernelFunctions := map[string]string{}
	for _, hook := range fsSyncHooks {
		kernelFunctions[hook.function] = hook.kernelFunction()
	}
	assert.Equal(t, "vfs_fsync_range", kernelFunctions["vfs_fsync_range"])
	assert.Equal(t, "ksys_sync", kernelFunctions["ksys_sync"])
	assert.Equal(t, kprobe.SyscallPrefix()+"sys_sync_file_range", kernelFunctions["sys_sync_file_range"])
}

func TestFsSyncProgramsToDisable(t *testing.T) {
	var tracingPrograms, kprobePrograms []string
	for _, hook := range fsSyncHooks {
		tracingPrograms = append(tracingPrograms, hook.fentry, hook.fexit)
		kprobePrograms = append(kprobePrograms, hook.kprobe, hook.kretprobe)
	}

	off := storageProbes{}
	assert.Subset(t, off.programsToDisable(), slices.Concat(tracingPrograms, kprobePrograms),
		"no file sync program is loaded when the file sync stats are disabled")

	kprobes := storageProbes{fsSync: true}
	assert.Subset(t, kprobes.programsToDisable(), tracingPrograms)
	for _, program := range kprobePrograms {
		assert.NotContains(t, kprobes.programsToDisable(), program, "the kprobes are always loaded")
	}

	tracing := storageProbes{fsSync: true, fsSyncTracing: allFsSyncHooks()}
	for _, program := range slices.Concat(tracingPrograms, kprobePrograms) {
		assert.NotContains(t, tracing.programsToDisable(), program)
	}

	mixed := storageProbes{fsSync: true, fsSyncTracing: allFsSyncHooks()}
	delete(mixed.fsSyncTracing, "do_fsync")
	assert.Subset(t, mixed.programsToDisable(), []string{StatsProgObiStatsFentryDoFsync, StatsProgObiStatsFexitDoFsync})
	assert.NotContains(t, mixed.programsToDisable(), StatsProgObiStatsFexitVfsFsyncRange)
}

// The programs of the file sync hooks are programs of the spec, and every tracing program is one
func TestFsSyncProgramNames(t *testing.T) {
	spec, err := LoadStats()
	require.NoError(t, err)
	names := fsSyncProgramNames()
	for _, name := range names {
		assert.Contains(t, spec.Programs, name)
	}
	for name, program := range spec.Programs {
		if program.Type == ebpf.Tracing {
			assert.Contains(t, names, name)
		}
	}
	assert.Len(t, names, len(fsSyncPrograms(&StatsObjects{})), "every program can be found once loaded")
}

// The fentry and fexit programs name the kernel functions of the system calls, which have the prefix
// of the architecture
func TestSetFsSyncTracingTargets(t *testing.T) {
	spec, err := LoadStats()
	require.NoError(t, err)
	assert.Equal(t, "sys_fsync", spec.Programs[StatsProgObiStatsFentrySysFsync].AttachTo)

	setFsSyncTracingTargets(spec)
	assert.Equal(t, kprobe.SyscallPrefix()+"sys_fsync", spec.Programs[StatsProgObiStatsFentrySysFsync].AttachTo)
	assert.Equal(t, kprobe.SyscallPrefix()+"sys_fsync", spec.Programs[StatsProgObiStatsFexitSysFsync].AttachTo)
	assert.Equal(t, "vfs_fsync_range", spec.Programs[StatsProgObiStatsFexitVfsFsyncRange].AttachTo)
	assert.Equal(t, "ksys_sync", spec.Programs[StatsProgObiStatsFentryKsysSync].AttachTo)
}

// A disabled tracing program is replaced with a stub of another type: a tracing program needs a
// kernel function to attach to
func TestFixupSpecStubsTracingPrograms(t *testing.T) {
	spec, err := LoadStats()
	require.NoError(t, err)
	require.Equal(t, ebpf.Tracing, spec.Programs[StatsProgObiStatsFexitDoFsync].Type)

	require.NoError(t, fixupSpec(spec, []string{StatsProgObiStatsFexitDoFsync, StatsProgObiStatsKprobeDoFsync}))
	assert.Equal(t, "stats_dummy", spec.Programs[StatsProgObiStatsFexitDoFsync].Name)
	assert.Equal(t, ebpf.Kprobe, spec.Programs[StatsProgObiStatsFexitDoFsync].Type)
	assert.Empty(t, spec.Programs[StatsProgObiStatsFexitDoFsync].AttachTo)
	assert.Equal(t, ebpf.Kprobe, spec.Programs[StatsProgObiStatsKprobeDoFsync].Type)
}

// btfSpecOfTypes builds a kernel BTF with the given types
func btfSpecOfTypes(t *testing.T, types ...btf.Type) *btf.Spec {
	t.Helper()
	builder, err := btf.NewBuilder(types, nil)
	require.NoError(t, err)
	raw, err := builder.Marshal(nil, nil)
	require.NoError(t, err)
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	require.NoError(t, err)
	return spec
}

func kernelFunc(name string) *btf.Func {
	return &btf.Func{Name: name, Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}}
}

// The verifier test loads the fentry and fexit programs of every function that the kernel has, as
// the kernel BTF tells, even without safe trampolines, and stubs the others
func TestPrepareStatsSpec(t *testing.T) {
	spec, err := LoadStats()
	require.NoError(t, err)
	kernel := btfSpecOfTypes(t, kernelFunc("vfs_fsync_range"), kernelFunc(kprobe.SyscallPrefix()+"sys_fsync"))

	require.NoError(t, PrepareStatsSpec(spec, kernel))
	assert.Equal(t, ebpf.Tracing, spec.Programs[StatsProgObiStatsFexitVfsFsyncRange].Type)
	assert.Equal(t, ebpf.Tracing, spec.Programs[StatsProgObiStatsFentrySysFsync].Type)
	assert.Equal(t, kprobe.SyscallPrefix()+"sys_fsync", spec.Programs[StatsProgObiStatsFentrySysFsync].AttachTo)
	for _, stub := range []string{StatsProgObiStatsFentryDoFsync, StatsProgObiStatsFexitDoFsync, StatsProgObiStatsFexitKsysSync} {
		assert.Equal(t, "stats_dummy", spec.Programs[stub].Name, stub)
	}
	assert.Equal(t, ebpf.Kprobe, spec.Programs[StatsProgObiStatsKprobeDoFsync].Type, "the kprobes are kept")
}

func TestFsSyncTracingHookOf(t *testing.T) {
	tracing := allFsSyncHooks()
	hook, ok := fsSyncTracingHookOf(errors.New("loading and assigning BPF objects: program obi_stats_fexit_sys_sync_file_range: "+
		"attach Tracing/TraceFExit: fexit __x64_sys_sync_file_range not supported"), tracing)
	assert.True(t, ok)
	assert.Equal(t, "sys_sync_file_range", hook)

	hook, ok = fsSyncTracingHookOf(errors.New("program obi_stats_fentry_do_fsync: load program: permission denied"), tracing)
	assert.True(t, ok)
	assert.Equal(t, "do_fsync", hook)

	_, ok = fsSyncTracingHookOf(errors.New("program obi_stats_raw_tp_block_rq_complete: load program: invalid argument"), tracing)
	assert.False(t, ok, "not a tracing program")
	_, ok = fsSyncTracingHookOf(errors.New("program obi_stats_kprobe_do_fsync: load program: invalid argument"), tracing)
	assert.False(t, ok, "a kprobe")
	delete(tracing, "do_fsync")
	_, ok = fsSyncTracingHookOf(errors.New("program obi_stats_fentry_do_fsync: load program: invalid argument"), tracing)
	assert.False(t, ok, "a hook already on kprobes")
}

// A hook whose fentry or fexit program the kernel can't load falls back to its kprobes, alone, and
// the programs are loaded again
func TestStorageProbesFallBackToKprobes(t *testing.T) {
	storage := storageProbes{disk: true, fsSync: true, fsSyncTracing: allFsSyncHooks()}
	var loads [][]string
	err := storage.loadOrDisable(func(toDisable []string) error {
		loads = append(loads, toDisable)
		switch len(loads) {
		case 1:
			return errors.New("program obi_stats_fexit_sys_fdatasync: attach Tracing/TraceFExit: not supported")
		case 2:
			return errors.New("program obi_stats_fentry_do_fsync: load program: permission denied")
		}
		return nil
	}, nil)

	require.NoError(t, err)
	require.Len(t, loads, 3)
	assert.NotContains(t, loads[0], StatsProgObiStatsFexitSysFdatasync)
	assert.Subset(t, loads[1], []string{StatsProgObiStatsFentrySysFdatasync, StatsProgObiStatsFexitSysFdatasync})
	assert.NotContains(t, loads[1], StatsProgObiStatsFexitDoFsync)
	assert.Subset(t, loads[2], []string{StatsProgObiStatsFentryDoFsync, StatsProgObiStatsFexitDoFsync})
	assert.False(t, storage.fsSyncTracing["sys_fdatasync"])
	assert.False(t, storage.fsSyncTracing["do_fsync"])
	assert.True(t, storage.fsSyncTracing["vfs_fsync_range"])
	assert.True(t, storage.disk)
	assert.True(t, storage.fsSync)
	assert.Empty(t, storage.disabled)
}

// When the stats programs can't be loaded for another reason, the storage features are disabled
func TestStorageProbesDisableTheFileSyncsWhenTheirKprobesCantBeLoaded(t *testing.T) {
	storage := storageProbes{fsSync: true}
	var loads [][]string
	err := storage.loadOrDisable(func(toDisable []string) error {
		loads = append(loads, toDisable)
		if len(loads) == 1 {
			return errors.New("program obi_stats_kprobe_vfs_fsync_range: load program: invalid argument")
		}
		return nil
	}, nil)

	require.NoError(t, err)
	require.Len(t, loads, 2)
	assert.False(t, storage.fsSync)
	assert.Subset(t, loads[1], fsSyncProgramNames())
	assert.Equal(t, []DisabledFeature{{
		Feature: featureFsSync,
		Reason:  "can't load their BPF programs: program obi_stats_kprobe_vfs_fsync_range: load program: invalid argument",
	}}, storage.disabled)
}

// A program that the kernel can't load disables its own storage feature only: the other keeps its
// programs
func TestStorageProbesDisableOnlyTheFeatureOfTheProgramThatCantBeLoaded(t *testing.T) {
	for _, tc := range []struct {
		failing, disabled string
		disk, fsSync      bool
	}{
		{failing: StatsProgObiStatsKprobeVfsFsyncRange, disabled: featureFsSync, disk: true},
		{failing: progObiStatsRawTpBlockRqComplete, disabled: featureDisk, fsSync: true},
	} {
		t.Run(tc.failing, func(t *testing.T) {
			storage := storageProbes{disk: true, fsSync: true, fsSyncTracing: allFsSyncHooks()}
			failure := "program " + tc.failing + ": load program: invalid argument"
			var loads [][]string
			err := storage.loadOrDisable(func(toDisable []string) error {
				loads = append(loads, toDisable)
				if len(loads) == 1 {
					return errors.New(failure)
				}
				return nil
			}, nil)

			require.NoError(t, err)
			require.Len(t, loads, 2)
			assert.Equal(t, tc.disk, storage.disk)
			assert.Equal(t, tc.fsSync, storage.fsSync)
			assert.Equal(t, tc.disk, !slices.Contains(loads[1], progObiStatsRawTpBlockRqComplete), "the disk programs")
			assert.Equal(t, tc.fsSync, !slices.Contains(loads[1], StatsProgObiStatsKprobeVfsFsyncRange), "the file sync programs")
			assert.Equal(t, []DisabledFeature{{
				Feature: tc.disabled,
				Reason:  "can't load their BPF programs: " + failure,
			}}, storage.disabled)
		})
	}
}

// Without the disk stats, the plan still reads the kernel BTF to tell which file sync hooks the
// fentry and fexit programs time
func TestStorageProbesOfTheFileSyncsAlone(t *testing.T) {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("no kernel BTF: %v", err)
	}
	features := export.FeatureStatsFsSyncDuration
	storage := planStorageProbes(slog.Default(), &features, false)
	assert.False(t, storage.disk)
	assert.True(t, storage.fsSync)
	assert.Equal(t, fsSyncTracingHooks(kernel), storage.fsSyncTracing)
	assert.Empty(t, storage.disabled)
}
