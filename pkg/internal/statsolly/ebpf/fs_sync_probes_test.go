// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
)

// kernelBTF builds the BTF of a kernel with the given functions, and with the struct of the
// kernels whose trampolines are safe for the functions that sleep when safe is set
func kernelBTF(t *testing.T, safe bool, functions ...string) *btf.Spec {
	t.Helper()
	var types []btf.Type
	if safe {
		types = append(types, &btf.Struct{Name: safeTrampolineStruct})
	}
	for _, function := range functions {
		types = append(types, &btf.Func{Name: function, Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4}}})
	}
	return btfSpecOf(t, types...)
}

// btfSpecOf builds a BTF spec of the given types
func btfSpecOf(t *testing.T, types ...btf.Type) *btf.Spec {
	t.Helper()
	builder, err := btf.NewBuilder(types, nil)
	require.NoError(t, err)
	raw, err := builder.Marshal(nil, nil)
	require.NoError(t, err)
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	require.NoError(t, err)
	return spec
}

func TestFsSyncTracingHooks(t *testing.T) {
	var functions []string
	allHooks := map[string]bool{}
	for _, hook := range fsSyncHooks {
		functions = append(functions, hook.kernelFunction())
		allHooks[hook.function] = true
	}
	assert.Equal(t, allHooks, fsSyncTracingHooks(kernelBTF(t, true, functions...)))
	assert.Empty(t, fsSyncTracingHooks(kernelBTF(t, false, functions...)),
		"the trampolines of the kernels without bpf_tramp_image (e.g. 5.8) are unsafe for the functions that sleep")

	// a function that the kernel inlined, or whose system call wrapper isn't in its BTF, falls back
	// to its kprobes alone
	for _, missing := range []string{"do_fsync", "vfs_fsync_range", kprobe.SyscallPrefix() + "sys_fdatasync"} {
		tracing := fsSyncTracingHooks(kernelBTF(t, true, slices.DeleteFunc(slices.Clone(functions), func(function string) bool {
			return function == missing
		})...))
		assert.Len(t, tracing, len(fsSyncHooks)-1, missing)
		for _, hook := range fsSyncHooks {
			assert.Equal(t, hook.kernelFunction() != missing, tracing[hook.function], hook.function)
		}
	}
}

func TestFsSyncProgramsToDisable(t *testing.T) {
	var tracing, kprobes []string
	for _, hook := range fsSyncHooks {
		tracing = append(tracing, hook.fentry, hook.fexit)
		kprobes = append(kprobes, hook.kprobe, hook.kretprobe)
	}
	assert.ElementsMatch(t, slices.Concat(tracing, slices.Compact(slices.Sorted(slices.Values(kprobes)))),
		fsSyncProgramsToDisable(false, nil), "every program when disabled, each once")
	assert.ElementsMatch(t, tracing, fsSyncProgramsToDisable(true, nil), "the kprobes time every hook")
	assert.ElementsMatch(t, []string{StatsProgObiStatsFentryDoFsync, StatsProgObiStatsFexitDoFsync},
		fsSyncProgramsToDisable(true, map[string]bool{
			"vfs_fsync_range": true, "vfs_fsync": true, "ksys_sync": true,
			"sys_fsync": true, "sys_fdatasync": true, "sys_syncfs": true, "sys_sync_file_range": true,
		}))
}

// The programs of the hooks are those of the spec, and every tracing program is one
func TestFsSyncPrograms(t *testing.T) {
	spec, err := LoadStats()
	require.NoError(t, err)
	programs := fsSyncPrograms(&StatsObjects{})
	for name := range programs {
		assert.Contains(t, spec.Programs, name)
	}
	for _, hook := range fsSyncHooks {
		for _, name := range []string{hook.kprobe, hook.kretprobe, hook.fentry, hook.fexit} {
			assert.Contains(t, programs, name)
		}
	}
	for name, program := range spec.Programs {
		if program.Type == ebpf.Tracing {
			assert.Contains(t, programs, name)
		}
	}
}

// The verifier tests load the fentry and fexit programs of every function that the kernel has, at
// the kernel function of each system call, even where OBI attaches the kprobes, and stub the others
func TestPrepareStatsSpec(t *testing.T) {
	spec, err := LoadStats()
	require.NoError(t, err)
	assert.Equal(t, "sys_fsync", spec.Programs[StatsProgObiStatsFentrySysFsync].AttachTo)

	kernel := kernelBTF(t, false, "vfs_fsync_range", "ksys_sync", kprobe.SyscallPrefix()+"sys_fsync")
	require.NoError(t, PrepareStatsSpec(spec, kernel))
	assert.Equal(t, ebpf.Tracing, spec.Programs[StatsProgObiStatsFexitVfsFsyncRange].Type)
	assert.Equal(t, "vfs_fsync_range", spec.Programs[StatsProgObiStatsFexitVfsFsyncRange].AttachTo)
	assert.Equal(t, kprobe.SyscallPrefix()+"sys_fsync", spec.Programs[StatsProgObiStatsFentrySysFsync].AttachTo)
	assert.Equal(t, kprobe.SyscallPrefix()+"sys_fsync", spec.Programs[StatsProgObiStatsFexitSysFsync].AttachTo)
	// sync(2) is timed at ksys_sync, as its system call wrapper isn't in the BTF of most kernels
	assert.Equal(t, "ksys_sync", spec.Programs[StatsProgObiStatsFexitKsysSync].AttachTo)
	for _, stub := range []string{StatsProgObiStatsFentryDoFsync, StatsProgObiStatsFexitDoFsync, StatsProgObiStatsFexitVfsFsync} {
		assert.Equal(t, "stats_dummy", spec.Programs[stub].Name, stub)
		assert.Equal(t, ebpf.Kprobe, spec.Programs[stub].Type, "a tracing stub has no function to attach to")
	}
	assert.Equal(t, "obi_stats_kprobe_do_fsync", spec.Programs[StatsProgObiStatsKprobeDoFsync].Name, "the kprobes are kept")
}
