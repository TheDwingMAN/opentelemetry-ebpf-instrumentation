// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"fmt"
	"io"
	"log/slog"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
)

// fsSyncHook is a kernel function whose calls the file sync probes time: with its kprobe pair, or
// with its fentry and fexit pair where the kernel can
type fsSyncHook struct {
	// a system call is named without the architecture prefix of its kernel function: sys_fsync
	function string
	syscall  bool

	kprobe, kretprobe, fentry, fexit string
}

func (h fsSyncHook) kernelFunction() string {
	if h.syscall {
		return kprobe.SyscallPrefix() + h.function
	}
	return h.function
}

// fsSyncRequiredHook is the only hook of the O_SYNC and O_DSYNC writes and of msync(2) on every
// kernel. The other hooks are skipped where the kernel inlined their function.
const fsSyncRequiredHook = "vfs_fsync_range"

var fsSyncHooks = []fsSyncHook{
	{
		function: fsSyncRequiredHook,
		kprobe:   StatsProgObiStatsKprobeVfsFsyncRange, kretprobe: StatsProgObiStatsKretprobeVfsFsyncRange,
		fentry: StatsProgObiStatsFentryVfsFsyncRange, fexit: StatsProgObiStatsFexitVfsFsyncRange,
	},
	{
		function: "vfs_fsync",
		kprobe:   StatsProgObiStatsKprobeVfsFsync, kretprobe: StatsProgObiStatsKretprobeVfsFsync,
		fentry: StatsProgObiStatsFentryVfsFsync, fexit: StatsProgObiStatsFexitVfsFsync,
	},
	{
		function: "do_fsync",
		kprobe:   StatsProgObiStatsKprobeDoFsync, kretprobe: StatsProgObiStatsKretprobeDoFsync,
		fentry: StatsProgObiStatsFentryDoFsync, fexit: StatsProgObiStatsFexitDoFsync,
	},
	{
		function: "ksys_sync",
		kprobe:   StatsProgObiStatsKprobeKsysSync, kretprobe: StatsProgObiStatsKretprobeKsysSync,
		fentry: StatsProgObiStatsFentryKsysSync, fexit: StatsProgObiStatsFexitKsysSync,
	},
	{
		function: "sys_fsync", syscall: true,
		kprobe: StatsProgObiStatsKprobeSysFsync, kretprobe: StatsProgObiStatsKretprobeSyncSyscall,
		fentry: StatsProgObiStatsFentrySysFsync, fexit: StatsProgObiStatsFexitSysFsync,
	},
	{
		function: "sys_fdatasync", syscall: true,
		kprobe: StatsProgObiStatsKprobeSysFdatasync, kretprobe: StatsProgObiStatsKretprobeSyncSyscall,
		fentry: StatsProgObiStatsFentrySysFdatasync, fexit: StatsProgObiStatsFexitSysFdatasync,
	},
	{
		function: "sys_syncfs", syscall: true,
		kprobe: StatsProgObiStatsKprobeSysSyncfs, kretprobe: StatsProgObiStatsKretprobeSyncSyscall,
		fentry: StatsProgObiStatsFentrySysSyncfs, fexit: StatsProgObiStatsFexitSysSyncfs,
	},
	{
		function: "sys_sync_file_range", syscall: true,
		kprobe: StatsProgObiStatsKprobeSysSyncFileRange, kretprobe: StatsProgObiStatsKretprobeSyncSyscall,
		fentry: StatsProgObiStatsFentrySysSyncFileRange, fexit: StatsProgObiStatsFexitSysSyncFileRange,
	},
}

func fsSyncPrograms(objects *StatsObjects) map[string]*ebpf.Program {
	return map[string]*ebpf.Program{
		StatsProgObiStatsKprobeVfsFsyncRange:    objects.ObiStatsKprobeVfsFsyncRange,
		StatsProgObiStatsKretprobeVfsFsyncRange: objects.ObiStatsKretprobeVfsFsyncRange,
		StatsProgObiStatsFentryVfsFsyncRange:    objects.ObiStatsFentryVfsFsyncRange,
		StatsProgObiStatsFexitVfsFsyncRange:     objects.ObiStatsFexitVfsFsyncRange,
		StatsProgObiStatsKprobeVfsFsync:         objects.ObiStatsKprobeVfsFsync,
		StatsProgObiStatsKretprobeVfsFsync:      objects.ObiStatsKretprobeVfsFsync,
		StatsProgObiStatsFentryVfsFsync:         objects.ObiStatsFentryVfsFsync,
		StatsProgObiStatsFexitVfsFsync:          objects.ObiStatsFexitVfsFsync,
		StatsProgObiStatsKprobeDoFsync:          objects.ObiStatsKprobeDoFsync,
		StatsProgObiStatsKretprobeDoFsync:       objects.ObiStatsKretprobeDoFsync,
		StatsProgObiStatsFentryDoFsync:          objects.ObiStatsFentryDoFsync,
		StatsProgObiStatsFexitDoFsync:           objects.ObiStatsFexitDoFsync,
		StatsProgObiStatsKprobeKsysSync:         objects.ObiStatsKprobeKsysSync,
		StatsProgObiStatsKretprobeKsysSync:      objects.ObiStatsKretprobeKsysSync,
		StatsProgObiStatsFentryKsysSync:         objects.ObiStatsFentryKsysSync,
		StatsProgObiStatsFexitKsysSync:          objects.ObiStatsFexitKsysSync,
		StatsProgObiStatsKretprobeSyncSyscall:   objects.ObiStatsKretprobeSyncSyscall,
		StatsProgObiStatsKprobeSysFsync:         objects.ObiStatsKprobeSysFsync,
		StatsProgObiStatsFentrySysFsync:         objects.ObiStatsFentrySysFsync,
		StatsProgObiStatsFexitSysFsync:          objects.ObiStatsFexitSysFsync,
		StatsProgObiStatsKprobeSysFdatasync:     objects.ObiStatsKprobeSysFdatasync,
		StatsProgObiStatsFentrySysFdatasync:     objects.ObiStatsFentrySysFdatasync,
		StatsProgObiStatsFexitSysFdatasync:      objects.ObiStatsFexitSysFdatasync,
		StatsProgObiStatsKprobeSysSyncfs:        objects.ObiStatsKprobeSysSyncfs,
		StatsProgObiStatsFentrySysSyncfs:        objects.ObiStatsFentrySysSyncfs,
		StatsProgObiStatsFexitSysSyncfs:         objects.ObiStatsFexitSysSyncfs,
		StatsProgObiStatsKprobeSysSyncFileRange: objects.ObiStatsKprobeSysSyncFileRange,
		StatsProgObiStatsFentrySysSyncFileRange: objects.ObiStatsFentrySysSyncFileRange,
		StatsProgObiStatsFexitSysSyncFileRange:  objects.ObiStatsFexitSysSyncFileRange,
	}
}

// fsSyncProgramsToDisable returns the file sync programs that must not be loaded: all of them when
// the file sync stats are disabled, and otherwise the fentry and fexit programs of the hooks that
// are not in tracing
func fsSyncProgramsToDisable(enabled bool, tracing map[string]bool) []string {
	var names []string
	for _, hook := range fsSyncHooks {
		if !enabled {
			names = append(names, hook.kprobe)
			// the system calls share their kretprobe
			if !slices.Contains(names, hook.kretprobe) {
				names = append(names, hook.kretprobe)
			}
		}
		if !enabled || !tracing[hook.function] {
			names = append(names, hook.fentry, hook.fexit)
		}
	}
	return names
}

// safeTrampolineStruct is in the BTF of the kernels whose BPF trampolines are safe for the
// functions that sleep, as file syncs do: before Linux 5.12 and 5.10.28, detaching an fexit program
// freed its trampoline while the tasks that slept in the function were still to return through it
// (commit e21aa341785c, "bpf: Fix fexit trampoline", added the struct)
const safeTrampolineStruct = "bpf_tramp_image"

func hasFunc(kernel *btf.Spec, name string) bool {
	var function *btf.Func
	return kernel.TypeByName(name, &function) == nil
}

func hasStruct(kernel *btf.Spec, name string) bool {
	var structure *btf.Struct
	return kernel.TypeByName(name, &structure) == nil
}

// fsSyncTracingHooks returns the hooks, by function, that fentry and fexit programs time on the
// kernel of a BTF: none where its trampolines are unsafe, else those whose function it has
func fsSyncTracingHooks(kernel *btf.Spec) map[string]bool {
	tracing := map[string]bool{}
	if !hasStruct(kernel, safeTrampolineStruct) {
		return tracing
	}
	for _, hook := range fsSyncHooks {
		if hasFunc(kernel, hook.kernelFunction()) {
			tracing[hook.function] = true
		}
	}
	return tracing
}

// setFsSyncTracingTargets names, in the fentry and fexit programs of the system calls, their kernel
// functions, which have the architecture prefix that the section names of the programs don't
func setFsSyncTracingTargets(spec *ebpf.CollectionSpec) {
	for _, hook := range fsSyncHooks {
		spec.Programs[hook.fentry].AttachTo = hook.kernelFunction()
		spec.Programs[hook.fexit].AttachTo = hook.kernelFunction()
	}
}

// PrepareStatsSpec makes the stats programs loadable on the kernel of a BTF, with the fentry and
// fexit programs of every function that the kernel has, whether or not OBI would attach them there
func PrepareStatsSpec(spec *ebpf.CollectionSpec, kernel *btf.Spec) error {
	setFsSyncTracingTargets(spec)
	tracing := map[string]bool{}
	for _, hook := range fsSyncHooks {
		tracing[hook.function] = hasFunc(kernel, hook.kernelFunction())
	}
	return fixupSpec(spec, fsSyncProgramsToDisable(true, tracing))
}

// The probe mechanism of a file sync hook, as the startup log reports it
const (
	fsSyncMechanismTracing = "fexit"
	fsSyncMechanismKprobes = "kprobe"
	fsSyncMechanismNone    = "none"
)

// attachFsSync attaches the probes of the file sync hooks: the fentry and fexit programs of the
// hooks in tracing, or else, or when those can't be attached, the kprobes. A hook whose probes
// can't be attached is skipped, but the required one, which is a storageError. It returns the probe
// mechanism of each hook, by function.
func attachFsSync(log *slog.Logger, objects *StatsObjects, tracing map[string]bool) ([]io.Closer, map[string]string, error) {
	programs := fsSyncPrograms(objects)
	var closables []io.Closer
	mechanisms := map[string]string{}
	for _, hook := range fsSyncHooks {
		links, mechanism, err := attachFsSyncHook(log, hook, programs, tracing[hook.function])
		if err != nil && hook.function == fsSyncRequiredHook {
			closeAll(closables)
			return nil, nil, &storageError{
				features: export.FeatureStatsFsSync,
				err:      fmt.Errorf("can't attach the %s probes: %w", hook.function, err),
			}
		}
		if err != nil {
			log.Debug("skipping a file sync function whose probes can't be attached", "function", hook.function, "error", err)
		}
		closables = append(closables, links...)
		mechanisms[hook.function] = mechanism
	}
	return closables, mechanisms, nil
}

func logFsSyncMechanisms(log *slog.Logger, mechanisms map[string]string) {
	attrs := make([]any, 0, 2*len(fsSyncHooks))
	var onKprobes []string
	for _, hook := range fsSyncHooks {
		attrs = append(attrs, hook.function, mechanisms[hook.function])
		if mechanisms[hook.function] == fsSyncMechanismKprobes {
			onKprobes = append(onKprobes, hook.function)
		}
	}
	log.Info("file sync probes attached", attrs...)
	if len(onKprobes) > 0 {
		log.Warn("some file syncs are probed with kprobes on this kernel: during a storage stall, the syncs "+
			"beyond the kernel's limit of concurrent kretprobes are not counted, nor, for up to 2 minutes, the "+
			"other syncs of their threads", "functions", onKprobes)
	}
}

func attachFsSyncHook(log *slog.Logger, hook fsSyncHook, programs map[string]*ebpf.Program, tracing bool,
) ([]io.Closer, string, error) {
	if tracing {
		links, err := attachTracingPair(programs[hook.fexit], programs[hook.fentry])
		if err == nil {
			return links, fsSyncMechanismTracing, nil
		}
		// e.g. EBUSY on a livepatched function before Linux 6.0, or ENOTSUPP on arm64 before 6.0
		log.Debug("can't attach the fentry and fexit programs of a file sync function: attaching its kprobes",
			"function", hook.function, "error", err)
	}
	links, err := attachKprobePair(hook.function, programs[hook.kretprobe], programs[hook.kprobe])
	if err != nil {
		return nil, fsSyncMechanismNone, err
	}
	return links, fsSyncMechanismKprobes, nil
}

// attachTracingPair attaches the fexit program of a function, then its fentry program, or neither:
// a sync started without its return probe would never complete
func attachTracingPair(exit, entry *ebpf.Program) ([]io.Closer, error) {
	exitLink, err := link.AttachTracing(link.TracingOptions{Program: exit, AttachType: ebpf.AttachTraceFExit})
	if err != nil {
		return nil, err
	}
	entryLink, err := link.AttachTracing(link.TracingOptions{Program: entry, AttachType: ebpf.AttachTraceFEntry})
	if err != nil {
		exitLink.Close()
		return nil, err
	}
	return []io.Closer{exitLink, entryLink}, nil
}

// attachKprobePair attaches the kretprobe of a function, then its kprobe, or neither
func attachKprobePair(function string, ret, entry *ebpf.Program) ([]io.Closer, error) {
	retLink, err := kprobe.Attach(function, ret, true)
	if err != nil {
		return nil, err
	}
	entryLink, err := kprobe.Attach(function, entry, false)
	if err != nil {
		retLink.Close()
		return nil, err
	}
	return []io.Closer{retLink, entryLink}, nil
}
