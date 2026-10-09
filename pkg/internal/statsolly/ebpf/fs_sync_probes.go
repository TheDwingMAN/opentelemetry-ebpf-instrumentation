// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
)

// featureFsSync names the file sync stats features in a DisabledFeature
const featureFsSync = "the file sync metrics (the fs_sync_* stats features)"

// fsSyncHook is a kernel function whose calls the file sync probes time, with its programs: a
// kprobe and a kretprobe, and an fentry and an fexit program, which are attached instead where the
// kernel can
type fsSyncHook struct {
	// function is the kernel function. A system call is named without the architecture prefix of
	// its kernel function, e.g. sys_fsync for __x64_sys_fsync.
	function string
	syscall  bool

	kprobe, kretprobe, fentry, fexit string
}

// kernelFunction is the name of the kernel function of the hook in the kernel BTF
func (h fsSyncHook) kernelFunction() string {
	if h.syscall {
		return kprobe.SyscallPrefix() + h.function
	}
	return h.function
}

// fsSyncRequiredHook is the hook that the file sync stats need: the only one of the O_SYNC and
// O_DSYNC writes and of msync(2) on every kernel. The others are skipped when the kernel inlined
// their function.
const fsSyncRequiredHook = "vfs_fsync_range"

// fsSyncHooks are the kernel functions whose calls are file syncs: the sync system calls, and the
// kernel functions that sync files, which some system calls don't call on some kernels
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

// fsSyncPrograms returns the loaded programs of the file sync hooks, by name
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

// fsSyncProgramNames returns the names of every program of the file sync hooks
func fsSyncProgramNames() []string {
	var names []string
	for _, hook := range fsSyncHooks {
		for _, name := range []string{hook.kprobe, hook.kretprobe, hook.fentry, hook.fexit} {
			// the system calls share their kretprobe
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
}

// fsSyncTracingProgramsToDisable returns the names of the fentry and fexit programs that must not be
// loaded: those of the hooks that are not in tracing
func fsSyncTracingProgramsToDisable(tracing map[string]bool) []string {
	var names []string
	for _, hook := range fsSyncHooks {
		if !tracing[hook.function] {
			names = append(names, hook.fentry, hook.fexit)
		}
	}
	return names
}

// safeTrampolineStruct is in the kernel BTF of the kernels whose BPF trampolines are safe for the
// functions that sleep, as file syncs do. Before it (Linux 5.12, and 5.10.28), detaching an fexit
// program freed its trampoline while the tasks that slept in the traced function were still to
// return through it (commit e21aa341785c, "bpf: Fix fexit trampoline", added the struct).
const safeTrampolineStruct = "bpf_tramp_image"

// hasStruct tells whether a BTF has a struct
func hasStruct(spec *btf.Spec, name string) bool {
	var typ *btf.Struct
	return spec.TypeByName(name, &typ) == nil
}

// hasFunc tells whether a BTF has a function
func hasFunc(spec *btf.Spec, name string) bool {
	var typ *btf.Func
	return spec.TypeByName(name, &typ) == nil
}

// fsSyncTracingHooks returns the hooks whose syncs are timed with fentry and fexit programs, by
// function: none where the BPF trampolines of the kernel are unsafe for the functions that sleep,
// else the hooks whose kernel function is in the kernel BTF. The kprobes time the others.
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

// kernelFsSyncTracingHooks returns the hooks whose syncs are timed with fentry and fexit programs on
// this kernel
func kernelFsSyncTracingHooks(log *slog.Logger) map[string]bool {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		log.Debug("can't read the kernel BTF: the file syncs are probed with kprobes", "error", err)
		return map[string]bool{}
	}
	return fsSyncTracingHooks(spec)
}

// setFsSyncTracingTargets names the kernel functions of the system calls in the fentry and fexit
// programs that time them, e.g. __x64_sys_fsync: the programs name them without the prefix of the
// architecture
func setFsSyncTracingTargets(spec *ebpf.CollectionSpec) {
	for _, hook := range fsSyncHooks {
		for _, name := range []string{hook.fentry, hook.fexit} {
			if program, ok := spec.Programs[name]; ok {
				program.AttachTo = hook.kernelFunction()
			}
		}
	}
}

// PrepareStatsSpec makes the stats programs loadable on the kernel of the given BTF, as OBI loads
// them, but with the fentry and fexit programs of every function that the kernel has, even where
// OBI doesn't attach them: it names the kernel functions of the system calls in their programs,
// and replaces the programs of the functions that the kernel doesn't have with no-op stubs.
func PrepareStatsSpec(spec *ebpf.CollectionSpec, kernel *btf.Spec) error {
	setFsSyncTracingTargets(spec)
	tracing := map[string]bool{}
	for _, hook := range fsSyncHooks {
		tracing[hook.function] = hasFunc(kernel, hook.kernelFunction())
	}
	return fixupSpec(spec, fsSyncTracingProgramsToDisable(tracing))
}

// fsSyncTracingHookOf returns the hook, among those of tracing, of the fentry or fexit program that
// a load error names
func fsSyncTracingHookOf(err error, tracing map[string]bool) (string, bool) {
	for _, hook := range fsSyncHooks {
		if !tracing[hook.function] {
			continue
		}
		if loadErrorNamesAny(err, []string{hook.fentry, hook.fexit}) {
			return hook.function, true
		}
	}
	return "", false
}

// loadErrorNamesAny tells whether a load error names one of the given programs, as cilium/ebpf
// names the program that it can't load
func loadErrorNamesAny(err error, programs []string) bool {
	return slices.ContainsFunc(programs, func(name string) bool {
		return strings.Contains(err.Error(), "program "+name+":")
	})
}

// The probe mechanism of a file sync hook, as the startup log reports it
const (
	fsSyncMechanismTracing = "fexit"
	fsSyncMechanismKprobes = "kprobe"
	fsSyncMechanismNone    = "none"
)

// attachFsSync attaches the probes of the file sync hooks: the fentry and fexit programs of the
// hooks in tracing, or the kprobes of a hook whose tracing programs are not loaded or can't be
// attached. A hook whose function the kernel doesn't have is skipped, but the required one. It
// returns the probe mechanism of each hook, by function.
func attachFsSync(log *slog.Logger, objects *StatsObjects, tracing map[string]bool) ([]io.Closer, map[string]string, error) {
	programs := fsSyncPrograms(objects)
	var closables []io.Closer
	mechanisms := map[string]string{}
	for _, hook := range fsSyncHooks {
		links, mechanism, err := attachFsSyncHook(log, hook, programs, tracing[hook.function])
		if err != nil {
			if hook.function == fsSyncRequiredHook {
				closeAll(closables)
				return nil, nil, fmt.Errorf("can't attach the %s probes: %w", hook.function, err)
			}
			log.Debug("skipping a file sync function whose probes can't be attached", "function", hook.function, "error", err)
		}
		closables = append(closables, links...)
		mechanisms[hook.function] = mechanism
	}
	return closables, mechanisms, nil
}

// logFsSyncMechanisms logs the probe mechanism of each file sync hook, and warns about the hooks
// that are probed with kprobes
func logFsSyncMechanisms(log *slog.Logger, mechanisms map[string]string) {
	attrs := make([]any, 0, 2*len(fsSyncHooks))
	var onKprobes []string
	for _, hook := range fsSyncHooks {
		mechanism := mechanisms[hook.function]
		attrs = append(attrs, hook.function, mechanism)
		if mechanism == fsSyncMechanismKprobes {
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

// attachFsSyncHook attaches the fentry and fexit programs of a hook when tracing tells to, or else,
// or when they can't be attached, its kprobes. It returns the mechanism of the probes it attached.
func attachFsSyncHook(log *slog.Logger, hook fsSyncHook, programs map[string]*ebpf.Program, tracing bool,
) ([]io.Closer, string, error) {
	if tracing {
		links, err := attachTracingPair(programs[hook.fexit], programs[hook.fentry])
		if err == nil {
			return links, fsSyncMechanismTracing, nil
		}
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
// a sync started without its return probe would never be completed
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

// attachKprobePair attaches the kretprobe of a function, then its kprobe, or neither. A system call
// is retried with the prefix of its kernel function.
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
