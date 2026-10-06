// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export"
)

const (
	progObiStatsRawTpRPCTaskBegin     = "obi_stats_raw_tp_rpc_task_begin"
	progObiStatsRawTpRPCStatsLatency  = "obi_stats_raw_tp_rpc_stats_latency"
	progObiStatsRawTpNFSReadpageDone  = "obi_stats_raw_tp_nfs_readpage_done"
	progObiStatsRawTpNFSWritebackDone = "obi_stats_raw_tp_nfs_writeback_done"

	RawTracepointRPCTaskBegin     = "rpc_task_begin"
	RawTracepointRPCStatsLatency  = "rpc_stats_latency"
	RawTracepointNFSReadpageDone  = "nfs_readpage_done"
	RawTracepointNFSWritebackDone = "nfs_writeback_done"
)

// Parameters of the btf_trace_<tracepoint> prototypes of the NFS client tracepoints: the
// tracepoint's private data, followed by the tracepoint arguments.
const (
	rpcStatsLatencyParams = 5 // data, task, backlog, rtt, execute
	nfsPgioDoneParams     = 3 // data, task, hdr
)

// The NFS client tracepoints have had the arguments the probes read since this kernel version.
// Their prototypes are only checked in the BTF when the kernel has it for the sunrpc and nfs
// modules (Linux 5.11+), so older kernels are trusted from this version on.
const (
	nfsTracepointsMajor = 5
	nfsTracepointsMinor = 8
)

// nfsProbes tells which NFS client probes the kernel can load
type nfsProbes struct {
	// rpc_task_begin and rpc_stats_latency, which need the sunrpc types
	rpc error
	// nfs_readpage_done and nfs_writeback_done, which need the sunrpc and nfs types
	pgio error
}

// nfsTypes looks up the types and tracepoint prototypes of the NFS client in the kernel BTF and in
// the BTF of the sunrpc and nfs modules, when they are modules
type nfsTypes interface {
	hasStruct(module, name string) bool
	proto(module, name string) (*btf.FuncProto, error)
}

type kernelNFSTypes struct {
	vmlinux *btf.Spec
	modules map[string]*btf.Spec
}

func newKernelNFSTypes() (*kernelNFSTypes, error) {
	vmlinux, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}
	types := &kernelNFSTypes{vmlinux: vmlinux, modules: map[string]*btf.Spec{}}
	for _, module := range []string{"sunrpc", "nfs"} {
		// built-in or not loaded modules have no BTF of their own
		if spec, err := btf.LoadKernelModuleSpec(module); err == nil {
			types.modules[module] = spec
		}
	}
	return types, nil
}

func (k *kernelNFSTypes) specs(module string) []*btf.Spec {
	if spec, ok := k.modules[module]; ok {
		return []*btf.Spec{k.vmlinux, spec}
	}
	return []*btf.Spec{k.vmlinux}
}

func (k *kernelNFSTypes) hasStruct(module, name string) bool {
	for _, spec := range k.specs(module) {
		var s *btf.Struct
		if err := spec.TypeByName(name, &s); err == nil {
			return true
		}
	}
	return false
}

func (k *kernelNFSTypes) proto(module, name string) (*btf.FuncProto, error) {
	err := btf.ErrNotFound
	for _, spec := range k.specs(module) {
		var proto *btf.FuncProto
		if proto, err = tracepointProto(spec)(name); err == nil {
			return proto, nil
		}
	}
	return nil, err
}

// kernelNFSProbes tells which NFS client probes the running kernel can load
func kernelNFSProbes() nfsProbes {
	types, err := newKernelNFSTypes()
	if err != nil {
		err = fmt.Errorf("reading the kernel BTF: %w", err)
		return nfsProbes{rpc: err, pgio: err}
	}
	major, minor := ebpfcommon.KernelVersion()
	knownLayout := major > nfsTracepointsMajor || (major == nfsTracepointsMajor && minor >= nfsTracepointsMinor)
	return nfsProbesFrom(types, knownLayout)
}

func nfsProbesFrom(types nfsTypes, knownLayout bool) nfsProbes {
	var probes nfsProbes
	if !types.hasStruct("sunrpc", "rpc_task") {
		probes.rpc = errors.New("the kernel BTF doesn't describe the sunrpc types: they need the BTF of " +
			"the sunrpc module (Linux 5.11+), with the module loaded when OBI starts")
	} else {
		probes.rpc = checkTracepoint(types, "sunrpc", RawTracepointRPCStatsLatency, rpcStatsLatencyParams, knownLayout)
	}

	switch {
	case probes.rpc != nil:
		probes.pgio = probes.rpc
	case !types.hasStruct("nfs", "nfs_pgio_header"):
		probes.pgio = errors.New("the kernel BTF doesn't describe the nfs types: they need the BTF of " +
			"the nfs module (Linux 5.11+), with the module loaded when OBI starts")
	default:
		probes.pgio = errors.Join(
			checkTracepoint(types, "nfs", RawTracepointNFSReadpageDone, nfsPgioDoneParams, knownLayout),
			checkTracepoint(types, "nfs", RawTracepointNFSWritebackDone, nfsPgioDoneParams, knownLayout))
	}
	return probes
}

// checkTracepoint checks the number of arguments of a tracepoint, when its prototype is in the
// BTF. Otherwise, it trusts kernels that are known to have the expected arguments.
func checkTracepoint(types nfsTypes, module, tracepoint string, params int, knownLayout bool) error {
	proto, err := types.proto(module, "btf_trace_"+tracepoint)
	switch {
	case err == nil && len(proto.Params) != params:
		return fmt.Errorf("unexpected %s prototype with %d parameters", tracepoint, len(proto.Params))
	case err == nil, knownLayout:
		return nil
	default:
		return fmt.Errorf("can't tell the arguments of %s on kernels older than %d.%d",
			tracepoint, nfsTracepointsMajor, nfsTracepointsMinor)
	}
}

// nfsLoad tells which NFS client programs to load, for the enabled features
type nfsLoad struct {
	taskBegin, statsLatency, pgio bool
}

func nfsLoadFor(features *export.Features, probes nfsProbes) nfsLoad {
	procedures := features.StatsNFSClientProcedureDuration() && probes.rpc == nil
	bytes := features.StatsNFSClientIO() && probes.pgio == nil
	return nfsLoad{
		// charges both the RPCs and their bytes to the thread that started them
		taskBegin:    procedures || bytes,
		statsLatency: procedures,
		pgio:         bytes,
	}
}

func (l nfsLoad) programsToDisable() []string {
	var toDisable []string
	if !l.taskBegin {
		toDisable = append(toDisable, progObiStatsRawTpRPCTaskBegin)
	}
	if !l.statsLatency {
		toDisable = append(toDisable, progObiStatsRawTpRPCStatsLatency)
	}
	if !l.pgio {
		toDisable = append(toDisable, progObiStatsRawTpNFSReadpageDone, progObiStatsRawTpNFSWritebackDone)
	}
	return toDisable
}

// nfsAttached tells which NFS client metrics have their probes attached
type nfsAttached struct {
	procedures, bytes bool
}

// attachNFS attaches the loaded NFS client programs. They are optional: a tracepoint that can't be
// attached, e.g. because its module was unloaded since the check, disables its metric only.
func attachNFS(log *slog.Logger, objects *StatsObjects, load nfsLoad) (nfsAttached, []io.Closer) {
	var closables []io.Closer
	attach := func(tracepoint string, program *ebpf.Program) bool {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: tracepoint, Program: program})
		if err != nil {
			log.Warn("can't attach an NFS client tracepoint", "tracepoint", tracepoint, "error", err)
			return false
		}
		closables = append(closables, l)
		return true
	}

	var attached nfsAttached
	if load.taskBegin && !attach(RawTracepointRPCTaskBegin, objects.ObiStatsRawTpRpcTaskBegin) {
		log.Warn("NFS client stats are not charged to workloads")
	}
	if load.statsLatency {
		attached.procedures = attach(RawTracepointRPCStatsLatency, objects.ObiStatsRawTpRpcStatsLatency)
	}
	if load.pgio {
		reads := attach(RawTracepointNFSReadpageDone, objects.ObiStatsRawTpNfsReadpageDone)
		writes := attach(RawTracepointNFSWritebackDone, objects.ObiStatsRawTpNfsWritebackDone)
		attached.bytes = reads || writes
	}
	return attached, closables
}

// NFSProcedureAccumMap returns the map where the kernel accumulates NFS client RPC latencies, or
// nil if their probes are not attached.
func (m *StatsFetcher) NFSProcedureAccumMap() *ebpf.Map {
	if !m.nfs.procedures {
		return nil
	}
	return m.objects.NfsProcedureAccum
}

// NFSIOAccumMap returns the map where the kernel accumulates the bytes that the NFS client read and
// wrote, or nil if their probes are not attached.
func (m *StatsFetcher) NFSIOAccumMap() *ebpf.Map {
	if !m.nfs.bytes {
		return nil
	}
	return m.objects.NfsIoAccum
}
