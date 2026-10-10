// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export"
)

const (
	progObiStatsRawTpRPCStatsLatency  = "obi_stats_raw_tp_rpc_stats_latency"
	progObiStatsRawTpNFSReadpageDone  = "obi_stats_raw_tp_nfs_readpage_done"
	progObiStatsRawTpNFSWritebackDone = "obi_stats_raw_tp_nfs_writeback_done"

	RawTracepointRPCStatsLatency  = "rpc_stats_latency"
	RawTracepointNFSReadpageDone  = "nfs_readpage_done"
	RawTracepointNFSWritebackDone = "nfs_writeback_done"
)

// The NFS client stats features, as DisabledFeature names them
const (
	featureNFSProcedures = "the NFS client procedure metrics (the nfs_client_procedure_* stats features)"
	featureNFSIO         = "the NFS client I/O metric (the nfs_client_io stats feature)"
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
	// rpc_stats_latency, which needs the sunrpc types
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
	statsLatency, pgio bool
}

func nfsLoadFor(features *export.Features, probes nfsProbes) nfsLoad {
	procedures := features.StatsNFSClientProcedures() && probes.rpc == nil
	bytes := features.StatsNFSClientIO() && probes.pgio == nil
	return nfsLoad{
		statsLatency: procedures,
		pgio:         bytes,
	}
}

func (l nfsLoad) programsToDisable() []string {
	var toDisable []string
	if !l.statsLatency {
		toDisable = append(toDisable, progObiStatsRawTpRPCStatsLatency)
	}
	if !l.pgio {
		toDisable = append(toDisable, progObiStatsRawTpNFSReadpageDone, progObiStatsRawTpNFSWritebackDone)
	}
	return toDisable
}

// nfsState tells which NFS client programs are loaded, which of them are attached, and which are
// pending: their tracepoints don't exist yet, and they are attached when they do
type nfsState struct {
	loaded, attached, pending nfsLoad
}

// attachNFS attaches the pending NFS client programs. They are optional: a tracepoint that can't be
// attached disables its metric only, unless it doesn't exist yet: the program waits for it.
func attachNFS(log *slog.Logger, objects *StatsObjects, state *nfsState) []io.Closer {
	var closables []io.Closer
	// attach tells whether the tracepoint is attached, and whether it is only missing
	attach := func(tracepoint string, program *ebpf.Program) (attached, missing bool) {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: tracepoint, Program: program})
		switch {
		case err == nil:
			closables = append(closables, l)
			return true, false
		case errors.Is(err, os.ErrNotExist):
			log.Debug("an NFS client tracepoint doesn't exist yet", "tracepoint", tracepoint)
			return false, true
		default:
			log.Warn("can't attach an NFS client tracepoint", "tracepoint", tracepoint, "error", err)
			return false, false
		}
	}

	if state.pending.statsLatency {
		state.attached.statsLatency, state.pending.statsLatency = attach(RawTracepointRPCStatsLatency, objects.ObiStatsRawTpRpcStatsLatency)
	}
	if state.pending.pgio {
		reads, readsMissing := attach(RawTracepointNFSReadpageDone, objects.ObiStatsRawTpNfsReadpageDone)
		writes, writesMissing := attach(RawTracepointNFSWritebackDone, objects.ObiStatsRawTpNfsWritebackDone)
		state.attached.pgio = reads || writes
		state.pending.pgio = !state.attached.pgio && (readsMissing || writesMissing)
	}
	return closables
}

// moduleBTFLoaded tells whether the BTF of the module of a pending program exists, as it does while
// the module is loaded: the prototype of the tracepoint can be checked then
func (s nfsState) moduleBTFLoaded() bool {
	modules, err := btf.NewCache().Modules()
	if err != nil {
		return false
	}
	return (s.pending.statsLatency && slices.Contains(modules, "sunrpc")) ||
		(s.pending.pgio && slices.Contains(modules, "nfs"))
}

// stopUnsupported stops waiting for the pending programs that the kernel BTF, with the BTF of the
// modules that are loaded now, says can't run
func (s *nfsState) stopUnsupported(log *slog.Logger, probes nfsProbes) {
	if probes.rpc != nil && s.pending.statsLatency {
		log.Warn("NFS client probes disabled", "metrics", featureNFSProcedures, "error", probes.rpc)
		s.pending.statsLatency = false
	}
	if probes.pgio != nil && s.pending.pgio {
		log.Warn("NFS client probes disabled", "metrics", featureNFSIO, "error", probes.pgio)
		s.pending.pgio = false
	}
}

// disabled returns the NFS client metrics whose loaded programs are not attached
func (s nfsState) disabled() []DisabledFeature {
	var disabled []DisabledFeature
	if s.loaded.statsLatency && !s.attached.statsLatency {
		disabled = append(disabled, notAttached(featureNFSProcedures, s.pending.statsLatency, "sunrpc",
			"can't attach the rpc_stats_latency tracepoint"))
	}
	if s.loaded.pgio && !s.attached.pgio {
		disabled = append(disabled, notAttached(featureNFSIO, s.pending.pgio, "nfs",
			"can't attach the nfs_readpage_done and nfs_writeback_done tracepoints"))
	}
	return disabled
}

func notAttached(feature string, waiting bool, module, reason string) DisabledFeature {
	if waiting {
		reason = fmt.Sprintf("waiting for the tracepoints of the %s kernel module: the probes are attached when they exist", module)
	}
	return DisabledFeature{Feature: feature, Reason: reason}
}

// RefreshNFSProbes attaches the NFS client probes that wait for the tracepoints of the sunrpc and
// nfs modules, if they exist now
func (m *StatsFetcher) RefreshNFSProbes() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.nfs.pending == (nfsLoad{}) {
		return
	}

	if m.nfs.moduleBTFLoaded() {
		m.nfs.stopUnsupported(m.log, kernelNFSProbes())
	}
	attached := m.nfs.attached
	m.closables = append(m.closables, attachNFS(m.log, m.objects, &m.nfs)...)
	if !attached.statsLatency && m.nfs.attached.statsLatency {
		m.log.Info("NFS client probes attached", "metrics", featureNFSProcedures)
	}
	if !attached.pgio && m.nfs.attached.pgio {
		m.log.Info("NFS client probes attached", "metrics", featureNFSIO)
	}
}

// NFSProcedureAccumMap returns the map where the kernel accumulates NFS client RPC latencies, or
// nil if their programs are not loaded. Their probes may be attached later.
func (m *StatsFetcher) NFSProcedureAccumMap() *ebpf.Map {
	if !m.nfs.loaded.statsLatency {
		return nil
	}
	return m.objects.NfsProcedureAccum
}

// NFSIOAccumMap returns the map where the kernel accumulates the bytes that the NFS client read and
// wrote, or nil if their programs are not loaded. Their probes may be attached later.
func (m *StatsFetcher) NFSIOAccumMap() *ebpf.Map {
	if !m.nfs.loaded.pgio {
		return nil
	}
	return m.objects.NfsIoAccum
}
