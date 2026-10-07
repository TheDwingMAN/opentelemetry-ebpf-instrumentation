// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"slices"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rpcStatsLatencyBTF is the sunrpc BTF of rpc_stats_latency as the Rocky 9
// lab (5.14.0-687) has it (S0-c):
//
//	TYPEDEF 'btf_trace_rpc_stats_latency' -> PTR -> FUNC_PROTO vlen=5
//	  (void *), (const struct rpc_task *), ktime_t, ktime_t, ktime_t
//
// params, when given, replaces the prototype's parameters.
func rpcStatsLatencyBTF(t *testing.T, params ...btf.FuncParam) *btf.Spec {
	t.Helper()
	ktime := &btf.Typedef{Name: "ktime_t", Type: &btf.Int{Name: "long long int", Size: 8, Encoding: btf.Signed}}
	task := &btf.Pointer{Target: &btf.Const{Type: &btf.Struct{Name: "rpc_task", Size: 256}}}
	if params == nil {
		params = []btf.FuncParam{
			{Type: &btf.Pointer{Target: &btf.Void{}}},
			{Type: task},
			{Type: ktime},
			{Type: ktime},
			{Type: ktime},
		}
	}
	proto := &btf.FuncProto{Return: &btf.Void{}, Params: params}
	typedef := &btf.Typedef{Name: nfsTracepointTypedef, Type: &btf.Pointer{Target: proto}}
	b, err := btf.NewBuilder([]btf.Type{typedef}, nil)
	require.NoError(t, err)
	spec, err := b.Spec()
	require.NoError(t, err)
	return spec
}

func TestCheckNFSTracepoint(t *testing.T) {
	require.NoError(t, checkNFSTracepoint(rpcStatsLatencyBTF(t)), "the lab's prototype")

	ktime := &btf.Typedef{Name: "ktime_t", Type: &btf.Int{Name: "long long int", Size: 8, Encoding: btf.Signed}}
	voidPtr := &btf.Pointer{Target: &btf.Void{}}
	task := &btf.Pointer{Target: &btf.Struct{Name: "rpc_task"}}
	for name, params := range map[string][]btf.FuncParam{
		// Without the tracepoint data pointer, args[0] would not be the task.
		"4 parameters":        {{Type: task}, {Type: ktime}, {Type: ktime}, {Type: ktime}},
		"task not first":      {{Type: voidPtr}, {Type: ktime}, {Type: task}, {Type: ktime}, {Type: ktime}},
		"not a task":          {{Type: voidPtr}, {Type: &btf.Pointer{Target: &btf.Struct{Name: "rpc_rqst"}}}, {Type: ktime}, {Type: ktime}, {Type: ktime}},
		"no data pointer":     {{Type: task}, {Type: task}, {Type: ktime}, {Type: ktime}, {Type: ktime}},
		"execute not ktime_t": {{Type: voidPtr}, {Type: task}, {Type: ktime}, {Type: ktime}, {Type: &btf.Int{Name: "long unsigned int", Size: 8}}},
	} {
		require.Error(t, checkNFSTracepoint(rpcStatsLatencyBTF(t, params...)), name)
	}

	b, err := btf.NewBuilder([]btf.Type{&btf.Int{Name: "int", Size: 4}}, nil)
	require.NoError(t, err)
	spec, err := b.Spec()
	require.NoError(t, err)
	assert.Error(t, checkNFSTracepoint(spec), "no tracepoint")
}

// Without module BTF for sunrpc and without its tracepoint in the kernel's
// BTF, sunrpc is either a module not loaded yet, which the attacher waits
// for, or a kernel without module BTF, which disables the NFS metrics.
func TestNFSTracepointBTFWithoutSunrpc(t *testing.T) {
	cache := btf.NewCache()
	kernel, err := cache.Kernel()
	if err != nil {
		t.Skip("no kernel BTF:", err)
	}
	var typedef *btf.Typedef
	if kernel.TypeByName(nfsTracepointTypedef, &typedef) == nil {
		t.Skip("sunrpc is built into this kernel")
	}
	old := sysKernelBTFDir
	sysKernelBTFDir = t.TempDir()
	t.Cleanup(func() { sysKernelBTFDir = old })

	_, err = nfsTracepointBTF(cache, func(string) bool { return false })
	require.ErrorIs(t, err, errSunrpcNotLoaded)

	_, err = nfsTracepointBTF(cache, func(string) bool { return true })
	require.Error(t, err)
	assert.NotErrorIs(t, err, errSunrpcNotLoaded)
}

// The running kernel's rpc_stats_latency, when sunrpc is there, has the
// prototype the programs read.
func TestCheckNFSTracepointOnThisKernel(t *testing.T) {
	spec, err := nfsTracepointBTF(btf.NewCache(), moduleLoaded)
	if err != nil {
		t.Skip("no sunrpc BTF on this kernel:", err)
	}
	require.NoError(t, checkNFSTracepoint(spec))
}

type fakeCloser struct{ closed bool }

func (c *fakeCloser) Close() error {
	c.closed = true
	return nil
}

func TestAttachNFSProgramFallsBackToRawTracepoint(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	var tried []string
	attach := func(fail ...string) func(string) (io.Closer, error) {
		return func(prog string) (io.Closer, error) {
			tried = append(tried, prog)
			if slices.Contains(fail, prog) {
				return nil, errors.New("rejected")
			}
			return &fakeCloser{}, nil
		}
	}

	_, prog, err := attachNFSProgram(log, attach())
	require.NoError(t, err)
	assert.Equal(t, progObiStatsTpBtfRPCStatsLatency, prog)
	assert.Equal(t, []string{progObiStatsTpBtfRPCStatsLatency}, tried, "no raw_tp load when tp_btf attaches")

	tried = nil
	_, prog, err = attachNFSProgram(log, attach(progObiStatsTpBtfRPCStatsLatency))
	require.NoError(t, err)
	assert.Equal(t, progObiStatsRawTpRPCStatsLatency, prog)
	assert.Equal(t, []string{progObiStatsTpBtfRPCStatsLatency, progObiStatsRawTpRPCStatsLatency}, tried)

	_, _, err = attachNFSProgram(log, attach(progObiStatsTpBtfRPCStatsLatency, progObiStatsRawTpRPCStatsLatency))
	require.Error(t, err)
}

// attachNFSProgramPair is shared by the main and begin programs: the begin
// pair falls back from tp_btf to raw_tp exactly like the main one.
func TestAttachNFSBeginProgramFallsBackToRawTracepoint(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	attach := func(fail ...string) func(string) (io.Closer, error) {
		return func(prog string) (io.Closer, error) {
			if slices.Contains(fail, prog) {
				return nil, errors.New("rejected")
			}
			return &fakeCloser{}, nil
		}
	}

	_, prog, err := attachNFSProgramPair(log, attach(), progObiStatsTpBtfRPCTaskBegin, progObiStatsRawTpRPCTaskBegin, "NFS task-begin")
	require.NoError(t, err)
	assert.Equal(t, progObiStatsTpBtfRPCTaskBegin, prog)

	_, prog, err = attachNFSProgramPair(log, attach(progObiStatsTpBtfRPCTaskBegin), progObiStatsTpBtfRPCTaskBegin, progObiStatsRawTpRPCTaskBegin, "NFS task-begin")
	require.NoError(t, err)
	assert.Equal(t, progObiStatsRawTpRPCTaskBegin, prog)

	_, _, err = attachNFSProgramPair(log, attach(progObiStatsTpBtfRPCTaskBegin, progObiStatsRawTpRPCTaskBegin),
		progObiStatsTpBtfRPCTaskBegin, progObiStatsRawTpRPCTaskBegin, "NFS task-begin")
	require.ErrorContains(t, err, "NFS task-begin")
}

// fakeNFSNode is a node whose sunrpc module and NFS program loads a test
// controls.
type fakeNFSNode struct {
	loaded    bool
	preflight error
	attachErr error
	attaches  int
	bursts    int
	attached  *fakeCloser

	// withBegin makes attacher() set beginFn; beginErr and beginAttaches
	// control and count its calls, like attachErr and attaches for the
	// main program.
	withBegin     bool
	beginErr      error
	beginAttaches int
	beginAttached *fakeCloser
}

func (n *fakeNFSNode) attacher() *nfsAttacher {
	a := &nfsAttacher{
		log: slog.New(slog.DiscardHandler),
		preflight: func() error {
			if !n.loaded {
				return errSunrpcNotLoaded
			}
			return n.preflight
		},
		attachFn: func() (io.Closer, string, error) {
			n.attaches++
			if n.attachErr != nil {
				return nil, "", n.attachErr
			}
			n.attached = &fakeCloser{}
			return n.attached, progObiStatsTpBtfRPCStatsLatency, nil
		},
		moduleLoaded: func(string) bool { return n.loaded },
		endBurst:     func() { n.bursts++ },
		checkDrops:   func() {},
		stop:         make(chan struct{}),
		stopped:      make(chan struct{}),
	}
	if n.withBegin {
		a.beginFn = func() (io.Closer, string, error) {
			n.beginAttaches++
			if n.beginErr != nil {
				return nil, "", n.beginErr
			}
			n.beginAttached = &fakeCloser{}
			return n.beginAttached, progObiStatsTpBtfRPCTaskBegin, nil
		}
	}
	return a
}

// On a fresh node, sunrpc loads with the first NFS mount, after OBI: the
// attacher keeps looking, for as long as it takes, and attaches then.
func TestNFSAttacherWaitsForSunrpc(t *testing.T) {
	node := &fakeNFSNode{}
	a := node.attacher()
	a.refresh()
	assert.Zero(t, node.attaches, "sunrpc is not loaded")
	for range 20 { // ten minutes of ticks
		a.refresh()
	}
	assert.Zero(t, node.attaches)
	assert.Zero(t, node.bursts, "no BTF is parsed while sunrpc is not loaded")
	assert.False(t, a.off)

	node.loaded = true
	a.refresh()
	assert.Equal(t, 1, node.attaches)
	assert.Equal(t, 1, node.bursts, "a late attach ends its BTF burst")
	a.refresh()
	assert.Equal(t, 1, node.attaches, "attached once")

	go a.run()
	require.NoError(t, a.Close())
	assert.True(t, node.attached.closed)
}

// A load or attach failure is tried three times in a row, one tick apart,
// then the NFS metrics stay off until OBI restarts.
func TestNFSAttacherStopsAfterThreeFailures(t *testing.T) {
	node := &fakeNFSNode{loaded: true, attachErr: errors.New("verifier rejection")}
	a := node.attacher()
	for range 5 {
		a.refresh()
	}
	assert.Equal(t, nfsAttachTries, node.attaches)
	assert.True(t, a.off)
}

func TestNFSAttacherRecoversFromOneFailure(t *testing.T) {
	node := &fakeNFSNode{loaded: true, attachErr: errors.New("module still initializing")}
	a := node.attacher()
	a.refresh()
	node.attachErr = nil
	a.refresh()
	assert.Equal(t, 2, node.attaches)
	assert.NotNil(t, a.attached)
	assert.Zero(t, a.failures)
}

// A tracepoint the programs cannot read (no sunrpc BTF, another prototype)
// disables the NFS metrics at once: retrying cannot change it.
func TestNFSAttacherPreflightFailureDisables(t *testing.T) {
	node := &fakeNFSNode{loaded: true, preflight: errors.New("unexpected prototype")}
	a := node.attacher()
	a.refresh()
	a.refresh()
	assert.Zero(t, node.attaches)
	assert.True(t, a.off)
}

// When a pod attribute is selected on a cgroup v2 host, startNFS sets
// beginFn: the begin program attaches in the same refresh as the main one.
func TestNFSAttacherAttachesBeginAlongsideMain(t *testing.T) {
	node := &fakeNFSNode{loaded: true, withBegin: true}
	a := node.attacher()
	a.refresh()
	assert.Equal(t, 1, node.attaches)
	assert.Equal(t, 1, node.beginAttaches)
	require.NotNil(t, a.beginAttached)

	go a.run()
	require.NoError(t, a.Close())
	assert.True(t, node.attached.closed)
	assert.True(t, node.beginAttached.closed, "Close closes the begin program too")
}

// A begin-program failure is logged once and never retried: it only means
// NFS RPCs keep no pod owner, not that the metrics themselves are broken.
func TestNFSAttacherBeginFailureIsNotRetriedAndMainStaysUp(t *testing.T) {
	node := &fakeNFSNode{loaded: true, withBegin: true, beginErr: errors.New("verifier rejection")}
	h := &levelCount{}
	a := node.attacher()
	a.log = slog.New(h)
	a.refresh()
	assert.Equal(t, 1, node.beginAttaches)
	assert.Nil(t, a.beginAttached)
	assert.Equal(t, 1, h.warn)
	require.NotNil(t, a.attached, "the main program stays up")

	// The attacher never retries once attached: the main program's
	// attachFn runs once per sunrpc appearance, which already happened.
	for range 5 {
		a.refresh()
	}
	assert.Equal(t, 1, node.beginAttaches)
	assert.Equal(t, 1, h.warn, "warned only once")
}

func TestNFSDropsWarnOnce(t *testing.T) {
	var drops uint64
	h := &levelCount{}
	d := &dropsLog{log: slog.New(h), read: func() (uint64, error) { return drops, nil }}
	d.check()
	assert.Zero(t, h.warn+h.debug, "no drops, no log")
	drops = 3
	d.check()
	drops = 5
	d.check()
	d.check()
	assert.Equal(t, 1, h.warn)
	assert.Equal(t, 1, h.debug)
}

func TestPrepareNFSSpec(t *testing.T) {
	bounds := make([]uint64, 32)
	for i := range bounds {
		bounds[i] = math.MaxUint64
	}
	bounds[0] = 1000

	spec, err := LoadNfsRpc()
	require.NoError(t, err)
	accum, err := prepareNFSSpec(spec, 0, true, NFSConfig{KernelBounds: bounds, Owner: true})
	require.NoError(t, err)
	assert.Equal(t, NfsRpcMapNfsRpcAccum, accum)
	assert.Equal(t, uint32(4096*nfsOwnerAccumFactor), spec.Maps[NfsRpcMapNfsRpcAccum].MaxEntries, "an owner multiplies the keys")
	assert.Equal(t, uint32(1<<18), spec.Maps[NfsRpcMapNfsTaskCg].MaxEntries)
	assert.Equal(t, unusedMapEntries, spec.Maps[NfsRpcMapNfsRpcAccumExp].MaxEntries)
	var got [32]uint64
	require.NoError(t, spec.Variables[NfsRpcVarNfsRpcBoundsNs].Get(&got))
	assert.Equal(t, bounds, got[:])
	var want uint8
	require.NoError(t, spec.Variables[NfsRpcVarNfsWantStatus].Get(&want))
	assert.Equal(t, uint8(1), want)
	var owner, cgroupV1 uint8
	require.NoError(t, spec.Variables[NfsRpcVarNfsKeyOwner].Get(&owner))
	assert.Equal(t, uint8(1), owner, "a pod attribute is selected")
	require.NoError(t, spec.Variables[NfsRpcVarNfsCgroupV1].Get(&cgroupV1))
	assert.Equal(t, uint8(0), cgroupV1, "cgroup v2 by default")

	expBounds := make([]uint64, 128)
	spec, err = LoadNfsRpc()
	require.NoError(t, err)
	accum, err = prepareNFSSpec(spec, 1, false, NFSConfig{Exponential: true, KernelBounds: expBounds})
	require.NoError(t, err)
	assert.Equal(t, NfsRpcMapNfsRpcAccumExp, accum)
	assert.Equal(t, uint32(8192), spec.Maps[NfsRpcMapNfsRpcAccumExp].MaxEntries, "sized with the global scale factor")
	assert.Equal(t, unusedMapEntries, spec.Maps[NfsRpcMapNfsTaskCg].MaxEntries, "no owner: no side map")
	assert.Equal(t, unusedMapEntries, spec.Maps[NfsRpcMapNfsRpcAccum].MaxEntries)
	var exp uint8
	require.NoError(t, spec.Variables[NfsRpcVarNfsHistExp].Get(&exp))
	assert.Equal(t, uint8(1), exp)
}

// levelCount counts the records logged at Warn and at Debug.
type levelCount struct{ warn, debug int }

func (h *levelCount) Enabled(context.Context, slog.Level) bool { return true }
func (h *levelCount) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *levelCount) WithGroup(string) slog.Handler            { return h }

func (h *levelCount) Handle(_ context.Context, r slog.Record) error {
	switch r.Level {
	case slog.LevelWarn:
		h.warn++
	case slog.LevelDebug:
		h.debug++
	}
	return nil
}
