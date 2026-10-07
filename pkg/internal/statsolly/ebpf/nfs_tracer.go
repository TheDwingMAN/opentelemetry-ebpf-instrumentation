// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

// The NFS client RPC programs are an object of their own: they load only
// when an NFS metric is enabled and sunrpc is there, and a load failure
// disables the NFS metrics only.
// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target $BPF_TARGETS -output-stem stats_nfsrpc NfsRpc ../../../../bpf/statsolly/nfs_rpc.c -- -I../../../../bpf

const (
	progObiStatsTpBtfRPCStatsLatency = "obi_stats_tp_btf_rpc_stats_latency"
	progObiStatsRawTpRPCStatsLatency = "obi_stats_raw_tp_rpc_stats_latency"
	// The rpc_task_begin programs (step 19): loaded and attached only when
	// NFSConfig.Owner is set and the host is not cgroup v1.
	progObiStatsTpBtfRPCTaskBegin = "obi_stats_tp_btf_rpc_task_begin"
	progObiStatsRawTpRPCTaskBegin = "obi_stats_raw_tp_rpc_task_begin"

	// RawTracepointRPCStatsLatency is the sunrpc tracepoint the NFS programs
	// attach to, once per RPC attempt.
	RawTracepointRPCStatsLatency = "rpc_stats_latency"
	// RawTracepointRPCTaskBegin is the sunrpc tracepoint the begin programs
	// attach to, once per RPC task, in the thread that started it.
	RawTracepointRPCTaskBegin = "rpc_task_begin"
	// nfsModule is the kernel module rpc_stats_latency and rpc_task_begin
	// live in.
	nfsModule = "sunrpc"
	// nfsTracepointTypedef is the BTF prototype of rpc_stats_latency:
	// void (*)(void *, const struct rpc_task *, ktime_t backlog, ktime_t rtt,
	// ktime_t execute).
	nfsTracepointTypedef = "btf_trace_" + RawTracepointRPCStatsLatency
)

// nfsRawTracepointFor names the raw tracepoint link.AttachRawTracepoint
// attaches a raw_tp NFS program to.
var nfsRawTracepointFor = map[string]string{
	progObiStatsRawTpRPCStatsLatency: RawTracepointRPCStatsLatency,
	progObiStatsRawTpRPCTaskBegin:    RawTracepointRPCTaskBegin,
}

// NFSConfig is how the NFS client RPC programs count: the kernel histogram
// layout the exporters' bucket settings select, and the pod attribution of
// step 19.
type NFSConfig struct {
	// Exponential counts in the exponential layout, nfs_rpc_accum_exp.
	Exponential bool
	// KernelBounds are the layout's bounds in nanoseconds, padded with
	// math.MaxUint64 to the size of its bound array.
	KernelBounds []uint64
	// Owner is whether a pod attribute (the pod trio or k8s.owner.name) is
	// selected on an NFS metric: the key keeps an owner, and on cgroup v2
	// the rpc_task_begin program attaches to capture it.
	Owner bool
	// CgroupV1 is whether this host's cgroup v2 hierarchy is not delegated
	// down to containers (S0-d): bpf_get_current_cgroup_id() would be the
	// root cgroup for every task there, so the owner is read directly from
	// the submitting thread's tgid (task->tk_owner) instead, and the begin
	// program is never attached.
	CgroupV1 bool
}

// errSunrpcNotLoaded is returned by the preflight while sunrpc is a module
// that is not loaded yet: the NFS programs attach once it is.
var errSunrpcNotLoaded = errors.New("the sunrpc module is not loaded")

// nfsTracepointBTF returns the BTF that describes rpc_stats_latency: the
// sunrpc module's, or the kernel's when sunrpc is built in.
func nfsTracepointBTF(cache *btf.Cache, loaded func(string) bool) (*btf.Spec, error) {
	if moduleBTFExists(nfsModule) {
		return cache.Module(nfsModule)
	}
	kernel, err := cache.Kernel()
	if err != nil {
		return nil, fmt.Errorf("reading the kernel BTF: %w", err)
	}
	var typedef *btf.Typedef
	if kernel.TypeByName(nfsTracepointTypedef, &typedef) == nil {
		return kernel, nil
	}
	if !loaded(nfsModule) {
		return nil, errSunrpcNotLoaded
	}
	return nil, errors.New("sunrpc is loaded but the kernel has no BTF for it:" +
		" the NFS client RPC metrics need kernel module BTF (CONFIG_DEBUG_INFO_BTF_MODULES, Linux 5.11+ or RHEL 9)")
}

// checkNFSTracepoint checks that rpc_stats_latency has the prototype the
// programs read: the tracepoint data, the task, then backlog, rtt and
// execute. Under raw_tp the task is args[0] and execute args[3].
func checkNFSTracepoint(spec *btf.Spec) error {
	var typedef *btf.Typedef
	if err := spec.TypeByName(nfsTracepointTypedef, &typedef); err != nil {
		return fmt.Errorf("no %s in the sunrpc BTF: %w", nfsTracepointTypedef, err)
	}
	ptr, ok := typedef.Type.(*btf.Pointer)
	if !ok {
		return fmt.Errorf("%s is not a function pointer", nfsTracepointTypedef)
	}
	proto, ok := ptr.Target.(*btf.FuncProto)
	if !ok {
		return fmt.Errorf("%s is not a function pointer", nfsTracepointTypedef)
	}
	const params = 5
	if len(proto.Params) != params {
		return fmt.Errorf("unexpected %s prototype with %d parameters, want %d",
			RawTracepointRPCStatsLatency, len(proto.Params), params)
	}
	if !isVoidPointer(proto.Params[0].Type) {
		return fmt.Errorf("%s: parameter 0 is not the tracepoint's void *", RawTracepointRPCStatsLatency)
	}
	if !isPointerToStruct(proto.Params[1].Type, "rpc_task") {
		return fmt.Errorf("%s: parameter 1 is not a struct rpc_task pointer", RawTracepointRPCStatsLatency)
	}
	for i, p := range proto.Params[2:] {
		if td, ok := p.Type.(*btf.Typedef); !ok || td.Name != "ktime_t" {
			return fmt.Errorf("%s: parameter %d is not a ktime_t", RawTracepointRPCStatsLatency, i+2)
		}
	}
	return nil
}

func isVoidPointer(t btf.Type) bool {
	ptr, ok := t.(*btf.Pointer)
	if !ok {
		return false
	}
	_, void := ptr.Target.(*btf.Void)
	return void
}

func isPointerToStruct(t btf.Type, name string) bool {
	ptr, ok := t.(*btf.Pointer)
	if !ok {
		return false
	}
	s, ok := btf.UnderlyingType(ptr.Target).(*btf.Struct)
	return ok && s.Name == name
}

// nfsLoader loads the NfsRpc collection with one of its two programs. Every
// load shares the aggregation and drop maps, created with the loader, and the
// kernel BTF cache. It is used from one goroutine at a time.
type nfsLoader struct {
	log *slog.Logger
	// spec is sized and configured once; each load works on a copy.
	spec *ebpf.CollectionSpec
	maps map[string]*ebpf.Map
	mu   sync.Mutex
	btf  *btfBurst
	// accum is the aggregation map of the layout in use.
	accum string
	// newCollection is ebpf.NewCollectionWithOptions, replaceable in tests
	// that cannot load BPF.
	newCollection func(*ebpf.CollectionSpec, ebpf.CollectionOptions) (*ebpf.Collection, error)
}

func newNFSLoader(log *slog.Logger, cfg *config.EBPFTracer, features export.Features, nfs NFSConfig) (*nfsLoader, error) {
	spec, err := LoadNfsRpc()
	if err != nil {
		return nil, fmt.Errorf("loading NFS BPF data: %w", err)
	}
	accum, err := prepareNFSSpec(spec, cfg.MapsConfig.GlobalScaleFactor, features.StorageNFSErrors(), nfs)
	if err != nil {
		return nil, err
	}
	l := &nfsLoader{
		log:           log,
		spec:          spec,
		maps:          map[string]*ebpf.Map{},
		btf:           kernelBTFCache,
		accum:         accum,
		newCollection: ebpf.NewCollectionWithOptions,
	}
	// The maps exist from now on, whenever the programs attach: userspace
	// reads them from startup, and a program reloaded after a failure
	// counts into the same map.
	if _, err := ebpfconvenience.ResolveMaps(spec.Copy(), l.maps, &l.mu); err != nil {
		return nil, fmt.Errorf("creating the NFS maps: %w", err)
	}
	return l, nil
}

// prepareNFSSpec sizes the maps and sets the load-time constants every load
// of spec uses, and returns the aggregation map the programs count into: the
// other layout's map is created with a single entry.
func prepareNFSSpec(spec *ebpf.CollectionSpec, scaleFactor int, wantStatus bool, nfs NFSConfig) (string, error) {
	ebpfconvenience.SetupMapSizes(spec, scaleFactor)
	accum, unused, bounds := NfsRpcMapNfsRpcAccum, NfsRpcMapNfsRpcAccumExp, NfsRpcVarNfsRpcBoundsNs
	if nfs.Exponential {
		accum, unused, bounds = NfsRpcMapNfsRpcAccumExp, NfsRpcMapNfsRpcAccum, NfsRpcVarNfsRpcExpBoundsNs
	}
	entries := map[string]uint32{unused: unusedMapEntries}
	if nfs.Owner {
		// The owner multiplies the key space by the number of submitting
		// cgroups (or tgids on cgroup v1), and the side map must outlive a
		// slow RPC while every completed one churns it (no delete hook: a
		// retry reuses the task).
		entries[accum] = scaledEntries(spec.Maps[accum].MaxEntries, nfsOwnerAccumFactor)
		entries[NfsRpcMapNfsTaskCg] = scaledEntries(spec.Maps[NfsRpcMapNfsTaskCg].MaxEntries, nfsTaskCgFactor)
	} else {
		// No owner: the side map is never written or read.
		entries[NfsRpcMapNfsTaskCg] = unusedMapEntries
	}
	if err := setMapEntries(spec, entries); err != nil {
		return "", err
	}
	consts := map[string]any{
		NfsRpcVarNfsWantStatus: boolConst(wantStatus),
		NfsRpcVarNfsHistExp:    boolConst(nfs.Exponential),
		NfsRpcVarNfsKeyOwner:   boolConst(nfs.Owner),
		NfsRpcVarNfsCgroupV1:   boolConst(nfs.CgroupV1),
	}
	if nfs.KernelBounds != nil {
		consts[bounds] = nfs.KernelBounds
	}
	if err := ebpfconvenience.RewriteConstants(spec, consts); err != nil {
		return "", fmt.Errorf("setting the NFS BPF constants: %w", err)
	}
	return accum, nil
}

const (
	// nfsOwnerAccumFactor multiplies the aggregation map when keys carry an
	// owner: dozens of (operation x status x server) keys per pod.
	nfsOwnerAccumFactor = 8
	// nfsTaskCgFactor multiplies nfs_task_cg's declared size (1<<14) to 1<<18
	// entries: an entry survives seconds, not milliseconds, at 100k RPC/s.
	nfsTaskCgFactor = 16
)

// scaledEntries returns n*factor, capped at the largest map size.
func scaledEntries(n, factor uint32) uint32 {
	if n > ebpfconvenience.MaxMapEntries/factor {
		return ebpfconvenience.MaxMapEntries
	}
	return n * factor
}

// Map returns one of the NFS maps.
func (l *nfsLoader) Map(name string) *ebpf.Map {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maps[name]
}

// attach attaches the tp_btf program, whose pointer walks are plain loads,
// or when it cannot load or attach, the raw_tp program, which reads through
// bpf_probe_read_kernel. It returns the attached program's name.
func (l *nfsLoader) attach() (io.Closer, string, error) {
	return attachNFSProgram(l.log, l.attachProgram)
}

func attachNFSProgram(log *slog.Logger, attach func(prog string) (io.Closer, error)) (io.Closer, string, error) {
	return attachNFSProgramPair(log, attach, progObiStatsTpBtfRPCStatsLatency, progObiStatsRawTpRPCStatsLatency, "NFS")
}

// attachBegin attaches the rpc_task_begin program (step 19), tp_btf first
// then raw_tp, exactly like attach. Call it only when the owner is wanted on
// a cgroup v2 host.
func (l *nfsLoader) attachBegin() (io.Closer, string, error) {
	return attachNFSProgramPair(l.log, l.attachProgram, progObiStatsTpBtfRPCTaskBegin, progObiStatsRawTpRPCTaskBegin, "NFS task-begin")
}

// attachNFSProgramPair tries the tp_btf program progBTF, then, on failure,
// the raw_tp fallback progRaw; label names the pair in the fallback log and
// the error it returns when neither attaches.
func attachNFSProgramPair(
	log *slog.Logger, attach func(prog string) (io.Closer, error), progBTF, progRaw, label string,
) (io.Closer, string, error) {
	c, errBTF := attach(progBTF)
	if errBTF == nil {
		return c, progBTF, nil
	}
	c, errRaw := attach(progRaw)
	if errRaw != nil {
		return nil, "", fmt.Errorf("neither %s program attaches: %w", label, errors.Join(errBTF, errRaw))
	}
	log.Info("the tp_btf "+label+" program cannot load or attach; using the raw tracepoint program", "error", errBTF)
	return c, progRaw, nil
}

func (l *nfsLoader) attachProgram(prog string) (io.Closer, error) {
	coll, err := l.load(prog)
	if err != nil {
		return nil, err
	}
	p := coll.Programs[prog]
	var lnk link.Link
	if p.Type() == ebpf.Tracing {
		lnk, err = link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachTraceRawTp})
	} else {
		lnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: nfsRawTracepointFor[prog], Program: p})
	}
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attaching %s: %w", prog, err)
	}
	return &nfsAttachment{coll: coll, link: lnk}, nil
}

// load loads the collection with only prog.
func (l *nfsLoader) load(prog string) (*ebpf.Collection, error) {
	spec := l.spec.Copy()
	for name := range spec.Programs {
		if name != prog {
			delete(spec.Programs, name)
		}
	}
	opts, err := ebpfconvenience.ResolveMaps(spec, l.maps, &l.mu)
	if err != nil {
		return nil, fmt.Errorf("resolving the NFS maps: %w", err)
	}
	opts.Programs = ebpf.ProgramOptions{LogSizeStart: fsVerifierLogSize}
	opts.Cache = l.btf.CacheFor(l.log, nfsModule)
	coll, err := l.newCollection(spec, *opts)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", prog, err)
	}
	return coll, nil
}

// PrepareNFSSpec removes the tp_btf programs from spec, for the verifier
// tests, when this kernel has no sunrpc BTF to load them against, and
// reports whether it kept them. The raw_tp programs load either way:
// without the sunrpc types their reads are dead code.
func PrepareNFSSpec(spec *ebpf.CollectionSpec) bool {
	if _, err := nfsTracepointBTF(kernelBTFCache.Cache(), moduleLoaded); err == nil {
		return true
	}
	delete(spec.Programs, progObiStatsTpBtfRPCStatsLatency)
	delete(spec.Programs, progObiStatsTpBtfRPCTaskBegin)
	return false
}

type nfsAttachment struct {
	coll    *ebpf.Collection
	link    link.Link
	recMiss recursionMisses
}

// pollRecursionMisses reports the recursion misses of the NFS program.
func (a *nfsAttachment) pollRecursionMisses(metrics imetrics.Reporter) {
	a.recMiss.poll(a.coll.Programs, metrics)
}

func (a *nfsAttachment) Close() error {
	err := a.link.Close()
	a.coll.Close()
	return err
}

// nfsAttacher attaches the NFS program once sunrpc is there: at startup, or
// from the tick after its module loads, which on a freshly started node
// comes with the first NFS mount, after OBI. It then stays attached until
// closed: an attached program holds sunrpc, which cannot unload.
type nfsAttacher struct {
	log *slog.Logger
	// preflight checks the tracepoint's BTF: errSunrpcNotLoaded waits for
	// the module, any other error disables the NFS metrics.
	preflight func() error
	attachFn  func() (io.Closer, string, error)
	// beginFn attaches the rpc_task_begin program (step 19); nil unless a
	// pod attribute is selected on a cgroup v2 host. Tried once, in the
	// same refresh that first attaches attachFn: a failure only means NFS
	// RPCs keep no owner, so it is never retried.
	beginFn func() (io.Closer, string, error)
	// moduleLoaded reports whether a kernel module is loaded.
	moduleLoaded func(module string) bool
	// endBurst ends the kernel BTF burst of a refresh that tried to attach.
	endBurst func()
	// checkDrops reads the attempts the kernel could not count.
	checkDrops func()
	// metrics receives the recursion misses of the attached programs; nil
	// reports nothing.
	metrics imetrics.Reporter

	// started is false until the first refresh, which tries whether or not
	// sunrpc has a /sys/module entry.
	started       bool
	attached      io.Closer
	beginAttached io.Closer
	// failures counts the failed loads and attaches in a row.
	failures int
	// off is set once the NFS metrics are disabled until OBI restarts.
	off bool
	// beginWarned is set once the begin program fails to attach, so the
	// warning is logged only the one time it is tried.
	beginWarned bool

	stop    chan struct{}
	stopped chan struct{}
}

// nfsAttachInterval and nfsAttachTries are the filesystem attacher's: a
// module still initializing can fail once, a verifier rejection fails every
// time.
const (
	nfsAttachInterval = fsAttachInterval
	nfsAttachTries    = fsAttachTries
)

func (a *nfsAttacher) run() {
	defer close(a.stopped)
	ticker := time.NewTicker(nfsAttachInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-ticker.C:
			a.refresh()
			a.checkDrops()
			a.logRecursionMisses()
		}
	}
}

// logRecursionMisses reports the recursion misses of the attached programs
// as the obi.bpf.storage.program.recursion.misses internal metric.
func (a *nfsAttacher) logRecursionMisses() {
	if a.metrics == nil {
		return
	}
	for _, closer := range []io.Closer{a.attached, a.beginAttached} {
		if r, ok := closer.(recursionMissReporter); ok {
			r.pollRecursionMisses(a.metrics)
		}
	}
}

// refresh attaches the NFS program when sunrpc is there and nothing ruled
// the NFS metrics out.
func (a *nfsAttacher) refresh() {
	startup := !a.started
	a.started = true
	if a.attached != nil || a.off {
		return
	}
	if !startup && !a.moduleLoaded(nfsModule) {
		return
	}
	// The startup refresh is part of the startup loads' burst, which the
	// stats fetcher ends.
	if !startup {
		defer a.endBurst()
	}

	if err := a.preflight(); err != nil {
		if errors.Is(err, errSunrpcNotLoaded) {
			if startup {
				a.log.Info("sunrpc is not loaded; the NFS client RPC metrics start when it is")
			}
			return
		}
		a.off = true
		a.log.Warn("the NFS client RPC tracepoint is not usable; disabling the NFS metrics", "error", err)
		return
	}

	closer, prog, err := a.attachFn()
	if err != nil {
		a.failures++
		if a.failures < nfsAttachTries {
			a.log.Warn("the NFS program failed to load or attach; retrying", "error", err)
			return
		}
		a.off = true
		a.log.Warn("the NFS program failed to load or attach; disabling the NFS metrics", "error", err)
		return
	}
	a.attached = closer
	a.failures = 0
	if a.beginFn != nil {
		a.attachBegin()
	}
	if startup {
		a.log.Info("NFS client RPC program attached", "program", prog)
		return
	}
	a.log.Info("sunrpc became probeable after startup; NFS client RPC program attached", "program", prog)
}

// attachBegin tries the rpc_task_begin program once: a failure leaves NFS
// RPCs without an owner, which StatGetters already defaults to "", so it is
// logged once and never retried.
func (a *nfsAttacher) attachBegin() {
	closer, prog, err := a.beginFn()
	if err != nil {
		if !a.beginWarned {
			a.beginWarned = true
			a.log.Warn("the NFS task-begin program failed to load or attach; NFS RPCs keep no pod owner", "error", err)
		}
		return
	}
	a.beginAttached = closer
	a.log.Info("NFS task-begin program attached", "program", prog)
}

func (a *nfsAttacher) Close() error {
	close(a.stop)
	<-a.stopped
	var errs []error
	if a.beginAttached != nil {
		errs = append(errs, a.beginAttached.Close())
	}
	if a.attached != nil {
		errs = append(errs, a.attached.Close())
	}
	return errors.Join(errs...)
}

// dropsLog warns the first time a counter it reads increases, and logs the
// later increases at Debug. warnMsg and debugMsg default to "" (no message
// text), harmless for a test that only counts how many times each level
// logged.
type dropsLog struct {
	log      *slog.Logger
	read     func() (uint64, error)
	warnMsg  string
	debugMsg string
	seen     uint64
	warned   bool
}

func (d *dropsLog) check() {
	n, err := d.read()
	if err != nil {
		d.log.Debug("reading the NFS drop counter failed", "error", err)
		return
	}
	if n == d.seen {
		return
	}
	d.seen = n
	if d.warned {
		d.log.Debug(d.debugMsg, "total", n)
		return
	}
	d.warned = true
	d.log.Warn(d.warnMsg, "total", n)
}

// sumPerCPU returns the sum of the per-CPU u64 values of key 0 of an array.
func sumPerCPU(m *ebpf.Map) (uint64, error) {
	var values []uint64
	if err := m.Lookup(uint32(0), &values); err != nil {
		return 0, err
	}
	var n uint64
	for _, v := range values {
		n += v
	}
	return n, nil
}

// nfsRPC is the NFS programs' aggregation map and their attacher.
type nfsRPC struct {
	accum    *ebpf.Map
	attacher *nfsAttacher
}

func (n *nfsRPC) Close() error { return n.attacher.Close() }

// startNFS creates the NFS maps, attaches the NFS program if sunrpc is
// there, and keeps looking for sunrpc every nfsAttachInterval until closed.
func startNFS(log *slog.Logger, cfg *config.EBPFTracer, features export.Features, nfs NFSConfig, metrics imetrics.Reporter) (*nfsRPC, error) {
	loader, err := newNFSLoader(log, cfg, features, nfs)
	if err != nil {
		return nil, err
	}
	drops := &dropsLog{
		log:      log,
		read:     func() (uint64, error) { return sumPerCPU(loader.Map(NfsRpcMapNfsRpcDrops)) },
		warnMsg:  "NFS RPC attempts not counted: the aggregation map is full; raise ebpf.maps.global_scale_factor (with a pod attribute selected, each submitting pod adds keys: deselect it or raise the factor further)",
		debugMsg: "NFS RPC attempts not counted: the aggregation map is full",
	}
	// ownerMisses: the begin program never ran for the task (evicted from
	// nfs_task_cg, or the task started before it attached), so the attempt
	// keeps owner 0 instead of its pod (2.5). Checked even when the begin
	// program is not wanted: it then stays 0 and never logs.
	ownerMisses := &dropsLog{
		log:      log,
		read:     func() (uint64, error) { return sumPerCPU(loader.Map(NfsRpcMapNfsTaskCgMisses)) },
		warnMsg:  "NFS RPC attempts had no pod owner: the task-begin side map had no entry for them",
		debugMsg: "NFS RPC attempts had no pod owner",
	}
	a := &nfsAttacher{
		log: log,
		preflight: func() error {
			spec, err := nfsTracepointBTF(loader.btf.Cache(), moduleLoaded)
			if err != nil {
				return err
			}
			return checkNFSTracepoint(spec)
		},
		attachFn:     loader.attach,
		moduleLoaded: moduleLoaded,
		endBurst:     loader.btf.Release,
		checkDrops:   func() { drops.check(); ownerMisses.check() },
		metrics:      metrics,
		stop:         make(chan struct{}),
		stopped:      make(chan struct{}),
	}
	if nfs.Owner && !nfs.CgroupV1 {
		a.beginFn = loader.attachBegin
	}
	a.refresh()
	go a.run()
	return &nfsRPC{accum: loader.Map(loader.accum), attacher: a}, nil
}
