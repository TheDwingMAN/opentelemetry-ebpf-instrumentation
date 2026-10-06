// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && bpf_verifier_tests

package bpf_verifier_test

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	generictracerbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	gotracerbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	gpueventbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/gpuevent"
	logenricherbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"
	loggerbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/logger"
	tpinjectorbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/uprobe"
	watcherbpf "go.opentelemetry.io/obi/pkg/internal/ebpf/watcher"
	netollybpf "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	rdnsxdpbpf "go.opentelemetry.io/obi/pkg/internal/rdns/ebpf/xdp"
	statsolly "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

// specCache memoises the parsed CollectionSpec per loadFn so each combo only
// pays for spec.Copy() instead of re-unmarshalling the embedded ELF.
var (
	specCache   sync.Map // map[uintptr]*ebpf.CollectionSpec keyed by loadFn pointer
	specCacheMu sync.Mutex
	btfCache    = btf.NewCache()
	// storageLoadMu serializes the loads of the storage collections. Their
	// programs relocate against module BTF (nfs, cifs, ceph, sunrpc), and
	// cilium/ebpf v0.22.0's split BTF decoders inflate the types of their
	// shared vmlinux base under their own lock only, so two concurrent
	// relocations through btfCache can write the base's type maps at once
	// (fatal error: concurrent map writes), as soon as more than one of
	// those modules is loaded.
	storageLoadMu sync.Mutex
)

func cachedSpec(t *testing.T, loadFn func() (*ebpf.CollectionSpec, error)) *ebpf.CollectionSpec {
	t.Helper()
	key := fmt.Sprintf("%p", loadFn)
	if cached, ok := specCache.Load(key); ok {
		return cached.(*ebpf.CollectionSpec).Copy()
	}
	specCacheMu.Lock()
	defer specCacheMu.Unlock()
	if cached, ok := specCache.Load(key); ok {
		return cached.(*ebpf.CollectionSpec).Copy()
	}
	spec, err := loadFn()
	require.NoError(t, err, "failed to load collection spec")
	specCache.Store(key, spec)
	return spec.Copy()
}

// loadAndVerify loads a BPF collection spec into the kernel, triggering the BPF
// verifier, then immediately closes it. Any verifier rejection surfaces as a test failure.
// Pin types are stripped so the test works without a mounted BPF filesystem.
// An optional constants map can be provided to rewrite BPF constants before loading.
func loadAndVerify(t *testing.T, name string, loadFn func() (*ebpf.CollectionSpec, error), consts ...map[string]any) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Parallel()
		spec := cachedSpec(t, loadFn)

		// On kernels < 5.17, replace obi_protocol_http (which uses bpf_loop)
		// with obi_protocol_http_legacy, matching what the production loader does.
		if spec.Programs["obi_protocol_http"] != nil {
			ebpfcommon.FixupSpec(spec, false)
		}
		uprobe.PrepareSpecs(spec)

		// Storage programs: the block tracepoint family this kernel uses,
		// and both families of every filesystem's programs, which carry a
		// placeholder attach target: the fentry/fexit ones pointed at the
		// filesystem's own functions or at vmlinux stand-ins, and the
		// kprobe/kretprobe fallback.
		storage := false
		if spec.Programs["obi_stats_tp_block_rq_issue"] != nil || spec.Programs["obi_stats_fentry_nfs_read"] != nil ||
			spec.Programs["obi_stats_tp_btf_block_bio_queue"] != nil {
			require.NoError(t, statsolly.PrepareStorageSpec(spec), "failed to prepare storage programs")
			storage = true
		}

		// The NFS program: the tp_btf variant needs the sunrpc BTF, which a
		// kernel without the module loaded does not have.
		if spec.Programs["obi_stats_tp_btf_rpc_stats_latency"] != nil {
			if !statsolly.PrepareNFSSpec(spec) {
				t.Log("no sunrpc BTF on this kernel: verifying the raw_tp NFS program only")
			}
			storage = true
		}

		if len(consts) > 0 && consts[0] != nil {
			err := ebpfconvenience.RewriteConstants(spec, consts[0])
			require.NoError(t, err, "failed to rewrite constants")
		}

		for _, m := range spec.Maps {
			m.Pinning = ebpf.PinNone
			// Some maps have MaxEntries=0 because the Go code sets them
			// dynamically at runtime. Use a minimal value for verification.
			if m.MaxEntries == 0 {
				switch m.Type {
				case ebpf.RingBuf:
					// Ring buffers require a page-aligned non-zero size.
					m.MaxEntries = uint32(os.Getpagesize())
				case ebpf.SkStorage, ebpf.InodeStorage, ebpf.TaskStorage, ebpf.CgroupStorage:
					// Per-object local storage maps must have MaxEntries=0.
				default:
					m.MaxEntries = 1
				}
			}
		}

		if storage {
			storageLoadMu.Lock()
		}
		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// Increase log buffer so verifier rejections are not truncated.
				LogSizeStart: 10 * 1024 * 1024,
			},
			Cache: btfCache,
		})
		if storage {
			storageLoadMu.Unlock()
		}
		if err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				t.Fatalf("BPF verifier rejected program(s):\n%+v", ve)
			}
			require.NoError(t, err, "failed to load BPF collection")
		}
		coll.Close()
	})
}

// constOption represents one constant and its possible values to test.
type constOption struct {
	name   string
	values []any
}

// forEachCombination generates generate every possible combination of options from all constant
// options and calls fn for each combination. The test name encodes all constant values.
// To get the next combination, it starts at the last index and increments it
// Example: we have 2 values, we start with [0, 0], then [0, 1], [1, 0], [1, 1],
// then [0, 0] stop.
func forEachCombination(t *testing.T, prefix string, loadFn func() (*ebpf.CollectionSpec, error), opts []constOption) {
	t.Helper()
	indices := make([]int, len(opts))
	for {
		consts := make(map[string]any, len(opts))
		var nameParts strings.Builder
		nameParts.WriteString(prefix)
		for i, opt := range opts {
			consts[opt.name] = opt.values[indices[i]]
			fmt.Fprintf(&nameParts, "/%s=%v", opt.name, opt.values[indices[i]])
		}
		loadAndVerify(t, nameParts.String(), loadFn, consts)

		// next combination
		carry := true
		for i := len(indices) - 1; i >= 0 && carry; i-- {
			indices[i]++
			if indices[i] < len(opts[i].values) {
				carry = false // found a valid item
			} else {
				indices[i] = 0 // finished all values for this option so reset
				// and move to the previous option
			}
		}
		if carry {
			break
		}
	}
}

// TestBPFVerifierWithConstants verifies that BPF programs pass the kernel verifier
// across all combinations of constant values (also default ones).
// Different constant values cause the verifier to evaluate different code paths
// (e.g. debug logging, traceparent parsing, header propagation), which may trigger
// verifier rejections not caught by default tests.
// Requires CAP_SYS_ADMIN / root.
// Run with: go test -exec=sudo -tags=bpf_verifier_tests ./pkg/internal/ebpf/verifier/...
func TestBPFVerifierWithConstants(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock limit (insufficient privileges?): %v", err)
	}

	// netolly
	netollyOpts := []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"sampling", []any{uint32(0), uint32(1), uint32(1000)}},
		{"trace_messages", []any{uint8(0), uint8(1)}},
		{"port_guessing", []any{uint8(0), uint8(1)}},
	}
	forEachCombination(t, "netolly/Net", netollybpf.LoadNet, netollyOpts)
	forEachCombination(t, "netolly/NetSk", netollybpf.LoadNetSk, netollyOpts)

	// generictracer
	forEachCombination(t, "generictracer/Bpf", generictracerbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"g_bpf_traceparent_enabled", []any{true, false}},
		{"filter_pids", []any{int32(0), int32(1)}},
		{"high_request_volume", []any{uint32(0), uint32(1)}},
		{"jvm_sampling_interval_ns", []any{uint64(0), uint64(1_000_000_000)}},
		{"max_transaction_time", []any{uint64(0), uint64(60_000_000_000)}},
		{"http_max_captured_bytes", []any{uint32(0), uint32(262144)}},
		{"tcp_max_captured_bytes", []any{uint32(0), uint32(65536)}},
		// pinned on, not paired: before the gate existed this code was live in
		// every combination below, and pairing it here would double the matrix
		{"g_traces_ctx_v1_enabled", []any{true}},
	})

	// nodejs_runtime_metrics_enabled only gates the decode path in nodejs.c,
	// which shares no code with the constants above except the debug and
	// traceparent machinery — a dedicated small matrix keeps the nodejs path
	// verified in both states without doubling the full generictracer
	// cross-product.
	forEachCombination(t, "generictracer/BpfNodejs", generictracerbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"g_bpf_traceparent_enabled", []any{true, false}},
		{"nodejs_runtime_metrics_enabled", []any{uint64(0), uint64(1)}},
		// the production default once a reader is present; see the matrix above
		{"g_traces_ctx_v1_enabled", []any{true}},
	})

	// The full matrices above pin g_traces_ctx_v1_enabled on, so the gated
	// obi_ctx writers stay verified against every other constant. This covers
	// the off path, where they compile away, without doubling either matrix.
	forEachCombination(t, "generictracer/BpfTracesCtxOff", generictracerbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"g_bpf_traceparent_enabled", []any{true, false}},
		{"http_max_captured_bytes", []any{uint32(262144)}},
		{"tcp_max_captured_bytes", []any{uint32(65536)}},
		{"g_traces_ctx_v1_enabled", []any{false}},
	})

	// gotracer
	forEachCombination(t, "gotracer/Bpf", gotracerbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"g_bpf_traceparent_enabled", []any{true, false}},
		{"g_bpf_header_propagation", []any{true, false}},
		{"g_bpf_probe_write_user_enabled", []any{true}},
		{"g_bpf_loop_enabled", []any{ebpfcommon.SupportsEBPFLoops(slog.Default(), false)}},
		{"capture_header_buffer", []any{int32(0), int32(1)}},
		{"high_request_volume", []any{uint32(0), uint32(1)}},
		{"max_transaction_time", []any{uint64(0), uint64(60_000_000_000)}},
		{"http_max_captured_bytes", []any{uint32(0), uint32(262144)}},
		{"tcp_max_captured_bytes", []any{uint32(0), uint32(65536)}},
		// pinned on, not paired: see the generictracer matrix above
		{"g_traces_ctx_v1_enabled", []any{true}},
	})
	forEachCombination(t, "gotracer/BpfTracesCtxOff", gotracerbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"g_bpf_traceparent_enabled", []any{true}},
		{"g_bpf_header_propagation", []any{true, false}},
		{"g_bpf_probe_write_user_enabled", []any{true}},
		{"g_bpf_loop_enabled", []any{ebpfcommon.SupportsEBPFLoops(slog.Default(), false)}},
		{"capture_header_buffer", []any{int32(1)}},
		{"http_max_captured_bytes", []any{uint32(262144)}},
		{"tcp_max_captured_bytes", []any{uint32(65536)}},
		{"g_traces_ctx_v1_enabled", []any{false}},
	})
	loadAndVerify(t, "gotracer/Bpf/no-write-user", gotracerbpf.LoadBpf, map[string]any{
		"g_bpf_header_propagation":       true,
		"g_bpf_probe_write_user_enabled": false,
	})

	// tpinjector
	// inject_flags is a bitmask: bit 0 = HTTP headers, bit 1 = TCP options.
	forEachCombination(t, "tpinjector/Bpf", tpinjectorbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"filter_pids", []any{int32(0), int32(1)}},
		{"inject_flags", []any{uint32(0), uint32(1), uint32(2), uint32(3)}},
		{"max_transaction_time", []any{uint64(0), uint64(60_000_000_000)}},
	})
	// tpinjector/BpfIter needs bpf_iter_tcp_get_func_proto (kernel >= 5.11)
	// for the verifier to recognize the sock_iter ctx type. Runtime loader
	// has a separate >= 6.4 gate (RCU stall) enforced in tpinjector.Iters.
	if major, minor := ebpfcommon.KernelVersion(); major > 5 || (major == 5 && minor >= 11) {
		forEachCombination(t, "tpinjector/BpfIter", tpinjectorbpf.LoadBpfIter, []constOption{
			{"g_bpf_debug", []any{true, false}},
		})
	} else {
		t.Logf("skipping tpinjector/BpfIter: kernel %d.%d < 5.11", major, minor)
	}

	// tpinjector/BpfFionreadFixup uses bpf_probe_write_user, rejected at load time
	// under kernel lockdown - none of the CI kernels run locked down
	forEachCombination(t, "tpinjector/BpfFionreadFixup", tpinjectorbpf.LoadBpfFionreadFixup, []constOption{
		{"g_bpf_debug", []any{true, false}},
	})

	// watcher
	forEachCombination(t, "watcher/Bpf", watcherbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
	})

	// gpuevent
	forEachCombination(t, "gpuevent/Bpf", gpueventbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"filter_pids", []any{int32(0), int32(1)}},
	})

	// logger
	forEachCombination(t, "logger/Bpf", loggerbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
	})

	// logenricher
	forEachCombination(t, "logenricher/Bpf", logenricherbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
	})

	// rdns xdp
	forEachCombination(t, "rdns/xdp/Bpf", rdnsxdpbpf.LoadBpf, []constOption{
		{"g_bpf_debug", []any{true, false}},
	})

	// statsolly
	forEachCombination(t, "statsolly/Stats", statsolly.LoadStats, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"stats_wakeup_data_bytes", []any{uint32(0), uint32(1 << 20)}},
		{"blk_want_queue_depth", []any{uint8(0), uint8(1)}},
		{"blk_emit_kinds", []any{uint8(0), uint8(0x0f)}},
		// Step 16: with it on, the issue programs read rq->rq_flags and
		// rq->start_time_ns and CO-RE-resolve enum rqf_flags.
		{"blk_want_queue", []any{uint8(0), uint8(1)}},
		// Step 13: with it on, the issue programs CO-RE-read bio->bi_bdev
		// and rq->part (guarded by bpf_core_field_exists), so this exercises
		// those relocations against this kernel's BTF.
		{"blk_want_part", []any{uint8(0), uint8(1)}},
	})
	// Kernel aggregation: the completion counts into the per-CPU maps in
	// either histogram layout instead of the ring buffer. The queue depth,
	// which forces the ring buffer, stays off.
	forEachCombination(t, "statsolly/StatsAgg", statsolly.LoadStats, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"blk_emit_kinds", []any{uint8(0x0f)}},
		{"blk_want_queue", []any{uint8(0), uint8(1)}},
		{"blk_want_part", []any{uint8(0), uint8(1)}},
		{"blk_emit_mode", []any{uint8(1)}},
		{"blk_hist_exp", []any{uint8(0), uint8(1)}},
	})
	// Step 20: the bio programs of stacked volumes, an object of their own.
	// tp_btf and raw_tp are loaded together, in the variant this kernel's
	// block_bio_queue prototype takes, in both emit modes and both histogram
	// layouts; blk_want_part adds the read of the bio's block_device dev_t.
	forEachCombination(t, "statsolly/BlkBio", statsolly.LoadBlkBio, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"blk_want_queue_depth", []any{uint8(0), uint8(1)}},
		{"blk_emit_kinds", []any{uint8(0), uint8(0x0f)}},
		{"blk_want_part", []any{uint8(0), uint8(1)}},
	})
	forEachCombination(t, "statsolly/BlkBioAgg", statsolly.LoadBlkBio, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"blk_emit_kinds", []any{uint8(0x0f)}},
		{"blk_want_part", []any{uint8(0), uint8(1)}},
		{"blk_emit_mode", []any{uint8(1)}},
		{"blk_hist_exp", []any{uint8(0), uint8(1)}},
	})
	// Step 21: storage_block_pod reads the blkcg chain at the issue of a
	// read or write (rq->bio) and at the queueing of a bio, and counts the
	// completion in blk_cg_agg, in both emit modes. The request issue also
	// reads the accounting start for operation_time, with queue.duration on
	// or off.
	forEachCombination(t, "statsolly/StatsPod", statsolly.LoadStats, []constOption{
		{"blk_want_cgroup", []any{uint8(1)}},
		{"blk_emit_kinds", []any{uint8(0), uint8(0x0f)}},
		{"blk_want_queue", []any{uint8(0), uint8(1)}},
		{"blk_want_part", []any{uint8(0), uint8(1)}},
		{"blk_emit_mode", []any{uint8(0), uint8(1)}},
	})
	forEachCombination(t, "statsolly/BlkBioPod", statsolly.LoadBlkBio, []constOption{
		{"blk_want_cgroup", []any{uint8(1)}},
		{"blk_emit_kinds", []any{uint8(0), uint8(0x0f)}},
		{"blk_want_part", []any{uint8(0), uint8(1)}},
		{"blk_emit_mode", []any{uint8(0), uint8(1)}},
	})
	forEachCombination(t, "statsolly/FsIo", statsolly.LoadFsIo, []constOption{
		{"g_bpf_debug", []any{true, false}},
		{"stats_wakeup_data_bytes", []any{uint32(0), uint32(1 << 20)}},
	})
	forEachCombination(t, "statsolly/NfsRpc", statsolly.LoadNfsRpc, []constOption{
		{"nfs_want_status", []any{uint8(0), uint8(1)}},
		{"nfs_hist_exp", []any{uint8(0), uint8(1)}},
		{"nfs_key_owner", []any{uint8(0), uint8(1)}},
		{"nfs_cgroup_v1", []any{uint8(0), uint8(1)}},
	})
	// Kernel aggregation (explicit and exponential layouts) against the ring
	// buffer, each with the fentry/fexit starts in task storage or in the
	// fs_start hash map.
	forEachCombination(t, "statsolly/FsIoAgg", statsolly.LoadFsIo, []constOption{
		{"fs_emit_mode", []any{uint8(0), uint8(1)}},
		{"fs_hist_exp", []any{uint8(0), uint8(1)}},
		{"fs_task_btf", []any{uint8(0), uint8(1)}},
	})
}

// TestBPFVerifierBlockWithoutBlkCgroup loads the block request and bio
// objects with storage_block_pod on against this kernel's BTF minus
// bio.bi_blkg, as on a kernel built without CONFIG_BLK_CGROUP: the blkcg
// chain is read only behind bpf_core_field_exists(bio->bi_blkg), so its
// relocations, which cannot be resolved there, must be dead code rather than
// an invalid instruction that rejects every block program (v2 commit
// b1dfc046f).
func TestBPFVerifierBlockWithoutBlkCgroup(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock limit (insufficient privileges?): %v", err)
	}
	kernel, err := btfCache.Kernel()
	require.NoError(t, err)
	types := kernel.Copy()
	var bio *btf.Struct
	require.NoError(t, types.TypeByName("bio", &bio))
	before := len(bio.Members)
	bio.Members = slices.DeleteFunc(slices.Clone(bio.Members), func(m btf.Member) bool { return m.Name == "bi_blkg" })
	require.Len(t, bio.Members, before-1, "this kernel's struct bio has bi_blkg to remove")

	for _, obj := range []struct {
		name string
		load func() (*ebpf.CollectionSpec, error)
	}{
		{"Stats", statsolly.LoadStats},
		{"BlkBio", statsolly.LoadBlkBio},
	} {
		for _, mode := range []uint8{0, 1} {
			t.Run(fmt.Sprintf("%s/blk_emit_mode=%d", obj.name, mode), func(t *testing.T) {
				spec := cachedSpec(t, obj.load)
				require.NoError(t, statsolly.PrepareStorageSpec(spec))
				require.NoError(t, ebpfconvenience.RewriteConstants(spec, map[string]any{
					"blk_want_cgroup": uint8(1),
					"blk_emit_kinds":  uint8(0x0f),
					"blk_emit_mode":   mode,
				}))
				for _, m := range spec.Maps {
					m.Pinning = ebpf.PinNone
					switch {
					case m.MaxEntries != 0:
					case m.Type == ebpf.RingBuf:
						m.MaxEntries = uint32(os.Getpagesize())
					case m.Type != ebpf.TaskStorage:
						m.MaxEntries = 1
					}
				}
				coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
					Programs: ebpf.ProgramOptions{KernelTypes: types, LogSizeStart: 10 * 1024 * 1024},
					Cache:    btfCache,
				})
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					t.Fatalf("BPF verifier rejected program(s) without bio.bi_blkg:\n%+v", ve)
				}
				require.NoError(t, err)
				coll.Close()
			})
		}
	}
}
