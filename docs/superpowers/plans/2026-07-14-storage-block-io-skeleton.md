# Storage Block I/O Latency — Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit a per-device **block I/O service-latency histogram** (`system.disk.io.latency`, experimental) end-to-end through OBI's existing **StatsO11y** pipeline — proving the "no new pipeline" seam and the histogram model before broadening to VFS/size/errors/queue-depth.

**Architecture:** Extend `statsolly` (NOT a new pipeline, per OBI issue #2453). A new eBPF program on the `block:block_rq_issue`/`block:block_rq_complete` tracepoints times each request by `(dev, sector)` and emits **one ringbuf event per completion** into the existing `stats_events` ring buffer, tagged with a new `flags` discriminator. Userspace decodes it into the existing `ebpf.Stat` record and the existing `statMetricsExporter` records it into an OTel `Float64Histogram` — the **same per-event → OTel-SDK-aggregates model statsolly already uses for TCP RTT**. This is OTLP-native (re-aggregatable exponential histograms, per the v2 proposal) and deliberately does **not** port the POC's in-kernel histogram maps; block-completion frequency is low enough that per-event is cheap, and the overhead is a measured gate (Task 10), with in-kernel aggregation held as the documented fallback if that gate fails.

**Tech Stack:** eBPF C (libbpf/CO-RE, bpf2go), Go 1.25+, cilium/ebpf, OpenTelemetry Go SDK, OBI `swarm` pipeline + `msg.Queue` primitives.

## Global Constraints

- Module `go.opentelemetry.io/obi`; work on branch `feat/storage-io-metrics` (already created).
- Kernel floor **5.8 + BTF** (RHEL8/4.18 backport). Block tracepoints `block_rq_issue`/`block_rq_complete` exist on all supported kernels. Do NOT use helpers unavailable at the floor.
- Generated files `*_bpfel.go`/`*_bpfel.o` are produced by `make generate` (bpf2go) and committed; NEVER hand-edit them or anything in `bpf/bpfcore/`.
- eBPF C rules (AGENTS.md): maps default `OBI_PIN_INTERNAL`; `SCRATCH_MEM*` for scratch buffers; `const` correctness; narrowest unsigned int types; enums over macros; `bpf_probe_read_kernel` for kernel memory; buffers are `unsigned char *`; no magic numbers. C must pass `make clang-format` + `make clang-tidy`.
- Validation targets: `make generate` (after any `bpf/*.c` change), `make compile`, `make test`, `make lint`. Full: `make verify`.
- Experimental metric name: ship as `system.disk.io.latency` now; a semconv PR runs in parallel and the final name is renamed on landing. Unit: seconds (`s`).
- Byte-match invariant: any Go wire struct that `ReinterpretCast`s a ringbuf sample MUST byte-match the C struct (field order + padding + `structs.HostLayout`).

---

### Task 1: eBPF — block I/O service-latency program

**Files:**
- Create: `bpf/statsolly/blk_io.c`
- Create: `bpf/statsolly/maps/blk_start.h`
- Modify: `bpf/statsolly/stats.c` (add `#include <statsolly/blk_io.c>`-style include OR add blk_io.c to the compiled unit — follow how `k_tcp.c`/`tp_tcp.c` are pulled into `stats.c`)
- Modify: `bpf/statsolly/types.h` (add `block_io_t` struct + `k_event_stat_block_io` enum value)
- Modify: `pkg/internal/statsolly/ebpf/stats_tracer.go:62` (bpf2go `//go:generate` line — add `-type block_io_t`)

**Interfaces:**
- Produces (C→Go via bpf2go): a generated `StatsBlockIoT` struct and, after attach wiring (Task 6), programs `ObiStatsTpBlockRqIssue` / `ObiStatsTpBlockRqComplete` on `StatsObjects`.
- Produces (wire contract for Task 2/3): event layout `{ u8 flags; u8 op; u8 _pad[2]; u32 dev; u64 latency_ns; u64 bytes; }`.

- [ ] **Step 1: Add the event struct + enum to `bpf/statsolly/types.h`**

Add near the other `k_event_stat_*` values and typedefs:

```c
enum stat_event_type {
    // ... existing values ...
    k_event_stat_block_io = 5, // keep in sync with StatTypeBlockIo in stat.go
};

typedef struct block_io {
    unsigned char flags;   // must be first: ring buffer event discriminator
    unsigned char op;      // 0=read, 1=write (from rwbs[0])
    unsigned char _pad[2];
    __u32 dev;             // kernel dev_t (major<<20 | minor)
    __u64 latency_ns;      // issue -> complete
    __u64 bytes;           // nr_sector * 512
} block_io_t;

const block_io_t *unused_block_io __attribute__((unused));
```

- [ ] **Step 2: Add the scratch map `bpf/statsolly/maps/blk_start.h`**

```c
#pragma once
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <common/pin_internal.h>

struct blk_rq_key {
    __u32 dev;
    __u64 sector;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct blk_rq_key);
    __type(value, __u64); // issue timestamp (ns)
    __uint(pinning, OBI_PIN_INTERNAL);
} blk_start SEC(".maps");
```

- [ ] **Step 3: Write `bpf/statsolly/blk_io.c`**

```c
//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <logger/bpf_dbg.h>
#include <statsolly/types.h>
#include <statsolly/maps/stats_events.h>
#include <statsolly/maps/blk_start.h>

static __always_inline unsigned char blk_op_from_rwbs(const char rwbs[8]) {
    // rwbs[0] == 'W' or 'F' (flush) => write; else read.
    return (rwbs[0] == 'W' || rwbs[0] == 'F') ? 1 : 0;
}

SEC("tracepoint/block/block_rq_issue")
int obi_stats_tp_block_rq_issue(struct trace_event_raw_block_rq *ctx) {
    struct blk_rq_key key = {};
    key.dev = BPF_CORE_READ(ctx, dev);
    key.sector = BPF_CORE_READ(ctx, sector);
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&blk_start, &key, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int obi_stats_tp_block_rq_complete(struct trace_event_raw_block_rq_completion *ctx) {
    struct blk_rq_key key = {};
    key.dev = BPF_CORE_READ(ctx, dev);
    key.sector = BPF_CORE_READ(ctx, sector);

    __u64 *issue_ns = bpf_map_lookup_elem(&blk_start, &key);
    if (!issue_ns) {
        return 0; // no matching issue seen; skip
    }
    __u64 latency = bpf_ktime_get_ns() - *issue_ns;
    bpf_map_delete_elem(&blk_start, &key);

    __u32 nr_sector = BPF_CORE_READ(ctx, nr_sector);
    char rwbs[8];
    bpf_probe_read_kernel(&rwbs, sizeof(rwbs), &ctx->rwbs);

    block_io_t *e = bpf_ringbuf_reserve(&stats_events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->flags = k_event_stat_block_io;
    e->op = blk_op_from_rwbs(rwbs);
    e->_pad[0] = 0; e->_pad[1] = 0;
    e->dev = key.dev;
    e->latency_ns = latency;
    e->bytes = (__u64)nr_sector * 512;
    bpf_ringbuf_submit(e, stats_events_flags());
    return 0;
}
```

> NOTE: confirm the tracepoint context type names (`trace_event_raw_block_rq`, `trace_event_raw_block_rq_completion`) against `bpf/bpfcore/vmlinux.h` on this kernel; if `block_rq_complete` lacks `sector`, fall back to keying complete by `dev` only and document the coarsening. Follow whatever `#include` mechanism `stats.c` uses for `k_tcp.c` to pull `blk_io.c` into the compiled object.

- [ ] **Step 4: Add `-type block_io_t` to the bpf2go directive**

Modify the `//go:generate` line in `pkg/internal/statsolly/ebpf/stats_tracer.go:62`, appending `-type block_io_t` alongside the existing `-type` flags.

- [ ] **Step 5: Generate + compile**

Run: `make generate && make compile`
Expected: PASS; `StatsBlockIoT` appears in the generated `Stats_bpfel.go`; `blk_start` and the two block programs appear on `StatsMaps`/`StatsPrograms`.

- [ ] **Step 6: Format + commit**

```bash
make clang-format clang-tidy
git add bpf/statsolly/ pkg/internal/statsolly/ebpf/
git commit -m "feat(storage): eBPF block_rq service-latency program in statsolly"
```

---

### Task 2: Go record types for block I/O

**Files:**
- Modify: `pkg/internal/statsolly/ebpf/stat.go`

**Interfaces:**
- Consumes: generated `StatsBlockIoT` (Task 1).
- Produces: `ebpf.StatTypeBlockIo StatType`; `Stat.BlockIo *BlockIo`; `BlockIo{Dev uint32; Op uint8; LatencyNs uint64; Bytes uint64}`; wire struct `StatsBlockIo`.

- [ ] **Step 1: Add the StatType, record field, and structs**

In `stat.go`, add to the `StatType` const block: `StatTypeBlockIo` (value 5). Add `BlockIo *BlockIo` to `Stat`. Add:

```go
type BlockIo struct {
    Dev       uint32 `json:"dev"`
    Op        uint8  `json:"op"`
    LatencyNs uint64 `json:"latency_ns"`
    Bytes     uint64 `json:"bytes"`
}

// StatsBlockIo mirrors block_io_t in bpf/statsolly/types.h.
type StatsBlockIo struct {
    _         structs.HostLayout
    Flags     uint8
    Op        uint8
    Pad       [2]uint8
    Dev       uint32
    LatencyNs uint64
    Bytes     uint64
}

// BlockIo operation codes (mirror blk_op_from_rwbs in bpf/statsolly/blk_io.c).
const (
    BlockOpRead  uint8 = 0
    BlockOpWrite uint8 = 1
)
```

- [ ] **Step 2: Compile**

Run: `go build ./pkg/internal/statsolly/...`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add pkg/internal/statsolly/ebpf/stat.go
git commit -m "feat(storage): BlockIo stat record types"
```

---

### Task 3: Ring buffer decode for block I/O

**Files:**
- Modify: `pkg/internal/statsolly/stats/tracer_ringbuf.go`
- Test: `pkg/internal/statsolly/stats/tracer_ringbuf_block_test.go`

**Interfaces:**
- Consumes: `ebpf.StatsBlockIo`, `ebpf.StatTypeBlockIo`, `ebpf.BlockIo` (Task 2); `ebpfcommon.ReinterpretCast` (existing).
- Produces: `readBlockIoIntoStat(record *ringbuf.Record) (ebpf.Stat, error)`.

- [ ] **Step 1: Write the failing test**

```go
package stats

import (
    "testing"
    "unsafe"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
    "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
)

func TestReadBlockIoIntoStat(t *testing.T) {
    ev := ebpf.StatsBlockIo{Flags: 5, Op: ebpf.BlockOpWrite, Dev: 0x800010, LatencyNs: 1_500_000, Bytes: 4096}
    raw := (*[unsafe.Sizeof(ev)]byte)(unsafe.Pointer(&ev))[:]

    stat, err := readBlockIoIntoStat(&ringbuf.Record{RawSample: raw})
    require.NoError(t, err)
    require.NotNil(t, stat.BlockIo)
    assert.Equal(t, ebpf.StatTypeBlockIo, stat.Type)
    assert.Equal(t, uint32(0x800010), stat.BlockIo.Dev)
    assert.Equal(t, ebpf.BlockOpWrite, stat.BlockIo.Op)
    assert.Equal(t, uint64(1_500_000), stat.BlockIo.LatencyNs)
    assert.Equal(t, uint64(4096), stat.BlockIo.Bytes)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/internal/statsolly/stats/ -run TestReadBlockIoIntoStat -v`
Expected: FAIL (`readBlockIoIntoStat` undefined).

- [ ] **Step 3: Add the decode case + reader**

In `handleStatEvent`'s switch add: `case ebpf.StatTypeBlockIo: return readBlockIoIntoStat(record)`. Add:

```go
func readBlockIoIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
    event, err := ebpfcommon.ReinterpretCast[ebpf.StatsBlockIo](record.RawSample)
    if err != nil {
        return ebpf.Stat{}, err
    }
    return ebpf.Stat{
        Type: ebpf.StatTypeBlockIo,
        BlockIo: &ebpf.BlockIo{
            Dev:       event.Dev,
            Op:        event.Op,
            LatencyNs: event.LatencyNs,
            Bytes:     event.Bytes,
        },
    }, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/internal/statsolly/stats/ -run TestReadBlockIoIntoStat -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/internal/statsolly/stats/
git commit -m "feat(storage): decode block_io ringbuf events"
```

---

### Task 4: Attribute names, getters, and metric definition

**Files:**
- Modify: `pkg/export/attributes/names/attrs.go` (add attribute names + the `StatDiskIOLatency` metric name — mirror where `StatTCPRtt` name is declared; grep for `StatTCPRtt =`)
- Modify: `pkg/internal/statsolly/ebpf/stat_getters.go`
- Modify: `pkg/export/attributes/attr_defs.go` (add the `StatDiskIOLatency.Section` block + a `statsDiskAttributes` report group)
- Test: `pkg/internal/statsolly/ebpf/stat_getters_block_test.go`

**Interfaces:**
- Consumes: `ebpf.Stat.BlockIo` (Task 2).
- Produces: attr names `attr.DiskDevice` (`system.device`), `attr.DiskIOOperation` (`disk.io.operation`); metric `attributes.StatDiskIOLatency` (OTEL `system.disk.io.latency`, Prom `system_disk_io_latency_seconds`); getters for both attrs.

- [ ] **Step 1: Write the failing getter test**

```go
package ebpf

import (
    "testing"

    "github.com/stretchr/testify/assert"

    attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestBlockIoGetters(t *testing.T) {
    s := &Stat{Type: StatTypeBlockIo, BlockIo: &BlockIo{Dev: 0x800010, Op: BlockOpWrite}}

    devGetter, ok := StatGetters(attr.DiskDevice)
    assert.True(t, ok)
    assert.Equal(t, "8:16", devGetter(s).Value.Emit())

    opGetter, ok := StatGetters(attr.DiskIOOperation)
    assert.True(t, ok)
    assert.Equal(t, "write", opGetter(s).Value.Emit())
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pkg/internal/statsolly/ebpf/ -run TestBlockIoGetters -v`
Expected: FAIL (`attr.DiskDevice` undefined).

- [ ] **Step 3: Add attribute names + metric name**

In `pkg/export/attributes/names/attrs.go`, add (mirror existing `Name` declarations):

```go
DiskDevice       = Name("system.device")
DiskIOOperation  = Name("disk.io.operation")
```

Add the metric-name declaration next to `StatTCPRtt` (mirror its exact construction — it has `.Section`/`.OTEL`/`.Prom`):

```go
StatDiskIOLatency = // same constructor as StatTCPRtt, with:
    // OTEL: "system.disk.io.latency", Prom: "system_disk_io_latency_seconds"
```

- [ ] **Step 4: Add the getters**

In `stat_getters.go`'s `switch name`, add:

```go
case attr.DiskDevice:
    getter = func(s *Stat) attribute.KeyValue {
        var dev uint32
        if s.BlockIo != nil {
            dev = s.BlockIo.Dev
        }
        return attribute.String(string(attr.DiskDevice), fmtDev(dev))
    }
case attr.DiskIOOperation:
    getter = func(s *Stat) attribute.KeyValue {
        op := "read"
        if s.BlockIo != nil && s.BlockIo.Op == BlockOpWrite {
            op = "write"
        }
        return attribute.String(string(attr.DiskIOOperation), op)
    }
```

Add the helper (dev_t major/minor decode, Linux `MAJOR=dev>>20`, `MINOR=dev&0xFFFFF`):

```go
func fmtDev(dev uint32) string {
    return fmt.Sprintf("%d:%d", dev>>20, dev&0xFFFFF)
}
```

(add `"fmt"` import).

- [ ] **Step 5: Register the metric's attribute group in `attr_defs.go`**

Add a report group near `statsAttributes` and a section entry beside `StatTCPRtt.Section`:

```go
var statsDiskAttributes = AttrReportGroup{
    Attributes: map[attr.Name]Default{
        attr.DiskDevice:      true,
        attr.DiskIOOperation: true,
    },
}
// ... in the getDefinitions map:
StatDiskIOLatency.Section: {
    SubGroups:  []*AttrReportGroup{&statsDiskAttributes},
    Attributes: map[attr.Name]Default{},
},
```

- [ ] **Step 6: Run to verify it passes**

Run: `go test ./pkg/internal/statsolly/ebpf/ -run TestBlockIoGetters -v && go build ./...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/export/attributes/ pkg/internal/statsolly/ebpf/stat_getters.go
git commit -m "feat(storage): disk.device/disk.io.operation attrs + latency metric def"
```

---

### Task 5: Feature flag `storage_block`

**Files:**
- Modify: `pkg/export/feature.go`
- Modify: `pkg/obi/config.go` (set the bit; mirror the `network` handling at ~L869)
- Test: `pkg/export/feature_test.go`

**Interfaces:**
- Produces: `export.FeatureStorageBlock`; mapper keys `"storage"`, `"storage_block"`; accessor `Features.StorageBlock() bool`; `StorageBlock` included in `Features.StatMetrics()` so the stats pipeline/exporter activate.

- [ ] **Step 1: Write the failing test**

```go
func TestStorageBlockFeatureParsing(t *testing.T) {
    var f Features
    require.NoError(t, yaml.Unmarshal([]byte(`["storage_block"]`), &f))
    assert.True(t, f.StorageBlock())
    assert.True(t, f.StatMetrics()) // storage rides the stats pipeline
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pkg/export/ -run TestStorageBlockFeatureParsing -v`
Expected: FAIL (`StorageBlock` undefined).

- [ ] **Step 3: Add the feature bit, mapping, accessor**

In `feature.go`: add `FeatureStorageBlock` to the `iota` const block; add mapper entries `"storage": FeatureStorageBlock` and `"storage_block": FeatureStorageBlock`; add:

```go
func (f Features) StorageBlock() bool { return f.any(FeatureStorageBlock) }
```

Find the existing `StatMetrics()` method and OR `FeatureStorageBlock` into its mask so the stats pipeline turns on for storage.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./pkg/export/ -run TestStorageBlockFeatureParsing -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/export/feature.go pkg/export/feature_test.go pkg/obi/config.go
git commit -m "feat(storage): storage_block metrics feature flag"
```

---

### Task 6: Attach the block tracepoints in the loader

**Files:**
- Modify: `pkg/internal/statsolly/ebpf/stats_tracer.go`

**Interfaces:**
- Consumes: `features.StorageBlock()` (Task 5); generated programs `ObiStatsTpBlockRqIssue`/`ObiStatsTpBlockRqComplete` (Task 1).

- [ ] **Step 1: Add the programs to `fixupSpec` disable list when off**

In the `toDisable` assembly, add (mirroring the TCP blocks): when `!features.StorageBlock()`, append the two block program names.

- [ ] **Step 2: Attach the tracepoints when on**

Add a tracepoint attach block mirroring the existing `link.Tracepoint` loop:

```go
for _, t := range []probe{
    {name: "block/block_rq_issue", program: objects.ObiStatsTpBlockRqIssue, enabled: features.StorageBlock()},
    {name: "block/block_rq_complete", program: objects.ObiStatsTpBlockRqComplete, enabled: features.StorageBlock()},
} {
    if !t.enabled {
        continue
    }
    group, tp, _ := strings.Cut(t.name, "/")
    l, err := link.Tracepoint(group, tp, t.program, nil)
    if err != nil {
        closeAll(closables)
        return nil, fmt.Errorf("failed tracepoint attachment %s: %w", t.name, err)
    }
    closables = append(closables, l)
}
```

- [ ] **Step 3: Compile**

Run: `make compile`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add pkg/internal/statsolly/ebpf/stats_tracer.go
git commit -m "feat(storage): attach block_rq tracepoints on storage_block"
```

---

### Task 7: OTel exporter — record the histogram

**Files:**
- Modify: `pkg/export/otel/metrics_stats.go`
- Test: `pkg/export/otel/metrics_stats_test.go`

**Interfaces:**
- Consumes: `attributes.StatDiskIOLatency` (Task 4), `features.StorageBlock()` (Task 5), `ebpf.Stat.BlockIo` (Task 2).
- Produces: `statMetricsExporter.diskIOLatency` histogram, created + recorded when `StorageBlock()`.

- [ ] **Step 1: Write the failing exporter test**

Mirror the existing block(s) in `metrics_stats_test.go`: feed a `[]*ebpf.Stat{{Type: StatTypeBlockIo, BlockIo: &ebpf.BlockIo{Dev: 0x800010, Op: 1, LatencyNs: 2_000_000, Bytes: 4096}}}` through an exporter built with `Features` = `FeatureStorageBlock`, and assert one `system.disk.io.latency` histogram data point with value `0.002` and attributes `system.device="8:16"`, `disk.io.operation="write"` (use the same in-memory manual reader the existing tests use).

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pkg/export/otel/ -run TestStat -v`
Expected: FAIL (no disk metric emitted).

- [ ] **Step 3: Add the histogram field, creation, view, and Do() recording**

Add `diskIOLatency *Expirer[*ebpf.Stat, metric2.Float64Histogram, float64]` to `statMetricsExporter`. In `newStatMetricsExporter`, after the TCP blocks:

```go
if cfg.CommonCfg.Features.StorageBlock() {
    log := log.With("metricFamily", "StorageBlock")
    h, err := ebpfEvents.Float64Histogram(attributes.StatDiskIOLatency.OTEL, metric2.WithUnit("s"))
    if err != nil {
        log.Error("creating disk io latency histogram", "error", err)
        return nil, err
    }
    attrs := attributes.OpenTelemetryGetters(ebpf.StatGetters, attrProv.For(attributes.StatDiskIOLatency))
    nme.diskIOLatency = NewExpirer[*ebpf.Stat, metric2.Float64Histogram, float64](ctx, h, attrs, timeNow, cfg.Metrics.TTL)
}
```

In `newStatMeterProvider`, add a `metric.WithView(statHistogramView(attributes.StatDiskIOLatency.OTEL, cfg.Buckets.StatTCPRttHistogram, isExponential, cfg.ExponentialHistogram))` (reuse the RTT bucket config for now; a dedicated `DiskIOLatencyHistogram` bucket knob is a follow-up).

In `Do()`:

```go
if me.diskIOLatency != nil && v.BlockIo != nil {
    h, attrs := me.diskIOLatency.ForRecord(v)
    h.Record(ctx, float64(v.BlockIo.LatencyNs)/1_000_000_000.0, metric2.WithAttributeSet(attrs))
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./pkg/export/otel/ -run TestStat -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/export/otel/metrics_stats.go pkg/export/otel/metrics_stats_test.go
git commit -m "feat(storage): OTel disk.io.latency histogram exporter"
```

---

### Task 8: Prometheus exporter — mirror the histogram

**Files:**
- Modify: `pkg/export/prom/prom_stats.go`
- Test: `pkg/export/prom/prom_stats_test.go` (if present; else add)

**Interfaces:**
- Consumes: same as Task 7.
- Produces: Prometheus histogram `system_disk_io_latency_seconds` gated on `StorageBlock()`.

- [ ] **Step 1: Read `prom_stats.go` and locate the TCP RTT histogram registration/record path.** Mirror it exactly for `StatDiskIOLatency`: register a histogram collector when `StorageBlock()`, and in the record loop, when `v.BlockIo != nil`, observe `float64(v.BlockIo.LatencyNs)/1e9` with the `system.device`/`disk.io.operation` labels from the same getters.

- [ ] **Step 2: Compile + test**

Run: `go test ./pkg/export/prom/ -v && make compile`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add pkg/export/prom/
git commit -m "feat(storage): Prometheus disk.io.latency histogram exporter"
```

---

### Task 9: Full build + lint gate

- [ ] **Step 1:** Run `make verify` — Expected: PASS (generate clean, compile, lint, tests).
- [ ] **Step 2:** Run `make test` — Expected: all statsolly + export tests green.
- [ ] **Step 3: Commit** any generation/format deltas:

```bash
git add -A && git commit -m "chore(storage): regenerate + verify block skeleton"
```

---

### Task 10: Overhead + run-and-observe gate (requires root; environment-limited)

> This task needs root + a real block device + `fio`. If unavailable in the current environment, document the exact commands + expected signatures for the operator to run, and mark the metrics-path unit tests (Tasks 3,4,7) as the CI-level guarantee.

- [ ] **Step 1:** Build and run: `sudo ./bin/obi` with `OTEL_EBPF_METRICS_FEATURES=storage_block` and a Prometheus endpoint enabled.
- [ ] **Step 2:** Drive load: `fio --name=randwrite --rw=randwrite --bs=4k --iodepth=16 --numjobs=4 --runtime=60 --direct=1 --filename=/dev/<testdev>`.
- [ ] **Step 3:** Confirm `system_disk_io_latency_seconds` histogram populates per `system.device`/`disk.io.operation`; verify against `biolatency`/`iostat` within tolerance.
- [ ] **Step 4:** Overhead A/B: measure agent CPU% with feature on vs off at fixed IOPS; record in the overhead table. **Gate:** < ~1% agent CPU. If it fails, open the fallback (in-kernel per-CPU histogram + map-poll) as a follow-up plan.

---

## Self-Review

- **Spec coverage:** Delivers the block-layer service-latency slice of Milestone M1 (§B, STORAGE-OBI-WORK-SUMMARY.md) via the "no new pipeline / extend StatsO11y" architecture (decision #8). VFS, three-phase (queue), size, errors, queue-depth are explicitly out of this skeleton and are follow-up plans that reuse Tasks 2–8's seams.
- **Placeholder scan:** Task 4 Step 3 (`StatDiskIOLatency` constructor) and Tasks 8/10 intentionally reference "mirror the exact existing pattern at <file>" because the precise constructor/registration idiom must be copied verbatim from the neighbouring TCP metric in the same file — the implementer reads that file. All novel code (eBPF, structs, decode, getters, Do()) is shown in full.
- **Type consistency:** `BlockIo{Dev,Op,LatencyNs,Bytes}`, `StatsBlockIo` wire struct, `StatTypeBlockIo`, `FeatureStorageBlock`, `StorageBlock()`, `StatDiskIOLatency`, `attr.DiskDevice`/`attr.DiskIOOperation`, `readBlockIoIntoStat`, `fmtDev` — used consistently across Tasks 1–8.
- **Open confirmations for the implementer:** (1) block tracepoint context struct names on this kernel; (2) whether `block_rq_complete` carries `sector`; (3) exact `StatDiskIOLatency` name constructor + prom registration idiom. All are "read the neighbouring code" confirmations, not design gaps.
