# Storage I/O Metrics Catalog — the target end-state

**Date:** 2026-07-14
**Status:** Authoritative goal reference for the OBI storage subsystem build.
**Scope:** Every metric, attribute, and instrument the feature will emit, across all milestones.
This is the "goal in sight" — individual plans implement slices of it; this file is the whole.

## Conventions used here

- **Instrument** = the OpenTelemetry instrument kind that carries the metric:
  - **Histogram** — distribution; exported as an OTLP **exponential histogram** so it re-aggregates
    across pods/time and percentiles are computed at query time (`histogram_quantile`). Preferred
    over precomputed-percentile gauges (a Prometheus-summary idiom that cannot re-aggregate).
  - **Counter** — monotonic; the backend takes `rate()` for per-second views (IOPS, throughput).
  - **UpDownCounter** — can go up and down (capacity used/free).
  - **Gauge** — point-in-time sample (queue depth, utilization ratio).
- **Layer** = `vfs` (per-pod, app-observed, sees network filesystems) or `block` (per-device, what
  the hardware delivers). See the block-vs-network-FS rule in `storage-types-on-k8s.md`.
- **Names** ship under **experimental** OTel-semconv-aligned names now; a semconv PR runs in
  parallel and final names are renamed on landing. Prometheus form is the snake_case translation
  (dots→underscores, unit suffix, `_bucket`/`_sum`/`_count` for histograms, `_total` for counters).
- **Milestone**: `M1` core (incl. size + errors), `M2` capacity, `M3` k8s volume topology,
  `M-last` outlier spans, `future` = deferred (page/dentry cache, biopattern).

---

## 1. LATENCY — the headline signal

### 1.1 `system.disk.io.latency`
- **Instrument:** Histogram · **Unit:** seconds (`s`)
- **Prometheus:** `system_disk_io_latency_seconds_bucket|_sum|_count`
- **Description:** How long an I/O took, split into three **phases** on one metric so an operator can
  decompose "the disk is slow" vs "the disk is saturated (queuing)" vs "time was above the device."
- **Phases (attribute `disk.io.phase`):**
  | phase | meaning | layer | source hook | milestone |
  |---|---|---|---|---|
  | `service` | device service time (issue→complete) | block | `block_rq_issue`→`block_rq_complete` | **M1 (skeleton)** |
  | `queue` | OS queue wait (insert→issue) | block | `block_rq_insert`→`block_rq_issue` | M1 |
  | `pod_total` | app-observed, whole op incl. cache | vfs | `vfs_read/write/fsync` entry→exit | M1 |
- **Attributes:** `disk.io.phase`, `disk.io.operation` (read\|write\|fsync), `disk.io.layer`
  (vfs\|block), `system.device` (block only), `system.filesystem.mountpoint`/`.type` +
  k8s/pod attrs (vfs `pod_total` only).
- **BCC equivalents:** biolatency, biolatpcts (block); ext4/xfs/btrfs/zfs/nfs`dist`, fileslower
  aggregated (vfs).
- **Limitations:** `queue`/`service` are per-device, NOT per-pod (block layer has no cgroup).
  `pod_total` is the only per-pod phase. For NFS/CIFS/CephFS there is no block layer, so only
  `pod_total` exists and it **includes the network round-trip**. Buffered writes complete at VFS and
  flush later on a kworker → their block phases are temporally detached; `fsync`/`O_DIRECT` are the
  synchronous cases where phases chain.

---

## 2. THROUGHPUT & IOPS — how much, how often

### 2.1 `system.disk.io`
- **Instrument:** Counter · **Unit:** bytes (`By`) · **Prometheus:** `system_disk_io_bytes_total`
- **Description:** Cumulative bytes moved; backend takes `rate()` for throughput (B/s).
- **Attributes:** `disk.io.operation`, `disk.io.layer`, `disk.io.direction` (read\|write),
  `system.device` (block) or pod attrs (vfs).
- **BCC:** biotop `Kbytes`, biopattern `KBYTES`, filetop, virtiostat. **Milestone:** M1.
- **Note:** emitted per layer; the vfs/block ratio of throughput is a **coarse page-cache-absorption
  hint** (not an exact hit rate — that needs a `cachestat` hook, deferred).

### 2.2 `system.disk.operations`
- **Instrument:** Counter · **Unit:** `{operation}` · **Prometheus:** `system_disk_operations_total`
- **Description:** Cumulative op count; `rate()` = IOPS.
- **Attributes:** `disk.io.operation`, `disk.io.layer`, `system.device`\|pod.
- **BCC:** biotop `I/O`, vfsstat, vfscount, biopattern `COUNT`. **Milestone:** M1.
- **Note:** to avoid double-counting, the `queue` path does NOT emit ops (same requests as
  `service`); rates come from the layer-native families only.

---

## 3. I/O SIZE — request size distribution

### 3.1 `system.disk.io.size`
- **Instrument:** Histogram · **Unit:** bytes (`By`) · **Prometheus:** `system_disk_io_size_bytes_*`
- **Description:** Distribution of individual I/O request sizes.
- **Source:** bytes counted at the same VFS/block exits as latency (no new hook).
- **Attributes:** `disk.io.operation`, `disk.io.layer`, `system.device`\|pod.
- **BCC:** bitesize. **Milestone:** **M1 (size prioritised early).**
- **Note:** the mean (`_sum`/`_count`) is a size signal, **not** a sequential-vs-random indicator
  (that needs offset analysis — biopattern, deferred).

---

## 4. ERRORS — failed I/O

### 4.1 `system.disk.io.errors`
- **Instrument:** Counter · **Unit:** `{error}` · **Prometheus:** `system_disk_io_errors_total`
- **Description:** Count of failed I/O operations, classified by errno.
- **Source:** VFS `fexit` with `ret < 0` (layer = vfs; block completion errors are a later add).
- **Attributes:** `disk.io.operation`, `disk.backend.type` (das\|nas\|cifs\|ephemeral),
  `error.type` (errno name: `EIO`, `ENOSPC`, `ESTALE`, `EACCES`, `EDQUOT`, …).
- **BCC:** no single tool; `*slower` surface some. **Milestone:** **M1 (errors prioritised early).**
- **Note:** a partial read (`0 < ret < count`) is **success**, not an error — only `ret < 0` counts.

---

## 5. SATURATION / UTILIZATION — is the device overwhelmed

### 5.1 `system.disk.queue.depth`
- **Instrument:** Gauge · **Unit:** `{operation}` (avg in-flight count) · **Prometheus:**
  `system_disk_queue_depth`
- **Description:** Time-averaged count of in-flight requests at the device — iostat's `avgqu-sz`,
  the canonical "busy vs overwhelmed" signal. Distinguishes a slow disk (high service latency) from
  a saturated one (high queue latency + deep queue).
- **Source:** per-device in-flight accumulator (`+1` on `block_rq_issue`, `−1` on
  `block_rq_complete`), time-weighted over the sample interval (Little's law:
  `Σ service_time / interval`). No new hook.
- **Attributes:** `system.device`. **Layer:** block. **BCC:** iostat `avgqu-sz`. **Milestone:** M1.
- **Validation:** time-weighting must track `iostat avgqu-sz` within tolerance under steady + bursty
  I/O (a correctness test).

### 5.2 `system.disk.io_time`
- **Instrument:** Counter · **Unit:** seconds (`s`) · **Prometheus:** `system_disk_io_time_seconds_total`
- **Description:** Cumulative time the device was busy; `rate(system.disk.io_time)` = iostat `%util`.
- **Source:** sum of block service times per device (derivable from the same `block_rq_*` events).
- **Attributes:** `system.device`. **Layer:** block. **Milestone:** M1/M2.

---

## 6. CAPACITY — filesystem headroom (M2)

Polled via `statfs()` per mount on a timer (userspace, cheap; no eBPF).

| Metric | Instrument | Unit | Attributes | Notes |
|---|---|---|---|---|
| `system.filesystem.usage` | UpDownCounter | `By` | `system.filesystem.mountpoint`/`.type`, `state`(used\|free) | df used/free |
| `system.filesystem.limit` | UpDownCounter | `By` | mountpoint, fs.type | total size |
| `system.filesystem.utilization` | Gauge | `1` (ratio) | mountpoint, fs.type | used/total |
| `system.filesystem.inodes.usage` | UpDownCounter | `{inode}` | mountpoint, fs.type, `state` | `f_files`/`f_ffree` |

- **BCC:** df. **Forecasting:** `predict_linear(system_filesystem_usage{state="used"}[6h], 14*86400)`
  gives days-to-full — needs no new metric.

---

## 7. KUBERNETES VOLUME TOPOLOGY (M3) — attributes, not new metrics

Adds, to the per-pod VFS and capacity series:
`k8s.persistentvolumeclaim.name`, `k8s.persistentvolume.name`, `k8s.storageclass.name`.
- **How:** PV name is recoverable from the kubelet CSI mount path
  (`/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~csi/<pv>/mount`), no API call; PV→PVC→SC needs a
  PV/PVC informer + RBAC. Turns "a host path is slow" into "the `gp3` PVC behind service X is slow."
- **Limitation:** path→PV parsing is CSI-driver-specific (hostPath / in-tree / NFS-direct differ).

---

## 8. OUTLIER SPANS (M-last) — traces, not metrics

Off by default. When `latency > span_thresholds[op]` (in-kernel compare) + token-bucket rate cap:
one bounded **standalone** span per slow op carrying `disk.io.operation`,
`system.filesystem.mountpoint`/`.type`, `system.device`, bytes, duration. The eBPF event reserves
`trace_id`/`span_id` (zeroed now) so linking to the causing request trace (OBI #1659) is additive
later, not a schema break. BCC equivalents: biosnoop, `*slower`, fileslower. `per_trace_span_limit`.

---

## 9. DEFERRED (future) — named so the goal is honest

| Signal | BCC tool | Why deferred |
|---|---|---|
| Page-cache hit ratio | cachestat, cachetop | hooks (`mark_page_accessed`, folio paths) are the most kernel-version-fragile |
| Dentry-cache hit ratio | dcstat, dcsnoop | same fragility; niche |
| Random vs sequential % | biopattern | needs per-device offset tracking, not just size |
| File lifespan / removals | filelife, filegone | event-trace niche, low metric value |
| Mount/umount events | mountsnoop | event-trace, not a metric |
| Block-completion errors | — | VFS errors cover the common case first |

---

## 10. ATTRIBUTE REFERENCE (values + cardinality)

| Attribute | Values | On layers | Cardinality driver? | semconv status |
|---|---|---|---|---|
| `disk.io.operation` | read \| write \| fsync | both | low (×3) | **new** (adds fsync) |
| `disk.io.layer` | vfs \| block | both | low (×2) | new |
| `disk.io.phase` | pod_total \| queue \| service | latency only | low (×3) | new |
| `disk.io.direction` | read \| write | both | low (×2) | existing |
| `system.device` | `major:minor` / disk name (nvme0n1) | block | medium (# disks) | existing |
| `system.filesystem.mountpoint` | host path | vfs, capacity | **HIGH** — first `drop_attributes` target | existing |
| `system.filesystem.type` | ext4/xfs/nfs/cifs/ceph/… | vfs, capacity | low | existing |
| `disk.backend.type` | das \| nas \| cifs \| ephemeral | vfs (errors) | low | new (lossy; SSD vs SAN both `das`) |
| `error.type` | errno name | errors | low-med | existing |
| `state` | used \| free | capacity | low (×2) | existing |
| k8s pod set | pod.uid/name, namespace, node | vfs `pod_total`, capacity | medium (# pods) | existing (AppO11y enrichment) |
| k8s volume set | pvc/pv/storageclass name | vfs, capacity (M3) | medium | new |

**Cardinality math (busy node, ~110 pods):** per-pod VFS latency dims `110×3×2≈660`; each histogram
fans out to `_bucket` series (~24 populated buckets + sum/count) → `≈17k` VFS-latency series, plus
size/counters → **~30–40k active series/node** worst case. Block adds `~8 dev × 3 op × 2 phase ×
~26 buckets ≈ 1.2k`.
**The exponential bucket factor is the single biggest lever.** Controls: `max_series_per_node` cap
(default 50000), `drop_attributes` (drop `mountpoint` first), cgroup allowlist (drop `system.slice`
at source), no-delta→no-emit (dead pods go stale, not frozen).

---

## 11. INSTRUMENT-TYPE SUMMARY (what maps to what)

| Metric | Instrument | Unit | Milestone |
|---|---|---|---|
| `system.disk.io.latency` | Histogram | s | M1 (service=skeleton) |
| `system.disk.io` | Counter | By | M1 |
| `system.disk.operations` | Counter | {operation} | M1 |
| `system.disk.io.size` | Histogram | By | M1 |
| `system.disk.io.errors` | Counter | {error} | M1 |
| `system.disk.queue.depth` | Gauge | {operation} | M1 |
| `system.disk.io_time` | Counter | s | M1/M2 |
| `system.filesystem.usage` | UpDownCounter | By | M2 |
| `system.filesystem.limit` | UpDownCounter | By | M2 |
| `system.filesystem.utilization` | Gauge | 1 | M2 |
| `system.filesystem.inodes.usage` | UpDownCounter | {inode} | M2 |

## 12. ACCEPTANCE (a metric is "done" when)

1. It exports over **both** OTLP and Prometheus with the attributes in §10.
2. Per-pod (vfs) series carry k8s metadata; block series do **not** carry `k8s.pod.uid`.
3. Latency/size are **exponential histograms** (percentiles at query time), not precomputed-quantile gauges.
4. Cardinality stays under `max_series_per_node` with system cgroups excluded; `drop_attributes`
   measurably reduces it.
5. Values validate against the BCC/`iostat` equivalent within tolerance (run-and-observe).
6. The overhead gate passes (< ~1% agent CPU under fio), or the sampling knob is engaged.
