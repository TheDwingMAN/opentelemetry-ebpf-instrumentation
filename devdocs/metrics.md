# OBI metrics

> The full list of metrics OBI exports — names in OTel and Prometheus form, types, units, descriptions, and per-metric attribute defaults — lives in the user-facing OBI docs: <https://opentelemetry.io/docs/zero-code/obi/metrics/>.
>
> This document is the **developer-internal companion** to that page: it explains how each component's pipeline turns eBPF events into the metrics listed there, where to edit when adding a new one, and the attribute-group composition behind each metric's label set.

## Table Of Contents

- [NetO11y](#neto11y)
- [AppO11y](#appo11y)
- [StatsO11y](#statso11y)
- [General notes](#general-notes)

Each component has its own pipeline, described in the [pipeline-map doc](pipeline-map.md). In short, each component has its own maps, events, and a set of userspace nodes that add, modify, and export the data obtained from eBPF probes.

## NetO11y

**NetO11y** uses eBPF probes attached at the [TC level in ingress and egress](../bpf/netolly/flows.c) as well as a [socket/filter](../bpf/netolly/flows_sock.c).

The event we're interested in on the kernel side is called `flow_record_t` and on the userspace side is called `NetFlowRecordT`, which is read by a dedicated ringbuffer (exclusive to **NetO11y**) and will be treated as an `ebpf.Record` (defined in [pkg/internal/netolly/ebpf/record.go](../pkg/internal/netolly/ebpf/record.go)) field from there on.

The `ebpf.Record` contains accumulated metrics from a flow, with additional metadata added from the user space. It is the structure that passes all the pipeline nodes to the metric exporters.

The `Attrs` field contains various attributes that can be added to the flow record. In particular, any attributes here must also be added to the `RecordGetters` functions in [pkg/internal/netolly/ebpf/record_getters.go](../pkg/internal/netolly/ebpf/record_getters.go) and `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go). For each metric, other ad hoc attributes are defined (such as `networkCIDR` or `networkInterZoneCIDR`).

In [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), `networkAttributes` and `networkKubeAttributes` are defined. These are `AttrReportGroup` structures that define groups of attributes allowed by a given metric, whether we're in a k8s environment or not. Note that not all attributes are set to true by default and if you want to enable them, you can do so during configuration using the `attributes` field, which allows you to configure the decoration of some extra attributes that will be added to each metric. Example:

```
attributes:
  select:
    obi_network_flow_bytes:
      include:
      - obi.ip
      - src.address
      - dst.address
      ...
```

In the following methods:

- `newMetricsExporter` in [pkg/export/otel/metrics_net.go](../pkg/export/otel/metrics_net.go) for OTEL
- `newNetReporter` in [pkg/export/prom/prom_net.go](../pkg/export/prom/prom_net.go) for Prometheus

the actual metrics are created using the names defined in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) with the attributes defined and added in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).

### Add a new network metric

To add a new network metric, follow these guidelines:

1. If new fields are needed on the flow record, extend `flow_record_t` on the eBPF side and the `NetFlowRecordT` / `ebpf.Record` structs on the userspace side.
2. Define the metric `Name` in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go), wrapping it in `metric(...)` and setting its `Section`, `OTEL`, `Unit` and `Type`. Never set `Prom` by hand: it is derived from the other three.
3. Register the metric in `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), wiring it to the relevant `AttrReportGroup`s (e.g. `networkAttributes`, `networkKubeAttributes`) and any ad-hoc attributes it needs.
4. If new attributes are introduced, add the matching getters in [pkg/internal/netolly/ebpf/record_getters.go](../pkg/internal/netolly/ebpf/record_getters.go).
5. If the metric is gated by its own feature flag, add the feature bit and its accessor in [pkg/export/feature.go](../pkg/export/feature.go), register the flag name in `FeatureMapper`, and include it in `AnyNetwork()` so it activates the network pipeline. Then run `make generate-config-schema` to refresh the config JSON schema and docs.
6. Wire up the metric in the exporters, gating it behind the feature predicate added in step 5 where applicable: `newMetricsExporter` in [pkg/export/otel/metrics_net.go](../pkg/export/otel/metrics_net.go) for OTEL, and `newNetReporter` in [pkg/export/prom/prom_net.go](../pkg/export/prom/prom_net.go) for Prometheus.
7. Register the metric in the schema registry: add a `metric.*` entry in [schemas/obi/groups/network/metrics.yaml](../schemas/obi/groups/network/metrics.yaml).

## AppO11y

**AppO11y** is the component that handles all application-level tasks and generates traces and metrics. Unlike NetO11y, it uses different types of eBPF probes (such as `uprobe`, `kprobe/kretprobe`) and introduces the concept of a `tracer`, which is the component responsible for tracing a given type of application. Specifically, we can divide tracers into two categories: `gotracer` and `generictracer`.

It also has three common tracers:

- `tpinjector`: handles context propagation via both HTTP headers (sk_msg) and TCP options (BPF_SOCK_OPS)
- `logenricher`: handles trace-log correlation
- `gputracer`: handles GPU (CUDA) instrumentation

These tracers are loaded for any tracer group.

That said, let's focus on the metrics.

In **AppO11y**, the `request.Span` (defined in [pkg/appolly/app/request/span.go](../pkg/appolly/app/request/span.go)) struct is populated with all the necessary information and passes through all the nodes of the pipeline, from reading the necessary data from the eBPF maps to exporting the metrics/traces.

In particular, any attribute here must also be added to the functions `SpanOTELGetters`, `SpanPromGetters` in [pkg/appolly/app/request/span_getters_providers.go](../pkg/appolly/app/request/span_getters_providers.go) and `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).

In [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go) some `AttrReportGroup` type structures are defined for application metrics in both the k8s and non-k8s environment: `appAttributes` and `appKubeAttributes`. Here too, ad hoc attributes such as `httpCommon`, `httpClientInfo`, and so on are added for each metric. There are attributes that default to true and others to false, but which can be enabled by the user during configuration.

In the following methods:

- `setupOtelMeters` in [pkg/export/otel/metrics.go](../pkg/export/otel/metrics.go) for OTEL
- `newReporter` in [pkg/export/prom/prom.go](../pkg/export/prom/prom.go) for Prometheus

the actual metrics are created using the names defined in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) with the attributes defined and added in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).

### Add a new application metric

To add a new application metric, follow these guidelines:

1. If new fields are needed on the span, extend `request.Span` in [pkg/appolly/app/request/span.go](../pkg/appolly/app/request/span.go) and populate them in the relevant tracer.
2. Define the metric `Name` in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go), wrapping it in `metric(...)` and setting its `Section`, `OTEL`, `Unit` and `Type`. Never set `Prom` by hand: it is derived from the other three.
3. Register the metric in `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), wiring it to the relevant `AttrReportGroup`s (e.g. `appAttributes`, `appKubeAttributes`, `httpCommon`, `httpClientInfo`) and any ad-hoc attributes.
4. If new attributes are introduced, add them to `SpanOTELGetters` and `SpanPromGetters` in [pkg/appolly/app/request/span_getters_providers.go](../pkg/appolly/app/request/span_getters_providers.go).
5. Wire up the metric in the exporters: `setupOtelMeters` in [pkg/export/otel/metrics.go](../pkg/export/otel/metrics.go) for OTEL, and `newReporter` in [pkg/export/prom/prom.go](../pkg/export/prom/prom.go) for Prometheus.
6. Don't forget to clean each `Expirer` in [`cleanupAllMetricsInstances()`](../pkg/export/otel/metrics.go).
7. Declare the metric and any new attribute in the schema registry, following [Adding telemetry](../schemas/obi/README.md#adding-telemetry): import an upstream metric OBI emits unchanged, or add a `metric.obi.*` group with every attribute from step 3. Run `make lint-schema` and `make generate-schema-docs`.
8. Cover the metric in an integration suite whose compose file runs weaver, so live-check validates what is emitted.

## StatsO11y

**StatsO11y** is the component responsible for calculating statistical metrics — for example, TCP RTT or failed-connection counts — across all applications running on a node, regardless of which PID triggered the event. The probes live in [bpf/statsolly](../bpf/statsolly/).

In [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go) some `AttrReportGroup` type structures are defined for stat metrics in both the k8s and non-k8s environment: `statsAttributes` and `statsKubeAttributes`. Here too, ad hoc attributes can be added for each metric. There are attributes that default to true and others to false, but which can be enabled by the user during configuration.

### BPF program naming convention

Every statsolly BPF program follows the pattern `obi_stats_{probe_type}_{kernel_func}[_{purpose}]`, where `purpose` is only appended when two or more probes share the same hook point (e.g. `tcp_close_srtt` vs `tcp_close_io_flush`).

### Add a new stat metric

To add a new metric, follow these guidelines:

1. Decide on the hook point where you want to attach the eBPF probe. For example, you can use a kprobe on the `tcp_close` function to retrieve `srtt_us`.
2. Add a unique flag that indicates an event related to the metric you want to calculate in [bpf/statsolly/types.h](../bpf/statsolly/types.h) and the corresponding Go constant in [stat.go](../pkg/internal/statsolly/ebpf/stat.go), for example, `k_event_stat_tcp_rtt` and `StatTypeTCPRtt`.
3. Add the eBPF probe to the [bpf/statsolly](../bpf/statsolly/) folder, following the naming convention above. The metric will be calculated and sent to userspace using the `stats_events` ringbuffer.
4. Add the metric's feature bit and accessor in [pkg/export/feature.go](../pkg/export/feature.go), register the flag name in `FeatureMapper`, and include it in the `FeatureStats` aggregate if it should be part of the umbrella `stats` feature. Then run `make generate-config-schema` to refresh the config JSON schema and docs.
5. Wire the probe into [stats_tracer.go](../pkg/internal/statsolly/ebpf/stats_tracer.go):
    - add a program name constant (e.g. `progObiStatsKprobeTCPCloseSrtt`) matching the C symbol;
    - add a hook-point constant (kernel function name for kprobes, `group/name` for tracepoints);
    - add an entry to the appropriate `kprobes`/`kretprobes`/`tracepoints`/`raw tracepoints` slice inside `NewStatsFetcher`, with `enabled` driven by the `features.StatsXxx()` predicate added in step 4. Disabled probes are replaced with a no-op stub before loading, preventing unused eBPF code from being loaded into the kernel.
6. In the [tracer_ringbuf.go](../pkg/internal/statsolly/stats/tracer_ringbuf.go), simply add a function that handles that metric. This function will convert the event to a `ebpf.Stat`.
7. Then, modify the `Stat` struct accordingly, by adding a data structure containing all the necessary fields. For example `TCPRtt` struct.
8. Define the metric `Name` in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go), wrapping it in `metric(...)` and setting its `Section`, `OTEL`, `Unit` and `Type`. Never set `Prom` by hand: it is derived from the other three.
9. Register the metric in `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), wiring it to the relevant `AttrReportGroup`s (e.g. `statsAttributes`, `statsKubeAttributes`) and any ad-hoc attributes it needs.
10. If new attributes are introduced, add the matching getters to `StatGetters` in [pkg/internal/statsolly/ebpf/stat_getters.go](../pkg/internal/statsolly/ebpf/stat_getters.go).
11. Wire up the metric in the exporters. Each exporter owns one observe-method per stat type (e.g. `observeTCPRtt`, `observeTCPFailedConnections`) that translates the `ebpf.Stat` into a given observation, with its attribute set resolved through the attribute selector's `For` method:

    - `newStatsReporter` in [pkg/export/prom/prom_stats.go](../pkg/export/prom/prom_stats.go) for Prometheus
    - `newStatMetricsExporter` in [pkg/export/otel/metrics_stats.go](../pkg/export/otel/metrics_stats.go) for OTEL

12. Register the metric in the schema registry: add a `metric.*` entry in [schemas/obi/groups/stats/metrics.yaml](../schemas/obi/groups/stats/metrics.yaml).

### Storage metrics

Storage metrics have three independent layers: block-layer I/O from the `block_rq_*` tracepoints ([bpf/statsolly/blk_io.c](../bpf/statsolly/blk_io.c)) and, opt-in, from the `block_bio_*` tracepoints for stacked volumes ([bpf/statsolly/blk_bio.c](../bpf/statsolly/blk_bio.c), see [Stacked volumes](#stacked-volumes-storage_block_volumes)), filesystem-layer I/O from `file_operations` probes on nfs/ceph/cifs/fuse/ext4/xfs/btrfs ([bpf/statsolly/fs_io.c](../bpf/statsolly/fs_io.c)), and NFS client RPCs from the sunrpc `rpc_stats_latency` tracepoint ([bpf/statsolly/nfs_rpc.c](../bpf/statsolly/nfs_rpc.c)).

`k8s.node.name`&dagger; below is the agent's own node, a constant for the whole run; `k8s.owner.name`&dagger; is the pod's top-level Kubernetes owner. Both exist only when Kubernetes decoration is enabled. The attributes marked &Dagger; name the pod the block I/O was charged to: they exist only with Kubernetes decoration and `storage_block_pod`, which also adds them to `obi.stat.disk.io` (see [Pod-attributed block I/O](#pod-attributed-block-io-storage_block_pod)).

| Metric (OTel / Prometheus) | Instrument | Unit | Attributes | Feature flag |
|---|---|---|---|---|
| `obi.stat.disk.operation.duration` / `obi_stat_disk_operation_duration_seconds` | histogram | `s` | `system.device`, `disk.io.direction`, `obi.disk.stacked`, `k8s.node.name`&dagger;, `obi.disk.partition` (opt-in) | `storage_block_duration` |
| `obi.stat.disk.io` / `obi_stat_disk_io_bytes_total` | counter | `By` | `system.device`, `disk.io.direction`, `obi.disk.stacked`, `k8s.node.name`&dagger;, `obi.disk.partition` (opt-in); with `storage_block_pod` also the pod attributes&Dagger; of `obi.stat.disk.operations` | `storage_block_io` |
| `obi.stat.disk.queue.duration` / `obi_stat_disk_queue_duration_seconds` | histogram | `s` | `system.device`, `disk.io.direction`, `obi.disk.stacked`, `k8s.node.name`&dagger;, `obi.disk.partition` (opt-in) | `storage_block_queue` |
| `obi.stat.disk.queue.depth` / `obi_stat_disk_queue_depth` (deprecated) | histogram | `{operation}` | `system.device`, `obi.disk.stacked`, `k8s.node.name`&dagger; | `storage_block_queue_depth` |
| `obi.stat.disk.operation.errors` / `obi_stat_disk_operation_errors_total` | counter | `{error}` | `system.device`, `disk.io.direction`, `obi.disk.stacked`, `error.type`, `k8s.node.name`&dagger;, `obi.disk.partition` (opt-in) | `storage_block_errors` |
| `obi.stat.disk.flush.duration` / `obi_stat_disk_flush_duration_seconds` | histogram | `s` | `system.device`, `obi.disk.stacked`, `error.type` (failed flushes only), `k8s.node.name`&dagger; | `storage_block_flush` |
| `obi.stat.disk.discard.duration` / `obi_stat_disk_discard_duration_seconds` | histogram | `s` | `system.device`, `obi.disk.stacked`, `error.type` (failed discards only), `k8s.node.name`&dagger;, `obi.disk.partition` (opt-in) | `storage_block_discard` |
| `obi.stat.disk.discard.io` / `obi_stat_disk_discard_io_bytes_total` | counter | `By` | `system.device`, `obi.disk.stacked`, `k8s.node.name`&dagger;, `obi.disk.partition` (opt-in) | `storage_block_discard` |
| `obi.stat.disk.pending_operations` / `obi_stat_disk_pending_operations` | updowncounter (OTLP non-monotonic Sum) / gauge | `{operation}` | `system.device`, `obi.disk.stacked`, `k8s.node.name`&dagger;, `disk.io.direction` (opt-in), `obi.disk.partition` (opt-in) | `storage_block_pending` |
| `obi.stat.disk.operations` / `obi_stat_disk_operations_total` | counter | `{operation}` | `system.device`, `disk.io.direction`, `obi.disk.stacked`, `k8s.node.name`&dagger;, `k8s.namespace.name`&Dagger;, `k8s.pod.name`&Dagger;, `k8s.owner.name`&Dagger; (`k8s.container.name`, `k8s.kind` opt-in) | `storage_block_pod` |
| `obi.stat.disk.operation_time` / `obi_stat_disk_operation_time_seconds_total` | counter | `s` | as `obi.stat.disk.operations` | `storage_block_pod` |
| `obi.stat.fs.operation.duration` / `obi_stat_fs_operation_duration_seconds` | histogram | `s` | `system.filesystem.type`, `fs.operation`, `k8s.node.name`&dagger;, `k8s.owner.name`&dagger; (`k8s.kind` opt-in), `system.device`/`obi.disk.physical_device` (block-backed only), `server.address` (network fs only), + pod/PV/PVC/storage-class (below) | `storage_fs_duration` |
| `obi.stat.fs.io` / `obi_stat_fs_io_bytes_total` | counter | `By` | `system.filesystem.type`, `fs.operation`, `k8s.node.name`&dagger;, `k8s.owner.name`&dagger; (`k8s.kind` opt-in), `system.device`/`obi.disk.physical_device` (block-backed only), `server.address` (network fs only), + pod/PV/PVC/storage-class (below) | `storage_fs_io` |
| `obi.stat.fs.operation.errors` / `obi_stat_fs_operation_errors_total` | counter | `{error}` | `system.filesystem.type`, `fs.operation`, `error.type`, `k8s.node.name`&dagger;, `k8s.owner.name`&dagger; (`k8s.kind` opt-in), `system.device`/`obi.disk.physical_device` (block-backed only), `server.address` (network fs only), + pod/PV/PVC/storage-class (below) | `storage_fs_errors` |
| `obi.stat.nfs.client.rpc.duration` / `obi_stat_nfs_client_rpc_duration_seconds` | histogram | `s` | `onc_rpc.version`, `onc_rpc.procedure.name` (v2/v3), `nfs.operation.name` (v4), `server.address`, `k8s.node.name` | `storage_nfs_duration` |
| `obi.stat.nfs.client.rpc.errors` / `obi_stat_nfs_client_rpc_errors_total` | counter | `{error}` | as above + `error.type` | `storage_nfs_errors` |
| `obi.stat.nfs.client.rpc.retransmits` / `obi_stat_nfs_client_rpc_retransmits_total` | counter | `{retransmit}` | as `rpc.duration` | `storage_nfs_retransmits` |
| `obi.stat.nfs.client.io` / `obi_stat_nfs_client_io_bytes_total` | counter | `By` | `network.io.direction`, `server.address`, `k8s.node.name`; opt-in `onc_rpc.version`, `onc_rpc.procedure.name`, `nfs.operation.name` | `storage_nfs_io` |

Opt-in attributes, off by default and selected with `attributes.select`: `obi.disk.partition` on the block metrics that list it; `k8s.kind` on the filesystem metrics; `system.filesystem.mountpoint` and `obi.fs.container.mountpoint` on the filesystem metrics; `k8s.namespace.name`, `k8s.pod.name`, `k8s.container.name` and `k8s.owner.name` on the NFS metrics (the pod that submitted the RPC, see [NFS client RPC metrics](#nfs-client-rpc-metrics)).

The agent also reports internal metrics about the storage programs themselves, not about the workload:

| Metric (OTel / Prometheus) | Instrument | Unit | Attributes | Enabled by |
|---|---|---|---|---|
| `obi.bpf.storage.dropped.operations` / `obi_bpf_storage_dropped_operations_total` | counter | `{operation}` | `bpf.drop.reason` (`fs_accum_full`, `fs_start_failed`, `kretprobe_miss`) | the internal metrics exporter ([pkg/export/attributes/metric_internal.go](../pkg/export/attributes/metric_internal.go)) |
| `obi.bpf.map.insert.failures` / `obi_bpf_map_insert_failures_total` | counter | `{insert}` | `bpf.map.name` (`blk_rq_inflight`, `blk_agg`, `blk_q_agg`, `blk_bio_inflight`, `blk_cg_agg`) | the internal metrics exporter |
| `obi.bpf.storage.program.recursion.misses` / `obi_bpf_storage_program_recursion_misses_total` | counter | `{execution}` | `bpf.probe.name` (the program) | the internal metrics exporter |

A non-zero rate means the storage metrics under-count: operations of a new filesystem series found the kernel map full (`fs_accum_full`), a start timestamp could not be stored (`fs_start_failed`), or a kprobe-mode return probe missed its entry (`kretprobe_miss`). Raise `ebpf.maps.global_scale_factor` or select fewer attributes. The NFS map has its own drop count, logged rather than exported (see [NFS client RPC metrics](#nfs-client-rpc-metrics)). The block maps count their full-map drops per map in `obi.bpf.map.insert.failures`, read every 30 seconds from the per-CPU `stats_drops` counters ([kernel_counters.go](../pkg/internal/statsolly/stats/kernel_counters.go)); the first drop of each map is also logged. `obi.bpf.storage.program.recursion.misses` counts, for every block, filesystem, sync and NFS program that is attached, the runs the kernel skipped because a BPF program was already running on that CPU (Linux 5.12+; read every 30 seconds from the program's info, never per event): each is an operation the metrics miss.

Ready-made queries for these metrics are in the [storage PromQL cookbook](metrics-storage-cookbook.md).

`storage_block`, `storage_fs` and `storage_nfs` are umbrella flags that enable every sub-metric of their layer at once; there is no single umbrella flag covering several layers, and `storage_fs` does not imply `storage_nfs` ([pkg/export/feature.go](../pkg/export/feature.go)). `storage_block_volumes` is not a metric and is in no umbrella: it adds the stacked volumes of the node as devices to whichever `storage_block_*` metrics are enabled, and is listed by name next to them (`*` and `all` select it). One metric is left out of the umbrella too, the deprecated `obi.stat.disk.queue.depth`: it needs a per-device in-flight counter that every CPU issuing or completing block I/O updates, so it is left out of `storage_block`, and of `*` and `all`, and only kept, and paid for, when `storage_block_queue_depth` is listed by name. Note that `metrics.features: ["*"]` (or `all`) otherwise selects every family, storage included, with the probe attachment and series cardinality that implies; list the flags explicitly to keep storage off. `fs.operation` is `read`, `write`, `fsync`, `fdatasync`, `sync`, `syncfs` or `sync_file_range`. Both fsync calls reach the filesystem through the same kernel operation; OBI separates them because a database flushing data only behaves differently from one also flushing metadata. Query `fs_operation=~"fsync|fdatasync"` for all durability waits. The three syscalls are `storage_fs_sync`: unlike `storage_fs_duration`/`storage_fs_io`/`storage_fs_errors`, which only split cardinality on an already-running probe pair, `storage_fs_sync` is its own probe set (the syscall wrappers of `sync`, `syncfs` and `sync_file_range`, not a filesystem's own `file_operations`), so turning it off stops that kernel-side work rather than just the export; it is still inside the `storage_fs` umbrella. `sync_file_range` is recorded only when its `flags` argument asks the kernel to wait for the I/O (`SYNC_FILE_RANGE_WAIT_BEFORE` or `WAIT_AFTER`); a pure `SYNC_FILE_RANGE_WRITE` writeback hint (PostgreSQL `*_flush_after`, RocksDB `bytes_per_sync`) returns long before the data reaches the device and is not recorded at all. `sync` has no file, so its events have no `system.filesystem.type` and no PV attribution (`system.device` omitted, device `0`). `disk.io.direction` is `read` or `write`, and only reads and writes feed the metrics that carry it (`operation.duration`, `io`, `queue.duration`, `operation.errors`, and the deprecated `queue.depth`). Writes are `REQ_OP_WRITE`, `REQ_OP_WRITE_ZEROES` and `REQ_OP_ZONE_APPEND`, including a data write that carries a preflush. A cache flush (`REQ_OP_FLUSH`, the request the kernel issues for fsync and fdatasync) is not a zero-byte write: it goes to `obi.stat.disk.flush.duration`. A discard (`REQ_OP_DISCARD`, and `REQ_OP_SECURE_ERASE`) is not a read: it goes to `obi.stat.disk.discard.duration` and `obi.stat.disk.discard.io`, so an `fstrim` shows as discarded bytes rather than read throughput. `obi.stat.disk.discard.io` counts only the bytes of discards that completed successfully: a failed discard released nothing, and is seen as an `error.type` on `obi.stat.disk.discard.duration`. Flush and discard failures are not counted in `operation.errors`; their histograms carry `error.type` when the request failed and omit it when it succeeded. Without `storage_block_flush` or `storage_block_discard`, the kernel program ends those requests without sending an event to userspace, so they cost only their in-flight map entry. Other operations (zone management, driver-private commands) are not reported. `system.filesystem.type` is one of `nfs`, `ceph`, `cifs`, `fuse`, `ext4`, `xfs`, `btrfs`, identified by which probe fired, not by inspecting the event. `obi.disk.partition` (opt-in via `attributes.select`) is the sysfs name of the partition a read, write, error, discard or pending request named at issue: the request's first bio's block device when it has one (always set from Linux 5.12 on, and unchanged by the kernel's partition-to-whole-disk remap), else its `rq->part` (flushes have no bio, so they fall back to it and still have no partition when `queue/iostats=0` has left it unset); omitted for whole-disk I/O and for a request whose partition could not be resolved. Selecting it is the only thing that makes the issue path read it at all: unselected, it costs nothing and never enters the aggregation key, which, unlike the attribute, always carries the field (see [blk_io.c](../bpf/statsolly/blk_io.c)).

`obi.stat.disk.pending_operations` (D10) is not built from an event or a kernel counter at all: at each collection, [blk_pending_reader.go](../pkg/internal/statsolly/stats/blk_pending_reader.go) takes a userspace batch snapshot of the in-flight map the issue/complete path already maintains (`blk_rq_inflight`, or `blk_rq_inflight_sector` on the classic-tracepoint fallback; with `storage_block_volumes` also `blk_bio_inflight`, the bios in flight on the tracked volumes, whose values have the same shape) and counts the live entries per device and direction. That costs nothing on the hot path, unlike the deprecated `obi.stat.disk.queue.depth`, which is why `storage_block_pending` is inside the `storage_block` umbrella where `storage_block_queue_depth` is not. An entry older than 5 minutes (a missed completion) is not counted; a device that had a request in flight within the metric's TTL reports 0 rather than disappearing, and only drops out once it has been idle for that long. `disk.io.direction` is opt-in here (unlike the other block metrics): a point-in-time snapshot sees flush and discard entries too, which have no direction, so turning it on splits reads and writes out of an otherwise device-only series rather than mislabel them.

**Migrating off `obi.stat.disk.queue.depth`.** The deprecated histogram observes the depth at every read/write completion, which iostat has no equivalent for; `obi.stat.disk.pending_operations` is a point-in-time count, closer to iostat's `aqu-sz` (average queue size over the sample interval) than to anything `queue.depth`'s histogram gave. The PromQL replacement for "average queue depth over the last interval" is an average over time of the gauge, not a histogram quantile:

```promql
avg_over_time(obi_stat_disk_pending_operations{system_device="vda"}[$__rate_interval])
```

This undercounts relative to a true time integral when requests complete between collections faster than the collection interval samples them (the same sampling gap `queue.depth`'s per-completion histogram did not have), but needs no per-request kernel work to get it.

How the block counts relate to `/proc/diskstats`, per whole disk:

- Flushes: `obi_stat_disk_flush_duration_seconds_count` matches the diskstats flushes.
- Writes: `obi_stat_disk_operation_duration_seconds_count{disk_io_direction="write"}` matches the diskstats writes, with two exceptions. diskstats also counts as a write each empty `REQ_PREFLUSH` write request (0 bytes, such as a dm-thin metadata commit or a flush passed through a loop device). That request is never issued to the device: the kernel issues a flush for it instead (none on a device without a write-back cache), and OBI counts only that flush. And diskstats counts a secure erase (`REQ_OP_SECURE_ERASE`) as a write, where OBI counts it as a discard, since it releases blocks rather than moves data.
- Discarded bytes: diskstats counts the sectors of a failed discard too, `obi.stat.disk.discard.io` does not (see above). A failed read or write still counts its bytes in `obi.stat.disk.io`, as in diskstats.

Two limits apply only to the classic-tracepoint fallback (`tracepoint/block/*`, used when the kernel BTF does not let the raw tracepoint programs find a request's disk):

- It names a request by `(dev, sector)`, and every flush reports sector 0, so all flushes on a disk share one key (with any request at sector 0). Concurrent flushes on one disk collide: the later issue replaces the earlier one's entry, the first completion ends it and the second finds nothing, so they are recorded as one flush, timed from the later issue.
- It classifies from the `rwbs` string, which has no letter for `REQ_OP_WRITE_ZEROES` or `REQ_OP_ZONE_APPEND` (both are `N`), so it ignores them, while the raw path counts them as writes.

`obi.stat.disk.queue.duration` runs from the request's block-layer accounting start (`rq->start_time_ns`, set after the tag or scheduler-tag allocation and shared by all requests of a plug batch) to `block_rq_issue`, the dispatch to the driver; it is read at issue, so there is no `block_rq_insert` program. Reads and writes only. Nothing is recorded: when the device has `queue/iostats=0` (the kernel then does not write the field, which holds a stale value from an earlier use of the tag; the check is `RQF_IO_STAT`); for the data write of a flush sequence (`RQF_FLUSH_SEQ`), whose start precedes the PREFLUSH it waited behind, so the histogram count is at most that of `operation.duration` and equal without PREFLUSH or FUA writes; and on a kernel whose BTF has no `enum rqf_flags` or where the classic block tracepoints are used. The two flags are resolved from that enum, and OBI does not hard-code their bits per kernel version, since wrong bits would give silently wrong data; the enum is absent on kernels that define the flags only as macros (this was not checked per kernel version), so the metric then has no series and OBI logs a warning at start. It shares its bucket boundaries with `obi.stat.disk.operation.duration` (`Buckets.StatDiskOperationDurationHistogram`), and so do `obi.stat.disk.flush.duration` and `obi.stat.disk.discard.duration`; `obi.stat.disk.queue.depth` and `obi.stat.fs.operation.duration` each have their own (`Buckets.StatDiskQueueDepthHistogram`, `Buckets.StatFsOperationDurationHistogram`) — see [pkg/export/bucket.go](../pkg/export/bucket.go).

#### Node-wide vs pod-attributed

Block metrics come from the request-queue tracepoints (`block_rq_issue`/`block_rq_complete`), which see the device and the request but not the process that issued it. They are node-wide, except for what `storage_block_pod` counts per cgroup ([next section](#pod-attributed-block-io-storage_block_pod)): no pod, namespace, or PV/PVC attribute is ever attached to the other block metrics, only `system.device`, `disk.io.direction`, `error.type` and, with Kubernetes decoration on, `k8s.node.name` — the agent's own node, a constant for the whole run (`ebpf.SetNodeName`/`NodeName`, set once from `MetadataProvider.CurrentNodeName` in `pipeline.go`'s `setNodeName`), not anything about the request's issuer. A request is followed from `block_rq_issue` to its final `block_rq_complete` by its `struct request` pointer, so requests that share a device and sector (the flush requests of several hardware queues) are told apart. A driver that completes a request in pieces (SCSI after a partial transfer) fires `block_rq_complete` once per piece; the request is recorded once, with all its bytes, when the last piece or a failed one completes. On a device without FUA, a write the flush machinery handles (one with a preflush or FUA) completes twice: with its bytes, which records it, then with none after the post-flush; the second completion finds no entry and is ignored, while the flushes are recorded as flushes.

#### Pod-attributed block I/O (`storage_block_pod`)

`storage_block_pod` (opt-in, in no umbrella; `*` and `all` select it) counts the completed block reads and writes per cgroup they were charged to, device and direction, in the kernel, and exports them as `obi.stat.disk.operations` and `obi.stat.disk.operation_time`, the per-pod counterparts of semconv's `system.disk.operations` and `system.disk.operation_time`. With `storage_block_io` on, `obi.stat.disk.io` is then counted the same way and carries the same pod attributes; its node-level series is their sum. There are no per-pod histograms: they would multiply the series by the buckets.

- **Whose I/O.** The cgroup is the one the request's first bio is charged to (its blkcg, `bio->bi_blkg->blkcg`, read at `block_rq_issue`: [blk_cgroup.h](../bpf/statsolly/blk_cgroup.h)), never the task running the program: requests are often issued by kernel threads (kblockd, the dm-thin pool worker, the writeback flushers) on a pod's behalf. Reads and direct I/O are charged to the submitting container; buffered writes, whether flushed by the kernel or by fsync, to the cgroup that owns the file's writeback domain: normally the container that created the file, then the dominant writer after some writeback rounds, then the pod or QoS slice once the container is removed. A cgroup is resolved to its pod and container through the shared cgroup index ([Kernel aggregation and the cgroup index](#kernel-aggregation-and-the-cgroup-index)) and the Kubernetes store, at every level under the kubelet's cgroup (container, conmon scope, pod and QoS slices); a pod's labels are kept for 10 minutes after the store last named it, since writeback keeps charging a deleted pod's files to its cgroup ([blk_cg_reader.go](../pkg/internal/statsolly/stats/blk_cg_reader.go)).
- **I/O of no pod.** Kernel threads such as the ext4 journal, system services and user sessions are counted too, as a series without pod attributes, so the series of a device and direction add up to all of its reads or writes. Without Kubernetes metadata every series is of that kind: the counters are then per device and direction only.
- **Time.** `obi.stat.disk.operation_time` adds, per request, the time from its block-layer accounting start (`rq->start_time_ns`, when the request flags say it is valid) to its completion, else from its issue to the driver (`queue/iostats=0`, and a write in a flush sequence); a stacked volume's bio is timed from its queueing (with `storage_block_volumes`, whose bios are counted here too). It is in seconds, a counter: `rate()` of it is the device's busy time per pod, as diskstats fields 7 and 11 are per device.
- **Where it works.** It needs cgroup v2 with the `io` controller enabled in the root's `cgroup.subtree_control`: configuration validation turns the flag off with a warning elsewhere ([block_pod_gate.go](../pkg/obi/block_pod_gate.go)), since cgroup v1 charges block I/O to blkio cgroups no pod cgroup id matches, and without `io` every request is charged to the root. On the classic-tracepoint fallback, which carries no request, the counters exist but every series is without a pod (a warning says so). A kernel without `CONFIG_BLK_CGROUP` charges nothing either.
- **Cost and memory.** A cgroup read at every issue and a per-CPU map update at every read or write completion, in either emit mode: the pod counters are always counted in the kernel, `ebpf.storage_aggregation.disabled` included, and have no per-event path. `blk_cg_agg` is sized at startup for 110 pods, as many removed within the tombstone window, three cgroups each and 32 cgroups of the node's own, per device and direction, scaled by `ebpf.maps.global_scale_factor` and capped by `ebpf.storage_aggregation.block_pod_maps_budget_bytes` (8 MiB, counted for every possible CPU; [blk_cg.go](../pkg/internal/statsolly/ebpf/blk_cg.go)). A completion whose key does not fit is not counted, and `obi.bpf.map.insert.failures{bpf_map_name="blk_cg_agg"}` counts it. Idle keys are deleted once their cgroup's tombstone has expired.
- **Attributes.** `k8s.namespace.name`, `k8s.pod.name` and `k8s.owner.name` (the pod's top-level owner, as on the filesystem metrics) by default, `k8s.container.name` and `k8s.kind` opt-in to bound the series. No `obi.disk.partition` on `operations` and `operation_time`.

Filesystem metrics come from probes on each filesystem's own `file_operations` read/write/fsync implementation, which runs in the calling process's context, so they carry `k8s.pod.name` and `k8s.namespace.name`, plus `k8s.persistentvolume.name`, `k8s.persistentvolumeclaim.name` and `k8s.storageclass.name` once the mount the file was reached through resolves to a kubelet volume mount. `k8s.owner.name` (default) and `k8s.kind` (opt-in) follow the pod's top-level Kubernetes owner — the Deployment that owns the ReplicaSet that owns the pod, and so on — the same rule the network decorator uses (`topOwnerNameKind` in [pkg/internal/pipe/transform/k8s/kubernetes.go](../pkg/internal/pipe/transform/k8s/kubernetes.go), shared by the PID decorator); a pod with no owner is attributed to itself, never guessed from a shared (RWX) mount when the process that issued the I/O could not be identified. The probes report the superblock device and the inode of the mount's root directory; the root inode tells apart volumes that share a superblock, as every PV carved out of one NFS export does (`scanForMount` in [pkg/internal/statsolly/ebpf/mount_resolver.go](../pkg/internal/statsolly/ebpf/mount_resolver.go)). When it cannot be told, the volume is left unnamed rather than guessed (`statsFsAttributes`, `statsFsKubeAttributes` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go)). All Kubernetes attributes, including the PV/PVC/storage-class ones, are disabled when Kubernetes metadata is off.

The filesystem metrics have two opt-in attributes for where a volume is mounted. They are off by default and add no series (one value per pod and volume, or per container and volume); select them with `attributes.select`, for instance `obi_stat_fs_io: {include: ["system_filesystem_mountpoint", "obi_fs_container_mountpoint"]}`. Nothing is read for one that is not selected.

- `system.filesystem.mountpoint` is the host path of the kubelet mount of the volume, `/var/lib/kubelet/pods/<pod uid>/volumes/kubernetes.io~<plugin>/<volume>[/mount]`, the path hostmetrics and the kubelet report. It comes from the host mount table the mount resolver has already read (`MountInfo.HostPath` in [pkg/internal/statsolly/ebpf/mount_resolver.go](../pkg/internal/statsolly/ebpf/mount_resolver.go)); no per-process read. A volume with a mount per pod (ReadWriteMany) reports the mount of the pod the I/O came from, never another pod's or the first in the table; when the pod is not known there is none. Paths are unescaped (`\040` is a space). The CSI staging mount, the `volume-subpaths` binds and mounts outside the kubelet are never the answer. It is omitted for `sync` and for I/O on no kubelet volume.
- `obi.fs.container.mountpoint` is where the container of the process mounts the volume, from the process's `/proc/<pid>/mountinfo` (`MountpointResolver` in [pkg/internal/statsolly/ebpf/mountpoint_resolver.go](../pkg/internal/statsolly/ebpf/mountpoint_resolver.go)): the mount of that device, with several (a subPath next to the whole volume) told apart by the root inode of the mount, read off the hot path, and otherwise the shortest path. A process that has exited is replaced by another of its PID namespace. Answers are cached per container and volume (4096 entries, 60 s; a miss 15 s) and the attribute is omitted while one is unknown.

Reads a process performs with `splice(2)`, `sendfile(2)` or
`copy_file_range(2)` take the filesystem's `splice_read` operation rather than
`read_iter`, so they need their own probe. They are recorded as
`fs.operation=read` on nfs, ext4, btrfs and fuse, which have a dedicated
symbol. Ceph, CIFS and XFS use the generic `filemap_splice_read`, which every
filesystem on the node shares including container root filesystems, so probing
it would defeat the point of hooking each filesystem separately; splice reads
on those three are not recorded. Writes have no equivalent path.

`k8s.pod.name` and `k8s.container.name` are resolved from the issuing process's own cgroup (`/proc/<pid>/cgroup`), which works for any container process, instrumented or not. A process that exited before its events were decorated is resolved through its PID namespace, and failing that the pod falls back to the volume mount's owner when the volume has exactly one; the container is then left unset.

Buffered writes (no `O_SYNC`, `O_DIRECT` or fsync) complete once the data is in the page cache, so their `obi.stat.fs.operation.duration` measures the copy into memory, not the round trip to the NFS server or the disk. The server's or device's latency shows in `fs_operation="fsync"`/`"fdatasync"` and in the block metrics.

Capacity and usage (bytes used/free/total on a volume) are out of scope here on purpose: join kubelet's own `kubelet_volume_stats_*` metrics on `k8s.persistentvolumeclaim.name` for that.

#### Attributes that do not apply, and error names

Storage metrics set an attribute only when it applies. Over OTLP, a string attribute whose value is empty is left out of the data point rather than sent as `""`: `k8s.pod.name`, `k8s.namespace.name`, `k8s.container.name`, `k8s.owner.name` and `k8s.kind` on I/O from a process in no pod, the PV, PVC and storage class on I/O that did not go through a kubelet volume, and `system.filesystem.type` or `fs.operation` for a code this build has no name for (never `unknown` or `read`). `newStorageExpirer` in [pkg/export/otel/metrics_stats.go](../pkg/export/otel/metrics_stats.go) does this for every storage metric; the TCP stat metrics are unchanged. Prometheus label sets are fixed per metric, so OBI's Prometheus endpoint keeps these labels with an empty value, which Prometheus stores as no label.

`error.type` is the errno name (`EIO`, `EACCES`), else the name of a kernel-internal errno (512 to 531, such as `EJUKEBOX` when an NFSv3 server asks the client to retry later, or `ENOTSUPP`), else the name of an NFSv4 status the NFS client passes up unmapped (10001 to 10096, such as `NFS4ERR_DELAY` and `NFS4ERR_GRACE`), else the decimal value ([pkg/internal/statsolly/ebpf/errno.go](../pkg/internal/statsolly/ebpf/errno.go)). Kernel-internal errnos and NFSv4 statuses used to be decimal (`528`, `10008`).

The PV, PVC and storage class of a filesystem stat depend only on the mount the I/O went through, so the PID decorator resolves them once per mount, looking the claim up once per mount resolution, and the stat carries a pointer to the result (`FsIo.Mount`); the getters read its fields. Telling apart the volumes that share a superblock needs the inode of each candidate mount point's root. That lookup runs in the background and never holds up the pipeline: until it returns, the first events of such a mount carry no volume attributes, and the mount is resolved again once the inode is known. It used to wait for the lookup, up to 1 s per mount point. A lookup still running after 30 s (a hard NFS mount of a server that does not answer) is logged as a warning naming the mount point, and at most 64 lookups run at once: past that, the volumes of further mounts on a shared superblock stay unnamed until one returns. A change to the mount table drops only the resolutions of the devices whose mounts it added or removed, and the root inodes of those mount points, rather than every resolution on the node.

The PVC lookup itself (`K8sPVCLookup`, [pkg/internal/statsolly/ebpf/pvc_resolver.go](../pkg/internal/statsolly/ebpf/pvc_resolver.go)) never runs on the decorator's goroutine either: a cache miss returns not-found at once and a GET runs in the background, filling the cache for the next call to that PV. A `claimRef` is only trusted while the PV is `Bound` — a `Released` PV's `claimRef` can name a claim that is gone, or reused by an unrelated new claim of the same name. Positive resolutions are cached for 10 minutes and negative ones for 30 seconds, so a `Retain` PV an admin re-binds to a different claim, or one that only later becomes `Bound`, is picked up without a process restart.

#### `system.device`, `obi.disk.physical_device` and `server.address` (fs join labels)

These three let a dashboard join a filesystem series to the disk or NFS series underneath it, without a topology metric. They are resolved once per mount, alongside the PV/PVC lookup, and read from the same `FsIo.Mount` fields as the PV/PVC/storage-class attributes above.

`system.device` is the sysfs basename of the mount's superblock device (`dm-4`, `nvme0n1p3`), like the block metrics' own attribute, but never the `<major>:<minor>` fallback: an anonymous superblock (major 0 — nfs, cifs, ceph, fuse, or a btrfs volume spanning more than one device) leaves it unset rather than guessing. A multi-device btrfs volume is still block-backed, though, so its mount source (e.g. `/dev/mapper/vg-lv`) is stat'd through `/proc/1/root` as a fallback, the same way a loop device's backing file is (`FSJoinDevice`, [pkg/internal/statsolly/ebpf/block_stack.go](../pkg/internal/statsolly/ebpf/block_stack.go)).

`obi.disk.physical_device` is the step 8 block-stack walk (`obi.disk.stacked`'s own `devInfo` cache) from that device: sorted, comma-joined, capped at 8. It is unset whenever `system.device` is.

`server.address` is the mount's `addr=` super option (the IP the kernel resolved the export or share to), netip-normalized so it matches byte for byte what the NFS RPC metrics report for the same server (`rpc_xprt->addr`) — the join key between `obi.stat.fs.*` and `obi.stat.nfs.client.*`. It falls back to the mount source's host only when the kernel reports no `addr=`, and is left unset for ceph (several monitors, ambiguous) and every local filesystem. With NFSv4.1+ trunking, mounting a second address of a server already mounted shares the first client, and the kernel rewrites that mount's `addr=` too: both sides then report the first-mounted address, not the address actually used for this mount — a client-side limitation, not an OBI bug.

#### Device-mapper coverage and `obi.disk.stacked`

Block metrics attach to the request-queue tracepoints, which see the underlying physical device, not any layer stacked on top of it. For LVM, LVM-S, md or dm-crypt-backed volumes, `obi.stat.disk.*` reports by default against the physical device (`sda`, `nvme0n1`, …), never the `dm-N` or `mdN` device on top of it. Those volumes are still observed per pod/PVC at the filesystem layer (ext4/xfs/btrfs mounted on the logical volume, through the PV-mount allowlist described below), and at the block layer under their own device once `storage_block_volumes` is enabled.

Every disk metric carries `obi.disk.stacked`: true when the device does not issue requests to hardware itself (it has a `dm/`, `md/` or `loop/` sysfs directory, a non-empty `slaves/` with none of those — bcache and other stacking drivers — or is an NVMe native-multipath head with a `multipath/` directory); a partition inherits its whole disk's value (`devInfo` cache, [pkg/internal/statsolly/ebpf/block_stack.go](../pkg/internal/statsolly/ebpf/block_stack.go)). On the request programs alone, `obi.disk.stacked=true` can only be observed for the two device kinds that get their own block-layer events despite being stacked: a request-based dm-multipath device (whose slaves are its SCSI paths) and an NVMe native-multipath head (whose `multipath/` directory lists its path namespaces). Bio-based LVM, dm-crypt, dm-thin and md volumes get series of their own, with `obi.disk.stacked=true`, only with `storage_block_volumes` (next section); without it their I/O is reported on the physical disks below, with `obi.disk.stacked=false`.

#### Stacked volumes (`storage_block_volumes`)

A bio-based stacked device has no request queue: its driver clones each bio onto the devices below, and only those issue requests. With `storage_block_volumes` (opt-in, in no umbrella, and effective only next to at least one `storage_block_*` metric) OBI loads two more programs, on `block_bio_queue` and `block_bio_complete` ([bpf/statsolly/blk_bio.c](../bpf/statsolly/blk_bio.c)), as a collection of their own: a kernel that rejects them, or one older than Linux 5.12 (no `bio->bi_bdev`), loses the volumes with one warning and keeps every other block metric. They are attached as `tp_btf` with `raw_tp` as fallback, in the variant the kernel's `block_bio_queue` prototype takes (`(bio)`, or `(q, bio)` before 5.11), read from BTF. A tracked bio enters `blk_bio_inflight` (a plain hash keyed by the bio pointer) when it is queued and is counted, at its completion, in the maps and events of the request programs, under the volume's device: the same metric names, `system.device="dm-4"` (or `md127`), with `obi.disk.partition` naming the partition for a bio submitted to one (an md array's partitions) when that attribute is selected.

Which devices are tracked ([blk_vol_devs.go](../pkg/internal/statsolly/ebpf/blk_vol_devs.go), read from `/sys/block` at startup and every 30 seconds, so a volume created later is measured from the next pass on):

- device-mapper and md devices (`dm/` or `md/` in sysfs),
- that are bio-based: no `mq/` directory. Request-based device-mapper (dm-multipath) is left out: its requests are already measured by the request programs, and the bios submitted to it fire `block_bio_queue` but never `block_bio_complete`, so they would be left in the in-flight map;
- that nothing is stacked on: an empty `holders/`. Every lower layer sees a clone of each bio of the volume above it (the I/O of a thin volume is queued and completed again on its pool and on the pool's data device), so tracking those would measure one I/O three times and export LVM internals as devices. A partition is not a holder: an md array with partitions is tracked.

NVMe native multipath heads (`nvme0n1` with a `multipath/` directory) are not tracked either: a head does not clone a bio, it points it at a path's device and submits it again, so the bio ends in a request of the path and its completion is traced as that request's, never as `block_bio_complete`. Their I/O is measured on the path devices by the request programs. Only bio-based devices that trace their bios' completions may enter the in-flight map; the kernel side enforces it by looking a bio's whole disk up in the tracked set (`blk_bio_devs`) before it inserts anything.

`block_bio_queue` fires for every bio submitted on the node, whatever its device, which is why the flag is opt-in. A bio that is not for a tracked volume costs three loads to the major of its gendisk and a comparison with the majors the tracked set holds (`blk_vol_major`, at most three: device-mapper's, md's, and mdp's for old partitionable arrays). The filter and the lookup go by the gendisk (`bio->bi_bdev->bd_disk`), not by the bio's own device number: a partition of an md array is `259:N` (the extended block major) while its disk is `9:M`.

What the series of a stacked volume mean:

- Counts are bios as submitted to the volume. The kernel traces the queueing and the completion once per bio, however the driver splits it, while `/proc/diskstats` (and node_exporter's `node_disk_*_completed_total`) of `dm-N` and `mdN` devices counts the fragments: one per thin-pool chunk, per md raid0 chunk, per raid1 split. Buffered writeback with 1 MiB bios on a thin volume with 64 KiB chunks shows 16 times more writes in diskstats than in OBI. Bytes match exactly (`obi.stat.disk.io` equals the diskstats sectors times 512, for reads, writes and discards): compare bytes, not operation counts, with node_exporter for stacked devices.
- `obi.stat.disk.operation.duration` is the end-to-end time of the bio as its submitter sees it: from `block_bio_queue` to the completion of the last fragment the driver made of it, including what the driver itself waited (a thin-pool allocation, a dm-delay, a raid resync barrier). There is no `obi.stat.disk.queue.duration` for a volume.
- A flush is an empty `REQ_PREFLUSH` write bio (what `fsync` and `fdatasync` submit): it goes to `obi.stat.disk.flush.duration`, never to the write series. A preflush or FUA write that carries data (a journal commit) is a write. diskstats never counts a flush on these devices: device-mapper counts each empty preflush as a write of 0 bytes (dm-thin counts a preflush with data as two writes), md does not count it at all. A volume whose queue has no write-back cache gets no flush bios: the block layer ends them before they are queued.
- Failed bios feed `obi.stat.disk.operation.errors` (and the `error.type` of the flush and discard histograms) even where diskstats counts nothing, as for the device-mapper `error` target.
- The I/O of a volume is also measured, as requests, on the disks below it. Summing a block metric over every `system.device` counts that I/O once per layer, so select the devices to add up (the disks, or the volumes).
- `dm-N` names are not stable across reboots.

Entries of `blk_bio_inflight` whose bio was queued more than 5 minutes ago are deleted by a sweep every 10 seconds ([blk_vol_sweep.go](../pkg/internal/statsolly/ebpf/blk_vol_sweep.go)), logged once, and `obi.stat.disk.pending_operations` already ignores them. They are the leftovers of completions the program missed: the kernel skips a run of a program that is already running on the CPU (counted per program in `obi.bpf.storage.program.recursion.misses`, which includes the two bio programs), and a skipped completion leaves its entry. A volume that leaves 16 or more of them in one pass is taken for one whose bios never fire `block_bio_complete` on this kernel (a driver that hands the bio it was given to a lower device instead of a clone, so that it completes as a request there), or that hung: it is removed from the tracked set with one warning, its bios in flight are deleted, and it is tried again an hour later. The map is shared by every tracked volume, and such a volume fills it at its own I/O rate (a few thousand bios a second fill it in seconds), after which the bios of every volume would be dropped until its entries were 5 minutes old. So when a sweep finds the map at least half full, entries older than 10 seconds are stale too: the volume is quarantined within two sweeps, and a healthy volume, whose bios complete in milliseconds, keeps its own. On RHEL 9 (5.14.0-749) dm-linear, dm-thin, md raid0 and md raid1 all trace one completion per bio. md raid0 and linear arrays clone a bio only to account for it (`md_account_bio`), so on an array with `queue/iostats=0` (and with a linear personality that does no accounting) the bio itself goes to the members and, on request-based members, completes without a `block_bio_complete` event: such an array ends up in this quarantine. A bio queued under a pointer that still has an entry (a struct bio the kernel reused after a missed completion) replaces that entry whole.

The aggregation maps are sized at startup for the request-based devices and the volumes tracked then, plus room for 32 more devices (see `planBlockAgg` in [blk_agg.go](../pkg/internal/statsolly/ebpf/blk_agg.go)); a volume has no keys in the queue map. Completions of volumes created later than that room holds are not counted, as for disks: `obi.bpf.map.insert.failures{bpf_map_name="blk_agg"}` counts them. `blk_bio_inflight` holds 65536 bios in flight; a bio queued while it is full goes unmeasured and is counted under `bpf_map_name="blk_bio_inflight"`.

#### Filesystem coverage and the PV-mount allowlist

Probes attach to each filesystem implementation's own read/write/fsync symbols (`nfs_file_read`, `ceph_read_iter`, `fuse_file_read_iter`, `ext4_file_read_iter`, `xfs_file_read_iter`, `btrfs_file_read_iter`, and their write/fsync counterparts — `fsTargets` in [pkg/internal/statsolly/ebpf/fs_probes.go](../pkg/internal/statsolly/ebpf/fs_probes.go)) rather than one generic VFS hook, so a node not using a given filesystem pays nothing for it. Detection is per filesystem, so a node can have `nfs` loaded and not `ceph`.

CIFS has three independent vtables, one per `cache=` mount option, and every one present attaches: `cifs_strict_readv`/`cifs_strict_writev`/`cifs_strict_fsync` (`cache=strict`), `cifs_loose_read_iter`/`cifs_file_write_iter`/`cifs_fsync` (`cache=loose`), `cifs_direct_readv`/`cifs_direct_writev`/`cifs_fsync` (`cache=none`). `cifs_fsync` is shared by `cache=loose` and `cache=none`; it is probed once, by whichever of the two resolves it first (`dedupeSharedFsync`), and that claim is then tracked for the life of the attacher (`fsAttacher.fsyncOwner`): a sibling planned alone in a later 30-second check, after the claimant already attached, is deduped against that live claim rather than re-resolving and probing the symbol a second time; and if the claimant instead fails permanently (3 tries), the claim is handed to whichever sibling is attached and lists the same symbol, so `cifs_fsync` is never probed twice and never left unprobed by anyone for the life of the process. `cifs_user_readv`/`cifs_user_writev`, the shared body `cache=strict` and `cache=none` call into, are never probed: they are not a filesystem's `file_operations`, and probing them would count `cache=strict` I/O twice. The three variants attach as independent `FsIo` collections, each failing, retrying and falling back to kprobes on its own; a node mounting only one `cache=` mode still gets every variant's probes loaded, since the mode is a per-mount choice OBI cannot see before a call reaches the kernel. On the lab's `cifs.ko` (a 5.14 el9 kernel), `cache=loose`'s `read_iter`/`write_iter` are static and absent from the module's own BTF even though its other seven symbols are present, so that variant alone falls back to kprobes (`fentryCapable`, per-symbol against the module's parsed BTF, not just the BTF directory's existence). Before this, `fsTargets` tried `cache=strict`'s symbols first and never attached `cache=loose` or `cache=none` at all.

`fs_start` (the in-flight map an entry/exit probe pair hands a call's start through) has no `cache=` variant field, only `FsTypeCode`: `clearMapFsStarts` filters by filesystem alone. When one CIFS variant's attach fails or is retried, closing its `fsAttachment` clears every `fs_start` entry of `cifs`, including one a different, still-attached variant's thread is about to look up for a call already in flight; that call then loses its one sample, the same degradation a kretprobe detaching mid-call already causes. This is bounded to the attach-failure/retry window, not every CIFS call, and is unverified against real CIFS traffic (`TestClearFsStartsCannotDistinguishCIFSVariants` in [fs_tracer_test.go](../pkg/internal/statsolly/ebpf/fs_tracer_test.go) sizes the mechanism at the unit level, without claiming a frequency). Fixing it needs a variant discriminator on `fs_start`'s value, a BPF-side change not made in step 12.

`ext4`, `xfs` and `btrfs` back the node's own root filesystem and every container's writable layer, in addition to PersistentVolumes, so those three are also gated through an allowlist (`fs_dev_filter`, [pkg/internal/statsolly/ebpf/fs_dev_filter.go](../pkg/internal/statsolly/ebpf/fs_dev_filter.go)): only a device that is both one of those three filesystems *and* actually backs a kubelet volume mount is allowed to record events. The allowlist is reconciled against the node's current kubelet volume mounts every 30 seconds. NFS, Ceph, CIFS and FUSE are not filtered this way, since they're never used for a node's own root or container writable layer.

The probes of `ext4`, `xfs` and `btrfs` are attached only while a kubelet volume of that filesystem is mounted on the node, and detached once two checks in a row have found none, so a node without such a volume (NFS-only, or no PersistentVolume at all) pays no probe on the reads and writes of its own services and container layers. A network filesystem is attached from the moment its module is loaded, which for NFS, CIFS, Ceph and FUSE is usually the node's first mount of that type, possibly after OBI started. Both are checked every 30 seconds (`fsAttacher` in [pkg/internal/statsolly/ebpf/fs_late_attach.go](../pkg/internal/statsolly/ebpf/fs_late_attach.go)).

#### Filesystem load isolation

The filesystem programs are a BPF object of their own (`FsIo`, [pkg/internal/statsolly/ebpf/fs_tracer.go](../pkg/internal/statsolly/ebpf/fs_tracer.go)), apart from the TCP and block programs. Each filesystem loads as a collection containing only the programs its plan attaches; its maps (the event ring buffer, the start maps `fs_start` and `fs_start_task`, the aggregation map and the allowlist) are the `OBI_PIN_INTERNAL` maps every stats collection shares, and every load uses the same load-time constants. The loads of a burst — the startup loads, or one 30-second check that loads a filesystem — share one kernel BTF cache, so vmlinux and module BTF are parsed once per burst and dropped when it ends; the startup log reports the parse times (`kernel_btf_parse`, `module_btf_parse`). A filesystem whose programs the kernel rejects is disabled on its own: the TCP, block and other filesystem probes keep running. When a filesystem's `fentry`/`fexit` programs fail to load or attach for a reason that rules them out on this kernel (no BTF for the function, no trampoline support, a function the kernel will not trace or a verifier rejection), it is tried at once with `kprobe`/`kretprobe` and stays on them; any other failure is retried with `fentry`/`fexit` on the next check. A filesystem that fails 3 times in a row, 30 seconds apart, is left alone until OBI restarts.

cilium/ebpf relocates every load against the BTF of all loaded kernel modules, so a module whose BTF cannot be parsed fails every load, the stats collection's included. For the filesystem loads only, OBI then retries against the kernel BTF and the filesystem's own module.

#### Filesystem program naming

The general StatsO11y convention above (`obi_stats_{probe_type}_{kernel_func}[_{purpose}]`) names a program after the specific kernel function it hooks. Filesystem probes can't follow that literally, because the actual symbol to attach (e.g. CIFS's `cache=strict` vs `cache=loose` vs `cache=none` vtables, which all attach side by side) is resolved per node at load time, not at compile time. Instead, each filesystem's read/write/fsync programs are compiled once against a placeholder `SEC("fentry/obi_dummy_fs_read")` (etc.) attach point and named by filesystem and operation instead of by kernel function — `obi_stats_fentry_nfs_read`, `obi_stats_kprobe_cifs_write`, and so on ([bpf/statsolly/fs_io.c](../bpf/statsolly/fs_io.c)). The real attach target is set from Go at load time (`fsPlanProbes` / `keepFsPrograms` in [fs_tracer.go](../pkg/internal/statsolly/ebpf/fs_tracer.go)). A filesystem's cache= variants reuse the same program names (they are all the same `fs_type`), each in its own `FsIo` collection pointed at a different kernel symbol.

#### fentry vs kprobe attach

Per filesystem and per symbol, OBI prefers `fentry`/`fexit` over classic `kprobe`/`kretprobe`. For a module with its own BTF (`/sys/kernel/btf/<module>`), the symbol must resolve by name in that module's parsed BTF, not just the directory existing: a static function can be entirely missing from its own module's BTF even when other functions of the same module are there, as CIFS's `cache=loose` `read_iter`/`write_iter` are on the lab's kernel. For the built-in filesystems (ext4/xfs/btrfs), which have no module BTF of their own, the symbol resolves in the kernel's own (vmlinux) BTF instead. When neither resolves, OBI falls back to kprobe/kretprobe; this is also the path exercised on RHEL8-family kernels (4.18 + eBPF backports), which lack `CONFIG_DEBUG_INFO_BTF_MODULES` altogether (`fentryCapable` in [pkg/internal/statsolly/ebpf/fs_probes.go](../pkg/internal/statsolly/ebpf/fs_probes.go)). A module whose BTF cannot be parsed at all is treated as capable, leaving the load itself as the final word. The fallback attaches with the kernel's default kretprobe `maxactive`, so under high filesystem concurrency some return probes are dropped and their operations go unrecorded; `fentry`/`fexit` has no such limit.

#### Runtime requirements

- **No tracefs mount is needed.** The block probes attach as raw tracepoints decoded through kernel BTF. Only when the kernel's BTF does not say where a request's disk lives does OBI fall back to the classic tracepoints, which need `/sys/kernel/tracing` mounted into the container; the log then says `neither debugfs nor tracefs are mounted`.
- **`hostPID: true`.** The filesystem probes attribute I/O by host PID, and
  the same setting makes the host init's mount table readable at
  `/proc/1/mountinfo` (or, on OpenShift nodes with mount namespace
  encapsulation, the kubelet's own table). That is where the kubelet's volume
  mounts are listed, and it is how a device is resolved to a PersistentVolume.
  No `/var/lib/kubelet` mount is needed. Without
  `hostPID` OBI falls back to its own mount table, and then only volumes
  mounted into its own container can be attributed.

  > no kubelet volume mounts visible; persistent volume attribution needs hostPID so the host's and the kubelet's mount tables can be read

  (`WarnIfNoKubeletVolumeMounts` in [pkg/internal/statsolly/ebpf/mount_resolver.go](../pkg/internal/statsolly/ebpf/mount_resolver.go), called from `buildPipeline` in [pkg/statsolly/agent/pipeline.go](../pkg/statsolly/agent/pipeline.go).)
- **OpenShift** needs the `privileged` SCC bound to the DaemonSet's ServiceAccount; the official Helm chart does not grant it automatically.

#### Kubernetes RBAC for volume attribution

Resolving a mount to `k8s.persistentvolume.name`, `k8s.persistentvolumeclaim.name` and
`k8s.storageclass.name` is one lazy `get` of the PersistentVolume per distinct volume the node
mounts (`K8sPVCLookup` in [pkg/internal/statsolly/ebpf/pvc_resolver.go](../pkg/internal/statsolly/ebpf/pvc_resolver.go)):
the claim and storage class are read from the PV's `spec.claimRef` and `spec.storageClassName`,
and only while the PV is `Bound`. There is no watch, and no read of `persistentvolumeclaims` or
`storageclasses`. Pod attributes come from the usual pod informer.

```yaml
rules:
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get"]
```

Without it OBI logs once `persistent volume lookup forbidden` and the storage series carry the
pod but no PV, claim or storage class.

#### NFS client RPC metrics

The NFS client RPC metrics are counted in the kernel, never sent per event: one program on the sunrpc tracepoint `rpc_stats_latency` ([bpf/statsolly/nfs_rpc.c](../bpf/statsolly/nfs_rpc.c)), in a BPF object of its own (`NfsRpc`, [pkg/internal/statsolly/ebpf/nfs_tracer.go](../pkg/internal/statsolly/ebpf/nfs_tracer.go)), adds each RPC attempt to a hash map keyed by server address, NFS version, procedure and, with `storage_nfs_errors`, the error status; [stats/tracer_nfs.go](../pkg/internal/statsolly/stats/tracer_nfs.go) reads it through `statagg`. The program runs as `tp_btf` and falls back to `raw_tracepoint` when that cannot load or attach. It attaches when sunrpc is loaded: at startup, or within 30 seconds of the module loading (usually the node's first NFS mount, after OBI started); a load or attach that fails 3 times in a row disables the NFS metrics until OBI restarts. While the program is attached, sunrpc cannot be unloaded (`modprobe -r` fails). It needs the sunrpc module BTF (Linux 5.11+, RHEL 9); without it the NFS metrics stay off with one warning.

- **Wire bytes.** `obi.stat.nfs.client.io` (`storage_nfs_io`) counts the bytes of each attempt's call and reply as they cross the wire, RPC and XDR headers and every procedure included (`GETATTR`, `LOOKUP` and `COMMIT` too), so it is larger than the NFS bytes of `obi.stat.fs.io`, which count only the payload a process read or wrote. `network.io.direction` is `transmit` (sent to the server) or `receive` (from it). The procedure and version breakdown is opt-in here, unlike on the duration and errors metrics, to keep the default to one pair of series per server. Both reads come from the same kernel key as the other NFS metrics, so enabling it adds no map.
- **Per attempt.** The tracepoint fires once per RPC attempt, the way `/proc/self/mountstats` counts `ops` and `errors`: the histogram count per procedure equals the mountstats `ops` delta. A retry the server asks for (NFSv3 `JUKEBOX`, NFSv4 `DELAY` or `GRACE`) is a new attempt: it shows as an error (`EJUKEBOX`, `NFS4ERR_DELAY`) followed by a slow successful attempt whose duration includes the client's backoff (5 s after a `JUKEBOX`), not as a retransmit. `obi.stat.nfs.client.rpc.retransmits` counts the transmissions of an attempt after its first (`rq_ntrans - 1`).
- **Names.** NFSv2 and NFSv3 RPCs carry `onc_rpc.procedure.name` (`READ`, `LOOKUP`, from RFC 1094 and RFC 1813). NFSv4 RPCs are all `COMPOUND` on the wire, so they carry `nfs.operation.name` instead: the client operation (`READ`, `OPEN`, `OPEN_NOATTR`), read from the `NFSPROC4_CLNT_*` enum in the nfsv4 module BTF, whose order changes between kernels (the index in decimal when that BTF is missing). `onc_rpc.version` is an integer over OTLP. Not `rpc.client.call.duration`, which OBI emits for application-level ONC RPC.
- **Errors.** `error.type` is on the errors counter only, never on the histogram. Every NFS error counts, as mountstats counts them: `ENOENT` on `LOOKUP` or `OPEN` is normal traffic (every `O_CREAT` on NFSv3 produces one), and `EJUKEBOX` and `NFS4ERR_DELAY` are server back-pressure. Filter on the procedure (`READ`, `WRITE`) for error-rate alerts.
- **`server.address`** is the server's IP address as the mount option `addr=` shows it (the kernel's IPv6 compression, v4-mapped addresses kept mapped, `%<scope id>` after a link-local address), so it joins the filesystem metrics' `server.address`. With NFSv4.1+ trunking, a mount through a second address of a server already mounted shares the first mount's client, and both show the first address.
- **Buckets.** `stat_nfs_client_rpc_duration_histogram` defaults to the filesystem bounds plus 10 s, so an attempt that includes a 5 s backoff lands below `+Inf`. The union of the OTel and Prometheus bounds must have at most 32 entries (the kernel's explicit layout): more is a configuration error when `storage_nfs_duration` is on.
- **Memory and drops.** One shared hash map of 4096 keys (times `ebpf.maps.global_scale_factor`, about 0.8 MB with the explicit layout) whatever the number of CPUs, created only when an NFS metric is enabled. Idle keys are deleted after two polls. An attempt that finds the map full is counted in `nfs_rpc_drops` and logged (a warning the first time). With a pod attribute selected, the owner adds one key per submitting pod (per submitting process on cgroup v1, where the owner is a tgid), so the map is 8 times larger (32768 keys before the scale factor) and the warning says to deselect the attribute or raise the factor; a cgroup v1 node with many short-lived NFS processes can still fill it.
- **Pod attribution** (step 19) is opt-in: selecting `k8s.namespace.name`, `k8s.pod.name`, `k8s.container.name` or `k8s.owner.name` on an NFS metric attaches a second program, on the `rpc_task_begin` tracepoint, which records the submitting thread's cgroup v2 id, keyed by task pointer, in an LRU side map (`nfs_task_cg`); the main program looks it up at `rpc_stats_latency` and resolves it to a pod through the same cgroup index the block and filesystem layers use. This works because `rpc_task_begin` fires in the thread that calls `rpc_execute`, before an asynchronous task hands off to the `rpciod` workqueue, so it still names the submitter even though `rpc_stats_latency` usually runs in `rpciod`. On a cgroup v1 host, where `bpf_get_current_cgroup_id()` would return the root cgroup for every task, the owner is `task->tk_owner` (the submitting thread's tgid) instead, resolved by its `/proc/<tgid>/cgroup`, and the begin program is not attached. Without a pod attribute selected, the key keeps no owner and the begin program is never loaded. A pod that exits before its RPCs are decorated keeps its attribution: the owner was captured when the call was submitted, not read again later. O_DIRECT, fsync- and close-driven flushes, and reads carry the submitter's id; background writeback (dirty-page expiry, `sync`, memory pressure), COMMIT, DELEGRETURN and other state-manager calls are submitted by a kernel thread and have no pod (S0-c). The side map holds 262144 entries (a single entry without a pod attribute): each completed RPC leaves one, since nothing deletes it, so an entry lives a few seconds at 100k RPC/s; an RPC outstanding longer than that (a hung server) loses it. A key whose cgroup the index has not scanned yet, or whose pod the Kubernetes store does not know yet, is decorated again the next time it counts, so a new pod is attributed within one poll. A submitter whose cgroup the side map has no entry for (evicted under CPU pressure, or the begin program attached after the call started) counts as a miss in `nfs_task_cg_misses`, logged like the drops counter, and keeps owner 0.

#### Export path summary

| Layer | Default path | Per-event fallback |
|---|---|---|
| Block (`obi.stat.disk.*`) | kernel aggregation | `ebpf.storage_aggregation.disabled` (`OTEL_EBPF_STORAGE_AGGREGATION_DISABLED`), `stats.print_stats`, `storage_block_queue_depth`, or more than 32 histogram bounds; `pending_operations` is a snapshot of the in-flight map and the `storage_block_pod` counters are counted in the kernel on both paths |
| Filesystem (`obi.stat.fs.*`) | kernel aggregation | `ebpf.storage_aggregation.disabled` (`OTEL_EBPF_STORAGE_AGGREGATION_DISABLED`), `stats.print_stats`, or more than 32 histogram bounds |
| NFS (`obi.stat.nfs.client.*`) | kernel aggregation | none: more than 32 bounds is a configuration error |

The series and their counts are the same on both paths; only the cost and the histogram flavour differ. Per-event histograms export classic and native buckets on Prometheus (`prometheus_export.native_histogram.bucket_factor`); histograms aggregated in the kernel export **classic buckets only** on Prometheus, unless `ebpf.storage_aggregation.exponential_histograms` (`OTEL_EBPF_STORAGE_AGGREGATION_EXPONENTIAL_HISTOGRAMS`) or the OTLP `histogram_aggregation: base2_exponential_bucket_histogram` selects the exponential layout, which exports native (Prometheus) and exponential (OTLP) histograms only, at scale 2. Dashboards that use `histogram_quantile` over `_bucket` series work in the default case; with the exponential layout use `histogram_quantile(q, sum by (...) (rate(metric[5m])))` on the native histogram, without `le`.

#### Kernel aggregation and the cgroup index

Stats families moved to kernel aggregation count in eBPF hash maps (per CPU, or shared with atomic updates) instead of sending an event per operation, and [pkg/internal/statsolly/statagg](../pkg/internal/statsolly/statagg) reads those maps and exports their metrics through the same OTel and Prometheus exporters. Each kernel key (a device, cgroup or owner with its operation and errno) is decorated like a per-event stat — Kubernetes metadata, the PID decorator, `filters.stats` and the dynamic PID selector, in the pipeline's order — when it first counts, and that decoration is reused while the key keeps counting, until it is `RedecorateAfter` (30 s) old ([family.go](../pkg/internal/statsolly/statagg/family.go)). So where the per-event path applies each decision to the next event, kernel aggregation applies it up to 30 s late: a pod whose labels or owner change, a process the dynamic PID selector starts or stops selecting, or a cgroup the index learns about later keeps counting into its previous series (or being dropped, or kept) until its key is decorated again. A key whose decoration lacked something that may still come (a cgroup the index does not know yet) is decorated again the next time it counts.

Histograms are counted in the kernel in one of two bucket layouts, chosen at load time (`HistogramChoice` in [bounds.go](../pkg/internal/statsolly/statagg/bounds.go)). The explicit layout holds the union of the OTel and Prometheus exporters' bounds (at most 32), and the Prometheus exporter emits it as classic buckets only: the native part that the per-event histograms carry by default (`prometheus_export.native_histogram.bucket_factor`) is not there. The exponential layout is selected only when the OTel exporter's `histogram_aggregation` is `base2_exponential_bucket_histogram` or the user opts in, never because Prometheus native histograms are configured; it is emitted as OTel exponential histograms and Prometheus native histograms, with no classic buckets, at a fixed scale of 2 (at most 2): coarser than the schema 3 the Prometheus client picks per event with the default bucket factor, and than the OTel SDK's adaptive scale. The parity tests in [statagg/parity](../pkg/internal/statsolly/statagg/parity) assert this difference.

The block metrics (`obi.stat.disk.*`) are counted in the kernel by default. The completion program adds each finished request into `blk_agg` (bytes, service time sum and buckets, per device, request kind and errno) and, for reads and writes with a queue wait, `blk_q_agg`; [blk_agg_reader.go](../pkg/internal/statsolly/stats/blk_agg_reader.go) turns those keys into the same metrics, with the same conditions per metric, as the per-event path ([blk_io.c](../bpf/statsolly/blk_io.c), [block_agg.go](../pkg/statsolly/agent/block_agg.go)). Block requests are still sent one by one when the deprecated `obi.stat.disk.queue.depth` or `print_stats` is on, when `ebpf.storage_aggregation.disabled` is set, or when the enabled block histograms in the enabled exporters need more than 32 bounds together (a warning names the bucket settings). Aggregated OTLP histograms have no min and max. The maps are sized once, at load, from `ebpf.storage_aggregation.block_maps_budget_bytes` (8 MiB), counted for every possible CPU since each CPU has its own copy of a value: a key per emitted request kind and request-based disk, room for 32 disks attached later and 32 errno keys; the allocated size is logged. A completion whose key does not fit is not counted: `obi.bpf.map.insert.failures{bpf_map_name="blk_agg"}` counts it, and the first one is logged. `obi.bpf.storage.program.recursion.misses` counts the runs of a block program the kernel skipped because it, or another eBPF program, was already running on that CPU; each such completion leaves its request unmeasured.

Metrics keyed by cgroup resolve the cgroup id to a pod and container through `CgroupIndex` ([cgroup_index.go](../pkg/internal/statsolly/statagg/cgroup_index.go)), which walks the cgroup v2 hierarchy in the background (every 30 seconds, and at most once a second when a lookup meets an id it does not know) and never on a lookup.

The index finds the kubelet's cgroup for the default `--cgroup-root` (`/`: `kubepods.slice` with the systemd cgroup driver, `kubepods` with cgroupfs) and for `/kubelet`, the root kind nodes use (`kubelet.slice/kubelet-kubepods.slice`, `kubelet/kubepods`); the `/kubelet` layout is covered by test fixtures only, not by a cluster run. With any other `--cgroup-root` no cgroup id resolves to a pod, and pod-attributed series carry no pod labels. A node with no kubelet cgroup at all (no Kubernetes, or before the kubelet starts) resolves every id to no pod and picks the kubelet cgroup up when it appears.

#### Filesystem kernel aggregation

The filesystem programs add each completed operation into `fs_io_accum` ([bpf/statsolly/maps/fs_io_accum.h](../bpf/statsolly/maps/fs_io_accum.h); `fs_io_accum_exp` in the exponential layout) instead of sending a ring buffer event, and `NewFsAccumFamily` ([pkg/internal/statsolly/stats/tracer_fs_accum.go](../pkg/internal/statsolly/stats/tracer_fs_accum.go)) exports `obi.stat.fs.operation.duration`, `obi.stat.fs.io` and `obi.stat.fs.operation.errors` from it. A key is the calling thread's cgroup (`bpf_get_current_cgroup_id()`), the volume (superblock device and mount root inode), the PID namespace, the filesystem, the operation and the errno, so keys grow with containers x volumes x operations, not with processes; the value holds the latency sum, the bytes, the kernel buckets and a process that counted into the key lately. It is a hash map shared by all CPUs (8192 keys x `global_scale_factor`, about 1.5 MB), updated with atomics; a key that finds the map full is not counted, and the drop (`fs_drops`) is logged once and counted in the internal metric `obi.bpf.storage.dropped.operations` (`bpf.drop.reason="fs_accum_full"`; a start that could not be stored counts as `fs_start_failed`). Idle keys are deleted by the reader, except those of a removed container's cgroup while its tombstone lasts. The same internal metric also carries `bpf.drop.reason="kretprobe_miss"`: a kprobe-mode fallback's return probe (a filesystem whose fentry/fexit load failed, or `sync`/`syncfs`/`sync_file_range` on a kernel without the syscall wrapper's BTF, 2.4) ran out of concurrent instances (`RetprobeMaxActive`, or the kernel default without tracefs) and missed a return; that call's latency, and for an AGG key its sample, never reached userspace. Misses are biased toward long calls in flight during a storage stall. The internal metric `obi.bpf.storage.program.recursion.misses` (`bpf.probe.name` is the program) counts, for every block, filesystem, sync and NFS program, the executions the kernel skipped because another eBPF program was already running on the CPU (`bpf_prog_info.recursion_misses`, Linux 5.12+; older kernels report 0 and export nothing). It is read from the program's info every 30 seconds, never per event.

- On a cgroup v2 host a key's pod and container come from its cgroup through the cgroup index; the PID decorator then only resolves the volume. A cgroup of no pod (the node's services, kernel threads) or one the index does not know yet is decorated through the key's PID namespace and sample process, as each event is on the per-event path. On a cgroup v1 or hybrid host (no `/sys/fs/cgroup/cgroup.controllers`) every key's cgroup is the root, and every key is decorated that way.
- The start of each operation in flight is kept in the thread's task storage (`fs_start_task`) by the `fentry`/`fexit` programs: no hash lookup, and the kernel frees it with the thread. The `kprobe`/`kretprobe` programs, and `fentry`/`fexit` programs on kernels that do not let tracing programs use task storage (before 5.11), keep it in the `fs_start` hash map, whose entries older than 10 minutes (threads that died inside a call) are deleted every 30 seconds while some filesystem or the sync probes (`storage_fs_sync`: `sync` always, `syncfs` and `sync_file_range` on kprobes) use it.
- The filesystem metrics are exported per event, as before, when `ebpf.storage_aggregation.disabled` is set, when `stats.print_stats` prints the stats, or when the OTel and Prometheus bounds of `stat_fs_operation_duration_histogram` together exceed 32 (logged at startup). `ebpf.storage_aggregation.exponential_histograms` opts into the exponential layout.

### Known limitations

#### `src.port` may be reported as `0`

The `src.port` attribute (disabled by default) can be `0` in metrics whose probes fire near socket teardown: specifically `obi_stat_tcp_rtt_seconds` and `obi_stat_tcp_failed_connections_total`. Metrics measured while the socket is still active (retransmits) are not affected. The root cause is a kernel-side race between the application's `close()` path and RST processing.

When a socket **receives** a RST and is orphaned (`SOCK_DEAD` set), the kernel calls:

```
tcp_done()
  └── inet_csk_destroy_sock()
        └── inet_put_port()  <-- zeroes skc_num (the source port)
```

This happens outside the application's `close()` call. By the time `parse_sock_info` in [bpf/common/sockaddr.h](../bpf/common/sockaddr.h) reads `skc_num`, it is already `0`.

The RST **sender** is not affected because it goes through the normal application `close()` path where the port is still valid at probe time.

StatsO11y probes fire at different points relative to `inet_put_port()`, so the behaviour is not uniform across metrics. For example, `obi_kprobe_tcp_close_srtt` (kprobe on `tcp_close`) may still observe a valid port in some RST-receiver scenarios, while `obi_tracepoint_inet_sock_set_state` (tracepoint on `inet_sock_set_state`) consistently sees `0`. Metrics with `src_port="0"` still carry useful signal — `dst_port`, `src_address`, `dst_address`, `reason`, and `network_tcp_handshake_role` remain valid.

### Performance considerations

Some stat metrics attach to kernel functions that are called very frequently (e.g. `tcp_sendmsg`, `tcp_cleanup_rbuf` for TCP IO). These probes add a small overhead on every call, so the aggregate cost is proportional to the rate of TCP sends/receives on the node. Consider:

- If you need RTT, failed connections, or retransmits **without** TCP IO overhead, enable those individually (`stats_tcp_rtt`, `stats_tcp_failed_connections`, `stats_tcp_successful_connections`, `stats_tcp_retransmits`) instead of using the `stats` aggregate feature — `stats` includes `stats_tcp_io`, which fires on every `tcp_sendmsg` and `tcp_cleanup_rbuf` call.
- The `stats_events` ring buffer and the per-metric eBPF maps (e.g. `tcp_io_accum`) have default size limits; on nodes with a very large number of concurrent connections these can be resized via the `ebpf.*` configuration knobs if events start being dropped.

### Final notes

We decided to create a component separate from **AppO11y** and **NetO11y**, focusing only on **statistical metrics** calculated for all applications running on the node. This is because statistical metrics are important if correlated to all applications, and also because some hook points can cause unreliable PID calculations and lead to false positives.

The user can then filter the metrics in userspace using appropriate filters or even the collector.

## General notes

Span Metrics, Service Graph Metrics and the info metrics carry no `Section`, because user-provided attribute selection is disabled for them: they are very specific metrics with an opinionated format. They are still declared once — span metrics in [metric_spanmetrics.go](../pkg/export/attributes/metric_spanmetrics.go), service graph in [metric_service_graph.go](../pkg/export/attributes/metric_service_graph.go), the `target.info` family in [metric_internal.go](../pkg/export/attributes/metric_internal.go) — so that both exporters read the same definition — the `OTEL` exporter takes `.OTEL` and `.Unit`, the `Prometheus` exporter takes the `.Prom` name derived from them. Do not add a new metric of this kind as a literal in either exporter.

Resource attributes exported through Prometheus `target_info` / `traces_target_info` (named `target.info` / `traces.target.info` on the OTLP path) and the corresponding OTLP resources can be filtered with `attributes.select.resource`. By default, detected resource attributes are preserved. For example:

```yaml
attributes:
  select:
    resource:
      exclude:
        - cloud.account.id
        - cloud.resource_id
        - host.image.id
        - host.type
        - k8s.pod.name
```

**Note**: a metric is defined using the `Name` type, which carries the metric's `Section`, its `OTEL` name, `Unit` and instrument `Type`, plus the `Prom` name derived from those. Subsequently, that metric can be a counter, gauge, or other type.
