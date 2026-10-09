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
    - for a TCP probe, which is required, add an entry to the appropriate `kprobes`/`kretprobes`/`tracepoints`/`raw tracepoints` slice in `attachTCPProbes`, with `enabled` driven by the `features.StatsXxx()` predicate added in step 4, and add its program to `tcpToDisable` in `NewStatsFetcher` when that predicate is false. The programs of that list are replaced with a no-op stub before loading, preventing unused eBPF code from being loaded into the kernel;
    - for a storage probe, which is optional, attach it in `storageProbes.attach` in [storage_probes.go](../pkg/internal/statsolly/ebpf/storage_probes.go): a storage feature whose probes can't be attached is disabled, with the reason, and the other stats keep working. Attach the completion or return probes before the start or entry probes, so that no start is recorded without its completion being measured. Add its program to the programs to disable of its feature, which `storageProbes.programsToDisable` gathers (`diskProgramsToDisable`): otherwise it is loaded even when its feature is off, and when the verifier rejects it, loading the stats programs without the storage ones fails too, and the TCP stats are lost. Start the names of its maps with `storageMapPrefix` (`disk_`): the storage maps that no loaded program uses are created with a single entry, so userspace must only use the maps of the features whose programs are loaded.
6. In the [tracer_ringbuf.go](../pkg/internal/statsolly/stats/tracer_ringbuf.go), simply add a function that handles that metric. This function will convert the event to a `ebpf.Stat`.
7. Then, modify the `Stat` struct accordingly, by adding a data structure containing all the necessary fields. For example `TCPRtt` struct.
8. Define the metric `Name` in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go), wrapping it in `metric(...)` and setting its `Section`, `OTEL`, `Unit` and `Type`. Never set `Prom` by hand: it is derived from the other three.
9. Register the metric in `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), wiring it to the relevant `AttrReportGroup`s (e.g. `statsAttributes`, `statsKubeAttributes`) and any ad-hoc attributes it needs.
10. If new attributes are introduced, add the matching getters to `StatGetters` in [pkg/internal/statsolly/ebpf/stat_getters.go](../pkg/internal/statsolly/ebpf/stat_getters.go).
11. Wire up the metric in the exporters. Each exporter owns one observe-method per stat type (e.g. `observeTCPRtt`, `observeTCPFailedConnections`) that translates the `ebpf.Stat` into a given observation, with its attribute set resolved through the attribute selector's `For` method:

    - `newStatsReporter` in [pkg/export/prom/prom_stats.go](../pkg/export/prom/prom_stats.go) for Prometheus
    - `newStatMetricsExporter` in [pkg/export/otel/metrics_stats.go](../pkg/export/otel/metrics_stats.go) for OTEL

12. Register the metric in the schema registry: add a `metric.*` entry in [schemas/obi/groups/stats/metrics.yaml](../schemas/obi/groups/stats/metrics.yaml).

A metric that the kernel accumulates in a map instead of sending events through `stats_events`, like `obi.stat.disk.service.duration`, is read by `DiskMapTracer` in [tracer_disk.go](../pkg/internal/statsolly/stats/tracer_disk.go) instead of step 6, and its kernel histogram is exported by `kernelHistogramProducer` (OTEL) and `kernelHistogramVec` (Prometheus) in step 11. The storage features are excluded from `FeatureAll` in step 4 and must be named: their probes fire on every block request. Each storage metric is also listed, in `diskStatSections` in [stat_filter.go](../pkg/statsolly/agent/stat_filter.go), so that the `filter.stats` filters on its attributes apply to the storage stats. Its section starts with `obi.stat.`, as those of all the stat metrics, and a test fails until it is listed.

### Storage stats

The storage stats are optional, as OBI's optional tracers are: when the probes of an enabled storage feature can't be loaded or attached on a node, because of a kernel without the BTF that they need, or a BPF verifier that rejects them, that feature is disabled on the node with a warning at startup that names it and the reason, and OBI and the other metrics keep working. The TCP stats remain required.

`obi.stat.disk.service.duration` is measured from the last `block_rq_issue` to the final `block_rq_complete` tracepoint of each request, so it is the time the device took to serve it, and a requeue or a retry restarts it: it excludes the time requests wait in the I/O scheduler or in blk-throttle before being issued. The kernel accumulates the latencies in a histogram per device, direction and outcome, which `DiskMapTracer` reads periodically.

The `filter.stats` attribute filters apply to the TCP and the storage stats separately. The TCP stats are matched against every filter but those on the attributes that the storage stat metrics have and the TCP stat metrics don't, such as `system_device`. A storage stat is matched only against the filters on the attributes of its own metrics: a filter on a TCP attribute, such as `dst_port`, doesn't drop the storage stats. The storage stat metrics are listed in `diskStatSections` in [stat_filter.go](../pkg/statsolly/agent/stat_filter.go).

#### Storage error types

The disk metrics carry an `error.type` on the requests that failed, and none on those that succeeded. It is the name of the errno that the kernel failed the request with, or `_OTHER` when the failure has no name.

The disk metrics name the status of each failed block request after its errno in the kernel's table of block statuses (`blk_errors`), whose description is also what the kernel logs, e.g. `critical medium error, dev sda, sector …` for `ENODATA`:

| `error.type` | Kernel log | Meaning |
| --- | --- | --- |
| `EIO` | `I/O error` | The generic failure. |
| `ETIMEDOUT` | `timeout error` | The request timed out. |
| `ENOLINK` | `recoverable transport error` | The path to the device failed: another path may succeed. |
| `EREMOTEIO` | `critical target error` | The device rejected or failed the command. |
| `ENODATA` | `critical medium error` | The device couldn't read or write its media. |
| `EBADE` | `reservation conflict error` (`critical nexus error` before Linux 6.5) | Another host holds a persistent reservation of the device. |
| `EILSEQ` | `protection error` | The protection information of the data, its integrity check, failed. |
| `ENOSPC` | `critical space allocation error` | The device has no space left, like a thin-provisioned device that is full. |
| `EOPNOTSUPP` | `operation not supported error` | The device doesn't support the operation. |
| `ENOMEM`, `EBUSY` | `kernel resource error`, `device resource error` | The kernel or the device lacked resources. |
| `EAGAIN` | `nonblocking retry error` | A request that must not wait would have had to. |
| `EREMCHG` | `dm internal retry error` | Device mapper retries the request. |
| `_OTHER` | | A block status whose number changed between kernel versions, such as those of zoned devices and of offline devices. Before Linux 5.16 (and on RHEL 8), requests report it by its errno instead. |

A dm-multipath device retries on another path the failures of its paths that another path may not have, all but `EOPNOTSUPP`, `ENOSPC`, `EREMOTEIO`, `EBADE`, `ENODATA` and `EILSEQ`: it reports them only when no path is left and it doesn't queue the I/O until a path comes back (`queue_if_no_path`).

#### Storage stats under dynamic application selection

When OBI is embedded with a dynamic selector (`instrumenter.WithDynamicSelector`), the storage stats are not reported, and their probes are not loaded: the dynamic selection matches the stats to the selected applications by their network endpoints, which the storage stats don't have. OBI logs a warning at startup when a storage stat metric is enabled under dynamic selection.

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

#### Block I/O (disk) stats

- Reads and writes are reported per direction. Writes include write-zeroes (`blkdiscard -z`, mkfs) and, on zoned devices, zone appends, as in `/proc/diskstats`, and their durations count in the write latency, as in iostat's `w_await`. Cache flushes, discards, passthrough requests, write-same (before Linux 5.18) and zone management (reset, open, close, finish) are not measured.
- Writes are counted as in `/proc/diskstats`. A write with a cache flush before or after it, like the journal commits of fsync, is completed twice by the kernel's flush sequence and counted once, at the end of the sequence: its duration includes the flush after it. The empty flush of an fsync, which the kernel completes without issuing it to the device, is a write without bytes: having no issue, it is timed from the kernel's start of the request, its allocation (from Linux 6.13, the start of its accounting), as in `/proc/diskstats`. Like the kernel, OBI doesn't count it on devices that don't keep I/O statistics, except on the kernels that number their request flags with macros (Linux 6.10 and earlier, and RHEL 8, but not RHEL 9.6), where it counts it if the device uses an I/O scheduler.
- Failed requests are counted too, with an `error.type` (see [Storage error types](#storage-error-types)), by the histogram.
- Filesystems without a block device (NFS, CIFS, FUSE, virtiofs) never reach the block layer, so they are not observed.
- Stacked devices, built on other block devices, report the same I/O as the devices below them, and have `obi.disk.stacked` set to `true`: to count the I/O once, add up the devices where it is `false`, and the dm-multipath devices, whose paths don't report their I/O. The device mapper devices also have their name, as `/dev/mapper` lists it, in `obi.disk.volume.name` (e.g. `mpatha` for `dm-1`). The kernel gives a new device mapper device the lowest free minor, often that of a volume just removed, and OBI keeps the names for 30 seconds: the I/O of a new volume can carry the name of the removed one for up to 30 seconds, while its `system.device` (`dm-<minor>`) is right. Request-based stacked devices (loop, dm-multipath) are measured like any device. Bio-based ones (device mapper volumes like LVM and dm-crypt ones, md RAID volumes, the head devices of NVMe native multipath, DRBD devices) never issue requests of their own, so they are not measured: their I/O is reported on the devices below them. The path devices below an NVMe native multipath head (e.g. `nvme1c0n1`) are request-based disks that sysfs hides, without a `/sys/dev/block` entry: from Linux 6.1 on, OBI takes their names from `/proc/diskstats`. Older kernels list them there without their numbers, so their metrics keep the numbers (e.g. `259:1`).
- The paths of a dm-multipath device carry the I/O of the multipath device, which reports it too, so they don't report `obi.stat.disk.service.duration`: the histograms of every path would multiply the series of each LUN, whose latency distribution is reported once, on its dm-multipath device, where `obi.disk.stacked` is `true`, so the latency queries of the LUNs must not filter on `obi.disk.stacked="false"`. The paths of a dm-multipath device are the disks that it holds, a device mapper device whose `/sys/block/<device>/dm/uuid` starts with `mpath-`. OBI refreshes what it knows of the paths every 30 seconds.
- Each request is timed from its issue to its completion on OBI's own clock, recorded by the probes. The kernel's own timestamps (`rq->io_start_time_ns`, `rq->start_time_ns`) are not used: from Linux 6.9, and on RHEL 9.6, they read the clock that the submitter's block plug cached, which can be hundreds of milliseconds old for writeback and batched asynchronous I/O. A request that the kernel requeues and issues again is timed from its last issue. The requests whose issue OBI didn't see, because they were issued before OBI started or because the kernel skipped the probe while another BPF program ran on the CPU, are still counted, timed from the kernel's own issue time (or, on queues where the kernel doesn't record it, from its start of the request), so their duration can carry the error above.
- The buckets are fixed, and can't be configured: the kernel buckets the latencies with the bounds of `DiskLatencyBounds` in [bucket.go](../pkg/export/bucket.go), from 100 µs to 60 s, and both exporters export those buckets. The exporters add up the requests of each kernel bucket into the same bucket of their histograms, once per read of the kernel maps, so these histograms are exported with explicit buckets: the exponential histograms of the OTLP exporter (`histogram_aggregation`) and the native histograms of the Prometheus exporter don't apply to them, as their resolution is the kernel's.
- The tracepoint arguments changed across kernel versions (and some of those changes were backported to older kernels), so OBI reads them from the kernel BTF instead of guessing from the kernel version. If the kernel BTF lacks the tracepoint prototypes, the disk probes are not loaded and a warning is logged; the other stat metrics keep working.

### Performance considerations

Some stat metrics attach to kernel functions that are called very frequently (e.g. `tcp_sendmsg`, `tcp_cleanup_rbuf` for TCP IO). These probes add a small overhead on every call, so the aggregate cost is proportional to the rate of TCP sends/receives on the node. Consider:

- If you need RTT, failed connections, or retransmits **without** TCP IO overhead, enable those individually (`stats_tcp_rtt`, `stats_tcp_failed_connections`, `stats_tcp_successful_connections`, `stats_tcp_retransmits`) instead of using the `stats` aggregate feature — `stats` includes `stats_tcp_io`, which fires on every `tcp_sendmsg` and `tcp_cleanup_rbuf` call.
- The `stats_events` ring buffer and the per-metric eBPF maps (e.g. `tcp_io_accum`) have default size limits; on nodes with a very large number of concurrent connections these can be resized via the `ebpf.*` configuration knobs if events start being dropped.
- The disk probes (`stats_disk_service_duration`) fire on every block request issue and completion, so their cost grows with the node's IOPS. They don't send one ring buffer event per request: the kernel accumulates the latencies in a histogram per device, direction and outcome (`disk_io_accum`), which userspace reads every `ebpf.batch_timeout`. The exporters add the count of each kernel bucket to their histograms at once, so their cost grows with the number of series, not with the IOPS. On a 4-vCPU VM, the block request probes cost about 0.7 µs of CPU per request, as OBI records the issue of each request itself. For these reasons they are not part of the `stats` aggregate, nor of `all` and `*`, and must be enabled explicitly.
- The starts of the block requests in flight are kept in an LRU map of 16384 entries, and of 256 entries per CPU on hosts with more than 64 CPUs. Before Linux 6.16, except from 6.12.39, 6.6.99, RHEL 9.8 and RHEL 10.2, which have the fix, each CPU keeps up to 128 free entries of an LRU map for itself, and once those hold most of the map, a CPU that needs an entry evicts a request in flight, which then goes uncounted.

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
