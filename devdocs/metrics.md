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
7. Register the metric in the schema registry: add the metric to the `metrics:` list in [schemas/obi/groups/network/metrics.yaml](../schemas/obi/groups/network/metrics.yaml).

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
7. Declare the metric and any new attribute in the schema registry, following [Adding telemetry](../schemas/obi/README.md#adding-telemetry): import an upstream metric OBI emits unchanged, or add it to the `metrics:` list of the domain's `metrics.yaml` with every attribute from step 3. Run `make lint-schema` and `make generate-schema-docs`.
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

12. Register the metric in the schema registry: add the metric to the `metrics:` list in [schemas/obi/groups/stats/metrics.yaml](../schemas/obi/groups/stats/metrics.yaml).

### Disk stats

`obi.stat.disk.service.duration`, enabled by the Config v2 stats feature `disk_service_duration`, is the service time of the block reads and writes, per whole disk (`system.device`: the I/O of a partition is its disk's) and direction (`disk.io.direction`). A raw tracepoint program records the last `block_rq_issue` of each request on OBI's clock, and its final `block_rq_complete` adds the duration to a histogram per device and direction in the kernel, which `DiskMapTracer` reads every `capture.engine.batching.batch_timeout`. A request is counted once, when its final completion takes the record of its issue, so without its wait in the I/O scheduler, or, if it was never issued, from the kernel's start of the request. Writes include write-zeroes and the zone appends of zoned devices, as in `/proc/diskstats`. Discards, passthrough commands and the I/O of bio-based devices (LVM, dm-crypt, md RAID, NVMe native multipath heads) are not measured.

`obi.disk.stacked` tells whether the device is built on other block devices, which also report its I/O: device mapper, md RAID and loop devices, or any device that sysfs lists slaves of. `obi.disk.volume.name` is the name of a device mapper device, as `/dev/mapper` lists it (e.g. `mpatha` for `dm-1`), and is absent for the other devices. The paths of a dm-multipath device (e.g. `sdb` and `sdc`) don't report the histograms, as the multipath device reports the same requests, so the multipath device isn't stacked.

The buckets are fixed, from 100 µs to 60 s (`DiskLatencyBounds` in [bucket.go](../pkg/export/bucket.go)), as the kernel buckets the durations. Both exporters export them as explicit histograms: exponential and native histograms don't apply.

Failed requests are in series of their own, with `error.type`: the name of the errno that they failed with (e.g. `EIO`, `ETIMEDOUT`), or `_OTHER` for the block statuses whose numbers changed between kernel versions, such as those of zoned and offline devices. It is absent on success.

`obi.stat.disk.operations` and `obi.stat.disk.service_time` (the stats features `disk_operations` and `disk_service_time`) are the count and the sum of the histogram, and `obi.stat.disk.io` (`disk_io`) the bytes of its successful requests, at their issue. A histogram series costs a series per bucket, while the two counters give the mean service time at one series each. The paths of dm-multipath devices report the counters, where a slow or failing path shows. The four features share the same probes.

`obi.stat.disk.flush.duration` (`disk_flush_duration`) is the duration of the cache flushes (`REQ_OP_FLUSH`) that the kernel sends the devices with a volatile write cache for the file syncs and the journal commits, per device and outcome, from their last issue to their completion on OBI's clock. It leaves out their wait for the dispatch, which the flush time of `/proc/diskstats` (from Linux 5.5, but not on RHEL 8) includes. It counts the flushes of the devices, not the syncs: the kernel sends a hardware queue one flush for all the syncs pending at the time. A write with a cache flush before or after it is timed without the flush. A device whose `queue/write_cache` is `write through` is sent no flush, and the bio-based devices pass theirs down to the devices below them. The block layer sends the flushes charged to no cgroup, so the histogram has neither a direction nor workload attributes: in Kubernetes, it reports only `k8s.cluster.name`. The disk probes measure the flushes whichever disk feature is enabled, and OBI drops them in user space when `disk_flush_duration` is not.

`container.id`, opt-in on the four metrics, is the container that the kernel charges the I/O to: the io controller cgroup of the request's first bio, as in `io.stat` and `io.max`. OBI takes the container ID from the name of the cgroup, `<id>` with the cgroupfs drivers and `<runtime>-<id>.scope` with the systemd ones, or from the name of its parent, as crun runs the processes of a container in a `container` child cgroup on cgroup v2, and systemd in a container in `init.scope`. The kernel records both names in `disk_cgroup_names` when it first counts the I/O of a cgroup, so this works outside OBI's cgroup namespace and after the cgroup is gone. The probes read the cgroup only when an enabled disk metric reports, or a stats filter matches, `container.id` or a Kubernetes attribute of the workload: otherwise the verifier leaves the read out, and `disk_cgroup_names` has a single entry.

In Kubernetes, OBI decorates the disk metrics with `k8s.cluster.name`, and with the pod of that container: `k8s.namespace.name`, `k8s.pod.name`, `k8s.container.name`, and the `k8s.owner.name` and `k8s.kind` of the top owner of the pod, which is the pod itself, of kind `Pod`, when it has no owner. The counters report the cluster, namespace, owner and kind by default, a series per workload, so the probes read the cgroup there by default. The histogram reports only the cluster by default, as each of its series costs a series per bucket, and OBI warns at startup when it is reported per pod or container. Over OTLP, the I/O charged to no pod has no workload attributes; OBI's Prometheus endpoint exposes them as empty labels.

When OBI is embedded with a dynamic selector (`instrumenter.WithDynamicSelector`), the disk stats are those that the kernel charges to the containers of the selected processes, and to the containers of the pods of the selected Kubernetes workloads, as the disk stats have no network endpoints to match the selection with. The probes then read the cgroup of every request.

### File sync stats

`obi.stat.fs.sync.duration`, enabled by the Config v2 stats feature `fs_sync_duration`, is the time that threads wait for file syncs, per sync type (`obi.fs.sync.type`) and outcome, on any filesystem: the writeback of their dirty pages, the journal commit and the cache flushes. The probes time the system calls `fsync(2)`, `fdatasync(2)`, `syncfs(2)`, `sync_file_range(2)` when it waits for the writeback, and `sync(2)` at the kernel's `ksys_sync`, and, outside of them, the kernel's `vfs_fsync_range`, `vfs_fsync` and `do_fsync` (a function of its own from Linux 6.12 and on RHEL 8), which serve the `O_SYNC` and `O_DSYNC` writes, `msync(2)` and io_uring: those are `fsync` or `fdatasync`, depending on whether they sync the metadata. Each sync is counted once, the innermost one when a stacked filesystem, like overlayfs, syncs the file below. The kernel accumulates the durations in `fs_sync_accum`, which `DiskMapTracer` reads with the disk stats, on the buckets of the disk histogram.

OBI times the syncs with fentry and fexit programs where the kernel BTF has the function and `struct bpf_tramp_image`, whose BPF trampolines are safe for the functions that sleep (Linux 5.12 and 5.10.28, RHEL 8 and 9). Elsewhere, and for a function whose programs can't be attached, it attaches the kprobe and the kretprobe of the function, and the kprobes of all of them when the fentry and fexit programs can't be loaded. The startup log tells the mechanism of each function, and warns when kprobes time some.

`error.type` is the errno that the sync returned, e.g. `EIO` or `ENOSPC`. The calls that fail before they sync anything are not counted: on an invalid file descriptor (`EBADF`), on a file that can't be synced, such as a pipe, a socket or a terminal (`EINVAL`, or `ESPIPE` for `sync_file_range(2)`), and `sync_file_range(2)` with invalid arguments. `container.id`, opt-in, and the Kubernetes attributes are those of the io controller cgroup of the thread that synced, found as for the disk stats, and the histogram reports only the cluster by default.

`obi.stat.fs.sync.operations` and `obi.stat.fs.sync.time` (the stats features `fs_sync_operations` and `fs_sync_time`, which share the probes) are the count and the sum of the histogram. As the disk counters, they report the cluster, namespace, owner and kind by default in Kubernetes: their ratio is the mean sync time of each workload, at two series each.

### NFS client stats

`obi.stat.nfs.client.procedure.duration`, enabled by the Config v2 stats feature `nfs_client_procedure_duration`, is the execute time of the RPCs of the kernel NFS client on the whole node, as `/proc/self/mountstats` counts it (nfsiostat's `avg exe`): from the start of each RPC to its completion, its wait for a transport slot, its retransmissions and the time of the server included, per server, procedure, NFS version and outcome. The probe runs at the `rpc_stats_latency` raw tracepoint of `sunrpc`, where the client counts each RPC in those statistics, and measures the RPCs of the NFS program, the `NULL` ping of each new client included. An RPC that the client restarts, as when the server asks it to retry later, is counted once per attempt, as in mountstats. The kernel accumulates the durations in `nfs_procedure_accum`, which `DiskMapTracer` reads with the disk stats, on the buckets of the disk histogram.

`server.address` is the server as its first mount on the node names it, without a DNS lookup: the host of `server:/export`, or its address when the mount names it by address. The procedure is `onc_rpc.procedure.name` for NFSv2 and NFSv3, as for the semantic conventions' `nfs.client.procedure.count`, and `nfs.operation.name` for NFSv4, as for `nfs.client.operation.count`: the NFSv4 client names its COMPOUND requests after their main operation, e.g. `READ` or `OPEN`. `onc_rpc.version` is the NFS version. The histogram has no workload attributes: in Kubernetes, it reports only `k8s.cluster.name`.

`error.type` is the status that the RPC completed with, before the client recovers from it: the name of its errno, e.g. `EIO`, `ESTALE` or `ENOENT`, or `_OTHER`, whose number OBI logs at debug level. It is not the failure of an application: the lookups of names that don't exist (`ENOENT` on `LOOKUP`) and the requests of a server to retry later are normal traffic.

The probe needs the `sunrpc` types in the vmlinux BTF, which `bpftool btf dump file /sys/kernel/btf/vmlinux | grep "STRUCT 'rpc_task'"` shows, and its tracepoint exists only while the `sunrpc` module is loaded, e.g. by the first NFS mount. When OBI starts before it, it logs that the NFS client stats wait for the module, and attaches the probe within 30 seconds of its loading, with another log: the RPCs before that are not counted. An attach that then fails for another reason disables the NFS client stats with a warning. While the probe is attached, `sunrpc` can't be unloaded.

### Known limitations

#### Disk stats

- Reads, writes and cache flushes are counted as in `/proc/diskstats`, except the requests in flight at startup or evicted from the in-flight map, those whose issue or completion program the kernel skipped as nested (the programs' `recursion_misses`), the rare ones whose in-flight record the kernel refused to delete because another map operation was running on the same CPU (about 3 in 8,000 on RHEL 8 kernels under emulation), and the requests of the devices whose `queue/iostats` is `0`, where the kernel counts only the cache flushes. The requests that complete without an issue, like the empty flush write of a file sync and the requests that the driver fails before their issue, are timed from the kernel's start of the request, as in `/proc/diskstats`. The kernel's write time also counts the wait of the writes in the I/O scheduler and, for a write with a cache flush after it, the flush.
- Failed requests are timed from their last issue, in their own series by `error.type`: a command that times out lands in the top buckets only if its last attempt does.
- The I/O of loop devices is also reported by the devices below them, as in `/proc/diskstats`. To add up a node's I/O, sum the devices with `obi_disk_stacked="false"`, and on the counters, which the paths of dm-multipath devices report too, leave out the devices with an `obi_disk_volume_name`.
- Devices are named from `/sys/dev/block` and, for the hidden paths of NVMe native multipath (e.g. `nvme1c0n1`), from `/proc/diskstats` on Linux 6.1 and later, refreshed every 30 seconds (a new volume that takes the numbers of a removed one keeps its volume name until then), or else by their `major:minor` numbers. The kernel keeps an entry per device, direction, outcome and cgroup, which OBI deletes after a minute without I/O: while its entries (4096 by default) are full, the I/O of new keys isn't counted, even on a device that has entries, and OBI logs a warning. Before Linux 5.14, the I/O that completes between the last read of an idle entry and its deletion is lost.
- The I/O that the kernel charges to no container has no `container.id` and no Kubernetes workload: that of its own threads, such as filesystem journal and metadata writes, of the cgroups below a container's child, and, on cgroup v2, of the containers whose cgroup doesn't have the `io` controller enabled, which is charged to an ancestor. Buffered writes are written back by kernel threads, and charged to the cgroup that dirtied them only on cgroup v2, on filesystems with cgroup writeback (ext2, ext4, btrfs, f2fs, xfs). Before Linux 5.18 and on RHEL 8, the block layer can merge the I/O of different cgroups into one request, charged to the cgroup of its first bio.
- The stats filters (`capture.network.stats.filters`) apply to every stats family: a filter on an attribute that a family doesn't have drops all its stats, as a filter on `system.device` drops the file sync and TCP stats, and one on `container.id` or `k8s.namespace.name` the TCP stats, unless the default value that a stat reads for an attribute it lacks (e.g. empty, `0` for a port, `::` for an address) passes the filter, as it does `match: "*"` or a `not_match` pattern that doesn't match it. A filter on an attribute that the cache flushes don't have, such as `disk.io.direction` or a workload attribute, drops them too, unless the value that they read for it, empty for these, passes the filter.
- Under dynamic application selection, the I/O charged to no container, the cache flushes included (OBI warns at startup when `disk_flush_duration` is enabled), and that of the selected processes outside containers are not reported, and no disk stat is while nothing is selected. Selecting Kubernetes workloads needs the Kubernetes metadata. The probes still measure the I/O of the other applications, which OBI drops in user space.
- If the probes of a storage feature can't be loaded or attached on a node, for example without `block_rq_issue` in the kernel BTF, or without the `sunrpc` types for the NFS client stats, OBI disables that feature at startup with a warning that names it and the reason, and the TCP stats keep running. A failed load first moves the file syncs to kprobes, then disables every enabled storage feature, as the kernel's error doesn't tell which program failed; a failed attach disables only its feature. A TCP stats probe that fails still stops OBI.

#### File sync stats

- A kretprobe misses the returns beyond the calls in progress at once that the kernel tracks for it, by default the number of CPUs on Linux 5.8, 5.10 and RHEL 8, and `max(10, 2 × CPUs)` from Linux 6.1 and on RHEL 9: where kprobes time the syncs, the syncs beyond it during a storage stall are not counted, nor, for up to 2 minutes, the syncs of their threads outside the system calls.
- On kernels that preempt kernel code (x86 Linux 7.0 and later by default, `preempt=full`, real time), the kernel skips an fentry or fexit program for the other tasks of a CPU while a task is preempted in it, and those syncs are not counted (the programs' `recursion_misses`).
- Before Linux 6.0, as on RHEL 8, a live patch of a function that fentry and fexit programs time fails with `EBUSY` while OBI runs: disable the file sync stats before applying it.
- The syncs of kernel threads, such as the NFS and SMB servers and the loop devices that sync their backing file, have no workload, so the syncs of a filesystem on a loop device are counted twice: for the application, and as `fsync` for the loop device. `ksys_sync` also syncs before a suspend.
- The writeback of dirty pages by the kernel is not measured, nor the `O_SYNC` and `O_DSYNC` writes of the filesystems that don't sync them, like tmpfs. `sync_file_range(2)` with `SYNC_FILE_RANGE_WRITE` alone, as the flush hints of PostgreSQL and RocksDB, doesn't wait for the writeback and is not counted.
- The stats filters, dynamic application selection and the disabling of the feature where its probes fail work as for the disk stats.

#### NFS client stats

- The mounts of a server (the same address, protocol and NFS version) share one client, which keeps the name of the first mount: a later mount that names the server otherwise, by an alias or by its address, is reported under that name until the server has no mount left on the node. Names longer than 95 characters are truncated. The data servers of pNFS layouts (files, flexfiles) report their own address, and possibly NFSv3, while mountstats counts their I/O under the metadata server. The mounts through a local TLS proxy, as those of the EFS utils (stunnel, efs-proxy), all report `127.0.0.1`.
- The RPCs that never got a transport slot, as during an outage of the server, are counted neither by OBI nor by mountstats. From Linux 6.12, a client built with `CONFIG_NFS_LOCALIO` reads and writes the files of a server on the same host without RPCs, which are not counted. Mountstats repeats the RPCs of the client of a server, such as its lease and session RPCs, in every mount of that server, while OBI counts them once per server.
- On kernels that preempt kernel code, the kernel can skip the probe as it skips the file sync programs, and those RPCs are not counted (the program's `recursion_misses`).
- A filter on `server.address`, `onc_rpc.procedure.name`, `onc_rpc.version` or `nfs.operation.name` drops the TCP, disk and file sync stats, and a filter on a disk, file sync, TCP or workload attribute drops the NFS client stats, unless the default value that a stat reads for an attribute it lacks passes the filter (see the disk stats).
- Under dynamic application selection, the NFS client stats are not reported, and their probe isn't loaded: OBI warns at startup when `nfs_client_procedure_duration` is enabled.

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
- The disk probes fire on every block request issue and completion, so their cost grows with the IOPS of the node, at less than 1 µs of CPU per request on a 4-vCPU VM: `capture.network.stats.enabled: true` alone doesn't enable them. They send no event per request, so the export cost grows with the number of series. The requests in flight are kept in an LRU map of 16384 entries by default, and at least 256 per possible CPU. Reading the cgroup of the requests costs about 0.08 µs of CPU more per request, and `disk_cgroup_names` keeps the names of up to 8192 cgroups, at 256 bytes each.
- The file sync probes fire on every file sync. `fs_sync_accum` keeps a histogram per sync type, outcome and cgroup (4096 entries), and `fs_sync_start` the syncs in progress, sized like the requests in flight; both have a single entry when the feature is off. The kprobes are loaded with the fentry and fexit programs, as their fallback.
- The NFS client probe fires on every RPC of the kernel NFS client, where it reads the names of the server and of the procedure and updates a hash map: a run takes about as long as a run of a block request probe (0.7 to 1.3 times as long in the same emulated VMs, and up to about twice as long on a kernel that preempts kernel code). `nfs_procedure_accum` keeps a histogram per server, procedure, version and outcome (4096 entries, about 1.3 MiB), and has a single entry when the feature is off. A server and NFS version have about 30 to 60 keys, at 19 series each, so about 0.6k to 1.1k series per server and node, which don't grow with the workloads.

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
