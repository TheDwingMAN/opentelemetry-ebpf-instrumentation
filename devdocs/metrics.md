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

The storage stats (disk, file sync and NFS client) are optional, as OBI's optional tracers are: when the probes of an enabled storage feature can't be loaded or attached on a node, because of a kernel without kprobes, without the BTF that they need, or a BPF verifier that rejects them, that feature is disabled on the node with a warning that names it and the reason, repeated every hour, and OBI and the other metrics keep working. When the kernel BTF has their types, the NFS client probes of a node whose `sunrpc` and `nfs` modules are not loaded yet are reported in the same warning, as waiting for them, and are attached when the modules are loaded (see [NFS client stats](#nfs-client-stats)). The TCP stats remain required.

`obi.stat.disk.operation.duration` is measured from the `block_rq_issue` to the final `block_rq_complete` tracepoint of each request, so it is the time the device took to serve it: it excludes the time requests wait in the I/O scheduler or in blk-throttle before being issued. Other limitations:

- Reads and writes are reported per direction by the disk I/O metrics. Cache flushes are reported by `obi.stat.disk.flush.duration`, and discards (including secure erases) by `obi.stat.disk.discard.duration` and `obi.stat.disk.discard.io`. Write-zeroes and passthrough requests are not measured.
- Writes and flushes are counted as in `/proc/diskstats`. A write with a cache flush before or after it, like the journal commits of fsync, is completed twice by the kernel's flush sequence and counted once, at the end of the sequence: its duration includes the flush after it. The empty flush of an fsync, which the kernel completes without issuing it to the device, is a write without bytes, timed from its allocation.
- Filesystems without a block device (NFS, CIFS, FUSE, virtiofs) never reach the block layer, so they are not observed.
- Stacked devices, built on other block devices, report the same I/O as the devices below them, and have `obi.disk.stacked` set to `true`: to count the I/O once, add up the devices where it is `false`. Request-based stacked devices (loop, dm-multipath) are measured like any device. Bio-based ones (device mapper volumes like LVM and dm-crypt ones, md RAID volumes, the head devices of NVMe native multipath, DRBD devices) never issue requests of their own: with `stats_disk_stacked_volumes` (part of `stats_disk`), their bios are measured from their submission until their completion, and reported on the volume (e.g. `dm-0`, whose name is in `/sys/block/dm-0/dm/name`). Their operations are bios, which the devices below may split or merge into a different number of requests. md RAID volumes are measured from Linux 5.15 on, and on RHEL 8.9+ and 9.6: older kernels don't trace the completion of their bios. The path devices below an NVMe native multipath head (e.g. `nvme1c0n1`) are request-based disks that sysfs hides, without a `/sys/dev/block` entry: from Linux 6.1 on, OBI takes their names from `/proc/diskstats`. Older kernels list them there without their numbers, so their metrics keep the numbers (e.g. `259:1`).
- Some drivers handle bios themselves for disks that are not built on other block devices, like the PowerFlex (ScaleIO) SDC (`scinia`), zram, pmem or brd: `stats_disk_stacked_volumes` measures their bios too, and they have `obi.disk.stacked` set to `false`. OBI tells a bio-based device by its queue: it has no `mq` directory, and no I/O scheduler (`/sys/block/<device>/queue/scheduler` is `none` or, on recent kernels, absent), unlike request-based devices. It refreshes the list every 30 seconds.
- Requests issued before OBI started are not measured.
- The kernel buckets the latencies of all the disk histograms with the same boundaries: the union of the `stat_disk_operation_duration_histogram`, `stat_disk_queue_duration_histogram`, `stat_disk_flush_duration_histogram` and `stat_disk_discard_duration_histogram` buckets of the enabled metrics in the enabled exporters. It keeps up to 24 distinct boundaries, and so do the file sync and NFS histograms: with more, it keeps 24 of them spread across the range, logs a warning, and the histograms of the exporters are approximated from the closest kernel buckets. Boundaries of 0 or less are ignored, as no latency falls under them.
- The exporters add up the requests of each kernel bucket into their own buckets, once per read of the kernel maps, so these histograms are exported with explicit buckets: the exponential histograms of the OTLP exporter (`histogram_aggregation`) and the native histograms of the Prometheus exporter don't apply to them, as their resolution is the kernel's.
- The tracepoint arguments changed across kernel versions (and some of those changes were backported to older kernels), so OBI reads them from the kernel BTF instead of guessing from the kernel version. If the kernel BTF lacks the tracepoint prototypes, the disk probes are not loaded and a warning is logged; the other stat metrics keep working.

The latency histograms of the storage stats (disk, file sync and NFS client) multiply their series by the number of buckets, so their workload attributes (`k8s.*`, `container.id`) are opt-in: select them in `attributes.select` to get a latency distribution per workload. The counters carry the workload by default, and the ratio of a time counter to its count counter (e.g. `obi.stat.disk.operation_time` / `obi.stat.disk.operations`) is the mean latency of each workload.

The disk metrics are charged to the workload that owns the I/O: the cgroup that the request's first bio is charged to, which is the cgroup the kernel also uses for `io.stat` and `io.max`. OBI reads the cgroup name in the kernel, takes the container ID from it, and decorates the metrics with the pod and container of that ID. Limitations:

- Only cgroups named after a container ID are attributed: `<id>` (cgroupfs drivers) or `<runtime>-<id>.scope` (systemd drivers, e.g. `cri-containerd-<id>.scope`). When the `io` (cgroup v2) controller is not enabled down to the container cgroups, the I/O is charged to an ancestor cgroup, such as the pod slice, and is reported without workload attributes.
- Some I/O is never charged to a workload, and is reported without workload attributes: filesystem journal and metadata I/O issued by kernel threads (e.g. `jbd2`), RAID resync and device-mapper internal I/O, and flush requests.
- Buffered writes are written back later by kernel threads. They are charged to the workload that dirtied the pages only on cgroup v2, and only on filesystems with cgroup writeback support (ext2, ext4, btrfs, f2fs, xfs). Otherwise they are reported without workload attributes.
- Before Linux 5.18 (and on RHEL 8), the block layer can merge the I/O of different cgroups into the same request. OBI charges a merged request to the cgroup of its first bio.
- `obi.stat.disk.io` counts the bytes of the requests that completed successfully, as issued to the device. The histogram and `obi.stat.disk.operations` count failed requests too, with an `error.type`.

Over OTLP, the storage stats (disk, file sync, NFS client and pod volume) omit the workload attributes of the I/O that is reported without a workload, and `k8s.cluster.name` when the cluster name is unknown. OBI's Prometheus endpoint exposes them as empty labels, which Prometheus treats as missing.

`obi.stat.disk.queue.duration` is the time requests wait between their allocation and their issue to the device, in the I/O scheduler or in the dispatch queues. Together with `obi.stat.disk.operation.duration`, it splits the time an I/O takes in the block layer like iostat's `await` does: the average number of requests waiting or in service (iostat's `aqu-sz`) is the rate of the sum of both histograms. Limitations:

- The kernel only timestamps the allocation of requests on devices that keep I/O statistics (`/sys/block/<device>/queue/iostats`) or use an I/O scheduler. The wait of other requests is not measured.
- Waits before the allocation, such as those of blk-throttle (`io.max`) and of writeback throttling, are not included.

`obi.stat.disk.pending_operations` is the number of reads and writes that each device is serving, as the kernel counts them for iostat (`/proc/diskstats` and `/sys/block/<device>/inflight`), sampled every `ebpf.batch_timeout`. The kernel counts flushes and discards in flight as writes. Before Linux 5.11 (including RHEL 8), it doesn't count the requests of a partition on its disk: the disk then reports the larger of its own requests and the sum of those of its partitions. It is reported for every device that has requests in flight or completed reads or writes recently.

The opt-in `obi.disk.partition` attribute is the partition that the I/O targets, such as `nvme0n1p1`, while `system.device` stays the whole disk. It is omitted for I/O on the whole disk and for requests that target no partition, like flushes. Before Linux 5.11 (including RHEL 8), the kernel only records the partition of requests on devices that keep I/O statistics, and it records the partition that holds the sectors of the request, as it does for its own statistics: I/O on the whole disk that falls within a partition is reported with that partition.

#### File sync stats

`obi.stat.fs.sync.duration` measures the sync system calls, `fsync(2)`, `fdatasync(2)`, `sync(2)`, `syncfs(2)` and `sync_file_range(2)`, and the calls to the kernel's `vfs_fsync_range` function (and, on kernels that have it as a function of its own, Linux 6.12 and later, `do_fsync`) outside of them. Those serve `O_SYNC` and `O_DSYNC` writes, `msync(2)` with `MS_SYNC`, and the io_uring equivalents of `fsync(2)`. It works on any filesystem, including network filesystems. It is the time an application waits for its data to be durable, which includes queueing and journaling, unlike the block I/O metrics.

`obi.stat.fs.sync.operations` and `obi.stat.fs.sync.operation_time` count the same syncs and add up their durations, per workload: their ratio is the mean sync time of each workload, without the series of a histogram per workload. They are enabled with `stats_fs_sync_operations` and `stats_fs_sync_operation_time`, and `stats_fs_sync` enables the three file sync metrics.

The `obi.fs.sync.type` attribute tells the system call apart: syncs outside of the system calls are reported as `fsync` or `fdatasync`, depending on whether they sync the metadata too. The opt-in `system.filesystem.mountpoint` and `system.filesystem.type` attributes are the filesystem of the synced file, from the mounts of the host (`/proc/1/mountinfo`), or of the kubelet's mount namespace, as for the [pod volume devices](#pod-volume-devices): when a filesystem is mounted more than once, its mount of the root of the filesystem with the shortest path. `sync(2)` syncs every filesystem, so it has no mountpoint. Limitations:

- It needs kprobes. On kernels without them, it is disabled with a warning, and the other metrics keep working. The system call probes are optional: when one can't attach, the syncs of that system call are measured through the kernel functions, if they call them.
- A sync is charged to the workload of the thread that called it, through the cgroup of its `io` controller (`blkio` on cgroup v1), so the same cgroup name rules as the disk metrics apply.
- Stacked filesystems, like overlayfs, sync the file of the filesystem below them: outside of the system calls, the sync of the lower file is measured, once per call, with the filesystem of the lower file.
- The writeback of dirty pages by the kernel is not measured.

[`contrib/grafana/obi-disk-stats.json`](../contrib/grafana/obi-disk-stats.json) is a Grafana dashboard of the disk, file sync, NFS client and pod volume metrics.

#### Pod volume devices

`obi.stat.k8s.pod.volume.device` links the pods to the disks of the block I/O metrics: it is 1 for each disk that a volume that a pod of the node mounts from a PersistentVolumeClaim is on, with the pod, the volume, the claim, the PersistentVolume, the device the volume is mounted from (`obi.disk.volume.device`) and the disk (`system.device`). A volume on a stacked device, like an LVM volume over two disks, has a series for each disk, and a volume on a loop device has the disks of the filesystem that holds the file of the loop device. When a pod no longer mounts a volume, its series are reported once more with 0. For example, the bytes read from the disks of each PersistentVolumeClaim, by any workload:

```promql
max by (k8s_persistentvolumeclaim_name, system_device) (obi_stat_k8s_pod_volume_device == 1)
  * on (system_device) group_left
sum by (system_device) (rate(obi_stat_disk_io_bytes_total{disk_io_direction="read"}[5m]))
```

OBI resolves the volumes every 30 seconds, from the Kubernetes metadata and the host:

- It watches the PersistentVolumes, which needs `list` and `watch` permissions on `persistentvolumes`. Without them, OBI logs a warning and reports no volumes, and the rest of the Kubernetes metadata keeps working. With the Kubernetes metadata cache (`k8s-cache`), enable its `persistent_volumes` option instead.
- Only `Bound` PersistentVolumes are the volume of their claim: a `Released` one keeps referring to a claim that was deleted, whose name a new claim may have taken.
- It finds the device of a volume from where the kubelet mounts it for the pod, `<kubelet root>/pods/<pod UID>/volumes/<plugin>/<PersistentVolume>`, in the mount table of the host (that of PID 1). `hostPath` PersistentVolumes, which the kubelet doesn't mount, are found by their path on the host. OBI needs the host PID namespace, like for the other disk metrics. When pods of the node mount volumes from claims and no volume mount of the kubelet is visible, e.g. without the host PID namespace, OBI warns once (`no volume mount of the kubelet is visible`).
- When the kubelet runs in a mount namespace of its own, like with OpenShift's mount namespace encapsulation (`kubens.service`, off by default), the host doesn't see these mounts: OBI then reads the table of a process in the namespace that `kubens.service` pins at `/run/kubens/mnt`. To find it through `/proc/1/root` and the `/proc/<pid>/ns/mnt` of the other processes, OBI needs `CAP_SYS_PTRACE`, e.g. a privileged container.
- It finds the file of a loop device by its path on the host (`/sys/block/<loop device>/loop/backing_file`). The loop device is reported as the disk when its file was deleted, is on no block device, like on tmpfs, or isn't at that path on the host, like the file of a loop device set up in the mount namespace of a container.
- Volumes on no block device, like NFS or tmpfs ones, and on filesystems that don't report the device they are on, like Btrfs subvolumes, are not reported. Generic ephemeral volumes are not reported either.

#### Stacked volume disks

`obi.stat.disk.volume.device` (`stats_disk_volume_devices`, part of `stats_disk`) links the stacked volumes of the node to the disks of the block I/O metrics, whether pods mount them or not: it is 1 for each disk that a device mapper (LVM, dm-crypt, multipath), md RAID or loop device of the node is on, with the volume (`obi.disk.volume.device`, e.g. `dm-0`), its device mapper name (`obi.disk.volume.name`, e.g. `rhel-root`, as `/dev/mapper` names it, omitted for md RAID and loop devices) and the disk (`system.device`). OBI walks sysfs every 30 seconds, without any probe, from the volumes down to the disks like for the pod volume devices: a volume on partitions is on their disks, a volume over another stacked volume is on the disks of the bottom one, and a loop device is on the disks of the filesystem that holds its file. A loop device whose file is on no block device, like on tmpfs, has no series, and neither has a loop device that is not bound to a file. When a volume is removed, its series are reported once more with 0. For example, the bytes written to the disks of each device mapper volume, by any workload:

```promql
max by (obi_disk_volume_name, system_device) (obi_stat_disk_volume_device{obi_disk_volume_name!=""} == 1)
  * on (system_device) group_left
sum by (system_device) (rate(obi_stat_disk_io_bytes_total{disk_io_direction="write"}[5m]))
```

#### NFS client stats

`obi.stat.nfs.client.procedure.duration` measures the RPCs of the kernel NFS client (the `nfs` ONC RPC program, any NFS version) from the `rpc_stats_latency` tracepoint: the time from the start of each RPC to its completion, including its wait for a transport slot and its retransmissions, as `/proc/self/mountstats` counts it. `obi.stat.nfs.client.procedure.count` and `obi.stat.nfs.client.procedure.time` count the same RPCs and add up their durations, per workload, like the semantic conventions' `nfs.client.procedure.count` with the server, the outcome and the workload. `obi.stat.nfs.client.io` counts the bytes that the read and write RPCs transferred, from the `nfs_readpage_done` and `nfs_writeback_done` tracepoints. Limitations:

- The probes need the BTF of the `sunrpc` and `nfs` types, which are in the kernel BTF on some kernels and in the BTF of the `sunrpc` and `nfs` modules on others. When the kernel BTF has the types (check with `bpftool btf dump file /sys/kernel/btf/vmlinux | grep -E "STRUCT '(rpc_task|nfs_pgio_header)'"`), the modules can be loaded after OBI starts, e.g. by the first NFS mount: OBI warns that the NFS metrics wait for the tracepoints of the modules, and attaches the probes within 30 seconds after they are loaded, with an INFO log. The RPCs before that are not counted. When only the BTF of the modules has the types (Linux 5.11+), the modules must be loaded when OBI starts, e.g. by an NFS mount. Otherwise, OBI warns that the NFS metrics are disabled: e.g. on Linux 5.8 with `sunrpc` built as a module.
- The arguments of the tracepoints are checked in the BTF of the modules (Linux 5.11+). Older kernels are trusted from Linux 5.8, so the NFS metrics are disabled on RHEL 8 kernels without module BTF.
- An RPC is charged to the workload of the thread that started it, through the cgroup of its `io` controller. The kernel writes cached data back from its own threads, unless the application syncs it, so those write RPCs are charged to no workload, like block I/O writeback on cgroup v1.
- `server.address` is the IP address of the server, as the RPC transport displays it, not the host name of the mount.
- `error.type` is the errno of failed RPCs, e.g. `EIO`. The kernel-internal errnos of the client and the NFSv4 errors that it doesn't translate into errnos have the names that the kernel and the RFCs give them, e.g. `EJUKEBOX` and `NFS4ERR_DELAY` when the server asks the client to retry later. A status without a name is reported by its number.

#### Storage stats profiles

The storage stats are opt-in, and their cost in series depends on the features and attributes you choose. Three starting points, with the series of a typical node (4 devices with I/O, 40 workloads doing I/O, 10 of them syncing files, 1 NFS server) and of a busy one (40 devices, 250 workloads, all of them syncing, 50 on NFS across 4 servers), with the default 19 histogram buckets (18 for NFS):

| Profile | What it reports | Typical node | Busy node |
|---|---|---|---|
| Minimal | Block I/O bytes, requests and time per device and workload, flush latency per device, file syncs and their time per workload. No probe on NFS, no request latency distribution. | ~500 | ~6,800 |
| Standard | Everything, with the latency histograms per device, call or procedure and the counters per workload: the defaults. | ~1,200 | ~17,000 |
| Detailed | The standard profile, with the latency histograms per workload too. | ~7,900 | ~150,000 |

Minimal:

```yaml
metrics:
  features: [stats_disk_io, stats_disk_operations, stats_disk_operation_time, stats_disk_flush,
             stats_fs_sync_operations, stats_fs_sync_operation_time]
```

Standard (add `stats_disk_pod_volumes` in Kubernetes to link the pods to their disks):

```yaml
metrics:
  features: [stats_disk, stats_fs_sync, stats_nfs]
```

Detailed:

```yaml
metrics:
  features: [stats_disk, stats_fs_sync, stats_nfs]
attributes:
  select:
    # every storage latency histogram, per workload but not per pod
    obi.stat.*.duration:
      include: ["*"]
      exclude: [obi.ip, obi.disk.partition, container.id, k8s.pod.name, k8s.container.name, k8s.kind]
```

The mean latency per workload doesn't need the detailed profile: it is the ratio of a time counter to its count counter, e.g. `rate(obi_stat_disk_operation_time_seconds_total[5m]) / rate(obi_stat_disk_operations_total[5m])`. Selecting `k8s.pod.name`, `k8s.container.name` or `container.id` on a latency histogram makes a series per bucket for each pod, and OBI warns about it at startup. With config v2, list the same families in `capture.network.stats.features` (without the `stats_` prefix) and the selection in `extensions.obi.enrich.attributes.select`.

#### Storage stats under dynamic application selection

When OBI is embedded with a dynamic selector (`instrumenter.WithDynamicSelector`), the block I/O, file sync and NFS metrics keep only what the kernel charges to the containers of the selected processes, and to the containers of the pods of the selected Kubernetes workloads. `obi.stat.k8s.pod.volume.device` keeps only the volumes of those pods. Limitations:

- The selection works through containers: a selected process outside a container, and the operations charged to no container (like those of kernel threads), are not reported.
- The requests in flight of the devices (`obi.stat.disk.pending_operations`) and the disks of the stacked volumes (`obi.stat.disk.volume.device`) belong to no application, so they are not reported.
- Selecting Kubernetes workloads needs the Kubernetes metadata.
- While nothing is selected, no storage stat is reported.

### Performance considerations

Some stat metrics attach to kernel functions that are called very frequently (e.g. `tcp_sendmsg`, `tcp_cleanup_rbuf` for TCP IO). These probes add a small overhead on every call, so the aggregate cost is proportional to the rate of TCP sends/receives on the node. Consider:

- If you need RTT, failed connections, or retransmits **without** TCP IO overhead, enable those individually (`stats_tcp_rtt`, `stats_tcp_failed_connections`, `stats_tcp_successful_connections`, `stats_tcp_retransmits`) instead of using the `stats` aggregate feature — `stats` includes `stats_tcp_io`, which fires on every `tcp_sendmsg` and `tcp_cleanup_rbuf` call.
- The `stats_events` ring buffer and the per-metric eBPF maps (e.g. `tcp_io_accum`) have default size limits; on nodes with a very large number of concurrent connections these can be resized via the `ebpf.*` configuration knobs if events start being dropped.
- The file sync probes (`stats_fs_sync_duration`) fire on every file sync, which is usually much less frequent than block requests. They read the cgroup of the thread that syncs only when a container or Kubernetes attribute of the metric is selected (by default in Kubernetes), and the filesystem of the synced file only when `system.filesystem.mountpoint` or `system.filesystem.type` is.
- The NFS client probes (`stats_nfs`) fire on every NFS RPC, and on every read and write RPC completion.
- The disk probes (`stats_disk_*` features) fire on every block request issue and completion, so their cost grows with the node's IOPS. `stats_disk_stacked_volumes` also fires on every bio submission, and skips the bios of devices that are not stacked volumes with a single map lookup. `stats_disk_pending_operations` only reads the kernel's counters of requests in flight, and `stats_disk_volume_devices` attaches no probe. The probes read the cgroup of each request only when a container or Kubernetes attribute of an enabled disk metric is selected (by default in Kubernetes), and its partition only when `obi.disk.partition` is. They don't send one ring buffer event per request: the kernel accumulates the latencies in a histogram per device, direction, outcome and cgroup (`disk_io_accum`), which userspace reads every `ebpf.batch_timeout`. The exporters add the count of each kernel bucket to their histograms at once, so their cost grows with the number of series, not with the IOPS. On a 4-vCPU VM, the block probes cost about 0.6 µs of CPU per request (0.5 µs more on kernels where the queue doesn't time its requests, such as RHEL 8). For these reasons they are not part of the `stats` aggregate, nor of `all` and `*`, and must be enabled explicitly. The same goes for the file sync, NFS and pod volume features.
- The starts of the block requests, bios, file syncs and NFS tasks in flight are kept in LRU maps of 16384 entries, and of 256 entries per CPU on hosts with more than 64 CPUs. Before Linux 6.16, each CPU keeps up to 128 free entries of an LRU map for itself, and once those hold most of the map, a CPU that needs an entry evicts a request in flight, which then goes uncounted.

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
