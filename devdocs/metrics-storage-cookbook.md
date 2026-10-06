# Storage metrics PromQL cookbook

Queries for the storage metrics described in [metrics.md](metrics.md#storage-metrics). They
use OBI's Prometheus endpoint names (`obi_stat_disk_operation_duration_seconds_bucket`, ...)
and label names (`system_device`, `k8s_pod_name`, ...). Over OTLP, a backend that translates
names with underscores and unit suffixes gives the same names; Prometheus 3 with UTF-8
ingestion keeps the dotted names and needs them quoted.

Conventions used below:

- Counters go through `rate()`, histograms through
  `histogram_quantile(q, sum by (le, ...) (rate(..._bucket[5m])))`. Keep `le` in the `by`.
- `k8s_node_name` is present when Kubernetes decoration is on. Without it, group by
  `instance` instead. Disk and filesystem series are per node, so keep the node in every
  `by` and `on` clause: `sda` on one node is not `sda` on another.
- An attribute that does not apply is an empty label, which Prometheus treats as absent:
  `{k8s_pod_name=""}` selects I/O of no pod.
- Histogram queries need classic buckets. They are there by default; with
  `ebpf.storage_aggregation.exponential_histograms` the storage histograms are native only, and
  `histogram_quantile(q, sum by (...) (rate(metric[5m])))` replaces the `_bucket` form.
- The block layer is node-wide: it has no pod, PV or PVC. Per-pod and per-PV numbers come
  from the filesystem layer (`obi_stat_fs_*`); disks are reached through the join labels
  (see [Joining filesystem to disk](#joining-filesystem-series-to-the-disk-underneath)).

## Block layer: per disk

### Latency percentiles

p99 service time (issue to completion) per disk and direction:

```promql
histogram_quantile(0.99,
  sum by (le, k8s_node_name, system_device, disk_io_direction) (
    rate(obi_stat_disk_operation_duration_seconds_bucket[5m])
  )
)
```

Mean latency, cheaper than a quantile when the buckets are coarse:

```promql
  sum by (k8s_node_name, system_device, disk_io_direction) (rate(obi_stat_disk_operation_duration_seconds_sum[5m]))
/ sum by (k8s_node_name, system_device, disk_io_direction) (rate(obi_stat_disk_operation_duration_seconds_count[5m]))
```

Flushes (the cache flush behind `fsync`) are not writes; they have their own histogram:

```promql
histogram_quantile(0.99,
  sum by (le, k8s_node_name, system_device) (rate(obi_stat_disk_flush_duration_seconds_bucket[5m]))
)
```

### Throughput and IOPS

Bytes per second, read and write, physical devices only. `obi_disk_stacked="true"` marks
devices that do not issue requests to hardware (loop, dm, md, NVMe multipath heads) and whose
bytes are also counted on the disks below them, so summing both double counts:

```promql
sum by (k8s_node_name, system_device, disk_io_direction) (
  rate(obi_stat_disk_io_bytes_total{obi_disk_stacked="false"}[5m])
)
```

IOPS is the rate of the duration histogram's count:

```promql
sum by (k8s_node_name, system_device, disk_io_direction) (
  rate(obi_stat_disk_operation_duration_seconds_count{obi_disk_stacked="false"}[5m])
)
```

Discarded bytes per second (`fstrim`, `discard` mounts):

```promql
sum by (k8s_node_name, system_device) (rate(obi_stat_disk_discard_io_bytes_total[5m]))
```

### Error ratio

Failed reads and writes over all reads and writes, per disk. `operation.errors` counts only
the failures, so the denominator is the duration histogram's count:

```promql
  sum by (k8s_node_name, system_device) (rate(obi_stat_disk_operation_errors_total[5m]))
/ sum by (k8s_node_name, system_device) (rate(obi_stat_disk_operation_duration_seconds_count[5m]))
```

By errno (`EIO`, `ENOSPC`, ...):

```promql
sum by (k8s_node_name, system_device, error_type) (rate(obi_stat_disk_operation_errors_total[5m]))
```

Flush and discard failures are not in `operation.errors`; they are the `error_type` label of
their histograms:

```promql
sum by (k8s_node_name, system_device, error_type) (
  rate(obi_stat_disk_flush_duration_seconds_count{error_type!=""}[5m])
)
```

### Queue time vs service time

`queue.duration` is the wait before the request was issued to the device; `operation.duration`
is the time the device took. A high queue share with a normal service time means saturation
of the queue (or a scheduler), not a slow disk. Only requests that went through
`block_rq_insert` are in `queue.duration`, so its count is at most the operation count.

```promql
  sum by (k8s_node_name, system_device) (rate(obi_stat_disk_queue_duration_seconds_sum[5m]))
/ (
    sum by (k8s_node_name, system_device) (rate(obi_stat_disk_queue_duration_seconds_sum[5m]))
  + sum by (k8s_node_name, system_device) (rate(obi_stat_disk_operation_duration_seconds_sum[5m]))
  )
```

p99 of each, side by side:

```promql
histogram_quantile(0.99, sum by (le, k8s_node_name, system_device) (rate(obi_stat_disk_queue_duration_seconds_bucket[5m])))
histogram_quantile(0.99, sum by (le, k8s_node_name, system_device) (rate(obi_stat_disk_operation_duration_seconds_bucket[5m])))
```

Average requests in flight (Little's law, the `aqu-sz` of `iostat`), from time spent in both
phases:

```promql
sum by (k8s_node_name, system_device) (
    rate(obi_stat_disk_queue_duration_seconds_sum[5m])
  + rate(obi_stat_disk_operation_duration_seconds_sum[5m])
)
```

### Pending operations

Requests in flight now, per disk. Gauge: no `rate()`. Available with the block merge
(`storage_block_pending`, see the placeholder in [metrics.md](metrics.md#storage-metrics)):

```promql
sum by (k8s_node_name, system_device) (obi_stat_disk_pending_operations)
```

The deprecated `obi_stat_disk_queue_depth` histogram (`storage_block_queue_depth`, off by
default) samples the in-flight count at each completion; its mean is:

```promql
  sum by (k8s_node_name, system_device) (rate(obi_stat_disk_queue_depth_sum[5m]))
/ sum by (k8s_node_name, system_device) (rate(obi_stat_disk_queue_depth_count[5m]))
```

## Filesystem layer: per PV and per pod

The filesystem metrics run in the context of the calling process, so they carry the pod and,
for kubelet volumes, the PersistentVolume and claim.

### Latency percentiles

p99 read and write latency per PV. Buffered writes complete in the page cache, so a write
percentile measures memory; durability is in the `fsync` queries below:

```promql
histogram_quantile(0.99,
  sum by (le, k8s_node_name, k8s_persistentvolume_name, fs_operation) (
    rate(obi_stat_fs_operation_duration_seconds_bucket{fs_operation=~"read|write",
                                                       k8s_persistentvolume_name!=""}[5m])
  )
)
```

Per pod, with the owning workload (`k8s_owner_name`) to keep series stable across pod
restarts:

```promql
histogram_quantile(0.99,
  sum by (le, k8s_namespace_name, k8s_owner_name, k8s_pod_name, fs_operation) (
    rate(obi_stat_fs_operation_duration_seconds_bucket{fs_operation=~"read|write",
                                                       k8s_pod_name!=""}[5m])
  )
)
```

### fsync tail latency

`fsync` and `fdatasync` are the durability waits of databases; `sync`, `syncfs` and
`sync_file_range` need `storage_fs_sync`. Per PV:

```promql
histogram_quantile(0.99,
  sum by (le, k8s_node_name, k8s_persistentvolume_name, system_filesystem_type) (
    rate(obi_stat_fs_operation_duration_seconds_bucket{fs_operation=~"fsync|fdatasync"}[5m])
  )
)
```

Per pod:

```promql
histogram_quantile(0.99,
  sum by (le, k8s_namespace_name, k8s_pod_name) (
    rate(obi_stat_fs_operation_duration_seconds_bucket{fs_operation=~"fsync|fdatasync"}[5m])
  )
)
```

### Throughput and IOPS

Bytes per second per PV (`obi_stat_fs_io_bytes_total` is read and write only):

```promql
sum by (k8s_node_name, k8s_persistentvolume_name, fs_operation) (
  rate(obi_stat_fs_io_bytes_total{k8s_persistentvolume_name!=""}[5m])
)
```

Per pod:

```promql
sum by (k8s_namespace_name, k8s_owner_name, k8s_pod_name, fs_operation) (
  rate(obi_stat_fs_io_bytes_total{k8s_pod_name!=""}[5m])
)
```

Operations per second per pod:

```promql
sum by (k8s_namespace_name, k8s_pod_name, fs_operation) (
  rate(obi_stat_fs_operation_duration_seconds_count{fs_operation=~"read|write"}[5m])
)
```

### Error ratio

```promql
  sum by (k8s_node_name, k8s_persistentvolume_name) (rate(obi_stat_fs_operation_errors_total[5m]))
/ sum by (k8s_node_name, k8s_persistentvolume_name) (rate(obi_stat_fs_operation_duration_seconds_count[5m]))
```

By errno and operation:

```promql
sum by (k8s_persistentvolume_name, fs_operation, error_type) (
  rate(obi_stat_fs_operation_errors_total[5m])
)
```

## NFS client

NFS series are per RPC attempt, as `/proc/self/mountstats` counts them. NFSv2 and v3 RPCs
carry `onc_rpc_procedure_name`; NFSv4 RPCs are all `COMPOUND` on the wire and carry
`nfs_operation_name` instead. A query that covers both versions uses `or` over the two labels.

### RPC latency per server

```promql
histogram_quantile(0.99,
  sum by (le, k8s_node_name, server_address) (
    rate(obi_stat_nfs_client_rpc_duration_seconds_bucket[5m])
  )
)
```

### RPC latency per operation

```promql
histogram_quantile(0.99,
  sum by (le, server_address, onc_rpc_procedure_name) (
    rate(obi_stat_nfs_client_rpc_duration_seconds_bucket{onc_rpc_procedure_name!=""}[5m])
  )
)
```

```promql
histogram_quantile(0.99,
  sum by (le, server_address, nfs_operation_name) (
    rate(obi_stat_nfs_client_rpc_duration_seconds_bucket{nfs_operation_name!=""}[5m])
  )
)
```

### Retransmit rate

Retransmits per second, and as a share of attempts:

```promql
sum by (k8s_node_name, server_address) (rate(obi_stat_nfs_client_rpc_retransmits_total[5m]))
```

```promql
  sum by (k8s_node_name, server_address) (rate(obi_stat_nfs_client_rpc_retransmits_total[5m]))
/ sum by (k8s_node_name, server_address) (rate(obi_stat_nfs_client_rpc_duration_seconds_count[5m]))
```

A server-requested retry (`EJUKEBOX`, `NFS4ERR_DELAY`, `NFS4ERR_GRACE`) is a new attempt, not
a retransmit: it shows in the errors counter, followed by a slow successful attempt.

### Error ratio

`ENOENT` on `LOOKUP` and `OPEN` is normal traffic, and the three back-pressure errors are not
failures. Exclude them for an alert, and show them separately:

```promql
  sum by (k8s_node_name, server_address) (
    rate(obi_stat_nfs_client_rpc_errors_total{error_type!~"EJUKEBOX|NFS4ERR_DELAY|NFS4ERR_GRACE|ENOENT"}[5m]))
/ sum by (k8s_node_name, server_address) (rate(obi_stat_nfs_client_rpc_duration_seconds_count[5m]))
```

```promql
sum by (k8s_node_name, server_address, error_type) (
  rate(obi_stat_nfs_client_rpc_errors_total{error_type=~"EJUKEBOX|NFS4ERR_DELAY|NFS4ERR_GRACE"}[5m])
)
```

### Wire throughput

`obi_stat_nfs_client_io_bytes_total` counts RPC and XDR headers and every procedure, so it is
larger than the payload bytes of `obi_stat_fs_io_bytes_total`:

```promql
sum by (k8s_node_name, server_address, network_io_direction) (
  rate(obi_stat_nfs_client_io_bytes_total[5m])
)
```

The ratio of payload to wire bytes shows how much the page cache absorbs and how much traffic
is metadata:

```promql
  sum by (k8s_node_name, server_address) (rate(obi_stat_fs_io_bytes_total{system_filesystem_type="nfs"}[5m]))
/ sum by (k8s_node_name, server_address) (rate(obi_stat_nfs_client_io_bytes_total[5m]))
```

## Joining across layers

There is no topology metric: the layers share labels, and a dashboard joins them. All the
joins below use `group_left()` with no copied labels, so the right side only filters and
multiplies by its value; use `on (...)` with the labels listed and nothing else.

### Joining filesystem series to the disk underneath

Block-backed filesystem series carry two labels:

- `system_device`: the sysfs name of the device the filesystem sits on (`vdb`, `dm-4`,
  `nvme0n1p3`). Empty for NFS, ceph, cifs, fuse and a multi-device btrfs.
- `obi_disk_physical_device`: the physical disks below it, sorted and comma-joined (`sdb,sdc`
  for a RAID or thin pool). Empty whenever `system_device` is.

Block series are keyed by the device that issues requests to hardware (`system_device` on
`obi_stat_disk_*`, with `obi_disk_stacked="false"`), so a filesystem on `dm-4` reaches the
disk through `obi_disk_physical_device`.

Edges, which PV is on which disks:

```promql
group by (k8s_node_name, k8s_persistentvolume_name, system_device, obi_disk_physical_device) (
  obi_stat_fs_io_bytes_total{system_device!=""}
)
```

Physical disk load behind each PV, for PVs on a single disk (a list value contains a comma):

```promql
  group by (k8s_node_name, k8s_persistentvolume_name, system_device) (
    label_replace(
      obi_stat_fs_io_bytes_total{obi_disk_physical_device!="", obi_disk_physical_device!~".*,.*"},
      "system_device", "$1", "obi_disk_physical_device", "(.+)"
    )
  )
* on (k8s_node_name, system_device) group_left()
  sum by (k8s_node_name, system_device) (
    rate(obi_stat_disk_io_bytes_total{obi_disk_stacked="false"}[5m])
  )
```

The `label_replace` overwrites `system_device` on the filesystem side with the physical disk
so both sides join on the same name. For a PV on several disks, match each member with `=~`
instead (`obi_disk_physical_device=~"(.*,)?sdb(,.*)?"`).

Same join for latency, the disk's p99 next to each PV:

```promql
  group by (k8s_node_name, k8s_persistentvolume_name, system_device) (
    label_replace(
      obi_stat_fs_io_bytes_total{obi_disk_physical_device!="", obi_disk_physical_device!~".*,.*"},
      "system_device", "$1", "obi_disk_physical_device", "(.+)"
    )
  )
* on (k8s_node_name, system_device) group_left()
  histogram_quantile(0.99, sum by (le, k8s_node_name, system_device) (
    rate(obi_stat_disk_operation_duration_seconds_bucket{obi_disk_stacked="false"}[5m])
  ))
```

The disk is shared by every PV and process on it: a disk that is slow for a PV may be loaded
by another.

### Joining filesystem series to NFS series

`server_address` is the server's IP as the mount's `addr=` option shows it, on both
`obi_stat_fs_*` (network filesystems only) and `obi_stat_nfs_client_*`, so it joins byte for
byte.

Which PVs and pods use which server:

```promql
group by (k8s_node_name, k8s_namespace_name, k8s_pod_name,
          k8s_persistentvolumeclaim_name, k8s_persistentvolume_name, server_address) (
  obi_stat_fs_io_bytes_total{system_filesystem_type="nfs"}
)
```

Server RPC p99 next to the PVs that use it (v3 procedures or v4 operations):

```promql
  group by (k8s_node_name, k8s_persistentvolume_name, server_address) (
    obi_stat_fs_io_bytes_total{system_filesystem_type="nfs"}
  )
* on (k8s_node_name, server_address) group_left()
  histogram_quantile(0.99, sum by (le, k8s_node_name, server_address) (
    rate(obi_stat_nfs_client_rpc_duration_seconds_bucket{onc_rpc_procedure_name=~"READ|WRITE|COMMIT"}[5m])
    or
    rate(obi_stat_nfs_client_rpc_duration_seconds_bucket{nfs_operation_name=~"READ|WRITE|COMMIT"}[5m])
  ))
```

Caveats: a mount through a second address of an NFSv4.1+ server shares the first mount's
client, and both report the first-mounted address. A subdirectory provisioner puts several
PVs on one NFS superblock, and RPC series carry no PV, so the RPC side is per server, not
per PV.

## Block volumes and pod attribution

Comparing stacked devices with the disks below them (`storage_block_volumes`), and per-pod
block I/O (`storage_block_pod`), land with the block merge. Their queries are added to this
page then. Until then the block layer is per physical disk and node-wide, and per-pod
numbers come from the filesystem queries above.
