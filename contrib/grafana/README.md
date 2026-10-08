# Grafana dashboard for the OBI disk stats

[`obi-disk-stats.json`](obi-disk-stats.json) shows the disk, file sync, NFS
client and pod volume metrics of OBI's StatsO11y, from a Prometheus data
source:

- **Devices**: IOPS, throughput, errors, service and queue time, average queue
  size, requests in flight, flushes, discards, stacked volumes (LVM, md RAID)
  and the disks they are on, and partitions.
- **Workloads**: the workloads that read and write the most, and their service
  time.
- **File syncs** and **NFS client**: rates and 99th percentiles, per call, per
  server and procedure, the average sync time of each filesystem, and the
  average sync and RPC time of each workload.
- **Pod volumes**: a node graph from the pods to their PersistentVolumeClaims,
  PersistentVolumes, the devices they are mounted from and the disks those are
  on, and the throughput of those disks.

Enable the metrics with the `stats_disk`, `stats_fs_sync`,
`stats_nfs` and `stats_disk_pod_volumes` features. In Kubernetes, the counters
carry the namespace and the owner of each workload by default. The partition
panel needs the opt-in `obi.disk.partition` attribute, and the file system
panel the opt-in `system.filesystem.mountpoint` attribute on the file sync
counters, `obi.stat.fs.sync.operations` and `obi.stat.fs.sync.operation_time`:

```yaml
attributes:
  select:
    obi.stat.fs.sync.operation*:
      include: ["*"]
      exclude: [container.id, k8s.pod.name, k8s.container.name]
```

Select it on the `obi.stat.fs.sync.duration` histogram only if you need the
latency distribution of each filesystem: the mountpoints include the staging
directory of each CSI volume, one per PersistentVolume that the pods of the node
mount, and each of them adds a series per bucket. OBI warns about it at
startup. See
[`devdocs/metrics.md`](../../devdocs/metrics.md) for the metrics and their
limitations.

To import it, in Grafana go to **Dashboards** > **New** > **Import** and
upload the file, or provision it from a file.

## Telling the nodes apart

When Prometheus scrapes OBI directly, the `instance` label identifies each OBI
instance, and the **Instance** variable selects them.

When OBI exports OTLP to an OpenTelemetry Collector that Prometheus scrapes,
`instance` is the collector's for every series, with or without
`resource_to_telemetry_conversion`. Select the opt-in `obi.ip` attribute on the
metrics, so that the panels group the devices of each node apart and the
**Node** variable selects them:

```yaml
attributes:
  select:
    obi.stat.*:
      include: ["obi.ip", ...]
```

Without it, the devices with the same name on different nodes, such as `sda`,
are added up together.
