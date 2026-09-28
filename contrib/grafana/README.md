# Grafana dashboard for the OBI disk stats

[`obi-disk-stats.json`](obi-disk-stats.json) shows the disk, file sync, NFS
client and pod volume metrics of OBI's StatsO11y, from a Prometheus data
source:

- **Devices**: IOPS, throughput, errors, service and queue time, average queue
  size, requests in flight, flushes, discards, stacked volumes (LVM, md RAID)
  and partitions.
- **Workloads**: the workloads that read and write the most, and their service
  time.
- **File syncs** and **NFS client**: rates and 99th percentiles, per call, per
  filesystem, per server and procedure.
- **Pod volumes**: a node graph from the pods to their PersistentVolumeClaims,
  PersistentVolumes, the devices they are mounted from and the disks those are
  on, and the throughput of those disks.

Enable the metrics with the `stats_disk`, `stats_fs_sync_duration`,
`stats_nfs` and `stats_disk_pod_volumes` features, and select the Kubernetes
attributes to see the workloads. The partition and file system panels need the
opt-in `obi.disk.partition` and `system.filesystem.mountpoint` attributes. See
[`devdocs/metrics.md`](../../devdocs/metrics.md) for the metrics and their
limitations.

To import it, in Grafana go to **Dashboards** > **New** > **Import** and
upload the file, or provision it from a file. The `instance` variable selects
the OBI instances by the `instance` label that Prometheus adds when it scrapes
them.
