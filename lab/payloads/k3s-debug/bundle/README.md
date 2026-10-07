# OBI storage metrics: deployment

Everything needed to run OBI with the disk, file sync, NFS client and pod volume
metrics of `feat/statso11y-disk-metrics-v2`, have Prometheus scrape it, and see
it in Grafana. The OBI configuration uses the v1 format.

| File | What it is |
|---|---|
| `obi-config.yaml` | OBI configuration (v1): the storage features, Prometheus endpoint on port 9400 |
| `kustomization.yaml`, `kubernetes/` | Kubernetes: namespace, the k8s-cache (Deployment, Service, RBAC), OBI's RBAC, ConfigMap (from `obi-config.yaml`), DaemonSet |
| `docker-compose.yaml` | a host without Kubernetes, with Docker |
| `obi.service` | a host without containers, with systemd |
| `prometheus/prometheus.yml` | Prometheus scrape jobs for the Kubernetes pods and for hosts |
| `grafana/` | Grafana provisioning of the Prometheus data source and the dashboard |

## 1. Build the images

A released OBI doesn't know these metrics, and a released k8s-cache doesn't watch
the PersistentVolumes: build both from the branch.

```bash
git clone https://github.com/TheDwingMAN/opentelemetry-ebpf-instrumentation.git
cd opentelemetry-ebpf-instrumentation
git checkout feat/statso11y-disk-metrics-v2
docker build -t registry.example.com/obi:disk-v2 .
docker build -f k8scache.Dockerfile -t registry.example.com/obi-k8s-cache:disk-v2 .
docker push registry.example.com/obi:disk-v2
docker push registry.example.com/obi-k8s-cache:disk-v2
```

For arm64 nodes, build with `docker buildx build --platform linux/arm64,linux/amd64 --push ...`.

## 2a. Kubernetes

Set your images in `kustomization.yaml` (`images:`) and your cluster name in
`kubernetes/daemonset.yaml` (`OTEL_EBPF_KUBE_CLUSTER_NAME`), then:

```bash
kubectl apply -k .
kubectl -n obi get pods -o wide
```

- OBI runs privileged, with the host's PID namespace and network, on every node.
- The Kubernetes metadata of the workloads comes from the k8s-cache
  (`kubernetes/k8s-cache.yaml`): one Deployment watches pods, services, nodes
  and PersistentVolumes, and the OBI pods connect to it at
  `obi-k8s-cache.obi.svc:50055` (`OTEL_EBPF_KUBE_META_CACHE_ADDRESS` in
  `kubernetes/daemonset.yaml`). Only the cache has those permissions.
- OBI's own ClusterRole only lets it list the nodes: it asks the Kubernetes API
  for the name and metadata of its node, which the pod volume metric needs.
- The cache runs with `persistent_volumes` on. Without it, or without its
  permission on PersistentVolumes, the pod volume metric is empty.
- The OBI pods share the host network: a `NetworkPolicy` that selects them by
  their labels doesn't apply to them. Restrict access to port 50055 with your
  CNI's host policies if you need to.

## 2b. Hosts without Kubernetes

With Docker, next to `obi-config.yaml`:

```bash
OBI_IMAGE=registry.example.com/obi:disk-v2 docker compose up -d
```

With systemd, take the binary out of the image and install it:

```bash
id=$(docker create registry.example.com/obi:disk-v2) && docker cp $id:/obi ./obi && docker rm $id
install -m 755 obi /usr/local/bin/obi
install -D -m 644 obi-config.yaml /etc/obi/obi-config.yaml
install -m 644 obi.service /etc/systemd/system/obi.service
systemctl daemon-reload && systemctl enable --now obi
```

Check it: `curl -s localhost:9400/metrics | grep ^obi_stat_disk`.

## 3. Prometheus

Add the jobs of `prometheus/prometheus.yml` that match your setup to your
Prometheus: `obi-k8s` finds the OBI pods through the Kubernetes API, `obi-hosts`
lists hosts (or the nodes, for a Prometheus outside the cluster) at
`<host>:9400`. Prometheus must scrape OBI directly: the dashboard tells the
nodes apart by the `instance` label.

## 4. Grafana

Copy `grafana/provisioning/*` to Grafana's provisioning directory
(`/etc/grafana/provisioning`), set the Prometheus URL in
`datasources/prometheus.yaml`, and copy `grafana/dashboards/obi-disk-stats.json`
to `/var/lib/grafana/dashboards/obi`. Or import the JSON from the Grafana UI
(**Dashboards** > **New** > **Import**).

## 5. OpenTelemetry Collector and ClickHouse

To send the metrics over OTLP, uncomment `otel_metrics_export` in
`obi-config.yaml` and set the collector address. With the collector's
`clickhouse` exporter, they land in the `otel` database:

| Table | Metrics |
|---|---|
| `otel_metrics_sum` | counters (`IsMonotonic` = 1): `obi.stat.disk.io`, `obi.stat.disk.operations`, `obi.stat.disk.operation.time`, `obi.stat.disk.discard.io`, `obi.stat.nfs.client.io`; up-down counters (`IsMonotonic` = 0): `obi.stat.disk.pending_operations`, `obi.stat.k8s.pod.volume.device` |
| `otel_metrics_histogram` | `obi.stat.disk.operation.duration`, `obi.stat.disk.queue.duration`, `obi.stat.disk.flush.duration`, `obi.stat.disk.discard.duration`, `obi.stat.fs.sync.duration`, `obi.stat.nfs.client.procedure.duration` |

`MetricName` has the OpenTelemetry name (dots, not `obi_stat_..._total`), the
`Attributes` map the attributes (`system.device`, `disk.io.direction`,
`k8s.namespace.name`...), and `ResourceAttributes['host.id']` the node.
`ServiceName` is empty. The values are cumulative: take differences, as the
queries in `clickhouse/queries.sql` do.

Checked with otelcol-contrib 0.161.0 (`otlp` receiver, `clickhouse` exporter with
`database: otel` and `create_schema: true`) and ClickHouse 25.8: all the tables
and queries above, with data.

## 6. No metrics? Find where they stop

`debug/obi-debug.sh` follows the metrics from OBI to the collector and ClickHouse
and says where they stop. It only reads: pods, logs, the ConfigMap, and metrics
through `kubectl port-forward` (the OBI image has no shell). It needs `kubectl`
and `curl`:

```sh
COLLECTOR_NAMESPACE=otel COLLECTOR_SELECTOR=app.kubernetes.io/name=otel-collector \
CLICKHOUSE_URL='http://user:password@clickhouse:8123' ./debug/obi-debug.sh
```

Without `COLLECTOR_SELECTOR` it looks for a pod with an otelcol image; without
`CLICKHOUSE_URL` it prints the queries to run. It tells whether OTLP exports
succeed only with OBI's internal metrics on, and prints the command that turns
them on (`OTEL_EBPF_INTERNAL_METRICS_EXPORTER=prometheus`, served on OBI's port
next to the storage metrics, at `/internal/metrics`).

The causes it recognizes:

- `otel_metrics_export` still commented out: OBI sends no OTLP.
- `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` without `/v1/metrics`: that variable is
  the whole URL, so OBI posts to `/` and the collector answers 404. The YAML
  `endpoint` and `OTEL_EXPORTER_OTLP_ENDPOINT` get the path added.
- The wrong address, port or protocol (4317 is gRPC, 4318 HTTP).
- A collector exporter that fails without a `sending_queue`: the collector
  refuses the data, and OBI's exports fail too.
- Nothing received by the collector, an exporter that can't write, no
  `otel_metrics*` tables or no `obi*` metric in them.

OBI logs its failed exports at INFO level, as `failed to upload metrics: ...`,
with the collector's answer. The collector exits at startup when its
`clickhouse` exporter can't reach ClickHouse. OBI exports every 60 s.

## Requirements and limits

- Linux 5.8+ with BTF, or RHEL 8.9+ (4.18). NFS metrics need module BTF: Linux
  5.11+ or RHEL 9; on RHEL 8 they are off with a warning.
- The file sync metric uses kprobes: kernels built without them (rare) can't run
  it, and OBI's stats don't start. Remove `stats_fs_sync_duration` there.
- `stats.agent_ip_iface: local` takes the host IP from its interfaces: the
  default looks up the route to 8.8.8.8, and fails on hosts without a default
  route.
- Cost: about 0.6 µs of CPU per block request and 1.5 to 3 µs per file sync
  (measured before the last optimizations), plus 45 to 65 ns per request for each
  exported histogram.

## Checked

- Kubernetes with the k8s-cache (single-node k3s with CoreDNS, Linux 6.12):
  `kubectl apply -k .` with only the images changed; the cache ready in 4 s and
  OBI running, connected to it at `obi-k8s-cache.obi.svc:50055`; OBI's service
  account can list nodes and nothing else (`kubectl auth can-i`: no on pods,
  services, PersistentVolumes), and OBI logs no forbidden request. Prometheus with
  the `obi-k8s` job scraping it (`instance` = node IP:9400, `node` label); disk
  I/O of the pods with their namespace, owner and cluster; pending operations,
  queue time, an LVM volume; file syncs with their mountpoint; NFS; pod → PVC →
  PV → disk for a local and a hostPath PersistentVolume, from the cache.
- The same without the cache (OBI with the RBAC of the cache): the same checks,
  and the provisioned Grafana dashboard ran all 26 queries, 22 with data (the
  other 4: I/O and NFS errors, discards and partitions, which the test didn't
  produce or select).
- `obi-config.yaml`: loaded unchanged by OBI on RHEL 8.10, RHEL 9.6, Linux 5.15
  and 6.12, with exact disk, file sync and NFS counts.
- `docker-compose.yaml`: runs OBI, which counts the disk operations exactly.
- `prometheus/prometheus.yml` loads in Prometheus. `obi.service` was not run.
