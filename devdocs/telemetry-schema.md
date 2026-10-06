# Published OBI telemetry schema

This directory is the source for OBI's published [OpenTelemetry Telemetry
Schema](https://opentelemetry.io/docs/specs/otel/schemas/) files. It is deployed
verbatim to GitHub Pages by `.github/workflows/publish-schemas.yml`, so the file

```text
site/schemas/obi/<version>
```

is served at

```text
https://open-telemetry.github.io/opentelemetry-ebpf-instrumentation/schemas/obi/<version>
```

which is the `schema_url` OBI stamps onto its OTLP telemetry (see
`pkg/export/attributes/names/schema_version.go`, `OBISchemaURL`).

## Rules

- **One file per release**, named by the OBI release version, no extension.
- **Files are immutable once released** — a published `schema_url` is a
  permanent identity. Never edit a released file; add a new version instead.
- The `versions:` block records the transformations (attribute/metric renames)
  between versions, newest first. The first release is an empty baseline.
- The `schema_url:` inside each file MUST equal its served URL. `make
  check-schema-files` enforces this.

## Releasing a new version

Version management is release-driven. The version comes from `versions.yaml`
(the OBI release version), and `make prerelease` runs `make generate-schema-next`
automatically, which:

- cuts `site/schemas/obi/<version>` (previous file plus a new, empty `<version>:`
  entry on top),
- regenerates the reference docs under `site/docs/`, and
- bumps `OBISchemaURL` in `pkg/export/attributes/names/schema_version.go` and the
  `schema_url` in `schemas/obi/manifest.yaml` to `<version>`.

These changes are part of the release-prep commit; on merge to `main` the file is
deployed by `publish-schemas.yml`. `make check-schema-files` (run in CI) enforces
that the emitted `OBISchemaURL` and the manifest both name the `versions.yaml`
version and that a schema file for that version is actually published.

**If telemetry changed this release** (an attribute or metric was renamed), add
the transformation entries by hand under the new `<version>:` block before
committing, draining "Pending transformations" below. Drain "Pending release
notes" into the release notes at the same time: those are telemetry changes the
schema format cannot express, so nothing else will surface them. E.g.:

```yaml
versions:
  <version>:
    all:
      changes:
        - rename_attributes:
            attribute_map:
              old.attribute.name: new.attribute.name
    metrics:
      changes:
        - rename_metrics:
            old_metric_name: new_metric_name
```

Released files are immutable — never edit a `<version>` file once it has shipped;
only add new ones.

### Pending transformations

A change that renames emitted telemetry lands before the version that ships it
exists, so it records the transformation here and the release owner drains this list
into the new `<version>:` block at release prep. Leave the section empty once drained.

A removal goes under "Pending release notes" below instead: the format has
`rename_attributes` and `rename_metrics` and no operation for dropping something.

```yaml
```

### Pending release notes

Breaking changes the schema cannot express: the format describes the OTLP output only, has
no operation for dropping something, and says nothing about the published reference docs.
Keep them out of the block above — copying them into a `<version>` file would corrupt a
published, immutable schema.
The release owner drains this list into the release notes at release prep, and leaves the
section empty once drained.

- The storage metrics (`obi.stat.disk.*`, `obi.stat.fs.*`) no longer send an attribute with
  an empty value over OTLP: `k8s.pod.name`, `k8s.namespace.name` and `k8s.container.name` on
  filesystem I/O from a process in no pod, `k8s.persistentvolume.name`,
  `k8s.persistentvolumeclaim.name` and `k8s.storageclass.name` on filesystem I/O that did not
  go through a kubelet volume, and any other storage attribute a getter leaves empty are now
  absent where they carried `""`. OBI's own Prometheus endpoint is unchanged: an empty label
  is no label to Prometheus. On both exporters, `system.filesystem.type` and `fs.operation`
  are now empty, rather than `unknown` and `read`, for a code OBI has no name for; the
  current probes send none, so no emitted series changes today.
- `error.type` on the storage metrics names kernel-internal errnos (512 to 531, such as
  `EJUKEBOX` and `ENOTSUPP`) and the NFSv4 statuses the NFS client passes up unmapped (such as
  `NFS4ERR_DELAY`), which were their decimal values (`528`, `10008`). A query matching the
  decimal value no longer matches.
- On an NFS superblock several volumes share, the first events of a newly seen mount can
  carry no `k8s.persistentvolume.name`, claim or storage class: the mount root's inode, which
  tells the volumes apart, is now looked up in the background instead of holding up the
  pipeline.
- Storage histograms that OBI aggregates in the kernel lose the native part of their
  Prometheus histograms: OBI's Prometheus endpoint emits them with classic buckets only,
  whatever `prometheus_export.native_histogram` says, where the per-event histograms carried
  both classic and native buckets by default. To get native histograms, opt into exponential
  kernel histograms, which OBI also selects when the OTLP exporter's `histogram_aggregation`
  is `base2_exponential_bucket_histogram`; those are emitted as native (Prometheus) and
  exponential (OTLP) histograms only, with no classic buckets, at a fixed scale of 2, coarser
  than the schema 3 per-event native histograms had with the default bucket factor.
- The series identity of the storage metrics shipped in the previous release changes: every `obi.stat.disk.*`
  series gains `obi.disk.stacked` and, with Kubernetes metadata on, `k8s.node.name`; every
  `obi.stat.fs.*` series gains `system.device`, `obi.disk.physical_device`, `server.address`
  (each empty where it does not apply), and with Kubernetes metadata on `k8s.node.name` and
  `k8s.owner.name`. Recording rules and dashboards that match an exact label set, or join
  with `on()`/`ignoring()` against these series, need updating. `fs.operation` also gains
  `fsync`, `fdatasync`, `sync`, `syncfs` and `sync_file_range` (the last three behind
  `storage_fs_sync`), so a query that sums over `fs_operation` without a filter now includes
  durability waits.
- Cache flushes no longer count as writes in `obi.stat.disk.*` (`disk.io.direction="write"`),
  which drops write counts and latencies on fsync-heavy workloads. They are in the new
  `obi.stat.disk.flush.duration`. Discards (and secure erases) were ignored and are now in the
  new `obi.stat.disk.discard.duration` and `obi.stat.disk.discard.io`. Write counts stay below
  the `/proc/diskstats` write count, which counts empty preflush requests as writes.
- `obi.stat.disk.queue.depth` is deprecated and no longer part of `storage_block`, `*` or
  `all`: a configuration that relied on `storage_block_queue` or an umbrella for it must list
  `storage_block_queue_depth`.
- `storage_block` now also enables `storage_block_flush`, `storage_block_discard` and
  `storage_block_pending` (`obi.stat.disk.pending_operations`), `storage_fs` also enables
  `storage_fs_sync` (its own set of probes), and `*`/`all` also enable the new `storage_nfs*`
  metrics (`obi.stat.nfs.client.*`), each adding probes and series where a configuration used
  those umbrellas. List the sub-flags to keep them off.
- The block metrics (`obi.stat.disk.*`) are now counted in the kernel by default, which
  brings the kernel-aggregated histogram change above to them, and their OTLP histograms no
  longer carry `min` and `max`: the kernel does not track them.
  `ebpf.storage_aggregation.disabled: true` restores the per-event path, and with it both.

## Hosting notes

`site/` is published as static files with no markdown processing, so the generated
pages under `site/docs/` are served as markdown, not HTML. They are meant to be
read rendered: on GitHub, or on the OpenTelemetry website, where OBI has a docs
section (`/docs/zero-code/obi/`) that is where these generated pages belong. The
published copies exist so the reference is fetchable at a stable URL alongside the
schema files.
