# Storage Metrics Review and Design Notes

## Summary

This document summarizes the design discussion around the PR adding storage metrics.

## High-level assessment of the PR

The idea is good in principle, but it is not low-risk. It adds new kernel-level metrics spanning block I/O, file sync, NFS client, and pod-to-volume mapping. The value is real, but the implementation touches:

- kernel tracepoints
- BTF assumptions
- kprobe attachment behavior
- Kubernetes informer dependencies
- high-cardinality metric labels
- stale series and lifetime handling

This means the feature is useful, but it needs strict runtime guardrails, explicit compatibility checks, and a staged rollout.

## Review comments by file

### `pkg/export/feature.go`

Main issues:
- The feature gate model is broad and easy to misuse.
- It does not clearly separate low-risk TCP stats from higher-risk storage metrics.
- There is no explicit conflict or compatibility checking for kernel-dependent features.

Recommended changes:
- Split TCP stats from storage metrics.
- Add explicit feature groups for disk, NFS, fsync, and pod-volume metrics.
- Add helper methods such as:
  - `AnyStorageMetrics()`
  - `RequiresKProbes()`
  - `RequiresBTF()`
  - `HighCardinalityMetrics()`
- Add validation around incompatible combinations, such as dynamic application selection + disk/NFS/fsync metrics.

### `pkg/export/otel/metrics_stats.go`

Main issues:
- No preflight validation for kernel prerequisites.
- Silent partial success when BTF or kprobes are unavailable.
- No guard against high-cardinality label combinations.

Recommended changes:
- Add a `validateStorageFeatures()` preflight check.
- Disable features gracefully when dynamic selection, BTF, or kprobes are unavailable.
- Log exact reasons for each disabled feature.
- Add cardinality warnings for label combinations involving `system.device` and K8s pod labels.

### `pkg/export/prom/prom_stats.go`

Main issues:
- No protection against Prometheus label cardinality explosions.
- No explicit stale-series expiry logic for gauge-like metrics.
- No validation of high-cardinality label combos before registration.

Recommended changes:
- Add `CardinalityMonitor` logic.
- Validate label combinations before registering collectors.
- Explicitly expire stale series for volume/device tracking metrics.
- Add alerting/logging for cardinality threshold breaches.

### `bpf/statsolly/tp_blk.c`

Main issues:
- Block I/O tracepoint fields vary by kernel version.
- Misattribution risk when cgroup or device extraction fails.
- Stacked devices (LVM, md) require additional handling.

Recommended changes:
- Add kernel-version-aware field access.
- Use CO-RE fallbacks and graceful skips on unsupported fields.
- Log when attribution is degraded instead of fabricating data.
- Separate stacked-device handling from direct device handling.

### `bpf/statsolly/k_fsync.c`

Main issues:
- Kprobe failures may be silent.
- Nested sync calls can double count.
- Invalid fd handling is too loose.

Recommended changes:
- Track kprobe attachment status explicitly.
- Add nested sync detection using a per-task stack.
- Validate fd values before processing.
- Surface attachment failures in logs and health checks.

### `bpf/statsolly/tp_nfs.c`

Main issues:
- NFS metrics depend on `sunrpc` and `nfs` BTF.
- Missing BTF can silently break metrics.
- Struct assumptions differ across kernel versions.

Recommended changes:
- Add explicit BTF validation before attaching programs.
- Fail gracefully with clear warnings when BTF is missing.
- Use robust `bpf_core_field_exists()` checks.
- Keep NFS metrics strictly opt-in and marked advanced.

### `cmd/k8s-cache/main.go`

Main issues:
- Adding a PersistentVolume informer creates a new dependency and RBAC requirement.
- Informer failure can degrade volume attribution without a clear operator signal.

Recommended changes:
- Make the PV informer optional.
- Validate RBAC early (`list` and `watch` on `persistentvolumes`).
- Add health checks and startup timing so stale PV mapping is visible.
- Keep pod-volume metrics optional and independent of the rest of the storage metrics.

## Conceptual design recommendations

### What metrics to add

The metric set should be added in stages.

Stage 1 (safe, high-value):
- `obi.stat.disk.io`
- `obi.stat.disk.operations`
- `obi.stat.disk.operation.time`
- `obi.stat.fs.sync.duration`
- `obi.stat.disk.flush.duration` (experimental)

These are directly useful and relatively easy to explain.

Stage 2 (advanced):
- `obi.stat.nfs.client.procedure.duration`
- `obi.stat.nfs.client.io`
- `obi.stat.k8s.pod.volume.device`

These are valuable, but should be treated as advanced because they depend on BTF, kernel support, K8s cache state, or high-cardinality mappings.

### What metrics to omit for now

These are either too noisy, too kernel-specific, or too operationally risky for an initial rollout:
- `obi.stat.disk.operation.duration` (histogram): noisy, especially without more tuning and filtering
- `obi.stat.disk.queue.duration`: high kernel variability; add only after testing
- `obi.stat.disk.pending_operations`: gauge semantics can cause stale series issues
- `obi.stat.disk.discard.duration` and `obi.stat.disk.discard.io`: low signal in most deployments
- NFS server-side metrics: outside scope of client-side instrumentation
- RPC-level details below NFS: too low-level and too variable
- detailed stacked-volume accounting: too complex for default exposure

## Recommended rollout plan

1. Ship basic disk I/O metrics first.
2. Add fsync metrics with kprobe guards.
3. Keep NFS client metrics behind separate advanced feature gates.
4. Only add pod-volume mapping after cardinality and RBAC are validated.
5. Keep queue/pending/discard metrics for later PRs.

## Core principle

Do not “ship everything at once.”

The right product design is:
- ship the high-value, stable 80% first
- keep the risky, broad, kernel-dependent features explicitly opt-in
- fail fast with clear operator signals when prerequisites are missing

This prevents misleading data and keeps the feature usable across different kernels and deployments.

## Final verdict on the idea

The idea is not bad. It is operationally useful, and it captures a real visibility gap in Kubernetes and Linux environments.

The problem is not the concept; the problem is the breadth and the assumptions behind it. It needs explicit runtime validation, strong defaults, and a staged rollout rather than a single “everything enabled” feature bundle.

The right long-term product is a carefully scoped storage metrics platform, not a catch-all storage instrumentation framework.

---

# Additional notes from the discussion: storage metrics strategy

## What I would add

### Stage 1: Block I/O attribution
- `obi.stat.disk.io`
- `obi.stat.disk.operations`
- `obi.stat.disk.operation.time`
- with `system.device` and `operation` attributes
- cgroup-based attribution via the first bio

### Stage 1: Filesystem sync latency
- `obi.stat.fs.sync.duration`
- with `obi.fs.sync.type` attribute
- optional filesystem attributes for mountpoint and type

### Stage 2: NFS client health
- `obi.stat.nfs.client.procedure.duration`
- `obi.stat.nfs.client.io`
- strict opt-in; only when BTF is present

### Stage 2: Volume mapping
- `obi.stat.k8s.pod.volume.device`
- separate feature gate
- requires PV informer and is subject to high-cardinality limits

## What I would omit

- queue duration histograms
- pending operation gauges
- discard metrics
- low-level NFS RPC instrumentation
- stacked volume tracing by default
- any feature that causes stale series or silent partial correctness

## Design philosophy

- Favor stable, valuable telemetry over exhaustive kernel introspection.
- Prefer low-cardinality, clearly attributed metrics.
- Make risky features explicit and optional.
- Fail gracefully when BTF, kprobes, or Kubernetes metadata are not available.

## Bottom line

The storage metrics idea is a strong one, but the implementation should be segmented by risk and by operational value. The right initial shape is a smaller, clearer first version based on basic disk I/O and fsync instrumentation, with NFS and pod-volume mapping held back behind stricter feature gates and better runtime validation.
