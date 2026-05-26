# OTEL Metrics Reporter Lifecycle Fix — Design

**Issue:** [open-telemetry/opentelemetry-ebpf-instrumentation#2138](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2138)
**Branch:** `fix/metrics-exporter-lifecycle`
**Date:** 2026-05-27
**Author:** Ron Sevir (TheDwingMAN)

## 1. Problem

Issue #2138 reports OBI memory growing to 124–180 GiB on a single pod in a 32-node cluster. The reporter's heap pprof shows:

- ~47% `inuse_objects` in `prom.(*metricsReporter).observe`
- ~2.8% `inuse_objects` in `otel.(*MetricsReporter).reportMetrics`
- **91,180** goroutines stuck in `metric.NewPeriodicReader.func2`

Two distinct bugs in `pkg/export/otel` produce the OTEL portion of the leak and a lossy log:

1. **Goroutine leak (the main memory eater):**
   In `newMetricsReporter` / `newSvcGraphMetricsReporter`, the LRU eviction callback calls `provider.ForceFlush(ctx)`. `ForceFlush` flushes pending data but does **not** stop the `PeriodicReader`'s background goroutine. Over a long run with service churn, every evicted entry leaks a goroutine that keeps holding its metric instruments, aggregators, and accumulated label sets.

2. **"failed to upload metrics: HTTP exporter is shutdown" (data loss):**
   The previous attempt to fix #1 — naïvely replacing `ForceFlush` with `Shutdown` — exposes a shutdown race. `MetricsReporter` and `SvcGraphMetricsReporter` share **one** OTLP exporter (`MetricsExporterInstancer.Instantiate()` returns the same `sdkmetric.Exporter` instance). Each reporter's `close()` called `mr.exporter.Shutdown(...)` in a detached goroutine. Whichever ran first marked the shared HTTP client as shut down, and every other still-cached `PeriodicReader` started logging `failed to upload metrics: the HTTP exporter is shutdown` at INFO level — silently dropping data.

The fix must address both together: stop the leaked goroutines *without* killing the shared connection that other live providers still depend on.

### Out of scope for this design

- The **47% Prometheus** memory share in the user's pprof. That code path is in `pkg/export/prom`, uses an independent `Expirer[T]` keyed on the prom client's `Collect` callback, and shares no state with the OTEL reporter. It needs its own investigation and is a separate spec.
- The `net.sock.peer.addr` / `net.sock.peer.port` cardinality concern (Grcevski's comment). That is a user-side config issue, not a code bug.

## 2. Architecture

### 2.1 Actors and lifetimes

| Actor | Created | Destroyed | Cardinality |
|---|---|---|---|
| Per-service `MeterProvider` (owns one `PeriodicReader` goroutine) | First span for a service UID | LRU/TTL eviction **or** pipeline shutdown | bounded by `ReportersCacheLen` (default `ReporterLRUSize = 256` in `pkg/obi/config.go`) |
| Shared OTLP `Exporter` (HTTP/gRPC client) | First `MetricsExporterInstancer.Instantiate()` call | Pipeline shutdown, **once** | 1 per OBI process |
| `MetricsReporter`, `SvcGraphMetricsReporter` | Pipeline start | Pipeline shutdown | 1 each |

### 2.2 Lifecycle invariant

> The shared OTLP exporter must outlive every per-service `MeterProvider` that holds a reference to its `PeriodicReader`.

The design enforces this with three rules:

1. **Reporters never see the real exporter.** `MetricsExporterInstancer.Instantiate()` returns `noopShutdownExporter{real}`. The wrapper embeds the real `sdkmetric.Exporter` and overrides only `Shutdown`, which becomes a no-op.
2. **Eviction stops the reader goroutine, not the connection.** The eviction callback calls `provider.Shutdown(ctx)`. Internally that calls `reader.Shutdown` → final flush via the *wrapper* (still works) + cancel the reader's ctx (goroutine exits) + `exporter.Shutdown` on the *wrapper* (no-op). Goroutine: gone. Connection: alive.
3. **Real shutdown happens exactly once, last.** `MetricsExporterInstancer.Shutdown()` is guarded by `sync.Once` and called from `pkg/instrumenter/instrumenter.go` *after* `g.Wait()` returns — meaning every reporter's `close()` has returned, every eviction goroutine has drained, and no `PeriodicReader` is still alive.

### 2.3 New types and signatures

```go
// pkg/export/otel/otelcfg/exporter.go

// noopShutdownExporter lets us share a single sdkmetric.Exporter across many
// per-service MeterProviders. Each provider's Shutdown stops its own
// PeriodicReader but cannot close the shared connection.
type noopShutdownExporter struct{ sdkmetric.Exporter }

func (noopShutdownExporter) Shutdown(context.Context) error { return nil }

type MetricsExporterInstancer struct {
    mutex        sync.Mutex
    instance     sdkmetric.Exporter
    Cfg          *MetricsConfig
    shutdownOnce sync.Once
}

func (i *MetricsExporterInstancer) Instantiate(ctx context.Context) (sdkmetric.Exporter, error)
func (i *MetricsExporterInstancer) Shutdown(ctx context.Context) error
```

```go
// pkg/export/otel/otelcfg/common.go

// Close synchronously evicts every entry in the pool, firing the eviction
// callback for each. Use at reporter shutdown to drain the cache.
func (rp *ReporterPool[K, T]) Close()
```

```go
// pkg/export/otel/otelcfg/config_metrics.go

type MetricsConfig struct {
    // ... existing fields ...
    ProviderShutdownTimeout time.Duration `yaml:"provider_shutdown_timeout" env:"OTEL_EBPF_METRICS_PROVIDER_SHUTDOWN_TIMEOUT"`
}

// Falls back to GetInterval() when unset.
func (m *MetricsConfig) GetProviderShutdownTimeout() time.Duration
```

### 2.4 Reporter struct changes

```go
type MetricsReporter struct {
    // ... existing fields ...
    providerShutdownWg sync.WaitGroup   // tracks in-flight eviction Shutdown goroutines
    systemProvider     *metric.MeterProvider // stored so close() can shut it down
}

type SvcGraphMetricsReporter struct {
    // ... existing fields ...
    providerShutdownWg sync.WaitGroup
}
```

### 2.5 Data flow during shutdown

```
pipeline ctx cancelled
        │
        ▼
each reporter's run loop returns → close() is called
        │
        ▼
reporters.Close()  ── purges the LRU; for each entry, eviction callback fires
        │
        ▼
each eviction callback:
    wg.Add(1)
    go func() {
        defer wg.Done()
        provider.Shutdown(timeoutCtx)   // flushes via noopShutdown wrapper, stops reader goroutine
    }()
        │
        ▼
providerShutdownWg.Wait()  ── close() blocks until every eviction has drained
        │
        ▼
systemProvider.Shutdown(timeoutCtx)  ── only MetricsReporter
        │
        ▼
close() returns; reporter's swarm goroutine exits
        │
        ▼
g.Wait() in instrumenter.RunWithContextInfo unblocks
        │
        ▼
ctxInfo.OTELMetricsExporter.Shutdown(timeoutCtx)  ── sync.Once, closes real OTLP client
        │
        ▼
RunWithContextInfo returns
```

## 3. Concrete code changes

### File-by-file plan (5 files, ~120 LoC net)

**A. `pkg/export/otel/otelcfg/exporter.go`** (~35 LoC)

- Add `noopShutdownExporter` type and its no-op `Shutdown` method.
- Wrap every return value of `Instantiate()` with `noopShutdownExporter{i.instance}`.
- Add `MetricsExporterInstancer.Shutdown(ctx)` guarded by `sync.Once`. It locks the mutex briefly to read `i.instance`, then calls `exp.Shutdown(ctx)` outside the lock.
- Docstring updates clarifying the lifecycle contract.

**B. `pkg/export/otel/otelcfg/common.go`** (~10 LoC)

- Add `ReporterPool[K,T].Close()` that nils the `lastReporter` short-circuit fields and calls `rp.pool.Purge()`. `Purge` invokes the eviction callback for every entry synchronously, so callers do not need to know about cache internals.

**C. `pkg/export/otel/otelcfg/config_metrics.go`** (~15 LoC)

- Add `ProviderShutdownTimeout` field with `yaml` + `env` tags.
- Add `GetProviderShutdownTimeout()` falling back to `GetInterval()` when zero.

**D. `pkg/export/otel/metrics.go`** (~30 LoC)

- Add `providerShutdownWg sync.WaitGroup` and `systemProvider *metric.MeterProvider` to `MetricsReporter`.
- In the eviction callback inside `newMetricsReporter`:
  - `mr.providerShutdownWg.Add(1)` synchronously **before** spawning the goroutine.
  - The goroutine `defer`s `Done()`, builds a `context.WithTimeout(context.Background(), cfg.GetProviderShutdownTimeout())`, and calls `v.provider.Shutdown(shutdownCtx)`. Background context — *not* the pipeline ctx — so cancellation during shutdown doesn't pre-empt the final flush.
- After `mr.systemMetrics := mr.newMetricsInstance(nil)`, store `mr.systemProvider = systemMetrics.provider`.
- Rewrite `close()`:
  ```go
  func (mr *MetricsReporter) close() {
      mr.reporters.Close()                     // fires eviction for every entry
      mr.providerShutdownWg.Wait()             // wait for those goroutines
      ctx, cancel := context.WithTimeout(context.Background(), mr.cfg.GetProviderShutdownTimeout())
      defer cancel()
      if err := mr.systemProvider.Shutdown(ctx); err != nil {
          mlog().Warn("closing system metrics provider", "error", err)
      }
      // NOTE: the shared exporter is shut down by the instrumenter, not here.
  }
  ```
- Add a one-line comment above the `metric.NewPeriodicReader(mr.exporter, ...)` call in `newMetricsInstance` explaining that `mr.exporter` is the noop-shutdown wrapper.

**E. `pkg/export/otel/metrics_svc_graph.go`** (~25 LoC)

Same shape as D, minus the system-provider piece (svc-graph doesn't have one). Eviction callback gains `providerShutdownWg`; `close()` becomes purge + wait.

**F. `pkg/instrumenter/instrumenter.go`** (~10 LoC)

After the existing `g.Wait()` call in `RunWithContextInfo`:

```go
shutdownCtx, cancel := context.WithTimeout(
    context.Background(),
    ctxInfo.OTELMetricsExporter.Cfg.GetProviderShutdownTimeout(),
)
defer cancel()
if err := ctxInfo.OTELMetricsExporter.Shutdown(shutdownCtx); err != nil {
    slog.Warn("closing OTEL metrics exporter", "error", err)
}
```

**G. `devdocs/config/config-schema.json`** (~12 LoC)

Add the `provider_shutdown_timeout` field under `otel_metrics_export` with the same description as the Go doc.

### What we intentionally do NOT change

- The LRU cache implementation (`simplelru.LRU`). The bug is in callback semantics, not the cache.
- The `Expirer` in `pkg/export/prom`. Out of scope.
- `MetricsExporterInstancer.Instantiate()`'s caching behaviour (`i.instance` reuse). Still one underlying exporter; we only change what each caller sees.
- Public types / YAML config except adding one optional knob.

## 4. Error handling & edge cases

| Case | Handling |
|---|---|
| Eviction `Shutdown` returns error (timeout, network) | Logged at WARN with service UID. Goroutine exits, `wg.Done()` still fires (`defer`). No leak. |
| Shutdown ctx times out mid-flight | Data for that one provider is lost on that flush attempt only. Other providers unaffected. Bounded by `ProviderShutdownTimeout`. |
| Many concurrent evictions (cache full + churn) | Each spawns its own goroutine; bounded by `ReportersCacheLen` (default 256). `wg.Wait()` correctly waits for all. |
| Real exporter shutdown called twice | `sync.Once` guarantees the second call is a no-op. |
| Reporter never started any per-service provider | `reporters.Close()` purges empty cache; `wg.Wait()` returns immediately. |
| Pipeline ctx already cancelled when `close()` runs | Eviction goroutines use `context.Background()` with their own timeout — they complete their final flush regardless. |
| System-metrics provider not initialised (early error) | `mr.systemProvider` is nil; `close()` guards with `if mr.systemProvider != nil`. |
| `MetricsExporterInstancer` was never instantiated (no metrics configured) | `i.instance` is nil; `Shutdown()` checks and returns nil. Already in current branch — preserved. |

## 5. Testing

All tests live in `pkg/export/otel/dont-upload/` — a directory we deliberately exclude from upstream contribution (path name signals this). These are regression tests for our local fix; if the design merges upstream we'd port a subset.

### 5.1 `TestEviction_ExporterRemainsOperational`

**Purpose:** Regression test for the "HTTP exporter is shutdown" log.
**Setup:** Real `collector.Start(ctx)` OTLP HTTP collector. `ReportersCacheLen: 1`, short export `Interval`.
**Action:** Push spans for service A, then service B (evicts A), then service C (evicts B), then more spans for service C.
**Assert:** The collector receives at least N export records for service C *after* the evictions of A and B. With the old code, exports for C stop because A's eviction killed the shared exporter.

### 5.2 `TestEviction_GoroutineCountStaysBounded`

**Purpose:** Regression test for the goroutine leak.
**Setup:** Real collector. `ReportersCacheLen: 50`, `Interval: 50 * time.Millisecond`.
**Action:** Push spans for 500 distinct service UIDs, paced so evictions happen continuously. Sample `runtime.NumGoroutine()` at start, mid-churn, and end (after a brief settle).
**Assert:** End-state goroutine count is within a small delta (e.g. ≤ `ReportersCacheLen + 20` overhead) of start-state, **not** proportional to the number of unique services seen. With the old code, the delta would be ~500.

### 5.3 `TestProviderShutdownTimeout_Configurable`

**Purpose:** Verify the new config knob takes effect.
**Setup:** A blocking exporter that hangs in `Export`. `ProviderShutdownTimeout: 100ms`.
**Action:** Push a span, evict via cache pressure.
**Assert:** Eviction's `provider.Shutdown` returns within ~100ms with a deadline-exceeded error. Without the knob, it would block for `Interval` (could be seconds).

### 5.4 Unit-test reasoning beyond what's coded

- The new wrapper is exercised implicitly by every test above (each provider's `Shutdown` would propagate to the real exporter without it; 5.1 would fail).
- The `sync.Once` semantics of `MetricsExporterInstancer.Shutdown` are covered by calling `Shutdown` twice in a small focused test (`TestExporterInstancer_ShutdownIdempotent`).

### 5.5 Lint & compile

`go vet ./...` and `go test ./pkg/export/otel/...` must pass. CI's existing race-detector job covers the `sync.WaitGroup` / `sync.Once` correctness.

## 6. Verification protocol on the leaking cluster

This is the part that's *missing* from the current branch — the fix must be validated against the real workload before opening an upstream PR.

### 6.1 Pre-flight (local)

1. `git checkout fix/metrics-exporter-lifecycle && go build ./cmd/...`
2. Run the three regression tests in §5 with `-race`. All must pass.
3. Build a container image tagged `obi:fix-metrics-lifecycle-<short-sha>`.

### 6.2 Baseline capture (current, buggy production OBI)

On one pod showing the leak symptom:

```bash
# Capture goroutine + heap profiles for "before" comparison.
curl -s http://<pod>:<pprof-port>/debug/pprof/goroutine -o baseline-goroutine.pb.gz
curl -s http://<pod>:<pprof-port>/debug/pprof/heap      -o baseline-heap.pb.gz

# Capture RSS at t=0.
kubectl top pod <pod> > baseline-rss.txt
```

Record from the baseline:
- `NumGoroutine` (sum) — expect tens of thousands.
- Count of frames matching `metric.NewPeriodicReader.func2` — expect ~thousands+.
- RSS — expect tens of GiB on the affected pod.

### 6.3 Deploy the fix to **one** pod first

Roll the new image to a single pod via a targeted manifest patch (don't update the whole DaemonSet yet). Pin scheduling to the same node where the leaking pod lives so cluster context matches.

### 6.4 Observation window (≥ 4 hours, ideally 24h)

Sample every 15 min:

```bash
curl -s http://<pod>:<pprof-port>/debug/pprof/goroutine -o gor-$(date +%s).pb.gz
kubectl top pod <pod>                                   >> rss-timeseries.txt
kubectl logs <pod> | grep -E "exporter is shutdown|evicted metrics provider" | wc -l
```

### 6.5 Success criteria

All four must hold:

- **Goroutine count stays flat or sublinear over the observation window** (no monotone climb tied to service churn).
- **RSS plateau within 2× the median across healthy pods** (other pods in the issue use 2–12 GiB; affected pod should land in that range).
- **Zero occurrences of `failed to upload metrics: ... HTTP exporter is shutdown`** in logs.
- **No new ERROR-level logs** introduced by the change.

### 6.6 Rollback condition

If RSS continues to climb past 2× the healthy-pod baseline, or any of the four criteria fails:

1. Roll the pod back to the previous image.
2. Capture a final heap + goroutine profile *before* rollback.
3. Diff against §6.2 baseline — if `metric.NewPeriodicReader.func2` count is flat but RSS still climbs, the residual leak is in `pkg/export/prom` (the 47% pprof share). That's a separate spec.

### 6.7 If verification passes

1. Prepare the upstream PR branch: keep the production code changes (files A–G), but strip the `pkg/export/otel/dont-upload/` directory from the upstream PR. Port a smaller upstreamable version of test 5.1 (`TestEviction_ExporterRemainsOperational`) into the standard `pkg/export/otel/` test location — that one test is the most direct regression proof for the headline bug.
2. Update the PR description on `fix/metrics-exporter-lifecycle` with the before/after profile screenshots and goroutine-count graph from §6.4.
3. Open the upstream PR against `open-telemetry/opentelemetry-ebpf-instrumentation:main` linking issue #2138.

## 7. Risks & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| OTel-go internal `PeriodicReader.Shutdown` semantics change in a future minor release | Low | Pinned go.mod version; CI catches; wrapper is local code we control. |
| Many concurrent eviction goroutines spike CPU briefly | Low | Bounded by `ReportersCacheLen` (default 256). Acceptable for shutdown-only. |
| `sync.Once` on `MetricsExporterInstancer.Shutdown` masks a real second-shutdown bug | Low | The second call returning nil is the correct semantic. Logged at the call site if first call errored. |
| Verification reveals the remaining leak is mostly prom-side, not OTEL | **High** | This is expected (pprof shows 47% prom vs 2.8% OTEL). The plan explicitly carves prom into a separate spec; this fix is still load-bearing for the OTEL share + the data-loss log. |

## 8. Acceptance criteria

The fix is complete when:

1. All three regression tests in §5 pass with `-race`.
2. The verification protocol in §6 reaches §6.7.
3. Upstream PR is open against `open-telemetry/opentelemetry-ebpf-instrumentation:main`.
