# OTEL Metrics Lifecycle Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the OTEL metrics goroutine leak (issue #2138) and the "HTTP exporter is shutdown" data-loss log, then verify the fix on the leaking production cluster before opening the upstream PR.

**Architecture:** Wrap the shared OTLP exporter in a `noopShutdownExporter` so per-service `MeterProvider.Shutdown()` stops its `PeriodicReader` goroutine and flushes via the wrapper without closing the real connection. Close the real exporter exactly once from `pkg/instrumenter` after `g.Wait()` returns.

**Tech Stack:** Go 1.22+, `go.opentelemetry.io/otel/sdk/metric`, `github.com/hashicorp/golang-lru/v2/simplelru`, OBI's existing `swarm` lifecycle, `collector.Start(ctx)` test harness for OTLP HTTP.

**Spec:** [docs/superpowers/specs/2026-05-27-otel-metrics-lifecycle-fix-design.md](../specs/2026-05-27-otel-metrics-lifecycle-fix-design.md)

**Branch:** Work on `fix/metrics-exporter-lifecycle` on the user's fork (`ronen` remote → github.com/TheDwingMAN/opentelemetry-ebpf-instrumentation). The code changes for Tasks 1–8 are **already present** on this branch from commit `2f9e0306`. Use Tasks 1–8 as an **audit checklist**: open each file, confirm the code matches what's shown here. If it does, tick the boxes and move on. If it diverges, reconcile by applying what's shown. Tasks 9–17 (regression tests audit, verification protocol, upstream PR prep) are the active work.

---

## Phase split — who executes what

The cluster in this work is an **on-prem cluster only the user can reach**. An automated agent cannot run `kubectl`, push to the cluster's registry, or scrape pprof endpoints on it.

| Phase | Tasks | Executor |
|---|---|---|
| Phase 1 — Code audit + tests | 0–9 | Agent (or user). All work is local to the repo + `go test`. |
| **CHECKPOINT 1** | — | Agent **stops** and reports back to user. User runs Phase 2. |
| Phase 2 — Cluster verification | 10–14 | **User only.** Requires `kubectl`, the cluster registry, and a running affected pod. |
| **CHECKPOINT 2** | — | User reports verification result (pass / fail / inconclusive) to the next session. |
| Phase 3 — Upstream PR prep | 15–17 | Agent (or user). Local branch surgery + `gh pr create`. Only proceed if Phase 2 passed. |

Every task in Phase 2 carries a **`USER ONLY`** banner. An agent reaching one of those banners must stop and surface the checkpoint to the user.

---

## File Map

| # | File | Status on branch | Purpose |
|---|---|---|---|
| A | `pkg/export/otel/otelcfg/exporter.go` | already changed | `noopShutdownExporter` + `MetricsExporterInstancer.Shutdown` |
| B | `pkg/export/otel/otelcfg/common.go` | already changed | `ReporterPool.Close()` |
| C | `pkg/export/otel/otelcfg/config_metrics.go` | already changed | `ProviderShutdownTimeout` field + getter |
| D | `pkg/export/otel/metrics.go` | already changed | `MetricsReporter` lifecycle: `providerShutdownWg`, `systemProvider`, new `close()` |
| E | `pkg/export/otel/metrics_svc_graph.go` | already changed | Same shape as D for the service-graph reporter |
| F | `pkg/instrumenter/instrumenter.go` | already changed | Final `MetricsExporterInstancer.Shutdown` after `g.Wait()` |
| G | `devdocs/config/config-schema.json` + `devdocs/config/CONFIG.md` | already changed | Generated docs for the new config knob |
| H | `pkg/export/otel/dont-upload/metrics_eviction_test.go` | already exists | Three regression tests (kept local) |

---

## Part 1 — Code audit (Tasks 1–8)

The branch `fix/metrics-exporter-lifecycle` was last updated with merge `a7f133cd` (upstream main into the branch) and docs commits `75b8324f`, `5219153a`. Before touching anything, confirm the working tree is clean and the branch is up to date with `ronen`.

### Task 0: Sanity check the branch

**Files:** none

- [ ] **Step 1: Confirm branch + remote state**

Run:
```bash
git switch fix/metrics-exporter-lifecycle
git fetch ronen
git status
git log --oneline -5
```
Expected:
- Working tree clean (or only the untracked `tests_metrics_fix/` directory, which is unrelated and stays untouched).
- Local HEAD matches `ronen/fix/metrics-exporter-lifecycle`.
- Top of log shows `5219153a docs(config): regenerate CONFIG.md...` then `75b8324f docs(spec): ...` then `a7f133cd Merge...`.

If the branch is not on `5219153a` or later, stop and report — something has changed since the plan was written.

- [ ] **Step 2: Build once to baseline compile errors**

Run:
```bash
go build ./...
```
Expected: exits 0, no output. If it fails, the existing branch state is broken; report and stop.

---

### Task 1: Audit `pkg/export/otel/otelcfg/exporter.go`

**File:**
- Modify: `pkg/export/otel/otelcfg/exporter.go`

This file should declare `NoopShutdownExporter`, wrap every return from `Instantiate()`, and expose a `Shutdown()` guarded by `sync.Once`.

- [ ] **Step 1: Read the current file**

Run:
```bash
sed -n '1,90p' pkg/export/otel/otelcfg/exporter.go
```

- [ ] **Step 2: Confirm the type declaration**

Expected to see, near the top of the file:

```go
// NoopShutdownExporter wraps a shared Exporter and turns Shutdown into a no-op.
// This allows individual MeterProviders to call provider.Shutdown() (which stops
// the PeriodicReader goroutine and flushes pending data) without permanently
// marking the shared underlying exporter as shut-down.
// The real exporter is shut down exactly once by MetricsExporterInstancer.Shutdown().
type NoopShutdownExporter struct{ sdkmetric.Exporter }

func (NoopShutdownExporter) Shutdown(context.Context) error { return nil }
```

If missing or different, replace the type block with the above.

- [ ] **Step 3: Confirm `MetricsExporterInstancer` has `shutdownOnce`**

Expected struct shape:

```go
type MetricsExporterInstancer struct {
    mutex        sync.Mutex
    instance     sdkmetric.Exporter
    Cfg          *MetricsConfig
    shutdownOnce sync.Once
}
```

- [ ] **Step 4: Confirm `Instantiate` wraps every return**

The function must return `NoopShutdownExporter{i.instance}` on **all three** paths: cached-instance return, MetricsConsumer return, and protocol-selected return. If any path returns the raw `i.instance`, the bug is back.

- [ ] **Step 5: Confirm `Shutdown` exists with `sync.Once`**

Expected:

```go
// Shutdown flushes and closes the underlying shared exporter exactly once.
// Call this after all reporters have shut down their MeterProviders, so no
// PeriodicReader goroutine is still exporting when the connection closes.
func (i *MetricsExporterInstancer) Shutdown(ctx context.Context) error {
    var err error
    i.shutdownOnce.Do(func() {
        i.mutex.Lock()
        exp := i.instance
        i.mutex.Unlock()
        if exp != nil {
            err = exp.Shutdown(ctx)
        }
    })
    return err
}
```

- [ ] **Step 6: Build**

Run:
```bash
go build ./pkg/export/otel/otelcfg/...
```
Expected: exits 0.

If you had to apply changes in Steps 2/3/5, commit now:
```bash
git add pkg/export/otel/otelcfg/exporter.go
git commit -m "fix(metrics): audit-correct exporter.go to spec"
```

---

### Task 2: Audit `pkg/export/otel/otelcfg/common.go`

**File:**
- Modify: `pkg/export/otel/otelcfg/common.go` (around line 313)

- [ ] **Step 1: Confirm `ReporterPool.Close` exists**

Run:
```bash
grep -A 8 "^func (rp \*ReporterPool\[K, T\]) Close" pkg/export/otel/otelcfg/common.go
```

Expected output:

```go
func (rp *ReporterPool[K, T]) Close() {
    rp.lastServiceUID = emptyUID
    rp.lastService = nil
    rp.lastReporter = nil
    rp.pool.Purge()
}
```

If missing, add it directly above `func (rp *ReporterPool[K, T]) get(`. Resetting the `lastService*` short-circuit fields is required — otherwise a stale pointer would survive the Purge.

- [ ] **Step 2: Build**

Run:
```bash
go build ./pkg/export/otel/otelcfg/...
```
Expected: exits 0.

If applied, commit:
```bash
git add pkg/export/otel/otelcfg/common.go
git commit -m "fix(metrics): audit-correct ReporterPool.Close"
```

---

### Task 3: Audit `pkg/export/otel/otelcfg/config_metrics.go`

**File:**
- Modify: `pkg/export/otel/otelcfg/config_metrics.go`

- [ ] **Step 1: Confirm `ProviderShutdownTimeout` field**

Expected near the other duration fields in `MetricsConfig`:

```go
// ProviderShutdownTimeout is the maximum time allowed for a MeterProvider to
// flush its pending metrics when evicted from the reporters cache.
// Defaults to Interval when unset.
ProviderShutdownTimeout time.Duration `yaml:"provider_shutdown_timeout" env:"OTEL_EBPF_METRICS_PROVIDER_SHUTDOWN_TIMEOUT"`
```

- [ ] **Step 2: Confirm `GetProviderShutdownTimeout` getter**

Expected:

```go
// GetProviderShutdownTimeout returns the configured eviction flush timeout,
// falling back to GetInterval() when ProviderShutdownTimeout is not set.
func (m *MetricsConfig) GetProviderShutdownTimeout() time.Duration {
    if m.ProviderShutdownTimeout == 0 {
        return m.GetInterval()
    }
    return m.ProviderShutdownTimeout
}
```

- [ ] **Step 3: Build**

```bash
go build ./pkg/export/otel/otelcfg/...
```
Expected: exits 0.

---

### Task 4: Audit `pkg/export/otel/metrics.go`

**File:**
- Modify: `pkg/export/otel/metrics.go`

- [ ] **Step 1: Confirm struct fields**

Run:
```bash
grep -E "providerShutdownWg|systemProvider" pkg/export/otel/metrics.go
```

Expected output includes the struct declaration and at least one use of each field:
```
providerShutdownWg sync.WaitGroup
systemProvider     *metric.MeterProvider
```

- [ ] **Step 2: Confirm `sync` is imported**

Run:
```bash
head -20 pkg/export/otel/metrics.go | grep -E '"sync"|"context"'
```
Expected: both imports present.

- [ ] **Step 3: Confirm eviction callback uses `Shutdown`**

The eviction callback in `newMetricsReporter` (around line 305–325) must:
1. Call `mr.providerShutdownWg.Add(1)` **before** spawning the goroutine.
2. Inside the goroutine, `defer mr.providerShutdownWg.Done()`.
3. Build a `context.WithTimeout(context.Background(), cfg.GetProviderShutdownTimeout())` — `Background`, not the pipeline ctx.
4. Call `v.provider.Shutdown(shutdownCtx)` — **not** `ForceFlush`.

Expected shape:

```go
mr.providerShutdownWg.Add(1)
go func() {
    defer mr.providerShutdownWg.Done()
    shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.GetProviderShutdownTimeout())
    defer cancel()
    if err := v.provider.Shutdown(shutdownCtx); err != nil {
        llog.Warn("error shutting down evicted metrics provider", "error", err)
    }
}()
```

- [ ] **Step 4: Confirm `systemProvider` is stored**

Around the call site for `mr.newMetricsInstance(nil)` (the host-info/system meter), the result's `provider` field must be assigned to `mr.systemProvider`:

```go
systemMetrics := mr.newMetricsInstance(nil)
mr.systemProvider = systemMetrics.provider
```

- [ ] **Step 5: Confirm `close()` shape**

Expected:

```go
func (mr *MetricsReporter) close() {
    mr.reporters.Close()
    mr.providerShutdownWg.Wait()
    shutdownCtx, cancel := context.WithTimeout(context.Background(), mr.cfg.GetProviderShutdownTimeout())
    defer cancel()
    if mr.systemProvider != nil {
        if err := mr.systemProvider.Shutdown(shutdownCtx); err != nil {
            mlog().Warn("closing system metrics provider", "error", err)
        }
    }
    mlog().Debug("Metrics reporter closed")
}
```

Critical: `close()` must **not** call `mr.exporter.Shutdown(...)` anywhere. The real exporter is closed only by `MetricsExporterInstancer.Shutdown()` (Task 6).

The spec adds a `if mr.systemProvider != nil` guard for the edge case where construction errors before the system provider is built; if the current code does not have the nil-guard, add it.

- [ ] **Step 6: Build**

```bash
go build ./pkg/export/otel/...
```
Expected: exits 0.

If you applied corrections, commit:
```bash
git add pkg/export/otel/metrics.go
git commit -m "fix(metrics): audit-correct MetricsReporter lifecycle"
```

---

### Task 5: Audit `pkg/export/otel/metrics_svc_graph.go`

**File:**
- Modify: `pkg/export/otel/metrics_svc_graph.go`

Mirror of Task 4 minus the system-provider piece — the service-graph reporter does not maintain a per-process system meter.

- [ ] **Step 1: Confirm `providerShutdownWg` exists on `SvcGraphMetricsReporter`**

Run:
```bash
grep -A 1 "providerShutdownWg" pkg/export/otel/metrics_svc_graph.go
```
Expected: `providerShutdownWg sync.WaitGroup` declared as a field on the `SvcGraphMetricsReporter` struct, with a comment such as:

```go
// providerShutdownWg tracks in-flight eviction goroutines so close() can
// wait for all of them before returning.
providerShutdownWg sync.WaitGroup
```

- [ ] **Step 2: Confirm `sync` is imported**

Run:
```bash
head -20 pkg/export/otel/metrics_svc_graph.go | grep '"sync"'
```
Expected: `"sync"` present in the import block.

- [ ] **Step 3: Confirm eviction callback uses `Shutdown` with the WaitGroup**

The eviction callback inside `newSvcGraphMetricsReporter` must:
1. Call `mr.providerShutdownWg.Add(1)` **before** spawning the goroutine.
2. Inside the goroutine, `defer mr.providerShutdownWg.Done()`.
3. Build a `context.WithTimeout(context.Background(), cfg.GetProviderShutdownTimeout())` — `Background`, not the pipeline ctx.
4. Call `v.provider.Shutdown(shutdownCtx)` — **not** `ForceFlush`.

Expected shape:

```go
mr.providerShutdownWg.Add(1)
go func() {
    defer mr.providerShutdownWg.Done()
    shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.GetProviderShutdownTimeout())
    defer cancel()
    if err := v.provider.Shutdown(shutdownCtx); err != nil {
        llog.Warn("error shutting down evicted metrics provider", "error", err)
    }
}()
```

- [ ] **Step 4: Confirm `close()`**

Expected:

```go
func (mr *SvcGraphMetricsReporter) close() {
    mr.reporters.Close()
    mr.providerShutdownWg.Wait()
    mr.log.Debug("SvcGraph metrics reporter closed")
}
```

It must **not** call `mr.exporter.Shutdown(...)` anywhere. The real exporter is closed only by `MetricsExporterInstancer.Shutdown()` (Task 6).

- [ ] **Step 5: Build**

```bash
go build ./pkg/export/otel/...
```
Expected: exits 0.

If you applied corrections, commit:
```bash
git add pkg/export/otel/metrics_svc_graph.go
git commit -m "fix(metrics): audit-correct SvcGraphMetricsReporter lifecycle"
```

---

### Task 6: Audit `pkg/instrumenter/instrumenter.go`

**File:**
- Modify: `pkg/instrumenter/instrumenter.go`

- [ ] **Step 1: Locate `RunWithContextInfo` and confirm the final shutdown call**

Run:
```bash
grep -A 12 "if err := g.Wait" pkg/instrumenter/instrumenter.go
```

Expected:

```go
if err := g.Wait(); err != nil {
    return err
}

// All pipeline goroutines have exited; every MeterProvider has been shut down
// via the NoopShutdownExporter wrapper. Now close the real shared exporter once.
shutdownCtx, cancel := context.WithTimeout(context.Background(), ctxInfo.OTELMetricsExporter.Cfg.GetProviderShutdownTimeout())
defer cancel()
if err := ctxInfo.OTELMetricsExporter.Shutdown(shutdownCtx); err != nil {
    slog.Warn("closing OTEL metrics exporter", "error", err)
}
```

If `ctxInfo.OTELMetricsExporter` could be nil in some configurations (no OTEL metrics enabled), add a nil-guard:
```go
if ctxInfo.OTELMetricsExporter != nil { ... }
```

- [ ] **Step 2: Confirm imports**

`context` and `slog` must already be imported (they are in the existing file). If `time` is needed elsewhere, leave it.

- [ ] **Step 3: Build**

```bash
go build ./...
```
Expected: exits 0.

---

### Task 7: Audit `devdocs/config/config-schema.json` + `devdocs/config/CONFIG.md`

**Files:**
- `devdocs/config/config-schema.json`
- `devdocs/config/CONFIG.md`

- [ ] **Step 1: Run the schema generator**

Run:
```bash
make generate-config-schema 2>/dev/null || go run ./cmd/obi-schema -output devdocs/config/config-schema.json
go run ./cmd/config-docs -schema devdocs/config/config-schema.json -output devdocs/config/CONFIG.md
git status
```

Expected: working tree is clean. If either file is modified, the generator caught new drift — investigate, commit the regen if it is purely the result of running the generator on the current source:
```bash
git add devdocs/config/config-schema.json devdocs/config/CONFIG.md
git commit -m "docs(config): regenerate schema and CONFIG.md"
```

---

### Task 8: Run the full Go test suite once

**Files:** none

- [ ] **Step 1: Run with the race detector**

Run:
```bash
go test -race ./pkg/export/otel/...
```

Expected: all PASS. If any test fails, stop and fix before continuing. Do not proceed to Part 2 until this is green.

- [ ] **Step 2: Run the broader package set**

Run:
```bash
go test -race ./pkg/...
```

Expected: all PASS. Treat any failure as a blocker.

---

## Part 2 — Regression tests audit (Task 9)

### Task 9: Audit `pkg/export/otel/dont-upload/metrics_eviction_test.go`

**File:**
- `pkg/export/otel/dont-upload/metrics_eviction_test.go` (already exists)

This file must contain three tests covering the spec's §5.

- [ ] **Step 1: Confirm the three test functions exist**

Run:
```bash
grep -E "^func Test" pkg/export/otel/dont-upload/metrics_eviction_test.go
```

Expected output includes the four function names, one for each of:
- `TestEviction_ExporterRemainsOperational` (spec §5.1)
- `TestEviction_GoroutineCountStaysBounded` or similar (spec §5.2)
- `TestProviderShutdownTimeout_Configurable` or similar (spec §5.3)
- `TestExporterInstancer_ShutdownIdempotent` (spec §5.4)

If any of the three is missing, add it. The shape of each test (verbatim from spec §5):

**§5.1 — TestEviction_ExporterRemainsOperational**
- Setup: `collector.Start(ctx)` for a real OTLP HTTP endpoint, `ReportersCacheLen: 1`, short `Interval` (e.g., `20 * time.Millisecond`).
- Action: push spans for service A → service B (evicts A) → service C (evicts B) → more spans for C.
- Assert: collector receives ≥ N export records bearing service C's resource attributes **after** the evictions of A and B (use `otlp.Records()` to inspect what arrived). Without the fix, the second eviction silently kills the shared exporter and C's exports never arrive.

**§5.2 — TestEviction_GoroutineCountStaysBounded**
- Setup: `collector.Start(ctx)`, `ReportersCacheLen: 50`, `Interval: 50 * time.Millisecond`.
- Action: in a loop, push spans for 500 distinct service UIDs paced so evictions happen continuously (e.g., one new service every 10 ms). Sample `runtime.NumGoroutine()` at: start, mid-loop (250 services in), end (after a 2× `Interval` settle).
- Assert: end-state goroutine count ≤ start + `ReportersCacheLen` + 30 (small overhead headroom for swarm goroutines, GC, etc.). Without the fix, end-state grows roughly linearly with the number of unique services seen.

**§5.3 — TestProviderShutdownTimeout_Configurable**
- Setup: a blocking exporter stub that hangs forever in `Export` (implement an in-test `sdkmetric.Exporter` that returns from `Export` only when a channel signals — for the test, never signal). `ProviderShutdownTimeout: 100 * time.Millisecond`.
- Action: instantiate a `MetricsReporter` with `ReportersCacheLen: 1`, push spans for service A then service B to force eviction of A.
- Assert: the eviction goroutine's `provider.Shutdown` returns within ~150 ms (i.e., the timeout fires; the stub does not block forever). Use a `time.AfterFunc` or `select { case <-done: case <-time.After(...) }` pattern.

**Bonus — TestExporterInstancer_ShutdownIdempotent** (spec §5.4)
- Setup: `MetricsExporterInstancer{Cfg: &MetricsConfig{CommonEndpoint: otlp.ServerEndpoint, MetricsProtocol: ProtocolHTTPProtobuf}}` with a real `collector.Start(ctx)`. Call `Instantiate(ctx)` once to populate `i.instance`.
- Action: call `instancer.Shutdown(ctx)` twice in sequence.
- Assert: first call returns nil, second call returns nil (no panic, no double-close error). This proves the `sync.Once` guard works.

This test is small (~25 lines). Add it to the same file.

- [ ] **Step 2: Run the three tests with `-race`**

Run:
```bash
go test -race -v -run 'TestEviction_|TestProviderShutdownTimeout' ./pkg/export/otel/dont-upload/...
```

Expected: all PASS, no race warnings. If any test fails, fix before moving on — these are the proof that the fix works.

- [ ] **Step 3: Sanity-check the bounded-goroutine test really stresses the LRU**

Open `metrics_eviction_test.go` and verify the second test:
- Uses `ReportersCacheLen` substantially smaller than the number of services pushed (50 vs 500 is fine).
- Sleeps between service-pushes so the LRU has time to evict (avoid pushing all 500 in one go before the periodic export tick fires).
- Calls `runtime.GC()` before measuring end-state goroutine count to settle anything in `time.AfterFunc` etc.

If any of these is missing, add it.

- [ ] **Step 4: Commit if you made changes**

```bash
git add pkg/export/otel/dont-upload/metrics_eviction_test.go
git commit -m "test(metrics): tighten eviction regression tests"
```

---

---

## CHECKPOINT 1 — Stop here if you are an agent

At this point Phase 1 (code audit + tests) is complete. The cluster verification in Phase 2 requires `kubectl` access to the user's on-prem cluster, push permission to its image registry, and a running affected pod — none of which an automated agent has.

**Agent action:** stop and report to the user. Include:
- The list of Tasks 1–9 boxes that you ticked.
- Any deviations you found and reconciled (or could not reconcile).
- The output of `go test -race ./pkg/export/otel/...`.
- A single sentence: "Phase 1 complete. Phase 2 (Tasks 10–14) is yours; ping me back for Phase 3 when verification passes."

The user will execute Phase 2 themselves and return for Phase 3.

---

## Part 3 — Verification on the leaking production cluster (Tasks 10–14)

> **USER ONLY.** Every task in this part requires access to the on-prem cluster. Agents must not attempt these tasks.

Spec §6. This is the part not yet done; do not skip.

### Task 10: Build the verification container image  *(USER ONLY)*

**Files:**
- existing `Dockerfile` / build scripts in the repo

- [ ] **Step 1: Capture the short SHA**

Run:
```bash
git rev-parse --short HEAD
```
Record the result as `<sha>`.

- [ ] **Step 2: Build the OBI binary**

Run:
```bash
make build 2>/dev/null || go build -o ./bin/ebpf-instrument ./cmd/ebpf-instrument
```
Expected: exits 0.

- [ ] **Step 3: Build the container image**

Run:
```bash
make image IMG=obi:fix-metrics-lifecycle-<sha> 2>/dev/null \
  || docker build -t obi:fix-metrics-lifecycle-<sha> .
```
Replace `<sha>` with the recorded short SHA.

- [ ] **Step 4: Push to the registry the cluster pulls from**

Run (substitute the real registry path):
```bash
docker tag obi:fix-metrics-lifecycle-<sha> <registry>/<repo>/obi:fix-metrics-lifecycle-<sha>
docker push <registry>/<repo>/obi:fix-metrics-lifecycle-<sha>
```

If the user's environment uses a different image build pipeline (Kaniko, BuildKit cache, GitHub Actions), use that path instead. The deliverable is: an image tag the affected cluster can pull.

---

### Task 11: Baseline capture on the leaking pod  *(USER ONLY)*

**Files:** none (operational task)

- [ ] **Step 1: Identify the leaking pod**

Run:
```bash
kubectl top pod -n <obi-namespace> --sort-by=memory | head -5
```

Pick the pod with the multi-GiB RSS. Record its name as `<pod>`.

- [ ] **Step 2: Confirm pprof is reachable**

If pprof is exposed on a known port (default OBI exposes profile under `/debug/pprof/` on the internal metrics port), confirm:

```bash
kubectl port-forward -n <obi-namespace> <pod> 6060:<pprof-port> &
sleep 2
curl -sf http://localhost:6060/debug/pprof/ | head -20
```

If pprof is not enabled in the running config, you cannot run this verification protocol — stop and ask the user to enable `profile_port` in OBI's config before continuing.

- [ ] **Step 3: Capture baseline profiles**

Run:
```bash
mkdir -p verification/baseline
curl -s http://localhost:6060/debug/pprof/goroutine -o verification/baseline/goroutine.pb.gz
curl -s http://localhost:6060/debug/pprof/heap     -o verification/baseline/heap.pb.gz
kubectl top pod -n <obi-namespace> <pod> > verification/baseline/rss.txt
date -u +"%Y-%m-%dT%H:%M:%SZ" > verification/baseline/timestamp.txt
```

- [ ] **Step 4: Record baseline numbers**

Run:
```bash
go tool pprof -text verification/baseline/goroutine.pb.gz 2>/dev/null \
  | grep -E "NewPeriodicReader|TOTAL goroutine count" | head -5
```

Expected: shows tens of thousands of goroutines, with `metric.NewPeriodicReader.func2` accounting for a large fraction. Save the numbers to `verification/baseline/notes.md`.

---

### Task 12: Deploy the fix to a single pod  *(USER ONLY)*

**Files:** none (operational task)

- [ ] **Step 1: Identify the DaemonSet/Deployment**

Run:
```bash
kubectl get pods -n <obi-namespace> <pod> -o jsonpath='{.metadata.ownerReferences[0].kind} {.metadata.ownerReferences[0].name}'
```

Record the controller kind+name.

- [ ] **Step 2: Plan the targeted rollout**

The plan: roll the new image to **one** pod first, not the whole DaemonSet. Two options:

(a) Patch the DaemonSet's image and use `updateStrategy: { type: RollingUpdate, rollingUpdate: { maxUnavailable: 1 } }`, then pause the rollout once the leaking node is rolled.
(b) Cordon the leaking node temporarily, create a one-off Pod from the same spec with the new image pinned to that node via `nodeName`.

Option (b) is safer — it does not modify the DaemonSet. Document the chosen option in `verification/deployment.md`.

- [ ] **Step 3: Deploy and confirm the new pod is running**

Run (option-dependent commands here). After deploying:
```bash
kubectl get pod -n <obi-namespace> <new-pod-name>
kubectl logs -n <obi-namespace> <new-pod-name> --tail=20
```

Expected: pod `Running`, recent logs show OBI startup completing with no panics or `level=ERROR` lines tied to the fix.

- [ ] **Step 4: Record the new pod's name for the observation window**

Save to `verification/deployment.md`:
- Old pod name (now removed or coexisting).
- New pod name running the fix image.
- Start time (UTC).

---

### Task 13: Observation window (≥ 4 hours)  *(USER ONLY)*

**Files:** none (operational task)

Spec §6.4: sample every 15 minutes.

- [ ] **Step 1: Start a periodic sampler**

In a tmux session, screen, or `nohup`-backed script:

```bash
#!/usr/bin/env bash
# verification/sample.sh
set -e
NAMESPACE=<obi-namespace>
POD=<new-pod-name>
PORT=<pprof-port>
OUT=verification/samples
mkdir -p "$OUT"
while true; do
  ts=$(date -u +"%Y%m%dT%H%M%SZ")
  kubectl port-forward -n "$NAMESPACE" "$POD" 6060:"$PORT" >/dev/null 2>&1 &
  pf=$!
  sleep 2
  curl -s http://localhost:6060/debug/pprof/goroutine -o "$OUT/gor-$ts.pb.gz" || true
  kubectl top pod -n "$NAMESPACE" "$POD" >> "$OUT/rss-timeseries.txt" || true
  kubectl logs -n "$NAMESPACE" "$POD" --since=15m \
    | grep -cE "exporter is shutdown|evicted metrics provider" \
    >> "$OUT/error-log-counts.txt" || true
  kill "$pf" >/dev/null 2>&1 || true
  sleep 900  # 15 minutes
done
```

Make executable and start it:
```bash
chmod +x verification/sample.sh
nohup verification/sample.sh > verification/sample.log 2>&1 &
echo $! > verification/sampler.pid
```

- [ ] **Step 2: Let it run for at least 4 hours, ideally 24**

The longer the better; the leak in the original code took hours to days to reach 124–180 GiB.

- [ ] **Step 3: Stop the sampler when done**

Run:
```bash
kill "$(cat verification/sampler.pid)"
ls verification/samples/ | wc -l   # confirm ≥ 16 samples for a 4-hour run
```

---

### Task 14: Evaluate success criteria  *(USER ONLY)*

**Files:** none (decision task)

Spec §6.5. All four must hold. Write the conclusion to `verification/conclusion.md`.

- [ ] **Step 1: Plot goroutine count**

Run:
```bash
for f in verification/samples/gor-*.pb.gz; do
  ts=$(basename "$f" .pb.gz | cut -d- -f2-)
  total=$(go tool pprof -text "$f" 2>/dev/null | awk '/Total:/ {print $2; exit}')
  echo "$ts $total"
done > verification/samples/goroutine-timeseries.txt
```

- [ ] **Step 2: Decide**

Open `verification/samples/goroutine-timeseries.txt` and `rss-timeseries.txt`. Check:

| Criterion | Pass condition |
|---|---|
| Goroutines flat or sublinear | The series shows no monotone climb tied to service churn |
| RSS ≤ 2× healthy-pod median | Compare against the 2–12 GiB band other pods use |
| Zero `HTTP exporter is shutdown` logs | `error-log-counts.txt` shows all zeros for that pattern |
| No new ERROR logs | `kubectl logs ... \| grep level=ERROR` returns nothing tied to the fix |

If all four pass → proceed to Task 15.
If any fails → execute Task 14b (rollback) and stop.

- [ ] **Step 2b: Rollback (only if a criterion fails)**

```bash
# Capture final profiles before rollback so we have evidence
curl -s http://localhost:6060/debug/pprof/goroutine -o verification/final-failed-goroutine.pb.gz
curl -s http://localhost:6060/debug/pprof/heap      -o verification/final-failed-heap.pb.gz
kubectl top pod -n <obi-namespace> <pod>            > verification/final-failed-rss.txt

# Roll back to the prior image (use the original DaemonSet image tag)
kubectl set image ds/<daemonset> -n <obi-namespace> obi=<original-image>
```

Then diff against the §11 baseline. If `NewPeriodicReader.func2` count is now flat (or only growing slowly) but RSS still climbs, the residual leak is on the prom side (spec §1 out-of-scope note) and needs a separate plan.

---

---

## CHECKPOINT 2 — Wait for user verification result

Before starting Part 4, the user must report back:
- **PASS** — all four success criteria from Task 14 held. Proceed to Part 4.
- **FAIL** — one or more criteria failed. Do NOT open an upstream PR. The rollback in Task 14 Step 2b applies and a new spec is needed (likely focused on the prom-side leak — spec §6.6).
- **INCONCLUSIVE** — verification could not be completed (cluster access lost, pod recycled, etc.). Re-run Phase 2; do not proceed to Part 4.

---

## Part 4 — Upstream PR preparation (Tasks 15–17)

Only proceed if Task 14 passed.

### Task 15: Port one regression test into the upstream-friendly test location

**Files:**
- Create: `pkg/export/otel/metrics_eviction_test.go` (or extend an existing `metrics_test.go`)
- Reference: `pkg/export/otel/dont-upload/metrics_eviction_test.go` (existing, stays local)

The upstream maintainers will not accept a `dont-upload/` directory. Port the most important of the three tests — `TestEviction_ExporterRemainsOperational` (spec §5.1) — into the standard test location.

- [ ] **Step 1: Find the existing test file structure**

Run:
```bash
ls pkg/export/otel/*_test.go
```

If there is an existing `pkg/export/otel/metrics_test.go`, prefer to add the function there. Otherwise create `pkg/export/otel/metrics_eviction_test.go`.

- [ ] **Step 2: Copy the test, adjust imports**

Copy `TestEviction_ExporterRemainsOperational` from `dont-upload/metrics_eviction_test.go` into the new location. Adjust:
- Package declaration from `dontupload_test` to `otel_test` (or whatever the destination file uses).
- Imports to use relative test helpers from `pkg/export/otel/` directly rather than `obiotel "go.opentelemetry.io/obi/pkg/export/otel"`.
- Function name kept as `TestEviction_ExporterRemainsOperational`.

- [ ] **Step 3: Run the ported test in isolation**

```bash
go test -race -v -run TestEviction_ExporterRemainsOperational ./pkg/export/otel/...
```
Expected: PASS.

- [ ] **Step 4: Commit the ported test**

```bash
git add pkg/export/otel/metrics_eviction_test.go
git commit -m "test(metrics): add eviction regression test (upstream-friendly)"
```

---

### Task 16: Prepare the upstream-PR branch

**Files:** various — branch surgery

The goal: a branch suitable for opening a PR against `open-telemetry/opentelemetry-ebpf-instrumentation:main` that contains the fix and the one ported test, but **not** the `dont-upload/` directory or the `docs/superpowers/` directory.

- [ ] **Step 1: Create a clean PR branch from main**

```bash
git fetch origin
git checkout -b pr/fix-metrics-lifecycle origin/main
```

- [ ] **Step 2: Cherry-pick only the production-code commits**

```bash
git log --oneline fix/metrics-exporter-lifecycle ^origin/main
```

Identify the commits that touch production code (typically just `2f9e0306 fix(metrics): ...` plus any audit commits from Tasks 1–8). Cherry-pick them in order:

```bash
git cherry-pick 2f9e0306
# plus any other production-code commits, in order
```

Resolve any merge conflicts that arise from upstream main moving forward; tests in conflicting files take precedence (don't drop them).

- [ ] **Step 3: Drop the `dont-upload/` directory if it came along**

If the cherry-pick brought in `pkg/export/otel/dont-upload/`, remove it:

```bash
git rm -r pkg/export/otel/dont-upload/
git commit -m "test(metrics): remove local-only test directory from upstream PR"
```

- [ ] **Step 4: Add the ported regression test**

```bash
git checkout fix/metrics-exporter-lifecycle -- pkg/export/otel/metrics_eviction_test.go
git commit -m "test(metrics): add eviction regression test"
```

- [ ] **Step 5: Confirm only the intended files differ from origin/main**

```bash
git diff --stat origin/main
```

Expected — only these files should appear (counts approximate):

```
devdocs/config/CONFIG.md                  |   2 +
devdocs/config/config-schema.json         |  12 +
pkg/export/otel/metrics.go                |  ~30
pkg/export/otel/metrics_eviction_test.go  | ~150  (new)
pkg/export/otel/metrics_svc_graph.go      |  ~25
pkg/export/otel/otelcfg/common.go         |  ~10
pkg/export/otel/otelcfg/config_metrics.go |  ~15
pkg/export/otel/otelcfg/exporter.go       |  ~35
pkg/instrumenter/instrumenter.go          |  ~10
```

If `docs/superpowers/`, `dont-upload/`, or `tests_metrics_fix/` appear: stop and remove them.

- [ ] **Step 6: Final build and test**

```bash
go build ./...
go test -race ./pkg/export/otel/...
```

Expected: both pass cleanly.

- [ ] **Step 7: Push the PR branch to the fork**

```bash
git push ronen pr/fix-metrics-lifecycle
```

---

### Task 17: Open the upstream PR

**Files:** none

- [ ] **Step 1: Compose the PR body**

Write `verification/pr-body.md` with this structure:

```markdown
## Summary

Fixes #2138.

Two bugs in the OTEL metrics reporter caused unbounded memory growth and data loss in clusters with high service churn:

1. **Goroutine leak.** LRU eviction called `provider.ForceFlush(ctx)` on evicted MeterProviders. `ForceFlush` does not stop the `PeriodicReader` background goroutine — only `Shutdown` does. The leaked goroutines accumulated indefinitely, each holding metric instruments and accumulated label sets (the reporter ran with ~91k goroutines and ~125 GiB RSS in the affected deployment).

2. **Shared-exporter shutdown race.** `MetricsReporter` and `SvcGraphMetricsReporter` share a single OTLP exporter. Each reporter's `close()` called `exporter.Shutdown()` in a detached goroutine with no ordering. Whichever ran first permanently shut down the shared connection; the other reporter's still-cached `PeriodicReader` goroutines then logged `failed to upload metrics: the HTTP exporter is shutdown` at INFO level, silently dropping data.

## Fix

- Replace `ForceFlush` with `provider.Shutdown(ctx)` in the eviction callback so the `PeriodicReader` goroutine is actually stopped.
- Wrap the shared exporter in `NoopShutdownExporter` so per-provider `Shutdown` cannot close the real connection.
- Shut the real exporter exactly once, from `pkg/instrumenter` after `g.Wait()` returns, via `sync.Once`.
- Add a `ReporterPool.Close()` that purges the LRU synchronously so reporter shutdown waits for all in-flight evictions.
- Track eviction goroutines with a `sync.WaitGroup` so reporter `close()` blocks until they drain.
- Add `provider_shutdown_timeout` config knob (defaults to `Interval`).

## Verification

Verified on the affected production deployment over <N> hours:
- Goroutine count: <baseline> → <after>, flat over observation window.
- RSS: <baseline GiB> → <after GiB>, within the healthy-pod band.
- Zero occurrences of `HTTP exporter is shutdown` in logs.

## Test plan

- Added `TestEviction_ExporterRemainsOperational` — verifies the shared OTLP exporter continues delivering records after one or more cache evictions.
- All existing tests pass with `-race`.
```

Fill in the `<...>` placeholders with the real numbers from `verification/conclusion.md` (Task 14).

- [ ] **Step 2: Open the PR via gh**

```bash
gh pr create \
  --repo open-telemetry/opentelemetry-ebpf-instrumentation \
  --base main \
  --head TheDwingMAN:pr/fix-metrics-lifecycle \
  --title "Fix OTEL metrics goroutine leak and shared-exporter shutdown race" \
  --body-file verification/pr-body.md
```

Record the returned PR URL.

- [ ] **Step 3: Done**

Report to the user:
- Link to the PR.
- Summary of the verification numbers.
- Note that `docs/superpowers/` and `pkg/export/otel/dont-upload/` stay on the fork branch (`fix/metrics-exporter-lifecycle`) for local reference; only the production code + one regression test is in the upstream PR.

---

## Acceptance criteria for this plan

The plan is complete when:

1. All Task 1–9 audit boxes are ticked and `go test -race ./pkg/...` passes.
2. Task 14 conclusion shows all four success criteria pass.
3. Task 17 step 2 returns a PR URL against `open-telemetry/opentelemetry-ebpf-instrumentation`.
