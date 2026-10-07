# Development loop for the OBI storage metrics

Scripts: `devloop/` of the lab kit (`~/obi-work/lab-kit/devloop/`; `OBI_REPO` and `OBI_WS` override the
repository and workspace paths, see `devloop/common.sh`). They never write to GitHub, push only to the fork
after `git remote -v` passes, author commits as TheDwingMAN, and never rewrite pushed history.

## The loop

```
          +----------------------+
          |  sync-upstream.sh    |  daily, and before opening or updating a PR
          |  (merge, never rebase)
          +----------+-----------+
                     v
  edit --> stage_hunks.py / git add -p --> commit.sh <msg> <pkgs>   (tests the staged content alone)
                     v
          +----------------------+
          |  pre-push.sh         |  before every push: what CI runs, on what changed
          |  [--privileged]      |
          |  [--generate]        |  when bpf/ C sources changed
          +----------+-----------+
                     v
          lab-matrix.sh <name>   when eBPF, probes, kernel-facing Go or the readers changed
                     v
          pre-push.sh --push     (remote gate, fast-forward only)
                     v
          ci-status.sh           read-only; re-runs only with the user's approval
```

## Scripts

| Script | What it does |
|---|---|
| `sync-upstream.sh [--merge [--push]]` | Fetches `upstream/main`, lists missing commits and conflict candidates, warns when upstream touched eBPF or generated files. `--merge` merges with a merge commit (clean tree required), aborts on conflicts and lists them, then runs `pre-push.sh --full`. |
| `commit.sh <message-file> [pkgs...]` | Refuses Claude trailers, policy files and `bpf/bpfcore`. Stashes the unstaged rest, builds, vets and tests the staged content, restores, commits as TheDwingMAN. |
| `pre-push.sh` | Mirrors CI: generated-file drift (`--generate`), clang-format of changed C, `check-ebpf-ver-synced`, build, vet, unit tests (changed packages; `--full` for all), privileged tests (`--privileged`), golangci-lint on linux and darwin, vanity imports, license headers, `go mod tidy -diff`, config schema and v2 artifact checks when config code changed, telemetry schema lint/tests/docs when `schemas/`, `site/` or attributes changed, markdown lint when available. Summary table; `--push` only after all pass. |
| `lab-matrix.sh <name> [--kernels ...] [--background]` | Builds `obi` and the privileged `stats.test` from HEAD into `lab/payloads/<name>/`, copies `run.sh` from `payloads/final` (or `--template`), runs `run-matrix.sh` on 6.12, RHEL 8.10, RHEL 9.6 and 7.2 by default, prints PASS/FAIL per kernel. |
| `ci-status.sh [sha]` | Counts the fork's check runs by conclusion, lists failures with their URLs. |

## Cadence

- **Every change:** one commit per logical change, staged with `git add -p`, tested by `commit.sh`, explained to the user.
- **Before every push:** `pre-push.sh` (add `--privileged` when probes or readers changed, `--generate` when C changed). Push with `--push`.
- **eBPF or kernel-facing changes:** `lab-matrix.sh` first; all four kernels must pass (RHEL 8.10 disables NFS by design and must say so in its WARN).
- **Daily, and before a PR:** `sync-upstream.sh`; merge when behind. If upstream touched `bpf/`, run `make docker-generate` after the merge and commit the generated files.
- **After a push:** `ci-status.sh`; the PR subscription wakes the session on CI events. Failures are diagnosed read-only (job logs via the GitHub MCP tool); a re-run needs the user's approval; no comments are posted.

## Environment notes

These were written in the cloud sandbox (root, no KVM, a 6.18 Firecracker kernel); on a workstation
the root-only test failures and the missing kprobes do not apply.


- Disk: the Go build cache reaches ~5 GiB on a full lint; `disk_guard` cleans it when under 6 GiB free. A full darwin lint of the whole repo filled the disk once; `pre-push.sh` lints changed packages unless `--full`.
- Root: three unit tests fail only because this host runs as root (`TestCheckOSCapabilities`, `TestLockdownParsing`, the file-permission case of `TestExtractNextJSRoutesFromManifest`); they pass in CI. They are not skipped, only explained.
- The sandbox kernel (6.18 Firecracker) has no kprobes and no tracefs: kprobe-based privileged tests skip there; the lab VMs cover them.
- Workstation (not root): `pre-push.sh --privileged` skips the privileged tests with a note; they run in the lab VMs (`lab/build-payload.sh final` then `run-vm.sh`, or `lab-matrix.sh`). Run as root, `--privileged` creates loop, zram and LVM devices on the host itself.
- podman-docker: `common.sh` exports `OCI_BIN=podman` when `docker --version` reports podman, so `make docker-generate` (`--generate`) does not pass `-u uid:gid`, which rootless podman maps to a subuid that cannot write the repository. Set `OCI_BIN` yourself to override.
- `go tool golangci-lint` can't lint for darwin (it would rebuild itself for macOS); `common.sh` builds a Linux binary into `devloop/bin/` once and runs it with `GOOS=darwin`.

## Scope of the upstream sync

The upstream sync is only needed while this feature is being developed and reviewed: it keeps the
branch mergeable and the PRs rebased-by-merge on current upstream. It is run by hand (or by the
assistant) at the cadence above; no scheduled routine is set up. Once the feature is merged
upstream, the loop ends with it.
