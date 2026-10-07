# KVM lab results for PR #4 (OBI storage metrics)

## State (updated 2026-10-07 23:38 +03:00)

This branch is written by the KVM lab on the user's workstation. Two shas are involved:

- `0b5d13939` (the code before `ec314571`): the kernel matrix, k3s and iostats blocks, and a supplement (the final payload with its NFS module unload line fixed, on the 8 kernels that failed `nfs-late-setup`), were run by an earlier lab session and are summarised in the second half of this file; their files are at the root of the branch (`matrix-final.tsv`, `matrix-final-nfsfix.tsv`, `k3s-final.tsv`, `iostats.tsv`, `out/`, `failures/`). All four are complete: none was cut off. No NVMe multipath run was made at this sha.
- `a285b5b3485227f0ea636a9c791c1a2a3521a3e0` (the passthrough fix: `7c6ab26c8` "statsolly: keep passthrough commands out of the block request timing" plus `a285b5b34` "statsolly: make the passthrough commands test robust", on top of `ec314571`): seen on `feat/statso11y-disk-metrics-v2` at 23:20 +03:00. The payloads `final`, `iostats`, `nvme-mpath-nobio` and `nvme-mpath-bio` were rebuilt from it and are run in this order: matrix on v6.12.111 v6.18.54 v7.2.6 rhel9.6 rhel8.10 (step a); matrix on the other six kernels (step b); iostats (step c); 20 rounds of the NVMe multipath repeat (step d), published every 5 rounds. Their results are under `a285b5b34/` and in the first half of this file. **Progress: steps a and b done (matrix, 11 kernels); step c (iostats) running; NVMe not started.**

Nothing was run at `ec314571` itself.

Things to know about the earlier blocks:

- The workstation was suspended from about 20:40 to 22:20 (+03:00), in the middle of the iostats block: the v6.12.111 iostats run that was in the guest at that time (exit 1, 3 FAIL, payload time 5983 s) is set aside as `failures/iostats-v6.12.111-host-suspended/` and was repeated afterwards (exit 0). The lab compares CLOCK_BOOTTIME with CLOCK_MONOTONIC around every VM and repeats any run the host slept through, so a suspend is not reported as a stall or a failure.
- Single runs of 2026-10-07 outside the blocks: two `payloads/rhel-smoke` boots from `setup.sh` (v6.12.111 and rhel8.10, both exit 0) and one NFS module diagnostic on v6.6.157 (`out/extra/`).
- The matrix's only FAIL at `0b5d13939` is `RESULT nfs-late-setup FAIL (rc=1)` on 8 of 11 kernels: `modprobe -r nfs` in `payloads/final/run.sh` leaves `sunrpc` loaded, so the precondition of the late-attach step fails (the payload, not OBI; the supplement passes with 0 FAIL on all 8). The lab kit is unchanged, so the same 8 FAIL lines are expected at the new sha.
- NFS checks (`nfs-*`, `e2e-nfs-*`) are reported but do not block anything: NFS is deferred.

## Runs at `a285b5b3485227f0ea636a9c791c1a2a3521a3e0`

OBI `feat/statso11y-disk-metrics-v2` at `a285b5b3485227f0ea636a9c791c1a2a3521a3e0` (HEAD: "statsolly: make the passthrough commands test robust"; the commit below it: "statsolly: keep passthrough commands out of the block request timing" (7c6ab26c8)). Lab kit `c865634`. `LAB_SMP=2 LAB_MEM=4096`, one VM at a time. 11 VM runs so far: all with `accel=kvm`. Files of this sha are under `a285b5b34/`.

### Kernel matrix (final payload)

`./run-matrix.sh payloads/final 1200 v6.12.111 v6.18.54 v7.2.6 rhel9.6 rhel8.10` (step a) and then `./run-matrix.sh payloads/final 1200 v5.8.18 v5.10.270 v5.15.221 v6.1.188 v6.6.157 rhel8.9`, payload built from `a285b5b34`.

| kernel | exit | verdict | PASS | FAIL | FAIL not NFS | SKIP | accel | boot | payload | total |
|---|---|---|---|---|---|---|---|---|---|---|
| v6.12.111 | 1 | FAIL | 37 | 1 | 0 | 1 | kvm | 0.9s | 128.9s | 129.9s |
| v6.18.54 | 1 | FAIL | 37 | 1 | 0 | 1 | kvm | 0.9s | 141.8s | 142.8s |
| v7.2.6 | 1 | FAIL | 37 | 1 | 0 | 1 | kvm | 0.9s | 127.9s | 128.8s |
| rhel9.6 | 1 | FAIL | 36 | 1 | 0 | 1 | kvm | 1.0s | 124.5s | 125.5s |
| rhel8.10 | 0 | PASS | 35 | 0 | 0 | 0 | kvm | 1.4s | 73.2s | 74.7s |
| v5.8.18 | 0 | PASS | 32 | 0 | 0 | 2 | kvm | 0.6s | 84.2s | 84.8s |
| v5.10.270 | 1 | FAIL | 37 | 1 | 0 | 0 | kvm | 1.0s | 54.8s | 55.8s |
| v5.15.221 | 1 | FAIL | 38 | 1 | 0 | 0 | kvm | 1.0s | 57.8s | 58.8s |
| v6.1.188 | 1 | FAIL | 38 | 1 | 0 | 0 | kvm | 0.9s | 56.8s | 57.8s |
| v6.6.157 | 1 | FAIL | 38 | 1 | 0 | 0 | kvm | 1.0s | 57.5s | 58.6s |
| rhel8.9 | 0 | PASS | 35 | 0 | 0 | 0 | kvm | 1.6s | 73.7s | 75.4s |

`verdict` is the VM's exit code (PASS = 0, TIMEOUT = 124, INFRA = 125: the guest never reported an exit code). NFS checks are reported but were deferred by the user: they do not block anything.

#### TestDiskPassthroughCommands

| kernel | result | line and skip reason (from the run's `privileged.log`) |
|---|---|---|
| v6.12.111 | PASS | `--- PASS: TestDiskPassthroughCommands (3.00s)` |
| v6.18.54 | PASS | `--- PASS: TestDiskPassthroughCommands (2.94s)` |
| v7.2.6 | PASS | `--- PASS: TestDiskPassthroughCommands (3.12s)` |
| rhel9.6 | PASS | `--- PASS: TestDiskPassthroughCommands (2.96s)` |
| rhel8.10 | PASS | `--- PASS: TestDiskPassthroughCommands (2.95s)` |
| v5.8.18 | PASS | `--- PASS: TestDiskPassthroughCommands (3.54s)` |
| v5.10.270 | PASS | `--- PASS: TestDiskPassthroughCommands (3.60s)` |
| v5.15.221 | PASS | `--- PASS: TestDiskPassthroughCommands (3.53s)` |
| v6.1.188 | PASS | `--- PASS: TestDiskPassthroughCommands (3.54s)` |
| v6.6.157 | PASS | `--- PASS: TestDiskPassthroughCommands (3.72s)` |
| rhel8.9 | PASS | `--- PASS: TestDiskPassthroughCommands (3.00s)` |

The whole `privileged.log` of every kernel is in `a285b5b34/out/matrix/<kernel>.privileged.log`.

#### Failures

- **v6.12.111**: exit 1 (FAIL), 1 FAIL; logs in `a285b5b34/failures/matrix-v6.12.111/`
  - `RESULT nfs-late-setup FAIL (rc=1)` (NFS, deferred)
- **v6.18.54**: exit 1 (FAIL), 1 FAIL; logs in `a285b5b34/failures/matrix-v6.18.54/`
  - `RESULT nfs-late-setup FAIL (rc=1)` (NFS, deferred)
- **v7.2.6**: exit 1 (FAIL), 1 FAIL; logs in `a285b5b34/failures/matrix-v7.2.6/`
  - `RESULT nfs-late-setup FAIL (rc=1)` (NFS, deferred)
- **rhel9.6**: exit 1 (FAIL), 1 FAIL; logs in `a285b5b34/failures/matrix-rhel9.6/`
  - `RESULT nfs-late-setup FAIL (rc=1)` (NFS, deferred)
- **v5.10.270**: exit 1 (FAIL), 1 FAIL; logs in `a285b5b34/failures/matrix-v5.10.270/`
  - `RESULT nfs-late-setup FAIL (rc=1)` (NFS, deferred)
- **v5.15.221**: exit 1 (FAIL), 1 FAIL; logs in `a285b5b34/failures/matrix-v5.15.221/`
  - `RESULT nfs-late-setup FAIL (rc=1)` (NFS, deferred)
- **v6.1.188**: exit 1 (FAIL), 1 FAIL; logs in `a285b5b34/failures/matrix-v6.1.188/`
  - `RESULT nfs-late-setup FAIL (rc=1)` (NFS, deferred)
- **v6.6.157**: exit 1 (FAIL), 1 FAIL; logs in `a285b5b34/failures/matrix-v6.6.157/`
  - `RESULT nfs-late-setup FAIL (rc=1)` (NFS, deferred)

#### SKIP lines

- v6.12.111: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v6.18.54: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v7.2.6: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- rhel9.6: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v5.8.18: `SKIP e2e-write-zeroes the loop device has no write-zeroes on this kernel`
- v5.8.18: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`

The payload output of every kernel is in `a285b5b34/out/matrix/<kernel>.out`.

### iostats (stale request starts, the RQF_IO_STAT gate)

`LAB_EXTRA_DISKS="1G" ./run-matrix.sh payloads/iostats 1800 v6.18.54 v7.2.6 v6.12.111 rhel9.6`, payload built from `a285b5b34`.

MODE: `payloads/iostats/MODE` after the build: `fixed`; printed by the payload in the runs: `-`.

No valid run yet.

### NVMe native multipath stall repeat (F-NVMe-2)

20 rounds; per round, in order: nvme-mpath-nobio and nvme-mpath-bio on v6.12.111, then on rhel9.6, each as `LAB_NVME_MPATH=256M ./run-vm.sh <kernel> payloads/<variant> 600`. Payloads built from `a285b5b34` (nobio) and `a285b5b34` (bio).

Not run yet.

## Earlier runs at `0b5d13939` (by the earlier lab session; files at the root of this branch)

OBI `feat/statso11y-disk-metrics-v2` at `0b5d13939b645166812424562b55918e82c6f2b1`. Lab kit `c865634`. Every VM ran with `accel=kvm`, `LAB_SMP=2 LAB_MEM=4096`, one at a time.

Notes on how the blocks were run:

- `run-matrix.sh` was called once per kernel (same payload, timeout and kernel order) so the host's free memory and load could be checked before every VM; the per-kernel TSVs are merged into one TSV per block here.
- Payloads were built with `build-payload.sh final`, `k3s-final`, `iostats`, `nvme-mpath-nobio`, `nvme-mpath-bio`; every `COMMIT` file says `0b5d13939`. In `k3s-final` the manifests' image tag is still named `obi:disk-v2-23410d280`; build-payload rebuilt that tag from `0b5d13939`.
- Logs are scrubbed: host name, user, home paths (`~`), non-guest IP and MAC addresses, and the guest kernel's lines about the CPU and firmware (the guests run with `-cpu host`) are replaced.

About the matrix's only failure, `nfs-late-setup` (8 kernels: every kernel where OBI can load the NFS probes):

- It is the precondition of the payload's "nfs late attach" step, not an OBI check: `modprobe -r nfs` in the guest removes `nfs` and `lockd` only and leaves `sunrpc` (and `grace`) loaded with refcnt 0 and no holders, so `[ ! -e /sys/module/sunrpc/initstate ]` fails. A diagnostic run on v6.6.157 shows it (`out/extra/diag-nfs-late-setup-v6.6.157.out`, script next to it): after `modprobe -r nfs` three retries over 21 s change nothing, and `modprobe -r sunrpc` then unloads it at once. Nothing pins the module.
- The consequence: on those 8 kernels the checks behind it (`nfs-waiting-warn`, `nfs-late-attach`, `e2e-nfs-late-io`, `nfs-modules-pinned`) did not run in the matrix. The privileged test `TestNFSProbesAttachWhenTheirModulesAreLoaded` passed on all 8.
- rhel8.9, rhel8.10 and v5.8.18 pass `nfs-late-setup` because the privileged test skips there without loading the modules; they take the `nfs-stays-off` branch.
- Supplement (below): a copy of `payloads/final` with only that line changed (`out/extra/final-nfsfix-run.sh.diff`: `modprobe -r sunrpc` after `modprobe -r nfs`), same binaries, on the 8 kernels. All 8 exit 0 with no FAIL, and `nfs-late-setup`, `nfs-waiting-warn`, `nfs-late-attach`, `e2e-nfs-late-io` and `nfs-modules-pinned` pass on each. The lab kit itself was not changed.

Status of this results set: the kernel matrix, k3s and iostats blocks at `0b5d13939` are complete. The NVMe multipath repeat was **not run** at `0b5d13939`: the branch moved on to a newer commit while these blocks ran, and the NVMe rounds were left to the lab session that runs the newer commit.

Host suspend: the host was suspended from 20:40:56 to 22:20:06 local time. One run was in progress (iostats on v6.12.111); it is set aside and was repeated. No other run of this set overlapped the suspend.

### Kernel matrix

`./run-matrix.sh payloads/final 1200`, payload built from `0b5d13939`.

| kernel | exit | verdict | PASS | FAIL | SKIP | accel | boot | payload | total |
|---|---|---|---|---|---|---|---|---|---|
| rhel8.9 | 0 | PASS | 35 | 0 | 0 | kvm | 1.8s | 68.7s | 70.6s |
| rhel8.10 | 0 | PASS | 35 | 0 | 0 | kvm | 0.8s | 68.6s | 69.5s |
| rhel9.6 | 1 | FAIL | 36 | 1 | 1 | kvm | 0.6s | 119.3s | 119.9s |
| v5.8.18 | 0 | PASS | 32 | 0 | 2 | kvm | 0.5s | 76.7s | 77.2s |
| v5.10.270 | 1 | FAIL | 37 | 1 | 0 | kvm | 0.6s | 47.7s | 48.3s |
| v5.15.221 | 1 | FAIL | 38 | 1 | 0 | kvm | 0.5s | 49.9s | 50.5s |
| v6.1.188 | 1 | FAIL | 38 | 1 | 0 | kvm | 0.5s | 49.5s | 50.0s |
| v6.6.157 | 1 | FAIL | 38 | 1 | 0 | kvm | 0.5s | 49.6s | 50.2s |
| v6.12.111 | 1 | FAIL | 37 | 1 | 1 | kvm | 0.5s | 107.9s | 108.5s |
| v6.18.54 | 1 | FAIL | 37 | 1 | 1 | kvm | 0.6s | 129.6s | 130.2s |
| v7.2.6 | 1 | FAIL | 37 | 1 | 1 | kvm | 8.3s | 119.7s | 128.0s |

#### Failures

- **rhel9.6**: exit 1 (FAIL), 1 FAIL; logs in `failures/matrix-rhel9.6/`
  - `RESULT nfs-late-setup FAIL (rc=1)`
- **v5.10.270**: exit 1 (FAIL), 1 FAIL; logs in `failures/matrix-v5.10.270/`
  - `RESULT nfs-late-setup FAIL (rc=1)`
- **v5.15.221**: exit 1 (FAIL), 1 FAIL; logs in `failures/matrix-v5.15.221/`
  - `RESULT nfs-late-setup FAIL (rc=1)`
- **v6.1.188**: exit 1 (FAIL), 1 FAIL; logs in `failures/matrix-v6.1.188/`
  - `RESULT nfs-late-setup FAIL (rc=1)`
- **v6.6.157**: exit 1 (FAIL), 1 FAIL; logs in `failures/matrix-v6.6.157/`
  - `RESULT nfs-late-setup FAIL (rc=1)`
- **v6.12.111**: exit 1 (FAIL), 1 FAIL; logs in `failures/matrix-v6.12.111/`
  - `RESULT nfs-late-setup FAIL (rc=1)`
- **v6.18.54**: exit 1 (FAIL), 1 FAIL; logs in `failures/matrix-v6.18.54/`
  - `RESULT nfs-late-setup FAIL (rc=1)`
- **v7.2.6**: exit 1 (FAIL), 1 FAIL; logs in `failures/matrix-v7.2.6/`
  - `RESULT nfs-late-setup FAIL (rc=1)`

#### SKIP lines

- rhel9.6: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v5.8.18: `SKIP e2e-write-zeroes the loop device has no write-zeroes on this kernel`
- v5.8.18: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v6.12.111: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v6.18.54: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v7.2.6: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`

The payload output of every kernel is in `out/matrix/<kernel>.out`.

### Supplement: the final payload with the sunrpc unload fixed (a patched copy, not the lab kit's)

`./run-matrix.sh <copy of payloads/final with out/extra/final-nfsfix-run.sh.diff> 1200 <the 8 kernels that failed nfs-late-setup>`, payload built from `0b5d13939`.

| kernel | exit | verdict | PASS | FAIL | SKIP | accel | boot | payload | total |
|---|---|---|---|---|---|---|---|---|---|
| rhel9.6 | 0 | PASS | 41 | 0 | 1 | kvm | 1.0s | 230.3s | 231.4s |
| v5.10.270 | 0 | PASS | 42 | 0 | 0 | kvm | 1.1s | 88.5s | 89.7s |
| v5.15.221 | 0 | PASS | 43 | 0 | 0 | kvm | 0.8s | 91.1s | 92.0s |
| v6.1.188 | 0 | PASS | 43 | 0 | 0 | kvm | 0.9s | 90.1s | 91.0s |
| v6.6.157 | 0 | PASS | 43 | 0 | 0 | kvm | 1.0s | 89.8s | 90.8s |
| v6.12.111 | 0 | PASS | 42 | 0 | 1 | kvm | 0.9s | 219.4s | 220.4s |
| v6.18.54 | 0 | PASS | 42 | 0 | 1 | kvm | 0.9s | 248.1s | 249.1s |
| v7.2.6 | 0 | PASS | 42 | 0 | 1 | kvm | 0.9s | 234.8s | 235.8s |

#### Failures

None: every kernel exited 0 with no `RESULT ... FAIL` line.

#### SKIP lines

- rhel9.6: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v6.12.111: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v6.18.54: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v7.2.6: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`

The payload output of every kernel is in `out/nfsfix/<kernel>.out`.

### k3s

`./run-matrix.sh payloads/k3s-final 3000 v6.12.111 rhel9.6`, payload built from `0b5d13939`.

| kernel | exit | verdict | PASS | FAIL | SKIP | accel | boot | payload | total |
|---|---|---|---|---|---|---|---|---|---|
| v6.12.111 | 0 | PASS | 42 | 0 | 0 | kvm | 0.6s | 1193.7s | 1194.4s |
| rhel9.6 | 0 | PASS | 42 | 0 | 0 | kvm | 3.6s | 1189.8s | 1193.6s |

#### Failures

None: every kernel exited 0 with no `RESULT ... FAIL` line.

The payload output of every kernel is in `out/k3s/<kernel>.out`.

### iostats (stale request starts, the RQF_IO_STAT gate)

`LAB_EXTRA_DISKS="1G" ./run-matrix.sh payloads/iostats 1800 v6.18.54 v7.2.6 v6.12.111 rhel9.6`, payload built from `0b5d13939`.

`payloads/iostats/MODE`: `fixed`.

| kernel | exit | verdict | PASS | FAIL | SKIP | accel | boot | payload | total |
|---|---|---|---|---|---|---|---|---|---|
| v6.18.54 | 0 | PASS | 33 | 0 | 3 | kvm | 0.5s | 195.3s | 195.9s |
| v7.2.6 | 0 | PASS | 33 | 0 | 3 | kvm | 0.6s | 197.0s | 197.5s |
| rhel9.6 | 0 | PASS | 33 | 0 | 3 | kvm | 1.0s | 196.3s | 197.4s |
| v6.12.111 | 0 | PASS | 33 | 0 | 3 | kvm | 1.0s | 201.4s | 202.4s |

#### Failures

None: every kernel exited 0 with no `RESULT ... FAIL` line.

#### Verdicts

| kernel | verdict lines | observed CLEAN | other |
|---|---|---|---|
| v6.18.54 | 11 | 11 | 0 |
| v7.2.6 | 11 | 11 | 0 |
| rhel9.6 | 11 | 11 | 0 |
| v6.12.111 | 11 | 11 | 0 |

Every verdict line observed CLEAN.

#### Runs set aside

The host was suspended during these runs (the guest clock jumped), so they are not counted above and were repeated:

- iostats-v6.12.111: exit 1; logs in `failures/iostats-v6.12.111-host-suspended/`

#### SKIP lines

- v6.18.54: `SKIP stale-flush-iostats-none write cache is 'write through', not 'write back': no flushes`
- v6.18.54: `SKIP stale-flush-iostats-mq-deadline write cache is 'write through', not 'write back': no flushes`
- v6.18.54: `SKIP stale-flush-nullb1-shared write cache is 'write through', not 'write back': no flushes`
- v7.2.6: `SKIP stale-flush-iostats-none write cache is 'write through', not 'write back': no flushes`
- v7.2.6: `SKIP stale-flush-iostats-mq-deadline write cache is 'write through', not 'write back': no flushes`
- v7.2.6: `SKIP stale-flush-nullb1-shared write cache is 'write through', not 'write back': no flushes`
- rhel9.6: `SKIP stale-flush-iostats-none write cache is 'write through', not 'write back': no flushes`
- rhel9.6: `SKIP stale-flush-iostats-mq-deadline write cache is 'write through', not 'write back': no flushes`
- rhel9.6: `SKIP stale-flush-nullb1-shared write cache is 'write through', not 'write back': no flushes`
- v6.12.111: `SKIP stale-flush-iostats-none write cache is 'write through', not 'write back': no flushes`
- v6.12.111: `SKIP stale-flush-iostats-mq-deadline write cache is 'write through', not 'write back': no flushes`
- v6.12.111: `SKIP stale-flush-nullb1-shared write cache is 'write through', not 'write back': no flushes`

The payload output of every kernel is in `out/iostats/<kernel>.out`.

### NVMe native multipath stall repeat (F-NVMe-2)

20 rounds; per round, in order: nvme-mpath-nobio and nvme-mpath-bio on v6.12.111, then on rhel9.6, each as `LAB_NVME_MPATH=256M ./run-vm.sh <kernel> payloads/<variant> 600`. Payloads built from `0b5d13939`.

Not run at this sha: the repeat is run at the new sha only.
