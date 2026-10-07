# KVM lab results for PR #4 (OBI storage metrics)

OBI `feat/statso11y-disk-metrics-v2` at `0b5d13939b645166812424562b55918e82c6f2b1`. Lab kit `c865634`. Every VM ran with `accel=kvm`, `LAB_SMP=2 LAB_MEM=4096`, one at a time.

Notes on how the blocks were run:

- `run-matrix.sh` was called once per kernel (same payload, timeout and kernel order) so the host's free memory and load could be checked before every VM; the per-kernel TSVs are merged into one TSV per block here.
- Payloads were built with `build-payload.sh final`, `k3s-final`, `iostats`, `nvme-mpath-nobio`, `nvme-mpath-bio`; every `COMMIT` file says `0b5d13939`. In `k3s-final` the manifests' image tag is still named `obi:disk-v2-23410d280`; build-payload rebuilt that tag from `0b5d13939`.
- Logs are scrubbed: host name, user, home paths (`~`), non-guest IP and MAC addresses, and the guest kernel's lines about the CPU and firmware (the guests run with `-cpu host`) are replaced.

## Kernel matrix

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

### Failures

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

### SKIP lines

- rhel9.6: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v5.8.18: `SKIP e2e-write-zeroes the loop device has no write-zeroes on this kernel`
- v5.8.18: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v6.12.111: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v6.18.54: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`
- v7.2.6: `SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel`

The payload output of every kernel is in `out/matrix/<kernel>.out`.

## k3s

`./run-matrix.sh payloads/k3s-final 3000 v6.12.111 rhel9.6`, payload built from `0b5d13939`.

Not run yet.

## iostats (stale request starts, the RQF_IO_STAT gate)

`LAB_EXTRA_DISKS="1G" ./run-matrix.sh payloads/iostats 1800 v6.18.54 v7.2.6 v6.12.111 rhel9.6`, payload built from `0b5d13939`.

`payloads/iostats/MODE`: `fixed`.

Not run yet.

## NVMe native multipath stall repeat (F-NVMe-2)

20 rounds; per round, in order: nvme-mpath-nobio and nvme-mpath-bio on v6.12.111, then on rhel9.6, each as `LAB_NVME_MPATH=256M ./run-vm.sh <kernel> payloads/<variant> 600`. Payloads built from `0b5d13939`.

Not run yet.

