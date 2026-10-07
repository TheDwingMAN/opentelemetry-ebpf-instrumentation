# OBI kernel VM lab (QEMU, KVM or TCG)

Boots Ubuntu mainline and RHEL-family kernels under QEMU (**KVM** when `/dev/kvm`
is readable and writable, else **TCG**), runs a payload script inside the guest,
and returns the payload's output and exit code on the host. Nothing here touches
the OBI repo; `build-payload.sh` only reads it.

## Quick start

```sh
cd ~/obi-work/lab-kit/lab

# one kernel
./run-vm.sh v6.18.54 payloads/rhel-smoke       # default timeout 900 s
./run-vm.sh v5.10.270 /path/to/my-payload 1200

# every kernel in cache/kernels, sequentially, with a TSV summary
./build-payload.sh verifier
./run-matrix.sh payloads/verifier 2400
./run-matrix.sh payloads/rhel-smoke 900 v5.15.221 v6.6.157
```

`run-vm.sh <kernel-version> <payload-dir> [timeout-seconds]`

- **stdout**: payload output, streamed live.
- **stderr**: one summary line:
  `[run-vm] exit=0 kernel=v6.18.54 (...) accel=kvm boot=17.4s payload=4.3s total=22.0s log=... results=...`
- **exit code**: the payload's exit code; `124` on timeout; `125` when the guest
  never reported `LAB_EXIT` (boot failure / panic; the last 40 console lines are
  printed to stderr).
- The full serial console is saved to `logs/<ver>-<timestamp>.log`.
- `runs/<ver>-<timestamp>/results/` holds `output.log`, `dmesg.log`,
  `exit_code` and anything the payload wrote to `$LAB_RESULTS`.

Knobs (env): `LAB_VERBOSE=1` (mirror the whole console to stderr, so payload
lines show twice on a terminal), `LAB_SMP` (2), `LAB_MEM` (4096),
`LAB_ACCEL` (`kvm` when `/dev/kvm` is usable, else `tcg,thread=multi`),
`LAB_CPU` (`host` under KVM, `max` under TCG), `LAB_TIMEOUT_SCALE` (1:
multiplies the timeout; the payload timeouts were sized for TCG, so under KVM
they are generous upper bounds), `LAB_TRANSPORT` (`9p` or `disk`; default 9p
when the kernel has 9p), `LAB_APPEND` (extra kernel cmdline, e.g. `loglevel=7` or
`lab.modules=9pnet_virtio,9p,loop`), `LAB_KEEP=1` (keep the qcow2 overlay and
the extra disks), `LAB_EXTRA_DISKS` (e.g. `"1G 1G"`: one empty raw virtio disk
per size, created sparse as `runs/<ver>-<ts>/extra-<n>.raw` and deleted after
the run like the overlay), `LAB_NVME_MPATH` (e.g. `256M`: one shared NVMe
namespace behind two controllers of one subsystem, for `payloads/nvme-mpath*`).

The extra disks sit in PCI slots `0x10` and up, after the root disk and, on
kernels without 9p, after the payload and results disks, so their names (`vdb`
with 9p, `vdd` without) depend on the kernel. Find them in the guest by their
virtio serial, `lab-extra-<n>` (`payloads/extra-disks-smoke` lists them):

```sh
for d in /sys/block/vd*; do [ "$(cat $d/serial 2>/dev/null)" = lab-extra-1 ] && echo ${d##*/}; done
```

Only one VM runs at a time: `run-vm.sh` takes `flock cache/vm.lock`, so parallel
invocations queue instead of competing for the host.

## Writing a payload

A payload is a directory with a `run.sh` (run with `bash`), plus whatever
binaries it needs (`build-payload.sh <name>` builds the ones the kit knows). In
the guest:

- the directory is shared read-only over 9p (`/payload`) and copied to
  `/work` (tmpfs); `run.sh` starts with `cwd=/work`, so it may write next to
  its binaries. Hard links into the payload dir are fine; symlinks pointing
  outside it are not (9p exposes the link, not the target). Kernels without 9p
  (RHEL) get the payload as a tar on a virtio disk instead.
- `$LAB_RESULTS` (`/results`) is a writable 9p share (a tar on a disk without
  9p) that appears on the host under `runs/<ver>-<ts>/results/`.
- you are root, PID 1's child, with no systemd, no network, and no docker.
- the userland is Ubuntu 24.04 (glibc 2.39), older than Fedora's: build Go
  binaries static (`CGO_ENABLED=0`, as `build-payload.sh` does).
- kernel messages are silenced on the console while the payload runs
  (`dmesg -n 1`); the full `dmesg` is saved to `results/dmesg.log`.

Available in the guest: bash, coreutils, util-linux (losetup, mount, findmnt,
…), e2fsprogs, kmod, fio, iproute2, procps, dmsetup, strace, curl, xz, zstd,
lvm2, mdadm, NFS server and client.

Guest environment set up by `/lab-init.sh`:

- proc, sysfs, devtmpfs, devpts, tmpfs on `/tmp` `/run` `/dev/shm`, debugfs,
  tracefs at `/sys/kernel/tracing`, bpffs at `/sys/fs/bpf`, configfs at
  `/sys/kernel/config`.
- **pure cgroup v2** at `/sys/fs/cgroup` (`cgroup_no_v1=all` on the cmdline,
  `nsdelegate`), with every available controller (including `io`) enabled in
  the root `cgroup.subtree_control`.
- modules loaded (non-fatal, result printed on the console as
  `[lab-init] ... modprobe ok: ...`): `9pnet_virtio 9p null_blk dm_mod dm_delay
  dm_flakey loop overlay`. `null_blk` loads with defaults, so `/dev/nullb0`
  exists; reload it with parameters if a test needs something else.

### Re-running the OBI verifier after code changes

```sh
./build-payload.sh verifier      # make generate + CGO_ENABLED=0 go test -c -tags bpf_verifier_tests
./run-matrix.sh payloads/verifier 2400
```

## How it works

| Piece | What it does |
|---|---|
| `fetch-kernel.sh <ver>` | Downloads `linux-image-unsigned-*-generic` + `linux-modules-*-generic` (amd64) from kernel.ubuntu.com/mainline and `dpkg-deb -x`es them into `cache/kernels/<ver>/`. `run-vm.sh` calls it for unknown versions, but a new kernel also needs `build-rootfs.sh --add <ver>` to get its modules into the image. |
| `fetch-rhel-kernel.sh <id>` | `rhel8.9`, `rhel8.10`, `rhel9.6`: downloads Oracle Linux RHCK `kernel-core` + `kernel-modules` (+ `kernel-modules-core` on 9.x) from yum.oracle.com and unpacks them with `rpm-extract.py` (see `KERNELS.md`). |
| `kernel-info.sh <ver>` | Prints `KREL`, `VMLINUZ`, `MODDIR`, `CONFIG` for an extracted kernel. |
| `rootfs/Dockerfile` | Ubuntu 24.04 userland (see package list above). |
| `build-rootfs.sh` | Run as root. `docker build` → `docker export` → 8 GB sparse ext4 `cache/base.raw` (loop-mounted on the host), copies every kernel's modules to `/lib/modules/<release>`, runs the guest's `depmod`, installs `/lab-init.sh`. `--init` refreshes only lab-init; `--add <ver>` adds one kernel's modules. |
| `build-initramfs.sh <ver>` | Only for kernels with `CONFIG_VIRTIO_BLK=m` or `CONFIG_EXT4_FS=m` (5.8–6.1 and RHEL here): a ~0.7 MB cpio with static busybox (`busybox:1.37-uclibc`, extracted by `setup.sh`; the default `busybox:1.37` tag is dynamically linked) + the modules that mounts `/dev/vda` and `switch_root`s into `init=`. Cached in `cache/initramfs/`. |
| `rootfs/lab-init.sh` | Guest PID 1 (`init=/lab-init.sh`): mounts, modprobes, mounts the 9p shares (or unpacks the payload disk), runs the payload, prints `LAB_EXIT=<rc>`, powers off via sysrq. |
| `run-vm.sh` | Creates a throwaway `qcow2` overlay backed by `base.raw`, boots with `-accel kvm -cpu host` (or `-accel tcg,thread=multi -cpu max`) `-smp 2 -m 4096`, parses the console. |
| `run-matrix.sh` | Loops `run-vm.sh` over kernels; writes `results/<payload>-<ts>.tsv`. |
| `build-payload.sh <name>` | Builds what a payload's `run.sh` uses from the OBI checkout (`OBI_REPO`): `obi`, `stats.test`, `verifier.test`, `ebpf.test`, the lab helper tools (`sfr` among them), `MODE` for `iostats`, and for k3s payloads `k3s-root.tar`, `images*.tar`, `otelcol-contrib`, `prometheus`. |

Kernel cmdline: `console=ttyS0 root=/dev/vda rw init=/lab-init.sh panic=-1
cgroup_no_v1=all mitigations=off loglevel=4 rcupdate.rcu_cpu_stall_timeout=120`.
`mitigations=off` is only there to make TCG faster; it is kept under KVM so the
guests match the cloud lab's.

Console protocol (from the guest): `===LAB_BOOTED=== <uptime>`,
`===LAB_PAYLOAD_BEGIN===`, `===LAB_PAYLOAD_END===`, `LAB_EXIT=<rc>`, and
`LAB_ERROR=<text>` for infrastructure failures (no `run.sh`, 9p mount failed).

## Timing under TCG (cloud lab, 4 host CPUs, `-smp 2`)

- Boot is **11–18 s**, measured on the host from QEMU start to `lab-init`
  ready (mounts, modprobes and 9p done). 5.x kernels take ~11–13 s; 6.6+
  take ~15–18 s.
- A trivial payload takes **~16 s end to end**.
- Payload staging copies the payload dir to tmpfs over 9p. A 74 MB Go test
  binary adds ~3 s on 6.x and ~12–14 s on 5.8–5.15.
- The statsolly verifier subset takes 3.5–5 s in the guest. Emulated code is
  roughly 10–30x slower than native. Under KVM the guest runs at native speed,
  so these times drop; the timeouts stay as upper bounds.

## Adding a kernel

```sh
./fetch-kernel.sh v6.19.3            # any https://kernel.ubuntu.com/mainline/<ver>/
sudo ./build-rootfs.sh --add v6.19.3 # modules into base.raw
./run-vm.sh v6.19.3 payloads/rhel-smoke
```

## Gotchas

- The RHEL kernels are Oracle Linux's Red Hat Compatible Kernel: the RHEL kernel
  rebuilt from Red Hat's sources (the repo's CI uses RHEL kernel images from quay.io).
- The guest has no network (no `-nic`); add one in `run-vm.sh` if needed.
- `build-rootfs.sh` runs under sudo, so it uses root's container engine: with
  moby (`docker`) start it with `sudo systemctl enable --now docker`; with
  podman-docker nothing is needed.
- mkfs.ext4 in the guest (e2fsprogs 1.47, Ubuntu defaults) does not enable
  `orphan_file`, so filesystems it creates mount read-write on 5.8 too.
- Do not run `build-rootfs.sh` while a VM is running; overlays point at
  `base.raw`.

## Disk usage

About 7 GB under `lab/` after `setup.sh` (cloud lab figures for 8 kernels, plus
the RHEL ones):

| Path | Size |
|---|---|
| `cache/kernels/` (11 extracted kernels) | ~3 GB |
| `cache/base.raw` (8 GB sparse) | ~2.5 GB allocated |
| `cache/debs/`, `cache/rpms/` (can be deleted) | ~1.5 GB |
| a k3s payload (`k3s-root.tar`, `images.tar`, collector, Prometheus) | ~0.9 GB, hard-linked from `cache/k3s/` and `cache/downloads/` |
| initramfs, logs, runs, results | <10 MB per run |

The container engine also keeps the `obi-lab-rootfs` image (~200 MB) and the
images `build-payload.sh` builds or pulls. Each run's qcow2 overlay is deleted
afterwards, unless `LAB_KEEP=1` is set.
