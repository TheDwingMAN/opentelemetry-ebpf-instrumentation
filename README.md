# OBI lab kit

The QEMU kernel lab and the development loop of the OBI storage-metrics work
(`feat/statso11y-disk-metrics-v2`), moved from the cloud sandbox to a Fedora
workstation with KVM. It boots 11 kernels (Ubuntu mainline 5.8 to 7.2, RHEL 8.9,
8.10 and 9.6 rebuilds), runs a payload in each and reports `RESULT ... PASS/FAIL`
lines. Only scripts, manifests and docs are here; kernels, the base image and
payload binaries are fetched or built on your machine.

```
~/obi-work/
  opentelemetry-ebpf-instrumentation/   the fork, feat/statso11y-disk-metrics-v2  (OBI_REPO)
  lab-kit/                              this kit: branch lab-kit of the fork      (OBI_WS)
    setup.sh                            one-time setup, safe to re-run
    lab/                                the VM lab: lab/README.md, lab/KERNELS.md
    devloop/                            the development loop: docs/devloop.md
```

## One-time Fedora 44 setup

`podman-docker` and moby (`moby-engine`, the `docker` command) conflict in dnf,
so pick one of the two blocks. The kit works with both.

(a) podman-docker (no daemon, no docker group):

```sh
sudo dnf install qemu-system-x86-core qemu-img golang clang llvm git make curl e2fsprogs dpkg zstd cpio rpm2cpio jq podman-docker
sudo usermod -aG kvm "$USER"            # only if /dev/kvm is not 0666, then log out and back in
```

(b) moby:

```sh
sudo dnf install qemu-system-x86-core qemu-img golang clang llvm git make curl e2fsprogs dpkg zstd cpio rpm2cpio jq moby-engine
sudo usermod -aG kvm,docker "$USER"     # drop kvm if /dev/kvm is 0666; then log out and back in
sudo systemctl enable --now docker
```

Fedora ships `/dev/kvm` as mode 0666 (`ls -l /dev/kvm`), so the kvm group is
only needed when it is not. Without the docker group, moby needs
`DOCKER="sudo docker"` for `build-payload.sh`.

```sh
mkdir -p ~/obi-work && cd ~/obi-work
git clone -b feat/statso11y-disk-metrics-v2 https://github.com/TheDwingMAN/opentelemetry-ebpf-instrumentation.git
git clone -b lab-kit --single-branch https://github.com/TheDwingMAN/opentelemetry-ebpf-instrumentation.git lab-kit
# the devloop gates pushes on these two remotes
git -C opentelemetry-ebpf-instrumentation remote add upstream https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation.git
git -C opentelemetry-ebpf-instrumentation remote set-url --push upstream DISABLED
```

The scripts call each other and need their executable bits, which a git clone
keeps. If you got the kit from an archive (a zip or the GitHub web UI) instead,
run `find ~/obi-work/lab-kit -name '*.sh' -exec chmod +x {} + && chmod +x ~/obi-work/lab-kit/lab/bin/docker ~/obi-work/lab-kit/devloop/stage_hunks.py ~/obi-work/lab-kit/lab/rpm-extract.py`.

## setup.sh

```sh
cd ~/obi-work/lab-kit && ./setup.sh
```

It checks the tools, `/dev/kvm` and docker; fetches the 11 kernels
(kernel.ubuntu.com, yum.oracle.com) and compares each vmlinuz with the cloud
lab's; extracts the static busybox of the initramfs; builds `lab/cache/base.raw`
(asks for sudo: loop mount and chroot); builds the initramfs; boots two smoke VMs
(`payloads/rhel-smoke` on v6.12.111 over 9p, and on rhel8.10 with an initramfs
and the disk transport; `SMOKE_KERNEL` sets the list) and ends with `lab ready`.
It also runs `go version` in the repo, which selects (and downloads) the
toolchain `go.mod` asks for; if that fails, set
`GOTOOLCHAIN=auto GOPROXY=https://proxy.golang.org,direct`. It needs ~8 GB
of disk and downloads ~2 GB. Re-running skips what is done.

KVM: `run-vm.sh` uses `-accel kvm -cpu host` when `/dev/kvm` is readable and
writable, else `-accel tcg,thread=multi -cpu max` (10-30x slower). The summary
line shows which (`accel=kvm`). `LAB_ACCEL` and `LAB_CPU` override it; the
timeouts were sized for TCG and stay as upper bounds (`LAB_TIMEOUT_SCALE`
multiplies them).

## Build and run a payload

`build-payload.sh <name>` builds what `payloads/<name>/run.sh` uses from the
fork's HEAD (it runs `make generate` first, see `OBI_GENERATE`) and writes
`payloads/<name>/COMMIT` (ignored by git, like the binaries).

One kernel:

```sh
cd ~/obi-work/lab-kit/lab
./build-payload.sh final       && ./run-vm.sh v6.12.111 payloads/final 1200
./build-payload.sh nvme-mpath  && LAB_NVME_MPATH=256M ./run-vm.sh v6.12.111 payloads/nvme-mpath 900
./build-payload.sh k3s-final   && ./run-vm.sh v6.12.111 payloads/k3s-final 3000
./build-payload.sh iostats     && LAB_EXTRA_DISKS=1G ./run-vm.sh v6.18.54 payloads/iostats 1800
```

The matrix (one VM at a time):

```sh
./run-matrix.sh payloads/final 1200                          # all 11 kernels
./run-matrix.sh payloads/k3s-final 3000 v6.12.111 rhel9.6   # the kernels you name
../devloop/lab-matrix.sh final                              # build from HEAD, run on 6.12, RHEL 8.10, RHEL 9.6, 7.2
```

`k3s-final` builds `k3s-root.tar` (rancher/k3s v1.30.14-k3s2), `images.tar`
(obi from the fork with `lab/docker/obi-image.Dockerfile`, tagged as the
manifest expects; go-disk-io from the fork; k3s's pause image),
`otelcol-contrib` 0.161.0 and `prometheus` 3.15.0, the versions the cloud lab ran.
`final` also gets `ebpf.test` (the privileged tests of `pkg/internal/statsolly/ebpf`) and
`sfr` (`lab/sfr/`, a `sync_file_range` caller). `iostats` gets `obi` and `MODE`: `fixed` when
the binary has the RQF_IO_STAT gate, else `current` (`IOSTATS_MODE=fixed|current` overrides it).

## Where the results are

| What | Where |
|---|---|
| guest console of a run | `lab/logs/<kernel>-<ts>.log` |
| payload output and files (`output.log`, `dmesg.log`, `exit_code`, `obi.log`, `metrics.txt`, ...) | `lab/runs/<kernel>-<ts>/results/` |
| matrix summary, one line per kernel | `lab/results/<payload>-<ts>.tsv` |
| matrix payload output per kernel | `lab/results/<payload>-<ts>/<kernel>.out` (`.err`: the `[run-vm]` line) |

## Reporting results back

After a matrix, paste the output of:

```sh
cat ~/obi-work/lab-kit/lab/payloads/<payload>/COMMIT
~/obi-work/lab-kit/devloop/lab-matrix.sh --summarize ~/obi-work/lab-kit/lab/results/<payload>-<ts>.tsv
```

(`run-matrix.sh` prints the tsv path last.) After a single `run-vm.sh`, paste
its `[run-vm]` line and `grep -E '^(RESULT|SKIP)' <results dir>/output.log`.
For a failure, add the `RESULT ... FAIL` context from `output.log` and the
tail of the console log.

## Paths and options

| Variable | Default | Used by |
|---|---|---|
| `OBI_REPO` | `~/obi-work/opentelemetry-ebpf-instrumentation` | `build-payload.sh`, `run-kind-disk.sh`, `devloop/` |
| `OBI_WS` | the kit root | `devloop/` (lab at `$OBI_WS/lab`) |
| `DOCKER` | `docker` | `build-payload.sh` |
| `OBI_GENERATE` | `make` (`make generate`); `docker` (`make docker-generate`, with podman when `docker` is podman-docker); `0` (skip) | `build-payload.sh` |
| `LAB_ACCEL`, `LAB_CPU`, `LAB_SMP`, `LAB_MEM`, `LAB_TRANSPORT`, `LAB_TIMEOUT_SCALE`, ... | see `lab/README.md` | `run-vm.sh` |

Optional pieces: `devloop/ci-status.sh` needs the GitHub CLI (`sudo dnf install gh`,
`gh auth login`); `lab/run-kind-disk.sh` needs `kind` and moby; `lab/bench/`,
`lab/soak/` and `lab/bpfstats/measure.sh` run as root on the host kernel.
`lab/bench/bench.sh`, `lab/bench/contention.sh` and `lab/soak/soak.sh` also need
`fio` (`sudo dnf install fio`) and an obi binary at `lab/bench/obi`, which no
builder makes: `cd ~/obi-work/opentelemetry-ebpf-instrumentation && go build -o
~/obi-work/lab-kit/lab/bench/obi ./cmd/obi`, or point `OBI=` at one.
Payloads whose binaries came from outside the lab (`smoke`, `fsyncargs`,
`v2spike`, `dynsel`) and `k3s-debug` are kept for reference;
`build-payload.sh` says so instead of building them.

SELinux: the repository's `scripts/lint-schema.sh` (the telemetry schema lint
step of `devloop/pre-push.sh`, run when `schemas/`, `site/` or attributes change)
bind mounts the registry without `:z`, so on an enforcing host the container
may be denied reading it. Keep SELinux on: run that step in the cloud sandbox or
CI, or with a container engine setup that relabels the mount.
