#!/usr/bin/env bash
# One-time, idempotent setup of the OBI kernel lab on a Fedora workstation. Re-running skips what is
# already done.
#   1. checks the tools, /dev/kvm, the container CLI, the OBI checkout and the free disk
#   2. fetches the 11 lab kernels into lab/cache/kernels (Ubuntu mainline debs, Oracle Linux RHCK
#      rpms) and compares each vmlinuz with the cloud lab's (lab/KERNELS.sha256)
#   3. extracts the static busybox of the initramfs (lab/cache/busybox-1.37-uclibc)
#   4. builds lab/cache/base.raw with build-rootfs.sh (sudo: loop mount and chroot), or adds the
#      modules of the kernels the image does not have yet
#   5. builds the initramfs of the kernels that need one
#   6. boots the smoke VMs: lab/payloads/rhel-smoke on each of $SMOKE_KERNEL (9p on v6.12.111;
#      initramfs, host depmod and disk transport on rhel8.10)
#
# Environment: OBI_REPO (default ~/obi-work/opentelemetry-ebpf-instrumentation), KERNELS (default:
# all 11), SMOKE_KERNEL (a list, default "v6.12.111 rhel8.10"), SKIP_SMOKE=1.
set -euo pipefail
KIT="$(cd "$(dirname "$0")" && pwd)"
LAB="$KIT/lab"
REPO="${OBI_REPO:-$HOME/obi-work/opentelemetry-ebpf-instrumentation}"
KERNELS="${KERNELS:-v5.8.18 v5.10.270 v5.15.221 v6.1.188 v6.6.157 v6.12.111 v6.18.54 v7.2.6 rhel8.9 rhel8.10 rhel9.6}"
SMOKE_KERNEL="${SMOKE_KERNEL:-v6.12.111 rhel8.10}"
BUSYBOX_IMAGE=docker.io/library/busybox:1.37-uclibc
BUSYBOX_CLOUD_SHA256=fd52b4605ca428985667515991871a62246cddd6ef06ed95637c6c4c0249bd6c
export PATH="$PATH:/usr/sbin:/sbin"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { echo; bold "### $*"; }
note() { echo "    $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

SUDO=()
[ "$(id -u)" = 0 ] || SUDO=(sudo)

# ---- 1. host checks

step "host checks"
declare -A PKG=(
    [qemu-system-x86_64]=qemu-system-x86-core [qemu-img]=qemu-img [go]=golang [git]=git [make]=make
    [curl]=curl [mkfs.ext4]=e2fsprogs [debugfs]=e2fsprogs [dpkg-deb]=dpkg [zstd]=zstd [xz]=xz [gzip]=gzip
    [cpio]=cpio [python3]=python3 [tar]=tar [flock]=util-linux [mountpoint]=util-linux [depmod]=kmod
    [timeout]=coreutils [sha256sum]=coreutils [docker]="podman-docker or docker" [jq]=jq [clang]=clang
    [llvm-strip]=llvm
)
missing=()
for t in "${!PKG[@]}"; do
    command -v "$t" >/dev/null || missing+=("$t (${PKG[$t]})")
done
[ "${#missing[@]}" -eq 0 ] || die "missing tools: ${missing[*]}"
note "tools: ok"

if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    note "KVM: /dev/kvm is usable, VMs run with -accel kvm -cpu host"
elif [ -e /dev/kvm ]; then
    note "KVM: /dev/kvm exists but $(id -un) can't open it: sudo usermod -aG kvm $(id -un), then log in again"
    note "     (until then the VMs fall back to TCG, 10-30x slower)"
else
    note "KVM: no /dev/kvm (virtualization off in the firmware?): the VMs fall back to TCG, 10-30x slower"
fi
# not a pipe into grep -q: under pipefail QEMU's SIGPIPE would fail the check
devs="$(qemu-system-x86_64 -device help 2>/dev/null || true)"
if ! grep -q virtio-9p <<< "$devs"; then
    note "QEMU has no virtio-9p: run the lab with LAB_TRANSPORT=disk (payload and results over virtio disks)"
    export LAB_TRANSPORT=disk
fi

[ "${#SUDO[@]}" -eq 0 ] || sudo -v || die "sudo is needed for the base image (loop mount, chroot) and root's container engine"
"${SUDO[@]}" docker info >/dev/null 2>&1 ||
    die "'${SUDO[*]} docker info' fails: with moby (docker) run 'sudo systemctl enable --now docker'; with podman-docker it should work as is"
note "container CLI: $(docker --version 2>/dev/null | head -1)"

if [ -e "$REPO/.git" ]; then
    note "OBI checkout: $REPO ($(git -C "$REPO" branch --show-current 2>/dev/null) @ $(git -C "$REPO" rev-parse --short HEAD))"
else
    note "WARNING: no OBI checkout at $REPO (set OBI_REPO): the lab runs without it, build-payload.sh needs it"
fi
note "go: $(go env GOVERSION)$([ -e "$REPO/go.mod" ] && echo ", the repo asks for $(grep -E '^(go|toolchain) ' "$REPO/go.mod" | tr '\n' ' ')")"
if [ -e "$REPO/go.mod" ]; then
    # run in the repo, so the go/toolchain lines of go.mod select (and download) the toolchain
    if gov="$(go -C "$REPO" version 2>&1)"; then
        note "go in the repo: $gov"
    else
        note "WARNING: 'go -C $REPO version' fails: $(tail -1 <<< "$gov")"
        note "         try GOTOOLCHAIN=auto GOPROXY=https://proxy.golang.org,direct (go env -w makes it stick)"
    fi
fi

free_gib="$(df -BG --output=avail "$LAB" | tail -1 | tr -dc '0-9')"
note "free disk under $LAB: ${free_gib}G (the kernels, packages and base image take ~8G, a k3s payload ~1G)"
[ "$free_gib" -ge 12 ] || note "WARNING: less than 12G free"

# ---- 2. kernels

step "kernels"
for v in $KERNELS; do
    k="$LAB/cache/kernels/$v"
    if [ ! -f "$k/.lab-fetched" ]; then
        case "$v" in
            rhel*) "$LAB/fetch-rhel-kernel.sh" "$v" ;;
            *) "$LAB/fetch-kernel.sh" "$v" ;;
        esac
        touch "$k/.lab-fetched"
    fi
    eval "$("$LAB/kernel-info.sh" "$v")"
    [ -f "$VMLINUZ" ] || die "$v: no vmlinuz in $k (remove the directory and re-run)"
    want="$(awk -v v="$v" '$2 == v { print $1 }' "$LAB/KERNELS.sha256")"
    got="$(sha256sum "$VMLINUZ" | cut -d' ' -f1)"
    if [ -z "$want" ]; then
        note "$v: $KREL (not one of the cloud lab's kernels)"
    elif [ "$got" = "$want" ]; then
        note "$v: $KREL, same vmlinuz as the cloud lab"
    else
        note "WARNING: $v: $KREL, vmlinuz differs from the cloud lab's ($got)"
    fi
done

# ---- 3. busybox for the initramfs

step "busybox for the initramfs"
bb="$LAB/cache/busybox-1.37-uclibc"
if [ ! -s "$bb" ]; then
    "${SUDO[@]}" docker pull "$BUSYBOX_IMAGE" >/dev/null
    cid="$("${SUDO[@]}" docker create "$BUSYBOX_IMAGE")"
    "${SUDO[@]}" docker cp "$cid:/bin/busybox" - | tar -xOf - busybox > "$bb.tmp"
    "${SUDO[@]}" docker rm "$cid" >/dev/null
    chmod 0755 "$bb.tmp"
    mv "$bb.tmp" "$bb"
fi
if [ "$(sha256sum "$bb" | cut -d' ' -f1)" = "$BUSYBOX_CLOUD_SHA256" ]; then
    note "$bb: same binary as the cloud lab"
else
    note "$bb: a newer build of $BUSYBOX_IMAGE than the cloud lab's (fine if static)"
fi

# ---- 4. base image

step "base image (lab/cache/base.raw)"
img="$LAB/cache/base.raw"
if [ ! -f "$img" ]; then
    note "building it: docker image -> 8G sparse ext4 (sudo for the loop mount and chroot)"
    "${SUDO[@]}" "$LAB/build-rootfs.sh"
else
    # the modules directories in the image, read without mounting it
    have="$(debugfs -R 'ls -p /usr/lib/modules' "$img" 2>/dev/null | awk -F/ 'NF > 5 { print $6 }')"
    add=()
    for v in $KERNELS; do
        eval "$("$LAB/kernel-info.sh" "$v")"
        grep -qxF "$KREL" <<< "$have" || add+=("$v")
    done
    if [ "${#add[@]}" -gt 0 ]; then
        note "adding the modules of: ${add[*]}"
        "${SUDO[@]}" "$LAB/build-rootfs.sh" --add "${add[@]}"
    else
        note "present, with the modules of every kernel"
    fi
fi
[ -O "$img" ] || "${SUDO[@]}" chown "$(id -u):$(id -g)" "$img"

# ---- 5. initramfs

step "initramfs (kernels whose virtio_blk or ext4 is a module)"
for v in $KERNELS; do
    out="$("$LAB/build-initramfs.sh" "$v")" || die "build-initramfs.sh $v failed"
    note "$v: ${out:-not needed}"
done

# ---- 6. smoke VM

if [ -n "${SKIP_SMOKE:-}" ]; then
    step "smoke VM skipped (SKIP_SMOKE)"
    exit 0
fi
for v in $SMOKE_KERNEL; do
    step "smoke VM: payloads/rhel-smoke on $v"
    case " $KERNELS " in
        *" $v "*) ;;
        *) note "skipped: $v is not in KERNELS (the base image may lack its modules)"; continue ;;
    esac
    set +e
    "$LAB/run-vm.sh" "$v" "$LAB/payloads/rhel-smoke" 600
    rc=$?
    set -e
    [ "$rc" = 0 ] || die "the smoke VM on $v failed (exit $rc): see the [run-vm] line above and lab/logs/"
done
bold "lab ready"
