#!/usr/bin/env bash
# Build (or update) the lab base image cache/base.raw.
#
#   build-rootfs.sh                 full rebuild: docker image -> ext4 raw image,
#                                   plus modules of every kernel in cache/kernels
#   build-rootfs.sh --init          only refresh /lab-init.sh in the existing image
#   build-rootfs.sh --add <ver>...  add/refresh modules of the given kernels
#
# Never run this while a VM is using the image (run-vm.sh overlays are
# throwaway qcow2 files backed by base.raw).
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
IMG="$LAB/cache/base.raw"
MNT="$LAB/cache/mnt"
SIZE="${SIZE:-8G}"
DOCKER_TAG=obi-lab-rootfs:latest

cleanup() {
    if mountpoint -q "$MNT"; then umount "$MNT"; fi
}
trap cleanup EXIT

mount_image() {
    mkdir -p "$MNT"
    mount -o loop "$1" "$MNT"
}

install_init() {
    install -m 0755 "$LAB/rootfs/lab-init.sh" "$MNT/lab-init.sh"
}

install_modules() {
    local ver=$1
    eval "$("$LAB/kernel-info.sh" "$ver")"
    echo "modules: $ver -> /lib/modules/$KREL"
    rm -rf "$MNT/usr/lib/modules/$KREL"
    mkdir -p "$MNT/usr/lib/modules"
    cp -a "$MODDIR" "$MNT/usr/lib/modules/$KREL"
    # Use the guest's own depmod so modules.dep.bin matches the guest kmod.
    chroot "$MNT" /usr/sbin/depmod -a "$KREL"
}

all_kernels() {
    ls "$LAB/cache/kernels"
}

case "${1:-}" in
--init)
    mount_image "$IMG"
    install_init
    ;;
--add)
    shift
    mount_image "$IMG"
    for v in "$@"; do install_modules "$v"; done
    ;;
"")
    docker build -q -t "$DOCKER_TAG" "$LAB/rootfs"
    tarball="$LAB/cache/rootfs.tar"
    cid="$(docker create "$DOCKER_TAG")"
    docker export -o "$tarball" "$cid"
    docker rm "$cid" >/dev/null

    rm -f "$IMG.tmp"
    truncate -s "$SIZE" "$IMG.tmp"
    mkfs.ext4 -q -F -L labroot "$IMG.tmp"
    mount_image "$IMG.tmp"
    tar --numeric-owner -xpf "$tarball" -C "$MNT"
    rm -f "$tarball"
    install_init
    for v in $(all_kernels); do install_modules "$v"; done
    sync
    umount "$MNT"
    mv "$IMG.tmp" "$IMG"
    ;;
*)
    sed -n '2,11p' "$0"
    exit 2
    ;;
esac
echo "done: $IMG ($(du -h "$IMG" | cut -f1) allocated)"
