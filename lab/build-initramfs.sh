#!/usr/bin/env bash
# Build cache/initramfs/<ver>.cpio.gz for kernels whose virtio_blk or ext4 is a module.
# Prints the initramfs path, or nothing when the kernel does not need one.
# Usage: build-initramfs.sh <ver>
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
VER="$1"
eval "$("$LAB/kernel-info.sh" "$VER")"

# the modules needed to mount the root disk: virtio_blk on Ubuntu kernels < 6.6, and ext4 too on
# RHEL-family kernels
needed=()
grep -q '^CONFIG_VIRTIO_BLK=y' "$CONFIG" || needed+=(virtio_blk)
grep -q '^CONFIG_EXT4_FS=y' "$CONFIG" || needed+=(ext4)
if [ "${#needed[@]}" -eq 0 ]; then
    exit 0
fi

OUT="$LAB/cache/initramfs/$VER.cpio.gz"
if [ -s "$OUT" ] && [ "$OUT" -nt "$LAB/rootfs/initramfs-init" ] && [ "$OUT" -nt "$0" ]; then
    echo "$OUT"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work"/{bin,modules,proc,sys,dev,newroot}
install -m 0755 "$LAB/cache/busybox-1.37-uclibc" "$work/bin/busybox"
install -m 0755 "$LAB/rootfs/initramfs-init" "$work/init"

# modules.dep lists the dependencies of each module; RPMs don't ship it, so generate it. A kmod
# built with moduledir=/usr/lib/modules looks under <base>/usr/lib/modules, so link that to the
# extracted lib/modules (kernel-info.sh still picks lib/modules first).
if [ ! -s "$MODDIR/modules.dep" ]; then
    base="${MODDIR%/lib/modules/*}"
    if [ ! -e "$base/usr/lib/modules/$KREL" ]; then
        mkdir -p "$base/usr/lib"
        ln -sfn ../../lib/modules "$base/usr/lib/modules"
    fi
    depmod -b "$base" "$KREL"
fi

# the modules in load order: dependencies first, each once
ordered=()
add_module() { # add_module <path relative to MODDIR>
    local rel=$1 dep
    for o in "${ordered[@]}"; do [ "$o" = "$rel" ] && return 0; done
    for dep in $(awk -F': *' -v m="$rel" '$1 == m { print $2 }' "$MODDIR/modules.dep"); do
        add_module "$dep"
    done
    ordered+=("$rel")
}
for m in "${needed[@]}"; do
    ko="$(cd "$MODDIR" && find kernel -name "$m.ko*" | head -1)"
    [ -n "$ko" ] || { echo "$m module not found in $MODDIR" >&2; exit 1; }
    add_module "$ko"
done

# initramfs-init loads /modules/*.ko in name order; busybox insmod needs them uncompressed
i=10
for rel in "${ordered[@]}"; do
    name="$i-$(basename "${rel%%.ko*}").ko"
    case "$rel" in
        *.zst) zstd -q -d -c "$MODDIR/$rel" > "$work/modules/$name" ;;
        *.xz)  xz -d -c "$MODDIR/$rel" > "$work/modules/$name" ;;
        *)     cp "$MODDIR/$rel" "$work/modules/$name" ;;
    esac
    i=$((i + 1))
done

mkdir -p "$(dirname "$OUT")"
(cd "$work" && find . -print0 | cpio --null -o -H newc --quiet) | gzip -9 > "$OUT.tmp"
mv "$OUT.tmp" "$OUT"
echo "$OUT"
