#!/usr/bin/env bash
# Print vmlinuz / modules dir / release for an extracted kernel.
# Usage: kernel-info.sh <version>   -> KVER= KREL= VMLINUZ= MODDIR= CONFIG=
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
VER="$1"
K="$LAB/cache/kernels/$VER"
[ -d "$K" ] || { echo "kernel $VER not fetched (run fetch-kernel.sh $VER)" >&2; exit 2; }
MODDIR="$( { ls -d "$K"/lib/modules/* "$K"/usr/lib/modules/* 2>/dev/null || true; } | head -1)"
KREL="$(basename "$MODDIR")"
# Ubuntu debs ship boot/vmlinuz-* and boot/config-*; RHEL-family RPMs ship them in the modules dir
VMLINUZ="$( { ls "$K"/boot/vmlinuz-* 2>/dev/null || ls "$MODDIR"/vmlinuz; } | head -1)"
CONFIG="$( { ls "$K"/boot/config-* 2>/dev/null || ls "$MODDIR"/config; } | head -1)"
printf 'KVER=%q\nKREL=%q\nVMLINUZ=%q\nMODDIR=%q\nCONFIG=%q\n' "$VER" "$KREL" "$VMLINUZ" "$MODDIR" "$CONFIG"
