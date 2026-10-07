#!/usr/bin/env bash
# Download + extract an Ubuntu mainline kernel (generic flavour, amd64).
# Usage: fetch-kernel.sh <version, e.g. v6.6.157>
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
VER="$1"
BASE="https://kernel.ubuntu.com/mainline/${VER}"
DEBS="$LAB/cache/debs/$VER"
OUT="$LAB/cache/kernels/$VER"
mkdir -p "$DEBS"

listing="$(curl -fsS --retry 3 --max-time 120 "$BASE/")"
mapfile -t files < <(printf '%s\n' "$listing" | grep -oE 'href="(amd64/)?linux-(image-unsigned|modules)-[^"]*-generic_[^"]*_amd64\.deb"' \
    | sed -e 's/^href="//' -e 's/"$//' | sort -u)
if [ "${#files[@]}" -lt 2 ]; then
    echo "ERROR: no amd64 generic image+modules debs under $BASE" >&2
    exit 2
fi
for f in "${files[@]}"; do
    dest="$DEBS/$(basename "$f")"
    if [ ! -s "$dest" ]; then
        echo "downloading $f"
        curl -fsS --retry 3 --max-time 1800 -o "$dest.part" "$BASE/$f"
        mv "$dest.part" "$dest"
    fi
done
rm -rf "$OUT"
mkdir -p "$OUT"
for d in "$DEBS"/*.deb; do
    dpkg-deb -x "$d" "$OUT"
done
# Newer Ubuntu packaging ships under usr/lib/modules; normalise.
ls -d "$OUT"/lib/modules/* "$OUT"/usr/lib/modules/* 2>/dev/null || true  # one of the two is absent
ls "$OUT"/boot/
