#!/usr/bin/env bash
# Download + extract a RHEL-family kernel: Oracle Linux's Red Hat Compatible Kernel (RHCK, the RHEL
# kernel rebuilt from Red Hat's sources) from yum.oracle.com, the packages the cloud lab used.
# Usage: fetch-rhel-kernel.sh <rhel8.9|rhel8.10|rhel9.6>
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
ID="${1:-}"
case "$ID" in
    rhel8.9)  REPO=OL8; NVR=4.18.0-513.24.1.el8_9;        PKGS=(kernel-core kernel-modules) ;;
    rhel8.10) REPO=OL8; NVR=4.18.0-553.146.1.el8_10;      PKGS=(kernel-core kernel-modules) ;;
    rhel9.6)  REPO=OL9; NVR=5.14.0-570.62.1.0.1.el9_6;    PKGS=(kernel-core kernel-modules-core kernel-modules) ;;
    *) sed -n '2,4p' "$0" >&2; exit 2 ;;
esac
BASE="https://yum.oracle.com/repo/OracleLinux/$REPO/baseos/latest/x86_64/getPackage"
RPMS="$LAB/cache/rpms/$ID"
OUT="$LAB/cache/kernels/$ID"
mkdir -p "$RPMS"

for p in "${PKGS[@]}"; do
    f="$p-$NVR.x86_64.rpm"
    if [ ! -s "$RPMS/$f" ]; then
        echo "downloading $BASE/$f"
        curl -fsS --retry 3 --max-time 1800 -o "$RPMS/$f.part" "$BASE/$f"
        mv "$RPMS/$f.part" "$RPMS/$f"
    fi
done
rm -rf "$OUT"
mkdir -p "$OUT"
for p in "${PKGS[@]}"; do
    python3 "$LAB/rpm-extract.py" "$RPMS/$p-$NVR.x86_64.rpm" "$OUT"
done
# RHEL-family RPMs ship vmlinuz and config in the modules dir
"$LAB/kernel-info.sh" "$ID"
