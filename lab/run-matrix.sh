#!/usr/bin/env bash
# Run one payload on several kernels, sequentially.
#   run-matrix.sh <payload-dir> [timeout-seconds] [kernel-version...]
# Without versions, every kernel in cache/kernels is used (oldest first).
# Writes results/<payload>-<ts>.tsv (kernel, exit, boot, payload, total, log)
# and per-kernel payload output to results/<payload>-<ts>/<ver>.out.
set -uo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD="$1"
TIMEOUT="${2:-900}"
shift $(( $# >= 2 ? 2 : 1 ))
if [ $# -gt 0 ]; then
    versions=("$@")
else
    mapfile -t versions < <(ls "$LAB/cache/kernels" | sort -V)
fi

name="$(basename "$(realpath "$PAYLOAD")")"
ts="$(date +%Y%m%d-%H%M%S)"
outdir="$LAB/results/$name-$ts"
tsv="$LAB/results/$name-$ts.tsv"
mkdir -p "$outdir"
printf 'kernel\texit\tboot\tpayload\ttotal\tlog\n' > "$tsv"

for v in "${versions[@]}"; do
    echo "=== $v" >&2
    "$LAB/run-vm.sh" "$v" "$PAYLOAD" "$TIMEOUT" > "$outdir/$v.out" 2> "$outdir/$v.err"
    rc=$?
    summary="$(grep '^\[run-vm\]' "$outdir/$v.err" | tail -1)"
    field() { printf '%s\n' "$summary" | grep -o "$1=[^ ]*" | head -1 | cut -d= -f2; }
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$v" "$rc" "$(field boot)" "$(field payload)" "$(field total)" "$(field log)" >> "$tsv"
    echo "$summary" >&2
done
cat "$tsv" >&2
echo "$tsv"
