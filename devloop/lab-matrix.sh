#!/usr/bin/env bash
# lab-matrix.sh: build a lab payload from the current checkout and run it on lab kernels.
#
#   lab-matrix.sh <payload-name> [--template <dir>] [--kernels "<v> <v> ..."] [--timeout <s>] [--background]
#
# The payload gets: obi (static build), stats.test (the privileged storage tests), COMMIT, and
# run.sh copied from the template payload (default: payloads/final; a git checkout does not keep
# the modification times that "the newest payload" relied on).
# Default kernels: the four that cover the support matrix edges: v6.12.111 rhel8.10 rhel9.6 v7.2.6.
# All lab kernels: ls $LAB/cache/kernels. Results: $LAB/results/<name>-<ts>.tsv and per kernel .out.
set -u
. "$(dirname "$0")/common.sh"

[ $# -ge 1 ] || { sed -n '2,11p' "$0"; exit 2; }

summarize() { # <results tsv>
    local tsv=$1 dir=${1%.tsv}
    step "results"
    cat "$tsv"
    for out in "$dir"/*.out; do
        [ -f "$out" ] || continue
        printf '  %-12s PASS=%s FAIL=%s\n' "$(basename "$out" .out)" "$(grep -c '^RESULT.*PASS' "$out")" "$(grep -c '^RESULT.*FAIL' "$out")"
        grep '^RESULT.*FAIL' "$out" | sed 's/^/      /'
    done
}

if [ "$1" = --summarize ]; then
    summarize "$2"
    exit 0
fi

NAME=$1; shift
TEMPLATE=""; KERNELS="v6.12.111 rhel8.10 rhel9.6 v7.2.6"; TIMEOUT=900; BACKGROUND=0
while [ $# -gt 0 ]; do
    case "$1" in
        --template) TEMPLATE=$2; shift 2 ;;
        --kernels) KERNELS=$2; shift 2 ;;
        --timeout) TIMEOUT=$2; shift 2 ;;
        --background) BACKGROUND=1; shift ;;
        *) die "unknown option $1" ;;
    esac
done

PAYLOAD="$LAB/payloads/$NAME"
mkdir -p "$PAYLOAD"
if [ ! -f "$PAYLOAD/run.sh" ]; then
    [ -n "$TEMPLATE" ] || [ ! -f "$LAB/payloads/final/run.sh" ] || TEMPLATE="$LAB/payloads/final"
    [ -n "$TEMPLATE" ] || TEMPLATE=$(ls -td "$LAB"/payloads/*/ | while read -r d; do [ -f "$d/run.sh" ] && { echo "$d"; break; }; done)
    [ -f "$TEMPLATE/run.sh" ] || die "no run.sh template found; pass --template"
    cp "$TEMPLATE/run.sh" "$PAYLOAD/run.sh"
    note "run.sh copied from $TEMPLATE"
fi

cd "$REPO" || exit 1
disk_guard
step "building the payload from $(git rev-parse --short HEAD)"
git rev-parse --short HEAD > "$PAYLOAD/COMMIT"
# a fresh clone has no generated eBPF files (they are not committed)
[ -n "$(find pkg -name '*_bpfel.go' -print -quit)" ] || make generate || die "make generate failed"
CGO_ENABLED=0 go build -o "$PAYLOAD/obi" ./cmd/obi || die "obi build failed"
CGO_ENABLED=0 go test -c -tags privileged_tests -o "$PAYLOAD/stats.test" ./pkg/internal/statsolly/stats || die "stats.test build failed"
ls -la "$PAYLOAD"


step "running on: $KERNELS (one VM at a time, ~3-4 min each)"
if [ "$BACKGROUND" = 1 ]; then
    LOG="$LAB/logs/matrix-$NAME-$(date +%Y%m%d-%H%M%S).log"
    # shellcheck disable=SC2086
    setsid nohup "$LAB/run-matrix.sh" "$PAYLOAD" "$TIMEOUT" $KERNELS > "$LOG" 2>&1 &
    note "started in the background, log: $LOG"
    note "when it ends, the last line of the log is the results tsv; summarize with: $0 --summarize <tsv>"
else
    # shellcheck disable=SC2086
    TSV=$("$LAB/run-matrix.sh" "$PAYLOAD" "$TIMEOUT" $KERNELS 2>/dev/null | tail -1)
    summarize "$TSV"
fi
