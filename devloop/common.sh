#!/usr/bin/env bash
# Shared helpers of the OBI storage-metrics development loop. Source this file.
#
# Layout:
#   REPO   the OBI checkout (OBI_REPO, default ~/obi-work/opentelemetry-ebpf-instrumentation)
#   WS     the out-of-repo workspace (docs, lab, research, this loop) (OBI_WS, default the kit root:
#          the parent of this devloop directory)
#   LAB    the kernel lab (QEMU VMs)
#   DEVBIN tools this loop builds for itself (a Linux golangci-lint that can lint for darwin)

REPO=${OBI_REPO:-${REPO:-$HOME/obi-work/opentelemetry-ebpf-instrumentation}}
WS=${OBI_WS:-${WS:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}}
LAB="$WS/lab"
DEVBIN="$WS/devloop/bin"

FORK_OWNER=${FORK_OWNER:-TheDwingMAN}
GIT_AUTHOR_NAME_LOOP=${GIT_AUTHOR_NAME_LOOP:-TheDwingMAN}
GIT_AUTHOR_EMAIL_LOOP=${GIT_AUTHOR_EMAIL_LOOP:-77314716+TheDwingMAN@users.noreply.github.com}

# podman-docker: the Makefile's container targets (make docker-generate) pass -u uid:gid unless
# OCI_BIN names podman, and rootless podman maps that uid to a subuid that cannot write the repo
if [ -z "${OCI_BIN:-}" ] && docker --version 2>/dev/null | grep -qi podman; then
    export OCI_BIN=podman
fi

# Minimum free disk, in GiB, before a build or lint starts. The Go build cache grows to ~5 GiB
# on a full lint; below this the cache is cleaned first.
MIN_FREE_GIB=${MIN_FREE_GIB:-6}

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { echo; bold "### $*"; }
note() { echo "    $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

free_gib() { df -BG --output=avail "$REPO" | tail -1 | tr -dc '0-9'; }

# disk_guard cleans the Go build cache when the disk is nearly full
disk_guard() {
    local free; free=$(free_gib)
    if [ "$free" -lt "$MIN_FREE_GIB" ]; then
        note "only ${free}G free: cleaning the Go build cache"
        (cd "$REPO" && go clean -cache)
        note "now $(free_gib)G free"
    fi
}

# base_ref prints the ref that "changed" is measured against: the remote branch when it exists,
# else the merge base with upstream/main
base_ref() {
    local branch; branch=$(git -C "$REPO" branch --show-current)
    if [ -n "$branch" ] && git -C "$REPO" rev-parse -q --verify "origin/$branch" >/dev/null; then
        echo "origin/$branch"
    else
        git -C "$REPO" merge-base HEAD upstream/main
    fi
}

# changed_files <base> [pathspec...] lists the files changed since base, committed or not
changed_files() {
    local base=$1; shift
    { git -C "$REPO" diff --name-only "$base" -- "$@"; git -C "$REPO" diff --name-only -- "$@"; } | sort -u
}

# changed_go_pkgs <base> prints ./dir/... for every directory with changed Go files
changed_go_pkgs() {
    changed_files "$1" '*.go' | xargs -r -n1 dirname | sort -u | sed 's|^|./|; s|$|/...|'
}

# golangci prints the path of a golangci-lint built for this host, building it on first use.
# "go tool golangci-lint" rebuilds the tool for GOOS=darwin and then can't run it, so the
# darwin lint needs this binary.
golangci() {
    local bin="$DEVBIN/golangci-lint"
    if [ ! -x "$bin" ]; then
        local pkg
        pkg=$(grep -oE 'github.com/golangci/golangci-lint(/v[0-9]+)?/cmd/golangci-lint' "$REPO/internal/tools/go.mod" "$REPO"/internal/tools/*.go 2>/dev/null | head -1 | cut -d: -f2-)
        [ -n "$pkg" ] || die "can't find the golangci-lint package in internal/tools"
        mkdir -p "$DEVBIN"
        (cd "$REPO" && go build -modfile=internal/tools/go.mod -o "$bin" "$pkg") >&2
    fi
    echo "$bin"
}

# remote_gate checks that pushes can only reach the fork
remote_gate() {
    step "git remote -v"
    git -C "$REPO" remote -v
    local push_origin push_upstream
    push_origin=$(git -C "$REPO" remote get-url --push origin)
    push_upstream=$(git -C "$REPO" remote get-url --push upstream 2>/dev/null || echo none)
    case "$push_origin" in
        *"/$FORK_OWNER/"*) ;;
        *) die "origin push URL is not the fork: $push_origin" ;;
    esac
    case "$push_upstream" in
        DISABLED|none) ;;
        *) die "upstream push is not disabled: $push_upstream" ;;
    esac
    note "push target is the fork, upstream push is disabled"
}

# retry <n> <cmd...> retries a network command with exponential backoff (2s, 4s, 8s, 16s)
retry() {
    local tries=$1; shift
    local delay=2 i
    for ((i = 1; i <= tries; i++)); do
        if "$@"; then return 0; fi
        [ "$i" -lt "$tries" ] || return 1
        note "attempt $i failed, retrying in ${delay}s"
        sleep "$delay"; delay=$((delay * 2))
    done
}

# with_root_tests_note explains the unit tests that fail only because this host runs as root
root_tests_note() {
    if [ "$(id -u)" = 0 ]; then
        note "running as root: TestCheckOSCapabilities, TestLockdownParsing and the file-permission case of"
        note "TestExtractNextJSRoutesFromManifest fail for that reason alone (they pass in CI, which is not root)"
    fi
}
