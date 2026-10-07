#!/usr/bin/env bash
# pre-push.sh: the gate before a push. Runs what OBI's CI runs, on what changed.
#
#   pre-push.sh [--base <ref>] [--full] [--no-darwin] [--privileged] [--generate] [--push]
#
#   --base <ref>   measure "changed" against this ref (default: origin/<branch>, else the merge
#                  base with upstream/main)
#   --full         lint and test every package, not only the changed ones (what CI does)
#   --no-darwin    skip the darwin lint (CI lints on macOS too, so only skip when iterating)
#   --privileged   also run the privileged tests of the changed packages, natively (root only: they
#                  create loop, zram and LVM devices on this host; skipped with a note otherwise)
#   --generate     run make docker-generate and fail on drift of the generated files (needs Docker
#                  or podman, see OCI_BIN in common.sh; without it, a bpf/ change only gets a reminder)
#   --push         after everything passes: git remote -v gate, then git push -u origin <branch>
#
# Exit code 0 only when every step passed. Steps keep going after a failure so the summary is
# complete.
set -u
. "$(dirname "$0")/common.sh"

BASE=""; FULL=0; DARWIN=1; PRIVILEGED=0; GENERATE=0; PUSH=0
while [ $# -gt 0 ]; do
    case "$1" in
        --base) BASE=$2; shift 2 ;;
        --full) FULL=1; shift ;;
        --no-darwin) DARWIN=0; shift ;;
        --privileged) PRIVILEGED=1; shift ;;
        --generate) GENERATE=1; shift ;;
        --push) PUSH=1; shift ;;
        *) die "unknown option $1" ;;
    esac
done

cd "$REPO" || exit 1
[ -n "$BASE" ] || BASE=$(base_ref)
BRANCH=$(git branch --show-current)
step "pre-push on $BRANCH @ $(git rev-parse --short HEAD), changes measured against $BASE"
git status --short | head -20
disk_guard

declare -a RESULTS=()
record() { RESULTS+=("$1|$2"); }
run_step() { # name cmd...
    local name=$1; shift
    step "$name"
    if "$@"; then record "$name" PASS; else record "$name" FAIL; fi
}
skip_step() { step "$1"; note "$2"; record "$1" SKIP; }

GO_PKGS=$(changed_go_pkgs "$BASE")
ALL_PKGS="./pkg/... ./cmd/... ./internal/..."
if [ "$FULL" = 1 ] || [ -z "$GO_PKGS" ]; then TEST_PKGS=$ALL_PKGS; else TEST_PKGS=$GO_PKGS; fi
note "Go packages under test: $(echo "$TEST_PKGS" | tr '\n' ' ')"

# 1. generated files
if [ -n "$(changed_files "$BASE" 'bpf/*.c' 'bpf/*.h')" ]; then
    if [ "$GENERATE" = 1 ]; then
        gen_check() {
            make docker-generate && [ -z "$(git status --porcelain -- '*_bpfel.go' '*_bpfeb.go' '*_bpfel.o' '*_bpfeb.o')" ] || {
                git status --porcelain -- '*_bpfel.go' '*_bpfeb.go' '*_bpfel.o' '*_bpfeb.o'; return 1; }
        }
        run_step "generated eBPF files match the C sources" gen_check
    else
        skip_step "generated eBPF files" "bpf/ C sources changed: run 'make docker-generate' and commit the generated files, or pass --generate"
    fi
    if command -v clang-format >/dev/null; then
        fmt_check() { changed_files "$BASE" 'bpf/*.c' 'bpf/*.h' | grep -v '^bpf/bpfcore/' | xargs -r clang-format --dry-run --Werror; }
        run_step "clang-format of the changed C files" fmt_check
    else
        skip_step "clang-format" "clang-format is not installed here; CI runs it (and clang-tidy)"
    fi
fi
run_step "ebpf library version in sync" make -s check-ebpf-ver-synced

# 2. build, vet, unit tests
run_step "go build" go build $ALL_PKGS
run_step "go vet" go vet $TEST_PKGS
unit_tests() { root_tests_note; go test -short -race -count=1 $TEST_PKGS 2>&1 | grep -v 'no test files' | tail -40; [ "${PIPESTATUS[0]}" = 0 ]; }
run_step "unit tests" unit_tests
if [ "$PRIVILEGED" = 1 ] && [ "$(id -u)" != 0 ]; then
    skip_step "privileged tests" "not root: they run in the lab VMs (build-payload.sh final, lab-matrix.sh); as root they create loop, zram and LVM devices on this host"
elif [ "$PRIVILEGED" = 1 ]; then
    PRIV_PKGS=$(changed_files "$BASE" '*.go' | xargs -r grep -l '//go:build.*privileged_tests' 2>/dev/null | xargs -r -n1 dirname | sort -u | sed 's|^|./|')
    if [ -n "$PRIV_PKGS" ]; then
        priv_tests() { go test -count=1 -tags=privileged_tests $PRIV_PKGS 2>&1 | tail -40; [ "${PIPESTATUS[0]}" = 0 ]; }
        run_step "privileged tests (native kernel $(uname -r))" priv_tests
    else
        skip_step "privileged tests" "no changed package has privileged tests"
    fi
fi

# 3. lint, as CI does on linux and macOS
LINT_PKGS=$TEST_PKGS
lint_linux() { go tool -modfile=internal/tools/go.mod golangci-lint run $LINT_PKGS --timeout=15m 2>&1 | grep -v 'level=warning'; [ "${PIPESTATUS[0]}" = 0 ]; }
run_step "golangci-lint (linux)" lint_linux
if [ "$DARWIN" = 1 ]; then
    lint_darwin() { local bin; bin=$(golangci) || return 1; disk_guard; GOOS=darwin "$bin" run $LINT_PKGS --timeout=15m 2>&1 | grep -v 'level=warning'; [ "${PIPESTATUS[0]}" = 0 ]; }
    run_step "golangci-lint (darwin)" lint_darwin
fi
run_step "vanity imports" make -s vanity-import-check

# 4. repository checks that pull_request.yml runs
run_step "license headers" make -s license-header-check
run_step "go.mod tidy" go mod tidy -diff
if [ -n "$(changed_files "$BASE" 'pkg/config/*' 'pkg/export/feature.go' 'pkg/export/*/config*.go' 'internal/config/*' 'cmd/obi-schema/*' 'cmd/config-docs/*' 'devdocs/config/*' 'cmd/check-config-v2-*/*')" ]; then
    run_step "config schema and docs up to date" make -s check-config-schema
    run_step "config v2 artifacts and parity" make -s check-config-v2-artifacts
fi
if [ -n "$(changed_files "$BASE" 'schemas/*' 'site/*' 'pkg/export/attributes/*')" ]; then
    run_step "telemetry schema lint" make -s lint-schema
    run_step "telemetry schema provenance tests" make -s test-schema
    run_step "published schema files consistent" make -s check-schema-files
    run_step "schema reference docs up to date" make -s check-schema-docs
fi
if [ -n "$(changed_files "$BASE" '*.md')" ]; then
    if make -n lint-markdown >/dev/null 2>&1 && command -v markdownlint-cli2 >/dev/null; then
        run_step "markdown lint" make -s lint-markdown
    else
        skip_step "markdown lint" "markdownlint is not installed here; CI runs it"
    fi
fi

# 5. summary
step "summary"
FAILED=0
for r in "${RESULTS[@]}"; do
    name=${r%|*}; status=${r##*|}
    printf '  %-5s %s\n' "$status" "$name"
    [ "$status" = FAIL ] && FAILED=1
done
if [ "$FAILED" = 1 ]; then
    echo; bold "NOT READY TO PUSH"; exit 1
fi
bold "all steps passed"

# 6. push, only on request
if [ "$PUSH" = 1 ]; then
    remote_gate
    [ -n "$BRANCH" ] || die "detached HEAD: check out the branch to push"
    step "unpushed commits"
    git log --oneline "origin/$BRANCH..HEAD" 2>/dev/null || true
    if git rev-parse -q --verify "origin/$BRANCH" >/dev/null && ! git merge-base --is-ancestor "origin/$BRANCH" HEAD; then
        die "origin/$BRANCH is not an ancestor of HEAD: this push would rewrite history. Merge instead."
    fi
    retry 5 git push -u origin "$BRANCH"
fi
