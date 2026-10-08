#!/usr/bin/env bash
# commit.sh <message-file> [go packages...]: commit what is staged, as TheDwingMAN, after testing
# the staged content alone.
#
# Stage first with git add -p (stage_hunks.py <file> <marker>... stages the hunks that contain a
# marker). The unstaged rest is stashed while the build, vet and tests run, then restored. Files
# that must never be committed by this loop are refused.
set -u
. "$(dirname "$0")/common.sh"

[ $# -ge 1 ] || { sed -n '2,8p' "$0"; exit 2; }
MSG=$1; shift
PKGS=${*:-./pkg/... ./cmd/... ./internal/...}
cd "$REPO" || exit 1
[ -f "$MSG" ] || die "message file $MSG not found"
grep -qiE 'co-authored-by: *claude|claude-session|claude (opus|sonnet|fable|haiku)' "$MSG" && die "the message carries a Claude trailer or model name: remove it"

step "git status"
git status --short
STAGED=$(git diff --cached --name-only)
[ -n "$STAGED" ] || die "nothing staged"
step "staged files"
echo "$STAGED" | sed 's/^/  /'
echo "$STAGED" | grep -E '^(CLAUDE\.md|AGENTS\.md|AI-POLICY\.md|\.claude/)' && die "repository policy files are staged: unstage them"
echo "$STAGED" | grep -E '^bpf/bpfcore/' && die "bpf/bpfcore files are staged: they are generated, never edited"

disk_guard
step "testing the staged content alone (the rest is stashed meanwhile)"
# refs/stash is shared by all the worktrees of the repository: name our entry and pop that one,
# so that a commit.sh running in another worktree at the same time never pops it, nor we theirs
tag="commit.sh $$ $(date +%s%N)"
git stash push --keep-index --include-untracked -q -m "$tag" || die "can't stash"
ok=1
go build ./pkg/... ./cmd/... ./internal/... || ok=0
# shellcheck disable=SC2086
[ $ok = 1 ] && { go vet $PKGS || ok=0; }
# shellcheck disable=SC2086
[ $ok = 1 ] && { root_tests_note; go test -count=1 $PKGS 2>&1 | grep -v 'no test files' | tail -20; [ "${PIPESTATUS[0]}" = 0 ] || ok=0; }
entry=$(git stash list --format='%gd %gs' | awk -v t="$tag" 'index($0, t) {print $1; exit}')
if [ -n "$entry" ]; then
    git stash pop -q "$entry" || die "STASH POP FAILED: the unstaged changes are in $entry ($tag)"
fi
[ $ok = 1 ] || die "the staged content fails: not committing"

git -c user.name="$GIT_AUTHOR_NAME_LOOP" -c user.email="$GIT_AUTHOR_EMAIL_LOOP" commit -q -F "$MSG" || die "commit failed"
git log --format='  %h %an <%ae>%n  %s' -1
