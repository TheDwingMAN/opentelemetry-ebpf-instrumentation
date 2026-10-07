#!/usr/bin/env bash
# ci-status.sh [<sha|branch>]: read-only summary of the GitHub check runs of a commit on the fork.
# Default: the current HEAD. Exit 1 when any check failed. Never writes to GitHub.
set -u
. "$(dirname "$0")/common.sh"

REF=${1:-$(git -C "$REPO" rev-parse HEAD)}
SHA=$(git -C "$REPO" rev-parse "$REF" 2>/dev/null || echo "$REF")
REPO_SLUG="$FORK_OWNER/$(basename "$(git -C "$REPO" remote get-url origin)" .git)"

step "check runs on $REPO_SLUG @ ${SHA:0:9}"
JSON=$(gh api "repos/$REPO_SLUG/commits/$SHA/check-runs?per_page=100" 2>/dev/null) || die "gh api failed (GitHub access or network)"
echo "$JSON" | jq -r '.check_runs[] | "\(.conclusion // .status)\t\(.name)"' | sort | awk -F'\t' '{c[$1]++} END {for (k in c) printf "  %-12s %d\n", k, c[k]}'
FAILS=$(echo "$JSON" | jq -r '.check_runs[] | select(.conclusion=="failure" or .conclusion=="timed_out" or .conclusion=="cancelled") | "  \(.conclusion)\t\(.name)\t\(.details_url)"')
if [ -n "$FAILS" ]; then
    step "not green"
    echo "$FAILS"
    note "logs: the GitHub MCP get_job_logs tool reads them; re-runs need the user's approval"
    exit 1
fi
PENDING=$(echo "$JSON" | jq -r '.check_runs[] | select(.status!="completed") | .name' | wc -l)
[ "$PENDING" = 0 ] && bold "all green" || note "$PENDING checks still running"
