#!/usr/bin/env bash
# sync-upstream.sh: keep the feature branch current with upstream main, by merge, never rebase.
#
#   sync-upstream.sh            fetch upstream main and report what the branch is missing
#   sync-upstream.sh --merge    also merge upstream/main into the current branch (clean tree only)
#   sync-upstream.sh --merge --push   and push the merge to the fork after the gate passes
#
# A merge that conflicts is aborted and the conflicting files are listed, so a human resolves it
# (git merge upstream/main, fix, make docker-generate if generated files conflict, commit).
# The merge commit is authored as TheDwingMAN. After a merge, pre-push.sh --full is run.
set -u
. "$(dirname "$0")/common.sh"

MERGE=0; PUSH=0
while [ $# -gt 0 ]; do
    case "$1" in
        --merge) MERGE=1; shift ;;
        --push) PUSH=1; shift ;;
        *) die "unknown option $1" ;;
    esac
done

cd "$REPO" || exit 1
BRANCH=$(git branch --show-current)
[ -n "$BRANCH" ] || die "detached HEAD"

step "fetching upstream main"
retry 5 git fetch -q upstream main || die "can't fetch upstream"
BEHIND=$(git rev-list --count "HEAD..upstream/main")
AHEAD=$(git rev-list --count "upstream/main..HEAD")
note "$BRANCH is $AHEAD commits ahead of and $BEHIND behind upstream/main ($(git rev-parse --short upstream/main))"
if [ "$BEHIND" = 0 ]; then bold "up to date"; exit 0; fi

step "upstream commits not in $BRANCH"
git log --format='  %h %s' "HEAD..upstream/main"
step "files they touch that the branch also touches (conflict candidates)"
comm -12 <(git diff --name-only "$(git merge-base HEAD upstream/main)..upstream/main" | sort) \
         <(git diff --name-only "$(git merge-base HEAD upstream/main)..HEAD" | sort) | sed 's/^/  /'
if git diff --name-only "$(git merge-base HEAD upstream/main)..upstream/main" | grep -qE '_bpfe[lb]\.(go|o)$|^bpf/'; then
    note "upstream changed eBPF sources or generated files: after merging, run 'make docker-generate' and commit the result"
fi

[ "$MERGE" = 1 ] || { echo; note "run with --merge to merge"; exit 0; }

[ -z "$(git status --porcelain)" ] || die "working tree not clean: commit or stash first (git stash list shows stashes)"
step "merging upstream/main into $BRANCH"
if ! git -c user.name="$GIT_AUTHOR_NAME_LOOP" -c user.email="$GIT_AUTHOR_EMAIL_LOOP" \
        merge --no-ff --no-edit -m "Merge upstream main ($(git rev-parse --short upstream/main)) into $BRANCH" upstream/main; then
    step "conflicts"
    git diff --name-only --diff-filter=U | sed 's/^/  /'
    git merge --abort
    die "merge aborted: resolve it by hand (git merge upstream/main), then rerun pre-push.sh --full"
fi
git log --oneline -1

step "validating the merge"
if "$WS/devloop/pre-push.sh" --full $([ "$PUSH" = 1 ] && echo --push); then
    bold "merge validated$([ "$PUSH" = 1 ] && echo ' and pushed')"
else
    die "the merge fails validation: fix on top of it (don't rewrite it), then pre-push.sh --full --push"
fi
