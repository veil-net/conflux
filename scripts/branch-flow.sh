#!/usr/bin/env bash
#
# Say whether a pull request goes where this repository's branches allow, from where it may.
#
#   BASE=dev HEAD_REF=feature/x HEAD_REPO=veil-net/conflux HEAD_SHA=<its head commit> \
#     REPO=veil-net/conflux RELEASE=version3 ./scripts/branch-flow.sh
#
# Run by branch-flow.yml on pull_request_target, in a checkout of the base branch: this is the
# base's own copy, and nothing of the pull request is checked out, built or run. Its head commit,
# HEAD_SHA, is fetched as data for git to compare: a commit is in the pull request's merge exactly
# when it is in the base or in the head, so the merge is judged without being made. The branches
# (docs/testing.md, "Branches"):
#
#   - Work goes into dev, and only into dev: a feature or maintenance branch is cut from dev and
#     its pull request is opened against it.
#   - RELEASE takes dev and nothing else: its pull request's head is this repository's dev.
#   - dev stays ahead of RELEASE: release.yml merges every release back into dev, and a pull
#     request into dev whose merge does not hold RELEASE's tip says that back-merge did not land.
#
# Each refusal names what to do instead. Fails, rather than skips, on every other base: a skipped
# required check counts as passing.
set -euo pipefail

: "${BASE:?}" "${HEAD_REF:?}" "${HEAD_REPO:?}" "${HEAD_SHA:?}" "${REPO:?}" "${RELEASE:?}"

die() { echo "::error::branch-flow: $*" >&2; exit 1; }

case "$BASE" in
  "$RELEASE")
    [ "$HEAD_REF" = dev ] && [ "$HEAD_REPO" = "$REPO" ] ||
      die "$RELEASE takes dev and nothing else, and this pull request is from $HEAD_REPO:$HEAD_REF. Open it against dev; $RELEASE is released from dev by its own pull request."
    echo "branch-flow: dev into $RELEASE, a release"
    ;;
  dev)
    [[ $HEAD_SHA =~ ^[0-9a-f]{40}$ ]] || die "HEAD_SHA is \"$HEAD_SHA\", which names no commit"
    git rev-parse -q --verify "refs/remotes/origin/$RELEASE" >/dev/null ||
      git fetch -q --no-tags origin "+refs/heads/$RELEASE:refs/remotes/origin/$RELEASE"
    # The head's objects, for the comparison below: fetched, and never checked out.
    git cat-file -e "$HEAD_SHA^{commit}" 2>/dev/null || git fetch -q --no-tags origin "$HEAD_SHA"
    git merge-base --is-ancestor "origin/$RELEASE" HEAD ||
      git merge-base --is-ancestor "origin/$RELEASE" "$HEAD_SHA" ||
      die "dev is behind $RELEASE: $RELEASE holds a commit dev does not, so the last release was not merged back into dev. Merge $RELEASE into dev, by pull request, before this one."
    echo "branch-flow: $HEAD_REF into dev, which holds $RELEASE"
    ;;
  *)
    die "a pull request goes into dev, and this one goes into $BASE. Retarget it to dev."
    ;;
esac
