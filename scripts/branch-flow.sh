#!/usr/bin/env bash
#
# Say whether a pull request goes where this repository's branches allow, from where it may.
#
#   BASE=dev HEAD_REF=feature/x HEAD_REPO=veil-net/conflux REPO=veil-net/conflux RELEASE=version3 \
#     ./scripts/branch-flow.sh
#
# Run by branch-flow.yml in a pull request's checkout, whose HEAD is the pull request merged into
# its base. The branches (docs/testing.md, "Branches"):
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

: "${BASE:?}" "${HEAD_REF:?}" "${HEAD_REPO:?}" "${REPO:?}" "${RELEASE:?}"

die() { echo "::error::branch-flow: $*" >&2; exit 1; }

case "$BASE" in
  "$RELEASE")
    [ "$HEAD_REF" = dev ] && [ "$HEAD_REPO" = "$REPO" ] ||
      die "$RELEASE takes dev and nothing else, and this pull request is from $HEAD_REPO:$HEAD_REF. Open it against dev; $RELEASE is released from dev by its own pull request."
    echo "branch-flow: dev into $RELEASE, a release"
    ;;
  dev)
    git rev-parse -q --verify "refs/remotes/origin/$RELEASE" >/dev/null ||
      git fetch -q --no-tags origin "+refs/heads/$RELEASE:refs/remotes/origin/$RELEASE"
    git merge-base --is-ancestor "origin/$RELEASE" HEAD ||
      die "dev is behind $RELEASE: $RELEASE holds a commit dev does not, so the last release was not merged back into dev. Merge $RELEASE into dev, by pull request, before this one."
    echo "branch-flow: $HEAD_REF into dev, which holds $RELEASE"
    ;;
  *)
    die "a pull request goes into dev, and this one goes into $BASE. Retarget it to dev."
    ;;
esac
