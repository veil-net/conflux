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
#   - A pull request's head is a branch of this repository, and its branch is tested by pushing
#     it here. The guard is the repository's setting that a fork's run from outside the
#     organisation and its collaborators waits for a maintainer's approval, which is never
#     given (docs/testing.md, "A fork's pull request from anyone outside the organisation and
#     its collaborators"). This refusal is a second line, for a run approved by mistake: a
#     fork's pull request runs its own copy of this file, so a member's or a collaborator's
#     fork, which runs unapproved, can edit the refusal out.
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

[ "$HEAD_REPO" = "$REPO" ] ||
  die "this pull request is from $HEAD_REPO, a fork, for which CI runs nothing, so none of it is tested. Push the branch here to test it, and open its pull request from there."

case "$BASE" in
  "$RELEASE")
    [ "$HEAD_REF" = dev ] ||
      die "$RELEASE takes dev and nothing else, and this pull request is from $HEAD_REF. Open it against dev; $RELEASE is released from dev by its own pull request."
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
