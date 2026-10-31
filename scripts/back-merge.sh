#!/usr/bin/env bash
#
# Merge a release back into dev, so dev stays ahead of version3, the branch it releases to.
#
#   ./scripts/back-merge.sh <the release's commit>
#
# Run by release.yml after a release of version3 is published, in a checkout of dev with its
# history.
# A release is a merge of dev, so dev's tip is that merge's second parent and dev fast-forwards to
# it; where dev has merged something since, the release is merged into it instead. A dev that
# already holds the commit is left alone. Then dev is pushed.
#
# A merge that will not go cleanly is a release that holds something dev does not, pushed to
# version3 directly: that is for a person to resolve, so this stops and says so rather than
# guessing.
set -euo pipefail

SHA=${1:?usage: back-merge.sh <commit>}

die() { echo "::error::back-merge: $*" >&2; exit 1; }

git rev-parse -q --verify "$SHA^{commit}" >/dev/null || die "$SHA is not a commit in this checkout"

if git merge-base --is-ancestor "$SHA" HEAD; then
  echo "back-merge: dev already holds $SHA"
  exit 0
fi

git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'

if git merge --ff-only "$SHA" 2>/dev/null; then
  echo "back-merge: dev fast-forwarded to $SHA"
else
  git merge --no-edit -m "Merge the release $SHA back into dev" "$SHA" ||
    die "the release $SHA does not merge cleanly into dev: something was pushed to version3 that dev does not hold. Merge version3 into dev by hand, by pull request."
  echo "back-merge: merged $SHA into dev"
fi

git push origin HEAD:refs/heads/dev ||
  die "dev refused the push. Its protection must let this workflow push to it (docs/testing.md, \"Branches\"); until then, merge version3 into dev by hand, by pull request."
