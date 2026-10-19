#!/usr/bin/env bash
# Write the description of a release: what it is, and what changed since the previous version.
#
#   ./scripts/release-notes.sh 1.0.0 > notes.md
#
# The argument is the tag the VERSION file names. "The previous version" is the nearest version
# tag on version3's first-parent history other than this one, so every rebuild of a version
# lists everything that version has gathered so far, and `latest`, which moves, is never the
# base. With none, it lists the most recent commits instead and says so.
#
# Both releases of a build carry this text, word for word: the version and `latest`.
# release.yml appends what is inside the binaries.
#
# Needs the history and the tags, which a default checkout does not fetch: release.yml checks
# out with fetch-depth 0.
set -euo pipefail

TAG=${1:?usage: release-notes.sh <version>}

REPO=${GITHUB_REPOSITORY:-veil-net/conflux}
SERVER=${GITHUB_SERVER_URL:-https://github.com}
SHA=$(git rev-parse HEAD)

# A version tag is MAJOR.MINOR.PATCH, a suffix allowed. A glob, as git describe takes.
VERSIONS='[0-9]*.[0-9]*.[0-9]*'

# Shown, so the list cannot outgrow the page; the full diff link has the rest. RECENT is how many
# a release with no version behind it shows.
MAX=200
RECENT=20

die() { echo "release-notes: $*" >&2; exit 1; }

[ "$(git rev-parse --is-shallow-repository)" = false ] ||
  die "this is a shallow clone, so the changes since the last version cannot be read; check out with fetch-depth 0"

prev=$(git describe --tags --abbrev=0 --first-parent --match "$VERSIONS" --exclude "$TAG" HEAD 2>/dev/null) || prev=""

# One line per paragraph: a release renders a single newline as a line break.
echo "conflux $TAG, built from \`$SHA\` on \`version3\`, with anchor's newest release build embedded."
echo
printf '%s %s\n' \
  "Published twice, with the same artifacts and this same text: as \`$TAG\`, and as \`latest\`, which moves to every newer build." \
  "A merge that leaves VERSION alone deletes both and releases them again from the commit that landed."
echo

if [ -z "$prev" ]; then
  echo "## Recent changes"
  echo
  echo "No earlier version is behind this commit, so these are the $RECENT most recent commits."
  echo
  git log --no-merges --format='- %s (%h)' -n "$RECENT" HEAD
  exit 0
fi

echo "## Changes since $prev"
echo

# The pull requests the range merged, from version3's own merge commits.
prs=$(git log --first-parent --merges --format=%s "$prev..HEAD" | grep -oE '#[0-9]+' | sort -t'#' -k2 -n -u | paste -sd' ' -) || prs=""
if [ -n "$prs" ]; then
  echo "Pull requests: ${prs// /, }"
  echo
fi

total=$(git rev-list --count --no-merges "$prev..HEAD")
if [ "$total" -eq 0 ]; then
  echo "No commits: this build is of the same tree as $prev."
else
  git log --no-merges --format='- %s (%h)' -n "$MAX" "$prev..HEAD"
  if [ "$total" -gt "$MAX" ]; then
    echo "- … and $((total - MAX)) more"
  fi
fi

echo
echo "Full diff: $SERVER/$REPO/compare/$prev...$TAG"
