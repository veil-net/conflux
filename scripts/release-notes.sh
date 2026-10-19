#!/usr/bin/env bash
# Write the description of a release: what it is, and a summary of what changed since the
# previous version.
#
#   GH_TOKEN=… ./scripts/release-notes.sh 1.0.0 > notes.md
#
# The argument is the tag the VERSION file names. "The previous version" is the nearest version
# tag on version3's first-parent history other than this one, so every rebuild of a version
# summarises everything that version has gathered so far, and `latest`, which moves, is never the
# base. With none, it summarises the most recent pull requests instead and says so.
#
# A summary, not a commit log. Each pull request version3 merged is its title and the opening
# paragraph of its description, which is where a pull request says what it does; a commit pushed
# to version3 on its own, with no pull request to speak for it, is its subject line. Titles and
# descriptions come from the API, with GH_TOKEN if it is set. Where the API answers nothing, a
# pull request is its title alone, as its merge commit records it, and the notes are still
# written.
#
# Both releases of a build carry this text, word for word: the version and `latest`.
# release.yml appends how to install it and what is inside the binaries.
#
# Needs the history and the tags, which a default checkout does not fetch: release.yml checks
# out with fetch-depth 0.
set -euo pipefail

TAG=${1:?usage: release-notes.sh <version>}

REPO=${GITHUB_REPOSITORY:-veil-net/conflux}
SERVER=${GITHUB_SERVER_URL:-https://github.com}
API=${GITHUB_API_URL:-https://api.github.com}
SHA=$(git rev-parse HEAD)

# A version tag is MAJOR.MINOR.PATCH, a suffix allowed. A glob, as git describe takes.
VERSIONS='[0-9]*.[0-9]*.[0-9]*'

# Pull requests summarised, newest first, and as many direct commits; the full diff has the rest.
MAX=20

die() { echo "release-notes: $*" >&2; exit 1; }

[ "$(git rev-parse --is-shallow-repository)" = false ] ||
  die "this is a shallow clone, so the changes since the last version cannot be read; check out with fetch-depth 0"

prev=$(git describe --tags --abbrev=0 --first-parent --match "$VERSIONS" --exclude "$TAG" HEAD 2>/dev/null) || prev=""

# summary prints pull request $1's title, then the opening paragraph of its description: its
# first block of text that is not a heading. A list keeps its lines; anything else becomes one
# line, since a release renders a single newline as a line break.
summary() {
  local auth=() doc
  [ -z "${GH_TOKEN:-}" ] || auth=(-H "Authorization: Bearer $GH_TOKEN")

  doc=$(curl -fsS --max-time 20 "${auth[@]}" \
    -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
    "$API/repos/$REPO/pulls/$1") || return 1

  python3 -c '
import json, re, sys

pr = json.loads(sys.argv[1])
print(pr["title"].strip())

body = re.sub(r"<!--.*?-->", "", pr.get("body") or "", flags=re.S).replace("\r\n", "\n")
for block in re.split(r"\n[ \t]*\n", body):
    lines = [l.rstrip() for l in block.split("\n") if l.strip() and not l.lstrip().startswith("#")]
    if not lines or lines[0].lstrip().startswith("```"):
        continue
    if re.match(r"\s*([-*+]|\d+[.)])\s", lines[0]):
        print("\n".join(lines))
    else:
        print(" ".join(l.strip() for l in lines))
    break
' "$doc"
}

echo "conflux $TAG, built from \`$SHA\` on \`version3\`, with anchor's newest release build embedded."
echo

if [ -n "$prev" ]; then
  range="$prev..HEAD"
  echo "## Changes since $prev"
else
  range=HEAD
  echo "## Recent changes"
  echo
  echo "No earlier version is behind this commit, so these are the most recent pull requests."
fi

# version3's own history, newest first: its merge commits are the pull requests, and anything else
# on it was pushed there directly, which only a range with a version behind it lists. One refusal
# from the API and it is not asked again.
prs=0 direct=() api=1
while IFS=$'\t' read -r hash parents subject; do
  if [[ $parents == *' '* && $subject =~ ^Merge\ pull\ request\ \#([0-9]+)(.*)$ ]]; then
    n=${BASH_REMATCH[1]} rest=${BASH_REMATCH[2]}
    prs=$((prs + 1))
    [ "$prs" -le "$MAX" ] || continue

    # GitHub's own merge message is "Merge pull request #N from owner/branch", with the title
    # as the body's first line; a message written by hand may carry it after "#N: " instead.
    if [[ $rest == ' from '* ]]; then
      title=$(git log -1 --format=%b "$hash" | sed -n '/[^[:space:]]/{p;q;}')
    else
      title=${rest#:}
      title=${title# }
    fi
    text=""

    if [ "$api" = 1 ]; then
      if out=$(summary "$n"); then
        title=${out%%$'\n'*}
        [[ $out != *$'\n'* ]] || text=${out#*$'\n'}
      else
        echo "release-notes: the API did not answer for #$n, so each pull request is its title alone" >&2
        api=0
      fi
    fi

    echo
    echo "### ${title:-Pull request #$n} (#$n)"
    if [ -n "$text" ]; then
      echo
      echo "$text"
    fi
  elif [ -n "$prev" ]; then
    direct+=("- $subject (${hash:0:7})")
  fi
done < <(git log --first-parent --format='%H%x09%P%x09%s' "$range")

if [ "$prs" -gt "$MAX" ]; then
  echo
  echo "… and $((prs - MAX)) earlier pull requests."
fi

if [ "${#direct[@]}" -gt 0 ]; then
  echo
  echo "### Pushed to version3 directly"
  echo
  printf '%s\n' "${direct[@]:0:MAX}"
  [ "${#direct[@]}" -le "$MAX" ] || echo "- … and $((${#direct[@]} - MAX)) more"
fi

echo
if [ -n "$prev" ]; then
  echo "Full diff: $SERVER/$REPO/compare/$prev...$TAG"
else
  echo "History: $SERVER/$REPO/commits/$TAG"
fi
