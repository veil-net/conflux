#!/usr/bin/env bash
# Write the description of a release: what it is, and a summary of what changed since the
# previous version.
#
#   GH_TOKEN=… ./scripts/release-notes.sh 1.0.0 > notes.md
#   GH_TOKEN=… BRANCH=dev ./scripts/release-notes.sh 1.0.0 > notes.md
#
# The argument is the version the VERSION file names. BRANCH is the branch built: version3, the
# release, unless it says dev, whose builds are the pre-release `dev-latest`.
#
# "The previous version" is the nearest version tag behind HEAD. On version3 it is found along
# version3's own first parent, other than this one, so every rebuild of a version summarises
# everything that version has gathered so far; on dev along any parent, since release.yml merges
# version3 back into dev after a release and that merge may not be dev's first parent. Neither
# `latest` nor `dev-latest`, which move, is ever the base. With none, it summarises the most recent
# pull requests instead and says so.
#
# What changed is what dev merged. Every change reaches version3 through dev, so a release is a
# merge of dev, and version3's own first parent holds nothing but such merges: the notes walk the
# dev side of it, its second parent, and list the pull requests dev merged since the previous
# version. A dev build walks dev's own history the same way, so the two read alike.
#
# A summary, not a commit log. Each pull request is its title and the opening paragraph of its
# description, which is where a pull request says what it does; a commit pushed to the branch on
# its own, with no pull request to speak for it, is its subject line, and a merge that is no pull
# request's -- version3 merged back into dev -- is nothing. Titles and descriptions come from the
# API, with GH_TOKEN if it is set. Where the API answers nothing, a pull request is its title
# alone, as its merge commit records it, and the notes are still written.
#
# Every release of a build carries this text, word for word: on version3 the version and
# `latest`. release.yml appends how to install it and what is inside the binaries.
#
# Needs the history and the tags, which a default checkout does not fetch: release.yml checks
# out with fetch-depth 0.
set -euo pipefail

TAG=${1:?usage: release-notes.sh <version>}
BRANCH=${BRANCH:-version3}

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

case "$BRANCH" in
  version3 | dev) ;;
  *) die "BRANCH is \"$BRANCH\"; a release is built from version3 or dev" ;;
esac

if [ "$BRANCH" = version3 ]; then
  prev=$(git describe --tags --abbrev=0 --first-parent --match "$VERSIONS" --exclude "$TAG" HEAD 2>/dev/null) || prev=""
else
  prev=$(git describe --tags --abbrev=0 --match "$VERSIONS" HEAD 2>/dev/null) || prev=""
fi

# The history the changes are read from: on version3, the dev side of the merge that released
# it, where there is one; otherwise the branch's own.
walk=HEAD
if [ "$BRANCH" = version3 ] && git rev-parse -q --verify 'HEAD^2' >/dev/null; then
  walk='HEAD^2'
fi

# What the links name, and whose anchor is inside: a version's tag and anchor's release, or a
# dev build's commit and anchor's dev build.
ref=$TAG anchor="anchor's newest release build"
if [ "$BRANCH" = dev ]; then
  ref=$SHA anchor="anchor's newest dev build, \`dev-latest\`,"
fi

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

echo "conflux $TAG, built from \`$SHA\` on \`$BRANCH\`, with $anchor embedded."
echo
if [ "$BRANCH" = dev ]; then
  echo "A dev build: the pre-release at \`dev-latest\`, which the next merge into dev replaces. A release is \`latest\`."
  echo
fi

if [ -n "$prev" ]; then
  range="$prev..$walk"
  echo "## Changes since $prev"
else
  range=$walk
  echo "## Recent changes"
  echo
  echo "No earlier version is behind this commit, so these are the most recent pull requests."
fi

# dev's history, newest first: its merge commits are the pull requests, a merge that is no pull
# request's is version3 merged back after a release, and anything else was pushed there directly,
# which only a range with a version behind it lists. One refusal from the API and it is not asked
# again.
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
  elif [ -n "$prev" ] && [[ $parents != *' '* ]]; then
    direct+=("- $subject (${hash:0:7})")
  fi
done < <(git log --first-parent --format='%H%x09%P%x09%s' "$range")

# And on version3, anything pushed to it directly since the previous version, beside the merges
# of dev: nothing should be, and a release that carries one says so.
if [ "$walk" != HEAD ] && [ -n "$prev" ]; then
  while IFS=$'\t' read -r hash subject; do
    direct+=("- $subject (${hash:0:7}, on version3)")
  done < <(git log --first-parent --no-merges --format='%H%x09%s' "$prev..HEAD^")
fi

if [ "$prs" -gt "$MAX" ]; then
  echo
  echo "… and $((prs - MAX)) earlier pull requests."
fi

if [ "${#direct[@]}" -gt 0 ]; then
  echo
  echo "### Pushed to $BRANCH directly"
  echo
  printf '%s\n' "${direct[@]:0:MAX}"
  [ "${#direct[@]}" -le "$MAX" ] || echo "- … and $((${#direct[@]} - MAX)) more"
fi

echo
if [ -n "$prev" ]; then
  echo "Full diff: $SERVER/$REPO/compare/$prev...$ref"
else
  echo "History: $SERVER/$REPO/commits/$ref"
fi
