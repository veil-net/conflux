#!/usr/bin/env bash
# Put the anchor binaries where //go:embed can find them.
#
# They are not in git: fourteen release builds are about 284 MB, and committing that
# costs it permanently, on every clone, for every refresh. So a build populates
# anchor/bin/ from a local anchor checkout instead.
#
#   make anchor-bins                      from ../anchor
#   make anchor-bins ANCHOR_SRC=/path     from somewhere else
#   make anchor-bins FETCH=1              from the published shelf, no checkout needed
#
# Three sources, in that order of preference. A local release/ is the pinned build and
# wins outright. A local dist/ is the unpinned development cross-build and is taken
# loudly. With neither, FETCH=1 downloads the pinned binaries from the shelf and
# verifies every digest -- which is what lets CI, and a fresh clone, have the real ones
# without a checkout and without a credential.
#
# With no source at all it writes placeholders, which is what lets gofmt, vet,
# staticcheck and the unit tests run on a machine with no access to any of the above. A
# conflux built from placeholders compiles, reports that it carries no anchor binaries,
# and is caught by the size gate in `make dist` -- it cannot be mistaken for a
# shippable build.
set -euo pipefail

ANCHOR_SRC=${ANCHOR_SRC:-../anchor}
DEST=${DEST:-anchor/bin}

# Opt-in rather than automatic, for now. Every macOS and Windows CI job runs this and
# needs only the two files its own build tag names, so fetching all fourteen there
# would move 284 MB to compile 43. Once the shelf serves every target and the per-target
# narrowing exists, this default is one line to flip.
FETCH=${FETCH:-0}
SHELF_URL=${SHELF_URL:-}

TARGETS="linux-amd64 linux-arm64 darwin-arm64 windows-amd64 windows-arm64 freebsd-amd64 openbsd-amd64"

# Two binaries per target. Counted rather than typed, so dropping a target from the
# line above does not leave three messages below claiming a number that is now wrong.
TOTAL=$(( $(echo $TARGETS | wc -w) * 2 ))

mkdir -p "$DEST"

# Clear anything that is not one of the $TOTAL before writing. Dropping a target
# otherwise leaves its binaries behind in a directory every file of which is a
# candidate for being embedded -- and a stale one is a real binary of the right size,
# so neither the size gate nor the header check would say a word about it.
want=""
for t in $TARGETS; do
  ext=""; case "$t" in windows-*) ext=".exe" ;; esac
  for p in anchord anchorctl; do
    want="$want $p-$t$ext"
  done
done
for f in "$DEST"/*; do
  [ -e "$f" ] || continue
  case " $want " in
    *" $(basename "$f") "*) ;;
    *) echo "anchor-bins: removing $(basename "$f") -- not a target" >&2; rm -f "$f" ;;
  esac
done

# release/ is the pinned, garbled build users get. dist/ is the unpinned development
# cross-build, which joins any tree and is wrong for anything shipped -- so it is
# accepted, and loudly.
src=""
kind=""
for candidate in release dist; do
  if [ -d "$ANCHOR_SRC/$candidate" ] && [ -n "$(ls -A "$ANCHOR_SRC/$candidate" 2>/dev/null)" ]; then
    src="$ANCHOR_SRC/$candidate"
    kind="$candidate"
    break
  fi
done

placeholder() {
  cat <<'EOF'
conflux: no anchor binaries, and this file is a placeholder so the module compiles.
Run `make anchor-bins ANCHOR_SRC=/path/to/anchor` with a real checkout to replace it.
EOF
}

# No local build, so try the shelf before giving up. `go run` rather than curl: this
# repository's one stated dependency is Go, and a fresh clone should not have to acquire
# a JSON parser to become buildable. The fetcher imports nothing that embeds anything,
# so it still runs when anchor/bin is empty -- which is the only moment it is wanted.
if [ -z "$src" ] && [ "$FETCH" = 1 ]; then
  echo "anchor-bins: no local anchor build; fetching the pinned binaries from the shelf" >&2

  args=""
  [ -n "$SHELF_URL" ] && args="-url $SHELF_URL"

  # $want is the same list the prune above is built from, so there is one definition of
  # what belongs here rather than two that can disagree.
  if go run ./cmd/anchor-fetch $args -dest "$DEST" -want "$(echo $want | tr ' ' ',')"; then
    echo "anchor-bins: $TOTAL/$TOTAL fetched from the shelf (pinned release build)"
    exit 0
  fi

  echo "anchor-bins: the fetch failed; falling back to placeholders" >&2
fi

if [ -z "$src" ]; then
  echo "anchor-bins: no anchor build found under $ANCHOR_SRC (looked for release/ and dist/)" >&2
  echo "anchor-bins: writing placeholders -- this build will NOT produce a working conflux" >&2
  for t in $TARGETS; do
    ext=""; case "$t" in windows-*) ext=".exe" ;; esac
    for p in anchord anchorctl; do
      placeholder > "$DEST/$p-$t$ext"
    done
  done
  echo "anchor-bins: $TOTAL placeholders written to $DEST"
  exit 0
fi

if [ "$kind" = dist ]; then
  echo "anchor-bins: using $src, which is an UNPINNED development build." >&2
  echo "anchor-bins: it will join any realm tree. Do not ship a conflux built from it." >&2
fi

missing=0
copied=0

for t in $TARGETS; do
  ext=""; case "$t" in windows-*) ext=".exe" ;; esac
  for p in anchord anchorctl; do
    from="$src/$p-$t$ext"
    if [ ! -f "$from" ]; then
      echo "anchor-bins: missing $from" >&2
      missing=1
      continue
    fi
    cp -f "$from" "$DEST/$p-$t$ext"
    chmod 0755 "$DEST/$p-$t$ext"
    copied=$((copied + 1))
  done
done

# anchoradmin can mint realm roots. It lives beside the other two in release/ and
# must never be copied here, because anything in this directory is a candidate for
# being embedded into every conflux a user runs.
rm -f "$DEST"/anchoradmin-* 2>/dev/null || true

if [ "$missing" != 0 ]; then
  echo "anchor-bins: $copied of $TOTAL copied; the rest are missing from $src" >&2
  echo "anchor-bins: build them with 'make release' (pinned) or 'make dist' in the anchor repo" >&2
  exit 1
fi

echo "anchor-bins: $copied/$TOTAL copied from $src ($kind)"
