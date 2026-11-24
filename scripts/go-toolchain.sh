#!/usr/bin/env bash
#
# Put the Go toolchain go.mod names in DIR, downloaded from go.dev and held to the SHA-256 go.dev
# publishes for it, and print its GOROOT.
#
#   ./scripts/go-toolchain.sh DIR
#
# For the release, which builds on a machine that outlives its jobs (release.yml). setup-go takes
# a toolchain the runner's tool cache holds already, and there any earlier job could have changed
# it: the compiler, the standard library, and the Go Cryptographic Module a build compiles in
# (GOFIPS140, lib/fips140 in the toolchain). So the release takes none of it from there: DIR is
# under the job's temporary directory, which the runner empties before and after every job. The
# version is the one setup-go reads from go.mod, its toolchain line or else its go line. Linux, on
# amd64 or arm64.
set -euo pipefail

dir=${1:?usage: scripts/go-toolchain.sh DIR}

die() { echo "::error::go-toolchain: $*" >&2; exit 1; }

version=$(sed -n 's/^toolchain go\([^[:space:]]*\).*/\1/p' go.mod)
[ -n "$version" ] || version=$(sed -n 's/^go \([^[:space:]]*\).*/\1/p' go.mod)
[ -n "$version" ] || die "go.mod names no Go version"

case $(uname -m) in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "there is no Go release for $(uname -m) here" ;;
esac
file=go$version.linux-$arch.tar.gz

[ ! -e "$dir/go" ] || die "$dir/go is there already, and the toolchain goes where nothing is"

# go.dev's list of every release's files, each an object of its own carrying its sha256: the one
# whose filename is this file is the one read. Whitespace is dropped first, which nothing in it
# holds, so the list is read whatever its layout.
list=$(curl -fsSL --proto '=https' --tlsv1.2 'https://go.dev/dl/?mode=json&include=all') ||
  die "could not read go.dev's list of Go releases"
entry=$(printf '%s' "$list" | tr -d ' \t\r\n' | grep -oE "\{[^{}]*\"filename\":\"${file//./\\.}\"[^{}]*\}") ||
  die "go.dev lists no $file"
want=$(printf '%s\n' "$entry" | grep -oE '"sha256":"[0-9a-f]{64}"' | cut -d'"' -f4) || want=""
case $want in
  "" | *[!0-9a-f]*) die "go.dev does not give $file one SHA-256: $entry" ;;
esac

mkdir -p "$dir"
curl -fsSL --proto '=https' --tlsv1.2 -o "$dir/$file" "https://go.dev/dl/$file" ||
  die "could not download https://go.dev/dl/$file"
got=$(sha256sum "$dir/$file" | cut -d' ' -f1)
[ "$got" = "$want" ] || die "$file's SHA-256 is $got, and go.dev publishes $want, so it is not used"

tar -xzf "$dir/$file" -C "$dir"
rm -f "$dir/$file"

said=$(GOTOOLCHAIN=local "$dir/go/bin/go" env GOVERSION) || die "the go in $file does not run here"
[ "$said" = "go$version" ] || die "the go in $file says it is $said, not go$version"

echo "go$version from go.dev, its SHA-256 $want go.dev's own, in $dir/go" >&2
echo "$dir/go"
