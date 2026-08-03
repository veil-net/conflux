#!/bin/bash
set -euo pipefail

mkdir -p bin

GARBLE_FLAGS=(-literals -tiny)
BUILD_FLAGS=(-ldflags="-s -w" -trimpath)

TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
  "windows/arm64"
  "darwin/arm64"
  "darwin/amd64"
)

total=${#TARGETS[@]}
i=0

for target in "${TARGETS[@]}"; do
  i=$((i + 1))
  IFS='/' read -r GOOS GOARCH <<< "$target"

  out="bin/conflux-${GOOS}-${GOARCH}"
  if [ "$GOOS" = "windows" ]; then
    out="${out}.exe"
  fi

  echo "[$i/$total] Building $GOOS/$GOARCH → $out"
  GOOS="$GOOS" GOARCH="$GOARCH" garble "${GARBLE_FLAGS[@]}" build "${BUILD_FLAGS[@]}" -o "$out" .
  echo "[$i/$total] Done $GOOS/$GOARCH"
done

echo "Build complete! Binaries are in bin/"
