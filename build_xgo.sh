#!/bin/bash

# Build script using xgo to cross-compile with prefix "anchor" into bin folder
# Usage: ./build_xgo.sh [targets]
# If no targets specified, builds for common platforms

# Create bin directory if it doesn't exist
mkdir -p bin

# Default targets if none specified
if [ $# -eq 0 ]; then
    TARGETS=(
        "linux/amd64"
        "linux/arm64"
        "windows/amd64"
        "windows/arm64"
        "darwin/amd64"
        "darwin/arm64"
    )
else
    TARGETS=("$@")
fi

# Check if xgo is installed
if ! command -v xgo &> /dev/null; then
    echo "xgo is not installed. Installing..."
    go install github.com/crazy-max/xgo@latest
fi

# Build for each target
for target in "${TARGETS[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$target"
    
    echo "Building for $GOOS/$GOARCH..."
    
    if ! xgo \
        -out conflux \
        -dest bin \
        -go latest \
        -ldflags "-s -w" \
        -trimpath \
        -targets "$target" \
        .; then
        echo "Error building for $GOOS/$GOARCH"
        exit 1
    fi
done

echo "Build complete! Binaries are in the bin/ directory."
