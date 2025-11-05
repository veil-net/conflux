#!/bin/bash

# VeilNet Daemon Build Script
# Builds for all major platforms and architectures

set -e

BUILD_DIR="build"

# Clean build directory
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

echo "Building VeilNet Conflux..."

# Build for all platforms
echo "Building for Linux AMD64..."
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o $BUILD_DIR/veilnet-conflux .

echo "Building for Linux ARM64..."
GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o $BUILD_DIR/veilnet-conflux-arm64 .

echo "Building for macOS AMD64..."
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o $BUILD_DIR/veilnet-conflux-darwin-amd64 .

echo "Building for macOS ARM64..."
GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w" -o $BUILD_DIR/veilnet-conflux-darwin-arm64 .

echo "Building for Windows AMD64..."
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o $BUILD_DIR/veilnet-conflux.exe .

echo "Building for Windows ARM64..."
GOOS=windows GOARCH=arm64 go build -ldflags "-s -w" -o $BUILD_DIR/veilnet-conflux-arm64.exe .

echo "Build completed! Files in $BUILD_DIR/"
ls -lh $BUILD_DIR/

echo "Building container image..."
go build -ldflags "-s -w" -o veilnet-conflux
docker compose down
docker compose build