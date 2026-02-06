#!/usr/bin/env bash
set -euo pipefail

# -------------------------
# Build script for libcprov3
# -------------------------

# Root of the project
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Build directory
BUILD_DIR="${PROJECT_ROOT}/build"

echo "Creating build directory at ${BUILD_DIR}..."
mkdir -p "$BUILD_DIR"

echo "Entering build directory..."
cd "$BUILD_DIR"

echo "Running CMake configure..."
cmake ..

echo "Building all targets..."
cmake --build . -- -j$(nproc)

echo "Build complete!"
