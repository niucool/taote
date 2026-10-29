#!/usr/bin/env bash
#
# build-linux.sh — build taote for Linux (the host) with vcpkg-managed deps.
#
# Prerequisites:
#   - cmake >= 3.15 and a C++17 toolchain
#   - vcpkg (VCPKG_ROOT defaults to $HOME/source/vcpkg)
#
# Environment overrides:
#   VCPKG_ROOT  path to the vcpkg checkout
#   BUILD_DIR   build directory (default: build)
#   JOBS        parallel compile jobs (default: nproc)
#
# Output:
#   build/deploy/  (bin/ + lib/ + include/ + share/) after `cmake --install`

set -euo pipefail

cd "$(dirname "$0")"

VCPKG_ROOT="${VCPKG_ROOT:-$HOME/source/vcpkg}"
TOOLCHAIN="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"

if [ ! -f "$TOOLCHAIN" ]; then
    echo "error: vcpkg toolchain not found at $TOOLCHAIN" >&2
    echo "       set VCPKG_ROOT to your vcpkg checkout" >&2
    exit 1
fi

BUILD_DIR="${BUILD_DIR:-build}"
JOBS="${JOBS:-$(nproc)}"

cmake -B "$BUILD_DIR" -S . \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DCMAKE_BUILD_TYPE=Release

# Build everything: the qiling library, qltool, the tools, and qiling_tests.
cmake --build "$BUILD_DIR" --config Release -j"$JOBS"

# Populate build/deploy with the relocatable tree.
cmake --install "$BUILD_DIR"

echo "linux build complete: $BUILD_DIR/deploy"
