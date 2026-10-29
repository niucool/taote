#!/usr/bin/env bash
#
# build-windows.sh — cross-compile taote for Windows x64 (MinGW-w64 + vcpkg).
#
# Prerequisites:
#   - cmake >= 3.15
#   - the mingw-w64 cross toolchain (x86_64-w64-mingw32-g++ and -strip)
#   - vcpkg (VCPKG_ROOT defaults to $HOME/source/vcpkg)
#
# Environment overrides:
#   VCPKG_ROOT   path to the vcpkg checkout
#   BUILD_DIR    build directory (default: build-mingw)
#   DEPLOY_DIR   where the stripped .exe files land (default: $BUILD_DIR/deploy-win)
#   JOBS         parallel compile jobs (default: nproc)
#
# Notes:
#   - The executables are linked with `-static`, so they only need Windows
#     system DLLs (kernel32, msvcrt, ws2_32, ...) at runtime.
#   - qiling_tests is not built: two gdb tests reference QlGdb, which lives in
#     the POSIX-only gdbserver slice (see qiling/CMakeLists.txt).

set -euo pipefail

cd "$(dirname "$0")"

VCPKG_ROOT="${VCPKG_ROOT:-$HOME/source/vcpkg}"
TOOLCHAIN="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
MINGW_TOOLCHAIN="$VCPKG_ROOT/scripts/toolchains/mingw.cmake"

command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1 || {
    echo "error: x86_64-w64-mingw32-g++ not found; install mingw-w64" >&2
    exit 1
}
if [ ! -f "$TOOLCHAIN" ]; then
    echo "error: vcpkg toolchain not found at $TOOLCHAIN" >&2
    echo "       set VCPKG_ROOT to your vcpkg checkout" >&2
    exit 1
fi

BUILD_DIR="${BUILD_DIR:-build-mingw}"
JOBS="${JOBS:-$(nproc)}"

# The MinGW cross-compiler is chain-loaded explicitly: the vcpkg CMake toolchain
# builds the dependencies for the mingw triplet but does not switch the consumer
# project's compiler. VCPKG_TARGET_ARCHITECTURE/CRT_LINKAGE must be passed too,
# because the triplet file is not read into the consumer CMake scope.
cmake -B "$BUILD_DIR" -S . \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DVCPKG_TARGET_TRIPLET=x64-mingw-static \
    -DVCPKG_TARGET_ARCHITECTURE=x64 \
    -DVCPKG_CRT_LINKAGE=dynamic \
    -DVCPKG_LIBRARY_LINKAGE=static \
    -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE="$MINGW_TOOLCHAIN" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXE_LINKER_FLAGS="-static"

# Build the shipped executables (qiling_tests does not link on Windows).
cmake --build "$BUILD_DIR" --config Release \
    --target qltool parity_trace gap_census taote -j"$JOBS"

# Stage the distributable .exe files. The default profiles are embedded in the
# binaries (see qiling/core.cpp), so no .ql files need to ship; a --profile file
# is only needed when a run wants to override the built-in defaults.
DEST="${DEPLOY_DIR:-$BUILD_DIR/deploy-win}"
mkdir -p "$DEST/bin"
for exe in qltool/qltool.exe \
           tools/parity_trace.exe \
           tools/gap_census.exe \
           tools/taote.exe; do
    name="$(basename "$exe")"
    cp "$BUILD_DIR/$exe" "$DEST/bin/$name"
    x86_64-w64-mingw32-strip "$DEST/bin/$name" 2>/dev/null || true
done

# Drop artifacts from the pre-rename layout (taote_unpack.exe and the bundled
# share/qiling/profiles tree the binaries no longer need).
rm -f "$DEST/bin/taote_unpack.exe"
rm -rf "$DEST/share"

echo "windows build complete: $DEST"
