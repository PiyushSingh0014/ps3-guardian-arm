#!/usr/bin/env bash
# Build advisor_server for the Raspberry Pi 4, with the same Arm toolchain,
# flags (-march=armv8-a -mtune=cortex-a72) and libraries as llama_main.
#
# Run in WSL, after `examples/raspberry_pi/setup.sh pi4` has built llama_main:
#   bash ~/ps3-guardian/deploy/advisor_server/build_pi4.sh ~/executorch
#
# It copies advisor_server.cpp next to llama_main's main.cpp, adds one target
# to examples/models/llama/CMakeLists.txt (once), and builds only that target.
# Nothing else in your ExecuTorch tree changes.
set -euo pipefail

ET="$(cd "${1:-$HOME/executorch}" 2>/dev/null && pwd)" || { echo "ERROR: no folder ${1:-$HOME/executorch}" >&2; exit 1; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LLAMA_DIR="$ET/examples/models/llama"
OUT_DIR="${CMAKE_OUT_DIR:-$ET/cmake-out}"                      # where setup.sh built everything
BUILD_DIR="$OUT_DIR/examples/models/llama"
TOOLCHAIN="${TOOLCHAIN_FILE:-$ET/arm-toolchain-pi4.cmake}"     # written by setup.sh pi4

fail() { echo "ERROR: $*" >&2; exit 1; }
[ -d "$LLAMA_DIR" ] || fail "no ExecuTorch tree at $ET (pass its path as the first argument)"
[ -f "$TOOLCHAIN" ] || fail "missing $TOOLCHAIN: run examples/raspberry_pi/setup.sh pi4 first"
[ -d "$BUILD_DIR" ] || fail "missing $BUILD_DIR: run examples/raspberry_pi/setup.sh pi4 first"

cp "$HERE/advisor_server.cpp" "$LLAMA_DIR/advisor_server.cpp"
if ! grep -q "PS3 Guardian advisor_server" "$LLAMA_DIR/CMakeLists.txt"; then
  cat "$HERE/cmake_snippet.cmake" >> "$LLAMA_DIR/CMakeLists.txt"
  echo "Added the advisor_server target to $LLAMA_DIR/CMakeLists.txt"
fi

cd "$ET"
export CMAKE_POLICY_VERSION_MINIMUM="${CMAKE_POLICY_VERSION_MINIMUM:-3.5}"   # CMake 4 with older CMakeLists
cmake -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DCMAKE_INSTALL_PREFIX="$OUT_DIR" \
  -DBUILD_TESTING=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -B"$BUILD_DIR" \
  "$LLAMA_DIR" > /dev/null
cmake --build "$BUILD_DIR" --target advisor_server -j"$(nproc)" --config Release

OUT="$BUILD_DIR/advisor_server"
[ -f "$OUT" ] || fail "build finished but $OUT is missing"
echo
echo "Built: $OUT"
if command -v file > /dev/null; then file "$OUT"; fi
echo
echo "Copy it next to llama_main on the Pi (change the IP if it changed):"
echo "  scp $OUT arrehinus@10.140.209.76:~/executorch-deployment/"
