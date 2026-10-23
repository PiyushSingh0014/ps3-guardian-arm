#!/usr/bin/env bash
# Build advisor_server for the Raspberry Pi 4, with the same Arm toolchain,
# flags (-march=armv8-a -mtune=cortex-a72) and libraries as llama_main.
#
# Run in WSL on the laptop (not on the Pi), after `examples/raspberry_pi/setup.sh pi4`
# has built llama_main there:
#   bash ~/advisor_server/build_pi4.sh ~/executorch
#
# It copies advisor_server.cpp next to llama_main's main.cpp, adds one target
# to the end of examples/models/llama/CMakeLists.txt (replacing the one an
# earlier run added), and builds only that target. Nothing else changes.
set -euo pipefail

fail() {
  echo "ERROR: $*" >&2
  if [ "$(uname -m)" = "aarch64" ]; then
    echo "       This is an Arm machine (the Pi?). Run this script in WSL on the laptop, with" >&2
    echo "       the ExecuTorch folder where examples/raspberry_pi/setup.sh pi4 built llama_main." >&2
  fi
  exit 1
}

ET="$(cd "${1:-$HOME/executorch}" 2>/dev/null && pwd)" || fail "no folder ${1:-$HOME/executorch}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LLAMA_DIR="$ET/examples/models/llama"
CML="$LLAMA_DIR/CMakeLists.txt"
OUT_DIR="${CMAKE_OUT_DIR:-$ET/cmake-out}"                      # where setup.sh built everything
BUILD_DIR="$OUT_DIR/examples/models/llama"
TOOLCHAIN="${TOOLCHAIN_FILE:-$ET/arm-toolchain-pi4.cmake}"     # written by setup.sh pi4

[ -f "$CML" ] || fail "no ExecuTorch tree at $ET (pass its path as the first argument)"
[ -f "$TOOLCHAIN" ] || fail "missing $TOOLCHAIN: run examples/raspberry_pi/setup.sh pi4 first"
[ -d "$BUILD_DIR" ] || fail "missing $BUILD_DIR: run examples/raspberry_pi/setup.sh pi4 first"

cp "$HERE/advisor_server.cpp" "$LLAMA_DIR/advisor_server.cpp"
# Drop the block an earlier run added (and the blank lines before it), then add the current one.
awk '/^# --- PS3 Guardian advisor_server/ { skip = 1; blank = 0; next }
     skip { if (/^# --- end PS3 Guardian advisor_server/) skip = 0; next }
     /^[[:space:]]*$/ { blank++; next }
     { while (blank > 0) { print ""; blank-- } print }' "$CML" > "$CML.tmp"
mv "$CML.tmp" "$CML"
cat "$HERE/cmake_snippet.cmake" >> "$CML"
echo "advisor_server target is at the end of $CML"

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
