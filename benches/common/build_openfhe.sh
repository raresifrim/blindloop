#!/usr/bin/env bash
# Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
# All rights reserved.
#
# build_openfhe.sh <64|32> — stock OpenFHE v1.5.1 at NATIVE_SIZE=64 or 32, installed
# into deps/stock[-<ARM_CPU>]/openfhe-n<size>. Called by build.sh.
#
# Release, OpenMP, shared libraries (as the Intel HEXL and rvv-hexl builds), no
# WITH_NATIVEOPT: the ISA flag is detect_env.sh's NATIVE_FLAG on every backend.
# Skipped when the install already matches this configuration (FORCE=1 rebuilds).
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"    # <repo>/benches/common
. "$SCRIPT_DIR/detect_env.sh"
DEPS="$(cd "$SCRIPT_DIR/../.." && pwd)/deps"

NSIZE="${1:-64}"
case "$NSIZE" in
  64|32) ;;
  *) echo "build_openfhe.sh: NATIVE_SIZE must be 64 or 32 (got '$NSIZE')" >&2; exit 1 ;;
esac
OPENFHE_TAG="${OPENFHE_TAG:-v1.5.1}"
SRC="$DEPS/src/openfhe-development"
BUILD="$SRC/build-n$NSIZE$DEPS_SUFFIX"
PREFIX="$DEPS/stock$DEPS_SUFFIX/openfhe-n$NSIZE"
LOGS="$DEPS/logs"
TAG="OpenFHE n$NSIZE"
STAMP="OpenFHE $OPENFHE_TAG NATIVE_SIZE=$NSIZE CXX=$CXX $("$CXX" -dumpversion) FLAGS=$NATIVE_FLAG"

if [ "${FORCE:-0}" != "1" ] && [ -f "$PREFIX/.ipcei-stamp" ] && [ "$(cat "$PREFIX/.ipcei-stamp")" = "$STAMP" ]; then
  echo "[$TAG] up to date in $PREFIX"
  exit 0
fi

mkdir -p "$DEPS/src" "$LOGS"
if [ ! -d "$SRC" ]; then
  echo "[OpenFHE] clone $OPENFHE_TAG ..."
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$OPENFHE_TAG" https://github.com/openfheorg/openfhe-development.git "$SRC"
fi

# riscv64 at NATIVE_SIZE=32: upstream's MultD covers riscv64 only through the
# HAVE_INT128 arm, which CMake disables at 32 bits, leaving the #error path.
python3 - "$SRC/src/core/include/math/hal/intnat/ubintnat.h" <<'PATCH_EOF'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
s = p.read_text()
if "defined(__riscv) && __riscv_xlen == 64" in s:
    sys.exit(0)
anchor = "#elif defined(__arm__) || defined(__powerpc__)  // 32 bit processor"
if s.count(anchor) != 1:
    sys.exit(f"ERROR: MultD dispatch anchor found {s.count(anchor)} times in {p} (expected 1)")
arm = """#elif defined(__riscv) && __riscv_xlen == 64
            // Added downstream: upstream covers riscv64 only via the HAVE_INT128 arm above,
            // which CMake disables at NATIVE_SIZE=32, leaving riscv64 on the #error path.
            __uint128_t c{static_cast<__uint128_t>(a) * b};
            res.hi = static_cast<uint64_t>(c >> 64);
            res.lo = static_cast<uint64_t>(c);
"""
p.write_text(s.replace(anchor, arm + anchor))
print("[OpenFHE] patched MultD(): riscv64 __int128 arm")
PATCH_EOF

cmake_clean_stale_cache "$SRC" "$BUILD"
rm -rf "$PREFIX"
echo "[$TAG] configure (Release, OpenMP, NATIVE_SIZE=$NSIZE, '$NATIVE_FLAG'; $OS/$ARCH) ..."
run_logged "$LOGS/openfhe-n$NSIZE$DEPS_SUFFIX-configure.log" "$TAG configure" \
  cmake -S "$SRC" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_COMPILER="${CC:-cc}" \
  -DCMAKE_CXX_FLAGS="$NATIVE_FLAG" \
  -DCMAKE_C_FLAGS="$NATIVE_FLAG" \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DWITH_OPENMP=ON \
  -DNATIVE_SIZE="$NSIZE" \
  -DWITH_NATIVEOPT=OFF \
  -DBUILD_SHARED=ON -DBUILD_STATIC=OFF \
  -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF \
  "${OMP_CMAKE_ARGS[@]}"
echo "[$TAG] build (the long one) ..."
run_logged "$LOGS/openfhe-n$NSIZE$DEPS_SUFFIX-build.log" "$TAG build" cmake --build "$BUILD" -j "$NPROC"
run_logged "$LOGS/openfhe-n$NSIZE$DEPS_SUFFIX-install.log" "$TAG install" cmake --install "$BUILD"

echo "$STAMP" > "$PREFIX/.ipcei-stamp"
echo "[$TAG] DONE -> $PREFIX"
