#!/usr/bin/env bash
# build_openfhe_hexl.sh — OpenFHE v1.5.1 with the openfhe-hexl v1.5.1.0 overlay and
# Intel HEXL 1.2.6 (which its CMake downloads and builds), NATIVE_SIZE=64, installed
# into deps/intel-hexl/openfhe-n64. Called by build.sh on x86-64 with AVX-512.
#
# This is what openfhe-configurator does for an "openfhe-hexl" build: stage the
# overlay onto a pristine openfhe-development checkout, then -DWITH_INTEL_HEXL=ON.
# NATIVE_SIZE=32 is not possible: OpenFHE's HEXL HAL reinterpret_casts the vectors
# to uint64_t* (it compiles and returns wrong results), so binfhe at 32 bits stays
# on the stock build. Skipped when the install already matches (FORCE=1 rebuilds).
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"    # <repo>/benches/common
. "$SCRIPT_DIR/detect_env.sh"
DEPS="$(cd "$SCRIPT_DIR/../.." && pwd)/deps"

if [ "$ARCH" != "x86_64" ]; then
  echo "build_openfhe_hexl.sh: Intel HEXL is x86-64 only ($OS/$ARCH)" >&2
  exit 1
fi
OPENFHE_TAG="${OPENFHE_TAG:-v1.5.1}"
OPENFHE_HEXL_TAG="${OPENFHE_HEXL_TAG:-v1.5.1.0}"
SRC="$DEPS/src/openfhe-hexl-src"        # openfhe-development + the staged overlay
OVERLAY="$DEPS/src/openfhe-hexl"
BUILD="$SRC/build"
PREFIX="$DEPS/intel-hexl/openfhe-n64"
LOGS="$DEPS/logs"
STAMP="OpenFHE $OPENFHE_TAG + openfhe-hexl $OPENFHE_HEXL_TAG CXX=$CXX $("$CXX" -dumpversion) FLAGS=$NATIVE_FLAG"

if [ "${FORCE:-0}" != "1" ] && [ -f "$PREFIX/.ipcei-stamp" ] && [ "$(cat "$PREFIX/.ipcei-stamp")" = "$STAMP" ]; then
  echo "[OpenFHE intel-hexl] up to date in $PREFIX"
  exit 0
fi

mkdir -p "$DEPS/src" "$LOGS"
if [ ! -d "$OVERLAY" ]; then
  echo "[OpenFHE intel-hexl] clone openfhe-hexl $OPENFHE_HEXL_TAG ..."
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$OPENFHE_HEXL_TAG" https://github.com/openfheorg/openfhe-hexl.git "$OVERLAY"
fi
if [ ! -f "$SRC/.staged" ]; then
  rm -rf "$SRC"
  echo "[OpenFHE intel-hexl] clone openfhe-development $OPENFHE_TAG and stage the overlay ..."
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$OPENFHE_TAG" https://github.com/openfheorg/openfhe-development.git "$SRC"
  for f in CMakeLists.txt CMakeLists.User.txt OpenFHEConfig.cmake.in; do
    [ -f "$OVERLAY/$f" ] || { echo "ERROR: overlay has no $f (upstream layout changed?)" >&2; exit 1; }
    cp "$OVERLAY/$f" "$SRC/"
  done
  for d in benchmark configure src third-party; do
    [ -d "$OVERLAY/$d" ] || { echo "ERROR: overlay has no $d/ (upstream layout changed?)" >&2; exit 1; }
    cp -R "$OVERLAY/$d" "$SRC/"
  done
  grep -q WITH_INTEL_HEXL "$SRC/CMakeLists.txt" \
    || { echo "ERROR: staged CMakeLists.txt has no WITH_INTEL_HEXL option" >&2; exit 1; }
  touch "$SRC/.staged"
fi

cmake_clean_stale_cache "$SRC" "$BUILD"
rm -rf "$PREFIX"
echo "[OpenFHE intel-hexl] configure (Release, OpenMP, WITH_INTEL_HEXL=ON, '$NATIVE_FLAG') ..."
run_logged "$LOGS/openfhe-intel-hexl-configure.log" "OpenFHE intel-hexl configure" \
  cmake -S "$SRC" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_COMPILER="${CC:-cc}" \
  -DCMAKE_CXX_FLAGS="$NATIVE_FLAG" \
  -DCMAKE_C_FLAGS="$NATIVE_FLAG" \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DWITH_OPENMP=ON \
  -DWITH_INTEL_HEXL=ON \
  -DNATIVE_SIZE=64 \
  -DWITH_NATIVEOPT=OFF \
  -DBUILD_SHARED=ON -DBUILD_STATIC=OFF \
  -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF \
  "${OMP_CMAKE_ARGS[@]}"
echo "[OpenFHE intel-hexl] build (also builds Intel HEXL 1.2.6) ..."
run_logged "$LOGS/openfhe-intel-hexl-build.log" "OpenFHE intel-hexl build" cmake --build "$BUILD" -j "$NPROC"
run_logged "$LOGS/openfhe-intel-hexl-install.log" "OpenFHE intel-hexl install" cmake --install "$BUILD"
ls "$PREFIX"/lib*/libhexl* >/dev/null 2>&1 \
  || echo "[OpenFHE intel-hexl] note: no libhexl installed under $PREFIX (linked into OpenFHE?)"

echo "$STAMP" > "$PREFIX/.ipcei-stamp"
echo "[OpenFHE intel-hexl] DONE -> $PREFIX"
