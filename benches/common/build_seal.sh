#!/usr/bin/env bash
# build_seal.sh <stock|intel-hexl> — Microsoft SEAL v4.1.2, static, installed into
# deps/<backend>[-<ARM_CPU>]/seal. Called by build.sh; the rvv-hexl SEAL comes from
# the rvv-hexl checkout instead (make seal WITH_RVV_HEXL=ON).
#
#   stock        -DSEAL_USE_INTEL_HEXL=OFF
#   intel-hexl   -DSEAL_USE_INTEL_HEXL=ON; SEAL_BUILD_DEPS fetches and builds Intel
#                HEXL 1.2.5 (x86-64 only; its AVX-512 kernels need AVX512-DQ/IFMA)
#
# Same options as rvv-hexl's third_party/seal.sh: no MSGSL, zlib or zstd, so the three
# backends differ only in the HEXL switch. Skipped when the install already matches
# this configuration (FORCE=1 rebuilds).
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"    # <repo>/benches/common
. "$SCRIPT_DIR/detect_env.sh"
DEPS="$(cd "$SCRIPT_DIR/../.." && pwd)/deps"

BACKEND="${1:-stock}"
case "$BACKEND" in
  stock)      HEXL=OFF ;;
  intel-hexl) HEXL=ON
              [ "$ARCH" = "x86_64" ] || { echo "build_seal.sh: Intel HEXL is x86-64 only ($OS/$ARCH)" >&2; exit 1; } ;;
  *) echo "build_seal.sh: backend must be stock or intel-hexl (got '$BACKEND')" >&2; exit 1 ;;
esac
SEAL_TAG="${SEAL_TAG:-v4.1.2}"
SRC="$DEPS/src/SEAL"
BUILD="$SRC/build-$BACKEND$DEPS_SUFFIX"
PREFIX="$DEPS/$BACKEND$DEPS_SUFFIX/seal"
LOGS="$DEPS/logs"
STAMP="SEAL $SEAL_TAG HEXL=$HEXL CXX=$CXX $("$CXX" -dumpversion) FLAGS=$NATIVE_FLAG"

if [ "${FORCE:-0}" != "1" ] && [ -f "$PREFIX/.ipcei-stamp" ] && [ "$(cat "$PREFIX/.ipcei-stamp")" = "$STAMP" ]; then
  echo "[SEAL $BACKEND] up to date in $PREFIX"
  exit 0
fi

mkdir -p "$DEPS/src" "$LOGS"
if [ ! -d "$SRC" ]; then
  echo "[SEAL] clone $SEAL_TAG ..."
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$SEAL_TAG" https://github.com/microsoft/SEAL.git "$SRC"
fi

rm -rf "$BUILD" "$PREFIX"
echo "[SEAL $BACKEND] configure (Release, HEXL=$HEXL, '$NATIVE_FLAG'; $OS/$ARCH) ..."
# CMAKE_POLICY_VERSION_MINIMUM=3.5: SEAL 4.1's fetched sub-projects declare
# cmake_minimum_required(<3.5), which CMake 4.x rejects.
run_logged "$LOGS/seal-$BACKEND$DEPS_SUFFIX-configure.log" "SEAL $BACKEND configure" \
  cmake -S "$SRC" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_CXX_FLAGS="$NATIVE_FLAG" \
  -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DSEAL_USE_INTEL_HEXL=$HEXL \
  -DSEAL_BUILD_DEPS=ON \
  -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF \
  -DSEAL_BUILD_SEAL_C=OFF \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5
echo "[SEAL $BACKEND] build ..."
run_logged "$LOGS/seal-$BACKEND$DEPS_SUFFIX-build.log" "SEAL $BACKEND build" cmake --build "$BUILD" -j "$NPROC"
run_logged "$LOGS/seal-$BACKEND$DEPS_SUFFIX-install.log" "SEAL $BACKEND install" cmake --install "$BUILD"

if [ "$HEXL" = "ON" ]; then
  # SEAL links the fetched HEXL into its own target but does not install it: put the
  # archive next to libseal so the benches can link it (build.sh passes SEAL_HEXL_LIB).
  HEXL_A="$(find "$BUILD" -name 'libhexl*.a' | head -1)"
  [ -n "$HEXL_A" ] || { echo "ERROR: SEAL built with HEXL=ON but no libhexl.a under $BUILD" >&2; exit 1; }
  cp "$HEXL_A" "$PREFIX/lib/libhexl.a"
fi
grep -q "^#define SEAL_USE_INTEL_HEXL" "$PREFIX"/include/SEAL-*/seal/util/config.h && GOT=ON || GOT=OFF
[ "$GOT" = "$HEXL" ] || { echo "ERROR: installed SEAL has SEAL_USE_INTEL_HEXL=$GOT, wanted $HEXL" >&2; exit 1; }

echo "$STAMP" > "$PREFIX/.ipcei-stamp"
echo "[SEAL $BACKEND] DONE -> $PREFIX"
