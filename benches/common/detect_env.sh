#!/usr/bin/env bash
# Shared platform detection for build.sh and the dependency scripts.
# Source it (don't execute):  . "$(dirname "$0")/detect_env.sh"
#
# Works on macOS (Homebrew) and Linux on x86-64, AArch64 and riscv64.
# Sets, for the caller to use:
#   OS ARCH NPROC          - uname string, machine arch, parallel build jobs
#   HAS_AVX512 HAS_RVV     - 1 when the CPU has AVX-512F (x86-64) / the V extension (riscv64)
#   HEXL_BACKEND           - the accelerated backend for this CPU: intel-hexl, rvv-hexl or empty
#   RVV_HEXL_DIR           - the rvv-hexl checkout (riscv64; $RVV_HEXL_DIR, else ../rvv-hexl
#                            next to this repo, else ~/rares/rvv-hexl, else ~/rvv-hexl)
#   DEPS_SUFFIX            - "-$ARM_CPU" when ARM_CPU is set (one dependency set per core type)
#   NATIVE_FLAG            - -mcpu=native (arm; -mcpu=$ARM_CPU if set) or -march=native (x86)
#   BREW_PREFIX           - `brew --prefix` if Homebrew is present, else empty
#   PREFIX_INCLUDE PREFIX_LIB - header/lib search roots for gmp etc.
#   OPENSSL_ROOT_DIR      - passed to CMake / used for -lcrypto
#   CXX (CC)              - clang++ on macOS, g++ on Linux; on RISC-V the newest RVA23-capable
#                           g++-16/15/14, exported (respects a preset $CXX)
#   OMP_CMAKE_ARGS        - bash array of extra -D flags to wire OpenMP on macOS
#                           (empty on Linux, where gcc ships OpenMP natively)

OS="$(uname -s)"
ARCH="$(uname -m)"

# Default compiler per platform, but honour a caller-provided $CXX. Determined here
# (before the ISA-flag case) so the RISC-V -march probe below can query it.
if [ -z "${CXX:-}" ]; then
  if [ "$OS" = "Darwin" ]; then CXX=clang++; else CXX=g++; fi
  # RISC-V: the newest GCC that accepts the RVA23 profile (16, then 15, 14). On the
  # SpaceMiT K3 this is what the suite is measured with: Ubuntu 26.04's GCC 15.2
  # rejects -march=rva23u64, and building for plain
  # rv64gcv instead loses Zicond/Zba/Zbb, i.e. up to 2.5x on OpenFHE's 64-bit NTT.
  # Exported so every sub-script and CMake configure uses the same compiler.
  if [ "$ARCH" = "riscv64" ]; then
    for _v in 16 15 14; do
      if command -v "g++-$_v" >/dev/null 2>&1 &&
         printf 'int main(){return 0;}\n' | "g++-$_v" -march=rva23u64 -x c++ -c -o /dev/null - >/dev/null 2>&1; then
        CXX="g++-$_v"
        if [ -z "${CC:-}" ] && command -v "gcc-$_v" >/dev/null 2>&1; then CC="gcc-$_v"; fi
        break
      fi
    done
    export CXX
    if [ -n "${CC:-}" ]; then export CC; fi
  fi
fi

# Does the active compiler accept a given -march? (trivial compile-to-null probe.)
_cc_accepts_march() { printf 'int main(){return 0;}\n' | "$CXX" -march="$1" -x c++ -c -o /dev/null - >/dev/null 2>&1; }

case "$ARCH" in
  # big.LITTLE (cores of different types, e.g. Genio 1200: 4x Cortex-A78 + 4x Cortex-A55):
  # GCC 13 resolves -mcpu=native to NOTHING there (no -mcpu reaches cc1, generic ARMv8-A
  # code and tuning, no warning). Name the core instead, one build per cluster:
  #   ARM_CPU=cortex-a78 ./build.sh   (then ARM_CPU=cortex-a78 taskset -c 4-7 ./run.sh)
  arm64|aarch64) NATIVE_FLAG="-mcpu=${ARM_CPU:-native}"
    if [ -z "${ARM_CPU:-}" ] && [ -r /proc/cpuinfo ] &&
       [ "$(grep "^CPU part" /proc/cpuinfo | sort -u | wc -l)" -gt 1 ]; then
      echo "detect_env: WARNING: cores of different types; -mcpu=native may build generic ARMv8-A." >&2
      echo "detect_env:          Set ARM_CPU (e.g. ARM_CPU=cortex-a78), one build per cluster." >&2
    fi ;;
  # RISC-V: -march=native is unreliable (depends on GCC + kernel hwprobe). Prefer the
  # full RVA23 profile (-march=rva23u64: GCC 16 / recent clang; Ubuntu's GCC 15.2
  # rejects the profile name) with the default -mtune, which is the recommended
  # baseline: -mtune=generic-ooo / spacemit-x60 measured neutral and
  # -mmax-vectorization harmful on the K3. Falls back to rv64gcv (RV64GC + Vector 1.0,
  # GCC 13+), then rv64gc (no vector). Either vector march lets the compiler
  # auto-vectorise with RVV, mirroring the ARM NEON-autovec methodology. Force a
  # specific one with e.g.  RISCV_MARCH=rv64gcv ./build.sh
  riscv64)
    if   [ -n "${RISCV_MARCH:-}" ];  then NATIVE_FLAG="-march=$RISCV_MARCH"
    elif _cc_accepts_march rva23u64; then NATIVE_FLAG="-march=rva23u64"
    elif _cc_accepts_march rv64gcv;  then NATIVE_FLAG="-march=rv64gcv"
    else                                  NATIVE_FLAG="-march=rv64gc"
    fi ;;
  *)             NATIVE_FLAG="-march=native" ;;
esac

if command -v nproc >/dev/null 2>&1; then
  NPROC="$(nproc)"
elif command -v sysctl >/dev/null 2>&1; then
  NPROC="$(sysctl -n hw.ncpu)"
else
  NPROC=4
fi

BREW_PREFIX=""
if command -v brew >/dev/null 2>&1; then
  BREW_PREFIX="$(brew --prefix)"
fi

# Where to find gmp / openssl headers and libs.
if [ -n "$BREW_PREFIX" ]; then
  PREFIX_INCLUDE="$BREW_PREFIX/include"
  PREFIX_LIB="$BREW_PREFIX/lib"
  OPENSSL_ROOT_DIR="$BREW_PREFIX/opt/openssl@3"
else
  # System locations on Linux; the linker's default search path also covers
  # multiarch dirs (e.g. /usr/lib/x86_64-linux-gnu) for plain -l flags.
  PREFIX_INCLUDE="/usr/include"
  PREFIX_LIB="/usr/lib"
  OPENSSL_ROOT_DIR="/usr"
fi

# ---- HEXL backends ----------------------------------------------------------
# x86-64 with AVX-512: Intel HEXL (OpenFHE through the openfhe-hexl overlay, SEAL
# through -DSEAL_USE_INTEL_HEXL=ON). Without AVX-512, HEXL only runs its portable
# scalar path, so the stock build is the meaningful one there.
# riscv64 with V: rvv-hexl, built from its own checkout (RVV_HEXL_DIR).
HAS_AVX512=0
HAS_RVV=0
case "$OS" in
  Linux)
    grep -qm1 avx512f /proc/cpuinfo 2>/dev/null && HAS_AVX512=1
    if [ "$ARCH" = "riscv64" ]; then
      # single-letter extensions of the isa string, e.g. rv64imafdcvh_zicbom_... -> imafdcvh
      _isa="$(sed -n 's/^isa[[:space:]]*:[[:space:]]*rv64\([a-z]*\).*/\1/p' /proc/cpuinfo 2>/dev/null | head -1)"
      case "$_isa" in *v*) HAS_RVV=1 ;; esac
    fi
    ;;
  Darwin)
    sysctl -n hw.optional.avx512f 2>/dev/null | grep -q 1 && HAS_AVX512=1
    ;;
esac

HEXL_BACKEND=""
RVV_HEXL_DIR="${RVV_HEXL_DIR:-}"
if [ "$ARCH" = "x86_64" ] && [ "$HAS_AVX512" = "1" ]; then
  HEXL_BACKEND=intel-hexl
elif [ "$ARCH" = "riscv64" ] && [ "$HAS_RVV" = "1" ]; then
  HEXL_BACKEND=rvv-hexl
  if [ -z "$RVV_HEXL_DIR" ]; then
    _repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    for _d in "$_repo/../rvv-hexl" "$HOME/rares/rvv-hexl" "$HOME/rvv-hexl"; do
      if [ -f "$_d/third_party/openfhe.sh" ]; then RVV_HEXL_DIR="$(cd "$_d" && pwd)"; break; fi
    done
  fi
fi

DEPS_SUFFIX="${ARM_CPU:+-$ARM_CPU}"

# OpenMP: clang on macOS needs Homebrew libomp wired in by hand; gcc on Linux
# supports -fopenmp out of the box, so no extra CMake flags are needed there.
OMP_CMAKE_ARGS=()
if [ "$OS" = "Darwin" ] && [ -n "$BREW_PREFIX" ] && [ -d "$BREW_PREFIX/opt/libomp" ]; then
  LOMP="$BREW_PREFIX/opt/libomp"
  OMP_CMAKE_ARGS=(
    -DOpenMP_CXX_FLAGS="-Xclang -fopenmp -I$LOMP/include"
    -DOpenMP_C_FLAGS="-Xclang -fopenmp -I$LOMP/include"
    -DOpenMP_CXX_LIB_NAMES=omp
    -DOpenMP_C_LIB_NAMES=omp
    -DOpenMP_omp_LIBRARY="$LOMP/lib/libomp.dylib"
  )
fi

export HAS_AVX512 HAS_RVV HEXL_BACKEND RVV_HEXL_DIR DEPS_SUFFIX

# ---- stale-CMakeCache guard --------------------------------------------------
# A CMake build tree records the absolute source and binary paths it was generated
# for. Move or rename the checkout (as happened when the libraries were relocated
# from ~/fhe-libs into deps) and every later `cmake -S ... -B ...` on
# that tree aborts with "CMakeCache.txt directory is different than ...". Because
# the sub-scripts send configure output to a log file, that failure is silent.
#
# cmake_clean_stale_cache <abs-source-dir> <abs-binary-dir>
#   Wipes the binary dir ONLY when its cache belongs to different paths, so normal
#   incremental rebuilds are preserved (OpenFHE takes ~10 min from scratch).
cmake_clean_stale_cache() {
  _ccsc_src="$1"; _ccsc_bin="$2"; _ccsc_cache="$2/CMakeCache.txt"
  [ -f "$_ccsc_cache" ] || return 0
  _ccsc_oldsrc="$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$_ccsc_cache" | head -1)"
  _ccsc_oldbin="$(sed -n 's/^CMAKE_CACHEFILE_DIR:INTERNAL=//p'  "$_ccsc_cache" | head -1)"
  if [ "$_ccsc_oldsrc" != "$_ccsc_src" ] || [ "$_ccsc_oldbin" != "$_ccsc_bin" ]; then
    echo "  [stale CMake cache in $_ccsc_bin"
    echo "   generated for '$_ccsc_oldsrc' — wiping so configure can succeed]"
    rm -rf "$_ccsc_bin"
  fi
}

# run_logged <logfile> <description> -- <command...>
# Runs a command with output captured to a log, and on failure prints the tail of
# that log before exiting. Without this, `set -e` plus a redirect kills the build
# with no indication of what went wrong or where to look.
run_logged() {
  _rl_log="$1"; _rl_what="$2"; shift 2
  if ! "$@" > "$_rl_log" 2>&1; then
    echo "" >&2
    echo "ERROR: $_rl_what failed. Last 30 lines of $_rl_log:" >&2
    echo "---------------------------------------------------------------" >&2
    tail -30 "$_rl_log" >&2
    echo "---------------------------------------------------------------" >&2
    return 1
  fi
}
