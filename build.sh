#!/usr/bin/env bash
# Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
# All rights reserved.
#
# build.sh — builds the FHE libraries and the blindloop benches, once per backend.
#
#   ./build.sh [--backends "stock intel-hexl rvv-hexl"] [--deps-only | --benches-only]
#              [--no-n32] [--packages] [--jobs N]
#
# Backends (auto-detected; --backends overrides):
#   stock        SEAL and OpenFHE (NATIVE_SIZE 64 and 32) as released, every platform
#   intel-hexl   x86-64 with AVX-512: Intel HEXL under SEAL (-DSEAL_USE_INTEL_HEXL=ON,
#                HEXL 1.2.5) and OpenFHE (openfhe-hexl overlay, HEXL 1.2.6); NATIVE_SIZE 64
#                only (OpenFHE's HEXL HAL is 64-bit), so tfhe_openfhe_n32 is not built
#   rvv-hexl     riscv64 with V: SEAL and OpenFHE (64 and 32) built by the rvv-hexl
#                checkout (RVV_HEXL_DIR, see benches/common/detect_env.sh) with its
#                OpenFHE patches, at its current commit: make seal / make openfhe
#                WITH_RVV_HEXL=ON, which first reinstalls rvv-hexl itself
#
# Layout:
#   deps/src/                         library sources
#   deps/<backend>[-<ARM_CPU>]/       seal, openfhe-n64, openfhe-n32 install prefixes
#   build/<backend>[-<ARM_CPU>]/      the benches of that backend (+ BUILD_INFO)
# Dependencies are rebuilt only when their configuration changed (FORCE=1 rebuilds).
#
# Environment: CXX/CC (default: clang++ on macOS, g++ on Linux, the newest RVA23 g++ on
# riscv64), ARM_CPU=cortex-a78 (big.LITTLE boards: one build per core type),
# RISCV_MARCH, RVV_HEXL_DIR, SEAL_TAG, OPENFHE_TAG, OPENFHE_HEXL_TAG.
#   BUILD_TAG=name        a separate dependency set and bench dir, deps/<backend>-<name> and
#                         build/<backend>-<name> (run.sh honours it too), for side-by-side
#                         configurations, e.g. BUILD_TAG=gcc15 CXX=g++-15 RISCV_MARCH=rv64gcv
#   OPENFHE_N32_NOVEC=1   stock OpenFHE NATIVE_SIZE=32 with auto-vectorisation disabled
#                         (separates the narrow word from the vectorisation it enables);
#                         use it with a BUILD_TAG, and check it with tools/vec_census.py
#
# --packages installs the system packages first (Homebrew / apt / dnf, with sudo).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMON="$REPO/benches/common"

BACKENDS=""
STAGE=all
WITH_N32=1
PACKAGES=0
JOBS=""
while [ $# -gt 0 ]; do
	case "$1" in
		--backends) BACKENDS="$2"; shift ;;
		--deps-only) STAGE=deps ;;
		--benches-only) STAGE=benches ;;
		--no-n32) WITH_N32=0 ;;
		--packages) PACKAGES=1 ;;
		--jobs) JOBS="$2"; shift ;;
		-h|--help) sed -n '2,28p' "$0"; exit 0 ;;
		*) echo "build.sh: unknown option $1 (see --help)" >&2; exit 2 ;;
	esac
	shift
done

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }

# ---------------------------------------------------------------- system packages
if [ "$PACKAGES" = "1" ]; then
	step "system packages"
	case "$(uname -s)" in
		Darwin) brew install cmake git libomp openssl@3 gmp boost ;;
		Linux)
			if command -v apt-get >/dev/null 2>&1; then
				sudo apt-get update
				sudo apt-get install -y build-essential cmake git python3 libgmp-dev libssl-dev \
					libboost-program-options-dev libomp-dev
				if [ "$(uname -m)" = "riscv64" ]; then
					for v in 16 15 14; do
						sudo apt-get install -y --no-upgrade "gcc-$v" "g++-$v" >/dev/null 2>&1 && break
					done
				fi
			elif command -v dnf >/dev/null 2>&1; then
				sudo dnf install -y gcc-c++ cmake git python3 gmp-devel openssl-devel boost-devel
			else
				echo "no apt-get or dnf: install a C++17 compiler, cmake >= 3.16, git, python3, gmp," >&2
				echo "OpenSSL 3 and boost program_options by hand" >&2
				exit 1
			fi ;;
	esac
fi

. "$COMMON/detect_env.sh"
[ -n "$JOBS" ] && NPROC="$JOBS"
export NPROC

if [ -z "$BACKENDS" ]; then
	BACKENDS="stock${HEXL_BACKEND:+ $HEXL_BACKEND}"
fi
for b in $BACKENDS; do
	case "$b" in
		stock) ;;
		intel-hexl)
			[ "$ARCH" = "x86_64" ] || { echo "build.sh: intel-hexl needs x86-64 (this is $ARCH)" >&2; exit 1; }
			[ "$HAS_AVX512" = "1" ] || echo "build.sh: WARNING: no AVX-512 here; Intel HEXL runs its scalar fallback" >&2 ;;
		rvv-hexl)
			[ "$ARCH" = "riscv64" ] || { echo "build.sh: rvv-hexl needs riscv64 (this is $ARCH)" >&2; exit 1; }
			if [ -z "$RVV_HEXL_DIR" ] || [ ! -f "$RVV_HEXL_DIR/third_party/openfhe.sh" ]; then
				echo "build.sh: rvv-hexl backend: no rvv-hexl checkout found." >&2
				echo "          Clone it next to this repo, or set RVV_HEXL_DIR=/path/to/rvv-hexl" >&2
				exit 1
			fi ;;
		*) echo "build.sh: unknown backend '$b' (stock, intel-hexl, rvv-hexl)" >&2; exit 2 ;;
	esac
done

echo "platform  : $OS/$ARCH, $NPROC jobs, $("$CXX" --version | head -1), '$NATIVE_FLAG'"
echo "CPU       : AVX-512 $HAS_AVX512, RVV $HAS_RVV${RVV_HEXL_DIR:+, rvv-hexl at $RVV_HEXL_DIR}"
echo "backends  : $BACKENDS"

# ---------------------------------------------------------------- per-backend installs
# Sets SEAL_ROOT SEAL_HEXL_LIB OPENFHE_ROOT OPENFHE_N32_ROOT BACKEND_INFO for backend $1.
RVV_ISA=rvv
backend_paths() {
	local d="$REPO/deps/$1$DEPS_SUFFIX"
	SEAL_HEXL_LIB=""
	OPENFHE_N32_ROOT=""
	HEXL_ROOT=""
	case "$1" in
		stock)
			SEAL_ROOT="$d/seal"
			OPENFHE_ROOT="$d/openfhe-n64"
			[ "$WITH_N32" = "1" ] && OPENFHE_N32_ROOT="$d/openfhe-n32"
			BACKEND_INFO="SEAL ${SEAL_TAG:-v4.1.2}, OpenFHE ${OPENFHE_TAG:-v1.5.1}" ;;
		intel-hexl)
			SEAL_ROOT="$d/seal"
			SEAL_HEXL_LIB="$d/seal/lib/libhexl.a"
			OPENFHE_ROOT="$d/openfhe-n64"
			BACKEND_INFO="SEAL ${SEAL_TAG:-v4.1.2} + Intel HEXL 1.2.5, OpenFHE ${OPENFHE_TAG:-v1.5.1} + openfhe-hexl ${OPENFHE_HEXL_TAG:-v1.5.1.0} (Intel HEXL 1.2.6)" ;;
		rvv-hexl)
			local r="$RVV_HEXL_DIR/build"
			SEAL_ROOT="$r/seal/$RVV_ISA/rvvhexl/install"
			SEAL_HEXL_LIB="$r/$RVV_ISA-release/install/lib/libhexl.a"
			HEXL_ROOT="$r/$RVV_ISA-release/install"
			OPENFHE_ROOT="$r/openfhe/$RVV_ISA/n64-rvvhexl/install"
			[ "$WITH_N32" = "1" ] && OPENFHE_N32_ROOT="$r/openfhe/$RVV_ISA/n32-rvvhexl/install"
			local rev
			rev="$(git -C "$RVV_HEXL_DIR" log -1 --format='%h %s' 2>/dev/null || echo unknown)"
			git -C "$RVV_HEXL_DIR" diff --quiet HEAD 2>/dev/null || rev="$rev (+ uncommitted changes)"
			BACKEND_INFO="rvv-hexl $rev; SEAL v4.1.2, OpenFHE v1.5.1 + openfhe-hexl v1.5.1.0 (rvv-hexl patches)" ;;
	esac
}

build_deps() {
	case "$1" in
		stock)
			bash "$COMMON/build_seal.sh" stock
			bash "$COMMON/build_openfhe.sh" 64
			[ "$WITH_N32" = "0" ] || bash "$COMMON/build_openfhe.sh" 32 ;;
		intel-hexl)
			bash "$COMMON/build_seal.sh" intel-hexl
			bash "$COMMON/build_openfhe_hexl.sh" ;;
		rvv-hexl)
			# rvv-hexl's own targets: incremental, and each reinstalls rvv-hexl first so
			# OpenFHE and SEAL pick up its current kernels. Same compiler as the benches.
			# OpenFHE's own unit tests and benchmarks are the heaviest part of that build
			# (memory included) and the suite does not use them
			local mk=(make --no-print-directory -C "$RVV_HEXL_DIR" ISA=$RVV_ISA CXX="$CXX" CC="${CC:-gcc}"
				JOBS="$NPROC" WITH_RVV_HEXL=ON OPENFHE_UNITTESTS=OFF OPENFHE_BENCHMARKS=OFF)
			echo "[rvv-hexl] SEAL ..."
			"${mk[@]}" seal
			echo "[rvv-hexl] OpenFHE n64 ..."
			"${mk[@]}" openfhe NATIVE_SIZE=64
			if [ "$WITH_N32" = "1" ]; then
				echo "[rvv-hexl] OpenFHE n32 ..."
				"${mk[@]}" openfhe NATIVE_SIZE=32
			fi ;;
	esac
	backend_paths "$1"
	local p
	for p in "$SEAL_ROOT" "$OPENFHE_ROOT" ${OPENFHE_N32_ROOT:+"$OPENFHE_N32_ROOT"} ${SEAL_HEXL_LIB:+"$SEAL_HEXL_LIB"}; do
		[ -e "$p" ] || { echo "build.sh: $1: expected $p after the build" >&2; exit 1; }
	done
}

build_benches() {
	local b="$1" dir="$REPO/build/$1$DEPS_SUFFIX"
	backend_paths "$b"
	local mac=()
	if [ -n "$BREW_PREFIX" ]; then
		mac=(-DCMAKE_PREFIX_PATH="$BREW_PREFIX" -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR"
			-DCMAKE_EXE_LINKER_FLAGS="-L$OPENSSL_ROOT_DIR/lib -L$BREW_PREFIX/lib")
	fi
	cmake_clean_stale_cache "$REPO" "$dir"
	mkdir -p "$dir"
	run_logged "$dir/configure.log" "benches ($b) configure" \
		cmake -S "$REPO" -B "$dir" \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_CXX_COMPILER="$CXX" \
		-DCMAKE_C_COMPILER="${CC:-cc}" \
		-DNATIVE_FLAG="$NATIVE_FLAG" \
		-DIPCEI_BACKEND="$b" \
		-DSEAL_ROOT="$SEAL_ROOT" \
		-DSEAL_HEXL_LIB="$SEAL_HEXL_LIB" \
		-DOPENFHE_ROOT="$OPENFHE_ROOT" \
		-DOPENFHE_N32_ROOT="$OPENFHE_N32_ROOT" \
		-DHEXL_ROOT="$HEXL_ROOT" \
		"${mac[@]}"
	run_logged "$dir/build.log" "benches ($b) build" cmake --build "$dir" -j "$NPROC"
	{
		echo "backend   $b"
		echo "libraries $BACKEND_INFO"
		echo "compiler  $("$CXX" --version | head -1)"
		echo "flags     $NATIVE_FLAG${ARM_CPU:+ (ARM_CPU=$ARM_CPU)}${BUILD_TAG:+ (BUILD_TAG=$BUILD_TAG)}"
		[ "${OPENFHE_N32_NOVEC:-0}" = "1" ] && echo "openfhe   NATIVE_SIZE=32 library built without auto-vectorisation"
		echo "host      $(uname -n) $OS/$ARCH"
		local suite
		suite="$(git -C "$REPO" log -1 --format='%h %s' 2>/dev/null || echo unknown)"
		git -C "$REPO" diff --quiet HEAD 2>/dev/null || suite="$suite (+ uncommitted changes)"
		echo "suite     $suite"
		echo "built     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	} > "$dir/BUILD_INFO"
	echo "[$b] benches in $dir:"
	(cd "$dir" && ls -1 bfv_* ckks_* tfhe_* ntt_* zk_selftest 2>/dev/null | tr '\n' ' '; echo)
}

for b in $BACKENDS; do
	if [ "$STAGE" != "benches" ]; then
		step "$b: libraries"
		build_deps "$b"
	fi
	if [ "$STAGE" != "deps" ]; then
		step "$b: benches"
		build_benches "$b"
	fi
done
step "done — run the benches with ./run.sh"
