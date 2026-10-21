#!/usr/bin/env bash
# Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
# All rights reserved.
#
# run.sh — runs the blindloop benches of every built backend and writes the report.
#
#   ./run.sh [--backends "stock rvv-hexl"] [--rounds R] [--stress-rounds R] [--only "bfv_seal ..."]
#            [--label NAME] [--launch "PREFIX"] [--no-ntt]
#
#   --backends       default: every build/<backend>[-<ARM_CPU>][-<BUILD_TAG>] that build.sh produced
#   --rounds         measured rounds of the protocol benches (default 12, plus 1 warm-up:
#                    every case of the window-lift scenario once)
#   --stress-rounds  measured rounds of the TFHE stress mode (raw signals; default 12)
#   --only           run only these benches: zk_selftest bfv_seal bfv_openfhe ckks_seal
#                    ckks_openfhe tfhe_flags tfhe_stress tfhe_n32_flags tfhe_n32_stress
#                    ntt_seal ntt_openfhe
#   --label          results/<label>/ (default: the host name, + -<ARM_CPU> and -<BUILD_TAG> when set)
#   --launch         command prefix for every bench, e.g. "taskset -c 4-7" (one cluster of a
#                    big.LITTLE board) or the K3's A100 launcher
#   --no-ntt         skip the NTT microbenches
#
# Writes results/<label>/<backend>/<bench>.json (the protocol breakdown) and .txt (the
# console output), RUN_INFO, and results/<label>/REPORT.md (tools/report.py).
# Run on an otherwise idle machine: the benches time wall clock.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BACKENDS=""
ROUNDS=12
STRESS_ROUNDS=12
ONLY=""
LABEL=""
LAUNCH=""
NTT=1
while [ $# -gt 0 ]; do
	case "$1" in
		--backends) BACKENDS="$2"; shift ;;
		--rounds) ROUNDS="$2"; shift ;;
		--stress-rounds) STRESS_ROUNDS="$2"; shift ;;
		--only) ONLY="$2"; shift ;;
		--label) LABEL="$2"; shift ;;
		--launch) LAUNCH="$2"; shift ;;
		--no-ntt) NTT=0 ;;
		-h|--help) sed -n '2,23p' "$0"; exit 0 ;;
		*) echo "run.sh: unknown option $1 (see --help)" >&2; exit 2 ;;
	esac
	shift
done

# single-core nodes: one OpenMP thread unless the caller sets OMP_NUM_THREADS
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"

SUFFIX="${ARM_CPU:+-$ARM_CPU}${BUILD_TAG:+-$BUILD_TAG}"
if [ -z "$BACKENDS" ]; then
	for b in stock intel-hexl rvv-hexl; do
		[ -f "$REPO/build/$b$SUFFIX/BUILD_INFO" ] && BACKENDS="$BACKENDS $b"
	done
fi
[ -n "$BACKENDS" ] || { echo "run.sh: nothing built under build/ (run ./build.sh first)" >&2; exit 1; }
LABEL="${LABEL:-$(uname -n | cut -d. -f1)$SUFFIX}"
OUT="$REPO/results/$LABEL"
mkdir -p "$OUT"

cpu_model() {
	if [ "$(uname -s)" = "Darwin" ]; then sysctl -n machdep.cpu.brand_string
	else
		grep -m1 -E "^(model name|uarch|Model)" /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' || echo unknown
	fi
}
{
	echo "label     $LABEL"
	echo "host      $(uname -n) $(uname -s)/$(uname -m)"
	echo "cpu       $(cpu_model)"
	echo "launch    ${LAUNCH:-(none)}"
	echo "threads   OMP_NUM_THREADS=$OMP_NUM_THREADS"
	echo "rounds    $ROUNDS (TFHE stress $STRESS_ROUNDS), 1 warm-up"
	echo "started   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUT/RUN_INFO"

wanted() { [ -z "$ONLY" ] || [[ " $ONLY " == *" $1 "* ]]; }

# run_bench <backend dir> <out dir> <name> <binary> [args...]
run_bench() {
	local dir="$1" out="$2" name="$3" bin="$4"
	shift 4
	if [ ! -x "$dir/$bin" ]; then
		echo "  $name: $bin not built, skipped"
		return 0
	fi
	printf '  %-18s ' "$name"
	local t0=$SECONDS
	# shellcheck disable=SC2086
	if $LAUNCH "$dir/$bin" "$@" > "$out/$name.txt" 2>&1; then
		echo "ok ($((SECONDS - t0)) s)"
	else
		echo "FAILED (see $out/$name.txt)"
	fi
}

ZK_DONE=0
for b in $BACKENDS; do
	dir="$REPO/build/$b$SUFFIX"
	out="$OUT/$b"
	mkdir -p "$out"
	cp "$dir/BUILD_INFO" "$out/BUILD_INFO"
	echo "== $b ($(sed -n 's/^libraries *//p' "$dir/BUILD_INFO"))"
	if [ "$ZK_DONE" = "0" ] && wanted zk_selftest; then
		# backend-independent (no FHE): once per run
		run_bench "$dir" "$OUT" zk_selftest zk_selftest --rounds 20
		ZK_DONE=1
	fi
	P=(--rounds "$ROUNDS" --warmup 1)
	S=(--rounds "$STRESS_ROUNDS" --warmup 1)
	wanted bfv_seal && run_bench "$dir" "$out" bfv_seal bfv_seal "${P[@]}" --json "$out/bfv_seal.json"
	wanted bfv_openfhe && run_bench "$dir" "$out" bfv_openfhe bfv_openfhe "${P[@]}" --json "$out/bfv_openfhe.json"
	wanted ckks_seal && run_bench "$dir" "$out" ckks_seal ckks_seal "${P[@]}" --json "$out/ckks_seal.json"
	wanted ckks_openfhe && run_bench "$dir" "$out" ckks_openfhe ckks_openfhe "${P[@]}" --json "$out/ckks_openfhe.json"
	wanted tfhe_flags && run_bench "$dir" "$out" tfhe_flags tfhe_openfhe --mode flags "${P[@]}" --json "$out/tfhe_flags.json"
	wanted tfhe_stress && run_bench "$dir" "$out" tfhe_stress tfhe_openfhe --mode stress "${S[@]}" --json "$out/tfhe_stress.json"
	wanted tfhe_n32_flags && run_bench "$dir" "$out" tfhe_n32_flags tfhe_openfhe_n32 --mode flags "${P[@]}" --json "$out/tfhe_n32_flags.json"
	wanted tfhe_n32_stress && run_bench "$dir" "$out" tfhe_n32_stress tfhe_openfhe_n32 --mode stress "${S[@]}" --json "$out/tfhe_n32_stress.json"
	if [ "$NTT" = "1" ]; then
		wanted ntt_seal && run_bench "$dir" "$out" ntt_seal ntt_seal
		wanted ntt_openfhe && run_bench "$dir" "$out" ntt_openfhe ntt_openfhe
	fi
done
echo "finished  $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/RUN_INFO"

python3 "$REPO/tools/report.py" "$OUT"
echo "report: $OUT/REPORT.md"
