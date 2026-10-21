#!/usr/bin/env bash
# Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
# All rights reserved.
#
# profile.sh — Linux perf profiles of the protocol benches, one node at a time.
#
#   tools/profile.sh [--backend B] [--label NAME] [--launch "PREFIX"] [--zones "central passenger"]
#                    [--only "bfv_seal bfv_openfhe ckks_seal ckks_openfhe ckks_openfhe_comp
#                            tfhe_flags tfhe_stress tfhe_n32_flags tfhe_n32_stress"]
#
# Every (bench, node) pair is one run under `perf record` (user-space cpu-clock, DWARF call
# graphs). The harness enables perf only while that node's steps of a measured round run
# (BLINDLOOP_PERF_CTL / BLINDLOOP_PERF_ZONE, harness.hpp): setup, key generation, warm-up and
# the other nodes stay out. The network emulation is off (--no-net): its peer processes
# would otherwise be sampled too, and its cost is reported by run.sh.
#
# Writes results/<label>/profile/<bench>.<node>.{self,incl,dso}.txt (perf report: self time
# per symbol, time including callees, self time per library) and the bench's console
# output; the perf.data files stay in profile-data/<label>/ (large, not in results).
# Needs perf, with perf_event_paranoid <= 2 (user-space profiling of one's own processes).
set -euo pipefail
# ckks_openfhe_comp: as in run.sh
CKKS_COMP="--scaling COMPOSITESCALINGAUTO --register-bits 30 --scaling-bits 40 --first-bits 42 --dnum 4"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BACKEND=stock
LABEL=""
LAUNCH=""
ZONES="central passenger"
ONLY="bfv_seal bfv_openfhe ckks_seal ckks_openfhe ckks_openfhe_comp tfhe_flags tfhe_stress tfhe_n32_flags tfhe_n32_stress"
while [ $# -gt 0 ]; do
	case "$1" in
		--backend) BACKEND="$2"; shift ;;
		--label) LABEL="$2"; shift ;;
		--launch) LAUNCH="$2"; shift ;;
		--zones) ZONES="$2"; shift ;;
		--only) ONLY="$2"; shift ;;
		-h|--help) sed -n '2,23p' "$0"; exit 0 ;;
		*) echo "profile.sh: unknown option $1 (see --help)" >&2; exit 2 ;;
	esac
	shift
done
command -v perf >/dev/null || { echo "profile.sh: perf not found" >&2; exit 1; }

SUFFIX="${ARM_CPU:+-$ARM_CPU}${BUILD_TAG:+-$BUILD_TAG}"
BIN="$REPO/build/$BACKEND$SUFFIX"
[ -f "$BIN/BUILD_INFO" ] || { echo "profile.sh: $BIN not built" >&2; exit 1; }
LABEL="${LABEL:-$(uname -n | cut -d. -f1)$SUFFIX}"
OUT="$REPO/results/$LABEL/profile"
DATA="$REPO/profile-data/$LABEL"
mkdir -p "$OUT" "$DATA"
cp "$BIN/BUILD_INFO" "$OUT/BUILD_INFO"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"

CTL="$(mktemp -u /tmp/blindloop-perf-ctl.XXXXXX)"
ACK="$(mktemp -u /tmp/blindloop-perf-ack.XXXXXX)"
mkfifo "$CTL" "$ACK"
trap 'rm -f "$CTL" "$ACK"' EXIT

{
	echo "label     $LABEL"
	echo "backend   $BACKEND"
	echo "host      $(uname -n) $(uname -s)/$(uname -m)"
	echo "launch    ${LAUNCH:-(none)}"
	echo "perf      $(perf --version)"
	echo "events    cpu-clock:u, DWARF call graphs (8 KiB stack)"
	echo "started   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUT/PROFILE_INFO"

# rounds and sampling rate per bench and node: enough samples (about 10-30k) in each profile
plan() {
	case "$1.$2" in
		bfv_seal.central) echo "3 99" ;;
		bfv_seal.*) echo "6 999" ;;
		bfv_openfhe.central) echo "30 499" ;;
		bfv_openfhe.*) echo "30 999" ;;
		ckks_*.central) echo "30 999" ;;
		ckks_*) echo "30 999" ;;
		tfhe_*stress.central) echo "4 499" ;;
		tfhe_*.central) echo "12 499" ;;
		tfhe_*) echo "12 999" ;;
	esac
}
args() {
	case "$1" in
		bfv_seal|bfv_openfhe|ckks_seal|ckks_openfhe) echo "$1" ;;
		ckks_openfhe_comp) echo "ckks_openfhe $CKKS_COMP" ;;
		tfhe_flags) echo "tfhe_openfhe --mode flags" ;;
		tfhe_stress) echo "tfhe_openfhe --mode stress" ;;
		tfhe_n32_flags) echo "tfhe_openfhe_n32 --mode flags" ;;
		tfhe_n32_stress) echo "tfhe_openfhe_n32 --mode stress" ;;
	esac
}

for b in $ONLY; do
	read -r exe rest <<< "$(args "$b")"
	[ -x "$BIN/$exe" ] || { echo "  $b: $exe not built, skipped"; continue; }
	for z in $ZONES; do
		read -r rounds freq <<< "$(plan "$b" "$z")"
		d="$DATA/$b.$z.data"
		printf '  %-16s %-9s ' "$b" "$z"
		t0=$SECONDS
		# shellcheck disable=SC2086
		if BLINDLOOP_PERF_CTL="$CTL,$ACK" BLINDLOOP_PERF_ZONE="$z" \
			perf record -q -e cpu-clock:u -F "$freq" --call-graph dwarf,8192 --control "fifo:$CTL,$ACK" -D -1 \
			-o "$d" -- $LAUNCH "$BIN/$exe" $rest --rounds "$rounds" --warmup 1 --no-net > "$OUT/$b.$z.txt" 2>&1; then
			perf report -i "$d" --no-children --sort sym -g none --stdio --percent-limit 0.1 > "$OUT/$b.$z.self.txt" 2>/dev/null
			perf report -i "$d" --children --sort sym -g none --stdio --percent-limit 0.5 > "$OUT/$b.$z.incl.txt" 2>/dev/null
			perf report -i "$d" --no-children --sort dso -g none --stdio > "$OUT/$b.$z.dso.txt" 2>/dev/null
			echo "ok ($((SECONDS - t0)) s, $(grep -m1 -o '[0-9]*K\? *of event' "$OUT/$b.$z.self.txt" | head -1 || true))"
		else
			echo "FAILED (see $OUT/$b.$z.txt)"
		fi
	done
done
echo "finished  $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUT/PROFILE_INFO"
