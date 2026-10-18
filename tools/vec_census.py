#!/usr/bin/env python3
# Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
# All rights reserved.
"""vec_census.py — counts the vector instructions in shared libraries or binaries.

    tools/vec_census.py LIB [LIB ...]

Disassembles each file (objdump -d) and reports, for AArch64 (NEON) or riscv64 (RVV):
all vector instructions, the arithmetic ones among them (no loads, stores, moves,
permutes or vsetvli), and the widening multiplies (umull/umull2, vwmulu). Used to check
an OPENFHE_N32_NOVEC=1 build: its arithmetic count must fall to (nearly) zero next to
the vectorised library, otherwise the compiler ignored the flags.
"""
import re
import subprocess
import sys

NEON_REG = re.compile(r"\bv\d+\.\d*[bhsd]\b")
NEON_NOT_ARITH = re.compile(
    r"^(ld[1-4]r?|st[1-4]|ldr|str|ldp|stp|ldur|stur|mov|movi|mvni|dup|ins|umov|smov|ext|"
    r"zip[12]|uzp[12]|trn[12]|tbl|tbx|rev\d*|fmov)$")
NEON_WMUL = re.compile(r"^umull2?$")
RVV_NOT_ARITH = re.compile(
    r"^(vset\w*|vl\w*|vs(e|se|ux|ox|\d)\w*|vmv\w*|vfmv\w*|vslide\w*|vrgather\w*|vcompress\w*|vid\.v)$")
RVV_WMUL = re.compile(r"^vwmulu\.")


def census(path):
    out = subprocess.run(["objdump", "-d", path], capture_output=True, text=True, check=True).stdout
    total = arith = wmul = 0
    head = out[:2000].lower()
    arch = "rvv" if "riscv" in head else "neon" if ("aarch64" in head or "arm64" in head) else None
    vreg = re.compile(r"\bv\d+\b")
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        mnem, ops = parts[-2].strip(), parts[-1]
        if not mnem or not vreg.search(ops) and not NEON_REG.search(ops):
            continue
        if arch == "neon":
            base = mnem.split(".")[0]          # LLVM objdump: umull.2d v0, v1, v2
            total += 1
            if not NEON_NOT_ARITH.match(base):
                arith += 1
            if NEON_WMUL.match(base):
                wmul += 1
        elif arch == "rvv" and re.match(r"^v[a-z]", mnem):
            total += 1
            if not RVV_NOT_ARITH.match(mnem):
                arith += 1
            if RVV_WMUL.match(mnem):
                wmul += 1
    return arch or "-", total, arith, wmul


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    print(f"{'file':60s} {'isa':5s} {'vector':>8s} {'arith':>8s} {'wmul':>6s}")
    for path in sys.argv[1:]:
        arch, total, arith, wmul = census(path)
        print(f"{path[-60:]:60s} {arch:5s} {total:8d} {arith:8d} {wmul:6d}")


if __name__ == "__main__":
    main()
