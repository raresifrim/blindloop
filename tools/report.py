#!/usr/bin/env python3
# Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
# All rights reserved.
#
"""report.py — turns one run.sh results directory into REPORT.md and summary.json.

    tools/report.py results/<label> [results/<label2> ...]

Reads <dir>/<backend>/<bench>.json (the harness breakdown), BUILD_INFO, RUN_INFO and
the .txt outputs of the microbenches. With several directories (e.g. one per board or
cluster), each gets its own report and the summary tables compare them side by side
in the first directory's parent as COMPARE.md.
"""
import json
import pathlib
import sys

BENCHES = [
    ("bfv_seal", "BFV, SEAL"),
    ("bfv_openfhe", "BFV, OpenFHE"),
    ("tfhe_flags", "TFHE flags, OpenFHE"),
    ("tfhe_stress", "TFHE stress, OpenFHE"),
    ("tfhe_n32_flags", "TFHE flags, OpenFHE NATIVE_SIZE=32"),
    ("tfhe_n32_stress", "TFHE stress, OpenFHE NATIVE_SIZE=32"),
]
BACKEND_ORDER = ["stock", "intel-hexl", "rvv-hexl"]
TOTALS = [("end_node", "= end-node total"), ("central_node", "= central-node total"),
          ("end_to_end", "= end to end")]


def ms(x):
    if x is None:
        return "–"
    if x >= 100:
        return f"{x:,.0f}"
    if x >= 1:
        return f"{x:.2f}"
    return f"{x:.3f}"


def info(path):
    out = {}
    if path.exists():
        for line in path.read_text().splitlines():
            k, _, v = line.partition(" ")
            out[k] = v.strip()
    return out


def load(d):
    backends = sorted((p.name for p in d.iterdir() if p.is_dir()),
                      key=lambda b: BACKEND_ORDER.index(b) if b in BACKEND_ORDER else 99)
    data = {}
    for b in backends:
        for name, _ in BENCHES:
            f = d / b / f"{name}.json"
            if f.exists():
                try:
                    data[(b, name)] = json.loads(f.read_text())
                except json.JSONDecodeError as e:
                    print(f"report.py: {f}: {e}", file=sys.stderr)
    return backends, data


def median(entry):
    return entry["stats"]["median_ms"] if entry.get("applicable") else None


def bench_table(name, backends, data):
    runs = [(b, data[(b, name)]) for b in backends if (b, name) in data]
    if not runs:
        return []
    base = runs[0][1]
    cols = [b for b, _ in runs]
    speed = len(runs) > 1 and runs[0][0] == "stock"
    head = "| node | step | " + " | ".join(f"{c} (ms)" for c in cols)
    head += " | " + " | ".join(f"{c} speed-up" for c in cols[1:]) if speed else ""
    lines = [head + " |", "|" + "---|" * (2 + len(cols) + (len(cols) - 1 if speed else 0))]

    def row(node, label, vals):
        cells = [ms(v) for v in vals]
        if speed:
            s0 = vals[0]
            cells += [f"{s0 / v:.2f}×" if s0 and v else "–" for v in vals[1:]]
        lines.append(f"| {node} | {label} | " + " | ".join(cells) + " |")

    for node in ("end", "central"):
        for i, st in enumerate(base["steps"]):
            if st["node"] != node:
                continue
            vals = [median(r["steps"][i]) for _, r in runs]
            if all(v is None for v in vals):
                continue
            row(node, st["label"], vals)
        key, label = TOTALS[0] if node == "end" else TOTALS[1]
        row(node, f"**{label}**", [r["totals"][key]["median_ms"] for _, r in runs])
    row("both", f"**{TOTALS[2][1]}**", [r["totals"]["end_to_end"]["median_ms"] for _, r in runs])
    lines.append("")
    lines.append("Correct rounds: " + ", ".join(f"{b} {r['correct']}/{r['checked']}" for b, r in runs) +
                 f"; medians of {base['rounds_measured']} measured rounds.")
    lines.append("")
    params = ", ".join(f"{k} {v}" for k, v in base["params"].items() if k != "backend")
    lines.append(f"Parameters ({base['library']}): {params}.")
    if base.get("sizes_bytes"):
        lines.append("")
        lines.append("Sizes: " + ", ".join(f"{k} {v:,.0f} B" for k, v in base["sizes_bytes"].items()) + ".")
    notes = base.get("notes") or []
    if notes:
        lines.append("")
        lines += [f"- {n}" for n in notes]
    return lines


def summary_rows(backends, data):
    rows = []
    for name, title in BENCHES:
        for b in backends:
            r = data.get((b, name))
            if r:
                t = r["totals"]
                rows.append((title, b, t["end_node"]["median_ms"], t["central_node"]["median_ms"],
                             t["end_to_end"]["median_ms"], f"{r['correct']}/{r['checked']}"))
    return rows


def report(d):
    backends, data = load(d)
    run = info(d / "RUN_INFO")
    md = [f"# blindloop: {run.get('label', d.name)}", ""]
    for k in ("host", "cpu", "launch", "threads", "rounds", "started", "finished"):
        if k in run:
            md.append(f"- **{k}**: {run[k]}")
    md.append("")
    md.append("| backend | libraries | compiler | flags | suite |")
    md.append("|---|---|---|---|---|")
    for b in backends:
        bi = info(d / b / "BUILD_INFO")
        md.append(f"| {b} | {bi.get('libraries', '?')} | {bi.get('compiler', '?')} | "
                  f"`{bi.get('flags', '?')}` | {bi.get('suite', '?')} |")
    md += ["", "## Summary (median ms per round)", "",
           "| bench | backend | end node | central node | end to end | correct |", "|---|---|---|---|---|---|"]
    rows = summary_rows(backends, data)
    for title, b, e, c, t, ok in rows:
        md.append(f"| {title} | {b} | {ms(e)} | {ms(c)} | {ms(t)} | {ok} |")
    for name, title in BENCHES:
        t = bench_table(name, backends, data)
        if t:
            md += ["", f"## {title}", ""] + t
    zk = d / "zk_selftest.txt"
    if zk.exists():
        md += ["", "## ZK proofs and signatures (zk_selftest)", "", "```", zk.read_text().rstrip(), "```"]
    for micro in ("ntt_seal", "ntt_openfhe"):
        for b in backends:
            f = d / b / f"{micro}.txt"
            if f.exists():
                md += ["", f"## {micro} ({b})", "", "```", f.read_text().rstrip(), "```"]
    (d / "REPORT.md").write_text("\n".join(md) + "\n")
    summary = {"run": run, "backends": {b: info(d / b / "BUILD_INFO") for b in backends},
               "benches": {f"{b}/{n}": r for (b, n), r in data.items()}}
    (d / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    return run.get("label", d.name), rows


def compare(dirs, results):
    out = dirs[0].parent / "COMPARE.md"
    md = ["# blindloop: comparison (median ms, end to end)", ""]
    labels = [l for l, _ in results]
    keys = []
    for _, rows in results:
        for title, b, *_ in rows:
            if (title, b) not in keys:
                keys.append((title, b))
    md.append("| bench | backend | " + " | ".join(labels) + " |")
    md.append("|---|---|" + "---|" * len(labels))
    for title, b in keys:
        cells = []
        for _, rows in results:
            v = next((r[4] for r in rows if r[0] == title and r[1] == b), None)
            cells.append(ms(v))
        md.append(f"| {title} | {b} | " + " | ".join(cells) + " |")
    out.write_text("\n".join(md) + "\n")
    print(f"comparison: {out}")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    dirs = [pathlib.Path(a) for a in sys.argv[1:]]
    results = [report(d) for d in dirs]
    if len(dirs) > 1:
        compare(dirs, results)


if __name__ == "__main__":
    main()
