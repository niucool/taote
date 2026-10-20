#!/usr/bin/env python3
"""Run one directory of samples through taote's trace tool and count outcomes.

This is the corpus sweep the scoreboard quotes ("97 exit 0" for the API sample
set, "N/32 exit 0" for the PMA corpus). Every run is bounded twice over: the
guest gets a deterministic instruction budget (`--count`), and the *process* is
wrapped in a wall-clock timeout, because a guest can block inside a host call
where no guest instruction retires (a Windows `accept()` on a real host socket
does exactly that). Such a run is reported as `blocked`, never as a failure and
never as a divergence, and it can therefore never stall the sweep.

Each run gets its own trace file: reusing one path meant a killed run re-read the
previous sample's JSON and misattributed its result.

Usage:
  sweep_samples.py --dir /path/to/bins [--timeout 30] [--count 40000000]
                   [--taote-trace build/tools/parity_trace] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SUFFIXES = (".exe", ".dll", ".sys", ".exe_", ".dll_", ".sys_")


def run_one(trace: Path, sample: Path, count: int, wall_timeout: int, workdir: Path):
    out = workdir / (sample.name.replace(os.sep, "_") + ".json")
    cmd = [str(trace), str(sample), "--out", str(out)]
    if count:
        cmd += ["--count", str(count)]
    try:
        subprocess.run(cmd, capture_output=True, timeout=wall_timeout)
    except subprocess.TimeoutExpired:
        # the guest is stuck in a host call: not a divergence, not a failure
        return {"sample": sample.name, "status": "blocked", "exit": None}
    if not out.exists():
        return {"sample": sample.name, "status": "no-trace", "exit": None}
    try:
        raw = json.loads(out.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {"sample": sample.name, "status": "no-trace", "exit": None}
    exit_code = raw.get("exit_code")
    return {
        "sample": sample.name,
        "status": "exit0" if exit_code == 0 else "failed",
        "exit": exit_code,
        "error": raw.get("error") or "",
        "calls": len(raw.get("apis") or []),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="sweep a sample directory through taote")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--taote-trace", default=str(Path(__file__).resolve().parent.parent / "build" / "tools" / "parity_trace"))
    ap.add_argument("--count", type=int, default=40000000, help="deterministic instruction budget")
    ap.add_argument("--timeout", type=int, default=30, help="wall-clock seconds per sample")
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv)

    trace = Path(args.taote_trace)
    if not trace.exists():
        print(f"sweep: build the trace tool first ({trace})", file=sys.stderr)
        return 77
    samples = sorted(p for p in Path(args.dir).iterdir() if p.suffix.lower() in SUFFIXES)
    if not samples:
        print(f"sweep: no samples in {args.dir}", file=sys.stderr)
        return 77

    results = []
    with tempfile.TemporaryDirectory(prefix="taote_sweep_") as tmp:
        workdir = Path(tmp)
        for sample in samples:
            result = run_one(trace, sample, args.count, args.timeout, workdir)
            results.append(result)
            if result["status"] != "exit0":
                print(f"  {result['status']:8s} {result['sample']} {result['exit']} {result.get('error', '')[:60]}")

    counts = {}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    summary = {
        "dir": str(Path(args.dir).resolve()),
        "total": len(results),
        "counts": counts,
        "results": results,
    }
    if args.json:
        Path(args.json).write_text(json.dumps(summary, indent=1))
    print("sweep: " + "  ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
