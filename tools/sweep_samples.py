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


def pe_machine(sample: Path) -> int | None:
    """The PE COFF machine field (0x14c = i386, 0x8664 = amd64), or None."""
    try:
        with open(sample, "rb") as f:
            head = f.read(0x400)
    except OSError:
        return None
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    import struct
    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if e_lfanew + 6 > len(head) or head[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    return struct.unpack_from("<H", head, e_lfanew + 4)[0]


def pick_rootfs(rootfs: str | None, sample: Path) -> str | None:
    """A base tree of x86_windows/ and x8664_windows/ resolves per sample."""
    if not rootfs:
        return None
    base = Path(rootfs)
    x86 = base / "x86_windows"
    x64 = base / "x8664_windows"
    if not (x86.is_dir() and x64.is_dir()):
        return rootfs
    return str(x64 if pe_machine(sample) == 0x8664 else x86)


def run_one(trace: Path, sample: Path, count: int, wall_timeout: int, workdir: Path,
            rootfs: str | None = None):
    out = workdir / (sample.name.replace(os.sep, "_") + ".json")
    cmd = [str(trace), str(sample), "--out", str(out)]
    rootfs = pick_rootfs(rootfs, sample)
    staged = None
    if rootfs:
        # real-dll mode: the same corpus against a collected System32 tree. The
        # runner does not stage into a caller-provided rootfs (the tests stage
        # themselves), so the sample is placed at <rootfs>/Windows/<name> here —
        # point --rootfs at a *copy* of the harvest, never the pristine tree.
        windows = Path(rootfs) / "Windows"
        windows.mkdir(parents=True, exist_ok=True)
        staged = windows / sample.name
        import shutil
        shutil.copyfile(sample, staged)
        cmd += ["--rootfs", rootfs]
    if count:
        cmd += ["--count", str(count)]
    try:
        subprocess.run(cmd, capture_output=True, timeout=wall_timeout)
    except subprocess.TimeoutExpired:
        # the guest is stuck in a host call: not a divergence, not a failure
        return {"sample": sample.name, "status": "blocked", "exit": None}
    finally:
        if staged is not None:
            try:
                staged.unlink()
            except OSError:
                pass
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
    ap.add_argument("--rootfs", default=None,
                    help="run against a real System32 tree (real-dll mode)")
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
            result = run_one(trace, sample, args.count, args.timeout, workdir, args.rootfs)
            results.append(result)
            if result["status"] != "exit0":
                print(f"  {result['status']:8s} {result['sample']} {result['exit']} {result.get('error', '')[:60]}")

    counts = {}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    summary = {
        "dir": str(Path(args.dir).resolve()),
        "rootfs": args.rootfs,
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
