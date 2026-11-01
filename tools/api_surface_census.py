#!/usr/bin/env python3
"""Census: which of a corpus's original imports does taote's stub surface lack?

For every (dll, function) pair the *originals* import, ask whether taote could seed
it into a stub dll (api_db + the CRT-family union) - i.e. whether a packer that
resolves imports by walking the module's own export names can find it.

Usage:
    tools/api_surface_census.py <manifest.json> [--top N]

The manifest is a harness manifest ({"runs": [{sample, orig, ...}]}); `orig` is the
not-packed original each run is graded against. Output is ranked by how many rows
carry a missing name, which is the number of rows a surface fix could touch.

Why it exists: round 198's CRT-family fix (msvcrt had ZERO names in api_db) was found
this way, and round 199 used it to rule out the remaining gaps as third-party DLLs
(gimp/gtk/glib, msvcp60) that no SDK database can cover.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import unpack_report as U  # the grader's own PE parser, so the two never disagree

API_DB = os.path.join(HERE, "..", "qiling", "unpack", "api_db.inc")


def load_api_db():
    rows = []
    with open(API_DB, encoding="ascii") as f:
        for line in f:
            line = line.strip()
            if not line.startswith('"'):
                continue
            body = line.strip('"').replace("\\t", "\t").replace("\\n", "")
            if "\t" in body:
                rows.append(body.split("\t", 1))
    return rows


def is_crt_family(n: str) -> bool:
    """Mirror of api_db.cpp's is_crt_family (the shipped family union)."""
    return (n in ("crtdll", "ucrt", "ucrtbase", "msvcrt", "msvcr")
            or n.startswith("msvcr") or n.startswith("api-ms-win-crt"))


def build_surface(rows):
    owned = defaultdict(set)
    for name, owners in rows:
        for d in owners.split(","):
            if d:
                owned[d].add(name)
    crt = set().union(*[v for k, v in owned.items() if is_crt_family(k)]) if owned else set()

    def surface(dll: str) -> set[str]:
        b = dll.lower()
        if b.endswith(".dll"):
            b = b[:-4]
        return crt if is_crt_family(b) else owned.get(b, set())
    return surface


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("--top", type=int, default=16)
    args = ap.parse_args(argv)

    surface = build_surface(load_api_db())
    runs = json.load(open(args.manifest))["runs"]
    pairs = Counter()
    rows_by_dll = Counter()
    missing = defaultdict(Counter)
    for r in runs:
        try:
            pe = U.parse_pe(r["orig"])
            if pe is None:
                continue
            imps = U.import_names(pe)
        except Exception:
            continue
        seen = set()
        for dll, name in imps:
            D = dll.upper()
            pairs[D] += 1
            if D not in seen:
                seen.add(D)
                rows_by_dll[D] += 1
            if name.startswith("#"):
                continue  # ordinal import: a name surface cannot help
            if name.lower() not in {x.lower() for x in surface(dll)}:
                missing[D][name] += 1

    print(f"{'dll':24s}{'rows':>6s}{'pairs':>9s}{'uniqMiss':>9s}  top missing (row count)")
    for D in sorted(missing, key=lambda d: -sum(missing[d].values()))[:args.top]:
        ex = ", ".join(f"{n}({c})" for n, c in missing[D].most_common(3))
        print(f"{D:24s}{rows_by_dll[D]:6d}{pairs[D]:9d}{len(missing[D]):9d}  {ex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
