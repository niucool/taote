#!/usr/bin/env python3
"""ref_parity.py - which of taote's misses does the REFERENCE actually solve?

taote's remaining headroom is not "the reference's 1996 all-three" (that number
is a corpus score, not a per-row oracle). The useful question is per row: for
every row taote fails, does pegasus produce the original entry point? Those rows
are the *parity targets* - the only misses where a ported mechanism is known to
exist. Rows both engines fail are not worth a mechanism (Themida, Yoda-Protector).

Usage:
  python3 tools/ref_parity.py --manifest runs/r117.json \
      --results runs/r117_rep.json --pegasus ~/source/jim/pegasus/build/cli/pegasus-cli \
      --outdir /tmp/refpar [--par 6] [--json out.json]

--results is what tools/unpack_report.py wrote; --manifest supplies the full
sample paths (the report keys rows by basename). Each pegasus run is captured to
<outdir>/logs/<sample>.json and its LAST "oep_rva" is compared with the original
EP RVA from the results file (pegasus reports an RVA; taote's orig_ep is an RVA).
"""
import argparse
import json
import os
import re
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor


def pegasus_oep_rva(path):
    try:
        text = open(path, errors="ignore").read()
    except OSError:
        return None
    found = re.findall(r'"oep_rva":\s*(-?\d+)', text)
    return int(found[-1]) if found else None


def makes_image(path):
    try:
        return '"image":' in open(path, errors="ignore").read()
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--results", required=True)
    ap.add_argument("--pegasus", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--par", type=int, default=6)
    ap.add_argument("--json")
    args = ap.parse_args()

    full = {r["sample"].split("/")[-1]: r["sample"]
            for r in json.load(open(args.manifest))["runs"]}
    rows = json.load(open(args.results))["results"]
    old = {r["sample"].split("/")[-1]: r for r in rows}
    passed = lambda r: r["valid_pe"] and r.get("oep_exact") and r["imports"]
    misses = [s for s, r in old.items() if not passed(r)]

    os.makedirs(os.path.join(args.outdir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(args.outdir, "out"), exist_ok=True)

    def run(name):
        sample = full[name]
        log = os.path.join(args.outdir, "logs", name + ".json")
        if os.path.exists(log) and '"error"' not in open(log, errors="ignore").read(200):
            return name
        cmd = ["taskset", "-c", str(hash(sample) % max(1, (os.cpu_count() or 4) - 2)),
               "timeout", "300", args.pegasus, "-t", sample,
               "--unpack", "--unpack-output", os.path.join(args.outdir, "out")]
        proc = subprocess.run(cmd, capture_output=True)
        open(log, "wb").write(proc.stdout + proc.stderr)
        return name

    with ThreadPoolExecutor(max_workers=args.par) as ex:
        list(ex.map(run, misses))

    solved = Counter()
    total = Counter()
    detail = []
    for name in misses:
        r = old[name]
        log = os.path.join(args.outdir, "logs", name + ".json")
        oep = pegasus_oep_rva(log)
        orig = r.get("orig_ep") or 0
        ok = oep is not None and orig and oep == orig
        total[r["family"]] += 1
        if ok:
            solved[r["family"]] += 1
            detail.append({"family": r["family"], "sample": name, "orig_ep": orig,
                           "ref_oep_rva": oep, "code_sim": r.get("code_sim"),
                           "imp_recall": r.get("imp_recall"),
                           "image": makes_image(log)})

    print("taote misses: %d   reference solves: %d" % (len(misses), len(detail)))
    for fam, n in solved.most_common():
        print("  %-18s %3d of %3d" % (fam, n, total[fam]))
    unsolved = [(f, total[f] - solved[f]) for f in total if total[f] > solved[f]]
    if unsolved:
        print("both engines fail (no mechanism to port):")
        for fam, n in sorted(unsolved, key=lambda x: -x[1]):
            print("  %-18s %3d" % (fam, n))
    if args.json:
        json.dump(detail, open(args.json, "w"), indent=1)
        print("wrote", args.json)


if __name__ == "__main__":
    main()
