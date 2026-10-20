#!/usr/bin/env python3
"""Run one PE under the reference implementation and emit its normalized trace.

This is the reference side of tools/parity_vs_qiling.py. It is deliberately thin:
create a `Qiling`, disable the emulator's own logging, capture the guest stdout,
run, and dump what the reference observed as JSON on stdout:

    { "emulator": "qiling", "sample": ..., "image_base": ...,
      "apis": [ { "position": 0, "name": "GetStdHandle", "retval": 0x...,
                  "retaddr": 0x... } ],
      "stdout": "...", "strings": [...], "exit_code": ...,
      "error": "Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)" }

The dispatch records come straight from the reference's own `QlOsStats`
(`ql.os.stats.syscalls`, ordered by the `position` counter that
`log_api_call` maintains), which is the same surface taote's `QlOsStats`
mirrors - so the two traces are directly comparable.

Run it with a Python that has the reference's dependencies installed
(unicorn, capstone, pefile, python-registry, keystone-engine):

    python qiling_reference_runner.py --qiling REPO --sample FILE --rootfs DIR
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import traceback


class LogCapture(logging.Handler):
    """Collect the reference's own log records (the unimplemented-api warnings)."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append((record.levelname, record.getMessage()))

    def unimplemented(self):
        out = set()
        for level, message in self.records:
            if level != "WARNING":
                continue
            match = re.match(r"api (\S+) \((\S+)\) is not implemented", message)
            if match:
                out.add(match.group(1))
        return sorted(out)

    def warnings(self):
        return [message for level, message in self.records if level in ("WARNING", "ERROR")]


class Capture:
    """A minimal `ql.os.stdout` replacement that keeps the guest bytes."""

    def __init__(self):
        self.data = bytearray()

    def write(self, blob):
        if isinstance(blob, str):
            blob = blob.encode("utf-8", "replace")
        self.data += blob
        return len(blob)

    def flush(self):
        pass

    def fileno(self):
        return 1

    def close(self):
        pass

    def text(self) -> str:
        # the guest renders CP1252-ish bytes; utf-8 with replacement keeps the
        # trace compare readable and stable
        return self.data.decode("utf-8", "replace")


def to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--qiling", required=True, help="path to the reference qiling checkout")
    ap.add_argument("--sample", required=True)
    ap.add_argument("--rootfs", required=True)
    ap.add_argument("--argv", nargs="*", default=[])
    ap.add_argument("--count", type=int, default=0, help="instruction budget (0 = none)")
    ap.add_argument("--timeout", type=int, default=0, help="seconds (0 = none)")
    ap.add_argument("--out", default=None, help="write the JSON here instead of stdout")
    ap.add_argument("--dump-images", default=None,
                    help="write the loader's image table and command line before the run")
    ap.add_argument("--dump-heap", default=None,
                    help="write the heap chunk table (address size state) before the run")
    ap.add_argument("--mem-watch", nargs=3, default=None,
                    metavar=("FILE", "BEGIN", "SIZE"),
                    help="log guest writes into [BEGIN, BEGIN+SIZE) as pc addr size value")
    ap.add_argument("--code-trace", default=None, help="log (pc, size) per executed instruction here")
    ap.add_argument("--code-trace-range", nargs=2, type=lambda v: int(v, 0), default=None,
                    metavar=("BEGIN", "END"), help="only log pcs inside [BEGIN, END)")
    args = ap.parse_args(argv)

    sys.path.insert(0, os.path.abspath(args.qiling))

    from qiling import Qiling
    from qiling.const import QL_VERBOSE

    capture = Capture()
    log_capture = LogCapture()
    # the reference logs through ``logging.getLogger(f'qiling{QL_INSTANCE_ID}')``;
    # attach at the root so any per-instance logger is caught
    logging.getLogger().addHandler(log_capture)
    logging.getLogger().setLevel(logging.DEBUG)
    result = {
        "emulator": "qiling",
        "sample": os.path.basename(args.sample),
        "apis": [],
        "stdout": "",
        "strings": [],
        "exit_code": None,
        "image_base": None,
        "error": None,
        "traceback": None,
        "unsupported": 0,
        "unimplemented": [],
        "warnings": [],
    }

    ql = None
    try:
        ql = Qiling([args.sample] + list(args.argv), args.rootfs, verbose=QL_VERBOSE.DISABLED)
        ql.os.stdout = capture

        # the instance logger does not propagate and its name is derived from a
        # global counter, so attach the capture to the instance's own logger
        # QL_VERBOSE.DISABLED parks the instance logger at CRITICAL, which
        # filters the "api X is not implemented" warnings out before any handler
        # sees them; the differential needs exactly those
        ql.log.setLevel(logging.DEBUG)
        ql.log.addHandler(log_capture)
        if args.dump_images:
            with open(args.dump_images, "w") as di:
                for img in ql.loader.images:
                    di.write("%x %s\n" % (img.base, img.path))
                di.write("cmdline '%s'\n" % ql.loader.cmdline.decode("latin-1").replace("'", ""))

        if args.dump_heap:
            heap = ql.os.heap
            with open(args.dump_heap, "w") as dh:
                dh.write("start %x\n" % heap.start_address)
                for chunk in heap.chunks:
                    try:
                        raw = ql.mem.read(chunk.address, min(chunk.size, 64))
                    except Exception:
                        raw = b""
                    text = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in raw)
                    dh.write("%x %d %s %s\n" % (chunk.address, chunk.size, "inuse" if chunk.inuse else "free", text))

        if args.mem_watch:
            path, begin, size = args.mem_watch
            begin, size = int(begin, 0), int(size, 0)
            sink2 = open(path, "w")

            def _watch(ql_, access, address, size_, value):
                if address + size_ > begin and address < begin + size:
                    sink2.write("%x %x %d %x\n" % (ql_.arch.regs.read("eip"), address, size_, value))
                    sink2.flush()

            ql.hook_mem_write(_watch)

        if args.code_trace:
            begin, end = (args.code_trace_range or (0, 0))
            sink = open(args.code_trace, "w")

            def _log(ql_, address, size):  # the reference passes (ql, address, size)
                if address >= begin and (not end or address < end):
                    try:
                        sp = ql_.arch.regs.read("esp")
                    except Exception:
                        sp = 0
                    sink.write("%x %d %x\n" % (address, size, sp))
                    sink.flush()

            ql.hook_code(_log)

        ql.timeout = args.timeout or 0
        ql.count = args.count or 0

        ql.run()
        result["exit_code"] = ql.os.exit_code
    except BaseException as ex:                       # the reference raises UcError, QlError*, ...
        result["error"] = str(ex) or ex.__class__.__name__
        result["traceback"] = traceback.format_exc(limit=6)
    finally:
        result["stdout"] = capture.text()
        result["unimplemented"] = log_capture.unimplemented()
        result["warnings"] = log_capture.warnings()[:64]

    if ql is not None:
        try:
            stats = ql.os.stats
            records = []
            for name, calls in stats.syscalls.items():
                for call in calls:
                    records.append(
                        {
                            "position": call.get("position"),
                            "name": name,
                            "retval": to_int(call.get("retval")),
                            "retaddr": to_int(call.get("retaddr")),
                            "address": to_int(call.get("address")),
                        }
                    )
            records.sort(key=lambda r: (r["position"] is None, r["position"]))
            result["apis"] = records
            result["strings"] = sorted(str(s) for s in stats.strings.keys())
            result["image_base"] = to_int(getattr(ql.loader, "pe_image_address", None))
            if result["exit_code"] is None:
                result["exit_code"] = to_int(getattr(ql.os, "exit_code", None))
        except Exception:
            result["traceback"] = traceback.format_exc(limit=6)

    text = json.dumps(result, default=str)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
