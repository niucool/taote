#!/usr/bin/env python3
"""Write the minimal registry hives the reference emulator insists on at startup.

The Python qiling builds a `RegistryManager` for every Windows target and, unless
the target is raw code, raises `QlErrorFileNotFound` when
`<rootfs>/Windows/registry` (or one of the hives inside it) is missing:

    qiling.exception.QlErrorFileNotFound: Windows registry directory not found

The real hives (SOFTWARE, SYSTEM, SAM, SECURITY, HARDWARE, NTUSER.DAT) come from
a Windows installation and are not redistributable, so this writes a valid but
empty hive in each name: a `regf` base block, one `hbin`, and a single root key
with no subkeys and no values. That is enough for a differential run - every
registry read on either side answers "not found", which is the value both
emulators agree on for an unseeded hive.

Usage:
    mkreg_hive.py OUTDIR
"""

from __future__ import annotations

import os
import struct
import sys

HIVES = ("SOFTWARE", "SYSTEM", "SAM", "SECURITY", "HARDWARE", "NTUSER.DAT")
BLOCK = 0x1000


def hive(root_name: str = "ROOT") -> bytes:
    # --- the root key cell (an 'nk' record) --------------------------------
    name = root_name.encode("ascii")          # KEY_COMP_NAME => ASCII key name
    nk = bytearray(b"nk")
    nk += struct.pack("<H", 0x2C)             # flags: KEY_HIVE_ENTRY | KEY_COMP_NAME
    nk += b"\0" * 8                           # last written (FILETIME)
    nk += struct.pack("<I", 0)                # access bits
    nk += struct.pack("<I", 0xFFFFFFFF)       # parent
    nk += struct.pack("<II", 0, 0)            # subkey count, volatile subkey count
    nk += struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)   # subkey list, volatile list
    nk += struct.pack("<I", 0)                # value count
    nk += struct.pack("<I", 0xFFFFFFFF)       # value list offset
    nk += struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)   # security, class name
    nk += struct.pack("<IIII", 0, 0, 0, 0)    # largest subkey name/class, value name/data
    nk += struct.pack("<I", 0)                # work var
    nk += struct.pack("<HH", len(name), 0)    # key name length, class name length
    nk += name
    nk += b"\0" * ((-len(nk)) % 8)
    cell = struct.pack("<i", -(len(nk) + 4)) + bytes(nk)

    # --- one hbin holding just that cell ----------------------------------
    hbin = bytearray(b"hbin" + struct.pack("<II", 0, BLOCK) + b"\0" * 20)  # 32-byte header
    hbin += cell
    hbin += b"\0" * (BLOCK - len(hbin))

    # --- the base block ----------------------------------------------------
    base = bytearray(BLOCK)
    base[0:4] = b"regf"
    struct.pack_into("<II", base, 4, 1, 1)        # primary/secondary sequence numbers
    struct.pack_into("<Q", base, 12, 0)           # last written
    struct.pack_into("<II", base, 20, 1, 5)       # major/minor version
    struct.pack_into("<II", base, 28, 0, 1)       # file type, file format
    struct.pack_into("<I", base, 36, 0x20)        # root cell offset (past the 32-byte hbin header)
    struct.pack_into("<I", base, 40, len(hbin))   # hive bins data size
    struct.pack_into("<I", base, 44, 1)           # clustering factor
    checksum = 0
    for i in range(0, 508, 4):
        checksum ^= struct.unpack_from("<I", base, i)[0]
    struct.pack_into("<I", base, 508, checksum)

    return bytes(base) + bytes(hbin)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    out = argv[0]
    os.makedirs(out, exist_ok=True)
    for name in HIVES:
        with open(os.path.join(out, name), "wb") as f:
            f.write(hive())
    print(f"mkreg_hive: wrote {len(HIVES)} hives in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
