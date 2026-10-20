#!/usr/bin/env python3
"""Synthesize the import-stub DLLs the reference emulator needs to dispatch imports.

The Python reference qiling loads Windows system DLLs as *file images* from the
rootfs (`<rootfs>/Windows/System32/*.dll`): an import is resolved by mapping the
DLL, reading its export table, and pointing the IAT slot at the exported code.
Those DLL images are only obtainable on a Windows host (`dllscollector.bat`, see
qiling's CI), so on a Linux host every import of every sample stays unresolved and
the guest walks off into address 0.

taote is not affected because its loader synthesizes the same stub DLLs in memory
(one `ret` cell per exported name, plus an export table naming it). This module
does the same thing on disk, so the reference gets a rootfs it can dispatch from:

    kernel32.dll: export table {Sleep -> rva 0x1000, GetStdHandle -> 0x1010, ...}
                  .text: 16-byte cells, each 0xC3 ('ret') followed by int3 padding

The cells are never executed by either emulator - each one's API hook fires on the
call and answers through the calling convention - so their content only has to be
the same shape on both sides. That keeps the differential about *handler semantics*
(which is what PLAN_PARITY Phase 1.9 compares) rather than about stub code.

Usage:
    stub_dlls.py --out DIR [--machine x86|x64] [--from-pe FILE ...]

With no --from-pe the export set is a fixed sanity list (kernel32!ExitProcess,
msvcrt!printf). With --from-pe each PE's import table contributes its dll -> names
map, which is how the parity driver seeds a rootfs for a whole corpus.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

# ---------------------------------------------------------------------------
# a minimal PE writer: one .text of `ret` cells + one .edata export directory
# ---------------------------------------------------------------------------

CELL_SIZE = 0x10            # one stub cell per exported name
SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200
IMAGE_BASE_X86 = 0x10000000
IMAGE_BASE_X64 = 0x180000000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def build_stub_pe(dll_name: str, exports, machine: str = "x86") -> bytes:
    """Render a PE32/PE32+ DLL that exports every name in `exports`."""

    names = sorted({str(n) for n in exports if n})
    cells = max(len(names), 1)   # the .text always holds at least one cell

    text_rva = SECTION_ALIGN
    text_size = cells * CELL_SIZE
    edata_rva = _align(text_rva + text_size, SECTION_ALIGN)

    # --- .edata layout -----------------------------------------------------
    # IMAGE_EXPORT_DIRECTORY (40 bytes), then AddressOfFunctions/Names/Ordinals,
    # then the module name and the export names.
    export_dir_size = 40
    funcs_off = export_dir_size
    name_ptrs_off = funcs_off + 4 * cells
    ordinals_off = name_ptrs_off + 4 * cells
    strings_off = ordinals_off + 2 * cells

    strings = bytearray()
    dll_name_off = 0
    strings += dll_name.encode("ascii") + b"\0"
    name_offsets = []
    for name in names:
        name_offsets.append(len(strings))
        strings += name.encode("ascii") + b"\0"
    strings += b"\0" * ((-len(strings)) % 4)

    edata = bytearray()
    edata += struct.pack(
        "<IIHHIIIIIII",
        0,                      # Characteristics
        0,                      # TimeDateStamp
        0,                      # MajorVersion
        0,                      # MinorVersion
        dll_name_off,           # Name RVA (patched below, relative to .edata)
        1,                      # Base
        len(names),             # NumberOfFunctions (0 exports => no symbols at all)
        len(names),             # NumberOfNames
        edata_rva + funcs_off,       # AddressOfFunctions (RVAs, not section offsets)
        edata_rva + name_ptrs_off,   # AddressOfNames
        edata_rva + ordinals_off,    # AddressOfNameOrdinals
    )
    for i in range(cells):
        edata += struct.pack("<I", text_rva + i * CELL_SIZE)
    for i, off in enumerate(name_offsets):
        edata += struct.pack("<I", edata_rva + strings_off + off)
    for i in range(len(names)):
        edata += struct.pack("<H", i)
    for i in range(len(names), cells):
        edata += struct.pack("<H", i)
    # module name RVA is relative to the image, and the string sits at strings_off
    struct.pack_into("<I", edata, 12, edata_rva + strings_off + dll_name_off)
    edata += strings

    text = bytearray()
    for i in range(cells):
        text += b"\xc3" + b"\xcc" * (CELL_SIZE - 1)     # ret, then int3 padding
    text += b"\xcc" * (text_size - len(text))

    def section(name: str, rva: int, data: bytes, characteristics: int):
        return {
            "name": name,
            "rva": rva,
            "data": bytes(data),
            "raw_size": _align(len(data), FILE_ALIGN),
            "characteristics": characteristics,
        }

    sections = [
        section(".text", text_rva, text, 0x60000020),    # code | execute | read
        section(".edata", edata_rva, edata, 0x40000040),  # initialized data | read
    ]

    # raw data is laid out from the first section's file offset upward
    raw_cursor = FILE_ALIGN
    for s in sections:
        s["raw_ptr"] = raw_cursor
        s["data"] = s["data"] + b"\0" * (s["raw_size"] - len(s["data"]))
        raw_cursor += s["raw_size"]

    size_of_image = _align(edata_rva + len(edata), SECTION_ALIGN)
    size_of_headers = FILE_ALIGN

    # --- headers -----------------------------------------------------------
    dos = bytearray(b"\0" * 64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack(
        "<HHIIIHH",
        0x14C if machine == "x86" else 0x8664,   # Machine
        len(sections),                            # NumberOfSections
        0,                                        # TimeDateStamp
        0,                                        # PointerToSymbolTable
        0,                                        # NumberOfSymbols
        0xE0,                                     # SizeOfOptionalHeader
        0x2102,                                   # DLL | EXECUTABLE_IMAGE | 32BIT_MACHINE
    )
    if machine != "x86":
        coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 0xF0, 0x2022)

    image_base = IMAGE_BASE_X86 if machine == "x86" else IMAGE_BASE_X64
    opt = bytearray()
    if machine == "x86":
        opt += struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B,               # Magic PE32
            0, 0,                # linker versions
            sum(s["raw_size"] for s in sections),
            0,                   # SizeOfInitializedData (patched by loaders anyway)
            0,                   # SizeOfUninitializedData
            0,                   # AddressOfEntryPoint: a stub dll has no DllMain
            text_rva,            # BaseOfCode
            edata_rva,           # BaseOfData
            image_base,
            SECTION_ALIGN,
            FILE_ALIGN,
            6, 0,                # OS version
            0, 0,                # image version
            6, 0,                # subsystem version
            0,                   # Win32VersionValue
            size_of_image,
            size_of_headers,
            0,                   # CheckSum
            3,                   # Subsystem: console
            0x400,               # DllCharacteristics
            0x100000, 0x1000,    # stack reserve/commit
            0x100000, 0x1000,    # heap reserve/commit
            0,                   # LoaderFlags
            16,                  # NumberOfRvaAndSizes
        )
    else:
        opt += struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x20B,               # Magic PE32+
            0, 0,
            sum(s["raw_size"] for s in sections),
            0,
            0,
            0,                   # AddressOfEntryPoint: no DllMain
            text_rva,
            image_base,
            SECTION_ALIGN,
            FILE_ALIGN,
            6, 0,
            0, 0,
            6, 0,
            0,
            size_of_image,
            size_of_headers,
            0,
            3,
            0x400,
            0x100000, 0x1000,
            0x100000, 0x1000,
            0,
            16,
        )

    dirs = bytearray()
    dirs += struct.pack("<II", edata_rva, len(edata))     # export directory
    dirs += b"\0" * (4 * 2 * 15)                          # the rest are unused
    opt += dirs

    header_size = FILE_ALIGN
    assert len(dos) + 4 + len(coff) + len(opt) <= header_size, len(dos) + 4 + len(coff) + len(opt)

    out = bytearray(b"\0" * header_size)
    out[0:len(dos)] = dos
    out[0x40:0x44] = b"PE\0\0"
    out[0x44:0x44 + len(coff)] = coff
    out[0x44 + len(coff):0x44 + len(coff) + len(opt)] = opt

    # section headers are written sequentially after the optional header
    sh_off = 0x44 + len(coff) + len(opt)
    for s in sections:
        struct.pack_into(
            "<8sIIIIIIHHI",
            out,
            sh_off,
            s["name"].encode("ascii")[:8].ljust(8, b"\0"),
            len(s["data"]),
            s["rva"],
            s["raw_size"],
            s["raw_ptr"],
            0, 0, 0, 0,
            s["characteristics"],
        )
        sh_off += 40
        out[s["raw_ptr"]:s["raw_ptr"] + len(s["data"])] = s["data"]

    return bytes(out)


# ---------------------------------------------------------------------------
# corpus import enumeration (a minimal import-table reader, no pefile needed)
# ---------------------------------------------------------------------------


def read_imports(path: str):
    """Return {dll_name_lower: set(export_name)} from a PE's import directory."""

    data = open(path, "rb").read()
    if data[:2] != b"MZ":
        return {}

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return {}

    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    size_opt = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B

    image_base = struct.unpack_from("<Q" if is64 else "<I", data, opt + (24 if is64 else 28))[0]
    nrva_off = opt + (108 if is64 else 92)
    nrva = struct.unpack_from("<I", data, nrva_off)[0]
    dirs = nrva_off + 4
    if nrva < 2:
        return {}

    export_rva, export_size = struct.unpack_from("<II", data, dirs + 0)

    sh = opt + size_opt
    sections = []
    for i in range(num_sections):
        off = sh + i * 40
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append((vaddr, vsize, raw_ptr, raw_size))

    def rva_to_off(rva: int) -> int:
        for vaddr, vsize, raw_ptr, raw_size in sections:
            if vaddr <= rva < vaddr + max(vsize, raw_size):
                delta = rva - vaddr
                if delta < raw_size:
                    return raw_ptr + delta
        return -1

    out = {}

    if export_rva and export_size:
        # the main image's own exports land in the same table, so a sample that
        # exports a name it also imports is not mistaken for an import of itself
        pass

    imp_rva, imp_size = struct.unpack_from("<II", data, dirs + 8)
    if not imp_rva:
        return {}

    off = rva_to_off(imp_rva)
    if off < 0:
        return {}

    thunk_size = 8 if is64 else 4
    ord_flag = (1 << 63) if is64 else (1 << 31)
    fmt = "<Q" if is64 else "<I"

    for _ in range(4096):
        desc = off + 20
        if desc + 20 > len(data):
            break
        orig_thunk, _ts, _fwd, name_rva, first_thunk = struct.unpack_from("<IIIII", data, off)
        if not name_rva:
            break

        name_off = rva_to_off(name_rva)
        if name_off < 0:
            break
        end = data.index(b"\0", name_off)
        dll = data[name_off:end].decode("ascii", "replace").lower()

        names = out.setdefault(dll, set())
        thunk_rva = orig_thunk or first_thunk
        thunk_off = rva_to_off(thunk_rva) if thunk_rva else -1
        if thunk_off >= 0:
            for i in range(65536):
                if thunk_off + i * thunk_size + thunk_size > len(data):
                    break
                value = struct.unpack_from(fmt, data, thunk_off + i * thunk_size)[0]
                if value == 0:
                    break
                if value & ord_flag:
                    continue
                hint_off = rva_to_off(value & 0x7FFFFFFF)
                if hint_off < 0:
                    continue
                try:
                    hend = data.index(b"\0", hint_off + 2)
                except ValueError:
                    continue
                names.add(data[hint_off + 2:hend].decode("ascii", "replace"))

        off = desc

    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, help="rootfs System32 directory to write into")
    ap.add_argument("--machine", default="x86", choices=("x86", "x64"))
    ap.add_argument("--from-pe", nargs="*", default=[], help="PEs whose imports seed the export sets")
    ap.add_argument("--default-set", action="store_true", help="always include the built-in sanity exports")
    args = ap.parse_args(argv)

    # dlls the reference always probes for, even when the sample never imports
    # them directly: the loader's api-ms-win-crt redirection scans these for the
    # requested symbol, so a redirect only resolves if its name is exported here
    key_dlls = ("kernel32.dll", "ntdll.dll", "kernelbase.dll", "ucrtbase.dll", "mscoree.dll")

    exports = {dll: set() for dll in key_dlls}
    if args.default_set or not args.from_pe:
        exports.setdefault("kernel32.dll", set()).update({"ExitProcess", "Sleep", "GetStdHandle"})
        exports.setdefault("msvcrt.dll", set()).update({"printf", "malloc"})

    for path in args.from_pe:
        for dll, names in read_imports(path).items():
            if dll.startswith("api-ms-win-"):
                # the redirect dlls contain no code: the reference walks its key
                # dlls looking for the symbol, so the names have to live there
                exports.setdefault("ucrtbase.dll", set()).update(names)
                continue
            exports.setdefault(dll, set()).update(names)

    os.makedirs(args.out, exist_ok=True)
    written = 0
    for dll, names in sorted(exports.items()):
        target = os.path.join(args.out, dll)
        blob = build_stub_pe(dll, names, args.machine)
        if os.path.exists(target) and open(target, "rb").read() == blob:
            continue
        with open(target, "wb") as f:
            f.write(blob)
        written += 1

    print(f"stub_dlls: {len(exports)} dlls in {args.out} ({written} rewritten)")
    for dll, names in sorted(exports.items()):
        print(f"  {dll}: {len(names)} exports")
    return 0


if __name__ == "__main__":
    sys.exit(main())
