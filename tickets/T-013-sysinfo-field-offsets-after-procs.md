# T-013 — `sysinfo` writes the fields after `procs` at the wrong offsets (and the wrong mem_unit value, and no 64-byte pad)

| field | value |
|---|---|
| severity | **medium** (guest-visible struct misalignment: fields 11–13 of `struct sysinfo` are read from the wrong addresses) |
| area | `qiling/os/posix/syscall.cpp:466-488` (`syscall_sysinfo`) |
| upstream | `qiling/os/posix/syscall/sysinfo.py` (`ql_syscall_sysinfo`) |
| found in | `470969c` (the io/fs tail slice) |
| status | open |

## What is wrong

Upstream packs the 14 fields **sequentially** — the `u16` `procs` field
changes the offset arithmetic for everything after it, and the joined blob is
padded to 64 bytes:

```python
# upstream sysinfo.py — field sizes in order: 10x pack (ps), 1x pack16 (2),
# 2x pack (ps), 1x pack32 (4); joined then ljust(64, b'\x00')
(0x0001, ql.pack16),   # nb current processes   -> offset 10*ps
(0x0000000000000000, ql.pack),  # total high mem    -> offset 10*ps + 2
(0x0000000000000000, ql.pack),  # avail high mem    -> offset 11*ps + 2
(0x00000000, ql.pack32),         # memory unit size  -> offset 12*ps + 2
data = b''.join(pmethod(val) for val, pmethod in fields)
ql.mem.write(info, data.ljust(64, b'\x00'))
```

The port writes fields 11/12 as if `procs` were pointer-sized, and writes
`mem_unit = 1` where upstream packs `0x00000000`:

```cpp
// qiling/os/posix/syscall.cpp:482-485
const std::uint16_t procs = 0x0001;
ql.mem().write(info + 10 * ps, ...);          // procs at 10*ps          ✓
put(info + 11 * ps, 0);                        // total high mem          ✗ (should be 10*ps + 2)
put(info + 12 * ps, 0);                        // avail high mem          ✗ (should be 11*ps + 2)
ql.mem().write(info + 13 * ps + 2, std::vector<std::uint8_t>{1, 0, 0, 0});
//                                              ^ mem_unit: wrong offset  ✗ (should be 12*ps + 2)
//                                              ^ and wrong value: 1      ✗ (upstream packs 0)
```

For an x86-64 guest (`ps == 8`) the deltas are: total high mem at 88 instead
of 82, avail high mem at 96 instead of 90, mem_unit at 106 instead of 98.
The port also omits upstream's `ljust(64)` — on a 32-bit guest upstream
writes 64 bytes total while the port writes 54.

A guest reading `((struct sysinfo *)buf)->mem_unit` gets the byte at
`12*ps + 2` of the port's image (which is 0) from upstream's slot — i.e.
whatever lands where it looks.

There is **no dedicated fixture** pinning this layout (the only test that
touches `sysinfo` is the old `SchedYieldContinuesRun` blob), which is how the
misalignment landed unnoticed.

## Suggested fix

Track a running byte offset (or replicate upstream's field-list walk) instead
of computing `n * ps` per field; write `0` for mem_unit; pad the final image
to 64 bytes:

```cpp
std::uint64_t off = 0;
const auto put_at = [&](std::uint64_t v, std::uint32_t width) { /* write at info+off, off += width */ };
put_at(0x1234, ps); /* ... the 10 pointer fields ... */
put16_at(0x0001);                    // procs
put_at(0, ps); put_at(0, ps);        // high mem pair — follow the u16, NOT a ps boundary
put_at(0, 4);                        // mem_unit == 0 verbatim
// pad the written image to 64 bytes total
```

## Acceptance test

- `tests/Posix_Test.cpp`: add `SysinfoPacksTheUpstreamLayout` — call the
  syscall on a 128-byte zeroed guest buffer, then read back and assert:
  (a) `procs == 1` at `10*ps`; (b) the high-mem pair read as **u64 from
  `10*ps + 2` / `11*ps + 2`** are 0; (c) `mem_unit` read as **u32 from
  `12*ps + 2`** is 0; (d) at least 64 bytes of the buffer were touched.
  The current code fails (a)-(c) — notably (c), since the port writes 1.
