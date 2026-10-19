# T-015 — the stat family writes 0 for every `st_*time_ns` cell (and the statx nsec conversion) where upstream serves the real host nanoseconds

| field | value |
|---|---|
| severity | **medium** (guest-visible fidelity: timestamp nanoseconds are always 0 across stat/fstat/lstat/stat64/statx) |
| area | `qiling/os/filestruct.hpp:146-161` (`QlFileStat` — no ns fields), `qiling/os/posix/stat.cpp` (the `StatSrc::Zero` ns cells in every layout table; `statx64_layout`/`statx32_layout` nsec cells; `source_value`), `qiling/os/filestruct.cpp` (`host_statat` snapshot) |
| upstream | `qiling/os/posix/stat.py` (`StatBase.__getitem__`) + `qiling/os/posix/syscall/stat.py` (`statx_convert_timestamp`) |
| found in | `0fc59a8` (the stat-packing family), carried through `8ce4463`, `2925f15`, `48dbefc`, `10aeb82` |
| status | open |

## What is wrong

Upstream's `StatBase.__getitem__` serves the **real** nanosecond components
because `os.stat_result` has `st_atime_ns` / `st_mtime_ns` / `st_ctime_ns`:

```python
# upstream stat.py StatBase
def __getitem__(self, key):
    if not key.startswith("__") and hasattr(self._stat_buf, key):
        return self._stat_buf.__getattribute__(key)
    return 0
```

`__common_pack_stat_struct` does `stat.__setattr__(field, int(info[field]))`
for *every* `_fields_` entry — so `st_atime_ns` etc. land in the guest image
with the host's real nanoseconds (truncated by the ctypes cell width). The
port's layout tables claim the ns cells "answer 0 through StatBase.__getitem__
(the snapshot never carries them)" — the parenthetical is true of the **port's
snapshot**, but the first half is wrong about **upstream**: `hasattr` succeeds
upstream, so upstream writes nonzero ns.

The port's host snapshot has no ns fields at all:

```cpp
// qiling/os/filestruct.hpp:147-160
struct QlFileStat {
    ...
    std::int64_t atime = 0;
    std::int64_t mtime = 0;
    std::int64_t ctime = 0;
```

…so every ns cell in every layout (`linux_x86_stat`, `linux_x86_64_stat`,
`linux_x86_stat64`, the statx tables) is `StatSrc::Zero`.

Additionally, upstream's statx runs the **nsec through the same float32
bit-pattern conversion** as the sec:

```python
# upstream syscall/stat.py statx_convert_timestamp
tv_sec  = struct.unpack('i', struct.pack('f', tv_sec))[0]
tv_nsec = struct.unpack('i', struct.pack('f', tv_nsec))[0]   # <- ns converted too
```

The port converts only the sec cell (the `as_statx_time` flag) and writes a
plain 0 for the nsec cell.

Guest-visible: any program comparing timestamps at ns granularity, using ns
as a uniqueness/entropy source, or reading statx nsec sees 0s.

## Suggested fix

1. Extend `QlFileStat` with `atime_ns` / `mtime_ns` / `ctime_ns`
   (`std::int64_t`).
2. Capture them host-side: POSIX `st.st_atim.tv_nsec` etc. (the `fstatat`
   path already has the `stat` struct); Windows has no ns in `_stat64` —
   use `GetFileTime` (FILETIME, 100 ns units) for the path stats, or
   `GetFileInformationByHandle` for the fd stats, and document whatever
   approximation is chosen for the Windows host.
3. Map the ns cells in the layout tables to the new `StatSrc` values
   (`AtimeNs`, `MtimeNs`, `CtimeNs`).
4. For the statx tables, apply the float32 bit-pattern conversion to the
   nsec cell as well (`as_statx_time` on the ns cell once it carries a value).

## Acceptance test

- `tests/StatPack_Test.cpp`: stage a file, `touch` it, pack the x86-64 stat
  image, and assert the `st_atime_ns` cell (offset per the table) is **not
  zero** (any real ns value from the host). Before the fix this reads 0.
- `tests/Posix_Test.cpp` (statx fixture): assert the statx atime nsec cell
  is the float32-bit-pattern of the real ns (mirroring the existing sec
  assertions).
