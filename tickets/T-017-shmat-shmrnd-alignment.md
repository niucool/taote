# T-017 — `shmat` with SHM_RND aligns the wrong direction and ignores the per-arch SHMLBA (and `shmget` misses SHM_HUGETLB)

| field | value |
|---|---|
| severity | **medium** (guest-visible: the attachment address — the syscall's return value — diverges from upstream whenever SHM_RND is used with a non-page-aligned `shmaddr`) |
| area | `qiling/os/posix/syscall.cpp:975-978` (the SHM_RND branch), `:928-934` (the shmget alignment) |
| upstream | `qiling/os/posix/syscall/shm.py` (`ql_syscall_shmat` SHMLBA table, `ql_syscall_shmget` SHM_HUGETLB walk) |
| found in | `3236d37` (the ipc/msg family) |
| status | open |

## What is wrong

Upstream selects the alignment boundary per arch and aligns **down**
(`ql.mem.align` rounds down):

```python
# upstream shm.py ql_syscall_shmat
shmlba = {
    QL_ARCH.MIPS:  0x40000,
    QL_ARCH.ARM:   ql.mem.pagesize * 4,
    QL_ARCH.ARM64: ql.mem.pagesize * 4,
    QL_ARCH.X86:   ql.mem.pagesize,
    QL_ARCH.X8664: ql.mem.pagesize
}
attaddr = ql.mem.align(shmaddr, shmlba[ql.arch.type])   # align DOWN to SHMLBA
```

The port always uses the page size and rounds **up**:

```cpp
// qiling/os/posix/syscall.cpp:976-978
} else if (shmflg & ipc::kShmRnd) {
    attaddr = ql.mem().align_up(shmaddr, ql.mem().pagesize());
}
```

Two divergences: the direction (up vs down — e.g. `shmaddr = 0x100123` on
x86-64: upstream attaches at `0x100000`, the port at `0x101000`) and the
boundary on MIPS/ARM/ARM64 (0x40000 / 4*pagesize). The return value and the
mapped range both differ.

Additionally, `shmget`'s size alignment drops the SHM_HUGETLB branch:

```python
# upstream shmget __create_shm
if flags & SHM_HUGETLB:
    shiftsize = (flags >> HUGETLB_FLAG_ENCODE_SHIFT) & HUGETLB_FLAG_ENCODE_MASK
    alignment = (1 << shiftsize)
else:
    alignment = ql.mem.pagesize
```

The port always aligns to the page size (the commit message documents "the
alignment walk" but only the page branch was ported). Low impact in practice
(guests rarely request huge pages), but it is a verbatim surface that was
silently dropped.

## Suggested fix

```cpp
std::uint64_t shmlba = ql.mem().pagesize();
switch (ql.arch().type()) {
    case QL_ARCH::MIPS:  shmlba = 0x40000; break;
    case QL_ARCH::ARM:
    case QL_ARCH::ARM64:  shmlba = ql.mem().pagesize() * 4; break;
    default: break;
}
attaddr = ql.mem().align(shmaddr, shmlba);   // align DOWN
```

(and port the HUGETLB shift for `shmget`, or document its omission).

## Acceptance test

- A shmat fixture with `shmaddr = base + 0x123` and `SHM_RND` asserting the
  returned address is `base` (round down), not `base + pagesize`.
- An ARM64 fixture with `SHM_RND` asserting the 4-page alignment.
