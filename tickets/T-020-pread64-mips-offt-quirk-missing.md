# T-020 — `pread64` is missing the MIPS offt quirk (and the OSError → -1 wrap); the comment claims it lives elsewhere

| field | value |
|---|---|
| severity | **low-medium** (MIPS guests read the file at the wrong offset; host OSError surfaces as an emulation error instead of -1 on all arches) |
| area | `qiling/os/posix/syscall.cpp:266-290` (`syscall_pread64`) |
| upstream | `qiling/os/posix/syscall/unistd.py:373-400` (`ql_syscall_pread64`) |
| found in | `470969c` (the io/fs tail) |
| status | open |

## What is wrong

Upstream overrides the file offset from the guest stack on MIPS (the
kernel's 32-bit MIPS pread64 convention — the `offt` register arg is not
the offset) and wraps the seek/read in `try/except OSError → -1`:

```python
# upstream unistd.py ql_syscall_pread64
if ql.arch.type is QL_ARCH.MIPS:
    offt = ql.mem.read_ptr(ql.arch.regs.arch_sp + 0x10, 8)
try:
    pos = f.tell(); f.seek(offt)
    data = f.read(length)
    f.seek(pos)
except OSError:
    regreturn = -1
else:
    ql.mem.write(buf, data)
    regreturn = len(data)
```

The port's comment claims the quirk is handled elsewhere, but the body has
no MIPS branch and no error wrap:

```cpp
// qiling/os/posix/syscall.cpp:267-268
// unistd.py ql_syscall_pread64: ... (the MIPS sp-offset quirk rides the
// MIPS arch slice)
...
const auto pos = f->tell();
f->lseek(offt, 0);          // no MIPS override — uses the register arg
```

A `grep` over the whole tree finds no `arch_sp + 0x10` handling — the
"MIPS arch slice" the comment points at does not exist. A MIPS guest calling
`pread64` reads at the register-arg value instead of the stack-passed offset.
Also, a host seek/read failure (seeking past EOF is benign, but e.g. an
invalid offset on some fs) surfaces as a thrown C++ exception rather than
the upstream `-1` return.

## Suggested fix

```cpp
std::uint64_t effective_offt = offt;
if (ql.arch().type() == QL_ARCH::MIPS) {
    effective_offt = ql.mem().read_ptr(ql.arch().regs().arch_sp() + 0x10, 8);
}
// wrap the tell/seek/read in the port's error path that maps host failure to -1
```

If the MIPS deferral is intended, fix the comment to say "lands with the
MIPS slice" explicitly as a TODO, so the next reader does not assume it
exists.

## Acceptance test

- On the x86-64 fixture path: an fd whose seek fails (a pipe) asserting
  `pread64` returns -1 rather than raising.
- The MIPS quirk itself lands with a MIPS fixture when that arch's
  pread64 is exercised (note it here, do not block on it).
