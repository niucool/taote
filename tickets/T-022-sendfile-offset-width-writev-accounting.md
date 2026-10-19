# T-022 — io/fs tail precision notes: `sendfile` reads the offset cell at a fixed 8 bytes (upstream: pointer-size); `writev` sums the host-written count (upstream: the requested length)

| field | value |
|---|---|
| severity | **low** (guest-visible only on short writes / 32-bit guests) |
| area | `qiling/os/posix/syscall.cpp:312-316` (`syscall_sendfile` offset cell), `:223-242` (`syscall_writev` ret accounting) |
| upstream | `qiling/os/posix/syscall/sendfile.py`; `qiling/os/posix/syscall/uio.py` |
| found in | `470969c` (the io/fs tail) |
| status | open |

## What is wrong

### 1. sendfile's offset cell width

Upstream reads the caller's offset cell with the guest pointer width:

```python
# upstream sendfile.py
goto = ql.mem.read_ptr(offset)      # pointer-size read
...
ql.mem.write_ptr(offset, where)     # pointer-size write
```

The port reads a fixed 8 bytes but writes back at the (pointer-size default
of) `write_ptr`:

```cpp
// qiling/os/posix/syscall.cpp:312-316
ifile->lseek(ql.mem().read_ptr(offset, 8), 0);   // fixed 8-byte read
...
ql.mem().write_ptr(offset, ifile->tell());       // default width = pointersize
```

On a 32-bit guest, upstream reads/writes 4 bytes; the port reads 8 (which
can fault when the cell sits at the end of a mapped page) and writes 4 —
inconsistent within the same call. `sendfile`'s `off_t` is 32-bit on
32-bit Linux (`sendfile64` carries 64-bit offsets and would be a separate
width decision), so the pointer-size behavior is also the ABI-correct one
for `sendfile`.

### 2. writev's return accounting

Upstream sums the *requested* lengths:

```python
# upstream uio.py ql_syscall_writev
ql.os.fd[fd].write(data)
ret += len(data)
```

The port sums the host-written count:

```cpp
// qiling/os/posix/syscall.cpp:237-239
ret += static_cast<std::int64_t>(f->write(data));
```

They diverge only when the underlying host write is short (a full disk, a
pipe with a small buffer) — the port then reports fewer bytes than upstream.
The upstream semantic is also what real `writev` returns (bytes accepted),
so the port's divergence is the *less* correct one for the guest.

## Suggested fix

- sendfile: use `ql.mem().read_ptr(offset)` (pointer-size) for both the read
  and the write-back.
- writev: `ret += static_cast<std::int64_t>(data.size());` (or keep a loop
  that pads/tracks to the requested length only if a deliberate divergence
  is recorded — the current one is not).

## Acceptance test

- A 32-bit guest fixture (the x86 blob path) calling sendfile with the
  offset cell at the last 4 bytes of a mapped page — the current fixed-8
  read faults; the pointer-size read succeeds.
- The writev accounting is hard to force short on the host; assert instead
  against a pipe consumer that reads less than the write (or accept the
  unit-level fix with a comment).
