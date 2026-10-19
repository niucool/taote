# Open review tickets

These tickets come from an **independent read-through review** of the port's
newest commit bodies. They are not the porting agent's own notes: each one
carries the upstream reference, the port evidence (`file:line`), the failure it
can cause, a suggested fix and the test that would catch it.

## Rounds

- **Round 1** (T-001 … T-011): the `qiling/hw` groundwork + board-profile
  slices and the posix socket family. **The hw subsystem has since been
  retired from the trunk** (`d0a8c6a`, full state on the `hw-backup` branch),
  so the hw-scoped bodies of T-001 … T-011 now live on that branch — fix
  them there, or fold them into the retirement decision record in
  `STATUS.md`, rather than on the trunk.
- **Round 2** (T-012 … T-023): the trunk-live commits that landed after the
  round-1 cutoff — the stat family (`0fc59a8` … `8a753c5`), mman
  (`aa9504b`), the directory-read surface (`a8c7d93`), the signal family
  (`eceb2da`), the file-op family (`bcbf82e`), the io/fs tail (`470969c`),
  the time family (`4191895`), the proc/misc family (`41a91d4`), the
  ipc/msg family (`3236d37`), and the macho fat-header/parseData/commpage
  slices (`5a4b6c3`, `00e8d7a`, `752aa67`). Round-2 HEAD: `d0a8c6a`
  (tree clean, suite 414 passed / 0 failed at review time). The socket
  family was covered by round 1; round 2 re-checked only its
  ioctl/sendfile-adjacent edges where the io/fs tail touched them.

## Pinned revision (round 1)

- HEAD when the review started: `063d5a2`; HEAD when these tickets were written: `3668d1e`
- reviewed bodies:
  - the `qiling/hw` groundwork + the board-profile slices:
    `8f92646` (hw groundwork), `e7d1c36` (systick + QlOsMcu), `22d0f91` (intc),
    `0c0b60f` (gpio family), `063d5a2` (usart family)
  - the posix socket family, sub-slices 2..10: `7d52367` … `9194c91`
- **not reviewed** (landed while this review was running, or untracked WIP):
  `0de4ef1` (Tim family), `3668d1e` (Exti family), and the untracked
  `qiling/hw/stm32f1xx_simple.{hpp,cpp}` + `qiling/hw/const_stm32fxxx_rcc.hpp`.
- **`qiling/hw/hw.cpp` is a moving target**: while this review ran, the porting
  agent added ~40 uncommitted lines to it (the Rcc/Flash/Adc/Spi/bitband/remap
  factory registrations), which shifts every line number below the constructor.
  Every citation in these tickets therefore *quotes the code verbatim* as well —
  match on the text, not the number. Line numbers for `peripheral.hpp`,
  `loader/mcu.cpp`, `connectivity.hpp` and the usart files were stable for the
  whole review.
- upstream source of truth: `E:\Projects\github\qiling`. The port claims
  *verbatim* fidelity, so a behavioural divergence from upstream is the primary
  defect class; memory-unsafety is the second (the port turns upstream's
  ctypes-layout UB into C++ heap UB).
- baseline at review time: `build/tests/Release/qiling_tests.exe` →
  `418 tests from 89 test suites ran`, `417 passed`, 1 skipped
  (`Path_Test.Symlink…` — host limitation, not a port defect), 23 `DISABLED_`
  bisect probes (already documented in `STATUS.md`).

## How to consume these

1. Round 1: `T-001` and `T-002` change emulated behaviour or memory safety —
   do those first (on `hw-backup`). Round 2: `T-012` (predictable
   `getrandom`), `T-013`/`T-014` (guest-visible struct/load-target
   divergence) and `T-015` (stat ns) are the behavior-first picks.
2. Every ticket has an **Acceptance test** section: write the test, watch it
   fail against the current code, then fix.
3. When a ticket is done, record the outcome in `STATUS.md` (as usual) and move
   the file to `tickets/done/`.
4. If a ticket turns out **not** to be a defect (the divergence is deliberate
   and documented), do not delete it silently: add a one-line rationale and
   move it to `tickets/done/`. The point of the file is the record of the
   decision.
5. Keep the diff for one ticket separate from the others — several of them
   touch the same few files (round 1: `qiling/hw/peripheral.hpp`,
   `qiling/hw/stm32f4xx_usart.hpp`, `qiling/loader/mcu.cpp`; round 2:
   `qiling/os/posix/syscall.cpp` carries T-012, T-013, T-016, T-019, T-020,
   T-021, T-022 — sequence those deliberately).

## Checked and found faithful (do not re-litigate)

Things this review looked at specifically and concluded are **not** defects, so
the porting agent does not have to re-derive them:

- `CortexMSysTick::step` vs upstream's `c_int32` `LOAD`/`VAL` fields
  (`qiling/hw/timer.cpp:12-38` vs `hw/timer/cm_systick.py:29-42`). The port reads the
  fields zero-extended, so the signed comparison could differ — **unreachable**:
  both write paths mask to 24 bits (`value &= 0xffffff`, `cm_systick.hpp:92-95`),
  so bit 31 of `VAL` can never be set, and the underflow branch reproduces
  upstream's `c_int32` wrap exactly.
- `IhexParser`'s coalescing `first` guard (`loader/mcu.cpp:59-76`): the port
  drops upstream's spurious leading `(0, b'')` segment (upstream's loop always
  emits it for a first record at a non-zero address). Harmless improvement.
- `using STM32F1xxUsart = STM32F4xxUsart` (`stm32f4xx_usart.hpp:93`): upstream
  `hw/char/stm32f1xx_usart.py` really is a pass-through of the F4 class, and the
  const tables are shared verbatim — the alias is correct.
- The usart `read_body`'s `if (has_input())` guard: a deliberate deviation from
  upstream's *blocking* `queue.Queue.get()` (`connectivity.py:102`); the port
  cannot hang. Documented in `STATUS.md:1152`. (Its API-contract problem is
  T-008, not the guard itself.)
- `CortexMNvic::region()` `[(0,1008), (3584,3616)]`, the `enable`-also-sets-ICER
  quirk, `get_pending`-reads-ISER, and the `MASK ^ (1 << bit)` clear mask: all
  verbatim against `hw/intc/cm_nvic.py:57-104,157-159`.
- `syscall_recvmsg` (`os/posix/socket.cpp`): the iov walk
  (`min(iov_len, len(data) - written)`, the `2*psize` stride), the 12-byte
  `cmsghdr` write-back, the `cmsg_len == len(cmsg_data)` quirk and the
  `written` accounting (which cannot underflow) all match
  `os/posix/syscall/socket.py:698-745`.
- The sockaddr write-backs (`write_sockaddr`, the AF_UNIX `path` truncation to
  `addrlen - 3`, the `objsize <= addrlen` gate) and every `memcpy` into a
  `sockaddr_un`/`sockaddr_in` are length-clamped to the target buffer
  (`os/posix/socket.cpp:600-680, 1033-1080`).
- The test result `418 ran / 417 passed` is clean, not a silent pass: the single
  non-pass is `GTEST_SKIP` in `tests/Path_Test.cpp:106` (symlink creation is not
  available on this Windows host). The 23 `DISABLED_` tests are the documented
  bisect probes (`STATUS.md:448`), and all pass with
  `--gtest_also_run_disabled_tests`. No `DISABLED_`, `GTEST_SKIP` or
  "can't fail" assertion hides a regression in the reviewed areas.

## Checked and found faithful in round 2 (do not re-litigate)

- `ql_syscall_time` ignoring `tloc` — upstream's signature takes no `tloc`
  parameter at all (`time.py ql_syscall_time(ql)`); the port's `(void)params`
  is verbatim, not a missing write-back.
- The sigprocmask `old-writes-to-NEWSET` quirk and the silent KILL/STOP drop,
  the sigaction write-before-load order, and the per-arch GuestSigaction
  field orders (x8664 mask-last; x86/ARM mask-second): all verbatim against
  `syscall/signal.py`, including the upstream union workaround.
- The ipc multiplexer's arg reshuffles (shmat `(args[0], args[3], args[1])`,
  msgsnd `(args[0], args[3], args[1], args[2])`, the msgrcv version-0
  msgp/msgtyp pointer walk, and the `-ENOSYS` default — all verbatim against
  `syscall/syscall.py ql_syscall_ipc`.
- The msgrcv copy-before-erase (the round-2 re-check of the
  use-after-free fix from `3236d37`): the mtype/mtext are copied to locals
  before the queue erase, and the MSG_COPY branch correctly skips the erase —
  matches upstream's refcount-kept-alive semantics.
- mmap's flag tables, the find_free_space hint, the fixed/noreplace/anonymous
  walks, the file-backed read-at-`addr` (within the enclosing-page mapping),
  and munmap's flush-then-clip order: verbatim against `syscall/mman.py`
  (including upstream's own flush-read of the full `length` — a
  length-past-region call faults in both trees).
- `map_commpage` (the comm-page bases `0x7FFFFFE00000`/`0x0000000FFFFFC000`,
  the 0x68 time-lock stamp) and the macho `parseData` data-blob commands:
  verbatim against `kernel_func.py` / `macho_parser/parser.py`.
- `chmod`/`mkdir`/`rmdir`/`umask`/`truncate` bodies incl. the added
  `is_safe_host_path` guards (a port-side safety improvement over upstream,
  not a divergence).

## Index

| id | severity | area | title |
|---|---|---|---|
| T-001 | high | `qiling/hw/peripheral.hpp` (+ `hw.cpp`) | peripheral image access is unbounded → guest MMIO write can run past the heap image |
| T-002 | medium | `qiling/hw/stm32f4xx_usart.hpp` | USART SR write sets non-sticky flags instead of preserving them (`&=` became `\|`) |
| T-003 | medium | `qiling/loader/mcu.cpp` | `IhexParser::parse_line` indexes `data[0]/data[1]` unguarded + accepts malformed records silently |
| T-004 | medium | `qiling/hw/peripheral.hpp` | `QlPeripheralUtils::hook_del` can never match (address identity over a by-value handle) |
| T-005 | medium | `qiling/hw/peripheral.hpp` | `hook_call` dispatches while a callback may mutate the hook list (iterator invalidation) |
| T-006 | medium | `qiling/hw/hw.cpp` | non-mapped MMIO: partial reads return 0, short writes are silently dropped (upstream clamps / raises) |
| T-007 | low | `qiling/hw/peripheral.hpp` | `watch()`/`verbose_` are inert; `AccessSequence`/`recorder` are dead code |
| T-008 | low | `qiling/hw/connectivity.hpp` | `PeripheralTube::get()` is UB on an empty tube; only the usart guards the call site |
| T-009 | low | `qiling/hw/stm32f4xx_usart.cpp` | the usart `step()` device bridge is a silent no-op, and it lives in the wrong class |
| T-010 | low | `qiling/loader/mcu.cpp` | `load_env` silently ignores `type == "peripheral"` records (no `load_all`) |
| T-011 | low | `qiling/hw/hw.cpp` | `QlHwManager::find` walks an `unordered_map` → nondeterministic dispatch on overlapping regions |
| T-012 | medium | `qiling/os/posix/syscall.cpp` | `getrandom` returns the deterministic `i*31+7` pattern instead of random bytes (upstream: `os.urandom`) |
| T-013 | medium | `qiling/os/posix/syscall.cpp` | `sysinfo`: the fields after the `procs` u16 land at wrong offsets, mem_unit = 1 (upstream 0), no 64-byte pad — no fixture pins the layout |
| T-014 | medium | `qiling/loader/macho.cpp` | fat-header slice scan is two-pass (first X8664, else ARM64); upstream's `elif`-in-loop returns the first slice of *either* type — the decoy fixture pins the port's wrong pick |
| T-015 | medium | `qiling/os/filestruct.*`, `qiling/os/posix/stat.cpp` | every `st_*time_ns` cell is 0 (host snapshot carries no ns); upstream serves real ns; the statx nsec float32 conversion is also dropped |
| T-016 | medium | `qiling/os/posix/syscall.cpp`, `ipc.hpp` | msgsnd/msgrcv: the MSGMNB cap checks `deque::max_size()` (dead `-EAGAIN`), `kMsgMnb` unused, and the no-IPC_NOWAIT blocking semantics silently diverge |
| T-017 | medium | `qiling/os/posix/syscall.cpp` | `shmat` SHM_RND rounds *up* to the page size; upstream rounds *down* to the per-arch SHMLBA (MIPS 0x40000, ARM/ARM64 4×pagesize); `shmget` drops SHM_HUGETLB |
| T-018 | medium (win32) | `qiling/os/filestruct.cpp` | `lstat` follows symlinks on Windows hosts (`_wstat64`) — guest `S_ISLNK` never true; upstream Python `os.lstat` handles reparse points on the same host |
| T-019 | low | `qiling/os/posix/syscall.cpp` | `times()` uses `::clock()` × 10 — the wrong quantity and scale on both host platforms vs upstream's `os.times()` |
| T-020 | low-medium | `qiling/os/posix/syscall.cpp` | `pread64` missing the MIPS `sp+0x10` offt override (the comment points at a nonexistent slice) and the OSError → -1 wrap |
| T-021 | low-medium | `qiling/os/posix/syscall.cpp`, `socket.hpp` | `ioctl` never dispatches to socket fds — SIOCGIFADDR/SIOCGIFNETMASK unreachable, `ifrname_override` inert; the stub matching also carries dead loops |
| T-022 | low | `qiling/os/posix/syscall.cpp` | `sendfile` reads the offset cell at fixed 8 bytes (upstream: pointer-size, inconsistent with its own write-back); `writev` sums the host-written count (upstream: the requested length) |
| T-023 | low-medium | `qiling/os/posix/syscall.cpp` | `nanosleep` stalls every guest thread under the thread management, and the function's header comment claims a park branch that does not exist |
