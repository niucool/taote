# Open review tickets

These tickets come from an **independent read-through review** of the port's
newest commit bodies. They are not the porting agent's own notes: each one
carries the upstream reference, the port evidence (`file:line`), the failure it
can cause, a suggested fix and the test that would catch it.

## Pinned revision

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

1. `T-001` and `T-002` change emulated behaviour or memory safety — do those first.
2. Every ticket has an **Acceptance test** section: write the test, watch it
   fail against the current code, then fix.
3. When a ticket is done, record the outcome in `STATUS.md` (as usual) and move
   the file to `tickets/done/`.
4. If a ticket turns out **not** to be a defect (the divergence is deliberate
   and documented), do not delete it silently: add a one-line rationale and
   move it to `tickets/done/`. The point of the file is the record of the
   decision.
5. Keep the diff for one ticket separate from the others — several of them
   touch the same few files (`qiling/hw/peripheral.hpp`,
   `qiling/hw/stm32f4xx_usart.hpp`, `qiling/loader/mcu.cpp`).

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
