# T-007 — `watch()` / `verbose_` are inert; `AccessSequence` / `recorder` are dead code

| field | value |
|---|---|
| severity | **low** (a debug facility that silently does nothing) |
| area | `qiling/hw/peripheral.hpp:48-66` (`AccessSequence`), `84-85` (`watch`/`verbose`), `124` (`verbose_`) |
| upstream | `qiling/hw/peripheral.py:28-33` (`watch`), `60-95` (`monitor` logging), `97-121` (`recorder`), `178-186` (`contain`, `field_description`) |
| found in | `8f92646` (hw groundwork) |
| status | open |

## What is wrong

Two upstream facilities were declared but never wired:

1. **The verbose access log.** `watch()` sets `verbose_`, and nothing in the
   port ever reads it (verified: `grep -n 'verbose_' qiling/hw/peripheral.hpp`
   → only the declaration and the setter). Upstream `monitor()` logs every
   peripheral access when `verbose` is on, using `field_description()`:

   ```python
   # qiling/hw/peripheral.py:67-70
   if self.verbose:
       self.ql.log.info(f'[{self.label.upper()}] [{hex(self.ql.arch.regs.arch_pc)}] [R] '
                        f'{self.field_description(offset, size):{width}s} = {hex(retval)}')
   ```

   The read path even logs *between* the body and the EXIT hooks (so the logged
   value is the body's result), and the write path adds the
   `(...)chr(value)` suffix for `DR` writes ≤ 255. So `peripheral->watch()` is a
   public call that promises a trace and delivers nothing — and any debugging
   session that relies on it (e.g. "why did this register read return 0?")
   silently gets no output.

2. **The recorder history.** `AccessSequence` (the `deque(maxlen=2)` ring, the
   verbatim `Access` equality) is declared and never instantiated; there is no
   `history` member and no `recorder()`. Upstream's `recorder()` is *used*:
   `qiling/hw/i2c/stm32f4xx_i2c.py:67,81` decorates its reads/writes with it.
   That peripheral is on the board-profile list still to be ported
   (`STATUS.md:1186`), so this will be needed — and it will be needed in
   `QlPeripheral`, not per-peripheral.

Neither `contain()` nor `field_description()` exists in the port, which is the
reason the log could not simply be copied: the port has no per-peripheral field
metadata (the image size rides the ctor, the offsets are named constants inside
each class). That is the real decision to make.

## Suggested fix (pick one, explicitly)

- **(A) Port the log.** Add a `field_description(offset, size)` *virtual* on
  `QlPeripheral` (default: the label + `[offset:offset+size]`; the usart/gpio/
  systick/nvic overrides name their registers), call it from `read`/`write` at
  the same points as upstream, and wire it to the port's logger. Then `watch()`
  is honest and the `recorder()` port has a place to live
  (`AccessSequence history_` + `history()` accessor).
- **(B) Do not claim it.** Make `watch()` and `verbose()` throw
  `QlErrorNotImplemented("the peripheral monitor log lands with the ... slice")`
  (and delete `AccessSequence` until then), so no caller can depend on a
  facility that does not exist.

Option (B) is cheap and consistent with the port's treatment of the `mcu fast
mode` (`qiling/os/mcu.cpp:28-30` throws); option (A) is what the i2c slice will
end up needing anyway. What must not stay is the current state: the flag is
set, the log is absent, and nothing says so.

## Acceptance test

- Option (A): `tests/Hw_Test.cpp` — `peripheral->watch()` then an access;
  assert the logger received a record mentioning the label and the value.
- Option (B): assert `watch()` (or the first access after it) throws
  `QlErrorNotImplemented`.
