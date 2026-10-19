# T-002 — USART SR write sets non-sticky flags instead of preserving them

| field | value |
|---|---|
| severity | **medium** (silent behavioural divergence from upstream; feeds the interrupt logic) |
| area | `qiling/hw/stm32f4xx_usart.hpp:54-58` |
| upstream | `qiling/hw/char/stm32f4xx_usart.py:73-75` |
| found in | `063d5a2` (the usart family slice) |
| status | open |

## What is wrong

Upstream folds the written value into the *existing* register with `&=`:

```python
# qiling/hw/char/stm32f4xx_usart.py:74-75
if offset == self.struct.SR.offset:
    self.instance.SR &= value | USART_SR.CTS | USART_SR.LBD | USART_SR.TC | USART_SR.RXNE | USART_SR.TXE
```

The port rewrote this as "keep the sticky bits, take the rest from `value`":

```cpp
// qiling/hw/stm32f4xx_usart.hpp:55-58
if (offset == kSrOffset) {
    const auto sr = raw_read(kSrOffset, 4);
    raw_write(kSrOffset, 4, (value & ~(usart::sr::CTS | usart::sr::LBD | usart::sr::TC | usart::sr::RXNE | usart::sr::TXE)) |
                                (sr & (usart::sr::CTS | usart::sr::LBD | usart::sr::TC | usart::sr::RXNE | usart::sr::TXE)));
}
```

The two are **not** equivalent. Per bit `b`:

| case | upstream (`SR &= value \| STICKY`) | port |
|---|---|---|
| sticky bit | `SR[b] & (value[b] \| 1)` = `SR[b]` (preserved) | `SR[b]` (preserved) ✅ |
| non-sticky, `SR[b]=1, value[b]=0` | `0` (cleared) | `0` ✅ |
| non-sticky, `SR[b]=1, value[b]=1` | `1` | `1` ✅ |
| non-sticky, `SR[b]=0, value[b]=1` | **`0`** (stays clear) | **`1`** (spuriously set) ❌ |

Upstream's semantics are "writing a 1 leaves the flag alone, writing a 0 clears
it" — a flag can **never** be raised by a write. The port raises it.

`STATUS.md` (line 1153) records this as "the SR write keeps the
CTS/LBD/TC/RXNE/TXE sticky bits" — only the sticky half was checked while
porting; the non-sticky half silently changed.

## Why it matters

The non-sticky flags (`PE`, `FE`, `NF`, `ORE`, `IDLE`) feed `check_interrupt`,
which pends the NVIC:

```cpp
// qiling/hw/stm32f4xx_usart.cpp:20-30
const bool peie_and_pe = (cr1 & usart::cr1::PEIE) && (sr & usart::sr::PE);
...
if (peie_and_pe || ... ) { nvic->set_pending(intn); }
```

So a guest that writes `SR = PE` (bit 0) on a usart with `CR1.PEIE` set gets a
*spurious* PE interrupt that upstream never raises, and any status bit can be
forged by a plain store. Firmware that polls SR (`if SR & ORE`) can also read a
flag it never set.

## Suggested fix

Mirror upstream exactly:

```cpp
if (offset == kSrOffset) {
    const auto sr = raw_read(kSrOffset, 4);
    constexpr std::uint32_t kSticky = usart::sr::CTS | usart::sr::LBD | usart::sr::TC |
                                      usart::sr::RXNE | usart::sr::TXE;
    raw_write(kSrOffset, 4, sr & (static_cast<std::uint32_t>(value) | kSticky));
}
```

(keep the `kSticky` list in one place — it is also the thing to re-check if the
F1 usart ever stops being a pure alias).

## Acceptance test

In `tests/Hw_Test.cpp` (`HwManager.Stm32f1xxUsartTubesRideDrAndInterruptCheck`
or a new focused case):

1. seed `SR = TXE|TC` (the ctor seed), `write_body(kSrOffset, 4, usart::sr::PE)`
   → assert `SR & PE == 0` (upstream) — this fails today.
2. with `CR1.PEIE` set, assert `check_interrupt()` does **not** grow
   `nvic->pending_interrupts()`.
3. keep the existing assertions (RXNE clear on DR read, the RXNEIE/RXNE pend)
   so the fix cannot regress the paths that already work.
