# T-008 — `PeripheralTube::get()` is UB on an empty tube (only the usart guards its call site)

| field | value |
|---|---|
| severity | **low** (latent, but the guard is caller discipline rather than an API contract) |
| area | `qiling/hw/connectivity.hpp:22-63` (`PeripheralTube`), `80` (`recv_from_user`) |
| upstream | `qiling/hw/connectivity.py:14-46` (`PeripheralTube : queue.Queue`), `99-102` (`recv_from_user`) |
| found in | `063d5a2` (the usart family slice) |
| status | open |

## What is wrong

```cpp
// qiling/hw/connectivity.hpp:53-59
void put(std::uint8_t byte) { data_.push_back(byte); }

std::uint8_t get() {
    const auto byte = data_.front();   // UB when the deque is empty
    data_.pop_front();
    return byte;
}
```

`get()` — and therefore `recv_from_user()` (line 80):

```cpp
std::uint8_t recv_from_user() { return itube_.get(); }
```

is UB on an empty tube. The one call site is guarded:

```cpp
// qiling/hw/stm32f4xx_usart.hpp:43-45
if (has_input()) { retval = recv_from_user(); }
```

which is a documented, sensible deviation (upstream's `queue.Queue.get()`
*blocks*, so upstream would hang; `STATUS.md:1152` records the guard). The
problem is that the safety lives in the *caller*, while the API's name
(`get()`, mirroring `queue.Queue.get`) advertises the opposite. The next
connectivity peripheral (i2c/spi/dma on the board-profile list,
`STATUS.md:1186-1189`) will reach for `recv_from_user()` and inherit a UB trap
instead of a defined result — and nothing in the header warns about it.

For contrast, the same file validates the snapshot path properly
(`restore()` throws `QlErrorBase("connectivity snapshot too short")`,
`connectivity.hpp:113-131`), so the missing contract here is an inconsistency
inside one class.

## Suggested fix

Make the empty case explicit and total:

```cpp
// the upstream's queue.Queue.get() would block; the port returns nullopt
std::optional<std::uint8_t> get() {
    if (data_.empty()) return std::nullopt;
    const auto byte = data_.front();
    data_.pop_front();
    return byte;
}
std::optional<std::uint8_t> recv_from_user() { return itube_.get(); }
```

then fix the two call sites (`stm32f4xx_usart.hpp:44`, and the tests) to use
the optional — the `has_input()` guard becomes a convenience rather than the
only thing standing between the guest and a crash. (Throwing `QlErrorBase` is
the alternative; it is worse here because "no input yet" is a normal state for a
polling firmware, not an error.)

While in the file: `PeripheralTube::save()` is non-const and is invoked through
`const_cast` from `QlConnectivityPeripheral::save()` (line 107-108) — make
`save()` const (it restores the drained bytes) so the `const_cast` can go.

## Acceptance test

`tests/Hw_Test.cpp`:

- construct a `PeripheralTube`, call `get()` / `recv_from_user()` with nothing
  written; expect `std::nullopt` (or the chosen defined result) — UB today.
- a usart `read_body(kDrOffset, 4)` with an empty itube still returns 0 and
  leaves SR alone (the existing behaviour must not change).
