# T-001 — peripheral image access is unbounded (guest MMIO can write past the heap image)

| field | value |
|---|---|
| severity | **high** (memory safety, guest-reachable) |
| area | `qiling/hw/peripheral.hpp:170-179`, entry via `QlPripheralHandler::read`/`write` in `qiling/hw/hw.cpp` (line numbers there drift — see the README) |
| upstream | `qiling/hw/peripheral.py` (`QlPeripheral.raw_read` / `raw_write`) |
| found in | `8f92646` (hw groundwork); the board-profile slices widen the reachable surface |
| status | open |

## What is wrong

`raw_read`/`raw_write` are the register-image accessors behind every
peripheral's default `read_body`/`write_body`. They clamp `size` to 8 bytes but
never check `offset` (or `offset + size`) against `instance_.size()`:

```cpp
// qiling/hw/peripheral.hpp:170-179
std::uint64_t raw_read(std::uint64_t offset, std::uint32_t size) const {
    std::uint64_t out = 0;
    std::memcpy(&out, instance_.data() + offset, std::min<std::size_t>(size, sizeof(out)));
    return out;
}

void raw_write(std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    const auto bytes = std::min<std::size_t>(size, sizeof(value));
    std::memcpy(instance_.data() + offset, &value, bytes);
}
```

`instance_` is a `std::vector<std::uint8_t>` sized to the register image
(`QlPeripheral(ql, label, image_size)` — 8 bytes for the `StubPeripheral`, 16
for the SysTick, 28 for the gpio/usart, 3616 for the NVIC). The MMIO dispatch
hands the access straight through:

```cpp
// qiling/hw/hw.cpp — QlPripheralHandler::read, and ::write with the same shape
if (auto* hardware = hwman_->find(address)) {
    return hardware->read(address - hardware->base(), size);   // no clamp
}
```

`find()` only guarantees `offset < image_size` (the region is
`[(base+0, base+struct_size)]`), so a guest access at the last byte of the image
with a 4- or 8-byte operand reaches `raw_write` with `offset + size >
instance_.size()` and writes up to 7 bytes past the heap block.

The same file clamps on its sibling path, which shows this is an oversight
rather than a decision:

```cpp
// qiling/hw/hw.cpp — the handler's own backing buffer (the read path)
if (offset + bytes <= mmio_.size()) { std::memcpy(&out, mmio_.data() + offset, bytes); }
```

## Reachable example

A 16-byte SysTick image mapped through `mmio;0xE000E000;0x1000` (`E000E010`
base): a guest `str` at `0xE000E01C`+4 bytes, or any 8-byte access ending at
`0xE000E020`, writes past the 16-byte `instance_`. With the 28-byte usart the
same applies at `base + 24` with `size == 8`, and with the 8-byte stub at
`base + 4` with `size == 8`.

## Upstream parity note (why upstream does not make this a non-issue)

Upstream has the same missing bound (`ctypes.memmove(addressof(self.instance) +
offset, data, size)`), but there the image is a `ctypes.Structure` *inside a
PyObject*: the overrun lands in interpreter-owned memory. Here it corrupts a
`std::vector` heap block, i.e. allocator metadata — a crash (or worse) instead
of a wrong number. The port already deviates from upstream when safety demands
it (see the `has_input()` guard in the usart), so this should deviate too.

## Suggested fix

1. Clamp in `raw_read`/`raw_write` (the single choke point all peripherals use):

```cpp
std::uint64_t raw_read(std::uint64_t offset, std::uint32_t size) const {
    const auto bytes = std::min<std::size_t>(size, sizeof(std::uint64_t));
    std::uint64_t out = 0;
    if (offset < instance_.size()) {
        std::memcpy(&out, instance_.data() + offset,
                    std::min<std::size_t>(bytes, instance_.size() - offset));
    }
    return out;   // out-of-range tail reads as 0
}
```

   and for the write drop only the out-of-range tail (zero-padding the in-range
   prefix is *not* wanted: upstream writes the low bytes first, so writing the
   prefix and discarding the tail keeps little-endian semantics identical for
   the in-range part).

2. Decide and document the out-of-range policy at the `QlPripheralHandler`
   level: silently zero-fill (current upstream-ish behaviour) vs
   `throw QlErrorBase` / a one-shot log. Whichever it is, put it in the
   `QlPeripheral` doc comment so the next peripheral author knows.

3. Note in the same comment that `size > 8` is truncated to 8 (upstream returns
   `size` bytes as a big integer); today MMIO sizes are ≤ 8, so this is a
   documented limit rather than a defect.

## Acceptance test

- `tests/Hw_Test.cpp`: extend `HwManager.CreateFindsAndDispatchesMmio` (or add
  `HwManager.TailAccessStaysInsideImage`) — store 4 bytes at
  `kMmioBase + struct_size - 1` and then assert
  (a) the in-range byte changed, (b) `raw_read(struct_size - 1, 1)` still reads,
  and (c) a following register access still works (i.e. nothing was corrupted).
- Run the same test under the MSVC debug heap (or ASAN) so the overrun trips
  before the fix and is impossible after it.
