# T-006 — non-mapped MMIO: partial reads return 0, short writes are silently dropped

| field | value |
|---|---|
| severity | **medium** (silent data loss + a divergence from upstream's loud failure) |
| area | `QlPripheralHandler::read` / `write` in `qiling/hw/hw.cpp` (line numbers there drift — see the README) |
| upstream | `qiling/hw/hw.py:34-48` (`QlPripheralHandler.read` / `write`, the `_mmio` bytearray slice) |
| found in | `8f92646` (hw groundwork) |
| status | open |

## What is wrong

The handler's own backing buffer (the non-mapped part of an mmio region) is
accessed with a full-range test plus silent truncation:

```cpp
// qiling/hw/hw.cpp — QlPripheralHandler::read
std::uint64_t out = 0;
const auto bytes = std::min<std::size_t>(size, sizeof(out));
if (offset + bytes <= mmio_.size()) {              // all-or-nothing
    std::memcpy(&out, mmio_.data() + offset, bytes);
}
return out;                                        // else: 0
```
```cpp
// qiling/hw/hw.cpp — QlPripheralHandler::write
if (offset < mmio_.size()) {
    const auto bytes = std::min<std::size_t>(size, mmio_.size() - offset);
    std::memcpy(mmio_.data() + offset, &value, std::min<std::size_t>(bytes, sizeof(value)));
}
```

Upstream uses *slice* semantics in both directions:

```python
# qiling/hw/hw.py:41-48
ql.log.debug('[%s] read non-mapped hardware [%#010x]', self._label, address)
return int.from_bytes(self._mmio[offset:offset + size], byteorder='little')
...
self._mmio[offset:offset + size] = value.to_bytes(size, 'little')
```

Consequences:

1. **Reads.** `mmio_` is 0x1000 bytes (the fixtures map 0x1000). Writing the
   last two bytes (`offset = 0xFFE`) and reading `offset = 0xFFF, size = 4`
   returns **0** in the port (because `0xFFF + 4 > 0x1000`) while upstream
   returns the one stored byte. Any guest that does a wide access straddling the
   end of the region reads zeros instead of the stored tail — a silent data
   loss, and the exact place where a mis-sized `mmio` env record would show up.
2. **Writes.** Upstream *raises* (`bytes` slice length != size →
   `ValueError: incorrect length`), so a guest write that runs off the end of the
   region stops the emulation loudly. The port silently drops the tail — the
   emulation keeps running with a register that was never written. Under the
   port's own "no silent passes" convention this should not be silent.
3. The `ql.log.debug('[%s] read non-mapped hardware ...')` calls (both
   directions) were not ported at all, although the comment above
   `QlPripheralHandler::read` says "the debug-log branch verbatim". With
   `--verbose` there is no trace that an access was served from the buffer
   rather than a peripheral (this overlaps T-007).

## Suggested fix

```cpp
// read: build from the available prefix
std::uint64_t out = 0;
if (offset < mmio_.size()) {
    const auto bytes = std::min<std::size_t>({size, sizeof(out), mmio_.size() - offset});
    std::memcpy(&out, mmio_.data() + offset, bytes);
}
return out;
```

For the write, pick one and document it in the handler comment:

- **fail loud (upstream-faithful):** `throw QlErrorBase("mmio: write past the
  end of the region ...")`; or
- **truncate + trace:** keep the clamp but emit the port's verbose log line so
  the drop is observable.

Either way, restore the two `ql.log`-equivalent debug lines (they are the only
diagnostic for "why did my mmio access do nothing").

## Acceptance test

`tests/Hw_Test.cpp`:

- `HwManager.NonMappedMmioTailRead` — write 2 bytes at `region + 0xFFE`, read
  4 bytes at `region + 0xFFF`; expect the stored byte in the low position (0
  today).
- `HwManager.NonMappedMmioShortWrite` — a write straddling the end. Assert the
  chosen policy explicitly (either a thrown `QlErrorBase`, or "the in-range
  prefix is stored and the drop is logged"). Today the write is silently
  partial.
