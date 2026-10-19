# T-003 — `IhexParser::parse_line` indexes `data[0]/data[1]` unguarded and accepts malformed records silently

| field | value |
|---|---|
| severity | **medium** (UB on malformed input + silent truncation of loaded images) |
| area | `qiling/loader/mcu.cpp:16-24` (`hex_to_bytes`), `79-98` (`parse_line`) |
| upstream | `qiling/loader/mcu.py:36-54` (`IhexParser.parse_line`) |
| found in | `22d0f91` (the intc slice, which landed the loader core) |
| status | open |

## What is wrong

```cpp
// qiling/loader/mcu.cpp:79-98
void IhexParser::parse_line(const std::string& line) {
    if (line.size() < 9) { return; }

    const std::string desc = line.substr(7, 2);
    const int size = static_cast<int>(std::stoul(line.substr(1, 2), nullptr, 16));

    const auto addr = hex_to_bytes(line.substr(3, 4));
    const auto data = hex_to_bytes(line.substr(9, static_cast<std::size_t>(size) * 2));

    if (desc == "00") {            // Data
        const std::uint64_t offset = (static_cast<std::uint64_t>(addr[0]) << 8) | addr[1];
        mem_.emplace_back(base_ + offset, std::move(data));
    } else if (desc == "02") {     // Extended Segment Address
        base_ = ((static_cast<std::uint64_t>(data[0]) << 8) | data[1]) * 0x10;
    } else if (desc == "04") {     // Extended Linear Address
        base_ = ((static_cast<std::uint64_t>(data[0]) << 8) | data[1]) * 0x10000;
    }
}
```

Three concrete problems, all on input the loader does not own (the `.hex`
sample under test):

1. **OOB vector index.** The `size` field comes from the file, but nothing
   checks that the line actually carries `2*size` data characters. A truncated
   record whose declared size is 1 (e.g. `:01000004 00` with no further
   characters, or any record cut short) leaves `data.size() == 1`, and the
   `02`/`04` branches then read `data[1]` — `std::vector::operator[]` out of
   range → UB (MSVC release reads adjacent heap memory; the debug STL aborts).
   Upstream is safe here: `int.from_bytes(data, byteorder='big')` on a short or
   empty `bytes` yields 0 instead of raising.

2. **Malformed hex is accepted silently.** `std::stoul(text.substr(i, 2), ...)`
   parses a *prefix* and does not throw for trailing garbage: `"1z"` → 1,
   `" z"` → 0. Upstream calls `bytes.fromhex(...)`, which raises `ValueError`
   on a non-hex digit. The port therefore loads *different bytes* than upstream
   for the same malformed file, instead of failing.

3. **The declared size is not checked against the payload.** `line.substr(9,
   size * 2)` returns a *shorter* string when the line is short (or when the
   record is missing its checksum), and `hex_to_bytes` happily returns fewer
   bytes → a data record silently contributes fewer bytes than it declares.
   Nothing validates the checksum either (upstream neither — noted for parity).

Additionally, the only errors thrown on the path are `std::out_of_range` /
`std::invalid_argument` from `stoul`/`substr`, which escape the loader as
std exceptions rather than `QlErrorBase` (the port's own loader-error
convention; see the explicit `QlErrorBase("mcu loader: cannot open ...")` in
the same file at line 46).

## Suggested fix

Move the validation into `parse_line`/`hex_to_bytes` and fail as a loader:

```cpp
// the record must carry LL(2) + AAAA(4) + TT(2) + size*2 payload + CC(2)
const auto chars = 11 + static_cast<std::size_t>(size) * 2 + 2;
if (line.size() < chars) {
    throw QlErrorBase("mcu loader: short ihex record: " + line);
}
```
```cpp
// hex_to_bytes: exact 2-hex-digit pairs, no prefix-parsing
if (text.size() % 2 != 0 || !std::all_of(text.begin(), text.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0; })) {
    throw QlErrorBase("mcu loader: malformed ihex hex field: " + text);
}
```
and guard the extended-address branches (`if (data.size() < 2) throw ...;`)
or build them via a helper that returns 0 for an empty field, matching
upstream's `int.from_bytes` behaviour. Whichever policy is chosen, write it in
the `IhexParser` comment so it is a decision, not an accident.

## Acceptance test

- A `tests/Hw_Test.cpp` (or a new `Loader_Mcu_Test.cpp`) case that writes a
  `.hex` with (a) a truncated `:01…04` extended-linear record, (b) a record with
  a non-hex payload character, (c) a data record whose declared size exceeds
  its payload. Expect `QlErrorBase` from each (and no crash / no silently short
  segment). Today (a) is UB and (b)/(c) silently succeed.
- Keep the existing happy-path fixture (`write_ihex_fixture()`) green.
