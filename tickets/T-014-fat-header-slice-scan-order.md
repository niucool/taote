# T-014 — fat-header slice scan picks the wrong slice when an ARM64 slice precedes the X8664 one

| field | value |
|---|---|
| severity | **medium** (guest-visible: the wrong architecture's binary is loaded for a real universal binary) |
| area | `qiling/loader/macho.cpp:104-125` (`MachoImage::parse_header`, the `getBinary` scan); the fixture pinning the wrong behavior: `tests/Loader_Macho_Test.cpp:265-296` |
| upstream | `qiling/loader/macho_parser/header.py` (`FatHeader.getBinary`) |
| found in | `5a4b6c3` (the fat-header branch) |
| status | open |

## What is wrong

Upstream's scan is a **single loop with an `elif` per item** — it returns the
*first slice whose cpu_type is either* X8664 *or* ARM64, in list order:

```python
# upstream header.py getBinary — the elif rides INSIDE the loop
for item in self.binarys:
    if item.cpu_type == CPU_TYPE_X8664:
        return item
    elif item.cpu_type == CPU_TYPE_ARM64:
        return item
```

So for `slices = [ARM64, X8664]` upstream returns the **ARM64** slice (the
first item matches the `elif`). The port instead does a two-pass priority
scan — first pass over all slices looking for X8664, second pass for ARM64:

```cpp
// qiling/loader/macho.cpp:104-120
const FatSlice* picked = nullptr;
for (const auto& slice : fat_slices_) {
    if (slice.cpu_type == CPU_TYPE_X8664) {
        picked = &slice;
        break;
    }
}
if (picked == nullptr) {
    for (const auto& slice : fat_slices_) {
        if (slice.cpu_type == CPU_TYPE_ARM64) {
            picked = &slice;
            break;
        }
    }
}
```

For `[ARM64, X8664]` the port picks the **X8664** slice. Real macOS
universal binaries are commonly emitted `[arm64, x86_64]` (clang's
`lipo -create -arch arm64 -arch x86_64` orders them that way) — exactly the
divergent case.

The commit message claims "the verbatim archtype-ignoring getBinary scan (the
first x8664 slice wins, then arm64)", and the fixture `FatContainerReparsesTheMatchingSlice`
builds an ARM64-decoy-first container and asserts the X8664 slice is picked
("the getBinary scan skips it — the x8664 pass runs first") — i.e. the
fixture **pins the port's behavior, not upstream's**. The port's own
archtype-parameter-ignored observation is correct; the scan-order claim is not.

## Suggested fix

Replace the two-pass scan with the verbatim single loop:

```cpp
const FatSlice* picked = nullptr;
for (const auto& slice : fat_slices_) {
    if (slice.cpu_type == CPU_TYPE_X8664 || slice.cpu_type == CPU_TYPE_ARM64) {
        picked = &slice;
        break;
    }
}
```

(Decide separately whether keeping the port's no-match degrade-to-invalid is
still wanted — that deviation is already documented and is fine.)

Update the fixture: the decoy-first container should now assert the **ARM64**
slice is picked (or build `[X8664, ARM64]` for the x8664 pick and add the
decoy case asserting the ARM64 pick).

## Acceptance test

- `tests/Loader_Macho_Test.cpp`: a fat container with `[ARM64, X8664]` (the
  current `build_fat` order!) must re-parse the **ARM64 slice** — flip the
  existing fixture's expectation (it currently asserts
  `image.header().cpu_type == CPU_TYPE_X8664` for the decoy-first order,
  which upstream would not do), and add the `[X8664, ARM64]` order asserting
  the X8664 pick.
