# T-005 — `hook_call` dispatches while a callback may mutate the hook list

| field | value |
|---|---|
| severity | **medium** (iterator/reference invalidation → UB on a re-entrant hook) |
| area | `qiling/hw/peripheral.hpp:110-122` (`hook_call`), callers `183-211` (`read`/`write`) |
| upstream | `qiling/hw/peripheral.py:48-57` (`_hook_call`) |
| found in | `8f92646` (hw groundwork) |
| status | open |

## What is wrong

`hook_call` iterates the *live* vector by reference and calls user callbacks
inside the loop:

```cpp
// qiling/hw/peripheral.hpp:115-122
std::optional<std::int64_t> hook_call(const std::vector<HookHandle>& list, PeripheralAction action,
                                      std::uint64_t offset, std::uint32_t size, std::uint64_t value) {
    std::optional<std::int64_t> retval;
    for (const auto& handle : list) {
        retval = handle.callback(*static_cast<Peripheral*>(this), action, offset, size, value);
    }
    return retval;
}
```

`read()`/`write()` pass `user_read_[intercept]` / `user_write_[intercept]`
directly (`peripheral.hpp:184-210`). A callback that registers another hook
(`hook_read`/`hook_write` → `push_back` → reallocation) or removes one
(`hook_del` → `erase`) invalidates the range being iterated: the classic
`std::vector` invalidation → UB, not a wrong-but-defined result.

This is easy to hit in practice, and it is exactly the shape that motivated the
existing safety deviations elsewhere in the port:

- an ENTER hook that installs a "one-shot" EXIT hook (a very natural pattern:
  "if the guest wrote the CTRL register, attach the follow-up probe");
- an EXIT hook that calls `hook_del` on itself to make a one-shot hook;
- the loader in `qiling/loader/mcu.cpp:212-215`, which already had to work
  around handle-lifetime issues for `HookRet` — hook lifetime is clearly on the
  critical path of this codebase.

Upstream is safe by accident here: Python iterates the live list, and mutating a
list during iteration is defined (append is seen, removal skips an entry).

## Suggested fix

Iterate over a snapshot of the list (the hooks' cost is a copy of a handful of
`std::function`s, and the port already prefers safety over upstream-verbatim
where the two conflict):

```cpp
const auto snapshot = list;               // const std::vector<HookHandle>
for (const auto& handle : snapshot) { ... }
```

Alternatively, index with a generation counter that `hook_read`/`hook_write`
bump and abort the walk when it changes — but a snapshot is clearer. Also
decide what a hook registered *during* a dispatch means: with a snapshot it
fires from the next access onwards (upstream fires it in the same walk). Record
that in the `hook_call` comment.

## Acceptance test

`tests/Hw_Test.cpp`:

1. `HwManager.HookRegistersHookDuringDispatch` — an ENTER write hook that calls
   `hook_write(...)`; run an access; no crash, and the second hook fires on the
   next access.
2. `HwManager.HookDeletesHookDuringDispatch` — an EXIT hook that calls
   `hook_del` on its own handle; run two accesses; no crash, exactly one firing
   (both tests are UB today; under the MSVC debug STL / ASAN they trip).
