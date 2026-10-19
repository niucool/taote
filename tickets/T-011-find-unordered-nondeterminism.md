# T-011 — `QlHwManager::find` walks an `unordered_map` (nondeterministic dispatch on overlapping regions)

| field | value |
|---|---|
| severity | **low** (determinism / debuggability; only bites with overlapping regions) |
| area | `QlHwManager::find` in `qiling/hw/hw.cpp`, the containers at `qiling/hw/hw.hpp:91-93` |
| upstream | `qiling/hw/hw.py:100-108` (`find` over insertion-ordered dicts) |
| found in | `8f92646` (hw groundwork) |
| status | open |

## What is wrong

```cpp
// qiling/hw/hw.cpp — QlHwManager::find
QlPeripheral* QlHwManager::find(std::uint64_t address) const {
    for (const auto& [label, regions] : region_) {        // region_ is unordered_map
        for (const auto& [lbound, rbound] : regions) {
            if (lbound <= address && address < rbound) {
                return entity_.at(label).get();
            }
        }
    }
    return nullptr;
}
```

```cpp
// qiling/hw/hw.hpp:91-93
std::unordered_map<std::string, std::unique_ptr<QlPeripheral>> entity_;
std::unordered_map<std::string, std::vector<std::pair<std::uint64_t, std::uint64_t>>> region_;
```

Upstream iterates `self.entity.keys()` — a Python `dict`, i.e. **insertion
order** — so when two peripherals' regions overlap, the winner is "whichever
was created first", deterministically, and the same board profile always
dispatches to the same peripheral. The port's `unordered_map` iteration order
is unspecified (and, for a given build, effectively hash-order — MSVC's bucket
order changes with the key set, so adding/renaming a peripheral can silently
change which peripheral answers an overlapping address).

Overlaps are not hypothetical in this design: a peripheral may declare several
regions (`CortexMNvic::region()` returns `[(0,1008), (3584,3616)]`,
`cm_nvic.hpp:55-58`), the STM32 profiles map a whole 1 MB `PERIP` mmio region
around the peripherals, and nothing prevents a `memory`/`mmio` env record from
covering a peripheral's base. Today's boards happen not to overlap, so the tree
is green — the failure mode is a future board (or a `destroy`/`create` ordering
change) dispatching a register access to the wrong peripheral, with no
compile-time or test-time signal.

## Suggested fix

Keep an insertion-ordered label list alongside the lookup maps and iterate that
in `find()`:

```cpp
std::vector<std::string> order_;   // the creation order (the upstream dict order)
// create(): order_.push_back(label);   destroy(): erase from order_
for (const auto& label : order_) {
    if (auto it = region_.find(label); it != region_.end()) {
        for (const auto& [lbound, rbound] : it->second) { ... }
    }
}
```

Optionally, detect the overlap at `create()` time and log it (the upstream
`find` has a `# TODO: this is wasteful` comment, i.e. it knew the search was
linear — but it was deterministic).

## Acceptance test

`tests/Hw_Test.cpp`: create two peripherals whose regions overlap (e.g. the
second at `base + 4` with the first 8 bytes wide); assert `find(address)` in the
overlap returns the **first-created** one, and that the result does not change
when a third, unrelated peripheral is created between them (the current
implementation is only accidentally stable).
