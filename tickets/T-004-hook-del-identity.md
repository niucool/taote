# T-004 — `QlPeripheralUtils::hook_del` can never match (address identity over a by-value handle)

| field | value |
|---|---|
| severity | **medium** (a public, advertised API is a silent no-op) |
| area | `qiling/hw/peripheral.hpp:78-108` (`HookHandle`, `hook_read`, `hook_write`, `hook_del`) |
| upstream | `qiling/hw/peripheral.py:35-46` (`hook_read` / `hook_write` / `hook_del`) |
| found in | `8f92646` (hw groundwork) |
| status | open |

## What is wrong

`hook_read`/`hook_write` store a copy in the vector and return a **copy** to the
caller; `hook_del` then tries to find the entry by comparing addresses:

```cpp
// qiling/hw/peripheral.hpp:87-108
HookHandle hook_read(PeripheralHookCallback callback, Intercept intercept = Intercept::ENTER) {
    HookHandle handle{true, intercept, std::move(callback)};
    user_read_.at(static_cast<int>(intercept)).push_back(handle);
    return handle;                     // <- a copy; the vector element has a different address
}

void hook_del(const HookHandle& handle) {
    auto& mapper = handle.is_read ? user_read_ : user_write_;
    auto& list = mapper.at(static_cast<int>(handle.intercept));
    for (auto it = list.begin(); it != list.end(); ++it) {
        if (&*it == &handle) {         // <- compares the caller's copy with the element
            list.erase(it);
            return;
        }
    }
}
```

`&*it` can never equal `&handle` for a handle that came back from
`hook_read`/`hook_write`, so `hook_del` is a **no-op** for every handle a caller
can legitimately hold:

```cpp
auto h = peripheral->hook_write(cb);   // h is a copy
peripheral->hook_del(h);               // does nothing, the callback stays registered
```

Upstream removes by **value** — `hook_function = (callback, user_data)` is the
tuple stored in the list and also the one inside the returned
`hook_struct`, so `mapper[hook_flag].remove(hook_function)` matches by
equality:

```python
# qiling/hw/peripheral.py:41-46
def hook_del(self, hook_struct):
    hook_type, hook_flag, hook_function = hook_struct
    mapper = self.user_read if hook_type else self.user_write
    mapper[hook_flag].remove(hook_function)
```

Two aggravating details:

- Even if a caller kept a reference *into* the vector, the next
  `hook_read`/`hook_write` reallocates it → dangling reference. Identity by
  address is not just wrong here, it is unstable.
- `STATUS.md` line 1067 marks `hook_del` as ported (`✅`), and the hw slice's
  fixtures never call it, so the tree is green while the API is broken.

There are no callers today (`grep hook_del` only finds `core_hooks`, a different
class), so this is **latent** — it will bite the first peripheral or test that
uses `hook_del`, and it makes any RAII unregister helper silently leak.

## Suggested fix

Give the entries a stable identity and use it:

```cpp
struct HookHandle {
    bool is_read = false;
    Intercept intercept = Intercept::ENTER;
    std::uint64_t id = 0;                 // the stable identity
    PeripheralHookCallback callback;
};
```
- a monotonically increasing `id_` member on `QlPeripheralUtils`, assigned in
  `hook_read`/`hook_write` and returned inside the handle;
- `hook_del` removes the entry whose `id` matches (and is a documented no-op for
  an unknown/stale id).

(`std::list` + iterator, or `std::shared_ptr<HookHandle>`, are the
alternatives — but they leak the container type into the public API. The id is
the smallest change that is also honest about staleness.)

While you are there: `hook_read`/`hook_write` ignore upstream's `user_data`
parameter entirely (the port's callback signature has no `user_data`). That is
a deliberate deviation (the capture carries it) — just make sure the
`HookHandle` comment says so.

## Acceptance test

`tests/Hw_Test.cpp`:

1. `HwManager.HookDelRemoves` — register an ENTER write hook, dispatch a write,
   assert it fired; `hook_del(h)`; dispatch again; assert it did **not** fire
   (fails today).
2. `HwManager.HookDelStaleHandleIsNoop` — `hook_del` a default/stale handle; no
   crash, no removal.
3. `HwManager.HookDelStableAcrossRegistrations` — register hook A, then several
   more hooks (forcing a vector growth), then delete A; assert only A is gone.
