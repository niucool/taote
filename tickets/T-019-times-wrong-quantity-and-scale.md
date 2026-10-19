# T-019 — `times()` reports the wrong quantity and scale on both host platforms

| field | value |
|---|---|
| severity | **low** (guest-visible wrong values; rarely gates control flow) |
| area | `qiling/os/posix/syscall.cpp:594-612` (`syscall_times`) |
| upstream | `qiling/os/posix/syscall/time.py` (`ql_syscall_times`) |
| found in | `4191895` (the time family) |
| status | open |

## What is wrong

Upstream serves `os.times()` — process CPU times in **seconds** — scaling the
fields by 1000 (to ms) and returning elapsed × 100 (clock ticks):

```python
# upstream time.py
times = os.times()
if tbuf:
    fields = (times.user, times.system, times.children_user, times.children_system)
    ql.mem.write(tbuf, b''.join(ql.pack32(int(f * 1000)) for f in fields))
return int(times.elapsed * 100)
```

The port uses `::clock()` — which is **process CPU time in µs** on POSIX
(`CLOCKS_PER_SEC == 1000000`) and **wall-clock ms** on Windows
(`CLOCKS_PER_SEC == 1000`) — multiplied by 10 in both places:

```cpp
// qiling/os/posix/syscall.cpp:600, 611
const auto now = static_cast<std::uint64_t>(::clock()) * 10;  // the ms since the start
...
put32(tbuf, now);            // tms_utime
...
return static_cast<std::int64_t>(::clock() * 10);
```

- On Windows: user-time field = wall-ms × 10 (upstream: CPU-sec × 1000) — a
  factor-of-100-and-wrong-quantity error; the return is wall-ms × 10 where
  upstream returns elapsed-sec × 100 (a further 100× off).
- On POSIX: `clock()` is CPU-µs, so both the field and the return are six
  orders of magnitude away from upstream's semantics.

The port also calls `::clock()` twice (once for the field, once for the
return), so the two values are not even consistent with each other.

## Suggested fix

- fields: host CPU times — `GetProcessTimes` (Windows) / `times()` or
  `getrusage(RUSAGE_SELF)` (POSIX) — seconds × 1000, matching upstream.
- return: wall elapsed since Qiling start — keep a `std::chrono::steady_clock`
  start timestamp on the `Qiling` object and return
  `duration_cast<seconds>(now - start) * 100`, matching upstream's
  `elapsed * 100`.

## Acceptance test

- A fixture calling `times` twice with a known elapsed interval (e.g. a
  50 ms host sleep) asserting the return delta is in `[4000, 6000]`
  (centiseconds) — the current code returns something several orders
  larger on both hosts.
