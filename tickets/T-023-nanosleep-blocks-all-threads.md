# T-023 — `nanosleep`/`clock_nanosleep` stall the whole emulation under multithread, and the function's header comment claims a park branch that does not exist

| field | value |
|---|---|
| severity | **low-medium** (guest-visible under the linux thread management: one thread's sleep freezes every guest thread; the code comment misleads the next reader) |
| area | `qiling/os/posix/syscall.cpp:560-590` (`sleep_common`) |
| upstream | `qiling/os/posix/syscall/time.py` (`__sleep_common` — the `thread_management` park via `sched_cb` + `gevent.sleep`) |
| found in | `4191895` (the time family) |
| status | open |

## What is wrong

Upstream parks the *current thread only* when the thread management is
active (other guest threads keep running), and host-sleeps only on the
single-thread path:

```python
# upstream time.py __sleep_common
if ql.os.thread_management:
    def _sched_sleep(cur_thread):
        gevent.sleep(tv_sec)
    ql.emu_stop()
    ql.os.thread_management.cur_thread.sched_cb = _sched_sleep
else:
    time.sleep(tv_sec)
```

The port always host-sleeps, but its **header comment describes the park
branch as if it existed**:

```cpp
// qiling/os/posix/syscall.cpp:563-567
// time.py __sleep_common: ... the thread-management branch parks the
// thread through the emu_stop + the sched_cb (the gevent.sleep analogue --
// the port wakes via the management wake-at deadline), the single-thread
// branch rides the host sleep
std::optional<std::int64_t> sleep_common(Qiling& ql, std::uint64_t req, bool force_timespec64) {
    ...
    // the inline comment below the code tells the truth:
    // "the port has no timer wake machinery, so the sleep rides the host
    //  clock inside the handler (the documented deviation: the sleeping
    //  thread stalls the whole emu for the interval)"
    std::this_thread::sleep_for(std::chrono::duration<double>(tv_sec));
```

Two issues:

1. The function's doc comment and its inline comment contradict each other
   — the header describes upstream's shape (park), the code does the
   single-thread thing unconditionally. A future reader trusting the header
   will believe the multithread case is handled.
2. The behavior itself: under `thread_management`, a guest thread sleeping
   1 second freezes **all** guest threads for that second (the driver loop
   is inside the syscall handler). A sleeping producer + a running consumer
   (the classic use of nanosleep in multithreaded guests) serializes.
   The futex-park machinery (`block_on`, the sched_cb poll) already exists
   and is the natural vehicle for the deadline park.

STATUS.md documents "the thread-management branch rides the host sleep with
the documented deviation — the port has no timer-wake machinery", so the
*behavior* is a recorded deviation — this ticket is for (a) fixing the
misleading header comment now, and (b) either implementing the park or
explicitly reclassifying the deviation as accepted behavior in STATUS.md.

## Suggested fix (minimum / full)

- Minimum: delete the park-branch claim from the header comment.
- Full: when `ql.os().thread_management() != nullptr`, `emu_stop()` and set
  the current thread's `sched_cb` to a deadline-aware park (record
  `steady_clock::now + tv_sec`; the management's ready-scan unblocks the
  thread when the deadline passes — the futex wake-at pattern), falling
  back to the host sleep on the single-thread path exactly as upstream
  does.

## Acceptance test

- A multithreaded fixture (the clone/spawn machinery): the child spins a
  counter, the main nanosleeps 50 ms, then the main joins — assert the
  child's counter advanced *while* the main slept (the current code freezes
  the child, so the counter only advances after the sleep).
