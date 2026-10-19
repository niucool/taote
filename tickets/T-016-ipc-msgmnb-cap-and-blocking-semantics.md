# T-016 — SysV IPC: the MSGMNB cap is never enforced (`max_size()` misuse) and the blocking semantics of msgsnd/msgrcv silently diverge

| field | value |
|---|---|
| severity | **medium** (dead error branch + a blocking-to-nonblocking semantic change in a commonly used API) |
| area | `qiling/os/posix/syscall.cpp:796-918` (`syscall_msgsnd` full-check at `:816`; `syscall_msgrcv` no-message return at `:894-896`), `qiling/os/posix/ipc.hpp:38` (`kMsgMnb` — defined, never used) |
| upstream | `qiling/os/posix/syscall/msg.py` (`ql_syscall_msgsnd`, `ql_syscall_msgrcv`) + `qiling/os/posix/msq.py` (`deque(maxlen=MSGMNB)`) |
| found in | `3236d37` (the ipc/msg family) |
| status | open |

## What is wrong

### 1. The queue-cap check compares against the wrong quantity

Upstream's queue is `deque(maxlen=MSGMNB)` (16384 messages), and the full
check is `len(msq.queue) < msq.queue.maxlen`:

```python
# upstream msg.py
while True:
    if len(msq.queue) < msq.queue.maxlen:   # maxlen == MSGMNB == 16384
        break
    if msgflg & IPC_NOWAIT:
        return -EAGAIN
```

The port checks against `std::deque::max_size()` — the **theoretical
allocator limit** (~2^61 on x64), not the upstream cap:

```cpp
// qiling/os/posix/syscall.cpp:816
if (msq->queue().size() >= msq->queue().max_size() && (msgflg & ipc::kNowait)) {
    return -11;  // -EAGAIN
}
```

So the `-EAGAIN` branch is unreachable dead code, `kMsgMnb` (ipc.hpp:38) is
defined but unused, and the queue grows without bound.

### 2. The blocking semantics changed without a recorded decision

Upstream **busy-waits** (hangs the emulation) when the queue is full without
`IPC_NOWAIT` (msgsnd) or when no matching message exists without
`IPC_NOWAIT` (msgrcv). The port returns immediately:

```cpp
// syscall_msgrcv — :894-896
auto* msg = find_msg(*msq, msgtyp, msgflg);
if (msg == nullptr) {
    return -42;  // -ENOMSG (the wait loop lands with the IPC_NOWAIT only)
}
```

The comment acknowledges the wait loop but STATUS.md's ipc row (`:1437`)
does not record the deviation. This changes guest behavior in a way that
matters: the *normal, correct* use of `msgrcv` is a blocking receive (a
consumer calls msgrcv before the producer sends) — such a guest gets
`-ENOMSG` under the port but succeeds under upstream (eventually). The
msgsnd side similarly appends where upstream would park.

## Suggested fix

1. Enforce the cap: `if (msq->queue().size() >= ipc::kMsgMnb && (msgflg & ipc::kNowait)) return -11;`
2. Decide and **document** the no-IPC_NOWAIT semantics in STATUS.md. Two
   defensible choices:
   - treat the wait loop as if `IPC_NOWAIT` were set (return `-EAGAIN` /
     `-ENOMSG` respectively) — closest to the port's single-host-thread
     reality, and consistent with the already-documented nanosleep
     deviation; **return `-EAGAIN` rather than appending** on a full queue
     so the cap has teeth; or
   - park the thread via the thread management (the futex-park machinery
     exists) when `thread_management()` is present, host-wait otherwise.
   Whichever is chosen, keep it out of an infinite loop on the single-thread
   path.

## Acceptance test

- A fixture filling a queue past `kMsgMnb` (construct a `MsqId` directly and
  pre-load 16384 entries, or lower the constant under a test seam) asserting
  `msgsnd(..., IPC_NOWAIT)` returns `-EAGAIN` and without it does not append
  a 16385th message.
- A msgrcv-before-msgsnd fixture asserting the chosen documented behavior
  (the `-ENOMSG` return, if that is the decision) and that a subsequent
  msgsnd+msgrcv round trip still succeeds.
