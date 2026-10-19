# T-021 — `ioctl` never dispatches to socket fds: SIOCGIFADDR / SIOCGIFNETMASK are unreachable (and the stub-table matching carries dead loops)

| field | value |
|---|---|
| severity | **low-medium** (functional gap: interface enumeration via `ioctl(SIOCGIFADDR)` — common in network tooling — answers -1 instead of the interface address; tracked as "deferred" but the deferral rationale is muddled) |
| area | `qiling/os/posix/syscall.cpp:396-462` (`syscall_ioctl` — no socket branch); `qiling/os/posix/socket.hpp` (`QlSocket` has no `ioctl` override) |
| upstream | `qiling/os/posix/syscall/ioctl.py:80-96` (the `isinstance(ql.os.fd[fd], ql_socket)` + SIOCGIFADDR/SIOCGIFNETMASK branch with the `ifrname_override` ride) |
| found in | `470969c` (the io/fs tail); STATUS.md:1393 documents the deferral |
| status | open |

## What is wrong

Upstream first checks whether the fd is a socket and the cmd is an interface
query, and only then falls to the stub table:

```python
# upstream ioctl.py
if isinstance(ql.os.fd[fd], ql_socket) and cmd in (SIOCGIFADDR, SIOCGIFNETMASK):
    data = ql.mem.read(arg, 64)
    ifr_name_override = ql.os.ifrname_ovr        # the profile setting
    ...
    data = ql.os.fd[fd].ioctl(cmd, bytes(data))  # the real host ioctl
    ql.mem.write(arg, data)
```

The port has no such branch: `SIOCGIFADDR` (0x8915) on a socket fd falls to
the stub table, matches nothing, and returns -1. `QlSocket` has no `ioctl`
override (the base `QlFsMappedObject::ioctl` is the degraded one), and the
`ifrname_override` profile entry (`qiling/profiles/linux.ql:40`) is inert.

STATUS.md records this as "the socket SIOCGIFADDR/ifrname-override branch
defers with the harness chardev surface" — the chardev/harness framing looks
like a copy-paste from the hw phase; the actual prerequisite is just a
`QlSocket::ioctl` over the host socket (winsock `WSAIoctl`/`ioctlsocket`
families) plus the ifrname plumbing. A real interface enumeration in the
guest (`getifaddrs`-style or direct SIOCGIFADDR loops) fails today.

Secondarily, the stub-table matching in the port carries two redundant
loops that make it very hard to reason about (the first loop's
`(void)test_fd;` discards the loop variable it names; the second loop's
condition reduces to an exact (fd, cmd) match that the first loop already
established). Behaviorally they happen to collapse to upstream's tuple
membership for the current static table, but the dead code invites a future
bug — see the upstream wildcard (`None`) semantics that the port translates
incompletely (upstream matches literal `None` entries in the table; the
port's `-1`/`0` sentinel translation only works because the table has no
such entries).

## Suggested fix

1. Add the socket branch ahead of the stub table: check the fd's object
   type for the socket, and for `SIOCGIFADDR`/`SIOCGIFNETMASK` run the host
   socket ioctl with the 64-byte ifreq read/write-back and the
   `ifrname_override` fill (16 bytes, NUL-padded, per upstream).
2. Collapse the matching to a single literal tuple-membership loop:
   `for (test : {(fd,cmd),(WILDCARD,cmd),(fd,WILDCARD)}) if (table.contains(test)) ...`
   — deleting the second loop outright.

## Acceptance test

- A fixture: socket fd + `SIOCGIFADDR` on a real interface (loopback is
  always present) asserting the returned ifreq carries the loopback address
  (127.0.0.1) and the call returns 0, with `ifrname_override` set in the
  profile asserting the name cell is the override.
