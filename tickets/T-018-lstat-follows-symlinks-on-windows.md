# T-018 — on Windows hosts `lstat` follows symlinks (`_wstat64`), so guest symlink detection never works

| field | value |
|---|---|
| severity | **medium** on Windows hosts (none on POSIX hosts) — guest-visible: `lstat()` on a symlink reports the *target*, so `S_ISLNK` checks in the guest always fail |
| area | `qiling/os/filestruct.cpp:229-238` (the `_WIN32` branch of `host_statat`), documented at `qiling/os/filestruct.hpp:158-166` |
| upstream | Python `os.lstat` on Windows — which **does** report reparse points correctly (uses `GetFileAttributesW`/`FindFirstFileW` under the hood) |
| found in | `2925f15` (the stat/lstat family) |
| status | open |

## What is wrong

The port's host stat collapses the follow/no-follow distinction on Windows:

```cpp
// qiling/os/filestruct.cpp — host_statat, _WIN32 branch
struct _stat64 st{};
if (::_wstat64(host_path.wstring().c_str(), &st) != 0) { ... }
```

`_wstat64` always follows symlinks; the `follow_symlinks` parameter is
ignored on this path (the POSIX path correctly passes
`AT_SYMLINK_NOFOLLOW`). The header comment documents this as a deviation
("the MSVC CRT has no lstat, so the no-follow request collapses onto
_wstat64") — but the reference point is wrong: **upstream qiling running on
Windows uses `os.lstat`, and Python's `os.lstat` handles reparse points
correctly on Windows**. So on the port's primary host, the divergence is
against upstream-on-the-same-host, not just against Linux.

Consequences in the guest: `lstat(path).st_mode & S_IFMT == S_IFLNK` is never
true (upstream would report the link), `lstat` on a dangling symlink returns
`-ENOENT` instead of the link's own stat, and file-type detection loops
(e.g. directory walkers, installers, the port's own `__do_readlink` callers)
take the wrong branch. The port's own `tests/Path_Test.cpp` symlink test is
`GTEST_SKIP`ped on this host, so nothing catches it.

## Suggested fix

On the `_WIN32` path, when `follow_symlinks == false`, take the no-follow
attributes from `std::filesystem::symlink_status` (which uses
`GetFileAttributesW` and reports reparse points):

```cpp
if (!follow_symlinks) {
    const auto st = std::filesystem::symlink_status(host_path, ec);
    // map st.type() to the POSIX st_mode shape (S_IFLNK for symlink, ...),
    // size from symlink_status (0 for reparse points — upstream Python
    // reports the reparse data length; approximate and document),
    // timestamps via last_write_time
} else {
    // the existing _wstat64 path
}
```

Windows-specific approximations (link size, inode) are fine if documented —
the critical part is that the mode reports `S_IFLNK` and the call does not
fail on dangling links.

## Acceptance test

- `tests/Path_Test.cpp`: replace/augment the skipped symlink test with one
  that creates a symlink **with the Windows privilege available** (the
  existing skip), asserts `lstat` reports `S_IFLNK` and differs from `stat`
  on the same path. If the host cannot create symlinks, gate the fixture on
  a runtime probe rather than skipping it unconditionally.
