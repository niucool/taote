# Port status

Legend (PORT_PLAN.md §13): **Ported** — exists and matches the Python source ·
**Audit** — exists, needs review · **NEW** — planned, not yet started ·
**C++-only** — no Python counterpart (infrastructure) · **Deferred** — parked
with its subsystem (resumes per PORT_PLAN.md §10 / OQ 9).

Rows are appended as phases land; the full future inventory is the tree in
`MIRROR_LAYOUT_REORGANIZATION.md`.

## Phase 0 — scaffolding and primitives (green: 34/34 gtest)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/const.hpp` | `qiling/const.py` | Ported | header-only (pure enums/constants); values verbatim; casefolded lookup replaces `__casefold_enum` |
| `qiling/exception.hpp/.cpp` | `qiling/exception.py` | Ported | hierarchy verbatim; `errno` attr renamed `errno_value()` (macro clash); `QlPrintException` not ported (traceback plumbing) |
| `qiling/log.hpp/.cpp` | `qiling/log.py` | Ported | spdlog-backed; named loggers, level+regex filters, `[!]`/`[=]`/`[+]`/`[x]` tags, colored/plain, NO_COLOR; `\n` eol pinned on all platforms (StreamHandler terminator); thread tag defers to Phase 3 (needs `ql.os.thread_management`); TERM-color probe approximates the curses branch |
| `qiling/utils.hpp/.cpp` | `qiling/utils.py` | Ported (subset) | string helpers (`trim`, `ascii_casefold`, `parse_int_base0` with PEP 515) + name→enum conversions with alias tables; `select_*` factories and emu-env guessing land in Phase 3 (5.2) |
| `qiling/profiles/inireader.hpp/.cpp` | — (configparser subset) | C++-only | OQ 8 audit closed: no profile uses interpolation; `%` literal; no continuation lines (strict, documented) |
| `qiling/profiles/windows.ql` | `qiling/profiles/windows.ql` | Ported | copied verbatim |
| `qiling/profiles/linux.ql` | `qiling/profiles/linux.ql` | Ported | copied verbatim |
| `qiling/qiling.hpp` | `qiling/__init__.py` | Ported | aggregate entry; grows per phase |
| `cmake/engine-deps.cmake` | — | C++-only | unicorn/keystone vcpkg ports ship no CMake config files; manual imported-target detection (`unicorn::unicorn`, `keystone::keystone`) |
| `qltool/main.cpp` | `qltool` + `qiling/cli.py` | NEW (stub) | help/version only; `run`/`code` surface lands Phase 7 |
| `tests/Util_Test.cpp` | `tests/` behaviour | Ported | conversion + string-helper suites |
| `tests/Log_Test.cpp` | `tests/` behaviour | Ported | level mapping, tags, named loggers, regex filter |
| `tests/Profile_Test.cpp` | `tests/` behaviour | Ported | parses bundled `.ql` profiles; configparser-parity cases |
| `tests/Exception_Test.cpp` | `tests/` behaviour | Ported | hierarchy, verbatim `QlSyscallError` rendering |
| `vcpkg.json` / `CMakeLists.txt` | — | C++-only | manifest + build (D1); unicorn pinned 2.1.4 via override (D15); manifest baseline = local vcpkg HEAD |

## Phase 1 — arch layer

Not started. Next: `qiling/arch/` bring-up over the direct unicorn/capstone/
keystone linkage (unicorn pinned 2.1.4), `qiling/cc/`, x86/x86-64 first.

## Deferred (tracked, not built)

`os/freebsd/`, `os/qnx/`, `os/macos/`, `os/uefi/`, `os/dos/`, `qiling/hw/`,
`qiling/extensions/mcu/` — resume criteria in PORT_PLAN.md §10 (OQ 9); the
remaining five profile files (dos/freebsd/macos/qnx/uefi `.ql`) defer with them.
