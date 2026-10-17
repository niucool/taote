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

## Phase 1 — arch layer (x86/x86-64 in; other arches smoke-level)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/arch/models.hpp` | `qiling/arch/models.py` | Ported | per-arch CPU model enums, values verbatim (== UC_CPU_* constants); static_assert parity in `Arch_Models_Test.cpp` |
| `qiling/arch/arch.hpp/.cpp` | `qiling/arch/arch.py` | Ported (core) | QlArch base: uc/regs/disassembler/assembler/endian/pointersize, save/restore (uc_context), stack helpers declared (require the Phase 2 memory manager); `Qiling*` nullable until the Phase 3 composition root |
| `qiling/arch/register.hpp/.cpp` | `qiling/arch/register.py` | Ported | QlRegisterManager: case-insensitive name + regid read/write, save/restore, arch_pc/arch_sp |
| `qiling/arch/x86.hpp/.cpp` | `qiling/arch/x86.py` | Ported | QlArchIntel + A8086/X86/X8664; reg maps are the mapping glue over UC_X86_REG_* (D3); cpu model via uc_ctl |
| `qiling/arch/msr.hpp/.cpp` | `qiling/arch/msr.py` | Ported | QlMsrManager over UC_X86_REG_MSR (uc_x86_msr payload; unicorn 2.x has no msr_read C API) |
| `qiling/arch/utils.hpp/.cpp` | `qiling/arch/utils.py` | Ported (subset) | standalone `assembler()` factory + Cs/Ks RAII wrappers; QlArchUtils tracing lands in Phase 2 (needs hooks/mem) |
| `qiling/cc/cc.hpp/.cpp` | `qiling/cc/__init__.py` | Ported | QlCC + QlCommonBaseCC; IndexError → std::out_of_range, NotImplementedError → QlErrorNotImplemented |
| `qiling/cc/intel.hpp/.cpp` | `qiling/cc/intel.py` | Ported | QlIntelBaseCC/64/32, amd64, ms64, macosx64; **`cdecl`/`stdcall` renamed `QlCdecl`/`QlStdcall`** (MSVC reserves the bare names as archaic keywords — the `errno_value()` precedent) |
| `tests/Arch_X86_Test.cpp` | `tests/test_arch_x86.py` behaviour | Ported | bring-up, reg round-trip + sub-register overlap, disasm/asm corpora byte-identical, MSR, save/restore, model selection |
| `tests/Arch_Models_Test.cpp` | `tests/test_cpu_models.py` | Ported | static_assert parity against UC_CPU_* constants + runtime uc_ctl round-trip |
| `tests/Cc_Test.cpp` | `tests/test_cc.py` behaviour | Ported | slot counts, return regs, amd64/ms64 register files, argbits masking, base-class NotImplemented surface |
| `cmake/engine-deps.cmake` | — | C++-only | (Phase 0) manual imported targets for the unicorn/keystone ports |
| `vcpkg.json` (capstone features) | — | C++-only | the capstone port builds with NO architectures by default — x86/arm/arm64/mips/ppc/riscv features enabled explicitly |

Remaining Phase 1 smoke-level work (per the exit criteria, full parity lands with
Phase 5): the ARM/ARM64/MIPS/PPC/RISC-V/Cortex-M arch classes (`arm.cpp`,
`mips.cpp`, ...) over the same Cs/Ks/uc plumbing, `qiling/cc/{arm,mips,ppc,riscv}`.

## Deferred (tracked, not built)

`os/freebsd/`, `os/qnx/`, `os/macos/`, `os/uefi/`, `os/dos/`, `qiling/hw/`,
`qiling/extensions/mcu/` — resume criteria in PORT_PLAN.md §10 (OQ 9); the
remaining five profile files (dos/freebsd/macos/qnx/uefi `.ql`) defer with them.
