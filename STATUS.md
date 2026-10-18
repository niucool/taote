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

## Phase 1 — arch layer (all arch classes in; 113/113 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/arch/models.hpp` | `qiling/arch/models.py` | Ported | per-arch CPU model enums, values verbatim (== UC_CPU_* constants); static_assert parity in `Arch_Models_Test.cpp` |
| `qiling/arch/arch.hpp/.cpp` | `qiling/arch/arch.py` | Ported (core) | QlArch base: uc/regs/disassembler/assembler/endian/pointersize, save/restore (uc_context), stack helpers declared (require the Phase 2 memory manager); `Qiling*` nullable until the Phase 3 composition root |
| `qiling/arch/register.hpp/.cpp` | `qiling/arch/register.py` | Ported | QlRegisterManager: case-insensitive name + regid read/write, save/restore, arch_pc/arch_sp |
| `qiling/arch/x86.hpp/.cpp` | `qiling/arch/x86.py` | Ported | QlArchIntel + A8086/X86/X8664; reg maps are the mapping glue over UC_X86_REG_* (D3); cpu model via uc_ctl |
| `qiling/arch/arm.hpp/.cpp` | `qiling/arch/arm.py` + `cortex_m.py` | Ported (smoke) | QlArchARM (live CPSR thumb/endianness, per-mode cached Cs/Ks, enable_vfp via cpr) + QlArchCORTEX_M (MCLASS+THUMB modes, m-class reg map, IRQ/CONTROL/EXC_RETURN/EXCP tables, is_handler_mode/using_psp, QlInterruptContext RAII) |
| `qiling/arch/arm64.hpp/.cpp` | `qiling/arch/arm64.py` | Ported (smoke) | QlArchARM64: x0..x30 + b/d/h/q/s/w/v families + fpcr/fpsr/cpacr_el1; enable_vfp |
| `qiling/arch/mips.hpp/.cpp` | `qiling/arch/mips.py` | Ported (smoke) | QlArchMIPS: r0..r31 + ABI aliases (a0==r4), hi/lo, cp0 regs; EL and EB |
| `qiling/arch/ppc.hpp/.cpp` | `qiling/arch/ppc.py` + `ppc_const.py` | Ported (smoke) | QlArchPPC (BE); MSR flag table verbatim; enable_float |
| `qiling/arch/riscv.hpp/.cpp` | `qiling/arch/riscv.py` + `riscv64.py` | Ported (smoke) | QlArchRISCV/RISCV64: x-regs + aliases, CSR surface, f-regs; MSTATUS table; assembler() degrades to QlErrorNotImplemented (keystone has no RISC-V, verbatim) |
| `qiling/arch/msr.hpp/.cpp` | `qiling/arch/msr.py` | Ported | QlMsrManager over UC_X86_REG_MSR (uc_x86_msr payload; unicorn 2.x has no msr_read C API) |
| `qiling/arch/cpr.hpp/.cpp` | `qiling/arch/cpr.py` + `cpr64.py` | Ported | QlCprManager (UC_ARM_REG_CP_REG, uc_arm_cp_reg payload; el→sec) + QlCpr64Manager (UC_ARM64_REG_CP_REG, uc_arm64_cp_reg) |
| `qiling/arch/utils.hpp/.cpp` | `qiling/arch/utils.py` | Ported (subset) | standalone `assembler()` factory + Cs/Ks RAII wrappers; QlArchUtils tracing lands in Phase 2 (needs hooks/mem) |
| `qiling/cc/cc.hpp/.cpp` | `qiling/cc/__init__.py` | Ported | QlCC + QlCommonBaseCC (incl. the `_retaddr_on_stack` attribute); IndexError → std::out_of_range, NotImplementedError → QlErrorNotImplemented |
| `qiling/cc/intel.hpp/.cpp` | `qiling/cc/intel.py` | Ported | QlIntelBaseCC/64/32, amd64, ms64, macosx64; **`cdecl`/`stdcall` renamed `QlCdecl`/`QlStdcall`** (MSVC reserves the bare names as archaic keywords — the `errno_value()` precedent) |
| `qiling/cc/arm.hpp/.cpp` | `qiling/cc/arm.py` | Ported | QlArmBaseCC (retaddr in lr, `_retaddr_on_stack = False`), aarch64 (x0..x7), aarch32 (r0..r3) |
| `qiling/cc/mips.hpp/.cpp` | `qiling/cc/mips.py` | Ported | mipso32: v0 ret, a0..a3 + 4-slot shadow, retaddr in ra |
| `qiling/cc/ppc.hpp/.cpp` | `qiling/cc/ppc.py` | Ported | ppc: r3 ret, r3..r8 args, retaddr in lr |
| `qiling/cc/riscv.hpp/.cpp` | `qiling/cc/riscv.py` | Ported | riscv: a0 ret, a0..a5 args, retaddr in ra |
| `tests/Arch_X86_Test.cpp` | `tests/test_arch_x86.py` behaviour | Ported | bring-up, reg round-trip + sub-register overlap, disasm/asm corpora byte-identical, MSR, save/restore, model selection |
| `tests/Arch_Models_Test.cpp` | `tests/test_cpu_models.py` | Ported | static_assert parity against UC_CPU_* constants + runtime uc_ctl round-trip |
| `tests/Cc_Test.cpp` | `tests/test_cc.py` behaviour | Ported | slot counts, return regs, amd64/ms64 register files, argbits masking, base-class NotImplemented surface |
| `tests/Arch_Arm_Test.cpp` | `tests/test_arch_arm.py` behaviour | Ported | ARM + Cortex-M smoke: bring-up, reg tables, thumb/endianness switching, disasm/asm corpora, cpr round-trip, enable_vfp, handler-mode detection |
| `tests/Arch_Arm64_Test.cpp` | `tests/test_arch_arm64.py` behaviour | Ported | bring-up, reg families, ARM64 disasm corpus, enable_vfp, cpr named access |
| `tests/Arch_Mips_Test.cpp` | `tests/test_arch_mips.py` behaviour | Ported | EL + EB disasm corpora, alias equivalence, nop assembly |
| `tests/Arch_Ppc_Test.cpp` | `tests/test_arch_ppc.py` behaviour | Ported | BE disasm corpus (li r3, 1), MSR flags, enable_float |
| `tests/Arch_Riscv_Test.cpp` | `tests/test_arch_riscv.py` behaviour | Ported | RISCV32/64 bring-up, addi corpus, CSR surface, assembler NotImplemented, MSTATUS flags, init_context |
| `tests/Cc_Arch_Test.cpp` | `tests/test_cc.py` behaviour | Ported | per-arch CC register files, return regs, lr/ra return-address surface |
| `cmake/engine-deps.cmake` | — | C++-only | (Phase 0) manual imported targets for the unicorn/keystone ports |
| `vcpkg.json` (capstone features) | — | C++-only | the capstone port builds with NO architectures by default — x86/arm/arm64/mips/ppc/riscv features enabled explicitly |

### Phase 1 findings (upstream-parity notes)

- **keystone ARM/ARM64 mode tables are exact-match** (`ks.cpp`): `Ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_THUMB)` and `Ks(KS_ARCH_ARM64, KS_MODE_ARM)` fail with `KS_ERR_MODE` — **verified identical in the Python binding** (keystone 0.9.2); the C++ port mirrors the failure via QlErrorArch. Pure `KS_MODE_THUMB` / `KS_MODE_LITTLE_ENDIAN` work in both trees.
- **unicorn 2.1.4 CPACR access via `UC_ARM_REG_CP_REG` is a silent no-op** (verified identical through the Python binding's `cpr_read`/`cpr_write`); `enable_vfp`'s persistent half in both trees is the `FPEXC` write. TPIDRURO-style CP15 access persists in both.
- **unicorn initializes ARM CPSR = 0x400001d3** (T=0, E=0 after normalization); mode-dependent disasm/asm pick their Capstone/Keystone modes from the live CPSR, exactly like `arm.py`.
- keystone lacks a RISC-V backend (KS_ARCH_RISCV absent) — `riscv.py`'s `QlErrorNotImplemented` assembler degrades identically.

## Phase 2 — core services (167/167 gtest green, incl. Phase 0+1 suites)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/core_struct.hpp/.cpp` | `qiling/core_struct.py` | Ported | QlCoreStructs: pack/pack8/16/32/64 (+signed) /unpack/unpacks; member-fn-pointer dispatch table by bit width; hand-rolled byteswap + host-endianness probe (C++17 has no std::endian); range errors → QlErrorStructConversion |
| `qiling/core_hooks_types.hpp` | `qiling/core_hooks_types.py` | Ported | callback typedefs as `std::function<int(...)>`; Hook/HookAddr/HookIntr/HookRet RAII handle (dtor unregisters) |
| `qiling/core_hooks.hpp/.cpp` | `qiling/core_hooks.py` | Ported | one trampoline per unicorn C callback signature (trace/intr/mem_valid/mem_invalid/insn_invalid/insn/addr); heap HookCtx user_data owned by a flat vector; per-event uc hooks (begin=1,end=0) + per-hook `bound_check`; `QL_HOOK_BLOCK` chain break; emu_stop + recorded exception discipline (nothing crosses the C frame); verbatim dispatcher error strings |
| `qiling/host.hpp/.cpp` | `qiling/host.py` | Ported | lazy cached os()/arch() via compile-time platform macros |
| `qiling/os/memory.hpp/.cpp` | `qiling/os/memory.py` | Ported (core) | QlMemoryManager: map/unmap (+`uc_mem_regions`-split unmap_between)/map_mmio (type-erased ctx)/protect/read/write/ptr/string/search/find_free_space (64-bit ubound saturates — Python bignums don't)/map_anywhere/mapinfo+formatted/add/change/save/restore; QlMemoryHeap alloc/free/clear/save/restore; regex `search` documented as bytes-only deviation |
| `qiling/os/fcall.hpp/.cpp` | `qiling/os/fcall.py` | Ported | QlFunctionCall over cc::QlCC: read/write params, ellipsis reader, call with on-enter/on-exit overrides + passthru (retaddr −1, no unwind) + variadic non-unwind, call_native staging; Accessor override map |
| `qiling/snapshot.hpp/.cpp` | `qiling/core.py` (save/restore envelope) | C++-only | envelope format for the resumable snapshot: `QLSN` magic + u32 version, sectioned (name/payload LE), bounds-checked reads; consumers (memory/regs) live in the memory manager |
| `qiling/arch/arch.hpp/.cpp` (stack helpers) | `qiling/arch/arch.py` | Ported | stack_push/pop/read/write now operate through the attached memory manager (`attach_memory`, Python `ql.mem` boot order); the unattached stub still degrades to QlErrorBase |
| `tests/Struct_Test.cpp` | `tests/test_core_struct.py` behaviour | Ported | per-width pack/unpack round-trips, endianness, range errors |
| `tests/CoreHooks_Test.cpp` | `tests/test_core_hooks.py` behaviour | Ported | the full §10 Phase 2 hook matrix: trace/block/addr/insn/intn/mem read+write+fetch+unmapped, hook types fired simultaneously, QL_HOOK_BLOCK chain break, hook_del/clear, exceptions inside hooks recorded + emu stop |
| `tests/Memory_Test.cpp` | `tests/test_memory.py` behaviour | Ported | map/protect/read/write/ptr/string/search round-trips, mapinfo formatting, free-space/map_anywhere, heap, save/restore |
| `tests/Fcall_Test.cpp` | `tests/test_fcall.py` behaviour | Ported | param read/write over the amd64 register file, ellipsis, call orchestration with overrides, passthru, call_native staging |
| `tests/Snapshot_Test.cpp` | `tests/test_snapshot.py` behaviour | Ported | envelope round-trip, unknown-section skipping, memory+register save/restore byte-identical, malformed input degrades to errors |
| `tests/Host_Test.cpp` | `tests/test_host.py` behaviour | Ported | host os/arch detection |

### Phase 2 findings (upstream-parity notes)

- **`UC_HOOK_MEM_FETCH` never fires for ordinary instruction fetches on x86-64 (unicorn 2.1.4)** — verified against a raw-unicorn probe: fetches surface as TLB/block events, so `hook_mem_fetch` registration is exercised but its delivery is unicorn-implementation dependent (the Python binding has the same property).
- **`uc_mem_map` inside a `UC_HOOK_MEM_UNMAPPED` callback works** (map-then-retry flows exactly like `memory.py`'s unmapped-access handling); `uc_mem_unmap` rejects page-unaligned ranges and ranges spanning several mappings — `unmap_between` splits at live `uc_mem_regions` boundaries.
- **`UC_ERR_READ_UNMAPPED`=6, `UC_ERR_MAP`=11; adjacent `uc_mem_map` regions are NOT merged in `uc_mem_regions`** (two entries [0x1000,0x1fff] [0x2000,0x2fff]).
- **String literals with embedded NULs truncate in C++** (`std::string_view` from a char literal stops at strlen) — test blobs need the `sv` suffix; the Python `b"\x00.."` equivalents are length-explicit. Recorded here because every hook/blob test hit it.
- keystone/unicorn headers pull `windows.h` macros on MSVC — `NOMINMAX` is defined project-wide in the root CMakeLists.

## Phase 3 — Qiling facade (composition root) — 209/209 gtest green

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/core.hpp/.cpp` | `qiling/core.py` | Ported | the composition root: ctor assembly sequence verbatim (argv/rootfs validation, arch/os guessing, select_arch, profile setup, loader, mem, os, `loader.run()`, stop guard); `class Qiling : QlCoreHooks, QlCoreStructs` keeps the Python inheritance — the bases gained deferred-init ctors to mirror the Python mid-constructor `__init__` calls; run/emu_start (rethrow-after-uc_emu_start, ARM `_init_thumb` via `adjust_emu_start`)/emu_stop/stop, patch/do_bin_patch/do_lib_patch, stack delegation, save/restore (the structured dict analogue), exit trap + sp guard |
| `qiling/utils.*` (factories + guessing) | `qiling/utils.py` §5.2 | Ported | `select_arch`/`select_loader`/`select_os`/`select_component_memory`/`select_debugger` (factory callables replacing getattr+partial; the bodies that need the complete facade live in core.cpp); `ql_guess_emu_env` + the pathname/ELF/Mach-O/PE sniffers hand-rolled (pefile/pyelftools-free, mirroring the Python's own ELF hand-parse); `QL_CPU` = the per-arch model enum variant (models.hpp) |
| `qiling/loader/loader.hpp/.cpp` | `qiling/loader/loader.py` | Ported | QlLoader base: Image (NamedTuple), find_containing_image, get_image_by_name (casefold), save/restore, skip_exit_check, run() abstract |
| `qiling/loader/blob.hpp/.cpp` | `qiling/loader/blob.py` | Ported | QlLoaderBLOB: the shellcode test vehicle (CODE profile section, images entry, sp init) |
| `qiling/os/os.hpp/.cpp` | `qiling/os/os.py` | Ported (base) | QlOs: exit_point defaults per bit width, CODE-section shellcode config, user_defined_api + set_api, resolve/process_fcall_params, call orchestration + stats + the unicorn-#1579 pc workaround, emu_error, stop; stdio streams as FILE*-backed PersistentQlFile (deviation: no fileno probing for embedded interpreters); path helpers constructed in `init_paths_if_managed()` (the C++ base ctor cannot dispatch the virtual `type()`) |
| `qiling/os/blob/blob.hpp/.cpp` | `qiling/os/blob/blob.py` | Ported | QlOsBlob: the per-arch cc table, explicit entry/exit overrides, the profile-driven heap, emu_start |
| `qiling/os/path.hpp/.cpp` | `qiling/os/path.py` | Ported | QlOsPath: virtual_abspath (cwd rebase, leading-parent strip — pathlib keeps mid-path `..`), virtual_to_host_path (symlink walk with the rootfs-rebase fallback), is_safe_host_path, host_to_virtual_path, host_casefold_path (NT hosts no-op); both separators normalized so host-side Windows paths check correctly |
| `qiling/os/mapper.hpp/.cpp` | `qiling/os/mapper.py` | Ported | QlFsMapper: add/remove/rename (KeyError→QlErrorBase), mapped-vs-fresh open dispatch (str binding / factory / instance), file_exists, create_empty_file, unsafe-path refusal (PermissionError analogue) |
| `qiling/os/filestruct.hpp/.cpp` | `qiling/os/filestruct.py` | Ported | QlFsMappedObject (all methods raising QlErrorNotImplemented verbatim), QlFile (stdio-backed; guest-flag and Python-mode-string opens), PersistentQlFile (close is a no-op) |
| `qiling/os/stats.hpp/.cpp` | `qiling/os/stats.py` | Ported | QlOsStats: log_api_call (the `hook_` prefix strip), log_string tokenization, summary (field-formatted instead of json.dumps — documented deviation) |
| `qiling/os/thread.hpp` | `qiling/os/thread.py` | Ported (interface) | QlThread: get_id/exit/stop over std::thread (the Python gevent.Greenlet base has no C++ counterpart; the Linux clone/futex and Windows fiber derivatives land in their phases — OQ 1 closes there) |
| `qiling/arch/utils.*` (QlArchUtils) | `qiling/arch/utils.py` | Ported | get_base_and_name (the label-coalescing image lookup + cache), disassembler trace lines, setup_output (DISASM/DUMP hooking); owned lazily by QlArch (`arch().utils()`); `shutdown()` drops the tracer hooks while uc is alive (see the findings) |
| `qiling/arch/arm.cpp` (init_context) | `qiling/arch/cortex_m.py` | Ported | CORTEX-M `init_context()` reads the vector table through the attached memory manager; `unicorn_exception_handler` stays deferred with the hw/NVIC tree (OQ 9) |
| `tests/Util_Factory_Test.cpp` | `tests/` behaviour | Ported | the factory surface + the ELF/Mach-O/PE/DOS guessing corpora (hand-rolled headers, no pefile) |
| `tests/Qiling_Test.cpp` | `tests/test_*.py` behaviour | Ported | the composition root end-to-end: ctor validation (mutual exclusion, rootfs, arch degradation), the blob path running through the real facade, patching, save/restore, loader images, stack delegation |
| `tests/Path_Test.cpp` | `tests/test_path.py` behaviour | Ported | the §5.6 traversal pass: `..` containment, NT flavor paths, symlink escapes, host↔virtual round-trips |
| `tests/FsMapper_Test.cpp` | `tests/test_fs_mapper.py` behaviour | Ported | mapping lifecycle, mapped-vs-fresh open dispatch, unsafe-path refusal, create/rename |
| `tests/Loader_Test.cpp` | `tests/` behaviour | Ported | the QlLoader base surface (containment, basename lookup) |
| `tests/Arch_Utils_Test.cpp` | `tests/` behaviour | Ported | the tracing helpers + the CORTEX-M init_context vector-table reads |

### Phase 3 findings (upstream-parity notes)

- **`Qiling(options)` inside a macro is the most vexing parse** — `Qiling(options);` in an EXPECT_THROW body declares a variable named `options` (default-constructed via the defaulted argument) instead of running the intended ctor; C4456 flagged it. Brace-init (`Qiling{options}`) is mandatory in macro statements.
- **`uc_hook_del` after the arch's uc engine closes segfaults** — with `Qiling : QlCoreHooks, ...`, the derived-class members (the arch's UcHandle) die before the base dtor runs; the tracer hooks must drop in the composition root dtor (`shutdown_utils()`) while uc is alive. The Python original leans on GC ordering.
- **`regs().write("pc", odd)` on ARM normalizes the thumb bit out of the stored pc** (it lands in xpsr.T) — verified identical through the Python binding; `init_context` asserts the normalized value.
- **`getint('CODE', ...)` raises when the profile lacks [CODE]** — Python raises NoSectionError for blob shellcode runs that don't pass a profile; the port degrades identically and the tests ship a minimal profile (there is no bundled `blob.ql`, matching the Python `profiles/` tree).
- `QlOsPath` re-implements pathlib's PurePosix/PureWindows semantics over strings; only leading parent refs are stripped at `virtual_abspath` (mid-path `..` resolve during `virtual_to_host_path`), matching pathlib exactly.
- **PE/ELF header sniffing is hand-rolled** (MZ + e_lfanew + COFF machine + optional-header subsystem): the PE machine table covers I386/AMD64/ARM/THUMB/ARM64, subsystems 10-16 map to UEFI, everything else to WINDOWS.

## Phase 4 — Windows (first full stack)

Not started. Next: `os/windows/` (`windows.py`, `api.py`/`fncc.py` registration tables, `handle.py`, `thread.py`, `fiber.py`, `registry.py`, `structs.py`, `utils.py`, the `dlls/` tree), the PE loader slice (`loader/pe.py` over pe-parse), `os/posix/` roots. Exit criteria per PORT_PLAN.md §10 Phase 4.

## Deferred (tracked, not built)

`os/freebsd/`, `os/qnx/`, `os/macos/`, `os/uefi/`, `os/dos/`, `qiling/hw/`,
`qiling/extensions/mcu/` — resume criteria in PORT_PLAN.md §10 (OQ 9); the
remaining five profile files (dos/freebsd/macos/qnx/uefi `.ql`) defer with them.
