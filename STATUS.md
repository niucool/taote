# Port status

Legend (PORT_PLAN.md §13): **Ported** — exists and matches the Python source ·
**Audit** — exists, needs review · **NEW** — planned, not yet started ·
**C++-only** — no Python counterpart (infrastructure) · **Deferred** — parked
with its subsystem (resumes per PORT_PLAN.md §10 / OQ 9).

**Scope note (post-Phase-13)**: the consumer surface is Windows PE + Linux ELF
(+ the Mach-O read path). The `qiling/hw/` baremetal subsystem (the MCU
device models: the STM32/SAM3XA/MK64F12/GD32VF1xx peripherals, the Cortex-M
nvic/scb/systick, the MCU os/loader) is **retired from the trunk** and lives
on the `hw-backup` branch (the last full state incl. the green Hw_Test
fixtures). The select_os/select_loader MCU branches, the core hw_ manager and
the cortex-m nvic forwarding degrade to QlErrorNotImplemented on the trunk;
the QL_OS::MCU enum stays for the value-space parity.

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

## Phase 4 — Windows stack core + posix roots (223/223 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/loader/pe.hpp/.cpp` | `qiling/loader/pe.py` | Ported (core) | QlLoaderPE (parsing layer now LIEF-backed per D17 — the original pe-parse staging of `ParsePEFromFile`/`IterSec`/`IterImpVAString` is superseded); the self-contained shellcode branch (the `pe=None` path) + the PE image path; import_symbols keyed by stub address; malformed binaries degrade to QlErrorBase (the robustness tenet); the QlPeCache pickle layer + TEB/PEB/LDR structs + the real system-DLL loading defer with the full Windows slices |
| `qiling/os/windows/api.hpp` | `qiling/os/windows/api.py` | Ported | the Windows SDK type aliases (LONG/HANDLE/LPVOID/STRING/... mapped onto the PARAM_* primitives; the windows.h-colliding spellings use the QL_-prefix/underscore convention) |
| `qiling/os/windows/fncc.hpp/.cpp` | `qiling/os/windows/fncc.py` | Ported | `WinCc` {Stdcall/Cdecl/Ms64} (the windows.h macro-collision rename, `errno_value()`/QlStdcall precedent) + the `@winsdkapi` decorator as a static `ApiRegistry` (register/find by name, re-registration replaces, the names() coverage surface) + the `WinsdkApi` fluent builder |
| `qiling/os/windows/handle.hpp/.cpp` | `qiling/os/windows/handle.py` | Ported | Handle (the 0xa0000000 id allocator), HandleManager (the stdio handles + the 8 registry hives pre-bound, search/search_by_obj/delete) |
| `qiling/os/windows/windows.hpp/.cpp` | `qiling/os/windows/windows.py` | Ported (core) | QlOsWindows: the per-cc fcall table (32-bit mixes Stdcall/Cdecl; 64-bit always Ms64) + the per-call-site `bind_fcall` rebind, the FS/GS segment regions, `hook_winapi` dispatch over the ApiRegistry, `run()` with the emu_error discipline; the GDT managers, registry/clipboard/fiber/thread subsystems and the dlls tree port per their slices |
| `qiling/os/posix/syscall/abi.hpp/.cpp` | `qiling/os/posix/syscall/abi/` | Ported | QlSyscallABI + Intel32/Intel64/ARM/ARM64 derivatives (the register tables verbatim); `get_id`/`get_params`/`set_return_value`; the over-read raises (the ValueError analogue) |
| `qiling/os/posix/syscall.hpp/.cpp` | `qiling/os/posix/syscall/unistd.py` | Ported (smoke set) | the static SyscallRegistry (the getattr resolution → static registration) + the unistd smoke set: exit/exit_group (the exit_code + stop), read/write (the fd bounds + the stdio streams), uname; the remaining syscall modules port per Phase 5 slices |
| `qiling/os/posix/posix.hpp/.cpp` | `qiling/os/posix/posix.py` | Ported (core) | QlOsPosix: the syscall abi per arch, `load_syscall` (the registry + the user overrides via set_syscall), the KERNEL profile identity, the per-arch syscall-entry hooks (`syscall` insn for x86-64, int 0x80 for x86); the fd table, msq/shm/signal land with their slices |
| `qiling/os/posix/map_syscall.hpp` | `qiling/os/linux/map_syscall.py` | Ported | the per-arch syscall number→name tables (2978 entries, generated verbatim from the Python data) |
| `qiling/os/thread.hpp` | `qiling/os/thread.py` | Ported (interface) | the QlThread interface over std::thread (the gevent base has no C++ counterpart) |
| `tests/Windows_Handle_Test.cpp` | `tests/` behaviour | Ported | the handle lifecycle + the pre-bound stdio/hive set |
| `tests/Windows_Api_Test.cpp` | `tests/` behaviour | Ported | the registration engine: find/re-register/case-sensitivity, the winsdkapi builder |
| `tests/Loader_Pe_Test.cpp` | `tests/` behaviour | Ported | a self-contained minimal PE64 fixture parses, maps and registers images; malformed binaries degrade to QlErrorBase |
| `tests/Posix_Test.cpp` | `tests/test_posix.py` behaviour | Ported | the abi layer (param registers per arch) + the real write/exit shellcode through the `syscall` instruction + the unknown-syscall degradation |

### Phase 4 findings (upstream-parity notes)

- **`uc_hook_del` after the arch's uc engine closes segfaults** (established in Phase 3) applies to EVERY hook owner: the composition root dtor now tears down the os hooks (`QlOs::shutdown()`), the tracer hooks (`QlArch::shutdown_utils()`) and the remaining registry handles (`clear_hooks()`) explicitly, in that order, before the members die. The Python original leans on GC ordering.
- **`STDCALL`/`CDECL` collide with windows.h macros on MSVC** — `WinCc` uses `Stdcall`/`Cdecl`/`Ms64` (the `errno_value()`/`QlStdcall` precedent).
- **`STD_INPUT_HANDLE` & co collide with windows.h macros** — the constants use the `QL_STD_*` spelling.
- **The posix shellcode runs need no user profile** — the bundled `linux.ql` already carries `[CODE]`; a user profile duplicating the section raises (the strict configparser behaviour, verbatim).
- **pe-parse mapped pefile's `get_memory_mapped_image` onto per-section staging** (`IterSec` + `readByte`); superseded by D17 (LIEF `sections()` + `content()` span) — kept for the historical record.
- The x86-64 syscall entry hooks the `syscall` instruction (`hook_insn`); i386 hooks int 0x80 (`hook_intno`) — matching `linux.py`'s per-arch wiring.

## Phase 5 — posix/linux full stack

The ELF container parsing, the interpreter loading, the vsyscall page, the ET_REL driver path, the windows registry, and the windows subsystems landed (above). Next: the `os/posix/syscall/` module tree (file/mmap/socket/signal/... — open/lseek/dup/pipe ride the fd-table slice), `os/linux/` (`linux.py`, `procfs.py`, `thread.py`, `futex.py`), the kernel proxy, the richer kernel_api.py handler set (printk, kmalloc, _copy_to_user, ...), and the real-hive fixture slice. The syscall tables landed with Phase 4 (map_syscall.hpp).

## Phase 5 — ELF container parsing + windows subsystems (234/234 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/loader/elf.hpp/.cpp` | `qiling/loader/elf.py` | Ported (core) | QlLoaderELF (see the D17 note below for the parsing layer): the PT_LOAD region consolidation (adjacent same-perm merge, the ARM64 0x400-page overlap workaround, else error), `seg_perm_to_uc_prot`, the auxv stack (argc/argv/envp + the full AT_* vector incl. AT_PLATFORM/AT_RANDOM/AT_EXECFN, the mips doubleword alignment), `brk_address = mem_end + 0x2000`, the shellcode branch (the `if self.ql.code` path); the ET_REL driver path (lkm_dynlinker relocations) and the vsyscall setup land with their slices |
| `qiling/os/windows/clipboard.hpp/.cpp` | `qiling/os/windows/clipboard.py` | Ported | the clipboard state machine (open/close/lock, the format table, ERROR_CLIPBOARD_NOT_OPEN on double-close) |
| `qiling/os/windows/fiber.hpp/.cpp` | `qiling/os/windows/fiber.py` | Ported | Fiber/FiberManager (alloc/free/set/get/get_noerr, the ERROR_INVALID_PARAMETER + os.last_error surfaces); the free-callback invocation stays skipped (the fiber.py <SKIP> block, verbatim rationale) |
| `qiling/os/windows/thread.hpp/.cpp` | `qiling/os/windows/thread.py` | Ported (core) | QlWindowsThread (THREAD_STATUS, waitfor/has_waitfor, the create() context prep with the thread-ret nop sled, suspend/resume over the saved register map, TLS slots) + QlWindowsThreadManagement (the TIME_SLICE round-robin scheduler, the QL_HOOK_BLOCK signal on switch, the thread_ret stop point); the live greenlet-unicorn context switching needs the fiber-callback machinery (the fiber.py <SKIP> constraint applies here too) and lands with the full guest-thread slice |
| `tests/Loader_Elf_Test.cpp` | `tests/test_elf.py` behaviour | Ported | a hand-crafted ET_EXEC fixture parses, maps, and runs the write/exit shellcode end-to-end; the malformed-container degradation |
| `tests/Windows_Subsystems_Test.cpp` | `tests/test_windows_cpp_*.py` behaviour | Ported | the clipboard state machine, the fiber table + error surfaces, the scheduler bookkeeping (no-candidate path) |

### Phase 5 findings (upstream-parity notes)

- **D17 — binary parsing unified over LIEF** (supersedes the pe-parse + hand-parser layering): `LIEF::PE::Parser`/`LIEF::ELF::Parser` replace pe-parse and the hand-rolled ELF container parser in one move (vcpkg `lief` 0.17.6). The upstream uses pyelftools + pefile; LIEF is the single native dependency that covers PE + ELF (+ Mach-O/DEX later). All loader behavior is test-protected: the migration landed with the suite green before and after. LIEF 0.17 is exception-free — a failed parse surfaces as a null `unique_ptr`, which degrades to `QlErrorBase`/`QlErrorELFFormat` per the robustness tenet. pe-parse/ELFIO left the manifest.
- **`QlOs::shutdown()` completes the teardown discipline**: every hook owner (the posix syscall-entry hook, the windows scheduler hook, the arch tracer) releases its handles from the composition root dtor before the arch's uc engine closes — the third instance of the uc-after-close crash class.
- **the auxv stack mirrors elf.py exactly**: argc/argv/envp pointers, the NULL sentinels, the 16-byte random + 'i686' platform + execfn strings, and the full AT_* list.
- **the interpreter loading follows elf.py verbatim**: the PT_INTERP path resolves through the rootfs (QlOsPath `virtual_to_host_path` + `is_safe_host_path`), the interpreter container maps with the same region consolidation, a relocatable interpreter (min vaddr == 0) takes the profile `interp_address` slot while a pre-relocated one keeps its own vaddrs, the entry becomes `interp_address + e_entry`, and `AT_BASE` lands in the auxv only when an interpreter exists.
- **`QlLoaderELF` covers both the container and shellcode paths** in one class (the Python splits them across loader/elf.py's run branches); `select_loader(LINUX)` returns it directly.
- The clipboard/fiber/thread constants (`CF_*`, `ERROR_*`) collide with windows.h/winerror.h macros — the `QL_`-prefixed spellings continue the naming precedent.

## Phase 5 — interpreter loading (LIEF-backed loaders, 235/235 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/loader/elf.cpp` (PT_INTERP branch) | `elf.py load_with_ld`'s interpreter branch | Ported | the interpreter resolves through the rootfs (`virtual_to_host_path` + `is_safe_host_path`), parses via LIEF, maps its PT_LOAD segments with the same consolidation, picks the base per the min-vaddr rule, hands the entry to `interp_address + e_entry`, appends the interpreter `Image`, and appends `AT_BASE` to the auxv only `if interp_path` |
| `tests/Loader_Elf_Interp_Test.cpp` | the load_with_ld interpreter path | Ported | end-to-end: a main ET_EXEC with PT_INTERP `/lib/ld.so` + a stub relocatable ld.so in the fixture rootfs; the run hands off main → interpreter → exit_group(42); asserts the profile interp_address base, the entry hand-off, and the registered interpreter image |

### Findings

- **the interp base follows the python `interp_address` variable semantics**: it is the *mapping base* (profile slot iff min_vaddr == 0, else 0 with the interpreter at its own vaddrs) — not the loaded range. The image list and the auxv carry the observable truth.
- **AT_BASE placement**: elf.py appends `(AT_BASE, interp_address)` after AT_PAGESZ only when an interpreter is present; the shellcode/no-interp path must not carry the entry (verbatim conditional).
- **LIEF `PE::Binary::entrypoint()` is the absolute VA** (`imagebase() + addressof_entrypoint()`); the pe.py `entry_rva` derivation subtracts the imagebase.
- **LIEF 0.17 sections() iterates by reference** (`for (const LIEF::PE::Section& s : ...)`); `Section::content()` returns a `span<const uint8_t>` replacing pe-parse's bounded-buffer readByte loop.

## Phase 5 — vsyscall page (237/237 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/loader/elf.cpp` (vsyscall block) | `elf.py load_with_ld`'s x86-64 tail | Ported | the profile vsyscall_address page maps for x86-64 LINUX only; three `mov rax, <NR>; syscall; ret` stubs (gettimeofday 96, time 201, getcpu 309) 1KiB apart, int3-padded; gated on `mem.is_available` like the upstream |
| `qiling/profiles/inireader.*` + `qiling/utils.*` (get_uint/parse_uint_base0) | profile.py `int_converter=partial(int, base=0)` | Ported (extended) | the vsyscall page sits above INT64_MAX; the unbounded Python int splits into a signed `get_int`/`parse_int_base0` pair plus an unsigned `get_uint`/`parse_uint_base0` sibling (same base-0 grammar; signs rejected) — the documented deviation |
| `tests/Loader_Elf_Interp_Test.cpp` | the vsyscall path | Ported | asserts the stub bytes (mov imm32 + `0f 05 c3`), the 1KiB spacing, the int3 padding, and the `[vsyscall]` mapinfo label |

### Findings

- **unicorn 2.1.4 cannot fetch-execute at the canonical top page**: `UC_ERR_FETCH_UNMAPPED` at any code living at/above 2^63 (0xffffffffff600000 included) — reproduced against the raw Python binding, so it is an upstream engine constraint, not a port gap. The vsyscall stubs map, read, and decode correctly; executing through them (the elf.py intent) needs a unicorn-side change or a rebased page. The upstream maps the page for "some specific needs" (gdb inspection); the port keeps the verbatim mapping.
- **the container path was missing `arch_sp = stack_address`** (elf.py run tail) — found by the vsyscall fixture's `call`; the interp fixture never touched the stack so the gap stayed hidden. The FREEBSD `rdi = stack_address + 0x40` quirk ports alongside ("No idea why", verbatim).
- **HookRet is RAII**: a discarded `ql.hook_code(...)` temporary unregisters the hook immediately — debug traces must hold the handle (`auto trace = ql.hook_code(...)`). Mirrors the core_hooks_types.py Hook discipline.

## Phase 5 — the ET_REL kernel-module path (239/239 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/loader/elf.*` (load_driver/lkm_get_init/lkm_dynlinker) | `elf.py` driver path | Ported | get_elfdata_mapping (the ehdr + the SHF_ALLOC sections at their sh_offsets, NOBITS as zeros), the `[api_mem]`/`[syscall_mem]` regions, `lkm_get_init` (the init_module symbol via LIEF symtab + st_value + sh_offset, QlErrorELFFormat when missing), the syscall table fill from the rev-reloc `sys_*` names (the hasattr check through the map_syscall reverse lookup `syscall_id_for_name`), the read/write/open stub registration keyed by name; the `loadbase=0x8000000` + the stack map moved before the type dispatch (elf.py verbatim) |
| `qiling/os/posix/kernel_api.*` | `os/linux/kernel_api/*` | Ported (core) | KernelApiRegistry (the `getattr(api, 'hook_' + name)` static-table analogue) + KernelApi (the `@linux_kernel_api(params, passthru)` builder) + the hook_sys_read/write/open stubs (verbatim signatures) |
| `QlOsPosix::hook_kernel_api` | `kernel_api/hook.py` | Ported | the code hook dispatch: the user override (set_api) runs RAW with (ql, pc, name); the registry path runs through the reshaped `QlOs::call` (the fcall orchestration incl. the passthru flag and the unicorn-#1579 pc guard); debug_stop raises QlErrorSyscallNotFound |
| `tests/Loader_Elf_Driver_Test.cpp` | the load_driver path | Ported | a hand-built ET_REL x86-64 object (.text/.rela.text/.symtab/.strtab) whose init_module calls sys_write (the builtin stub) then sys_exit_group (the user override stops with 42); asserts the import stubs, the syscall-table slots, and the images |

### Findings

- **QlFunctionCall now owns its cc** (`cc_owner_`): the borrowed-reference construction freed the cc at the end of the constructing full expression — a use-after-free the fixtures only surfaced through heap-layout luck (the solitary runs worked; the multi-emulation sequences aborted). The windows `fcall_table_` entries fixed alongside. The owner member must precede the borrowed pointer (the mem-init order).
- **`QlOs::call` matches os.py verbatim now**: resolve_fcall_params (the cc-based reads) → fcall.call with the onenter/onexit/passthru hooks → process_fcall_params → stats → the pc reassignment skipped when the emulation already stopped.
- **the ET_REL reloc walk notes**: LIEF's `object_relocations()` exposes purpose-tagged section relocs with `section()` (the sh_info target) and `symbol()` (the sh_link symtab entry, incl. shndx); the r_info_sym==0 relocs are skipped (the upstream asserts a symbol there — the documented deviation); the R_X86_64_64 `+0x2000000` FIXME and the page_offset_base SYSCALL_MEM write port verbatim.
- **`syscall_id_for_name`** (map_syscall.hpp): the reverse SYSCALL_NR lookup for the `hasattr(SYSCALL_NR, tmp_sc)` check.

## Phase 5 — the windows registry subsystem (243/243 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/os/windows/registry.*` | `os/windows/registry.py` | Ported (core) | RegConf (the json diff store over nlohmann; the load/create/delete/read/write/save surface; the missing file degrades to an empty conf), RegHive (the create/delete/write no-ops verbatim; the binary hive parsing defers with the real-hive fixture slice), RegistryManager (the diff-first read precedence, `__reg_mem_read/__reg_mem_write` marshalling incl. the RegSZ/ExpandSZ/wide and the null-or-too-small skip, the access() logging, save()) |
| `qiling/os/stats.*` (QlWinStats) | `os/stats.py QlWinStats` | Ported | the registry access records (key → {item, type, value, position}), log_reg_access, the summary extension; QlOs::stats_ became polymorphic (the windows os installs QlWinStats; the summary/clear went virtual) |
| `tests/Windows_Registry_Test.cpp` | the registry manager flow | Ported | the RegConf round-trip through the json file, the manager write→read→save over a guest string (the utf-8 narrow form), the missing-hive-dir raise (the container path), and the QlWinStats access records |

### Findings

- **the hive-file reads defer**: the python-registry package parses the binary hive files; the port's RegHive keeps the upstream no-op mutations and a not-found read surface. The diff store carries the full function (registry.py's own precedence: the conf first, the hive fallback).
- **the container path demands the hive dir**: the windows os ctor's RegistryManager raises QlErrorFileNotFound when `windir/registry` is missing and no shellcode runs (registry.py verbatim) — the PE fixtures create the dir.
- **the stats member went polymorphic**: `set_stats()` swaps the flavour before the emulation starts; the posix families keep the base QlOsStats.

## Phase 5 — the posix fcall expansion (244/244 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/os/posix/syscall.cpp` (the unistd expansion) | `os/posix/syscall/unistd.py` | Ported (expanded) | the identity/credential set (getuid/setuid/getgid/setgid + the 32 variants, geteuid/seteuid/getegid, issetugid, setgroups, setresuid/setresgid, capget/capset, getpid 0x512 / getppid 0x1024 verbatim, alarm, nice, setsid, kill (the sig dispatch lands with the signal slice), set_tid_address); `syscall_brk` (the grow/shrink around the loader brk) and `close` (the std streams close through the os streams; the opened-file entries land with the fd-table slice) |
| `qiling/core.hpp` (os<T>()) | — | Ported | the typed os accessor for the syscall handlers (the posix handlers downcast to QlOsPosix for the identity surface) |
| `tests/Posix_Test.cpp` (IdentityAndCredentialSet) | the unistd behaviour | Ported | the getuid/getgid/getpid shellcode stores the results to guest memory; the 1000/1000/0x512 identity triple asserts |

### Findings

- **the QlLoader base gained `brk_address`**: the unistd brk reads/writes it through the loader pointer; the ELF loader mirrors its private `brk_address_` into the base member at load time (the accessor + the base member coexist — the in-class assignment collision needs the `QlLoader::` qualification).
- **getpid returns 0x512 / getppid 0x1024**: the upstream constants kept verbatim (the real-pid identities land with the multithread slices).

## Phase 5 — the fd-table slice (245/245 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/os/posix/posix.hpp` (QlFileDes) | `posix.py QlFileDes` | Ported | the 1024-slot fd table over `shared_ptr<QlFsMappedObject>`, the bounds-checked `at`/`set`, the save/restore views; the std streams occupy fd[0..2] (the ctor wiring, the property-setter semantics verbatim) |
| `qiling/os/posix/const_mapping.*` | `os/posix/const_mapping.py` | Ported | `ql_open_flag_mapping`: the linux_x86_open_flags → windows host flags table walk (the FLAG_UNSUPPORTED drops), the O_BINARY bit forced at the end (the "NOTE: not sure why this one is needed" comment, verbatim) |
| `syscall.cpp` (the fd set) | `fcntl.py` + `unistd.py` | Ported | open/openat/creat (the `__do_open` flow: the flag mapping before the fs_mapper open, the -ENOENT collapse), close (the slot clear), read/write (through the table — the fd0/1/2 special cases retired), lseek (the as-signed 32-bit offset), _llseek (the high/low composition + the result write), dup/dup2/dup3 |
| `tests/Posix_Test.cpp` (OpenWriteCloseReopenRead) | the fd flows | Ported | open(O_RDWR|O_CREAT) → write → close → reopen(O_RDONLY) → read; the bytes round-trip and the reopen reuses the freed slot |

### Findings

- **the flag mapping runs before the open** (fcntl.py `__do_open`, verbatim): `QlFile::open` decodes the HOST (MSVC CRT) flag spellings (`_O_CREAT=0x100` etc.) — the guest tables only feed the mapper.
- **the open-failure translations collapse onto -ENOENT** in this slice (the typed FileNotFound/IsADirectory/AccessDenied refinements defer with the errno granularity slice).
- the dup2/dup3 target-slot form shares the handler (the dup3 flags handling — O_CLOEXEC — lands with the fcntl slice).

## Phase 5 - the richer kernel_api handler set + the fd flows (249/249 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/os/posix/kernel_api.cpp` (the extended registrations) | `os/linux/kernel_api/kernel_api.py` | Ported (expanded) | ~50 handlers in a static-init block: _copy_to_user/_copy_from_user (the unmapped-ubuf check, the count-return verbatim), memset, memcpy, kmalloc, kfree, strlen/strstr/strcmp/strncmp, the __x86_indirect_thunk_rax/r14 passthru thunks, proc_create, prepare_creds, the misc/chrdev/sock/filp/htable/module-notifier zero-returns, simple_strtol, memcmp, sys_read/write/open, make_kgid/make_kuid, commit_creds/abort_creds |
| `QlOsPosix::heap()` | the kmalloc backing | Ported | the lazy posix heap (HEAP_BASE 0x2000000, 16 MiB) over QlMemoryHeap |
| `tests/Kernel_Api_Test.cpp` | the handler surface | Ported | the registry surface (the names + the passthru flags), the memset bytes, the _copy_to_user marshalling, the strlen guest-string count |

### Findings

- **upstream bug kept visible**: the Python hook_strncmp reads `params["str"]` (a KeyError away from working); the port resolves str1.
- **the STRING params arrive as raw pointers** (the resolver machinery defers): the string-touching handlers read the guest cstrings through a helper (read_cstring_helper).
- **kernel_api.py's handler surface is 64 hook_ functions**; the port carries all 64 (the full-surface count verified by the registry-name diff at the close of the hw phase — the earlier ~50 note was stale).

## Phase 5 - the os/linux tree slice: QlOsLinux + procfs (250/250 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/os/linux/linux.*` (QlOsLinux) | `os/linux/linux.py` | Ported (core) | the LINUX os family subclass (the type() discriminator, select_os(LINUX) wires it); the per-arch syscall-hook installation lives in the QlOsPosix base (the port absorbed it into the shared run() path); the futexm/thread_class/fh members defer with the futex/thread slices |
| `qiling/os/linux/procfs.*` | `os/linux/procfs.py` | Ported | FsMappedStream (the buffered pseudo file: the cursor-based read, the read-only write) + QlProcFS (self_auxv: the pair-walk until the AT_NULL pair through the loader auxv_address; self_cmdline: the NUL-joined argv; self_environ: the K=V join; self_exe: the image bytes; self_map: the get_mapinfo rendering with the "p" suffix and the container-or-label last column) |
| `QlOsLinux::setup_procfs` + `run()` | linux.py load/run | Ported | the five /proc/self factory bindings through add_mapping (the has_mapping precedence, verbatim); the run() guard skips the procfs for the shellcode and the drivers (`if not self.ql.code and not self.ql.loader.is_driver`) |
| `QlLoader::is_driver` | elf.py self.is_driver | Ported | the base flag; the ELF loader sets it for the ET_REL loads |
| `tests/Posix_Test.cpp` (CmdlineReadsThroughFdFlow) | the procfs fd flow | Ported | open("/proc/self/cmdline") -> read: the placeholder-argv NUL byte round-trips through the FsMappedStream; the fixture drives setup_procfs directly (the upstream run() skips the procfs for shellcode) |

### Findings

- **the shellcode path never runs setup_procfs upstream** (linux.py run: `not self.ql.code`); the procfs only lives for the image loads. The test harness calls setup_procfs() explicitly.
- **the CRT `environ` macro collision** (the errno_value() precedent): the local variable named `environ` expands to `__p__environ` under windows.h - renamed to env_data.
- **the QlOsPosix `final` was dropped** to admit the QlOsLinux subclass (the mirror-layout rule outranks the leaf-class final here; the Python class hierarchy is open).
- **the auxv pair-walk termination**: the loop breaks after the AT_NULL pair (both words zero) is appended - matching the upstream `endswith(null_entry)` check.

## Phase 5 - the QlOsUtils printf engine + the printk api (251/251 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/os/utils.*` (QlOsUtils) | `os/utils.py` | Ported (core) | read_string (the char-width-stepped NUL walk; the stats log_string feed), read_cstring/read_wstring/read_guid (the bytes_le uuid in the canonical text form), printf/sprintf (the utf-8 stdout write / the utf-16le+NUL guest write) |
| the printf engine | `__common_printf` | Ported (single-pass deviation) | the %[flags][width][.precision][size]type walk; the %s guest-string read (the C snprintf cannot take it - the manual width/precision pad), the %S flipped-width form, the %Z UNICODE_STRING Buffer at +8 (both the 32- and the 64-bit layouts), the %p -> #x, the numeric conversions through the host snprintf (the size modifiers hh/h/l/ll/I32/I64/j/t/z pass through); the `*` width/precision pull extra slots; the float types promote the slot as an integer (the upstream quirk kept) |
| `hook_printk` | `kernel_api.py hook_printk` | Ported | the KERN_* level table verbatim, the level = format[1] digit else 4, the format[2:] strip (the '>' survives upstream - kept), the short-format guard (the port's addition), the variadic args through read_ellipsis (one native slot per resolved param, the pass-1 pull counting) |
| `tests/Kernel_Api_Test.cpp` (PrintkRendersFormatWithArgs) | the printk flow | Ported | the handler invoked directly with the format pointer; rsi/rdx carry the varargs; the level-tagged render captured through the swapped stdout stream (QlFile over a temp file) |

### Findings

- **the format walk is single-pass** (the upstream translates to the python %-operator form and re-applies it in a second stage); the port formats each conversion inline - the same output, one pass (the documented structural deviation).
- **the %s args cannot ride the C snprintf**: the guest strings are read through read_cstring and padded manually (the '-' left-align, the precision truncate).
- **the upstream `format[2:]` quirk**: a "<4>msg" format renders as "KERN_WARNING >msg" - the '>' survives the two-char strip. The port keeps it verbatim; the test asserts the quirk.
- **the ellipsis slot count**: the upstream readEllipsis counts the RESOLVED param values (each defaulting to the PARAM_INTN accessor); the port passes one PARAM_INTN slot per param and pulls the rest; the pull count comes from a first format walk (the conversions + the * widths).
- **the stdout capture seam**: set_stdout(shared_ptr<QlFile>) swaps the stream the printf engine writes to; the test drains a temp file after close().

## Phase 5 - the fd-table leftovers: pipe / fcntl / the typed open errors (254/254 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/os/filestruct.*` (QlPipe) | `os/posix/filestruct.py ql_pipe` | Ported | the host `_pipe` pair in the mapped-object interface (read/write/fileno/close/ioctl/dup); the fcntl swallows (the python None-returning form degrades to 0); the lseek rides the base NotImplemented (the python ql_pipe has no lseek) |
| `syscall.cpp` (pipe/pipe2) | `unistd.py ql_syscall_pipe` | Ported | the fd-table walk for the two slots, the 4-byte write_ptr pair into the guest buffer (the MIPS v1 register quirk defers with its arch slice); pipe2 shares the body (the flags handling defers) |
| `syscall.cpp` (fcntl/fcntl64/flock) | `fcntl.py` | Ported | F_DUPFD (the arg-start slot walk), F_GETFD/F_SETFD over the close_on_exec flag, F_GETFL (the recorded host flags through the virtual fcntl), F_SETFL (the mapping then the record); fcntl64 verbatim (the degraded form: -1 the out-of-range fd, 2 the F_GETFL/F_GETFD, 0 elsewhere); flock (the always-0 comment, verbatim) |
| `dup3` (O_CLOEXEC) | `unistd.py ql_syscall_dup3` | Ported (completed) | the EINVAL self-dup guard + the O_CLOEXEC (0o2000000) propagation onto the dup'd object |
| `close_on_exec` | the python dynamic attribute | Ported | a plain member on QlFsMappedObject (the setattr/getattr-default semantics as a member); the execve close-all consumer defers with the execve slice |
| the typed open errors | `fcntl.py __do_open` | Ported (completed) | QlErrorFileExists / QlErrorIsADirectory / QlErrorAccessDenied join the hierarchy; QlFile::open rewritten over `_open` with the CRT errno -> typed throw mapping (ENOENT/EEXIST/EISDIR/EACCES/EPERM); the do_open catch ladder returns -ENOENT/-EEXIST/-EISDIR/-EACCES (the unclassified errors still collapse onto -ENOENT) |
| `QlFsMappedObject::fcntl` | the host fcntl call | Ported (deviation) | a virtual no-op on the base (the windows host has no fcntl); QlFile overrides with the F_GETFL/F_SETFL flag tracking |

### Findings

- **the O_EXCL semantics forced the _open rewrite**: the old fopen mode-string form could not fail EEXIST (the "wb" mode truncates silently); `_open(path, host_flags | _O_BINARY, pmode)` carries the create/excl/trunc/append bits exactly as the const-mapped host flags spell them.
- **the 4-byte pipe slots vs the 8-byte fixture loads**: the pipe syscall writes 4-byte fd slots; a `mov rdi, [addr]` fixture load reads 8 bytes and picks up the neighbour's bytes - the fixtures need `mov edi` (the 32-bit load). The kernel-side write_ptr(size=4) is correct.
- **the F_GETFL returns the HOST flag spellings** (the upstream fcntl.fcntl returns the host-side flags too - the guest sees the windows-mapped values; the quirk kept verbatim).

## Phase 5 - the futex management slice (257/257 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/os/linux/futex.*` (QlLinuxFutexManagement) | `os/linux/futex.py` | Ported (core) | futex_wait (the unpack32 value check -> -EAGAIN, the emu stop, the (bitset, thread, event) queue put, the wait sched_cb), get_futex_wake_list (pops up to `number` entries, the bitset matching, the non-matching entries DROP - the upstream behaviour), futex_wake (the emu stop, the notify sched_cb); the FUTEX_BITSET_MATCH_ANY = 0xffffffff constant |
| `QlFutexEvent` | `gevent.event.Event` | Ported | set/clear/is_set/wait over a mutex+cv pair; the cooperative wait degrades to the host cv wait (the single-threaded emu never blocks in practice) |
| `qiling/os/linux/thread.*` (QlLinuxThread shell) | `os/linux/thread.py` | Ported (shell) | the thread ids from 2000 (the LINUX_THREAD_ID global), the set_child_tid write (the CLONE_CHILD_SETTID semantics), the sched_cb surface, the status constants, the robust-list bookkeeping; the gevent Greenlet run machinery defers with the thread-management slice |
| `tests/Futex_Test.cpp` | the futex bookkeeping | Ported | the mismatch -EAGAIN, the queue + the wake-notify pairing (the sched callbacks invoked manually, mirroring the future management run loop), the wake counting + the bitset filtering |

### Findings

- **the futex syscall registration defers**: the upstream ql_syscall_futex reaches `ql.os.thread_management.cur_thread` (the AttributeError without the management); the port registers it with the thread-management slice.
- **the moved-from bug class**: the wake collects the entries then moves them into the sched_cb lambda - the return count must be computed BEFORE the move (a C++-specific pitfall the python closure semantics do not have).
- **the gevent dependency boundary**: futex.py imports gevent only for the Event; the port's mutex+cv pair covers the surface. The thread.py machinery (628 lines) imports the greenlets wholesale - the port needs a design decision (std::thread + cv, or cooperative slices) before that slice starts (OQ 10).

## OQ 10 - D18: the concurrency model for the thread.py port

**Decision: a cooperative driver-loop scheduler; no host threads, no fibers.**

The weighing:

1. **std::thread per guest thread + one shared uc engine** - impossible: a
   unicorn engine executes single-threaded; concurrent uc_emu_start on one
   handle is unsupported.
2. **std::thread + per-thread uc engines with shared guest memory** -
   unicorn has no shared-memory abstraction across engines; each uc maps its
   own RAM. Dead end.
3. **Windows fibers (the real host-stack switching)** - viable (the port
   carries a Fiber primitive) but buys nothing semantically: unicorn's
   execution is single-threaded regardless, the switch points are always
   exactly "after uc_emu_start returns", and fibers complicate the SEH +
   exception-unwinding interplay across switches.
4. **The cooperative driver loop (chosen)** - the management owns the
   schedule; each thread runs in count-bounded emu_start slices
   (count=32337, the upstream constant); the futex/yield/exit callbacks only
   RECORD the post-slice state (the block event, the termination). This
   matches the upstream semantics exactly: gevent greenlets are cooperative
   greenlets on one host thread, the upstream design note itself says
   "within both contexts, our program is single thread" and "never give up
   control in unicorn context" - the port keeps that invariant trivially.

What upstream's gevent actually does (the semantics the port mirrors):
the greenlets interleave emu_start slices round-robin (each _run loop
iteration = one bounded slice + the sched_cb, which may park the greenlet on
a gevent Event or yield); the futex wait queues (bitset, thread, event) and
blocks the greenlet; the wake sets the events; the events' set() un-parks
the waiters through the hub. The port's driver loop replicates all of it
with the uc context save/restore + the per-arch TLS carrying the thread
state, and the management's readiness predicate polling `is_set()` in place
of the gevent hub.

## Phase 5 - the thread management slice + the futex dispatch (260/260 gtest green)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `qiling/os/linux/thread.*` (QlLinuxThreadManagement) | `os/linux/thread.py` | Ported (core) | run() (the _prepare_lib_patch loader pass + the main spawn + the driver loop), run_ready (the round-robin ready-scan, the slice + the retire sweep), stop()/stop_thread (the world stop, the LINUX_THREAD_ID reset), the deferred destruction (the exit closures park their own thread mid-slice; the retire runs outside any run_slice stack), the all-blocked QlErrorExecutionStop (the gevent LoopExit analogue) |
| QlLinuxThread (the run machinery) | thread.py _run | Ported | the first-entry pc arm + the context save, the restore-then-resume-from-the-current-pc (the upstream emu_start reads the arch_pc after the restore), the count=32337 slices, the sched_cb fire, the block_on driver state, the _on_stop (the CLONE_CHILD_CLEARTID futex wake, the direct event set for the stopped thread) |
| QlLinuxX8664Thread | thread.py | Ported | the TLS over the IA32_FS_BASE MSR (the set_thread_tls/save/restore); the QlArchIntel::msr accessor added (the x86.py cached_property); the other arch subclasses defer with their slices |
| the futex dispatch (`syscall_futex`) | `os/posix/syscall/futex.py` | Ported | the WAIT/WAIT_BITSET/WAKE/WAKE_BITSET ops (the PRIVATE_FLAG mask, the val3 bitset), the cur_thread handoff to the futexm, the unhandled-op emu stop; the syscall registration (futex/set_robust_list/sched_yield) |
| `syscall_set_robust_list` / `syscall_sched_yield` | futex.py / sched.py | Ported | the robust-list bookkeeping onto the cur_thread; the yield = the emu stop + the empty sched_cb (the gevent sleep(0) analogue) |
| the exit/exit_group multithread branches | `unistd.py ql_syscall_exit` | Ported | the _sched_cb_exit closure (stop_thread + the thread exit code), the plain path unchanged |
| `install_syscall_hooks` | posix.py load | Ported (refactor) | the per-arch hook install extracted from the single-shot run; the multithread and the plain paths share it (idempotent) |
| the loader shellcode elf_entry | elf.py | Ported (fix) | the shellcode path sets elf_entry = the shellcode base (the management's interp check stays honest; the python sets the os entry_point only - the port keeps the loader field consistent) |
| `tests/Thread_Test.cpp` | the management flows | Ported | the round-robin wake (the child's store+wake loop interleaves with the main's futex wait; the main exits 42; the wake's emu_stop bounds the slices), the all-blocked deadlock surfacing, the sched_yield continuation |

### Findings

- **the TB-boundary stop semantics (CORRECTED by the TbSemantics probes)**:
  the earlier note claimed the INSN-hook stop defers to the next TB boundary;
  the probe evidence (P1/P2/P3) pins the opposite - the stop is immediate
  (the pc = the hooked instruction + its size, the TB tail does not run).
  See the Phase 5 findings for the pinned accounting.
- **the resume pc reads the restored context** (the upstream emu_start reads
  the arch_pc AFTER the restore, not the original start address) - the first
  slice arms the pc from the start address and saves.
- **the deferred destruction pitfall**: the exit closure parks its own
  thread in the retire list while run_slice is still on the stack - the
  destruction must wait for the slice to unwind (the moved-from/std::thread
  style use-after-free class, the second instance after the cc ownership).
- **the HookRet RAII struck again**: a discarded hook_mem_unmapped temporary
  unregisters immediately - the held-handle rule applies to every hook.
- **the futex wait's block = the driver-model park** (the thread records the
  event pointer; the management polls is_set) - the gevent event.wait's cv
  blocking would hang the single host thread (the driver loop has nowhere to
  yield to).
- **the child-thread exit uses exit(60)** (the plain thread termination -
  stop_thread, no world stop); exit_group from the main stops the world
  (unistd.py verbatim).

## Phase 5 - the TLS variants + the clone/clone3 dispatch (266 passed + 1 skipped)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `QlLinuxARMThread` / `QlLinuxARM64Thread` / `QlLinuxMIPS32Thread` | `os/linux/thread.py` | Ported | the TLS over the TPIDRURO / TPIDR_EL0 coprocessor registers (the QlCprManager/QlCpr64Manager named access) and the cp0_userlocal (the CONFIG3_ULR bit 13 set); the save/restore ride the uc context + the explicit TLS; the spawn factory dispatches per the arch |
| `QlSyscallABIMipsO32` | `os/posix/syscall/abi/mips.py` | Ported | the a0-a3 args + the stack args beyond (the stack_read at the pointersize offsets), the a3/v0 error-flag return convention (the negative value inverts onto a3=1/v0=-value, the -1134 bound) |
| the clone/clone3 dispatch | `os/posix/syscall/sched.py` | Ported (core) | the CLONE_VM thread spawn through the management: the child's context (the pc past the clone syscall, the child's stack, the return 0), the CHILD_SETTID (the ctor's tid write), the SETTLS, the CHILD_CLEARTID (the _on_stop zeroing + the futex wake), the PARENT_SETTID, the emu stop + the add-thread event; clone3: the clone_args struct translation (the flags/stack/stack_size/tls/child_tid/parent_tid/exit_signal), the x86-64 arg pre-swap (the cancellation of the clone's swap) |
| the fork path (no CLONE_VM) | sched.py | Ported (deviation) | QlErrorNotImplemented: the upstream windows branch constructs the multiprocessing.Process object without ever starting it and runs the child code in the caller's greenlet (a broken placeholder); the port surfaces it as not-implemented |

### Findings

- **the child's context save must advance the pc past the clone syscall first**: the unicorn's INSN-hook pc still points at the syscall when the handler runs; the save before the set_arch_pc would snapshot the syscall address and the child would re-execute the clone.
- **the pc drift after the INSN-hook emu_stop (PINNED by the TbSemantics probe suite)**: the earlier TB-boundary guess is overturned by the probe evidence. The pinned semantics (the raw-unicorn probes, unicorn 2.x):
  - **P1 - the stop is immediate**: uc_emu_stop inside a UC_HOOK_INSN callback takes effect right after the hooked instruction - the TB tail does NOT run past the stop; the pc lands at the hooked instruction + its size (the natural post-instruction advance).
  - **P2 - the in-hook pc set gets the instruction's size re-added**: a set_arch_pc inside the INSN hook survives, but unicorn's post-instruction advance adds the hooked instruction's length onto it afterward (the effective resume pc = set + insn size). This is the drift mechanism: the clone handler's in-hook child-pc set + the parent's in-hook restore each had the +2 (the syscall's size) re-applied onto the live pc.
  - **P3 - no syscall re-fire on the resume**: a fresh emu_start after the stop does not re-execute the hooked instruction.
  - **P4 - the fresh-TB mid-TB restart**: the restart onto an address never used as a begin executes correctly (the taken-path store lands).
  - **P5 - the cached-TB restart (the 2026-10 study's CORRECTED verdict)**: the original "cached-TB mis-execution" was A PROBE ARTIFACT - the probe's own runaway code-hook guard (code_count > 64 -> uc_emu_stop) tripped in the child phase after the parent's jmp$ loop burned the budget (the code trace showed the child stopping after ONE instruction - indistinguishable from a mis-execution without the trace). The corrected P5 (MidTbRestartOnCachedTb, re-enabled, the guard defused between phases) PASSES: the cached-TB restart executes correctly. The uc_ctl tb flush is NOT needed (the flush experiment rode the same artifact).
  - **P6-P13 - the probe inventory (all DISABLED_ in the harness, all PASS with --gtest_also_run_disabled_tests)**: P6 the instrumented P5 (the per-phase traces), P7 the poisoning bisect (the natural-until / code-hook-stop / count-cap exits all clean), P8 the INSN-continuation interior TB (the parent's TB spanning the syscall + the body - the child's interior restart works), P9 the INSN-stop park + the second syscall, P10 until=0xffffffffffffffff (the port's emu_start argument shape), P11 the in-hook RIP write (the clone's -2 compensation shape), P12 the full uc_context save/restore switch, P13 the emu_stop inside the clone hook. Every shape passes with the store landing.
  - **P14/P15/P16 - the trampoline-replication round (all DISPROVED)**: P14 replicates the port's EXACT three-slice sequence (the clone hook's in-hook ctx save + the -2 compensation + the stop, the parent's slice re-entering +0x02 and parking via an INSN stop INSIDE that TB, the child re-entering the CACHED TB) - PASSES. P15 saves the child's uc_context AFTER the in-hook pc/sp writes (the pending-advance-capture hypothesis) - PASSES. P16 adds the in-hook guest-memory access (the CHILD_SETTID write + the futex's ctid read inside the INSN callbacks) - PASSES. **The resume-after-stop path, the ctx capture after the in-hook writes, and the in-hook mem access are all exonerated at the raw level** - the size-lag does not originate from any of them.
  - **P1x - the raw-unicorn verdict**: emu_start into a cached TB (whatever the begin provenance - an emu_start begin, an INSN-hook continuation, a uc_context restore) executes CORRECTLY on unicorn 2.1.4; no uc_ctl/flush/re-register sequence is needed. The nine probe shapes (P5, P8-P16) all pass.
  - **the REAL second-pass anomaly (the clone + the uefi fixtures, trace-pinned)**: on the SECOND execution through a cached region a UC_HOOK_CODE event fires carrying the PREVIOUS instruction's size (the clone: the taken-exit event at the store (+0x67) with size=2 = the jz's size, the pc walking +2 INTO the 11-byte store -> the mid-instruction UC_ERR_READ_UNMAPPED; the uefi: the call r10 event at 0x10027b with the mov r10's 7, the pc at 0x10027b+7=0x100282 -> the call falls through and the dispatch never reaches the field's address hook). The trigger could NOT be reproduced in the raw harness (the 9 probe shapes), so it is a port-side hook/dispatch interaction.
  - **the narrowed trigger candidates (the port-only surface, the next probes)**: (1) **the uefi's in-hook pc relocation**: the port's address-hook dispatch (dispatch_service -> QlOs::call -> the fcall unwind) performs set_arch_sp (the stack pop) AND set_arch_pc(retaddr) INSIDE the address-hook callback (the UC_HOOK_CODE at the field cell; the port's QlOs::call skips the pc write only when the emulation already stopped - the unicorn issue #1579 guard) - the second pass through the same field rides the CACHED cell TB and mis-pairs (the +7 walk at the second call site); the raw analog of the in-hook pc write alone (P11) is clean, so the full fcall/unwind layer needs replicating to pin further. (2) **the port's trampoline indirection chain**: the facade's hook_insn/hook_code route through the static trampolines (trampoline_trace/trampoline_insn) -> the dispatch_* methods -> the std::function hooks with the try/catch and the bound_check(pc_reader_) gate; the raw probes registered direct callbacks, so replicating the chain is the next probe. (3) the upstream-verbatim check pending: whether the upstream's uefi BS dispatch does the same in-hook set_arch_pc (os.py call does - the upstream may rely on the cell decode differing).
  - **the fix applied**: the clone handler compensates the parent's in-hook restore with the pre-advance (the set to after_syscall - 2 so the post-advance lands on after_syscall); the parent's slice-end pc now lands exactly at the clone's continuation (the trace evidence).
- **the mid-TB restart on a CACHED TB (the final verdict)**: the cached-TB restart itself is CLEAN raw (the P5/P8-P16 probe verdict - see the retraction above). **The uefi "second-pass anomaly" was RESOLVED as a FIXTURE ARTIFACT**: the event blob's .text section was sized 0x80 while the blob rides ~0x150 bytes — the tail (the check2's `call r10` and everything after) never loaded, and the pre-load byte dump (`[pre-load] 0x100274: 48 8b 0d dd 01 00 00 4d 8b 97 78 00 00 00 00 00 ...`) pinned the zeros directly. With the section sized to the code, the check2's dispatch works, and the two rip-relative `mov rcx` loads (the close and the re-signal) pointed at stale cells (the close loaded [0x100045c] = the interleaved create/check1 status garbage = 0x600000000; the re-signal loaded the check1's NOT_READY) — the original fault's `add [rax], al` with rax=0 was the zero-filled tail executing, not a unicorn mis-execution. The re-derived displacements make the full six-dispatch flow (the create, the check1 NOT_READY, the signal, the check2 SUCCESS, the close OK, the re-signal INVALID) ride green; the fixture was RE-ENABLED. **The P17 raw replication of the fcall/unwind-inside-address-hook shape (the stack_pop + the set_arch_pc inside the UC_HOOK_CODE callback, two call sites through the same cell) also PASSED** — the in-hook stack/pc manipulation is exonerated raw too.
- **the SetVariable/GetVariable round trip**: the blob's tail rode past the same 0x80 truncation; with the section fixed the round trip completes (the SetVariable stores the env, the GetVariable reads it back). The utf-16le name reads exposed a real port-side gap: the port's read_wstring appended the raw 2-byte units (the embedded NUL bytes — the env key = "M\\0y\\0V\\0a\\0r\\0" while the test read the plain "MyVar") — **the port's read_wstring now decodes utf-16le to utf-8** (the surrogate pairs combine, the lone surrogates render backslashreplace-style — the upstream's errors='backslashreplace' shape). Both fixtures RE-ENABLED and green.
- **the clone-join raw-shape exonerations (CLOSED)**: the mis-fire belongs to the CHILD's first slice (the clone's continuation at 0x23), where the taken-exit event at the store fires with the JZ's size=2 and the pc walks +2 into the 11-byte store. Cumulative size-checked exonerations: the cached-TB re-entry shapes (P5, P12), the in-hook stops/pc writes/mem access (P2/P8/P13/P16), the fcall/unwind-inside-address-hook shape (P17), the wrapper layer by inspection (trampoline_trace/dispatch_code = a plain per-hook iteration; QlArch::save/restore = plain uc_context; adjust_emu_start = identity; the emu_start args identical), the ranged-vs-global UC_HOOK_CODE registration (P18 — the facade's begin=0/end=huge shape, CLEAN), and the INSN dispatcher's full in-hook uc-call sequence (P19 — the six ABI reg reads, the ctx dance, the compensation, the trailing set_return_value RAX write + the log_api_call arch_pc read AFTER the stop — the stale-size re-latch hypothesis disproved; the taken path fires the nop's size=1 then the store's size=11, err=OK, store=42).
- **the clone-join bisect, cycle 1 (the [rs]/[clone]/[fwait] instrumentation)**: the trace pins the failing sequence exactly: **the parent's park ([fwait] val=0x7d1 — the CHILD_SETTID write already landed, done in the thread ctor in-hook) is followed directly by the CHILD's first slice ([rs] begin=0x11ff023) — there is NO child wake before the fault** (correcting the earlier "spawn and wake both worked" reading — the child faults on its first slice, re-entering the cached TB at 0x23 translated by the parent's slice 2, and never reaches its own futex wake). **The wrapper-level inspection is now complete**: Qiling::emu_stop = plain uc_emu_stop + the state flag; QlRegisterManager read/write/arch_pc = plain uc_reg_read/write; clear_internal_exception = a null store; the INSN registration shape = raw-identical (begin=1, end=0, the syscall id). **The surprise**: every port-side uc call in the failing path, replicated verbatim in composition (P19), executes the taken entry cleanly — yet the port's own run misfires. The port-only remainder: the per-event C++ machinery (the HookCtx allocation, the std::function indirection, the exception frames), the QlMem wrapper layer, the parent's in-hook uc_context save/restore round-trip (the one in-hook uc pair the P19 probe did NOT replicate), and the management's run_ready interleave between the slices. The bisect instrumentation ([rs]/[rs-end]/[clone]/[fwait] prints) is COMMITTED as the active study state and comes out when the study closes.
- **the clone-join bisect, cycle 2 (b1: the CHILD_SETTID in-hook write removed)**: with the thread-ctor's in-hook `write_ptr(set_child_tid_addr, tid, 4)` commented out (the address bookkeeping kept), the misfire REMAINS byte-identical ([fwait] val=deadbeef confirms the removal; the child's slice still fires 0x67 with size=2 and walks into the store) — **the CHILD_SETTID in-hook mem write is EXONERATED as the perturbing ingredient**.
- **the clone-join bisect, cycle 3 (b2: the parent's in-hook uc_context save/restore removed)**: with the in-hook parent-ctx save and its matching restore both commented out (the compensation and the child's ctx save kept), the misfire REMAINS byte-identically — **the parent's in-hook uc_context round-trip is EXONERATED**. Caveat: the companion b3 attempt (skipping run_slice's tail saves via an `if (!saved_context_)` guard) was TAINTED — the first-entry branch had already captured the start state, so all tail saves were skipped and the parent re-ran the setup firing a SECOND clone; the b3 exoneration stands on the as-run datum (zero between-emu_starts saves, the misfire still reproduced with the same 0x67/size=2 signature on the cached mid-TB entry), and the guard was reverted to the unconditional tail save.
- **the clone-join bisect, cycle 6 (b6: the DIRECT raw uc_hook_add INSN callback, the full real dispatcher)**: the facade's INSN registration was replaced with a bare `uc_hook_add(..., UC_HOOK_INSN, raw_cb, this, 1, 0, UC_X86_INS_SYSCALL)` whose callback calls the same `load_syscall()` — no trampoline_insn, no dispatch_insn, no HookCtx, no std::function, no exception frames — and **the misfire PERSISTS byte-identically** (one [clone], one [fwait], the child's slice fires 0x67 with size=2, the same walk, the same UC_ERR_READ_UNMAPPED) — **the facade's INSN plumbing is EXONERATED as the perturbing surface**.
- **the clone-join bisect, cycle 6b/7**: the (b6b) minimal-dispatcher variant (the inline P19 body, no load_syscall) DEGENERATED — no child spawn means no interleave, the main thread just looped, the run hit the timeout — INVALID as a bisect datum, reverted; the (b7) removal (the FS_BASE MSR bookkeeping: save_impl's in-hook MSR read + restore_impl's per-slice MSR write — uc-touching ops no raw probe ever exercised) was re-run against the REAL path (the direct callback + load_syscall) and **the misfire STILL persists** — the thread TLS/FS_BASE MSR ops are EXONERATED too.
- **the exoneration table after (b1)-(b7)**: the CHILD_SETTID in-hook write, the parent's in-hook uc_context round-trip, the between-emu_starts saves, the facade UC_HOOK_CODE tracer, the facade INSN plumbing (the direct raw hook), the FS_BASE MSR bookkeeping — ALL exonerated by removal; the cpu model and the stop guards exonerated by inspection (not registered for this fixture); every wrapper (emu_stop, the register manager, QlMem::read_ptr, the thread save/restore) inspected plain. **The remaining candidates: the management's run_ready interleave as a whole, and the engine-level state (the port's mappings/layout) — the next probe family would relocate the blob or drive the slices with raw uc calls on the port's engine (P19-on-the-port's-engine).** The bisect state ([rs]/[clone]/[fwait] prints, the b1/b2/b7 commented removals, the b6 direct registration, the tracer restored) is COMMITTED as the active study state. The clone-join test stays DISABLED_; the round-robin wake flow is green.
- **the clone-join bisect, cycle 8 (b8: the raw-engine probe — the management exonerated)**: a test-local probe driving the PORT'S OWN engine and mappings (`ql.arch().uc()` + the loader-mapped blob at 0x11ff000) entirely with plain `uc_*` calls — no QlLinuxThread, no management, no facade hooks — **REPRODUCES the misfire** (the child's slice fires 0x11ff067 with size=2, walks into the store, the same UC_ERR_READ_UNMAPPED). **The QlLinuxThread construction and the management's run_ready are EXONERATED by construction** — the misfire lives below them.
- **the clone-join bisect, cycle 9 (b9: the standalone harness + the port's blob)**: a fresh `uc_open` + hand mappings (the P19 harness) running the port's join blob **MISFIRES IDENTICALLY** — zero port code in the loop. **The port is fully exonerated as an ingredient: the trigger is the blob+unicorn interaction itself**, reachable by plain uc calls. (Two heredoc-mangling build breaks on the way — the pinned gotcha, fixed via the edit tool.)
- **the clone-join bisect, cycle 10 (b10: the minimal taken-entry blob — CLEAN)**: a minimal blob with the jz TAKEN DIRECTLY into the 11-byte store (the P19-style interleave: the clone's hook does the child-ctx dance + the compensation + the stop, the parent's park, the child's slice) runs **CLEAN — the taken-entry event at the store fires with size=11 and the store lands (42)**. So the bare taken-entry-into-a-multi-byte-instruction shape is NOT the trigger; the join blob's remaining features (the parent's loop traversal before the park, the long 0x3f displacement, the second jcc at 0x33, the exit block preceding the store) are the next ladder rungs. The b10 datum also confirms the child's slice lands correctly and spins at its jmp $ until the count expires — the interleave mechanics are sound in the minimal shape.
- **the clone-join re-enable, the suite confirmation**: `CloneSpawnsChildAndJoinWakes` rides the passing column (the
  disabled count 22 → 21; 356 passed at the (b13) close). **The ev stack-push slice (the next commit)**: the macos ev
  manager gained the RUN=True emit path (the `gen_stub_code` trampoline port from `os/macos/utils.py` verbatim, the
  emit's RUN split, the `trigger()` drain with the >6-params stack-push — the upstream's unbalanced-stack shape kept
  verbatim, the savedrip=deadcode ride deferred with the kext slices), the `emit_by_type(ins_cookie)` form with the
  ipf-cookie table, and the `emit_by_type_and_proto` protocol filter; `QlOsMacos` gained the `RUN` flag (true in the
  ctor, cleared at the run's end and on the error rethrow — the macos.py shape). **Both stub-execution probes are
  now RE-ENABLED AND PASSING (360/0/21)** — the suspected heap mapping was INNOCENT (QlMemoryHeap self-maps its
  chunks at [0x2000000, 0x3000000), the trampoline write is host-side uc). The real faults, three stacked: (1) the
  fixture's cb stores used `48 89 3D disp32` — modrm rm=101 is the RIP-RELATIVE special case, so the "absolute"
  disp32 landed the stores at base+0x47+0x2000; the absolute form needs the SIB byte `48 89 3C 25 disp32` (extend
  the (b13) mechanical-audit pin: verify the ADDRESSING MODE, not just the reg field); (2) **a real port bug**:
  `Qiling::run(begin)` set `entry_point_` but never `entry_point_set_`, so `run(begin=cb)` silently emu_started at
  the loader entry where the ret popped an extra param into a wild jump — fixed to ride the optional's presence
  (the upstream None-ness); (3) the trigger's `run(begin=cb)` until = `cb + len(code)` is 0x40 PAST the blob end
  (unreachable by construction — the upstream closes these runs via the deferred kext savedrip machinery), so the
  fixture parks the cb with a jmp and stops the slice via a `hook_address` at the park (the eoe-trap device). The
  full instruction trace proved the stub/cb/cleaner/park flow executes perfectly once the stores are absolute.
  Next: the socket/ipf emitters (the net_*/ctl_* methods) that ride the now-present emit surface.
- **the socket/ipf emitters LANDED (the ev manager's remaining upstream surface minus the net_send/net_recv pair)**:
  the `SocketEvent` (10 values) + `NetworkProtocol` (the verbatim 105-entry IPPROTO table, wrapped in
  push_macro/pop_macro guards — the winsock IPPROTO_* macros collide with the enumerator names, the types.hpp S_IF*
  pattern with restore) tables + `base_event_socket = 0x1000`; the manager gained the endpoint seeds
  (192.168.13.37:1337 / 10.2.13.38:1338 with the babe-c0de-be57/babe-feed-face macs — the ports stored host-order,
  gen_sock writes the sin_port network-order), `gen_sock` (the 16-byte sockaddr_in_t), `net_new_socket` (the
  sflt_attach emit + the trigger + the cookie read-back through the holder pointer), the ctl_connect/disconnect/
  send/setopt/getopt emitters (the sockaddr_ctl_t/mbuf_t/sockopt_t images on the heap; the mbuf_t 256-byte shape
  with mh_data@16/mh_len@24/mh_type@28/mh_flags@30 and the M_dat fields verified against the upstream ctypes via
  a live sizeof dump), and the net_connect_out/in + net_disconnect + net_set_option/get_option cascades (the
  SocketEvent.value - base_event_socket notify offsets verbatim). `EvJob` gained the event `type` (the upstream
  job tuple carries the QlMacOSEv object). **Two upstream verbatim findings pinned**: net_connect_out reads an
  unbound local `cookie` (a latent upstream NameError — the port takes the cookie as the parameter, documented);
  and emit with no registered (name, type) callback is a silent no-op (the fixtures must register listeners
  first). **Deferred to the kext slice**: net_send/net_recv (the scapy packet build — a hand-rolled Ether/IP
  builder or the fixture demand will pin the shape), sysctlbyname and the kauth_* emitters (they ride the
  kernel-symbol/savedrip machinery). Six fixtures green (GenSockBuildsSockaddrIn, CtlConnectEmitsSockaddrCtl,
  CtlSendBuildsMbuf, NetNewSocketReadsGuestCookie, NetConnectOutCascade, NetSetOptionCarriesSockopt); 366/0/21.
- **the mach_msg message-path machinery (two slices)**: the `MachMsgHeader`/`MachMsg` wire format (mach_port.py —
  the 24-byte header, the content window addr+24..addr+ssize with the **ssize-overrides-msgh_size quirk** verbatim,
  the read/write mem bodies) + the `MachHostServer`/`MachTaskServer` MIG reply builders (subsystems.py verbatim:
  the host_info HOST_BASIC_INFO/HOST_PRIORITY_INFO fixed cells, the clock/semaphore/special-port replies with the
  16-byte port trailers — port/pad1/pad2/disposition 0x11/type/pad-end) + the `QlOsMacos::deal_with_msg` dispatch
  (the msgh_id routes 200/206/3418/3409 to the servers, the reply writes back over the request buffer in place,
  anything else throws the "Mach Msgid Not Found" QlErrorBase) + the `mach_msg_trap` registry entry (the 6-param
  proto: args, opt, ssize, rsize, rname, timeout). **Two pinned findings**: (1) the upstream parses NO
  MACH_SEND/MACH_RCV option flags — the `opt` argument is only logged, every trap rides the id dispatch verbatim
  (the user-requested flag-branch coverage collapses into the msgh_id branches); (2) the mach-trap ids ride the
  0x1000000 range in the guest (rax=0x100001f — the fixture's plain 31 never dispatched; the map_syscall.py
  0x1000000-range keys are the GUEST-side trap numbers, and the x86 mach traps are invoked with rax = 0x1000000 |
  trap). The fixture harness runs the helper via make_unique<Qiling>(std::move(options)) — the Qiling is neither
  copyable nor movable, and binding `auto& ql = *helper()` dangles the temporary (the SEH 0xc0000005 trap — the
  unique_ptr temporary dies at the declaration's end). Five fixtures: MachMsgHostInfoReplyReturnsSuccess (the
  full in-emu trap ride: the blob → rdi/ssize → the id-200 dispatch → the 88-byte reply verified cell by cell →
  rax=KERN_SUCCESS), MachMsgUnknownIdThrows, MachMsgClockServiceAndTaskPorts (the 206/3418/3409 trailer ports
  0x803/0x903/0x707), MachMsgHostInfoPriorityFlavor (the 72-byte priority reply), MachMsgHostInfoShortContentAndBad
  FlavorThrow (the <16-byte guard + the unknown-flavor throw); 371/0/21.
- **the clone-join ladder, cycles 12-13 (b12/b12b + the (b13) delta bisect): THE MISFIRE WAS A FIXTURE ARITHMETIC ERROR - RETRACTED IN FULL.** The (b12)/(b12b) "reproducer" blobs' pad rows fell short of the claimed 0x4d store offset (37 bytes of 0x90 padding instead of 41/56), so the child's taken jz landed at 0x4d on ZERO-FILLED page memory, not on the store - the "taken-entry fires size=2" was unicorn faithfully executing the misaligned bytes. The python 2.1.4 cross-check (the correct 0x38 pad) was right all along; the C++/python divergence never existed. The (b13) bisect (the guard removal, the silent hooks, the standalone main, the /MT vs /MD, the prior uc_open, the LoadLibrary of the sibling dlls, the minimal gtest binary - all still misfiring with the mispadded TU, then mechanical blob audit) exposed it. The **port's own join blob had the same one-byte error** (the child jz targeted 0x67 while the store sat at 0x66; the parent_done at 0x54 vs the jz's 0x55) - the multi-week cached-TB-restart/mid-instruction-walk study, the b1-b12 ladder, and the candidate upstream issue all collapse into this fixture bug. With every blob mechanically aligned to its jz targets: **the corrected (b12) and (b12b) rungs run CLEAN** (the taken-entry fires size=11, the store lands 42), and **CloneSpawnsChildAndJoinWakes is RE-ENABLED AND PASSES** - the port's clone join flow was correct all along. **The fixture discipline pin**: every hand-built blob's store offset must be verified mechanically (count the initializer bytes, compare against the jz displacement) before a probe run is trusted. **There is no candidate upstream unicorn issue.**
- **the clone-join deletion bisect EXHAUSTED — the study state**: every individually-removable port-side operation in the failing path (the CHILD_SETTID in-hook write, the parent's in-hook ctx round-trip, the between-emu_starts saves, the facade code hook) is EXONERATED by removal, yet the misfire persists through every combination. The port's failing path is now uc-call-for-uc-call identical to the clean P19 composition (every wrapper inspected plain: Qliling::emu_stop = uc_emu_stop + the flag; QlRegisterManager = uc_reg_read/write; QlMem::read_ptr = uc_mem_read + unpack; the INSN registration = the raw-identical shape). **The remaining un-removable structure: the INSN-side facade plumbing as a whole** (trampoline_insn → dispatch_insn → load_syscall riding the HookCtx/std::function indirection and the C++ exception frames) and the management's run_ready interleave — neither deletable without losing the dispatch. **Next cycle (b6, surgery not deletion): a test-local direct `uc_hook_add` INSN hook driving a minimal dispatcher against the port's own engine (ql.arch().uc()), bypassing the facade's INSN registration — if the misfire vanishes under the direct hook, the facade's INSN plumbing is the perturbing surface; if it persists, the delta is below every port layer and inside the uc interaction pattern itself.** The bisect instrumentation ([rs]/[clone]/[fwait], the commented-out SETTID write and in-hook ctx pair, the #if 0'd tracer) is COMMITTED as the active study state and comes out when the study closes. The clone-join test stays DISABLED_; the round-robin wake flow is green.
- **the mips O32 return convention** inverts the negative returns onto the a3 flag pair - the same shape as the real kernel ABI.

## Phase 5.5 - the os/freebsd dialect (the first deferred-subsystem slice)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `QlOsFreebsd` | `os/freebsd/freebsd.py` | Ported | the FREEBSD type over the posix base; the amd64 fcall; the load() GDT/segment setup (the x86_utils GDTManager + SegmentManager64 shape, ported compactly); the run() rides the posix |
| the freebsd x8664 table | `os/freebsd/map_syscall.py` | Ported | the 410-entry table (the freebsd numbers); the posix `__get_syscall_mapper` went virtual (the `map_syscall` method) — the os-specific table resolution, the upstream shape |
| `const.hpp` | `os/freebsd/const.py` | Ported | the CTL_*/KERN_*/HW_* identifiers + the FREEBSD_OSRELDATE (stable/12, 2021.3.12) |
| the 6 handler deltas | `os/freebsd/syscall.py` | Ported | __sysctl (the OSRELDATE + the NAME2OID/hw.pagesizes paths), sysarch (the FS BASE MSR, the "wild guess" verbatim), sigprocmask, clock_gettime (the freebsd timespec, the *1e6 nsec arithmetic verbatim), __getcwd (the posix getcwd delegate, added to the posix layer), fstatat (the stat-module defer, surfaced as not-implemented) |
| `freebsd.ql` | `qiling/profiles/freebsd.ql` | Ported (deviation) | the verbatim copy + the [CODE] load_address added (the upstream's profile lacks it; the port's shellcode fixtures read it — the documented deviation) |
| `tests/Freebsd_Test.cpp` | the fixture flows | Ported | the sysctl both paths (the OSRELDATE constant write; the NAME2OID hw.pagesizes vec + the length), the clock_gettime (the epoch + the nsec bounds), the sigprocmask, the sysarch (the msr read-back), the getcwd ("/" + the NUL), the fstatat (the not-implemented raise) — 7 fixtures |

### Findings

- **the freebsd dialect is thin where the posix base is thick**: the 783-line
  module needed only the 6 handler deltas + the table + the GDT; the syscall
  dispatch, the fd table, the fcall and the ABI ride the Phase 5 base as-is.
- **the x86-64 imm32 forms**: the `49 C7 C5` (the mov r8, imm32) did not land
  the value into the ABI's 5th slot in the fixture — the `41 B8` (the mov
  r8d, imm32) does; the test blobs use the shorter form (the fixture note,
  not a port defect — the encoding difference is unexplained, the P5-style
  probe did not chase it).

## Phase 5.6 - the os/qnx dialect (the ARM32 kercall slice)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `QlOsQnx` | `os/qnx/qnx.py` | Ported | the QNX type over the posix base; the R12 id-register ABI override (`QlSyscallABIArmQnx`, the upstream `QlAArch32QNX` shape); the interrupt-2 kernel-entry hook (`hook_intno(hook_syscall, 2)`, installed unconditionally — the upstream early-returns for `ql.code` and its hooks then never install; the port installs so the shellcode fixtures ride it) |
| the ARM kercalls table | `os/qnx/map_syscall.py` | Ported | the 101-entry verbatim table (the kercalls.h numbers); the dispatcher resolves through the virtual `map_syscall` |
| `const.hpp` | `os/qnx/const.py` | Ported | the NTO_*/SYSMGR_*/pthread sync constants; the EINVAL/S_IFMT names guarded behind the windows.h macro collisions |
| `structs.hpp` | `os/qnx/structs.py` | Ported | the _sync/_sync_attr/_thread_local_storage layouts (all 32-bit cells) + the SYNC_OWNER_BITS helper |
| `helpers.hpp` | `os/qnx/helpers.py` | Ported | the QnxConn record + the get_message_body (the iov form rides the first entry only — the upstream shape verbatim) |
| the run() prelude | `qnx.py run()` | Ported | the OS32 profile addresses, the syspage map + the rootfs syspage.bin image, the TLS seed (errptr/pid/tid + the derived owner), the cpupage cells |
| the handlers | `os/qnx/syscall.py` | Ported (complete) | channel_create (the counter), thread_destroy (the (-1,-1,status) exit), clock_time (the CLOCK_REALTIME ns read; the set-time warn+(-1)), clock_cycles (the 0xFE000000 id, the ns simplification), sys_cpupage_get/set (the ADDR/PLS/SYSPAGE indexes), connect_attach/detach (the ND+CLOEXEC pins, the coid counters), connect_flags, connect_client_info (the scoid=-1 record), sync_create/sync_mutex_lock/sync_mutex_unlock (the ker_sync.c stamps + the stubs), msg_sendv/msg_sendvnc (the type dispatch → the message.py handlers) + `message.cpp`: io_write (the iov[0] header + the iov[1] payload, the posix write delegate), io_close (the conn's fd clears first, the do_close delegate), mem_ctrl (the flat 24-byte struct, the unknown subtype throws, the known subtype warns and returns -1 — the upstream TODO verbatim), the io_connect COMBINE extra-iov walk (the align slot skipped at sparts>2, the fourth-iov _IO_PATHCONF name check with the name==5 → 1024 early return — the verbatim quirk; the _IO_STAT branch is written (the packer + the reply-iov#2 fstat) but its happy-path fixture stays PARKED — see the park table) |
| the posix stat-packing family + the fstat syscall | `os/posix/stat.*` + `syscall.cpp` | ✅ 0fc59a8 / 8ce4463 | the stat.py port: the QNX/Linux-x86 layout tables (the duplicate-column quirks verbatim), the ctypes-shape packer (the min(width,pack) alignment), the get_stat_layout dispatch; syscall_fstat ports __do_fstat (the fd range/EBADF ladder, the OSError→-EIO branch, the pack via the layout dispatch) — the delegate the parked COMBINE branch will ride when it resumes |
| the stat/lstat syscall family (statFamily) | `syscall.cpp` + `filestruct.cpp` | ✅ 2925f15 | statFamily ported (the cstring path, the transform + the is_safe_host_path check, the host stat via the new host_stat_path helper with the _WIN32 no-follow deviation noted, the OSError→-errno branch); the stat64 packing family (the LinuxX86Stat64 table + the get_stat64 ladder with the x8664→linux-x86 fallback verbatim); the stat/lstat (+ the *64) registrations — the lstat's pack_stat64_struct choice is the verbatim quirk; the fixture asserts both images (the x8664 144-byte and the i386 stat64 96-byte) and the -ENOENT branch |
| the newfstatat/fstatat64 family (transform_path) | `syscall.cpp` + `filestruct.cpp` | ✅ 48dbefc | the transform_path port (the '/'-prefix rootfs join, the AT_FDCWD resolution, the AT_EMPTY_PATH fd-name flow, the 0<dirfd<NR_OPEN dirfd branch, the verbatim fall-through throw); the fstatat host path (the POSIX fstatat, the _WIN32 no-fstatat deviation throwing for the real-dirfd requests); the AT_SYMLINK_NOFOLLOW flag is ignored verbatim (the upstream's os.stat always follows); the fixture rides the absolute/AT_EMPTY_PATH/-ENOENT branches — the x86-64 syscall 4th arg rides r10 (the blob gotcha re-pinned) |
| the statx syscall (the Statx tables + the float32 timestamp quirk) | `stat.cpp` + `syscall.cpp` | ✅ | the Statx64/Statx32 tables (the 256/164-byte images, the _pack_ 4/8 verbatim, the StatxTimestamp cells riding the struct.pack('f')→unpack('i') float32 BIT-PATTERN conversion — the sign-extend-into-tv_sec quirk pinned), the glibc major/minor splits, the hardcoded STATX_BASIC_STATS 0x7ff mask, the catch-all Exception→-1 branch (the verbatim -1, NOT -errno — unlike newfstatat); the fixture rides the absolute-path image and the missing-path -1 — the dirfd-relative requests stay POSIX-only (the _WIN32 NotImplementedError verbatim) |
| the statfs/fstatfs stub (ql_syscall_statfs / ql_syscall_fstatfs) | `syscall.cpp` | ✅ | the verbatim stub — NOT the packing-table family the earlier note predicted: the upstream writes 96 copies of the ASCII '0' (0x30) into the buffer (the b"0" * (12*8) quirk, NOT NULs), ignores the path/fd arguments entirely, and answers -1 on the write failure (the bare except); the fixture pins the 0x30 fill, the ignored /nonexistent path and fd=-1, and the unmapped-buffer -1 |
| `qnx.ql` | `qiling/profiles/qnx.ql` | Ported (deviation) | the verbatim copy + the [CODE] load_address (the same deviation as freebsd.ql) |
| `tests/Qnx_Test.cpp` | the fixture flows | Ported | 16 fixtures: the channel_create + the thread_destroy exit; the clock_time read; the clock_cycles (the literal-pool blob for the 0xFE000000 id + the ARM32 return-register truncation pin); the cpupage set/get PLS roundtrip; the connect attach/detach (the side-channel coid); the flags + the client_info record (the KERNEL pid 1996); the sync create/lock stamps (the TLS owner (pid<<16\|tid), the WAITING bit clear); the msg_sendv io_write (the iov form, the byte-count return); the sys_conf both sub-paths (the _CONF_NUM pagesize reply + the _CONF_STR libpath iov string); the io_connect OPEN (the 40-byte header, the fd into the connection, the link reply umask); the io_read (the flat form, the nbytes==-rparts pin); the io_lseek (the 8-byte position reply); the io_stat (the QNXARMStat 18-cell packing); the mem_map (the anon private page, the prot>>=8, the <QQQ> reply); the channel_destroy (the upstream-absent fall-through pin); the io_close (the two-sweep close/EBADF ride); the mem_ctrl (the known subtype -1 + the unknown-subtype throw, which distinguishes the wired handler from the dispatcher's no-hook fall-through); the io_connect COMBINE+PATHCONF (the name==5 → 1024 ride); the io_devctl (the no-handler fall-through pin) |

### Findings

- **the ARM32 fixture encodings** (the session's tripped-over points, pinned):
  the MOV immediate puts Rd at bits 15-12 (a misplaced nibble silently targets
  the Rn field); the rotate field is bits 11-8 (the `#0x30` written with the
  rotate nibble set became `#0x30000000`); the 0xFE000000 kercall id does not
  fit a rotimm — the fixture pools it via `ldr r12, [pc, #imm]` with the
  little-endian literal; addresses above 0xFF00 are not single-rotimm
  encodable either (`mov r4, #0x2304` silently encodes `#0x2300` — the
  low byte is dropped by the rotate; use `mov r4, #0x2300` +
  `add r4, r4, #4`); the fixture scratch regions must not overlap (a
  4-entry iov array at 0x2100 runs to 0x211F and silently clobbers a hdr
  body parked at 0x2110); the message-table's `sflag` rides
  `file_sharing_modes` (SH_COMPAT=0 — not 1).
- **the ARM32 return register truncation**: the dispatcher's set_return_value
  writes R0 (32-bit) — a 64-bit ns return truncates to its low 32 bits (the
  upstream's r0 write has the same shape; the clock_cycles fixture pins it).
- **the `QlSyscallABIArm` lost its `final`** to let the QNX ABI derive — the
  upstream models the inheritance (QlAArch32QNX(QlAArch32)) the same way.
- **the mem-unmapped retry semantics (CORRECTED — not a deviation)**: the
  session probe had flagged the port's `dispatch_mem` as deviating; reading
  the upstream `core_hooks.py _hook_mem_cb` shows the port is verbatim — a
  hook whose bound_check matches marks the access handled (whatever it
  returns; the return only carries QL_HOOK_BLOCK for the loop break) and
  unicorn then retries the access. The raise fires only when nothing matched
  the bound check (the upstream raise, ported). The observed infinite retry
  is the shared unicorn semantics for a mem hook that does not map the
  memory — a hook-authoring gotcha, not a port defect.
- **the Qiling-facade UC_HOOK_CODE on ARM did not fire in the session probe**
  (the same blob ran fine — the INTR hook fired, the code hook never did; the
  CoreHooks unit tests pass on the raw path). Open observation, not chased
  further in-session.

## Phase 6 - the os/dos dialect (the real-mode interrupt slice)

| File | Python counterpart | Status | Notes |
|---|---|---|---|
| `QlLoaderDOS` | `loader/dos.py` | Ported | the bare COM (the profile [COM] start_cs/ip/sp), the MZ-headered COM (the ComParser over the MZ header fields), the MBR (the 0x7C00 entry, the dx=0x80 BIOS handoff, the QlDisk mapping on the "0x80" drive key) + the full 1MB map; the curses excepthook plumbing is a TUI artifact and is not ported |
| `QlDisk` | `os/disk.py` | Ported | the CHS/LBA wrapper over QlFsMappedObject (the 1-head/1-cylinder raw-file shape, the lba/read_sectors/read_chs/write_chs surface) — the disk.py's only consumer is the dos slice |
| `QlOsDos` | `os/dos/dos.py` | Ported | the FLAGS register bits + the set/test flag helpers, the (intno, ah) interrupt dispatch with the user CALL/ENTER/EXIT api maps keyed by the leaf tuple (the set_api shape verbatim), the handles/handle_next for int21, the [KERNEL] version/ticks_per_second, the run() prelude |
| the utils | `os/dos/utils.py` | Ported | bin2bcd/bcd2bin, linaddr, read_dos_string ($-terminated), read_dos_string_from_ds_dx |
| the handlers | `os/dos/interrupts/*.py` | Ported (complete) | int10 (the console-detached shape: the resolution map verbatim, the cursor/scroll no-ops, the null-stdscr attr read ax=0x0720, the teletype echo via console_out), int13 (the reset, the CHS read, the drive params, the extensions check, the LBA read/write over QlDisk), int15 (the APM leaves — the shutdown-request stop — and the us-wait), int16 (the blocking key read over the injected stdin + the SCANCODES table; the poll throws NotImplemented), int19 (the MBR reload + the cs=0x07C0 transfer), int1a (the elapsed ticks, the BCD RTC time/date, the days-since-1980), int20 (the ah=13h no-op), int21 (the full leaf set: the char/string print, the version, the file open/close/read/write/delete, the alloc stubs, the 4c exit) |
| `dos.ql` | `qiling/profiles/dos.ql` | Ported | the verbatim copy |
| `tests/Dos_Test.cpp` | the fixture flows | Ported | 7 fixtures: the HI.COM ride (the 09 print + the 4c exit + the user ENTER/EXIT api hooks — the upstream test_dos shape); the int1a clock (the BCD ranges + the ticks al=0); the MBR two-pass boot through int19 (the dl=0x80 handoff + the QlDisk reload); the int13 LBA read (the DAP + the marker sector over the mapped image); the int15 APM shutdown stop; the int16 key read ('A' → al=0x41/ah=0x1e via the injected stdin); the int10 mode set + the null-stdscr attr read |

### Phase 6 findings (upstream-parity notes)

- **the `hook_intr`/`hook_intno` HookRet is RAII** — discarding the returned
  handle unregisters the hook silently (the dos int dispatch initially never
  fired; the posix/freebsd/qnx slices store their hooks in members, the dos
  now does too). Pinned by the debugging trail.
- **the raw-unicorn 16-bit INTR probe** (`TbSemantics.RealModeIntHookRawProbe`,
  DISABLED_-prefixed with the measured note) — int 0x21 + a UC_HOOK_INTR
  handler + emu_stop works at the raw 16-bit level; the port-level failure
  was the RAII unregister, not a unicorn quirk.
- **the ARM/x86 fixture encoding pins** (the session's tripped-over points):
  the modrm reg field for the byte stores (AL=0x06 CL=0x0E DL=0x16 BL=0x1E
  AH=0x26 CH=0x2E DH=0x36 BH=0x3E) — the earlier CL/DL stores rode the BL/CH
  encodings and passed by the value coincidence; the je rel8 displacement is
  measured from the instruction END (the +5-vs-+4 off-by-one).
- **the python-heredoc escape mangling** struck again on the C++ char
  literals (`'\b'`/`'\t'`/`'\r'`/`'\''` became the control bytes) — the
  established rule stands: the escape-bearing edits go through the edit
  tool, never the python heredoc.

## Phase 6.5 - the os/uefi service-table phase continues (the BS dispatch + the protocol round trip)

Building on the Phase 6 service-table skeleton (the ST layout, the BS/RT
descriptor walk, the dxeapi-shaped dispatch), this slice landed the
protocol-handler pairs and closed the loop end to end:

| Piece | Upstream counterpart | Status | Notes |
|---|---|---|---|
| the BS protocol pair | `bs.py hook_InstallProtocolInterface` / `hook_HandleProtocol` | Ported | the common.py `InstallProtocolInterface`/`HandleProtocol` verbatim (the handle==0 heap alloc, the per-handle GUID-string dict, the `EFI_UNSUPPORTED` miss) + the `EFI_STATUS` error-bit constants (the const.py shapes) in `services.hpp` |
| the pool/pages stubs | `bs.py hook_AllocatePages`/`FreePages`/`AllocatePool`/`FreePool` | Ported | the dxe shape verbatim (the AllocateAddress map branch carries the upstream TODO note verbatim; the pool type TODO too) |
| the fixture | `tests/Uefi_Test.cpp` | Ported | `InstallThenHandleProtocolRoundTrip`: the module installs the GUID at the .data cells and immediately HandleProtocols it back (the blob walks gST->BootServices twice, reading the Install field at `gBS+0x80` and the HandleProtocol field at `gBS+0x88`) |
| the BS surface completion | `bs.py` (the full descriptor) | Ported | the table corrected to the FULL upstream 44-field order (the compacted Phase-6 list had HandleProtocol at 0x88 — the spec/upstream slot is 0x98 with Reinstall/Uninstall at 0x88/0x90) + the remaining handlers: GetMemoryMap (the SUCCESS stub), CreateEvent/CreateEventEx (the shared body, the event id = len(events) — the id REUSES after a CloseEvent, verbatim), SetTimer/WaitForEvent (the SUCCESS stubs), SignalEvent/CloseEvent/CheckEvent (the utils.signal_event shape: the Set flag + the notify_list append), Reinstall/UninstallProtocolInterface (the common.py NOT_FOUND walk), RegisterProtocolNotify (the event_guids side-map), LocateHandle/LocateHandleBuffer (the LocateHandles helper + the BUFFER_TOO_SMALL flow), LocateDevicePath (SUCCESS), InstallConfigurationTable (the raw-GUID-bytes entry walk over the ST conftable cells), LoadImage/StartImage/UnloadImage/Exit/ExitBootServices (the emu_stop stubs + the upstream TODO notes), GetNextMonotonicCount (the os monotonic_count pre-increment), Stall/SetWatchdogTimer/ConnectController/DisconnectController/CloseProtocol/ProtocolsPerHandle (the SUCCESS stubs), OpenProtocol (the LocateProtocol body over the OpenProtocol layout), OpenProtocolInformation (NOT_FOUND), CopyMem/SetMem (the raw mem ops), CalculateCrc32 (the CRC-32 body) |
| the event-family fixture | `tests/Uefi_Test.cpp` | DISABLED_ | `DISABLED_EventFamilyCreateSignalCheckClose` — the create/check1/signal dispatches flow but the SECOND call to the same CheckEvent field (0x4000200) faults with a 1-byte UC_MEM_READ_UNMAPPED at [0] while the first call to the same field dispatched cleanly; the second-dispatch-to-a-hooked-field anomaly needs the dispatch-path study (the signature + the instrumentation live in the fixture's comment) |
| the RT variable services | `rt.py` (the full descriptor) | Ported | the RT table corrected to the full upstream 14-field order (GetTime, SetTime, GetWakeupTime, SetWakeupTime, SetVirtualAddressMap, ConvertPointer, GetVariable, GetNextVariableName, SetVariable, GetNextHighMonotonicCount, ResetSystem, UpdateCapsule, QueryCapsuleCapabilities, QueryVariableInfo) with the GetVariable/SetVariable bodies verbatim (the store rides ql.env — the `env_mut()` accessor added; the WSTRING name read via the utils read_wstring; the APPEND/AUTH/TODO branches verbatim; the FIXME default-attribute set on the read), GetTime (the 16-byte EFI_TIME write from the localtime), GetNextHighMonotonicCount (the high-count write), ResetSystem (the emu_stop), the remaining verbatim SUCCESS stubs; the GetNextVariableName ported over the env["Names"] \0-joined shape (the upstream keeps a python list object — the serialization is the port-adapted shape; the missing Names returns EFI_NOT_FOUND where the upstream's KeyError would abort) |
| the RT round-trip fixture | `tests/Uefi_Test.cpp` | DISABLED_ | `DISABLED_SetVariableThenGetVariableRoundTrip` — the SetVariable (the first dispatch) rides and returns but the emu restarts mid-instruction (the fault pc = blob+0x81, inside the second block's mov r10 displacement) and faults with UC_ERR_READ_UNMAPPED before the GetVariable call; the same anomaly family as the event fixture (the signature + the instrumentation live in the fixture's comment) |

### Phase 6.5 findings (upstream-parity notes)

- **the BS service-table field layout**: the descriptor order rides the
  table verbatim — `kTableHeaderSize` (24) + index*8; InstallProtocolInterface
  (index 13) lands at `gBS+0x80` and HandleProtocol (index 14) at `gBS+0x88`.
  The fixture's first-draft `[gBS+0x98]` read was the LocateProtocol slot.
- **the post-call register state in the fcall adapter**: only `rax` carries
  the return value; the blob cannot re-derive `gBS` from `rax` after a call
  (rax = EFI_SUCCESS = 0) — the fixture's second field load went RIP-relative
  straight at the field address (length-preserving, no later-disp shifts).
- **the fixture imm64 base gotcha**: the hand-encoded `mov rcx, imm64`
  immediates wrote `0x1000400` instead of `0x100400` (byte 3 = 0x01 puts the
  bit at position 24) — the module's .data reads then faulted with uc_err 6
  while the map list showed the region correctly mapped at 0x100000. The
  blob edits stay length-preserving (the established rule) and the imm64
  byte order needs the LE double-check.
- **the upstream Interface param is stored verbatim** (common.py:40,
  `dic[params["Protocol"]] = params["Interface"]`, no dereference), so the
  round-trip assertion pins the passed-through pointer, not a dereferenced
  interface value.
- **the REX.B trap struck the r15-base field loads**: `4C 8B 97` decodes as
  `mov r10, [rdi+disp]` (rdi=0 → the [0x50] fault) — the r15 base needs the
  `4D` REX.WB prefix; the same class as the freebsd `48 C7 C5` (rbp) trap.
  The RIP-relative form (`4C 8B 15`) needs no REX.B and avoids the whole
  class — prefer it for the absolute field loads in the fixture blobs.
- **the open item: the second pass through a multi-call blob mis-fires with the size-lag** —
  both the event fixture (the second call to the same CheckEvent field) and the
  RT round-trip (the SetVariable → the GetVariable sequence) show the first
  dispatch riding cleanly and the second-pass UC_HOOK_CODE event carrying the
  PREVIOUS instruction's size (the event fixture: the call r10 event at
  0x10027b with the mov r10's 7, the pc at +7 skipping the call; the RT's
  fault pc = blob+0x81, inside the second block's mov r10 disp). The TB-restart
  study (the P5/P8-P13 probe verdict) EXONERATES the cached-TB restart itself —
  the mechanism is the SECOND-PASS SIZE-LAG signature (shared with the
  clone-join blocker; see the Phase 5 finding), a port-side hook/dispatch
  interaction, not the raw unicorn TB cache. Both fixtures DISABLED_ with the
  signatures.

## Phase 7 - the loader/macho container parser (the macho_parser port)

The Mach-O container parser over the upstream's hand-rolled
`qiling/loader/macho_parser/` (no parsing dependency upstream — struct.unpack
over the raw bytes — so the port is hand-rolled too; decision D17's LIEF
mapping applies only where the upstream itself carries the dependency). The
parse shape: the ctor runs `parseFile()` (parse_header → parse_load_command
→ parse_data), the header stage gates validity by the magic dispatch
(MAGIC_64 → the 32-byte BinaryHeader, the x8664 CPU-type check pinned) and
the load-command stage walks the cmd_id/cmd_size pairs.

| the piece | the port file | the state | the notes |
|---|---|---|---|
| the container skeleton (the header + the magic/CPU checks) | `qiling/loader/macho.hpp/.cpp` | ✅ 5cfb208 | `MachoImage` + `parse_header()`; `valid()` rides the parsed magic |
| the LC_SEGMENT_64 walk | `qiling/loader/macho.cpp` `parse_load_command()` | ✅ 2320192 | the Segment/Section records with the data.py content slicing; the unknown commands skip by their declared cmd_size |
| the LC_UNIXTHREAD/LC_MAIN entries | `qiling/loader/macho.hpp/.cpp` | ✅ 119a801 | the X86_THREAD_STATE64 state (the entry = the rip, the 16th state slot after the 16 GPRs) and the LC_MAIN entry_offset/stack_size pair |
| the remaining commands (LC_UUID, LC_DYLD_INFO…) | — | defer | the loader slices add them per need |
| the fat-header branch + parseData | — | defer | the FatHeader slice + the data.py stage |
| the fat-header branch | `macho.hpp/.cpp` | ✅ | the MAGIC_FAT dispatch: the big-endian arch_num + the 20-byte FatInfo records (the getBinary verbatim quirk — the archtype parameter is IGNORED, the scan takes the first x8664 slice then the first arm64), the picked slice re-sliced into the container and re-parsed through the 64-bit header + the load-command walk; the no-match case degrades to the invalid image (the deviation: the upstream would crash on the None slice) |
| parseData (the data.py stage) | `macho.hpp/.cpp` | ✅ | the port's walk already merged parseLoadCommand + parseData (the single pass — the observable shape identical to the upstream's two passes; the global sections-list/sections_index ride skipped, the consumers index segments()[i].sections); this slice adds the four data-blob commands (LC_FUNCTION_STARTS/LC_DATA_IN_CODE/LC_CODE_SIGNATURE/LC_SEGMENT_SPLIT_INFO) as the DataBlob (data_offset, data_size, content-slice) records with the present flag and the accessors |

Fixture-driven throughout (`tests/Loader_Macho_Test.cpp`, 11 tests): the
minimal in-memory MH_EXECUTE blobs with hand-encoded command records, the
fat-container fixtures riding the CAFEBABE wrapper with a decoy ARM64
slice + the thin x8664 blob, and the data-blob fixtures patching the
extra-command body to the section content region.

### Phase 7 findings (upstream-parity notes)
- **the section_64 stride is 0x50 with a reserved3 tail** — the Apple
  struct memory (80 bytes = 16+16+8+8+7×4) is short one u32; the upstream's
  `LoadSection64` reads 0x50 and parses address/size/offset/alignment/
  relocations_offset/number_of_relocations/flags/reserved1/reserved2/
  reserved3 after the name/segname prefix.
- **the fixture blob's extra commands ride between the segment command and
  the content** — the walk reads commands sequentially from the header end,
  so a command appended after the segment's file content is never reached;
  and the extra command must NOT inflate the segment's declared cmd_size
  (the walk then skips over it as part of the segment). The ncmds/sizeofcmds
  fixup counts each command separately.
- **the LC_UNIXTHREAD state layout**: flavor + count then count×8 state
  bytes; the x86_64 entry is the rip at the state index 16 (after the 16
  GPRs rax..r15, before rflags/cs/fs/gs).

## Phase 8 - the os/macos dialect skeleton (the QlOsMacos surface)

The macos dialect over the posix base (the freebsd precedent: a thin
dialect riding the completed Phase 5 POSIX surface), on top of the Phase 7
container parser. The upstream's `QlOsMacos(QlOsPosix)` ctor shape ported:
the fcall re-created as the `macosx64` convention (the first 6 args in
regs — the same regs as the posix amd64; the distinct class keeps the
upstream's explicit intent) and the X8664 load() (the GDT/segment
setup_cs_ds_ss_es(0, 4<<30) shape + the SYSCALL INSN hook). The MACOS
x8664 syscall table (349 entries) rides the map_syscall override with the
LIBSYSTEM fixup (0x2000000 <= n < 0x3000000 maps to n - 0x2000000).

| the piece | the port file | the state | the notes |
|---|---|---|---|
| the dialect skeleton (the ctor + the load() + the fcall) | `qiling/os/macos/macos.hpp/.cpp` | ✅ 8670000 | the GDT shape mirrors the freebsd load() (the upstream repeats it per dialect) |
| the MACOS x8664 syscall table | `qiling/os/macos/map_syscall.hpp` | ✅ 8670000 | generated verbatim (349 entries) + the 0x2000000 fixup in the override |
| the factory wiring (select_os/select_loader) | `qiling/utils.cpp` | ✅ 8670000 | the macos shellcode path shares the QlLoaderELF (the documented deviation: the real QlLoaderMachO lands as its own slice) |
| the profile | `qiling/profiles/macos.ql` | ✅ 8670000 | the upstream verbatim + the CODE load_address port deviation (the freebsd/qnx precedent) |
| the syscall handlers — the mach self-trap family + the stubs | `qiling/os/macos/syscall.cpp` | ✅ 67f4ebc | mach_reply_port (2187), thread_self_trap (0x307), task_self_trap (9876), host_self_trap (0x303), csops (the CS_ENFORCEMENT\|CS_GET_TASK_ALLOW flag), getentropy (the KERN_SUCCESS stub); the mach_port/task/thread surfaces ride `mach_port.hpp` (the ctor-seeded deviation until the Mach-O loader lands) |
| the file/syscall-info family | `qiling/os/macos/syscall.cpp` + `kernel_func.hpp/.cpp` | ✅ 3c9212a | access_macos (the raw ENOENT over the fs isexists), getattrlist (the 24-byte attrlist unpack + the get_common_attr walk — the name-offset cell, the dev/type/ino cells), getrlimit (the verbatim double-write clobber + the 0x1000 mask oddity), sigprocmask (the log-only no-op, no return), fcntl64_macos (the fixed cmd table + the 0xefffffff ADDFILESIGS blob), pread (seek/read through the fd table + the CF clear); the FileSystem helper rides `kernel_func.*` (the vm_to_real_path + the VM-path type-check quirk verbatim) |
| the mach vm/port trap family | `qiling/os/macos/syscall.cpp` | ✅ 7e5c882 | kernelrpc_mach_vm_allocate_trap (the min_offset bump allocator + the *addr write-back), vm_deallocate (the KERN_SUCCESS stub), vm_map (the vmmap cursor walk from the profile's vmmap_trap_address + the mask alignment verbatim), port_deallocate/mod_refs/construct (the pass stubs); the fixtures ride the 0x1000000-range numbers |
| the bsdthread/shims group | `qiling/os/macos/syscall.cpp` | ✅ 94e47fb | bsdthread_register (the CF clear + the fixed 0x400000df pthread magic), thread_selfid (the seeded thread id 123), thread_fast_set_cthread_self64 (the mdep shim: the tsd base into IA32_GS_BASE_MSR 0xC0000101) |
| the misc tail | `qiling/os/macos/syscall.cpp` | ✅ 47eb5a2 | sysctl/poll (the KERN_SUCCESS stubs), shared_region_check_np (the raw EINVAL "not ready"), csrctl (returns 1), proc_info (the PIDINFO+REGIONPATHINFO branch writes "/usr/lib/dyld" at buff+248, no return otherwise), terminate_with_payload (the emu stop + KERN_SUCCESS), abort_with_payload (no stop), the nocancel pair (write_nocancel carries the upstream's verbatim `return 0` quirk; open_nocancel delegates to the posix open with the fd-slot semantics), shared_region_check_np/proc_info ride the PROC_* consts |
| the kernel_api fncc surface (kernel_api.py, 111 handlers) | `qiling/os/macos/kernel_api.hpp/.cpp` + `kernel_api_registry.inc` | ✅ d397443 | the registry/builder mirror the posix kernel_api slice (the fluent `KernelApi(name, params, passthru) = handler` shape); the verbatim surface: the passthru stubs (the empty `return` bodies — the guest's own stub code runs), the real-bodied handlers (suulong/fuulong, read_random/erandom with the 0xdeadbeaf stamp, clock_get_calendar_microtime with the verbatim ms-arithmetic oddity, proc_selfpid 0x1337 / selfppid 0x13371337, msleep/kernel_thread_start the 0 stubs, vfs_context_proc the identity); the dispatch rides `QlOsMacos::hook_kernel_api` (inert until the QlLoaderMachO import symbols land) |
| the QlLoaderMachO loader slice | `qiling/loader/macho.hpp/.cpp` + `select_loader` | ✅ e9ee146 | the container load (the segment mapping with the __PAGEZERO page + the LC_UNIXTHREAD/LC_MAIN entries), the shellcode branch (the ELF-shape map), the LC_SYMTAB symbol/string tables (the nlist_64 walk) feeding import_symbols; the deviation note: the import symbols ride the file's own LC_SYMTAB — the upstream's loadDriver walks the kernel.development symbol tables + the LC_DYSYMTAB relocations + the trampoline code (that path lands with the kernel-loader slice) |
| the kernel_api dispatch end-to-end | `qiling/os/macos/macos.cpp` `hook_kernel_api` | ✅ e9ee146 | the stub-address dispatch through the import symbols + the user overrides + the registry + the os.call with the passthru; the fixture: the guest calls the _proc_selfpid stub, the hook fires, 0x1337 lands in rax, the pc past the call, exit(42) |
| the events/policy slice | `qiling/os/macos/ev.hpp/.cpp` | ✅ 4156f1f | the QlEvManager port: the add_process proc_t image (the 1144-byte upstream layout: p_pid/p_ppid/p_pgrpid/p_flag=4/p_ucred/p_comm(17)/p_name(33) + the le_next/le_prev tail chain), set_allproc (the head cell), proc_find, the init_ev_ctx lazy cells (the label l_flags=1, the cred 501/501/501/15/groups(20,12,61,79,80,81)/20/20/501/2 with cr_label at 120, the vnode with v_name at 344), the register/emit/emit_by_type job surface, the QlOsPolicy mpo_file_check_mmap (the fileglob_t image + the emit) + the bank |
| the re-pointed kernel_api handlers | `qiling/os/macos/kernel_api.cpp` | ✅ 4156f1f | proc_name (the p_comm image at buf, the size param unread — the upstream FIXME verbatim), proc_find (the image address, 0 on the miss), kauth_getuid/getgid (the lazy ev-ctx cred cells 501/20), kauth_cred_setuidgid (the fresh ucred carrying uid/uid/uid + ng 1 + gid/gid, the address returned) |
| the mach_msg + the message-path machinery (MachMsg, the port-manager deal_with_msg) | — | defer | needs the MachMsg struct port + the message dispatch tree; deferred with a note (the kext/message surface rides the kernel-loader slices) |
| the loadDriver path (the kernel.development parse + the LC_DYSYMTAB relocation walk + the static-symbol trampolines) | ✅ c127763 + the reloc passes | the LC_DYSYMTAB parse + the load_driver symbol walk (the kernel local/extern tables feed import_symbols_, the registry resolves the kext imports) landed at c127763; the sub-slice-2 relocation machinery (the X86_64_RELOC_BRANCH/UNSIGNED passes + the STATIC-page construct-stub trampolines + the local slide) is implemented and trace-verified — the disp32 patches to the stub, the abs64 carries the kernel n_value, the local cell slides — but its fixture stays DISABLED_ on the tail blocker below |
| **OPEN blocker — the driver-path INSN hook** | `qiling/os/posix/posix.cpp` install_syscall_hooks | ⚠ DISABLED_ | on the kext driver path, after the STATIC-page construct-stub bridge (the `sub rsp,8` + the stack-constructed `ret`), the `UC_HOOK_INSN` (UC_X86_INS_SYSCALL) hook never fires: the syscall at 0x3000022f executes with the UC_HOOK_CODE hooks tracing every instruction, rcx=0/r11=0 (ruling out a native unicorn syscall execution), and the run dies with UC_ERR_WRITE_UNMAPPED at the syscall pc; the same INSN hook fires on the shellcode path and on the driver path when the guest calls via a direct `call rax` (the sub-slice-1 fixture, green) — the divergence is the stub-mediated `call rel32`+`ret` control flow; undiagnosed uc-level hook/TB interaction, resume with the trace protocol (the code-hook pc tracer + the [sys] load_syscall entry print) |
| the StubBridge raw-uc probe matrix (the blocker's bisect round 1) | `tests/Tb_Semantics_Test.cpp` | ✅ | four probes, all green: DirectCall (the call rel32 straight to the body), ConstructStub (the exact failing shape — the upstream-verbatim construct stub on its own mapped page, the stack writes included), ConstructStubWithLateCodeHook (the construct stub + a UC_HOOK_CODE registered after the INSN hook), JmpStub (the movabs+jmp stub, no stack writes) — **the construct-stub path fires the INSN hook fine at the raw level**, so the stock unicorn is NOT the limiter for this shape; two further port-side probes pin the negative space: a raw INSN hook registered from the test AFTER every loader map also stays silent (late_fired=0 — the registration timing is not the trigger), and the [run] emu_start args are benign and identical to the passing sub-slice-1 (entry=0x30000200, exit=0xffffffffffffffff, timeout=0, count=0) — the interference lives inside the port's machinery between the raw hook registration and the emu (the remaining suspects: the facade's shared UC_HOOK_CODE dispatcher/HookCtx layer, the GDT/segment setup, or an early-emu pass in the load path); resume NEXT with the documented trace protocol (the code-hook pc tracer + the [sys] load_syscall entry print), one hypothesis per run |
| **PARKED** — kext INSN-hook blocker | — | ⏸ | probed to exhaustion (the b1-b13 bisect rounds + the StubBridge raw matrix); parked until new evidence — do not re-enter without a new hypothesis from fresh data |
| the COMBINE _IO_STAT fixture (RESOLVED) | `tests/Qnx_Test.cpp` | ✅ | the park was a fixture defect, not a handler one: the stashed blob moved rmsg to 0x2400 but the reply-iov array was still written at the old 0x2150, so the handler read a zeroed iov array and faulted writing to base 0 (the uc_err 7); the fix moves the array to the blob's rmsg and the 72-byte stat image to 0x21E0 clear of the 0x2180 header scratch (the old 0x2190 image overlapped the header's tail); both the happy-path (the QNXARMStat image: the size 10, the mode bits, the zero hi cells) and the missing-path (-1) fixtures green |
| shared_region_map_and_slide_np + sysctlbyname | — | defer | absent from the upstream's x8664 table (ARM64-only entries) — the x8664 port surface mirrors the table verbatim |
| the kernel_api fncc surface (kernel_api.py, 1404) | `qiling/os/macos/macos.cpp` | ✅ d397443 | the row was stale (it predated the registry slice): the fncc.py `macos_kernel_api` wrapper (the os.call with the passthru + the ENTER/EXIT user hooks) and the hook.py dispatch (the user CALL override runs raw with (ql, address, api_name), the find-miss warns and honors debug_stop with QlErrorSyscallNotFound) both live in QlOsMacos::hook_kernel_api — the surface is complete; kernel_func.py's map_commpage landed with it (the comm-page map + the 0x68 time-lock stamp, the FIXME'd-out vm_shared_region_enter stays out verbatim) |
| the mach_trap/kernel-func trap dispatch (the mach_msg path) | — | defer | the MachMsg struct + the message dispatch tree (the mach-port surface); rides the mach_port/task deferred rows |
| the events/policy managers (events/, mach_port, task) | — | defer | the kext/driver machinery + the Mach-O kernel-loader port first |
| the kext/driver path (load_kext, run's savedrip) | — | defer | blocked on the QlLoaderMachO port |

Fixture-driven (`tests/Macos_Test.cpp`): the exit smoke through the plain
number 1 and through the fixup'd 0x2000000+1 (both terminate with the code
42), plus the positive factory tests.

### Phase 8 findings (upstream-parity notes)

- **the generated-table hex-key gotcha**: the upstream's x8664 table carries
  the mach-trap entries under hex keys (0x100001a mach_reply_port through
  0x100001d host_self_trap); a decimal-only `\d+` extraction silently drops
  them (349 vs the true 357 entries) and the traps dispatch to the
  not-implemented fall-through with rax=0. Extract with `(?:0x)?[0-9a-f]+`.
- **the MachPortManager aggregate-init trap**: the upstream's
  `MachPortManager(ql, my_port)` — the my_port is a separate member, NOT the
  host_port (the fixed 0x303); a positional aggregate init from the seed
  port assigns it to host_port and the host_self_trap returns the reply
  port's name. Seed my_port by assignment.
- **the csops arg order**: (pid, ops, useraddr, usersize) rides rdi/rsi/
  rdx/rcx — the useraddr is the THIRD arg (rdx); a rdi=useraddr blob faults
  the handler's write at 0 (uc_err 7).
- **the ModRM disp8-vs-disp32 store trap**: `48 89 83` is `[rbx+disp32]`
  (mod=10) — the disp32 eats the following opcode byte as its high
  displacement and the store faults at a wild address; the `[rbx+disp8]`
  form is ModRM `0x43` (mod=01). The register dump (rbx correct at the
  fault) exonerated the base and pinned the encoding.
- **the getrlimit which-mask oddity is real**: the upstream masks
  `which & _RLIMIT_POSIX_FLAG` (0x1000) — a caller passing a plain which
  (0..8) stays in range, but the fixture's 0x1000 pre-masked which masks to
  itself (4096 ≥ 9) and rides the EINVAL path; the success path needs a
  plain which.
- **the shared-registry overwrite semantics**: the port collapses the
  upstream's per-os registries into one map where re-registration overwrites
  — safe because every dialect ctor re-registers its own names at
  construction, so the last-constructed os's handlers match the running os
  (the sigprocmask name is shared by the freebsd and macos dialects).
- **the getrlimit success path carries NO return** (the upstream body ends
  with `pass`) — rax stays untouched; the same nullopt convention as the
  macos sigprocmask.
- **the profile reads cannot run in the dialect ctor**: the Qiling ctor
  loads the profile AFTER the os construction — a ctor-side
  `profile().get_int` dereferences the null config and SEHs (0xc0000005);
  the vmmap_cursor seed reads in run() instead (the qnx prelude reads its
  keys on the same pattern).
- **the mach-trap 6th-arg ABI**: the x8664 syscall ABI rides (rdi, rsi,
  rdx, r10, r8, r9) — the 4th arg is r10 (the kernel ABI's rcx clobber
  work-around), so the vm_map's mask rides r10d and the flags/protect ride
  r8d/r9d; the 6-arg proc_info keeps (callnum, pid, flavor, arg, buff,
  buffer_size) in that exact slot order — the flavor is the 3rd arg (rdx),
  NOT r10.
- **the upstream's own table gaps**: sysctlbyname (274) and
  shared_region_map_and_slide_np (438) exist only in the ARM64 table — the
  x8664 surface mirrors the table verbatim and those handlers stay
  unregistered for x8664 (the fixtures document the absence).
- **the fncc passthru semantics**: the upstream's empty `return` bodies with
  passthru=True mean the guest's own stub code at the import address
  executes (the hook only resolves the params for the log); the non-passthru
  stubs (the IOKit/lck family) get the full os.call shape with the pc set to
  the retaddr. The port's stub bodies return nullopt — the semantics ride
  the call() passthru flag, not the body.
- **the K_BOOL alias gap**: the posix kernel_api header defines K_UINT/
  SIZE_T/POINTER/STRING but not K_BOOL (the upstream macos decorators use
  BOOL) — the macos header pins K_BOOL = PARAM_INT32 locally.
- **the kernel_api dispatch wiring gotchas, in order**: (1) the posix
  `hook_kernel_api` was non-virtual — the macos override shadowed it and the
  inherited enable_kernel_api_hooks lambda dispatched the POSIX body (its
  QlLoaderELF gate no-oped); the virtual makes the override participate.
  (2) the macho C symbols carry the leading underscore (`_proc_selfpid`) —
  the port's registry keys are unprefixed, so the dispatch strips one
  underscore (the upstream's getattr rides the raw symbol name).
  (3) the fixture's mov-imm64 for the stub address encoded 0x100000300 (the
  byte-3/byte-4 slip) — the fetch faulted at the unmapped address BEFORE the
  hook could fire; the call target must land inside the mapped __TEXT.
  (4) the rip-relative store inside the image resolves against the image
  base — an absolute 0x2100 target is NOT reachable from the 0x1000000
  region; the fixture stores into an in-image cell.
- **the hook_code full-range registration**: the kernel-api hook now passes
  explicit begin=0/end=MAX bounds (the default begin=1/end=0 registration
  did not fire on the arm/qnx path — the pinned gotcha).
- **the ev/policy image-layout pin**: the port's ucred_t cr_ref cell uses
  the 4-byte shape (the upstream's `ctypes.c_ulong` splits 4/8 by host
  platform — _WIN32 4, linux/macOS 8; the port pins the 4-byte shape
  consistently for the writer and the readers at cr_posix = 20); the
  policy's emit_by_type only queues jobs for REGISTERED callbacks — a
  policy emit without a registered listener silently no-ops (the fixture
  pins the listener-registration path first).

## Phase 9 - the posix mman family (the mmap/munmap/mprotect/madvise slice)

The `mman.py` port lands the memory-management syscall family on the
existing memory-manager surface — the slice that unblocks the real-ELF
flow (every loader and allocator rides mmap).

| file | upstream | state | notes |
|---|---|---|---|
| `qiling/os/posix/mman.hpp/.cpp` | `syscall/mman.py` | Ported | the `select_mmap_flags` dispatch (the linux/mips/freebsd/macos/qnx tables verbatim — the mips arm keys on the arch inside the LINUX entry, the freebsd MAP_FIXED_NOREPLACE=MAP_EXCL alias verbatim); the `syscall_mmap_impl` boundary walk verbatim (the unaligned-fixed-base -EINVAL off-QNX, the find_free_space hint at max(addr, the ELF loader's mmap_address), the MAP_FIXED_NOREPLACE -EEXIST / the MAP_FIXED unmap_between, the ANON zero-fill skipping on MAP_UNINITIALIZED, the file-backed fd walk with the `[mmap] <basename>` label); the QlFile gained the public `is_map_shared`/`mapped_offset` accessors for the flush-on-unmap flow; `munmap` (the enclosing-[mmap] range walk via get_mapinfo, the basename fd match, the shared flush writing the FULL read(addr, length) — the verbatim NUL-padding growth, the clip-to-ubound unmap), `mprotect` (the verbatim "Error: change protection at" rethrow), `madvise` (the MADV_DONTNEED zero-fill) |
| the registrations | `syscall.cpp` | ✅ | mmap (9) / mmap2 (192) / old_mmap (90, the ia32 struct form) / munmap (11) / mprotect (10) / madvise (28) |
| the fixtures | `tests/Posix_Test.cpp` | ✅ 3 green | the fixed-anon mmap + the madvise DONTNEED zero-fill; the file-backed mapping reading the payload through the fd; the shared munmap flush growing the host file to the munmap length (the verbatim pad) |

Findings: the blob-arg wiring gotcha re-confirmed (the mmap fd rides r8 —
the first pass put it in rdi/addr and the unaligned-base EINVAL masked the
dispatch), and the flush-on-unmap verbatim pads the host file with NULs to
the munmap length (the upstream reads the full length and writes it back).

## Phase 10 - the directory-read surface (the unistd access/readlink/chdir/
getcwd/getdents slice)

| piece | upstream | state | notes |
|---|---|---|---|
| access/getcwd/chdir | `unistd.py` | ✅ | access (the safe-host-path PermissionError propagation + the exists check → 0/-ENOENT); getcwd (the cwd+NUL write, the return = len+1 — the bufsize argument ignored verbatim); chdir (the isdir gate → the QlOsPath::set_cwd ride / -ENOENT) — the QlOs gained `path_mut()` and the QlOsPath the `set_cwd` setter |
| readlink/readlinkat | `unistd.py __do_readlink` | ✅ | the procfs pseudo files (/proc/self/exe → host_to_virtual_path — raising for a program outside rootfs verbatim; /proc/self/cwd; /proc/self/root) and the FIXME branch verbatim: an existing real path reads as the EMPTY target (0, nothing written); readlinkat rides the `virtual_abspath_at` shape (the as-signed dirfd, the AT_FDCWD → cwd, the real-dirfd → host_to_virtual_path, the -ENOTDIR check) via the new `QlOsPath::virtual_abspath_from(base, vpath)` |
| getdents/getdents64 | `unistd.py __getdents_common` | ✅ | the tell()==0 gate (the _WIN32 dir FILE* cannot seek — a `dir_scan_done` flag rides alongside the verbatim seek-to-END); the '.'/'..' chain first then the scandir results; the d_ino-alignment reclen math verbatim; the getdents64 layout (the d_type before d_name) vs the legacy linux_dirent (the d_type in the record's last byte, the pad between d_name and d_type); the second call answers 0 |
| the fixtures | `tests/Posix_Test.cpp` | ✅ 3 green | the getdents64 walk ('.', '..', the two files, the second call 0 — the dir fd pre-seeded as a synthetic QlFile since the _WIN32 CRT cannot open a directory); the chdir/getcwd ride (+ the -ENOENT miss); the readlink pseudo-file + the existing-path empty target |

Findings: the incremental field-walk into guest memory kept tripping the
fixture until the record composition moved to a local buffer with one
write (the per-field pointer table dangled through the vector reallocs);
the getdents64 syscall id gotcha re-pinned (217 = 0xD9 — the first blob
encoded 0xDD and the stale rax masked the miss); the \b escape in a python
heredoc mangles exactly as pinned before — the edit tool with the on-disk
bytes is the only reliable repair.

## Phase 11 - the signal family (the sigaction struct + rt_sigaction/
rt_sigprocmask/signal)

| piece | upstream | state | notes |
|---|---|---|---|
| the sigaction struct | `signal.py __make_sigaction` | ✅ | the `GuestSigaction` (the handler/mask/flags/restorer u64 slots); the field ORDER per arch verbatim (the x8664 puts the mask last, the x86/ARM families put the mask second — theFIXME'd-out union quirk: the handler slot carries both spellings); the load/save ride the native width (the 32-bit hosts shrink to 4-byte cells) |
| rt_sigaction | `signal.py` | ✅ | the EINVAL checks verbatim (the signum out of NSIG=32 or the SIGKILL/SIGSTOP pair → -1); the oldact write rides the PREVIOUS state (the write-before-load order — the first call answers zeros); the act load stores into the os.sig table |
| rt_sigprocmask | `signal.py __sigprocmask` | ✅ | the BLOCK/UNBLOCK/SETMASK walk over the os.blocked_signals; the verbatim quirk preserved: the old mask writes to NEWSET (the upstream line rides write_ptr(newset, ...) — NOT oldset — so the guest's requested set is read back AFTER the old-mask overwrite); the KILL/STOP bits drop silently after the apply |
| signal | `signal.py` | ✅ | the verbatim 0 stub (no registration) |
| the fixtures | `tests/Posix_Test.cpp` | ✅ 2 green | the x8664 sigaction round trip (the install + the read-back + the two EINVAL branches) and the sigprocmask walk (the blocked-after quirk: the BLOCK pass's guest set never applies — the old-mask overwrite rides first; the SETMASK pass sets bit 2 with the KILL/STOP drop) |

The frame machinery (the actual signal delivery + the sigreturn) is its
own later slice; the delivery hooks hang off the same sig_actions_ table.

## Phase 12 - the socket family (sub-slice 1: the socket/shutdown core)

| piece | upstream | state | notes |
|---|---|---|---|
| `qiling/os/posix/socket.hpp/.cpp` | `filestruct.py ql_socket` + `syscall/socket.py` | ✅ core | the `QlSocket` over the host sockets API (winsock on _WIN32 with the one-time WSAStartup — the winsock2.h-before-windows.h ordering gotcha pinned; the POSIX sockets elsewhere); `open` (the host OSError shapes map onto the QlError* translations), `read`/`write` (the recv/send without flags), `close`, `shutdown` (the host failure → false → the caller's -1), `family`/`socktype` |
| socket / shutdown | `syscall/socket.py` | ✅ | `socket(domain, type, proto)` rides the next-free-fd walk + the fd-table set (the EMFILE when full); the open failure collapses onto -1 (the upstream idx=-1 branch); `shutdown(how)` via the get-opened-socket walk (-ENOTSOCK for the non-socket fd) |
| the fixture | `tests/Posix_Test.cpp` | ✅ | the socket(AF_INET, SOCK_STREAM, 0) → fd 3 + the fd-table ride (the family/type recorded) + the unconnected-socket shutdown → -1 (the upstream would raise the uncaught OSError on the ENOTCONN host failure — the deviation pinned in the fixture) |

The remaining socket-family sub-slices: socketpair + connect/bind/listen/
accept; send/recv/sendto/recvfrom; getsockopt/setsockopt. The sockaddr
parse (the make_sockaddr families) lands with the connect/bind slice.

### Phase 12 sub-slice 2 — connect/bind/listen/accept

| piece | upstream | state | notes |
|---|---|---|---|
| the sockaddr parse | `socket.py make_sockaddr` walk | ✅ | the `SockaddrView` (the LE u16 family word; the sun_path partitioned at the first NUL — the abstract namespace rides the raw bytes; the AF_INET (port BE, the dotted-quad off the LE s_addr)) |
| connect/bind/listen/accept | `syscall/socket.py` | ✅ | the connect (the family-mismatch -1, the AF_UNIX rootfs transform via the verbatim `ql_unix_socket_path`, the AF_INET getaddrinfo walk, the EAFNOSUPPORT for the other families); the bind (the bindtolocalhost default + the unprivileged 8000 port shift verbatim, the -EACCES shape for the errno granularity); the listen; the accept (the next-free fd, the AF_INET peer (family, port BE, s_addr) write-back with the addrlen update) — the errors collapse onto -1/-13 pending the errno-granularity slice |
| the fixtures | `tests/Posix_Test.cpp` | ✅ 2 more green | the AF_UNIX bind/listen over the rootfs path (the host bind created the socket file; the stale temp-rootfs socket blocks the rebind — the fixture clears it); the shutdown ride from sub-slice 1 |

Findings: the winsock `in_addr` **s_addr macro** collides with a local
variable named s_addr (C3927 via the textual `S_un.S_addr` expansion) —
rename locals; the Win32 unix-socket file is a reparse point the plain
`std::filesystem::exists` rejects (the ec-form still trips) — the bind's 0
return is the fixture's evidence.

### Phase 12 sub-slice 3 — socketpair + the send/recv family

| piece | upstream | state | notes |
|---|---|---|---|
| socketpair | `syscall/socket.py` + `filestruct.py ql_socket.socketpair` | ✅ | the two next-free fds into the sv pair (the i32 writes at sv+0/sv+4 verbatim); the _WIN32 host lacks socketpair — the loopback accept walk (the listener on 127.0.0.1:0 + the connect off the getsockname addr) backs it; the AF_UNIX host open fails on _WIN32 so the fixture rides AF_INET |
| recv/send | `syscall/socket.py` | ✅ | the recv (the empty read writes nothing, the count rides the return) and the send (the verbatim IOError → 0 branch) |
| sendto/recvfrom | `syscall/socket.py` | ✅ core | the STREAM sockets and the NULL addr ride the send/recv bodies verbatim; the datagram dest/src paths throw pending their sub-slice (the upstream's SOCK_STREAM/SOCK_SEQPACKET checks verbatim) |

Findings (re-pinned): the r10-vs-r9 4th-arg gotcha fired again, this time
as the r10/r8 **pair** (the 4th/5th slots must ride in order — the reversed
pair produced the failures that looked like handler bugs); and the x8664
table has NO bare send/recv — the sendto/recvfrom names (44/45) carry the
NULL-addr delegation (the upstream's recvfrom-with-NULL-addr comment
verbatim).

### Phase 12 sub-slice 4 — getsockopt/setsockopt (the family core close-out)

| piece | upstream | state | notes |
|---|---|---|---|
| getsockopt/setsockopt | `syscall/socket.py` | ✅ | the optlen in-out cell (the min-1024 clamp + the negative -EINVAL verbatim); the NULL optval rides the empty-value host call; the **level/option names ride the two-stage mapping** (the const_mapping.py shape: the guest value → the linux-table name → the host constant) — the winsock host requires it (SOL_SOCKET 1→0xffff, SO_TYPE 3→0x1008, SO_KEEPALIVE 9→8); the IPPROTO_IP/TCP option tables defer with their slices (the SOL_SOCKET table is complete) |
| the fixture | `tests/Posix_Test.cpp` | ✅ | the SO_KEEPALIVE set + the SO_TYPE get round trip over SOL_SOCKET (the mapping verified live) |

The socket family core is now complete: socket/shutdown, connect/bind/
listen/accept, socketpair, send/recv/sendto/recvfrom (the STREAM + the
NULL-addr bodies), getsockopt/setsockopt. The remaining surface: the
datagram sendto/recvfrom dest/src paths, socketcall (the x86 multiplexer),
the IPPROTO_IP/TCP option tables — each its own slice.

### Phase 12 sub-slice 5 — getsockname/getpeername

| piece | upstream | state | notes |
|---|---|---|---|
| getsockname/getpeername | `syscall/socket.py` | ✅ | the shared local/peer host-name walk (the AF_UNIX path or the AF_INET (host, port)); the write-back over the **write_sockaddr helper** (the upstream's getsockname/accept addr-body shapes: the AF_UNIX host→virtual transform + the addrlen truncation (the `[:addrlen - 2 - 1]` verbatim), the AF_INET family/BE-port/dotted-quad triple, the save gated on `objsize <= addrlen` while the addrlen cell ALWAYS updates when set) |
| the fixture | `tests/Posix_Test.cpp` | ✅ | getsockname after the INADDR_ANY bind (the family word 2, the BE ephemeral port nonzero, the addrlen cell 16) + the getpeername -ENOTCONN ride |

Findings: the upstream has **no bare accept4 handler** (the SYS_ACCEPT4=18
socketcall slot raises NotImplementedError in net.py — the bare accept is
the only accept handler upstream); the upstream getpeername on the
unconnected socket raises uncaught — the port answers -1 (the same
documented ENOTCONN deviation shape as the shutdown slice); the port's
accept peer write-back predates the helper and still writes the fixed
110-byte unix sockaddr (the verbatim dynamic-size walk lands when the
accept body rides the shared write_sockaddr helper — a small follow-up).

### Phase 12 sub-slice 6 — the datagram sendto/recvfrom dest/src paths

| piece | upstream | state | notes |
|---|---|---|---|
| sendto datagram | `syscall/socket.py` | ✅ | the dest parse rides the guest sockaddr (the AF_UNIX ql_unix_socket_path transform, the AF_INET (host, port)); the unsupported family falls through the verbatim "if dest is not None" gate returning 0; the (ConnectionError, FileNotFoundError) except branch rides 0 (verbatim) |
| recvfrom datagram | `syscall/socket.py` | ✅ | the src address write-back over the QlSocket::recvfrom out params; the FIXME verbatim (the addrlen is NOT read — the whole obj writes at addr, no addrlen-cell update); the abstract-namespace path stays unfilled (the comment verbatim); the unsupported family rides objlen=0 (no write-back) |
| the QlSocket sendto/recvfrom | `filestruct.py ql_socket.sendto/recvfrom` | ✅ | the host sendto/recvfrom with the AF_UNIX-path / AF_INET-addr split, the recvfrom n<=0 empty-read shape |
| the fixture | `tests/Posix_Test.cpp` | ✅ | the UDP self-conversation: B binds 127.0.0.1:0 + getsockname fills the dest sa, A sendtos "PING" to it, B recvfroms it and the src (family, BE port, BE addr) writes back |

Findings: the REX.B encoding trap fired AGAIN as 49 C7 C0 — a W+/-B
`mov r8, imm32` mistaken for r9 (the r9 form is 49 C7 C1) — the overwritten
src arg made the write-back land at the len cell while the fixture probed
the src, a silent misdirect that still passed the PING assertion; and the
sa layout gotcha: the dotted-quad addr rides at sa+4 (right after the
family+port words) — preloading the port+addr as 6 bytes at +4 shifts the
addr to +6 and the parse reads 0.0.127.0.

### Phase 12 sub-slice 7 — the IPPROTO_IP/TCP option tables

| piece | upstream | state | notes |
|---|---|---|---|
| host_socket_option tables | `const_mapping.py socket_ip/tcp_option_mapping` + `const.py linux_socket_ip_options/linux_socket_tcp_options` | ✅ | the level dispatch in the two-stage walk: the IPPROTO_IP (0x0) and IPPROTO_TCP (0x6) tables land alongside the SOL_SOCKET walk; the IP table carries TOS/TTL/HDRINCL/OPTIONS/PKTINFO + the multicast set, the TCP table NODELAY/MAXSEG/KEEPIDLE/KEEPINTVL/KEEPCNT; the host constants resolve via the host macros (the winsock IP_TTL=4 vs the linux 2, the winsock TCP_MAXSEG=4 vs the linux 2); the linux-only names (IP_MTU_DISCOVER, TCP_CORK, ...) throw the NotImplementedError shape (the caller's -22 ride) |
| the fixture | `tests/Posix_Test.cpp` | ✅ | IP_TTL (set 64 + the get-back 64) at the IPPROTO_IP level and TCP_NODELAY at the IPPROTO_TCP level |

The socket-option mapping surface is now complete for the levels the linux
apps touch (the SOL_SOCKET + the IP + the TCP walks).

### Phase 12 sub-slice 8 — socketcall (the x86 multiplexer, the family close-out)

| piece | upstream | state | notes |
|---|---|---|---|
| socketcall | `syscall/net.py ql_syscall_socketcall` | ✅ | the call→handler table (the SOCKETCALL values 1–15 with the per-call arg counts mirroring the upstream's inspect.signature walk: socket/bind/connect/get* 3, listen/shutdown 2, send/recv/socketpair 4, sendto/recvfrom 6, the sockopt pair 5); the args array reads at the pointer-size stride; the unhandled calls (the recvmsg/sendmmsg/accept4 slots — the recvmsg defers with its slice, the accept4 has no upstream bare handler) throw the verbatim 'socketcall: call {call} not implemented' |
| the fixture | `tests/Posix_Test.cpp` | ✅ | the x86-32 blob riding int 0x80 (the QlSyscallABIIntel32 register ABI: eax=102, ebx=SYS_SOCKET, ecx=the args pointer) through the socket body, asserting the fd 3 |

The socket family surface in the port now covers: socket/shutdown,
connect/bind/listen/accept, socketpair, send/recv/sendto/recvfrom (the
STREAM + the NULL-addr + the datagram walks), getsockname/getpeername,
getsockopt/setsockopt (the SOL_SOCKET + IP + TCP tables), socketcall. The
remaining deferrals: recvmsg/sendmsg + the msg family (its own slice),
accept4's verbatim NotImplemented (the upstream has no bare handler),
sendmmsg/recvmmsg.

### Phase 12 sub-slice 9 — the msg family (recvmsg + the msghdr/iov/cmsg walk)

| piece | upstream | state | notes |
|---|---|---|---|
| recvmsg | `syscall/socket.py ql_syscall_recvmsg` | ✅ | the msghdr load (the upstream's arch-independent layout: name u64@0, namelen i32@8, iov@16, iovlen i32@24, control@32, controllen i32@40, flags i32@48); the **bufsize rides msg_namelen verbatim** (the upstream quirk — the recvmsg(bufsize=msg_namelen, ancbufsize=msg_controllen, flags) call); the iov scatter over the min-walk (the iovec rides the arch pointer size); the cmsg write-back over the 12-byte make_cmsghdr (the cmsg_len carries ONLY the data length — the verbatim quirk) + the msg_flags save-back; the ConnectionError → -1; the **TODO: handle the addr verbatim** (the name discarded) |
| QlSocket::recvmsg | `filestruct.py ql_socket.recvmsg` | ✅ | the POSIX host rides recvmsg(2) over the CMSG_FIRSTHDR/NXTHDR walk; the winsock rides **WSARecvMsg** (the SIO_GET_EXTENSION_FUNCTION_POINTER + WSAID_WSARECVMSG dance) — the host socket creation switched to WSASocketW with **WSA_FLAG_OVERLAPPED** (the msdn WSARecvMsg requirement, pinned: the plain ::socket-socket answers WSAEOPNOTSUPP) |
| sendmsg | `socket.py` | ✅ absent | the upstream defines NO sendmsg handler — the name rides the dispatcher's not-implemented fall-through verbatim (the warn + the continue) |
| the fixture | `tests/Posix_Test.cpp` | ✅ | the UDP self-conversation with the IP_PKTINFO option: the msghdr (the one-entry iov + the 128-byte control), the PING scatter, the cmsg (the level IPPROTO_IP, the type the host IP_PKTINFO, the payload the host IN_PKTINFO size) and the msg_flags cell |

Findings: the winsock IP_PKTINFO cmsg payload is 8 bytes (the 2-field
IN_PKTINFO — no ipi_spec_dst) against the linux 12; the WSARecvMsg's
Control.len/namelen are in-out (the used lengths write back); the cmsg_len
quirk means the write-back length is the payload only, so the guest's
CMSG_NXTHDR-style walk over the port's output needs the CMSG_ALIGN walk —
the verbatim upstream shape (a known upstream divergence, pinned here
rather than fixed).

The remaining socket deferrals: sendmmsg/recvmmsg (the msg-family
multiplexers over the mmsghdr array — each its own slice).

### Phase 12 sub-slice 10 — the socketcall recvmsg ride + the recvmmsg/sendmmsg fall-through pin (the family close-out)

**Grounding correction to the sub-slice-9 deferral note:** the upstream
defines **no recvmmsg and no sendmmsg handler** — the names exist only in
the per-arch syscall tables (the x86 recvmmsg=337 / sendmmsg=345, the x8664
299/307) and the SOCKETCALL enum lists the slots (19/20) without handlers.
There was never a vlen/timeout walk to port — both names ride the
dispatcher's not-implemented fall-through (the warn + the continue)
verbatim.

| piece | upstream | state | notes |
|---|---|---|---|
| socketcall SYS_RECVMSG | `net.py` handlers map | ✅ | the recvmsg ride added to the port's socketcall dispatch (the 3-arg form: fd, msg, flags) — the sub-slice-8 table had carried the calls 1–15 only, a verbatim gap now closed; the recvmmsg/sendmmsg socketcall slots stay unhandled (the verbatim NotImplementedError throw) |
| recvmmsg/sendmmsg | the syscall tables only | ✅ pinned | the x86-32 fixture rides int-0x80 recvmmsg(337): the name resolves, the registry misses, the emulation **continues** (the marker store after the call lands) — the verbatim fall-through; the recvmsg ride in the same blob pins the socketcall dispatch through the ENOTCONN -1 (the documented deviation shape) |

The socket family is now **fully closed against the upstream surface**:
socket/shutdown, connect/bind/listen/accept, socketpair, send/recv/
sendto/recvfrom (the STREAM + the NULL-addr + the datagram walks),
getsockname/getpeername, getsockopt/setsockopt (the SOL_SOCKET + IP + TCP
tables), recvmsg (the msghdr/iov/cmsg walk), socketcall (the x86
multiplexer with the recvmsg ride), and the verbatim unimplemented shapes
for sendmsg/recvmmsg/sendmmsg/accept4. **Findings:** the earlier
assumption that recvmmsg/sendmmsg carried upstream handler bodies (with
the vlen/timeout walk) was wrong — the handler bodies exist only for
recvmsg; and the x86 recvmmsg id is 337 (the 365 hit was the ARM table —
the table-array boundaries matter when pinning ids across arches).

### Phase 13 — the qiling/hw groundwork (the QlHwManager + the QlPeripheral base)

| piece | upstream | state | notes |
|---|---|---|---|
| QlPeripheral | `hw/peripheral.py` | ✅ | the instance-bytes register image, the raw_read/raw_write, the **monitor-decorator shape** (the ENTER/CALL/EXIT hook walk with the CALL replacing the body, the read_body/write_body overrides replacing the decorated read/write); the region/size/base walk; the save/restore pair; the step hook (the hasattr walk as the virtual default no-op) |
| QlPeripheralUtils + Access | `hw/peripheral.py` + `hw/utils/access.py` | ✅ | the hook_read/hook_write/hook_del (the ENTER/CALL/EXIT intercepts), the Access equality (the value only on the writes — the verbatim __eq__), the AccessSequence ring |
| QlHwManager | `hw/hw.py` | ✅ core | the entity/region maps, the create over the register_struct factory registry (the upstream rides the dynamic module lookup — the port's registry is the explicit map), the find walk, the step walk, the setup_mmio over the port's existing map_mmio, the save/restore; the env-driven load_env/load_all defer with the env-dict machinery |
| QlPripheralHandler | `hw/hw.py` | ✅ | the MMIO trampoline: the find-or-buffer dispatch (the verbatim non-mapped read/write onto the handler's byte buffer), the has_read/has_write prot derivation already in the port's map_mmio |
| the fixture | `tests/Hw_Test.cpp` | ✅ | the 4 tests: the mmio write dispatch + the find walk, the hook walk (the CALL intercept replacing the body verbatim), the non-mapped buffer ride, the step + the save/restore |

Findings: the host-side uc_mem_read/write DO route through the uc_mmio_map
callbacks (the fixture rides the mem API directly, no guest blob needed);
the mmio regions must be **page-aligned in size** (uc_mmio_map answers
UC_ERR_ARG 15 for the sub-page sizes); and the QlPeripheral ctor cannot
dispatch the virtual struct_size — the image size rides the ctor arg (the
base-ctor virtual call lands on the base body — the classic CTOR-virtual
order). The guest-side blob ride (the load/store instructions against the
mmio) is the next slice's first fixture.

### Phase 13.1 — the guest-side mmio fixture + the CortexMSysTick (the first concrete peripheral)

| piece | upstream | state | notes |
|---|---|---|---|
| QlTimerPeripheral | `hw/timer/timer.py` | ✅ | the ratio accessor pair + the extended snapshot (the ratio rides the save bytes' header, the verbatim `(ratio, bytes(instance))` pair shape) |
| CortexMSysTick | `hw/timer/cm_systick.py` (+ `cm3_systick.py` the pass-through) | ✅ | the 4-register SYSTICK image (CTRL@0/LOAD@4/VAL@8/CALIB@12, the CALIB seed 0xC0000000), the step downcount (the COUNTFLAG set + the LOAD reload at zero), the read-clear COUNTFLAG, the CTRL reserved-bit mask + the low-24-bit non-CTRL mask, the LOAD-write restart; the **TICKINT → the NVIC set_pending branch defers with the intc slice** (the hw manager carries no nvic yet) |
| SYSTICK_CTRL | `hw/const/cm4_systick.py` | ✅ | the ENABLE/TICKINT/CLKSOURCE/COUNTFLAG bit table verbatim |
| the fixture | `tests/Hw_Test.cpp` | ✅ | the guest x86-64 blob stores the LOAD/CTRL through the mmio (the A3 moffs form), the test drives the step walk, the COUNTFLAG read-clear pinned |

Findings: the `C7 04 25` SIB-store encoding burned the disp32 byte order
twice (the wrong-order variants faulted as the write-unmapped at the
garbage addresses — the tracer caught the first, the mis-grouped imm32 the
second); the `A3` moffs form is the reliable fixture shape (the 8-byte
abs64 LE — the same form the earlier posix fixtures use). The SysTick's
mmio map covers the containing page (0xE000E000) while the peripheral
keeps its verbatim 0xE000E010 base — the sub-page region rides the
handler's offset math.

### Phase 13.2 — the QlOsMcu skeleton + the core hw_ wiring

| piece | upstream | state | notes |
|---|---|---|---|
| QlOsMcu | `os/mcu/mcu.py` | ✅ core | the QlOs subclass (the type MCU → the baremetal membership), the stop (emu_stop + runable=false), the non-fast-mode run walk (the `while runable: emu_start(pc, 0, count=1); hw.step(); counter++` verbatim, the end-address + the count breaks); the **fast-mode MCUTask path throws** (lands with the uc-task slice) |
| the core wiring | `core.py` `if self.baremetal` | ✅ | the Qiling ctor creates the QlHwManager for the baremetal os (the MCU) — the hw() accessor returns the live manager; the select_os MCU case lands |
| the loader | `loader/mcu.py` | defers | the QlLoaderMCU (the elf/bin/hex reset walks + the ihex parser) rides the next slice; until then the MCU emulations go through the blob-style code path |

The hw phase resumes at the board-profile slice (the stm32f4xx/gd32vf103
const tables) — the intc slice landed below.

### Phase 13.3 — the intc slice (the CortexMNvic + the SCB + the TICKINT completion)

| piece | upstream | state | notes |
|---|---|---|---|
| CortexMNvic | `hw/intc/cm_nvic.py` | ✅ | the 3616-byte image (the ISER/ICER/ISPR/ICPR/IABR/IPR/STIR layout), the IRQN_MAX/MASK/OFFSET derivations verbatim, the enable/disable/pending/priority walks with the negative-IRQn SCB delegation, the byte-level write triggers (the set-bit fires the per-bit walk verbatim), the IPR reserved-low-nibble mask, the step's priority sort + the basepri/primask/faultmask gates + the dispatch, the region [(0, 1008), (3584, 3616)]; the verbatim quirks ported: the enable sets the ICER bit too, the clear mask is `MASK ^ (1 << bit)` (the low-5-bits-only AND), the get_pending reads the ISER |
| CortexMScb + CortexM4Scb | `hw/misc/cm_scb.py` + `cm4_scb.py` | ✅ | the SHCSR/ICSR walks for the negative IRQn (the enable/pending/priority), the ICSR write with the PENDSVSET (the bit 28) riding back into the nvic, the CM4 seed (CPUID 0x410FC241, AIRCR 0xFA050000, CCR 0x200) |
| the arch interrupt_handler | `arch/cortex_m.py` | ✅ | the priority/mask gates + the QlInterruptContext frame walk + the vector-table entry (isr*4) + the ipsr/pc/lr set + the raw uc emu_start; the unhandled-exception forward map (the EXCP → the IRQ) with the nvic set_pending ride |
| the exception-return completion | (the port-side) | ✅ deviation | **the unicorn 2.1.4's `do_v7m_exception_exit` is a `return; // FIXME` stub** — the bx to the EXC_RETURN magic raises EXCP_EXCEPTION_EXIT in a loop (the INTR hook fires with the intno 8). The port's unicorn_exception_handler stops the emu on the EXCEPTION_EXIT and lets the QlInterruptContext::exit() perform the frame restore from the magic pc (the verbatim exit walk) |
| QlOsMcu | `os/mcu/mcu.py` | ✅ core | (from the earlier slice) the non-fast walk with the hw.step() per slice |
| QlLoaderMCU | `loader/mcu.py` | ✅ core | the IhexParser (the 00/02/04 records + the coalescing walk verbatim), the bin/hex reset walks, the arch init_context + the entry_point from the pc; the elf branch throws (the pyelftools' PT_LOAD paddr walk rides the board-profile slice); the load_env rides the port's encoded env records (`type;arg1;arg2`) — the deviation from the upstream dict-of-dicts env documented in the header |
| the fixture | `tests/Hw_Test.cpp` | ✅ | the CORTEX_M hex fixture: the vector table (the MSP + the reset loop + the SysTick handler at the vector 15), the env-driven memory/mmio/core walks creating the systick/nvic/scb trio, the host-side LOAD/CTRL writes, the bounded run, and the handler's marker store at the SRAM asserted |

Findings: (1) the discarded `HookRet` RAII-unregisters the hook at the
temporary's destruction — the loader holds the intr-hook handle in a member
(the python's wrapper has no destroying-dtor semantics, so the upstream
discards freely — a port deviation that keeps the hook alive). (2) the
unicorn 2.1.4 v7m exception return is the FIXME stub (see above). (3) the
cortex_m fixture blob gotchas: the `movs r1, #imm` encoding puts the Rd in
the [10:8] bits (the earlier `0x2102` was the mov r1, #2 — the 0x2120 form
is the mov r1, #0x20), and the msp/sp registers alias (the msp write
reflects the sp read).

### Phase 13.4 — the board-profile slice 1: the Gpio family (the STM32F1xxGpio + the GpioHooks + the Afio)

| piece | upstream | state | notes |
|---|---|---|---|
| GpioHooks | `hw/gpio/hooks.py` | ✅ | the per-pin set/reset hook tables (the 16 pins); the upstream stores the (func, args, kwargs) tuples — the port rides the std::function captures (documented) |
| STM32F1xxGpio | `hw/gpio/stm32f1xx_gpio.py` | ✅ | the 28-byte image (CRL/CRH/IDR/ODR/BSRR/BRR/LCKR), the BSRR reads 0, the IDR writes ignored, the BSRR bit walk (the low half sets / the high half resets), the ODR diff walk firing the flip hooks, the set/reset pin rides (the ODR + the IDR + the hooks); the verbatim quirk: the BRR is a plain raw store (the upstream write never drives the pins from it) |
| STM32F1xxAfio | `hw/gpio/stm32f1xx_afio.py` | ✅ | the 32-byte image (EVCR/MAPR/EXTICR[4]/pad/MAPR2), the exti(index) nibble walk over the EXTICR → the gpio{a..g} entity lookup; the verbatim unmasked nibble shift (the out-of-range port throws — the upstream's IndexError analogue) |
| the factory kwargs | (the port-side) | ✅ | the PeripheralFactory rides the kwargs map (the upstream's **kwargs create flow) — the create(label, struct, base, kwargs) |
| the fixture | `tests/Hw_Test.cpp` | ✅ | the guest x86-64 blob stores to the GPIOA BSRR (the low + the high halves) through the 1MB PERIP mmio; the pin hooks fire per the flips, the ODR diff walk resets the set pins, the BRR/IDR no-ops pinned |

Findings: the PERIP mmio region rides the board's 1MB span (the fixture's
first 4KB map missed the GPIOA at 0x40010800 — the write-unmapped caught it);
the BSRR/ODR bit walks only drive the pins from the BSRR and the ODR — the
BRR write is the verbatim no-op.

### Phase 13.5 — the board-profile slice 2: the Usart family (the QlConnectivityPeripheral + the STM32F4xxUsart/F1xx + the const tables)

| piece | upstream | state | notes |
|---|---|---|---|
| PeripheralTube | `hw/connectivity.py` | ✅ | the byte queue (the readable/read/write/put/get walks), the save drain-then-refill + the restore verbatim |
| QlConnectivityPeripheral | `hw/connectivity.py` | ✅ | the itube/otube pair, the send/recv/send_to_user/recv_from_user, the connect/device_list; the snapshot rides the prefixed tube counts + the instance bytes (the port-side encoding of the upstream tuple); the port's recv_from_user guards the empty tube (the upstream's queue.get would block — the deviation documented) |
| STM32F4xxUsart | `hw/char/stm32f4xx_usart.py` | ✅ | the 28-byte image (SR/DR/BRR/CR1/CR2/CR3/GTPR), the SR seed TXE\|TC, the DR read clears the RXNE + rides the input tube + re-runs the transfer, the SR write keeps the CTS/LBD/TC/RXNE/TXE sticky bits, the DR write sends to the output tube, the transfer walk, the check_interrupt (the CR1/SR pairs pend the nvic), the step ride |
| STM32F1xxUsart | `hw/char/stm32f1xx_usart.py` | ✅ | the verbatim pass-through (the same register surface) |
| the const tables | `hw/const/stm32f4xx_usart.py` | ✅ | the USART_SR/DR/BRR/CR1/CR2/CR3/GTPR bit tables verbatim |
| the loader env kwargs | (the port-side) | ✅ | the core records carry the trailing `key=value` parts riding the kwargs map (the upstream's env kwargs dicts) |
| the fixture | `tests/Hw_Test.cpp` | ✅ | the CORTEX_M env walk creating the usart2 (the intn=38 kwarg) — the DR write lands the 'A' in the output tube, the injected input rides the RXNE via the transfer, the RXNEIE+RXNE pair pends the nvic through the check_interrupt (the ISER enable precedes — the set_pending only queues the enabled IRQs), the DR read drains and clears |

Findings: the usart2 sits at 0x40004400 (the board table) — the earlier blob
store targeting 0x40004C04 was the hand-arithmetic error (the DR = the base +
4); the nvic's set_pending only queues the enabled interrupts (the ISER bit
must ride the enable walk first — the firmware's NVIC_EnableIRQ shape).

### Phase 13.6 — the board-profile slice 3: the Tim family (the STM32F4xxTim/F1xx + the const tables)

| piece | upstream | state | notes |
|---|---|---|---|
| STM32F4xxTim | `hw/timer/stm32f4xx_tim.py` | ✅ | the 21-register image (CR1..OR), the ctor's derived-interrupt chain (the absent brk/cc/trg_com/up slots ride intn), the set_ratio override (the CNT + the prescale counter reset), the ratio/prescale overrides (the PSC division with the rounding), the send_update_interrupt (the DIER.UIE + the SR.UIF + the nvic pending), the step walk (the CEN gate, the ARR match resetting the CNT, the prescale division) |
| STM32F1xxTim | `hw/timer/stm32f1xx_tim.py` | ✅ | the verbatim pass-through |
| the const tables | `hw/const/stm32f4xx_tim.py` | ✅ | the TIM_CR1/CR2/SMCR/DIER/SR/EGR bit tables verbatim |
| the fixture | `tests/Hw_Test.cpp` | ✅ | the CORTEX_M env walk creating the TIM2 (the intn=28 + the up_intn kwarg) — the ARR/CEN/UIE walk pends the nvic at the ARR match, the PSC=1 prescale holds the CNT |

Findings: the QlTimerPeripheral's set_ratio/ratio became virtual for the Tim
override (the base's ratio_ member rides the derived ctor chain); the cm_systick
implementation moved to timer.cpp — the header cannot include hw/hw.hpp without
the peripheral.hpp <-> hw.hpp cycle (the TICKINT branch's nvic lookup needs the
full manager type).

### Phase 13.7 — the board-profile slice 4: the Exti family (the STM32F1xxExti)

| piece | upstream | state | notes |
|---|---|---|---|
| STM32F1xxExti | `hw/intc/stm32f1xx_exti.py` | ✅ | the 24-byte image (IMR/EMR/RTSR/FTSR/SWIER/PR), the per-line intn table (the exti0..4 singles + the 9_5/15_10 shared slots), the SWIER write masked against the IMR and the 0x7ffff with the 0->1 transitions riding the send_interrupt, the PR write clearing the pending + the SWIER bits, the send_interrupt walk (the IMR gate → the PR set → the gpio mirror via the afio's exti → the nvic pending with the line's intn) |
| the fixture | `tests/Hw_Test.cpp` | ✅ | the CORTEX_M env walk creating the gpioa/afio/exti (the exti0_intn=6 kwarg) — the EXTICR0 nibble 0 maps the line 0 to the port A, the SWIER bit 0 sets the gpio pin 0 and pends the nvic at 6, the PR write clears, the unmasked-line SWIER write stays inert |

The board-profile families remaining upstream: the Adc/Spi/I2c/Dma/Rcc/Flash/
Crc/Usb/Can/Bkp/Pwr/Wwdg/Iwdg classes (the mk64f12/sam3/gd32 boards ride the
same slice pattern); the stm32f103 board table + the load_env 'peripheral'
items ride the board-assembly slice once the peripheral classes land.

### Phase 13.8 — the board-profile batches 1-2 + the stm32f103 board assembly

| piece | upstream | state | notes |
|---|---|---|---|
| STM32F1xxRcc | `hw/misc/stm32f1xx_rcc.py` | ✅ | the 40-byte image (the CR/CFGR/CIR/APB2RSTR/APB1RSTR/AHBENR/APB2ENR/APB1ENR/BDCR/CSR), the CR/CFGR/CSR seeds (0x83/0x14/0x0C000000), the rdyon step walk (the on-bits reflect into the ready bits over the CR HSI/HSE/PLL/PLLI2S + the CFGR SWS/SW + the CSR LSI tables) |
| STM32F1xxFlash | `hw/flash/stm32f1xx_flash.py` | ✅ | the plain 36-byte image (the ACR..WRPR monitor bodies) |
| STM32F1xxAdc | `hw/analog/stm32f1xx_adc.py` (+ the const tables) | ✅ | the 80-byte image (the SR..DR), the DR 0x7ff seed, the CR2 write with the RSTCAL/CAL/SWSTART self-clearing walks (the SWSTART sets the EOS) |
| STM32F1xxSpi | `hw/spi/stm32f1xx_spi.py` | ✅ | the 32-byte tube-paired image (the CR1..I2SCFGR), the seed (the SR 0x0B, the DR 0x0C, the CRCPR 7), the DR read riding the input tube, the DR write to the output tube, the send_interrupt (the nvic pending) |
| CortexMBitband | `hw/mem/cm_bitband.py` | ✅ | the bit-banding bridge (the base|((offset&0x1ffffff)>>5) walk, the read/write through the aliased word with the bit pick/set) |
| MemoryRemap | `hw/mem/remap.py` | ✅ | the mem-backed pass-through region |
| STM32F1xxDma | `hw/dma/stm32f1xx_dma.py` | ✅ | the Stream record (CR/NDTR/PAR/MAR) + the one-unit step walk (the mem copy with the PSIZE/MSIZE alignments + the MINC/PINC), the last transfer clearing the EN + the transfer_complete (the ISR TC bit table + the nvic pending), the ISR-write-ignore + the IFCR-clear walks, the stream-intn table |
| STM32F4xxI2c/F1xx | `hw/i2c/stm32f4xx_i2c.py` | ✅ | the 9-register image, the recorder-driven SR1/SR2 pair ADDR clear, the CR1 START/STOP generation walks (the SB + the master/slave modes), the DR master walk (the OAR1 match + the ADDR/TXE/AF + the TRA + the send_data tube ride), the send_event_interrupt (the BUF/SLAVE/MASTER SR1 walks) |
| stm32f103 board table | `extensions/mcu/stm32f1/stm32f103.py` | ✅ | the full board env (the memory/mmio/core/peripheral items with the kwargs) as the port's encoded records; the loader's load_env creates the peripheral items (the port-side fold-in of the upstream's load_all — the upstream load_env ignores them); the upstream-missing classes (the Wwdg/Iwdg/Bkp/Pwr/Usb/Can/Crc/Rtc/Dbgmcu) degrade to absent entities mirroring the upstream's module-not-found warn |
| the fixtures | `tests/Hw_Test.cpp` | ✅ | the batch-1 fixture (the rcc rdyon, the adc SWSTART self-clear, the spi tube round trip, the bitband SRAM bit flip), the batch-2 fixture (the dma1 mem-to-mem copy + the stream-1 TC pend + the i2c1 START/DR address-match walk), the board fixture (the 25-entry assembly + the missing-class degradation + the exti0 pend through the board table) |

Findings: the std::vector .data() vs &vector gotcha (the bitband's memcpy
copied the vector object's internals into the write buffer — the segfault
bisected to the write walk); the board table's peripheral items ride the
load_env create (the deviation documented) — the upstream's load_all exists
but nothing calls it in the mcu path.

### Phase 13.9 — the board dicts (the sam3x8e/gd32vf103/mk64f12 family ports)

The user's premise that the boards "reuse the existing peripheral classes with
their own const tables" was corrected on inspection: each upstream board
carries its OWN peripheral-class family (the Sam3xa*, the GD32VF1xx, the
MK64F12* structs) — not the STM32 ones. The upstream implements a subset of
each board's referenced structs (12 of ~60 for the sam3x8e, 10 of ~30 for the
gd32vf103, 12 of ~73 for the mk64f12) and the rest degrade with the
module-not-found warn (the port mirrors the degradation: the create returns
null, the entity stays absent).

| piece | upstream | state | notes |
|---|---|---|---|
| SAM3xa family (12 classes) | `hw/{char,dma,misc,analog,flash,gpio,power,spi,timer}/sam3xa_*.py` | ✅ | the Uart (the RHR/THR tube walks + the step RXRDY pend), the Pdc/Wdt/Efc/Pwm/Tc plain images, the Adc (the CHER/CHDR + the CR.START → the ISR.DRDY), the Dac (the CDR → the EOC), the Pio (the SODR/CODR/PUER/PUDR pin walks over the GpioHooks-32), the Pmc (the clock-status write walks), the Spi (the RDR/TDR tube walks), the Uotghs (the CTRL CLKUSABLE walk) |
| sam3x8e board env | `extensions/mcu/atmel/sam3x8e.py` | ✅ | the full board table verbatim; the fixture rides the assembly + the adc/dac/pio/uart/pmc/spi walks (the uart RXRDY pend at intn 8) |
| GD32VF1xx family (10 classes) | `hw/{char,gpio,spi,i2c,dma,math,misc,timer,intc}/gd32vf1xx_*.py` | ✅ | the Usart/Spi/I2c connectivity images with the seeds (the STAT 0xc0, the TBE 0x2, the RT 0x2), the Gpio (the OCTL per-bit-transition walk + the BOP set/reset-halves walk over the GpioHooks-16), the Dma/Crc/Rcu/Rtc/Timer plain images, the Eclic 360-byte core image |
| gd32vf103 board env | `extensions/mcu/gd32vf1/gd32vf103.py` | ✅ | the full board table verbatim (the ECLIC core + the peripherals); the fixture rides the standalone hw-manager create walks + the gpio BOP/OCTL walk — the full-os run is documented as the RISCV/eclic slice debt (the gd32 board has no 0x0 mapping so the CORTEX_M init_context's read at 0x0 would fault; the upstream board rides the RISCV arch) |
| MK64F12 family (12 classes) | `hw/{char,gpio,spi,timer,analog,misc}/mk64f12_*.py` | ✅ | the Uart (the S1 TDRE|TC seed, the D-write tube, the RXFE/RCFIFO-vs-S1.RDRF read/step, the C2.RIE pend), the Gpio (the verbatim unmasked PSOR/PCOR/PTOR 32-pin loops + the PDDR-vs-PDIR pin storage + the port.send_interrupt ride), the Port (the PCR.IRQC 5-mode interrupt gate), the Spi (the POPR/PUSHR/CTAR + the RFDF/RXCTR), the Ftm (the QlTimerPeripheral CNT walk), the Adc (the SC1 no-op + the SC3.CAL self-clearing COCO), the Mcg (the C1/C5/C6 status walks), the Sim/Smc/Wdog/Osc/Rtc plain images |
| mk64f12 board env | `extensions/mcu/nxp/mk64f12.py` | ✅ | the full board table verbatim (73 entries); the fixture rides the create walks + the uart/gpio/adc/mcg walks |

Findings: the QlPeripheral using-declaration ctor trap — the Sam3xaPmc's
`using QlPeripheral::QlPeripheral` bound the registration's intn kwarg to the
image_size parameter, sizing the instance to 5 bytes while the walks wrote at
0x20/0x68 (the nondeterministic teardown segfault; fixed with the explicit
cctor); the ihex ELA type-04 record pin (the addresses past 64K need the
extended-linear-address record, the 16-bit addr field truncates); the gd32
board's absent 0x0 mapping vs the CORTEX_M init_context read at 0x0.

### Phase 12 sub-slice 3 — socketpair + the send/recv family

| piece | upstream | state | notes |
|---|---|---|---|
| socketpair | `syscall/socket.py` + `filestruct.py ql_socket.socketpair` | ✅ | the two next-free fds into the sv pair (the i32 writes at sv+0/sv+4 verbatim); the _WIN32 host lacks socketpair — the loopback accept walk (the listener on 127.0.0.1:0 + the connect off the getsockname addr) backs it; the AF_UNIX host open fails on _WIN32 so the fixture rides AF_INET |
| recv/send | `syscall/socket.py` | ✅ | the recv (the empty read writes nothing, the count rides the return) and the send (the verbatim IOError → 0 branch) |
| sendto/recvfrom | `syscall/socket.py` | ✅ core | the STREAM sockets and the NULL addr ride the send/recv bodies verbatim; the datagram dest/src paths throw pending their sub-slice (the upstream's SOCK_STREAM/SOCK_SEQPACKET checks verbatim) |
| the fixture | `tests/Posix_Test.cpp` | ✅ | the socketpair(AF_INET) + the send('PING')/recv flow over the pair — the pinned r10 gotcha fired a third time (the 4th syscall arg must ride r10, and the x8664 has NO bare send/recv — the sendto/recvfrom names at 44/45 ride the NULL-addr delegation) |

## Deferred (tracked, not built)

`qiling/hw/` (the peripheral tree: the manager + the peripheral base landed
as the Phase 13 groundwork; the `const/` register tables and the concrete
peripherals land with their consumer slices), `qiling/extensions/mcu/` +
`os/mcu` (the bare-metal half — the MCU os class is absent; the hw manager
wires into the core when the MCU dialect lands), `qiling/extensions/afl|r2
|tracing|sanitizers|coverage` (the optional-integration surface), the
kernel-module paths (`.ko` rides the ET_REL elf branch — the branch is in
due to the elf driver; `.kext` rides the macho loader; `.sys` rides pe.py +
ntoskrnl.exe emulation), the known-loop-trigger studies (the cached-TB
restart family: the Tb_Semantics/Thread_Clone DISABLED_ probes + the uefi
two multi-call anomalies + the MacosOs DISABLED_KextDriverRelocationsBridge
Calls uc INSN-hook-after-stub interaction — each its own dedicated session),
and the macos **net_send/net_recv** emitters (the upstream bodies exist but
have **no callers anywhere in the upstream** — the scapy-coupled wire build
is dead code there; the port skips them verbatim-absent until a consumer
appears).

### Resume-criteria reassessment (post-Phase-5)

- **`os/freebsd/` (~783 lines, `QlOsFreebsd(QlOsPosix)`, 6 syscall handlers)**:
  the most reachable — a thin dialect riding the completed Phase 5 POSIX base
  (the fcall layer, the kernel_api registry, the syscall ABI pieces it needs
  all exist). Slots as the Phase 5.5 dialect slice; TDD against the upstream's
  `test_freebsd.py` fixture shape.
- **`os/qnx/` (~1,303 lines)**: the same dialect shape but with its own
  `types.py` surface; reachable right after freebsd (the shared POSIX base
  means the second dialect is cheaper than the first).
- **`os/dos/` (~1,500 + `os/disk.py`, its only consumer)**: the interrupt
  phase; needs the COM/MBR loader branch on top of the done MZ sniffing.
  Reachable but self-contained; schedule after the dialects.
- **`os/uefi/` (~13,300 + `loader/pe_uefi.py`)**: the service-table phase over
  the done PE path; the largest single slice of the reachable set — plan as
  its own phase with the loader branch first.
- **`os/macos/` (~8,300 + `loader/macho_parser/`)**: the biggest lift (a new
  loader format + the OS); defers until the Mach-O parser is scoped.
- **`qiling/hw/` + the mcu tree (~23,500)**: the bare-metal phase; orthogonal
  to the OS families, defer unchanged.

Priority order adopted: **freebsd → qnx → dos → uefi → macos** (the dialects
first: the marginal cost per dialect shrinks as the POSIX base stabilises).
Status: freebsd ✅ (Phase 5.5), qnx ✅ (Phase 5.6, the COMBINE _IO_STAT branch
unparked green at 4aa66dd), dos ✅ (Phase 6), uefi ✅ (the loader + the
service-table + the RT slices; the two multi-call anomalies stay DISABLED_ +
documented), **macos ✅** (Phase 7 the container parser, Phase 8 the dialect
skeleton, the syscall.py surface, the kernel_api fncc surface, the
QlLoaderMachO container load + the end-to-end kernel_api dispatch, the
events/policy slice, the mach_msg message-path machinery (d147dec/e246444),
the loadDriver kernel-symbol walk + the kext import resolution (c127763),
the socket/ipf emitters (bec6e48), the ev stack-push emit path + the trigger
(f168bca) — the remaining macos surface: the DISABLED_ kext-relocs
insn-hook study + the upstream-dead net_send/net_recv emitters, both
tracked in the Deferred section) — **qiling/hw is in progress** (Phase 13:
the groundwork landed as this slice) and the socket family closed at Phase
12 (the sub-slices 1-10). The dos carry-overs all landed: the posix
`pack_stat_struct` family (0fc59a8 — and it unblocked the qnx COMBINE
_IO_STAT happy path at 4aa66dd), the connect_client_info full-body-vs-stub
oddity stays the upstream-verbatim stub (the full body is upstream dead
code). The dos int10/int16 curses surface stays console-detached (the
resolution map and the null-stdscr branches verbatim; the cursor/scroll
leaves are no-ops, the int16 poll throws NotImplemented) and the curses
color-pair machinery rides the state shell without a terminal.

### Phase 13.10 — the chardev bridge (the device_handler pre-walk)

| piece | upstream | state | notes |
|---|---|---|---|
| QlConnectivityPeripheral::device_handler_prewalk | `hw/connectivity.py device_handler` | ✅ | the decorator's pre-walk: the otube byte (`recv(1)`) forwards to every connected device (`device.send(data)`) and the devices step before the subclass body; the C++ rides the explicit pre-walk call at the top of the decorated steps (the decorator-to-explicit-call deviation) |
| the wired steps | `hw/char/stm32f4xx_usart.py`, `hw/i2c/stm32f4xx_i2c.py` steps | ✅ | the STM32F4xxUsart::step (the transfer + the check_interrupt after the pre-walk), the STM32F4xxI2c::step (the send_event_interrupt after the pre-walk); the upstream's third decorated step (the stm32f4xx_spi pass-body) rides the port's STM32F1xxSpi which predates it |
| the fixture | `tests/Hw_Test.cpp` | ✅ | the usart2→usart3 bridge ride (the DR write fills the otube, the step forwards to the usart3's itube, the usart3's RXNE + the nvic pend at 39, the DR read rides the byte), the i2c step walk |

### Phase 13.11 — the stm32f4xx spi variant + the contain walk

| piece | upstream | state | notes |
|---|---|---|---|
| STM32F4xxSpi | `hw/spi/stm32f4xx_spi.py` | ✅ | the 36-byte image (the CR1..I2SPR — the I2SPR tail the F1xx lacks), the verbatim seeds (the SR 0xB, the DR 0xC, the CRCPR 7, the I2SPR 2), the SR/RXCRCR/TXCRCR write ignores, the CR1/CR2/CRCPR/I2SCFGR/I2SPR RW_MASK stores, the DR store-then-send over the contain span, the device_handler step, the send_interrupt |
| QlPeripheral::contain | `hw/peripheral.py contain` | ✅ | the access-span check (field <= offset && offset+size <= field+field_size); the STM32F1xxSpi read/write switched from the exact-offset match to the verbatim contain walk |
| the I2c coverage pin | `hw/i2c/stm32f4xx_i2c.py` | ✅ | the port's STM32F4xxI2c already covers the upstream f4xx i2c shape verbatim (the recorder pair-clear, the CR1 RW_MASK, the DR master walks, the send_event_interrupt, the generate walks, the device_handler step); the fetch_device_address stays stubbed pending the upstream's device-address contract (the upstream reads `device_list[0].address`, an attribute defined only on the external harness chardev objects, not in the hw tree) |

### Phase 13.12 — the mcu fast mode (the interval-slice walk)

| piece | upstream | state | notes |
|---|---|---|---|
| QlOsMcu::run fast branch | `os/mcu/mcu.py` (MCUTask + tasks_start) | ✅ | the emu slices per the 100ms interval (the uc timeout in the usec — the uc's interval default rides as the port constant); the hw.step() rides per slice (the on_interrupted body); the fault warns and requests the clean stop (the on_interrupted non-OK shape); the count rides the schedule count; the end/stop checks break the loop |
| the deviation | — | — | the upstream's fast mode rides the gevent threadpool + the greenlet timeout; the port rides the uc's own emu_start timeout parameter per slice (the same slicing shape without the gevent machinery — the multitask/multi-uc-thread path remains the upstream-only surface) |
| the fixture | `tests/Hw_Test.cpp` | ✅ | the fast-mode TICKINT dispatch (the systick LOAD=3 + the CTRL TICKINT, the 6 interval slices riding the downcount cross + the handler store through the interrupt context, the counter == 6) |

### Phase 13.13 — the gd32 full-os run (the RISCV/eclic slice)

| piece | upstream | state | notes |
|---|---|---|---|
| QlArchRISCV::unicorn_exception_handler | `arch/riscv.py` | ✅ | the illegal instruction (intno 2) warns and continues; the rest raise NotImplemented (the verbatim upstream shape) |
| QlLoaderMCU the arch dispatch | — | ✅ | the reset + the intr hook dispatch on the arch type (the RISCV rides the riscv init_context + the exception handler; the CORTEX_M keeps its own) |
| the gd32 full-os fixture | — | ✅ | the ihex blob (the ELA record) loads at the flash, the RISCV-32 blob (the lui/addi/sw/jal) executes through the loader's reset + the eclic core entity rides the board table; the store lands in the SRAM |

### The closing-state assessment (the hw-phase completion)

The port's reachable surface is **not exhausted**. The dialect/OS phases all
closed (freebsd/qnx/dos/uefi/macos ✅, the socket family ✅, the hw/mcu phase
✅ — the 3 board families + the fast mode + the RISCV run) and the linux
kernel_api surface is complete (64/64). The genuinely remaining work, by
priority:

1. **The posix syscall gaps (prioritized)**:
   - the io/fs tail (~14: the readv/writev/pread64/sendfile/ioctl/faccessat/
     mknodat/fsync/fdatasync/fstat64/sysinfo/getrandom bodies — most are the
     small verbatim bodies over the done fd-table/fs-mapper surfaces);
   - the time family (6: nanosleep/clock_nanosleep/setitimer/time/times);
   - the proc/misc family (~10: arch_prctl/prctl/personality/ptrace/rseq/
     getpriority/setrlimit/prlimit64/ugetrlimit/gettid);
   - the epoll family (5) + the exec family (3: execve/fork/vfork — the
     execve rides the close_on_exec consumer).
2. **The optional extensions surface** (afl/r2/tracing/sanitizers/coverage):
   the tooling integrations; tractable but value depends on the consumer
   demand — defer with the tracked note.
3. **The DISABLED_ probe/study set** (the TB/clone bisects, the uefi
   second-dispatch pair, the macos kext-relocs): each its own dedicated
   session per the standing loop-trigger discipline.
4. **The upstream-dead surfaces** (the macos net_send/net_recv emitters, the
   dos connect_client_info full body): stay skipped verbatim-absent until a
   consumer appears.

The first step on item 1 landed with this section (the file-op family:
chmod/fchmod/mkdir/rmdir/umask/truncate/ftruncate — 430 passed).

### Phase 13.14 — the io/fs tail (the readv/writev/pread64/sendfile/ioctl/faccessat/fsync family)

| piece | upstream | state | notes |
|---|---|---|---|
| readv/writev | `os/posix/syscall/uio.py` | ✅ | the iovec walk (the 2-native-size records, the iov_base/iov_len pairs), the per-iovec fd write/read ride, the byte-sum return; the non-readable/writable fd answers 0 |
| pread64 | `unistd.py` | ✅ | the fd check, the is_mapped -EFAULT gate, the tell/seek/read/seek-back walk (the MIPS sp-offset quirk rides the MIPS slice) |
| sendfile/sendfile64 | `sendfile.py` | ✅ | the fd range checks, the offset read/seek, the read/write pump, the offset write-back, the old-location restore; the sendfile64 alias |
| fsync/fdatasync | `unistd.py` | ✅ | the fd check + the host flush via the fd's fileno (_commit on WIN32; the OSError answers -1 verbatim) |
| faccessat | `unistd.py` | ✅ | the virtual_abspath_at walk (the AT_FDCWD cwd + the opened dirfd's host_to_virtual_path), the safety check, the exists check answering 0 or -ENOENT |
| ioctl | `ioctl.py` | ✅ | the stub table (the allowed/disallowed (fd,cmd) pairs), the TCGETS 4-byte pack, the TIOCGWINSZ (1000,360,1000,1000) u16 pack, the TIOCSWINSZ/TCSETSW ignores, the unknown KeyError answering -1; the socket SIOCGIFADDR/ifrname-override branch defers with the harness chardev surface |
| sysinfo | `sysinfo.py` | ✅ | the 14-field pack verbatim (the pointer-size pack, the pack16 procs, the pack32 mem_unit) |
| getrandom | `random.py` | ✅ | the is_mapped -EFAULT gate + the urandom bytes + the len return |
| mknodat | `stat.py` | ✅ | the dirfd-resolved path + the empty-file creation (the WIN32 dev-node deviation documented); the EEXIST check |
| fstat64 | `stat.py` | ✅ | the __do_fstat alias riding the pack_stat64 layout (the do_fstat refactor carries the pack64 flag) |
| the fixture | `tests/Posix_Test.cpp` | ✅ | the writev iovec walk through the open/close flush cycle (the 4+6 byte pairs, the file content verified host-side) |

**Finding (the SchedYieldContinuesRun blob correction)**: the test's blob rode
`mov eax, 99` believing it sched_yield — on x86-64 **99 = sysinfo** (the
sched_yield is 24). The test passed vacuously through the not-implemented
fall-through (rax untouched) and the new sysinfo body faulted writing at the
guest's garbage `info=0` — the verbatim upstream behavior for sysinfo(0). The
blob now rides the real sched_yield number; the sysinfo(info=0) fault shape is
the same class as the upstream's (the mem.write at the caller-supplied
pointer).

### Phase 13.15 — the time family

| piece | upstream | state | notes |
|---|---|---|---|
| time | `os/posix/syscall/time.py` | ✅ | int(time.time()) |
| nanosleep/clock_nanosleep/clock_nanosleep_time64 | `time.py __sleep_common` | ✅ | the tv_sec read (the timespec64 forcing the 8-byte sec) + the nsec/1e9 add; the thread-management branch rides the host sleep (the documented deviation: the upstream parks via gevent.sleep with its own FIXME "this seems to be incomplete"; the port has no timer-wake machinery, so the sleeping thread stalls the emu for the interval) |
| setitimer | `time.py` | ✅ | the verbatim no-op (the upstream FIXME: the signal machinery is unmodeled) |
| times | `time.py` | ✅ | the 4×u32 ms fields + the elapsed*100 return (the clock-based approximation on WIN32) |
| the fixture | `tests/Posix_Test.cpp` | ✅ | the time/times/setitimer blob ride (the epoch, the ticks, the stub-0) |

### Phase 13.16 — the proc/misc family

| piece | upstream | state | notes |
|---|---|---|---|
| arch_prctl | `os/posix/syscall/prctl.py` | ✅ | the ARCH_SET/GET_FS/GS walks over the FS/GS base MSRs (the msr manager ride), the unknown-code -EINVAL |
| prctl/personality/ptrace/rseq | `prctl.py`/`personality.py`/`ptrace.py`/`rseq.py` | ✅ | the zero bodies verbatim (the rseq ENOSYS alternative stays commented verbatim) |
| gettid | `types.py` | ✅ | the thread-management id or the pid (the port's fixed getpid constant 0x512 rides the single-thread case) |
| ugetrlimit | `resource.py __getrlimit_common` | ✅ | the RLIMIT_STACK rides the profile `OS{bits}` stack_size pair (cur, -1); the others ride the host getrlimit (the WIN32 stub pair) |
| setrlimit | `resource.py` | ✅ | the nop shape (the maybe-nop comment verbatim) |
| prlimit64 | `resource.py` | ✅ | the pid==0 && new_limit==0 read branch via the host getrlimit; the rest -1 (the WIN32 stubs) |
| getpriority | `resource.py` | ✅ | the nice-0 fixed ride (the WIN32 has no getpriority) |
| the fixture | `tests/Posix_Test.cpp` | ✅ | the arch_prctl FS round trip + the prctl/personality/rseq zero rides |

### Phase 13.17 — the ipc/msg/shm family

| piece | upstream | state | notes |
|---|---|---|---|
| msgget | `os/posix/syscall/msg.py` | ✅ | the IPC_PRIVATE/create walk, the MSGMNI cap, the S_IWUGO\\|S_IRUGO mode shape |
| msgsnd/msgrcv | `msg.py` | ✅ | the mtype/mtext walk, the MSG_COPY/MSG_EXCEPT gates, the E2BIG/MSG_NOERROR branch, the S_IWUGO/S_IRUGO perms |
| shmget | `os/posix/syscall/shm.py` | ✅ | the create/get_by_key walk, the IPC_CREAT/IPC_EXCL, the SHMMNI cap, the SHM_W\\|SHM_R perms |
| shmat/shmdt | `shm.py` | ✅ | the shmaddr/SHM_RND alignment, the map + the attach list, the detach lookup |
| ipc (the multiplexer) | `os/posix/syscall.py ql_syscall_ipc` | ✅ | the version hi-word + the lo-word call decode, the arg reshuffles, the msgrcv version-0 msgp/msgtyp pointer walk |
| the fixture | `tests/Posix_Test.cpp` | ✅ | the direct msgget/msgsnd/msgrcv round trip (the sent bytes return through the queue) |
| the multiplexer fixture | — | ⏸️ | the ipc number 117 is x86-32 only (the x86-64 117 = setresuid); exercising it needs an i386 dialect fixture (deferred) |

**The family finding**: the msgrcv use-after-free — the port popped the queue
entry before copying the payload (the upstream python keeps the popped object
alive via the refcounting; the C++ `queue.erase` invalidated the `msg`
pointer → the segfault). Fixed by copying the mtype/mtext before the erase.
Also swept: the committed debug prints ([sysinfo]/[clone]/[disp]) removed.

## Phase 14 — the windows dlls tree (the MIRROR_LAYOUT_REORGANIZATION.md
## `os/windows/dlls/` mapping; the PE-first directive)

The consumer surface is the upstream `qiling/os/windows/dlls/` (the ~522
`@winsdkapi` handlers; the port's PE priority: kernel32 → msvcrt → user32,
ntoskrnl/wudplatform defer with the driver path).

| piece | upstream | state | notes |
|---|---|---|---|
| const.hpp | `os/windows/const.py` | ✅ | the 468 scalar constants verbatim (the #ifndef guards ride the windows.h macro duality — the dll bodies reference the bare spellings); REG_TYPES→registry.cpp, the LOCALE/MAP_VK/SYSTEMS_VERSION/Mapper tables port with their consumer families |
| wdk_const.hpp | `os/windows/wdk_const.py` | ✅ | the IRP major functions + the device types + the IOCTL bases (115 entries) |
| the fncc handler shape | `fncc.py winsdkapi` | ✅ | the ApiHandler upgraded to the resolved-params shape (the posix kernel_api ResolvedParams duality); the STRING/WSTRING entries arrive decoded, the plain-int entries raw |
| the hook_winapi dispatch | `windows.py hook_winapi` + `fncc.py` | ✅ | completed: the user-override raw ride → the registry find → the debug_stop QlErrorSyscallNotFound raise → the per-call-site fcall select + the resolve_named_params + the os.call (the unicorn-1579 pc guard) |
| the ctor profile deferral | — | ✅ | the QlOsWindows ctor profile reads moved to ensure_profile_state() (the ctor runs before the profile loads; the pinned macos gotcha) — the end-to-end QlOsWindows construction is now reachable |
| kernel32/handleapi | `dlls/kernel32/handleapi.py` (3) | ✅ | DuplicateHandle (the verbatim TODO comment), CloseHandle (the last_error ERROR_INVALID_HANDLE + the FIXME-protected branch; the IO-close ride defers to the fileapi slice), SetHandleInformation |
| kernel32/fileapi | `dlls/kernel32/fileapi.py` (29) | ✅ | the full family: the _CreateFile disposition walk (the GENERIC masks + the create_empty_file + the truncate), ReadFile/WriteFile (the QlFsMappedObject + the stats log_string for the stdio), FindFirstFileA/ExA (the WIN32_FIND_DATAA pack + the FILETIME 1601 walk), GetTempPath/GetShortPathName/GetVolumeInformation/GetDriveType/GetDiskFreeSpace (the profile rides), CreateDirectory/GetFileSize/CopyFile/DeleteFile/SetFileAttributes/AreFileApis, the mapping trio (the FileMappingMem page-file flavour + the FileMappingFile mem-hook flavour with the named-search dedup verbatim); the Handle ids widened to u64 (the MapViewOfFile id shape) |
| the fileapi findings | — | ✅ | (1) the create_file_mapping_body initially blanked the A-side lpName — the placeholder-typed params arrive decoded for both the A/W spellings, no per-branch re-decode; (2) the INVALID_HANDLE_VALUE branch creates a fresh mapping without the name dedup (the upstream shape, verbatim); (3) the shellcode scratch region rides the windows.ql CODE load_address 0x140000000 (not the posix 0x1000000) |
| kernel32/processthreadsapi | `dlls/kernel32/processthreadsapi.py` (20) | ✅ | the full family: the ExitProcess emu_stop, the GetStartupInfoA/W pair (the ctypes-aligned STARTUPINFO pack over the new structs writer), the TLS cycle (the TlsAlloc/TlsFree/TlsGetValue/TlsSetValue over the per-thread slots), the GetCurrent process/thread quartet, the IsProcessorFeaturePresent (the PF_XSAVE upstream-0x17 pin), the CreateThread over QlWindowsThread::create, the ExitThread pass, the TerminateProcess self-pid stop, the OpenProcess guards, the OpenProcessToken/OpenThreadToken over the new Token struct, the GetThreadContext/GetThreadTimes pass bodies |
| the processthreadsapi findings | — | ✅ | (1) `__setup_components` now wires the main thread + the QlWindowsThreadManagement + the main-thread handle; the scheduler `install_hook` MUST defer to load() — a hook_code registration at the os-ctor time dereferences the not-yet-wired uc engine (SEH, the 14-failure burst); (2) the thread-scan `(cur_thread.id + i) % len(threads)` makes the main-thread id parity decide the candidate — the added per-Qiling main thread silently flipped the Scheduling probe's parity onto the null-ql main thread; the test now pins the sequence via reset_id_sequence(); (3) the winnt.h preempts PF_XSAVE_ENABLED with the decimal 17 while the upstream const.py pins 0x17 — the handler pins the upstream value; (4) the STARTUPINFO pack is the ctypes DEFAULT-ALIGNED layout (the pointer fields at 8/16/24), not the packed walk |
| the Token struct | `os/windows/structs.py` | ✅ | the TokenInformationClass enum (the verbatim values incl. the 47-gap + the MaxTokenInfoClass 49), the ctor seeding TokenUIAccess/TokenGroups = ql.pack(0x1) + the TokenIntegrityLevel = the make_sid SID (the root check rides the SYSTEM permission, the 0x1234/545 split) parked on a sid-addr-id handle; the get() raises the NotImplemented for the unseeded classes |
| kernel32/synchapi | `dlls/kernel32/synchapi.py` (24) | ✅ | the Sleep pass, the critical-section pass set (the Enter/Leave/Delete 0 + the Initialize trio 1), the wait trio (the WaitForSingleObject/Ex riding the cur_thread waitfor list, the WaitForMultipleObjects walking the guest handle array), the mutex/event bodies over the new Mutex struct (the Global-prefix always-valid 0xD10C ride, the ERROR_FILE_NOT_FOUND/ALREADY_EXISTS guards, the ReleaseMutex ERROR_INVALID_HANDLE/ERROR_NOT_OWNER walks), the SRW no-op set; the Handle gains the obj_type typeid capture (the python isinstance checks ride the RTTI) |
| the synchapi findings | — | ✅ | (1) the upstream synchapi.py has NO SetEvent/ResetEvent — the kernel32 event surface is create-only; the KeSetEvent/KeResetEvent pair lives in ntoskrnl.py (a later family); (2) the WaitForSingleObject appends the handle obj to the waitfor list blindly (the python duck typing) — the mutex-handle wait = the latent AttributeError upstream, the port's typeid capture makes the ReleaseMutex isinstance safe; (3) the CreateMutex's second-create path leaves the last error untouched (the ERROR_ALREADY_EXISTS line commented out upstream) |
| kernel32/heapapi | `dlls/kernel32/heapapi.py` (8) | ✅ | the full family: HeapCreate (the verbatim alloc over the initial size), HeapAlloc (the shared body with the HEAP_ZERO_MEMORY page-granularity zero walk verbatim), HeapReAlloc (the null-base HeapAlloc ride + the zero-size free + the old-data copy walk), HeapSize/HeapFree, HeapSetInformation (the verbatim 1), GetProcessHeap (the heap start), HeapValidate (the verbatim _find + the inuse flag; the public find_chunk accessor on QlMemoryHeap) |
| kernel32/memoryapi | `dlls/kernel32/memoryapi.py` (4) | ✅ | VirtualAlloc (the verbatim heap-alloc ride), VirtualFree (the free + the verbatim 1), VirtualProtect (the verbatim 1), VirtualQuery (the MEMORY_BASIC_INFORMATION pack over the pointer-sized stride with the chunk-containment walk + the ERROR_INVALID_PARAMETER page-not-found guard, the EXECUTE_READ_WRITE/MEM_COMMIT/MEM_MAPPED constants verbatim) |
| kernel32/libloaderapi | `dlls/kernel32/libloaderapi.py` (16) | ✅ | the GetModuleHandleA/W/ExW trio (the null-module pe_image_address + the has_lib_ext .dll append + the get_image_by_name walk), the GetModuleFileNameA/W (the images walk + the nSize-1 truncate + the ERROR_INSUFFICIENT_BUFFER), the GetProcAddress (the MAXUSHORT ordinal/name split + the self-module export_symbols walk + the per-dll iat lookup), the LoadLibraryA/W/ExA/W (the load_dll walk), the resource pass bodies, the FreeLibrary/DisableThreadLibraryCalls, the SetDefaultDllDirectories (the USER_DIRS NotImplemented verbatim); the loader gains the init_exports walk (the LIEF ExportEntry parse: the export_symbols + the per-image iat slices + the pe_image_address accessor + the public load_dll over the __get_path_elements shape) |
| the libloaderapi findings | — | ✅ | (1) the upstream export_symbols is populated by init_exports for the MAIN image only, the dll exports land in the import_symbols/iat via load_dll — the port registers both into the same maps keyed by the image (the fixture rides the qldll.dll load through load_dll's export registration); (2) the fixture-blob discipline bit again: the ofstream of the stub dll silently failed on the missing System32 parent dir — create_directories before the write (the load_dll's casefold walk then reported the miss, the probe pinned it) |
| kernel32/sysinfoapi | `dlls/kernel32/sysinfoapi.py` (16) | ✅ | the full family: GetVersion (the (4<<16)|4 pack), the GetVersionExA/W pair (the verbatim 1), the GetSystemInfo/GetNativeSystemInfo pair (the ctypes-aligned SYSTEM_INFO pack: the dwPageSize, the lpMin = the pe_image_address, the lpMax = the dll_address + the dll_size, the fixed processor constants verbatim), GetLocalTime (the SYSTEMTIME walk, the isoweekday split), GetSystemTimeAsFileTime (the 1601 walk), GetSystemTimePreciseAsFileTime + GetSystemTime (the verbatim microsecond-pack64 quirks, the precise returns 0), GetTickCount (the verbatim 200000), the GetWindowsDirectory/GetSystemWindowsDirectory/GetSystemDirectory A/W set (the windir/winsys + the utf-16le/utf-8 encodings); the loader gains the dll_size accumulation + the dll_address accessor |
| the sysinfoapi findings | — | ✅ | (1) the upstream GetSystemTime/GetSystemTimePreciseAsFileTime pack the MICROSECOND-of-the-minute (the pack64 quirk, not the SYSTEMTIME/FILETIME walk) — the fixtures assert the <1000000 bound to pin the shape; (2) the GetVersionEx bodies write NOTHING into the caller's struct (the verbatim 1 only) — the callers that need the fields hit the un-initialized guest memory (the upstream shape, recorded); (3) the shellcode-mode pe_image_address rides 0 (the loader never mapped an image) — the GetSystemInfo lpMin assert pins the 0 |
| kernel32/processenv | `dlls/kernel32/processenv.py` (9) | ✅ | the full family: GetStdHandle (the verbatim passthrough), the GetCommandLineA/W pair, the GetEnvironmentStrings/W pair (the empty block = the bare NUL(s)), FreeEnvironmentStringsW (the verbatim 1), ExpandEnvironmentStringsW (the profile-PATH marker walk), the GetEnvironmentVariableA/W pair (the flat 0) |
| the processenv findings | — | ✅ | (1) the GetCommandLineA quirk: the loader cmdline already carries its trailing NUL and the upstream appends a SECOND one (the W path does not — it re-encodes the terminated cmdline utf-16le, one wide NUL inside); (2) the ExpandEnvironmentStringsW walk is stale-index: the pos = rmarker + len(val) uses the pre-replacement rmarker, so a replacement shorter than the %KEY% span skips past the next var (the chained vars mostly stay unresolved — the fixture pins the single-var + the kept-%KEY% shapes); (3) the nSize compare rides BYTES while the Win32 semantic is TCHARs — the short buffer skips the write but the full byte length still returns; (4) the port's cmdline composition (the basename + NUL) deviates from the upstream's Desktop-join with the quoting — the loader-slice deviation, already recorded |
| kernel32/interlockedapi | `dlls/kernel32/interlockedapi.py` (1) | ✅ | InitializeSListHead (the handle id IS the ListHead address, the empty-obj placeholder, the verbatim 0) |
| the interlockedapi findings | — | ✅ | the single handler needs no findings row; the Interlocked* arithmetic family lives nowhere upstream (the emulated binaries execute them natively) |
| the dlls aggregation | `dlls/__init__.py` | ✅ | dlls.hpp/.cpp: the register_dlls() re-seedable surface (the test isolation) + the per-family static-init |
| the fixtures | tests/Windows_Api_Test.cpp | ✅ | the handleapi coverage/shapes + the get_param/api_get_int paths |

The remaining dll families (the ~516 handlers): kernel32 (fileapi 29,
synchapi 24, processthreadsapi 20, winbase 40, sysinfoapi 16, libloaderapi 16,
heapapi 8, processenv 9, the console/debug/timezone/psapi/tlhelp32 tails),
msvcrt 50, user32 60, ntdll 29, advapi32 31, wininet 19, the small modules;
ntoskrnl 80 + wudplatform defer with the driver path. The per-family slice
cadence: the verbatim bodies over the done handle/fs/fd surfaces, one commit
per family, the structs.py pieces (FILETIME/SYSTEMTIME/SYSTEM_INFO/
OSVERSIONINFOEX...) port as their consumers need them.
