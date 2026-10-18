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
- **kernel_api.py's handler surface is 64 hook_ functions**; the port carries ~50 (the typed-struct handlers - the cred/filp field accessors - defer with the struct slices).

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

- **the TB-boundary stop semantics**: uc_emu_stop from a UC_HOOK_INSN
  callback aborts at the next TB boundary, not immediately - a linear guest
  body runs past its emu_stop into whatever follows; the child bodies end
  with `jmp $` (the branch ends the TB) or rely on the syscall resume pc.
  The upstream gevent flow tolerates the same slop (the pc lands past the
  syscall and the resume re-checks).
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

## Deferred (tracked, not built)

`os/freebsd/`, `os/qnx/`, `os/macos/`, `os/uefi/`, `os/dos/`, `qiling/hw/`,
`qiling/extensions/mcu/` — resume criteria in PORT_PLAN.md §10 (OQ 9); the
remaining five profile files (dos/freebsd/macos/qnx/uefi `.ql`) defer with them.
