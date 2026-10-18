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

The ELF container parsing, the interpreter loading, the vsyscall page, the ET_REL driver path, the windows registry, and the windows subsystems landed (above). Next: the `os/posix/syscall/` module tree (file/mmap/socket/signal/...), `os/linux/` (`linux.py`, `procfs.py`, `thread.py`, `futex.py`), the kernel proxy, the richer kernel_api.py handler set (printk, kmalloc, _copy_to_user, ...), and the real-hive fixture slice. The syscall tables landed with Phase 4 (map_syscall.hpp).

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

## Deferred (tracked, not built)

`os/freebsd/`, `os/qnx/`, `os/macos/`, `os/uefi/`, `os/dos/`, `qiling/hw/`,
`qiling/extensions/mcu/` — resume criteria in PORT_PLAN.md §10 (OQ 9); the
remaining five profile files (dos/freebsd/macos/qnx/uefi `.ql`) defer with them.
