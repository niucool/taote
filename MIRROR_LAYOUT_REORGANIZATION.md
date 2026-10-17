# Qiling Mirror Layout Reorganization

**Source tree**: the Python project being ported lives in the sibling `qiling`
checkout (`../qiling` relative to this repo). All `qiling/...` references below are
relative to that tree; the repository root is this repo's port root (the port
lives at the top level, not under a `cpp/` subdirectory).

## Overview

This document defines the complete mirror-layout mapping between the Python package
(`qiling/`) and the C++ port rooted at the repository root.

**Scope** (per `PORT_PLAN.md` §1): **Windows PE first, then Linux ELF.** The initial
path comprises the root/arch/core/loader(PE+ELF+blob)/Windows/POSIX+Linux/debugger/
extensions/CLI surface. Mach-O, UEFI, DOS, QNX, FreeBSD, macOS, the `hw/` peripheral
tree, and the MCU board database are **Deferred** — they are mapped in the deferred
tree (see [Final Directory Layout](#final-directory-layout)) so a future resumption
slots in without re-planning. `qiling/extensions/idaplugin/`, `qltui.py`,
`jexamples/`, and the Docker packaging are out of scope entirely.

Companion documents: `PORT_PLAN.md` fixes the *what and in what order* (phases,
risks, dependencies, exit criteria); `ARCHITECTURE/*.md` are the per-subsystem
invariants. This document fixes the *how*: file/namespace mapping, the
C++17/CMake/vcpkg toolchain, the Python-to-C++ construct mappings, and the final
directory structure.

## Build System & Dependencies

### Platform Support
- **Target Platforms**: Windows and Linux (x64)
- **Compiler Support**:
  - Windows: MSVC (Visual Studio 2019/2022)
  - Linux: GCC 9+ or Clang 10+
- **Language Standard**: C++17 (ISO/IEC 14882:2017)
- **Build System**: CMake (minimum version 3.15)
- **Package Manager**: vcpkg for dependency management

### Third-Party Libraries

The following libraries are required and managed via vcpkg (see `PORT_PLAN.md` §6
for the reconciliation rationale — the Python ctypes bindings to unicorn/capstone/
keystone are *deleted*, not ported):

| Library | Purpose | vcpkg Package | Notes |
|---------|---------|---------------|-------|
| unicorn | CPU emulator (the engine under everything) | `unicorn` | **hard-pinned to 2.1.4** (D2, amended by D15) |
| capstone | Disassembly + its generated `*_const.h` headers | `capstone` | replaces `qiling/arch/*_const.py` (D3) |
| keystone | Assembly | `keystone` | |
| pe-parse | PE container/headers/imports/relocations parsing | `pe-parse` | Phase 3 (PE loader) |
| ELFIO | ELF segments/sections/symbols/dynamics reading | `elfio` | Phase 5 (ELF loader) |
| nlohmann-json | JSON (Windows registry `config.json`, report) | `nlohmann-json` | |
| spdlog | Logging (named loggers, levels, filters) | `spdlog` | |
| cxxopts | CLI option parsing for `qltool` | `cxxopts` | |
| Google Test | Unit testing framework | `gtest` | |
| unicornafl | AFL fuzzing integration | (feature `fuzz`) | optional, mirrors the `fuzz` extra |
| libr2 | radare2 integration | (feature `RE`) | optional, mirrors the `RE` extra |

Deferred dependencies (return with their subsystem): `yaml-cpp` (MCU board config),
`boost-context` (only if the ucontext fiber backend hits a platform gap).

**Setup Instructions**:

```bash
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=[vcpkg-root]/scripts/buildsystems/vcpkg.cmake
```

**CMake Configuration Example**:

```cmake
cmake_minimum_required(VERSION 3.15)

project(qiling VERSION 1.4.11 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(unicorn CONFIG REQUIRED)      # pinned to 2.1.4 in vcpkg.json (D15)
find_package(capstone CONFIG REQUIRED)
find_package(keystone CONFIG REQUIRED)
find_package(pe-parse CONFIG REQUIRED)
find_package(ELFIO CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(cxxopts CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)
# yaml-cpp returns when the deferred MCU path resumes

add_subdirectory(qiling)
add_subdirectory(qltool)
add_subdirectory(tests)

enable_testing()
add_test(NAME qiling_tests COMMAND qiling_tests)
```

### Build Outputs

The project produces **three primary build artifacts**:

| Artifact | Type | Description |
|----------|------|-------------|
| **Static Library** | `.lib` (Windows) / `.a` (Linux) | Core emulation framework (`qiling.lib` / `libqiling.a`) for integration into other projects |
| **CLI Tool** | `.exe` (Windows) / executable (Linux) | `qltool` — the `run`/`code` command-line front-end |
| **Test Executable** | executable | `qiling_tests` — the Google Test suite |

**CMake Build Targets**:

```bash
# Build everything (library + CLI + tests)
cmake --build build --config Release

# Build only the static library
cmake --build build --target qiling --config Release

# Build only the CLI tool
cmake --build build --target qltool --config Release
```

### Testing

**Test Framework**: Google Test (gtest) is used for all unit and integration tests.

**Test Structure**: Test files mirror the Python `tests/` inventory — each
`tests/test_*.py` maps to a `tests/*_Test.cpp` (mapping table in
[Test Layout Mapping](#test-layout-mapping) below). Fixture binaries come from the
`examples/rootfs/` submodule, reused unchanged.

**Running Tests**:

```bash
# Run all tests
./build/tests/qiling_tests

# Run a specific suite
./build/tests/qiling_tests --gtest_filter=Windows_Api.*

# Verbose output / machine-readable results
./build/tests/qiling_tests --gtest_output=json:test_results.json
```

**Test Coverage Requirements**:
- Every ported public API must have corresponding unit tests.
- Each phase's exit criteria (`PORT_PLAN.md` §10) name the suites that gate it.
- The Windows PE tests keep the real-DLL collection constraint (`tests/test_pe.bat`,
  `examples/scripts/` collectors) and remain host-gated.
- Malformed-binary robustness suites are mandatory for both loaders (host boundary).

## Mirror Layout Rules

1. **File Basename Matching**: Python `.py` files → C++ `.hpp` + `.cpp` pair with
   **identical basenames** (`qiling/os/mapper.py` → `qiling/os/mapper.hpp` +
   `mapper.cpp`). Header-only cases (pure enums/constants) may stay `.hpp`-only.
2. **`__init__.py` dissolution**: package inits dissolve into the package's
   namespace and a `pkg.hpp` aggregate header where needed. Two exceptions:
   `qiling/__init__.py` → `qiling/qiling.hpp` (the package entry), and
   `qiling/cli.py` + the `qltool` script → `qltool/main.cpp` (the CLI is one
   executable, not a library module).
3. **Namespace to Directory Mapping**: Python packages map to C++ namespaces and
   mirrored directories (`qiling/os/posix/syscall` →
   `namespace qiling::os::posix::syscall` under `qiling/os/posix/syscall/`).
4. **Directory Structure**: C++ directories **exactly mirror** the Python package
   structure — including subpackages (`os/windows/dlls/kernel32/`,
   `os/posix/syscall/abi/`, `debugger/qdb/arch/`, ...). Deferred subpackages are
   *not* pre-created; they appear when their phase runs.
5. **Class Names Verbatim**: `Qiling`, `QlMemoryManager`, `QlFsMapper`, `QlThread`,
   `QlLoader`, `Qdb`, ... carry over unchanged so either tree can be grepped for
   the counterpart.
6. **Const modules**: `qiling/arch/*_const.py` (x86_const, arm_const, ...) are
   **replaced by Capstone's generated headers** (`<capstone/x86_const.h>`, ...); no
   C++ counterpart file (D3). `qiling/hw/const/` (peripheral register tables) has
   no upstream and is ported by hand **when the bare-metal path resumes**.
7. **Python-Specific Constructs**:
   - ABC / `@abstractmethod` → abstract base classes with pure virtuals
   - `typing.Protocol` (hook callback shapes) → `std::function` type aliases
   - decorator-based API registration (`fncc.py`, `winsdkapi`) → static registration
     tables (`PORT_PLAN.md` 5.2)
   - `cached_property` → lazy-initialized members
   - `enum.Enum` → `enum class`
   - `with`-blocks → RAII
   - `*args/**kwargs` → option structs / overloads
8. **C++-Only Files**: documented with a note and placed next to their consumers —
   the Unicorn hook trampolines (`core_hooks_trampolines.*`), the fiber scheduler
   (`fiber.*` under `os/`), and the INI profile reader (`profiles/inireader.*`).

## Status Legend

- **Ported** — File exists and matches the Python source
- **Audit** — File exists but needs review/fixes for spec compliance
- **NEW** — File does not yet exist; planned per `PORT_PLAN.md`
- **C++-only** — No Python counterpart; C++ infrastructure file
- **Deferred** — Parked subsystem (PE/ELF priority); mapped in the deferred tree,
  resumes per `PORT_PLAN.md` §10 / OQ 9

Maintain `STATUS.md` listing each mirrored file with its status (initially all
`NEW`; deferred subsystems tracked in a separate section).

## Final Directory Layout

Phase tags (`[P#]`) refer to `PORT_PLAN.md` §10. Every initial-path file is listed;
deferred subsystems follow in their own tree.

### Initial port path

```
.
  CMakeLists.txt                 # top-level; adds qiling/, qltool/, tests/      [P0]
  vcpkg.json                     # manifest (unicorn@2.1.4, capstone, keystone,
                                 #   pe-parse, elfio, nlohmann-json, spdlog,
                                 #   cxxopts, gtest; features: fuzz, RE)         [P0]
  CONVENTIONS.md                 # conventions: ownership, exceptions, fibers,
                                 #   encoding (PORT_PLAN.md §9)                  [P0]
  qiling/
    # ---- root (qiling/*.py) ----                                            [P0-P3]
    qiling.hpp                   # <- __init__.py (package entry)
    core.hpp/.cpp                # <- core.py (Qiling composition root)
    core_hooks.hpp/.cpp          # <- core_hooks.py (hook registration surface)
    core_hooks_trampolines.hpp/.cpp  # C++-only: static C trampolines + payload
                                     # contexts bridging unicorn callbacks (5.1)
    core_hooks_types.hpp         # <- core_hooks_types.py (callback type aliases)
    core_struct.hpp/.cpp         # <- core_struct.py (QlCoreStructs)
    const.hpp                    # <- const.py (QL_ARCH, QL_OS, QL_ENDIAN,
                                 #      QL_STATE, QL_STOP, QL_VERBOSE, QL_CPU)
    exception.hpp/.cpp           # <- exception.py (QlError hierarchy)
    host.hpp/.cpp                # <- host.py (QlHost)
    log.hpp/.cpp                 # <- log.py (logger factory; wraps spdlog)
    utils.hpp/.cpp               # <- utils.py (static factories, emu-env
                                 #      guessing: PE -> arch/OS tables)
    profiles/                    # INI profiles copied verbatim                [P0]
      windows.ql                 #   (deferred OSes' profiles defer with them)
      linux.ql
      inireader.hpp/.cpp         # C++-only: tiny INI reader (configparser subset)

    # ---- arch (qiling/arch/) ----                                           [P1]
    arch/
      arch.hpp/.cpp              # <- arch.py (QlArch base)
      register.hpp/.cpp          # <- register.py (QlRegisterAccessor)
      models.hpp/.cpp            # <- models.py (QL_CPU per-arch tables)
      utils.hpp/.cpp             # <- utils.py (disasm/asm helpers)
      x86.hpp/.cpp               # <- x86.py
      x86_utils.hpp/.cpp         # <- x86_utils.py
      arm.hpp/.cpp                # <- arm.py
      arm_utils.hpp/.cpp          # <- arm_utils.py
      arm64.hpp/.cpp              # <- arm64.py
      cortex_m.hpp/.cpp           # <- cortex_m.py
      mips.hpp/.cpp               # <- mips.py
      ppc.hpp/.cpp                # <- ppc.py
      riscv.hpp/.cpp              # <- riscv.py
      riscv64.hpp/.cpp            # <- riscv64.py
      cpr.hpp/.cpp                # <- cpr.py   (ARM coprocessor regs)
      cpr64.hpp/.cpp              # <- cpr64.py
      msr.hpp/.cpp                # <- msr.py   (x86 MSR regs)
      # x86_const.py / arm_const.py / arm64_const.py / cortex_m_const.py /
      #   mips_const.py / ppc_const.py / riscv_const.py -> <capstone/*_const.h>
      #   (no C++ counterpart; D3)

    # ---- cc (qiling/cc/) ----                                               [P1]
    cc/
      cc.hpp                     # <- __init__.py (QlCC, QlCommonBaseCC)
      intel.hpp/.cpp             # <- intel.py (QlIntel64/32, amd64, ms64, ...)
      arm.hpp/.cpp               # <- arm.py
      mips.hpp/.cpp              # <- mips.py
      ppc.hpp/.cpp               # <- ppc.py
      riscv.hpp/.cpp             # <- riscv.py

    # ---- loader (qiling/loader/) ----                                       [P3/P5]
    loader/
      loader.hpp/.cpp            # <- loader.py (QlLoader base)
      pe.hpp/.cpp                # <- pe.py (over pe-parse; .sys/ntoskrnl
                                 #      kernel-driver surface defers)     [P3]
      blob.hpp/.cpp              # <- blob.py (shellcode test vehicle)    [P3]
      elf.hpp/.cpp               # <- elf.py (over ELFIO; ET_REL .ko
                                 #      driver branch defers)            [P5]

    # ---- os root (qiling/os/*.py) ----                                      [P2-P4]
    os/
      os.hpp/.cpp                # <- os.py (QlOs base)
      const.hpp                  # <- const.py
      memory.hpp/.cpp            # <- memory.py (QlMemoryManager, QlMemoryHeap,
                                 #      MMIO handler plumbing)
      fcall.hpp/.cpp             # <- fcall.py (QlFunctionCall marshalling)
      mapper.hpp/.cpp            # <- mapper.py (QlFsMapper, QlFsMappedObject)
      path.hpp/.cpp              # <- path.py (QlOsPath virtualization)
      struct.hpp/.cpp            # <- struct.py (QlStructFactory)
      thread.hpp/.cpp            # <- thread.py (QlThread base)
      fiber.hpp/.cpp             # C++-only: fiber scheduler (ucontext /
                                 #   Windows fibers) backing QlThread (5.3)
      filestruct.hpp/.cpp        # <- filestruct.py (ql_file, ql_pipe, ...)
      utils.hpp/.cpp            # <- utils.py
      stats.hpp/.cpp             # <- stats.py

      # ---- os/blob (qiling/os/blob/) ----                                   [P3]
      blob/
        blob.hpp/.cpp            # <- blob.py

      # ---- os/posix (qiling/os/posix/) ----                                 [P5]
      posix/
        posix.hpp/.cpp           # <- posix.py (QlPosix)
        const.hpp                # <- const.py
        const_mapping.hpp/.cpp   # <- const_mapping.py (errno maps)
        filestruct.hpp/.cpp      # <- filestruct.py
        structs.hpp/.cpp         # <- structs.py
        stat.hpp/.cpp            # <- stat.py
        msq.hpp/.cpp             # <- msq.py (SysV message queues)
        shm.hpp/.cpp             # <- shm.py (shared memory)
        kernel_proxy/            # host-kernel syscall proxy
          proxy.hpp/.cpp         # <- proxy.py
          ipc.hpp/.cpp           # <- ipc.py
          proxy_fd.hpp/.cpp      # <- proxy_fd.py
          argtypes.hpp/.cpp     # <- argtypes.py
        syscall/                 # one .hpp/.cpp per module, basenames identical
          unistd.hpp/.cpp  mman.hpp/.cpp  socket.hpp/.cpp  futex.hpp/.cpp
          signal.hpp/.cpp  stat.hpp/.cpp  ioctl.hpp/.cpp  epoll.hpp/.cpp
          fcntl.hpp/.cpp  msg.hpp/.cpp  net.hpp/.cpp  personality.hpp/.cpp
          poll.hpp/.cpp  prctl.hpp/.cpp  ptrace.hpp/.cpp  random.hpp/.cpp
          resource.hpp/.cpp  rseq.hpp/.cpp  sched.hpp/.cpp  select.hpp/.cpp
          sendfile.hpp/.cpp  sysctl.hpp/.cpp  sysinfo.hpp/.cpp  time.hpp/.cpp
          types.hpp/.cpp  uio.hpp/.cpp  utsname.hpp/.cpp  wait.hpp/.cpp
          syscall.hpp/.cpp       # <- syscall.py (dispatch base)
          abi/                   # per-arch syscall ABIs
            arm.hpp/.cpp  intel.hpp/.cpp  mips.hpp/.cpp
            ppc.hpp/.cpp  riscv.hpp/.cpp

      # ---- os/linux (qiling/os/linux/) ----                                 [P5]
      linux/
        linux.hpp/.cpp           # <- linux.py (QlLinux)
        syscall.hpp/.cpp         # <- syscall.py
        syscall_nums.hpp         # <- syscall_nums.py
        map_syscall.hpp/.cpp     # <- map_syscall.py (num -> name tables)
        thread.hpp/.cpp          # <- thread.py (QlLinuxThread)
        futex.hpp/.cpp           # <- futex.py
        procfs.hpp/.cpp          # <- procfs.py
        fncc.hpp/.cpp            # <- fncc.py
        function_hook.hpp/.cpp   # <- function_hook.py
        utils.hpp/.cpp           # <- utils.py
        kernel_api/
          kernel_api.hpp/.cpp    # <- kernel_api.py
          hook.hpp/.cpp          # <- hook.py

      # ---- os/windows (qiling/os/windows/) ----                             [P4]
      windows/
        windows.hpp/.cpp         # <- windows.py (QlWindows)
        api.hpp/.cpp             # <- api.py (winsdkapi surface)
        fncc.hpp/.cpp            # <- fncc.py (registration tables; 5.2)
        const.hpp                # <- const.py
        wdk_const.hpp            # <- wdk_const.py
        handle.hpp/.cpp          # <- handle.py (handle manager)
        thread.hpp/.cpp          # <- thread.py (QlWindowsThread)
        fiber.hpp/.cpp           # <- fiber.py (guest fibers)
        registry.hpp/.cpp        # <- registry.py (config.json primary; D10)
        structs.hpp/.cpp         # <- structs.py
        utils.hpp/.cpp           # <- utils.py
        clipboard.hpp/.cpp       # <- clipboard.py
        dlls/                    # one pair per DLL module
          dlls.hpp/.cpp          # <- __init__.py (loader/registration)
          const.hpp              # <- const.py
          advapi32.hpp/.cpp  ntdll.hpp/.cpp  kernel32/  user32.hpp/.cpp
          msvcrt.hpp/.cpp  ucrtbased.hpp/.cpp  msvbvm60.hpp/.cpp
          crypt32.hpp/.cpp  mscoree.hpp/.cpp  msi.hpp/.cpp  ntoskrnl.hpp/.cpp
          ole32.hpp/.cpp  oleaut32.hpp/.cpp  shell32.hpp/.cpp  shlwapi.hpp/.cpp
          wininet.hpp/.cpp  wsock32.hpp/.cpp  wudplatform.hpp/.cpp
          kernel32/              # one pair per API family                  [P4]
            consoleapi.hpp/.cpp  consoleapi2.hpp/.cpp  consoleapi3.hpp/.cpp
            debugapi.hpp/.cpp  errhandlingapi.hpp/.cpp  fibersapi.hpp/.cpp
            fileapi.hpp/.cpp  handleapi.hpp/.cpp  heapapi.hpp/.cpp
            interlockedapi.hpp/.cpp  ioapiset.hpp/.cpp  libloaderapi.hpp/.cpp
            memoryapi.hpp/.cpp  processenv.hpp/.cpp  processthreadsapi.hpp/.cpp
            profileapi.hpp/.cpp  psapi.hpp/.cpp  stringapiset.hpp/.cpp
            synchapi.hpp/.cpp  sysinfoapi.hpp/.cpp  timezoneapi.hpp/.cpp
            tlhelp32.hpp/.cpp  winbase.hpp/.cpp  winnls.hpp/.cpp
            winnt.hpp/.cpp  wow64apiset.hpp/.cpp

    # ---- debugger (qiling/debugger/) ----                                  [P6]
    debugger/
      gdb/
        gdb.hpp/.cpp             # <- gdb.py (remote-serial server)
        utils.hpp/.cpp           # <- utils.py
        xmlregs.hpp/.cpp         # <- xmlregs.py (target-descriptor XML)
      qdb/
        qdb.hpp/.cpp             # <- qdb.py (Qdb command set, scripts, RR)
        const.hpp  context.hpp/.cpp  helper.hpp/.cpp  misc.hpp/.cpp
        utils.hpp/.cpp
        arch/                    # per-arch disasm/register views
          arch.hpp/.cpp  arch_arm.hpp/.cpp  arch_intel.hpp/.cpp
          arch_mips.hpp/.cpp  arch_riscv.hpp/.cpp
        branch_predictor/        # reverse-execution branch oracle
          branch_predictor.hpp/.cpp  branch_predictor_arm.hpp/.cpp
          branch_predictor_intel.hpp/.cpp  branch_predictor_mips.hpp/.cpp
          branch_predictor_riscv.hpp/.cpp
        render/                  # TUI rendering
          render.hpp/.cpp  render_arm.hpp/.cpp  render_intel.hpp/.cpp
          render_mips.hpp/.cpp  render_riscv.hpp/.cpp

    # ---- extensions (qiling/extensions/) ----                              [P6]
    extensions/
      coverage/
        utils.hpp/.cpp           # <- utils.py
        formats/
          base.hpp/.cpp          # <- base.py
          drcov.hpp/.cpp  drcov_exact.hpp/.cpp  ezcov.hpp/.cpp
          history.hpp/.cpp
      tracing/
        utils.hpp/.cpp           # <- utils.py
        formats/
          base.hpp/.cpp  registers.hpp/.cpp  tenet.hpp/.cpp
      sanitizers/
        heap.hpp/.cpp            # <- heap.py
      report/
        report.hpp/.cpp          # <- report.py (nlohmann-json; no new dep)
      afl/                       # behind the `fuzz` build feature
        afl.hpp/.cpp  qlfuzzer.hpp/.cpp
      r2/                        # behind the `RE` build feature
        r2.hpp/.cpp

  qltool/
    main.cpp                     # <- qltool (script) + cli.py (argparse ->
                                 #    cxxopts; run/code subcommands)      [P7]

  tests/                         # gtest; see mapping below              [P0-P8]
```

### Deferred tree (parked; resumes per PORT_PLAN.md §10)

Mapped for completeness — **not built** under the current PE/ELF priority. Each
entry keeps the identical basename/namespace rules:

```
qiling/
  loader/
    macho.hpp/.cpp               # <- macho.py (macOS path)
    macho_parser/                # <- macho_parser/ (7 files, ported as-is)
    pe_uefi.hpp/.cpp             # <- pe_uefi.py (UEFI PE)
    dos.hpp/.cpp                 # <- dos.py (COM/MBR)
    mcu.hpp/.cpp                 # <- mcu.py (Intel HEX / raw firmware)
  os/
    disk.hpp/.cpp                # <- disk.py (QlDisk; sole consumer is DOS)
    freebsd/                     # <- os/freebsd/ (5 files)
    qnx/                         # <- os/qnx/ (10 files)
    macos/                        # <- os/macos/ (20 files)
    uefi/                        # <- os/uefi/ (20 root files + protocols/,
                                 #    guids.csv; boot/runtime/SMM services)
    dos/                         # <- os/dos/ (12 files, interrupt services)
    mcu/                         # <- os/mcu/ (3 files)
    windows/dlls/wudplatform.hpp/.cpp  # exercised by the UEFI path
  hw/                            # <- qiling/hw/ (139 files: hw.py,
                                 #    peripheral.py, connectivity.py, 17 device
                                 #    families + const/ register tables + utils/)
  extensions/
    mcu/                         # <- extensions/mcu/ (29 files: board/chip
                                 #    definitions for atmel/bes/gd32vf1/nxp/
                                 #    stm32f1/stm32f4)
```

## Test Layout Mapping

Python `tests/test_*.py` → C++ gtest suites. In-scope initial-path mapping:

| Python test | C++ suite | Phase |
|---|---|---|
| `test_pe.py`, `test_pe_sys.py`, `test_peshellcode.py` | `tests/Pe_Test.cpp` (+ `Loader_Pe_Test.cpp`) | 3-4 |
| `test_windows_cpp_x86.py`, `test_windows_cpp_x8664.py` | `tests/Windows_Api_Test.cpp`, `tests/Windows_Dlls_Test.cpp` | 4 |
| `test_windows_debugger.py` | `tests/Windows_Debugger_Test.cpp` | 6 |
| `test_elf.py`, `test_elf_multithread.py` | `tests/Loader_Elf_Test.cpp`, `tests/Linux_Test.cpp`, `tests/Multithread_Test.cpp` | 5 |
| `test_posix.py` | `tests/Posix_Syscall_Test.cpp` | 5 |
| `test_android.py` (ARM ELF), `test_riscv.py`, `test_tendaac15_httpd.py` (MIPS ELF) | `tests/Linux_Arch_Test.cpp` (per-arch Linux groups) | 5 |
| `test_kernel_proxy.py` | `tests/KernelProxy_Test.cpp` | 5 |
| `test_shellcode.py`, `test_blob.py` | `tests/Shellcode_Test.cpp` | 3 |
| `test_struct.py`, `test_pathutils.py` | `tests/Struct_Test.cpp`, `tests/Path_Test.cpp` | 2-3 |
| `test_cpu_models.py` | `tests/Arch_Models_Test.cpp` | 1 |
| `test_debugger.py`, `test_qdb.py` | `tests/Gdb_Server_Test.cpp`, `tests/Qdb_Test.cpp` | 6 |
| `test_history.py` | `tests/Ext_Tracing_Test.cpp` (history format) | 6 |
| `test_r2.py` | `tests/Ext_R2_Test.cpp` (RE feature-gated) | 6 |
| `test_qltool.py` | `tests/Cli_Test.cpp` | 7 |
| `test_perf.py` | `tests/Perf_Baseline_Test.cpp` (timing baselines) | 8 |

Deferred (parked with their subsystems): `test_macho.py`, `test_macho_kext.py`,
`test_dos.py`, `test_dos_exe.py`, `test_uefi.py`, `test_qnx.py`, `test_mcu.py`,
`test_edl.py`. Host-gated scripts (`test_pe.bat`, `test_onlinux.sh`, `test_macho.sh`)
become CI recipes, not ported files.

## Key Migration Considerations

Extends the construct rules above with the project-specific decisions
(`PORT_PLAN.md` §9 is authoritative):

- **Memory Management**: Python GC → C++ RAII/smart pointers. `Qiling` owns
  components (`arch`, `os`, `loader`, `mem`, `hw`) via `std::unique_ptr` in the
  documented init order; non-owning back-references are raw pointers/references;
  guest handles that can outlive creators use `shared_ptr`/`weak_ptr` (5.5).
- **Exception Handling**: the `QlError*` hierarchy ports verbatim. Exceptions never
  cross a Unicorn C frame (the trampoline records and `emu_start` re-raises — 5.1)
  and never unwind across a fiber switch (5.3/5.4).
- **Dynamic Dispatch**: name-based component resolution (`utils.py` `getattr`),
  decorator API registration (`fncc.py`), and duck-typed contracts → static
  factories and registration tables (5.2).
- **Guest Threading**: gevent `Greenlet` → the stackful fiber scheduler under
  `os/thread` (5.3).
- **Strings/Paths**: `std::string` for guest bytes; `std::filesystem` only at the
  host boundary (mapper, profiles); the `QlFsMapper` containment checks are the
  host trust boundary and get a dedicated traversal test pass (5.6).
- **Collections**: `dict` dispatch → `std::unordered_map`; `list` → `std::vector`;
  `Optional[X]` → `std::optional<T>`.
- **Constants**: Capstone's generated headers replace `arch/*_const.py` (D3);
  `hw/const/` peripheral tables port by hand when the bare-metal path resumes.
- **Snapshots**: `pickle` (`ql.save`/`ql.restore`) → an explicit versioned binary
  format; no pickle compatibility (OQ 7 defines the format).
- **C++17 Features Leveraged**: `std::optional`, `std::variant`, `std::filesystem`,
  `std::string_view`, structured bindings, `if constexpr`.
