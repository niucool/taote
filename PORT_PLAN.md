# Qiling C++ Port Plan

**Source tree**: the Python project this plan ports lives in the sibling `qiling`
checkout (`../qiling` relative to this repo). All `qiling/...` file references
are relative to that tree; all `cpp/...` references are relative to this repo's
future `cpp/` root.

Companion to `MIRROR_LAYOUT_REORGANIZATION.md` (the *how*: file/namespace mapping,
the final directory layout, build outputs, test mapping) and the
`ARCHITECTURE/*.md` module docs (`core.md`, `arch.md`, `loader.md`,
`os-base.md`, `os-posix.md`, `os-windows.md`, `os-baremetal.md`, `hw.md`,
`debugger.md`, `cli.md` — each subsystem's invariants, boot flow, and API
surface). This document fixes the *what and in what order*: what we are porting, the
dependency order it must be built in, the hard problems that will bite, and a phase
plan with exit criteria and tests for each milestone.

Everything here targets the **library + CLI** scope (the same thing the Python package
ships today: `qiling/`, `qltool`). The TUI, the IDA plugin, and the packaging Docker
setup are out (see 1).

---

## 1. Scope

### In scope

| Python subsystem | Role | .py files | lines |
|---|---|---:|---:|
| `qiling/` root (`core.py`, `core_hooks*.py`, `core_struct.py`, `utils.py`, `const.py`, `log.py`, `exception.py`, `host.py`, `cli.py`) | The facade, hook engine, component factory, CLI | 10 | ~2,963 |
| `qiling/arch/` | CPU layer: `QlArch` per-arch classes, registers, disassembly, calling conventions | 25 | ~3,498 |
| `qiling/cc/` | Calling-convention data (`QlCC`) | 6 | ~425 |
| `qiling/loader/` | Format loaders: ELF, PE, Mach-O (+ in-tree `macho_parser/`), DOS, MCU, blobs, kernel modules | 16 | ~4,376 |
| `qiling/os/` | OS emulation: base + POSIX syscalls + Linux/FreeBSD/macOS/QNX + Windows DLLs + UEFI/DOS/MCU/BLOB | 219 | ~57,352 |
| `qiling/hw/` | MMIO peripheral emulation (peripheral classes + `const/` register tables) | 139 | ~12,225 |
| `qiling/debugger/` | GDB remote-serial server (`gdb/`) and the built-in Qdb debugger (`qdb/`) | 31 | ~4,586 |
| `qiling/extensions/` — `afl`, `coverage`, `tracing`, `sanitizers`, `r2`, `report`, `mcu` | Optional integrations + the MCU board/chip definition database | ~33 | ~12,468 |

Total mirror surface: **~97,900 lines of Python**; the initial PE+ELF port path is
**~48,000** of those (Sub-scoping below).

Note on `qiling/extensions/mcu/`: despite living under `extensions/`, it is not an
external-IDE plugin — it is the per-board/chip definition database the MCU examples
load as `env=gd32vf103` (`examples/mcu/gd32vf103_blink.py:11`). It is on the required
path for bare-metal emulation and is tracked for the deferred bare-metal path (see
Sub-scoping). The actual GUI/AddIn analogue is `qiling/extensions/idaplugin/` (below).

### Out of scope (explicitly excluded)

- `qiling/extensions/idaplugin/` (2,277 lines) — an IDA Pro GUI plugin; the underlying
  coverage/tracing behaviour it exposes is already in scope via `extensions/coverage`.
- `qltui.py` (674 lines) — the terminal UI; a later phase may port it, but it is not
  on the core path.
- `jexamples/` — legacy, unexercised by CI.
- `Dockerfile` / packaging — replaced by the CMake/vcpkg build (8).
- `tests/` as *tests* — the .py test files are not ported; their **behaviour** is
  preserved as Google Test suites under `cpp/tests/` (see 11). `examples/rootfs/` is
  reused as the input-fixture submodule, unchanged.

### Sub-scoping (format priority)

**Windows PE first, Linux ELF second; everything else is deferred** — no plan to
support the rest now. Concretely:

- **Initial port path (~48,000 lines)**: the PE loader (`loader/pe.py`) +
  `os/windows/` first, then the ELF loader (`loader/elf.py`) + `os/posix/` +
  `os/linux/`, sharing the root/arch/core/debugger/CLI surface. The minimal
  `loader/blob.py` + `os/blob/` glue (~120 lines) stays in Phase 3 as the shellcode
  test vehicle — it is a degenerate loader with no format to parse.
- **Deferred (≈ 49,000 lines, resume criteria in OQ 9)**: `os/freebsd/`, `os/qnx/`,
  `os/macos/` (+ `loader/macho_parser/`), `os/uefi/` (+ `loader/pe_uefi.py`),
  `os/dos/`, the `qiling/hw/` peripheral tree (needed only by bare-metal targets),
  `qiling/extensions/mcu/` (the MCU board database), the kernel-module paths
  (`.ko`, `.kext`, `.sys`), and the `os/blob` bare-metal half. These are parked,
  not deleted: the deferred-subsystems table in 10 notes where each slots back in.
- **ELF arch coverage**: Windows PE implies x86/x86-64 first (the ARM/ARM64 PE
  machine types exist in `utils.py` but no Windows-on-ARM fixtures are in the
  suite); Linux ELF spans many arches in the Python tree — Phase 5 exercises
  x86/x86-64 and ports the remaining arch classes opportunistically (Phase 1
  already builds them all; per-arch bring-up is cheap const-table work).
- **RE / fuzz extras**: `extensions/r2` and `extensions/afl` depend on optional C
  libraries (`r2libr`, `unicornafl`). They port as optional build features (vcpkg
  features), never hard dependencies — mirroring the `pyproject.toml` extras.

---

## 2. Scale and reality check

This is not a thin port. Three observations frame it:

1. **`qiling/os/` is 57,352 lines — 59% of the codebase — but it is breadth, not
   depth.** It is ~28 POSIX syscall modules, ~20 Windows DLL modules, a UEFI service
   table set, and the QNX/DOS/macOS dialects. Each module is small and independently
   testable; the volume is the schedule, not any single piece. The genuinely hard
   slices inside it are the multithread emulation (fibers, 5.3) and the API-dispatch
   engine (5.2).

2. **The single biggest risk of the comparable decompiler port (replacing a mature
   runtime library layer, e.g. an ECMA-335 metadata reader) does not exist here.**
   The three foundational libraries — Unicorn (CPU), Capstone (disassembly),
   Keystone (assembly) — are already C. The PyPI `unicorn`/`capstone`/`keystone-*`
   packages are thin ctypes bindings over them; the C++ port links directly and
   *deletes* a layer. Likewise the pure-Python `pefile`/`pyelftools` parsers are
   replaced by mature C++ parsers (5.8) and the Mach-O parser is already hand-written
   in-tree. The foundation is the *cheapest* part of this port.

3. **Python dynamism is the real tax.** The codebase leans on: name-based component
   resolution (`qiling/utils.py`), decorator-registered API hooks (`qiling/os/fcall.py`,
   `qiling/os/windows/fncc.py`), duck-typed `QlOs`/`QlLoader` contracts, gevent
   greenlets for multithread emulation (`qiling/os/thread.py`), and exceptions
   crossing the Unicorn callback boundary. C++ has none of that for free; each must
   become an explicit static mechanism (factories, registration tables, fibers,
   exception discipline — 5.1–5.4). That redesign, not the line count, is where the
   schedule risk concentrates.

The honest read: this is a multi-engineer, multi-quarter effort, not a weekend. The
plan below is phased so that each milestone is independently useful and testable, and
so the riskiest pieces (hook engine, fibers, POSIX breadth) are confronted early
rather than discovered late.

---

## 3. Architecture recap (the pipeline we must reproduce)

Taken from `CLAUDE.md` (Boot / Entry Flow) and the module docs:

```
User binary (PE first, then ELF; Mach-O/COM/UEFI/HEX deferred)
  -> Qiling facade (core.py): guess arch/OS, build components       [Phase 3]
  -> Loader: parse format, map image into emulated memory           [Phase 3 (PE) / 5 (ELF)]
  -> Arch layer: QlArch, register maps, uc instance, QlCC           [Phase 1]
  -> Core services: memory manager/heap, fcall, hooks, host fs      [Phase 2]
  -> OS layer (QlOs subclass): Windows [Phase 4] / POSIX+Linux [Phase 5]
       -- every CPU exit (syscall / API call / interrupt / MMIO) --
       -- dispatches back into the OS layer through the hook engine --
  -> Debugger: GDB server + Qdb (reverse debugging)                 [Phase 6]
  -> Extensions: coverage/tracing, AFL fuzzing, sanitizers, r2      [Phase 6]

CLI: qltool run|code  ->  qiling.cli.run                            [Phase 7]

(hw MMIO peripherals + the MCU bare-metal path are deferred with the MCU subsystem)
```

Key invariants we must preserve in C++ (from `CLAUDE.md` and the code):

- **`Qiling.__init__` is the composition root** with a fixed instantiation order
  (`qiling/core.py:35`): arch/OS guessing → arch → struct/hook mixins → logger →
  profile → loader → memory manager → OS layer → hardware manager (bare-metal only)
  → `loader.run()`. The C++ facade preserves this order.
- **`Qiling.emu_start` (`qiling/core.py:743`) is the only entry into Unicorn.** All
  emulated-exit dispatch flows back through the hook engine into the OS layer; no
  syscall path may bypass it.
- **All name→class resolution lives in `qiling/utils.py`** (QL_ARCH/QL_OS → class);
  the C++ port keeps a single resolution point (5.2).
- **The fs mapper and path virtualization (`qiling/os/mapper.py`, `qiling/os/path.py`)
  are the host trust boundary.** Rootfs escape via path handling is the review-listed
  host-boundary risk; the C++ port must keep the containment checks and add the
  `std::filesystem` equivalent review pass (5.6).
- **Emulation fidelity beats abstraction** (project deviation): syscall/API/peripheral
  implementations mirror the real platform's observable behavior even when that means
  repetitive per-OS code. Do *not* unify the POSIX and Windows layers in C++.
- **`unicorn == 2.1.3` is hard-pinned** (`pyproject.toml:39`). The pin carries over;
  touching it remains a project-wide event.
- **Robustness tenet**: guest-controlled sizes/offsets reaching host allocations must
  be checked where they occur (loader parsers are the reachable-from-untrusted-input
  surface); unverifiable input degrades to a QlError, never a host crash.

---

## 4. Dependency graph and porting order

Build order is forced by the composition root: nothing above the arch layer runs
without it, and no OS layer runs without loaders and core services. Within the
port, the format priority (Sub-scoping in 1) sequences **PE before ELF**.

```
Util + exceptions + logging                   Phase 0
  |
  v
Arch layer (x86/x86-64 bring-up first)        Phase 1   <-- foundation, low risk
  |
  v
Core services (memory, hooks, fcall, host)    Phase 2   <-- hook engine, hardest #1
  |
  v
Qiling facade + PE loader (+ BLOB glue)       Phase 3
  |
  v
Windows (APIs, DLLs, registry, fibers)        Phase 4   <-- hardest #2 (breadth + dispatch)
  |
  v
ELF loader + POSIX base + Linux               Phase 5   <-- hardest #3 (breadth + fibers)
  |
  +----------------+
  |                |
  v                v
Debugger + Extensions          Phase 6
  |
  v
qltool CLI + profiles          Phase 7
  |
  v
Integration + hardening        Phase 8
```

Parked branches (resume when the priority changes): the UEFI/DOS/QNX/macOS OS
layers and the hw/MMIO bare-metal path hang off Phase 3's facade; the `freebsd`
layer hangs off Phase 5's POSIX base. Each slots back in as a phase insertion
without disturbing Phases 0-8 (resume criteria: OQ 9).

---

## 5. Top porting risks and decisions

### 5.1 The hook engine — the hottest path in the framework

`qiling/core_hooks.py` wraps every Unicorn hook type (mem read/write/fetch/valid/
invalid/unmapped, code/instruction/block, interrupt, invalid-insn, syscall) with a
Python closure that re-enters `Qiling`. In Python this is cheap to write and unsafe
to reason about; in C++ it becomes the correctness-critical core:

- **Trampoline design**: Unicorn takes C function pointers. Each registration wraps a
  `std::function` payload in a static C trampoline, with `uc_hook_add`'s `user_data`
  pointing at a heap-allocated context that owns the callback and a back-pointer to
  the `Qiling`. One trampoline per UC hook signature, not per callback.
- **No exceptions may cross into Unicorn C frames.** The trampoline catches every
  `QlError` subclass, records it on the Qiling instance (the Python
  `ql.internal_exception` mechanism, `qiling/core.py:373`), and returns so Unicorn
  stops cleanly; `emu_start` re-raises on exit. This is a hard rule — a C++ exception
  unwinding into Unicorn's `uc_emu_start` is undefined behavior.
- **Hook lifetime**: Python relies on GC and `remove_*_hook`; C++ introduces RAII
  hook handles (destroying the handle unregisters). Audit every `hook_*` call site
  (`ARCHITECTURE/core.md` hook inventory) to pin ownership.

Exit criteria for the slice are in Phase 2; this decision lands there.

### 5.2 Dynamic dispatch → static registration

Three Python-dynamic mechanisms need explicit C++ replacements:

- **Component resolution** (`qiling/utils.py`): QL_ARCH/QL_OS → class name → `getattr`
  construction. Replace with static factory functions and a single `resolve*` table
  per enum (same single-point-of-resolution invariant as `utils.py`).
- **API/syscall registration**: Windows DLL emulation registers handlers by name via
  decorators (`qiling/os/windows/fncc.py`, the `api.py` method set); POSIX syscalls
  dispatch through `map_syscall.py` name tables. Replace with per-OS static
  registration tables (`std::unordered_map<std::string_view, Handler>` built at
  startup, or `constexpr` arrays where the set is closed). The lookup key, the
  calling-convention wrapper (`QlFunctionCall`, `qiling/os/fcall.py:21`), and the
  "not implemented" degradation path must behave identically to Python — including
  which unimplemented entries raise `QlErrorNotImplemented` versus log-and-continue.
- **Duck-typed component contracts**: `QlOs`, `QlLoader`, `QlArch` are ABCs in Python
  and duck-typed in call sites. In C++ they become abstract bases with pure virtuals;
  call sites that relied on duck typing must be tightened (this is mechanical but
  touches everything — budget for it inside each OS phase, not as a separate pass).

### 5.3 Multithread emulation: gevent greenlets → stackful fibers

`qiling/os/thread.py` builds `QlThread` on `gevent.Greenlet`; emulated guest threads
(cooperative, one Unicorn instance, switched on blocking syscalls) are scheduled as
greenlets. This is the highest-design-risk subsystem:

- Options considered: OS threads with one Unicorn per thread (rejected: Unicorn
  instances are heavyweight and per-thread state sharing breaks `QlOs` assumptions),
  stackless coroutines (rejected: cannot cross the Unicorn C stack), **stackful
  fibers** (selected).
- Decision: a small `Fiber` abstraction — **ucontext on POSIX, Windows fibers
  (`CreateFiber`) on Windows** — plus a cooperative scheduler mirroring
  `QlThread`/`QlLinuxThread`/`QlWindowsThread` switch semantics. No new third-party
  dependency (boost-context is the fallback if ucontext hits a platform gap).
- Audit first (Phase 4): enumerate every greenlet yield site and every blocking
  syscall that triggers a switch; the fiber switch points must be a strict superset.

### 5.4 Exception discipline

Python raises `QlError*` (`qiling/exception.py`) from deep inside syscall handlers
and catches at the emulation boundary. C++ ports the hierarchy verbatim (`QlError`
base + `QlErrorFileNotFound`, `QlErrorArch`, `QlErrorOsType`, `QlErrorNotImplemented`,
`QlErrorMemoryAccess`, ...). Rules, enforced in review:

- Exceptions may be thrown from syscall/API handlers and hook callbacks, but must be
  caught by the hook trampoline (5.1) or at the `os.run()` boundary — never across a
  Unicorn C frame (see 5.1) and never across a fiber switch (5.3): a fiber must not
  unwind while suspended. Any error that must cross a switch is re-thrown by the
  scheduler, mirroring how gevent propagates greenlet exceptions.
- `try/finally` patterns → RAII guards; file descriptors and mapped regions released
  by destructor.

### 5.5 GC lifetimes → explicit ownership

The Python object graph is a tree rooted at `Qiling` (`qiling/core.py:204-244`
accessors: `mem`, `hw`, `arch`, `loader`, `os`, `log`, `host`), so this is easier
than the ilspy case:

- `Qiling` owns components via `std::unique_ptr` in the documented init order.
- Non-owning back-references (`ql` pointers inside OS/DLL classes) are raw
  `Qiling&`/`Qiling*` — the owner outlives them by construction.
- Hook contexts and `QlFsMappedObject` handles (`qiling/os/mapper.py:25`) are the
  two heap-shared cases: `shared_ptr`/`weak_ptr` where a guest handle can outlive
  its creator, documented per site.
- `weakref` uses (fd cache, kernel-proxy objects) → `std::weak_ptr`.

### 5.6 Strings, paths, and the host boundary

Guest path encodings differ per OS (POSIX: raw bytes; Windows: A/W API variants) but
internal handling is byte-oriented already. Decision: **`std::string` for guest
paths/bytes, `std::filesystem::path` only at the host boundary** (mapper, profile
loading, rootfs). The `QlFsMapper` containment checks (rootfs prefix enforcement)
are the review-listed host-boundary risk (`CLAUDE.md` security deviations): the C++
port re-derives them against `std::filesystem` semantics (`lexically_normal`,
`lexically_relative`) and adds dedicated traversal tests — symlinks, `..`,
drive-letter and UNC edge cases — as part of Phase 3/4 exit criteria.

### 5.7 Constant tables — reuse, don't port

`qiling/arch/*_const.py` (1,344 lines: `x86_const`, `arm_const`, ...) mirror
Capstone's own generated headers (`<capstone/x86_const.h>`, ...). Decision: **use the
Capstone headers directly** and keep only the mapping glue (`qiling/arch/utils.py`).
The `qiling/hw/const/` peripheral register tables (4,961 lines) have no upstream
equivalent and are ported by hand — mechanical, low-risk, table-shaped.

### 5.8 pefile / pyelftools → pe-parse / ELFIO

- **PE**: `qiling/loader/pe.py` uses `pefile` for headers, imports, exports,
  relocations — exactly `pe-parse`'s surface (MIT, vcpkg). Adopt `pe-parse`; keep a
  thin `loader/PeParser` wrapper so loader code stays dependency-agnostic.
- **ELF**: `qiling/loader/elf.py` and `loader/mcu.py` use `pyelftools` for
  segments/sections/symbols/dynamics. Adopt **ELFIO** (header-only C++, Boost
  license, vcpkg port) as the reader baseline; program-header mapping stays in our
  loader code.
- **Mach-O**: `qiling/loader/macho_parser/` (1,106 lines) is already hand-written
  pure Python — port it directly when the macOS path resumes; no new dependency.
  Deferred with the macOS subsystem (Sub-scoping).
- Note: unlike `pefile`/`pyelftools`, neither replacement is "the mature reader
  under a thin surface" — they *are* the mature reader. This is a strict downgrade
  in port risk vs the ilspy situation.

### 5.9 python-registry (Windows registry hive parsing)

`qiling/os/windows/registry.py:9` imports the `Registry` package to parse real
NT hive files collected from a host Windows install (seeding the emulated registry;
writes go to `config.json`). C++ has no equivalent on vcpkg. Decision: **the
`config.json` path becomes primary** (`nlohmann-json`); hive ingestion is deferred
behind an optional feature and, if restored, a minimal hand-written hive reader
(documented format) — see open question 3.

### 5.10 Profiles and config

- `.ql` profiles (`qiling/profiles/*.ql`) are INI (`configparser`) files with a small
  used feature set. Decision: a tiny in-tree INI reader (no `plog`-style dependency;
  `iniconfig`-sized). Audit whether `configparser` interpolation is used anywhere
  (open question 10); if not, the reader is trivial.
- MCU board config is YAML (`qiling/utils.py:420-426`) — **deferred** with the MCU
  subsystem; when it resumes, the choice is **yaml-cpp** (vcpkg, MIT).
- `config.json` registry store and `extensions/report` JSON: **nlohmann-json**.

### 5.11 Logging, regex, CLI

- **Logging**: `qiling/log.py` (levels, per-name filters, output devices, colored
  console) → **spdlog** (vcpkg): leveled named loggers, pattern formatting, sink
  collection map 1:1 onto the Python surface.
- **Regex** (`log.py` filter, `utils.py`): simple patterns → `std::regex`; no regex
  library added.
- **CLI**: `qltool`/`qiling/cli.py` (`run`/`code` subcommands, ~20 flat options) →
  **cxxopts** (vcpkg), consistent with the CLI-parsing decision used by the
  comparable decompiler port. `qltui.py` is out of scope (1).
- **Threads**: host-side threads (GDB server, stats) → `std::thread` + `std::atomic`;
  nothing exotic. Guest threads are fibers (5.3).

### 5.12 Dropped Python-only surface

- `qiling/extensions/idaplugin/` — dropped (GUI host).
- `qltui.py` — dropped for now; a `qltui` C++ port would need a TUI library decision
  and is not on the core path.
- `pickle` in `qiling/core.py` (snapshot serialization) — replaced by an explicit
  versioned binary format over the same save/restore surface (`ql.save`, `ql.restore`);
  no cross-compatibility with Python pickle snapshots (open question 9).

---

## 6. Third-party library reconciliation

| Need | Python source | C++ choice | Notes |
|---|---|---|---|
| CPU emulator | `unicorn == 2.1.3` (ctypes) | **unicorn C**, direct linkage | keep the hard pin; delete the binding layer |
| Disassembly | `capstone ^5` (ctypes) | **capstone C** + its generated `*_const.h` headers | replaces `qiling/arch/*_const.py` (5.7) |
| Assembly | `keystone-engine ^0.9.2` (ctypes) | **keystone C**, direct linkage | |
| PE parsing | `pefile` | **pe-parse** (vcpkg, MIT) | thin in-tree wrapper (5.8) |
| ELF parsing | `pyelftools` | **ELFIO** (vcpkg, Boost license, header-only) | program-header mapping stays ours (5.8) |
| Mach-O parsing | in-tree `macho_parser/` | **deferred** (port as-is when resumed) | already dependency-free |
| Registry hives | `python-registry` | **deferred**; `config.json` primary; minimal hand-written reader if restored | 5.9 |
| Guest threads | `gevent` | **fibers**: ucontext (POSIX) / Windows fibers | no new dep; 5.3 |
| Host threads | `threading` | `std::thread` | |
| YAML (MCU config) | `pyyaml` | **deferred**; yaml-cpp (vcpkg) when MCU resumes | 5.10 |
| JSON | stdlib `json` | **nlohmann-json** (vcpkg) | registry store, report |
| Logging | stdlib `logging` | **spdlog** (vcpkg) | 5.11 |
| INI profiles | `configparser` | tiny in-tree reader | audit interpolation first (OQ 8) |
| CLI parsing | `argparse` | **cxxopts** (vcpkg) | 5.11 |
| Regex | `re` | `std::regex` | no new dep |
| Tests | `unittest` | **Google Test** (vcpkg) | 11 |

Net vcpkg dependencies: `pe-parse`, `elfio`, `nlohmann-json`, `spdlog`, `cxxopts`,
`gtest` (+ optional `unicornafl`, `r2libr` behind features; `yaml-cpp` returns with
the deferred MCU path). All are permissive-licensed and GPL-2.0-or-later compatible.
`gevent`, `pyelftools`, `pefile`, `python-registry`, `pyyaml` (as a Python pkg) and
the ctypes layer all drop out.

---

## 7. C++ directory layout under `cpp/`

Mirror rules live in `MIRROR_LAYOUT_REORGANIZATION.md` (file basename matching,
namespace mapping, status legend, and the fully enumerated final tree). Summary:

1. **File basename matching**: Python `foo.py` → C++ `foo.hpp` + `foo.cpp` with the
   identical basename (`qiling/core.py` → `cpp/qiling/core.hpp/.cpp`).
2. **Namespace = directory**: `qiling/os/posix/syscall` → `namespace qiling::os::posix::syscall`
   under `cpp/qiling/os/posix/syscall/`.
3. **Directory structure exactly mirrors** the Python package; `_const.py` modules
   dissolve into the capstone-header reuse (5.7) or stay as headers when they carry
   real tables (`hw/const/`).
4. **Class names carry over verbatim** (`QlMemoryManager`, `QlFsMapper`, `QlThread`,
   `Qdb`), so grepping either tree finds the counterpart.
5. **Python-specific constructs**:
   - `abc`/`abstractmethod` → abstract base classes with pure virtuals
   - `typing.Protocol` (hook callback shapes, `qiling/core_hooks.py:55-137`) →
     `std::function` type aliases with the same parameter order
   - properties → getters; `cached_property` → lazy-initialized members
   - decorators (API registration) → registration tables (5.2)
   - `*args/**kwargs` → option structs / overloads
   - `enum.Enum` → `enum class`
   - `with`-blocks → RAII
6. **C++-only files** (trampolines, fibers, INI reader) are documented with a note
   and placed next to their consumers.

Proposed root:

```
cpp/
  CMakeLists.txt                 # top-level; adds qiling/, qltool/, tests/
  vcpkg.json                     # manifest: pe-parse, elfio, yaml-cpp, nlohmann-json, spdlog, cxxopts, gtest
  README                         # conventions (ownership, exceptions, fibers, encoding)
  qiling/
    core.hpp/.cpp  core_hooks.hpp/.cpp  core_hooks_types.hpp  core_struct.hpp/.cpp
    utils.hpp/.cpp  const.hpp  exception.hpp/.cpp  host.hpp/.cpp  log.hpp/.cpp
    arch/        # QlArch per-arch classes; capstone headers via CMake include
    cc/
    loader/
    os/
      os.hpp/.cpp  const.hpp  memory  fcall  mapper  path  struct  thread  filestruct
      utils  stats
      blob/ posix/ (incl. syscall/ + abi/ + kernel_proxy/) linux/ windows/ (incl. dlls/)
      (disk.py parks with DOS; freebsd/ qnx/ macos/ uefi/ dos/ mcu/ deferred)
    hw/           # + const/
    debugger/
      gdb/ qdb/
    extensions/
      coverage/ tracing/ sanitizers/ report/   # afl/ r2/ behind build features
      (mcu/ deferred with the bare-metal path)
    profiles/     # windows.ql + linux.ql copied verbatim (the other five defer with
                  # their OSes)
  qltool/         # main.cpp — the CLI
  tests/          # gtest; mirrors tests/test_*.py (11)
```

Status legend for every file as it lands: **Ported** (exists, matches the Python
source), **Audit** (exists, needs review), **NEW** (planned per this plan),
**C++-only** (no Python counterpart; trampolines, fibers, INI reader).

---

## 8. Build system

CMake ≥ 3.15, C++17, vcpkg toolchain (same toolchain baseline as the comparable
decompiler port for cross-project consistency). Three targets:

- `qiling` — the core static library (`qiling.lib` / `libqiling.a`), aggregating
  everything under `cpp/qiling/` except `cli`.
- `qltool` — the CLI executable, linking `qiling` + cxxopts.
- `qiling_tests` — the gtest executable.

```cmake
cmake_minimum_required(VERSION 3.15)
project(qiling VERSION 1.4.11 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# vcpkg manifest mode; deps declared in vcpkg.json
find_package(pe-parse CONFIG REQUIRED)
find_package(ELFIO CONFIG REQUIRED)
# yaml-cpp returns when the deferred MCU path resumes
# find_package(yaml-cpp CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(cxxopts CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)
# unicorn/capstone/keystone: vcpkg ports, direct linkage, unicorn pinned to 2.1.3
find_package(unicorn CONFIG REQUIRED)
find_package(capstone CONFIG REQUIRED)
find_package(keystone CONFIG REQUIRED)

add_subdirectory(qiling)
add_subdirectory(qltool)
add_subdirectory(tests)

add_executable(qltool ...)            # links qiling
add_executable(qiling_tests ...)      # links qiling GTest::gtest
enable_testing()
add_test(NAME qiling_tests COMMAND qiling_tests)
```

Warnings: `-Wall -Wextra` (GCC/Clang) and `/W4` (MSVC); **no `-Werror` initially** —
the Python code has no analogue to port and 100k lines of fresh C++ will emit noise
worth triaging before it is promoted to errors. Revisit for `qiling` after Phase 8.

Platforms: Windows and Linux (the Python project's CI matrix); GCC 9+/Clang 10+
and MSVC 2019/2022.

---

## 9. Conventions: Python → C++ mapping

| Python | C++ | Notes |
|---|---|---|
| `namespace`/package layout | directory-mirrored namespaces | rule 2 above |
| `Qiling` class | `qiling::Qiling` | composition root, init order preserved |
| mixins (`Qiling(QlCoreHooks, QlCoreStructs)`) | C++ mixin inheritance | same shape, `public` inheritance |
| ABC / `@abstractmethod` | pure virtual + `override` | |
| properties | `const T& GetX()` / `void SetX(T)` | |
| `typing.Optional[X]` | `std::optional<T>`; raw `T*` only where documented | |
| `dict` dispatch | `std::unordered_map` over string_view keys | 5.2 |
| list/set comprehensions | STL algorithms / range-for | |
| f-strings | `fmt::format` (bundled with spdlog) | |
| `pathlib` | `std::filesystem` (host boundary only) | 5.6 |
| `enum.Enum` | `enum class` | |
| exceptions | ported `QlError*` hierarchy | 5.4 |
| `with` / context managers | RAII | |
| `functools.cached_property` | lazy member + `std::once_flag` | |
| `pickle` (snapshots) | explicit versioned binary format | 5.12 |
| callbacks/closures into Unicorn | C trampolines + `std::function` payloads | 5.1 |
| gevent `Greenlet` | `Fiber` (ucontext / Windows fibers) | 5.3 |
| `weakref` | `std::weak_ptr` | 5.5 |
| duck typing | concrete types behind interfaces | tightened call sites |

---

## 10. Porting phases

Each phase has: scope, dependency, deliverable, exit criteria, and tests. The TDD
rule from `CLAUDE.md` applies: survey the suite before writing tests, write the
failing test, show red, implement, show green. Never skip red.

### Phase 0 — Scaffolding and primitives

Scope: `cpp/` skeleton, CMake/vcpkg, `QlError*` hierarchy (5.4), `QL_ARCH`/`QL_OS`/
`QL_ENDIAN`/`QL_STATE`/`QL_VERBOSE`/`QL_STOP` enums (`const.hpp`), logging via spdlog
with the `qiling/log.py` surface (named loggers, level filter, regex filter), JSON
(nlohmann), tiny INI reader for `.ql` profiles, string/path helpers, the
conventions README (9).

Dependency: none.

Deliverable: `qiling` / `qltool` / `qiling_tests` targets build; primitives tested.

Exit criteria: builds on MSVC and GCC/Clang; `qiling_tests` runs and the Util/Log/
Exception suites pass; a `.ql` profile parses to the same key/value structure the
Python `configparser` yields.

Tests: `tests/Util_Test.cpp`, `tests/Log_Test.cpp`, `tests/Profile_Test.cpp`.

### Phase 1 — Arch layer (foundation)

Scope: `qiling/arch/` minus the const modules (replaced by capstone headers — 5.7):
`QlArch` base and per-arch classes (x86, x8664, ARM, ARM64, MIPS, RISC-V 32/64,
PowerPC, Cortex-M, 8086), `register.py` (`QlRegisterAccessor`), `models.py` (CPU
models, `QL_CPU`), per-arch disassembly helpers, `qiling/cc/` (`QlCC` calling
conventions). Unicorn/Capstone/Keystone direct linkage with the 2.1.3 pin.

Dependency: Phase 0.

Deliverable: per-arch `uc_open` bring-up, register maps, get/set through
`ql.arch.regs`, capstone disassembly and keystone assembly behind
`QlArchUtils`-equivalent helpers.

Exit criteria: for x86 and x86-64 (the PE/ELF initial path), a gtest initializes the
CPU, sets/reads registers, disassembles and assembles a fixed instruction corpus
with byte-identical results to the Python layer's output on the same input; the
remaining arch classes build with smoke-level bring-up tests (full per-arch parity
lands with Phase 5 and the deferred bare-metal path).

Tests: `tests/Arch_*_Test.cpp` (one per arch) + `tests/Cc_Test.cpp`.

### Phase 2 — Core services (hook engine, memory, fcall)

Scope: `core_hooks.py`/`core_hooks_types.py` (the trampoline engine — 5.1),
`core_struct.py` (`QlCoreStructs`), `os/memory.py` (`QlMemoryManager`, `QlMemoryHeap`,
MMIO handler plumbing), `os/fcall.py` (`QlFunctionCall` per-convention marshalling),
`host.py` (`QlHost`), `exception.py` integration, snapshot save/restore of memory +
registers (`core.py:609` surface, explicit binary format — 5.12).

Dependency: Phase 1.

Deliverable: every UC hook type fires through the trampoline with correct
`user_data` context and no exception leakage; memory map/unmap/protect round-trips;
fcall marshals arguments/returns per arch convention; mem+reg snapshot round-trips.

Exit criteria:
- A gtest hooks every hook type simultaneously on a synthetic blob and observes
  correct dispatch order and data.
- An exception thrown inside a hook is recorded as `internal_exception` and re-raised
  by `emu_start` — never unwinding into Unicorn.
- Memory-string/struct helpers (`QlCoreStructs`) round-trip against the Python
  behaviour on a fixture corpus.
- Save/restore produces a byte-identical resumable state.

Tests: `tests/CoreHooks_Test.cpp`, `tests/Memory_Test.cpp`, `tests/Fcall_Test.cpp`,
`tests/Struct_Test.cpp`, `tests/Snapshot_Test.cpp`. The hook-engine suite is the
heaviest investment of this phase.

### Phase 3 — Qiling facade and PE loader

Scope: `core.py` (composition root, `run()`/`emu_start`, exit trap, patching),
`utils.py` (static factories replacing `getattr` resolution — 5.2), the PE path of
`loader/` (`loader.py` base, `pe.py` over pe-parse), the minimal `blob.py` loader +
`os/blob/` glue (the shellcode test vehicle — no format to parse), `os/mapper.py`
(`QlFsMapper` + containment) and `os/path.py` (`QlOsPath`) with the traversal test
pass (5.6). ELF is Phase 5.

Dependency: Phase 2.

Deliverable: `Qiling(**argv)` assembles the full object graph; PE images map with
sections/imports resolved; the mapper enforces rootfs containment; raw blobs run.

Exit criteria:
- A raw shellcode blob and a PE fixture both run to completion through the real
  facade; PE section addresses, import resolution, and entry points match the
  Python loader's output for the same file.
- Malformed binaries (truncated headers, bogus offsets) raise `QlError*` or log a
  warning — never a host crash (robustness tenet).
- Path-traversal tests (symlink, `..`, absolute-guest-path escapes) all contained.

Tests: `tests/Loader_Pe_Test.cpp`, `tests/FsMapper_Test.cpp`, `tests/Path_Test.cpp`,
plus a malformed-input robustness suite.

### Phase 4 — Windows (first full stack)

Scope: `os/windows/` — `windows.py` (`QlWindows`), `api.py`/`fncc.py` (the
registration-table engine from 5.2), `handle.py`, `thread.py`, `fiber.py`,
`registry.py` (config.json primary — 5.9), `structs.py`, `utils.py`, and the
`dlls/` tree (kernel32, ntdll, user32, advapi32, msvcrt, + the rest). The fiber
scheduler (5.3) lands here with the guest-thread support — the switch-point audit
(OQ 1) closes on the Windows thread paths.

Dependency: Phase 3.

Deliverable: a Windows PE fixture runs end-to-end with emulated DLL imports
resolved and API handlers dispatching by name.

Exit criteria: `tests/test_pe.py`/`test_windows_cpp_*.py` behaviour reproduces under
gtest on Windows hosts (the DLL-collection fixture constraint carries over —
`ARCHITECTURE/os-windows.md`); registry config.json round-trips; unimplemented
APIs follow the Python stub semantics; a multithreaded Windows fixture runs to
completion with fibers.

Tests: `tests/Windows_Api_Test.cpp`, `tests/Windows_Dlls_Test.cpp` (per-DLL case
groups), `tests/Windows_Registry_Test.cpp`, `tests/Windows_Fiber_Test.cpp`.

### Phase 5 — ELF loader + POSIX/Linux (second full stack)

Scope: the ELF path of `loader/` (`elf.py` over ELFIO; the `.ko` ET_REL driver branch
inside it is deferred with the kernel-module paths) and the POSIX/Linux OS layers:
the `os/os.py` pieces not already landed with Windows in Phase 4, `os/posix/`
(`posix.py`, the root support modules `const.py`/`const_mapping.py`/
`filestruct.py`/`structs.py`/`stat.py`/`msq.py`/`shm.py`, `kernel_proxy/` — the
host-kernel syscall proxy exercised by `tests/test_kernel_proxy.py` — and
`syscall/` per module — `unistd`, `mman`, `socket`, `futex`, `signal`, ... — and
`abi/`), `os/linux/` (`linux.py`, `syscall.py`, `map_syscall.py`, `kernel_api/`,
`procfs.py`, `thread.py`, `futex.py`), `os/filestruct.py`, `os/utils.py`,
`os/stats.py`. `os/freebsd/` is deferred (parked on the POSIX base).

Dependency: Phase 4 (shares the core, mapper, and OS-base patterns; the POSIX
syscall modules themselves only need Phase 3 + fcall, so slices can start early).

Deliverable: a Linux ELF userspace binary from `examples/rootfs/` runs end-to-end
through `qiling_tests`/`qltool`: syscalls dispatch, stdout/file output matches,
blocking syscalls yield fibers.

Exit criteria:
- The Python suite's Linux fixtures (`tests/test_elf.py`, `test_posix.py`) reproduce
  under gtest with matching observable output.
- A multithreaded Linux fixture (`tests/test_elf_multithread.py` behaviour) runs to
  completion with fibers.
- Unimplemented syscalls degrade per the per-OS convention (log + errno, or
  `QlErrorNotImplemented` where Python does), never crash.

Tests: `tests/Loader_Elf_Test.cpp`, `tests/Posix_Syscall_Test.cpp` (one case group
per syscall module), `tests/Linux_Test.cpp`, `tests/Multithread_Test.cpp`.

### Phase 6 — Debugger and extensions

Scope: `debugger/gdb/` (GDB remote-serial protocol server: `gdb.py`, `utils.py`,
and `xmlregs.py` — the target-descriptor XML the client consumes) and
`debugger/qdb/` (Qdb command set, `.qdb` script execution, reverse debugging —
including its per-arch subpackages `arch/`, `branch_predictor/`, `render/`);
`extensions/coverage` (the `formats/` writers: drcov, drcov_exact, ezcov, history),
`tracing` (`formats/`: registers, tenet), `sanitizers`, `report` (pure JSON, no new
dep); `extensions/afl` (unicornafl C API) and `r2` (r2libr) behind optional build
features.

Dependency: Phase 4 for the debugger (Windows debugging is the first exercise);
the extensions as their subjects land (coverage needs Phase 2 hooks, AFL needs
Phase 3).

Deliverable: a GDB client attaches, breaks, steps, reads registers/memory on a PE
and an ELF target; a `.qdb` script executes (`tests/qdb_scripts/` fixtures run
as-is — they are plain text); coverage/tracing produce the same artifacts
(DRCOV-format outputs etc.) as the Python layer on a fixture.

Exit criteria: the gdb fixtures from `tests/test_debugger.py` behaviour reproduce;
the six `.qdb` scripts in `tests/qdb_scripts/` run against their target binaries;
a `test_r2.py`-equivalent smoke passes when the `RE` feature is enabled; an AFL
smoke run feeds a mutated input through `uc` in persistent mode.

Tests: `tests/Gdb_Server_Test.cpp`, `tests/Qdb_Test.cpp`,
`tests/Ext_Coverage_Test.cpp`, `tests/Ext_Tracing_Test.cpp`,
`tests/Ext_Afl_Test.cpp` (feature-gated), `tests/Ext_Sanitizers_Test.cpp`.

### Phase 7 — qltool CLI

Scope: `cli.py` (`run`/`code` subcommands, option set) ported to cxxopts into
`qltool/main.cpp`; profile loading; log configuration flags.

Dependency: Phases 3-5 as exercised.

Deliverable: `qltool run <args>` executes rootfs binaries with the same CLI surface
(argv, env, rootfs, arch/ostype overrides, debugger attachment, verbose levels).

Exit criteria: CLI round-trip parity — the same invocation string produces the same
emulated behaviour as the Python `qltool` for a PE + ELF fixture matrix.

Tests: `tests/Cli_Test.cpp` (option parsing, exit codes, end-to-end runs).

### Phase 8 — Integration, fixtures, and hardening

Scope: cross-phase parity harness over the `examples/rootfs` corpus (Python-vs-C++
syscall trace / output diffing), **performance baselines** (a C++ port that is not
at least Python-parity on the fixture corpus is a finding; record per-fixture
timings in CI), CI on Windows + Linux mirroring
`.github/workflows/build-ci.yml`, `-Werror` consideration, snapshot format freeze,
robustness fuzz pass on the loader parsers (host boundary), documentation updates
(`ARCHITECTURE/*.md` gains a C++ note per module), `cpp/STATUS.md` completion.

Deliverable: CI green on both platforms; parity within agreed tolerance across the
fixture corpus; a documented delta list of intentional Python-vs-C++ differences.

Exit criteria: the fixture corpus emulates with the same success rate as the Python
framework; no gratuitous behavioural differences; `qltool` usable as a drop-in for
the common workflows.

### Deferred subsystems (resume criteria: OQ 9)

Not ported under the current PE/ELF priority; each slots back into the phase map
without disturbing Phases 0-8:

| Subsystem | Python lines | Slots in as | Depends on |
|---|---:|---|---|
| `os/freebsd/` | ~783 | a thin dialect phase after 5 | Phase 5 (POSIX base) |
| `os/qnx/` | ~1,303 | a thin dialect phase after 5 | Phase 5 (POSIX base) |
| `os/uefi/` + `loader/pe_uefi.py` | ~13,300 | a service-table phase after 4 | Phase 3/4 (PE path) |
| `os/dos/` (+ `os/disk.py`, its only consumer) | ~1,500 | an interrupt phase after 4 | Phase 3 (COM/MBR loader) |
| `os/macos/` + `loader/macho_parser/` | ~9,400 | a Mach-O phase (loader + OS) | the Phase 3 pattern |
| `qiling/hw/` + `os/mcu/` + `extensions/mcu/` | ~23,500 | the bare-metal phase | Phases 1-3 (blob path) |
| kernel modules (`.ko`, `.kext`, `.sys`) | (branches, not files: `.ko` is the ET_REL branch of `elf.py`, `.kext` of `macho.py`, `.sys` rides `pe.py` + `ntoskrnl.exe` emulation) | after their host OS phase | Phase 4/5 |

---

## 11. Test strategy

- **Framework**: gtest. Test files mirror the flat `tests/test_*.py` inventory 1:1
  (`tests/test_elf.py` → `cpp/tests/Loader_Elf_Test.cpp` grouping noted in each file
  header), so the suite inventory maps without diffing trees.
- **TDD**: every new behaviour gets a failing test first (per `CLAUDE.md`). The
  survey rule applies doubly here: inventory `tests/` (34 `test_*.py` files) per phase
  before porting any test.
- **Fixtures**: `examples/rootfs/` is reused as the input-fixture submodule,
  unchanged. The Windows PE tests keep the real-DLL collection constraint
  (`tests/test_pe.bat`, `examples/scripts/` collectors) and remain host-gated.
- **Parity harness**: for each fixture, capture the Python framework's observable
  behaviour (exit code, stdout/stderr, syscall trace summary) once, and diff the C++
  run against it. Byte-exact parity is the goal for deterministic fixtures; define a
  tolerance for ASLR/timing-dependent ones.
- **No silent passes**: when an expected component is missing, `FAIL()` (per
  `CLAUDE.md`); never `return` early to bypass an assertion.
- **Robustness tests**: malformed binaries must degrade to `QlError*`/warnings,
  never host crashes — dedicated suites for the loader parsers (5.6, 10 Phase 3).
- **Invariant sweeps**: the hook-engine exception rule (5.1) and fiber switch-point
  audit (5.3) are enforced by tests that run the full hook matrix and the multithread
  fixtures in every debug build.

---

## 12. Effort and sequencing summary

Indicative sizes (Python lines to port) per phase:

| Phase | Subsystem | Python lines (approx) | Risk |
|---|---|---:|---|
| 0 | Scaffolding/util/exceptions/logging | ~1,500 | low |
| 1 | Arch layer + cc (const reuse cuts ~1.3k; x86/x86-64 exercised) | ~2,600 | low-medium |
| 2 | Core services (memory, hooks, fcall) | ~3,000 | medium-high (hook engine) |
| 3 | Facade + PE loader + fs mapper (+BLOB glue) | ~3,300 | medium (trust boundary) |
| 4 | Windows (APIs, DLLs, registry, fibers) | ~14,400 | **high** (breadth + dispatch engine) |
| 5 | ELF loader + POSIX base + Linux (+fibers) | ~16,500 | **high** (breadth + fibers) |
| 6 | Debugger + extensions (gdb, qdb, coverage, AFL, ...) | ~6,100 | medium |
| 7 | qltool CLI | ~300 (new) | low |
| 8 | Integration/hardening | n/a | medium |

Initial-path total ≈ 47,700 of the ~97,900-line mirror; the remaining ~50,200 lines
(freebsd/qnx/macos/uefi/dos/hw/MCU + the Mach-O parser) are deferred per Sub-scoping
and re-enter through the deferred-subsystems table in 10.

Sequencing notes:
- Phases 4 and 5 dominate the schedule; Phase 4 additionally carries the fiber
  redesign (5.3), the single highest-design-risk item — it must be green before
  Phase 5 reuses the scheduler for Linux guest threads.
- Phase 6 decomposes into small, independently testable pieces (gdb server, per-
  extension suites) — good for parallelisation once Phase 4 is green.
- Phase 2's hook engine gates everything above it; do not let Phases 3+ start on a
  provisional trampoline design.

---

## 13. Status tracking

Use the status legend from 7 on every file as it lands: `Ported`, `Audit`, `NEW`,
`C++-only`. Maintain a `cpp/STATUS.md` (all `NEW` initially) listing each mirrored
file and its status, so progress is visible without diffing trees. The deferred
subsystems (`os/freebsd`, `os/qnx`, `os/macos`, `os/uefi`, `os/dos`, `qiling/hw/`,
`qiling/extensions/mcu/`) are tracked in a separate `Deferred` section of
`cpp/STATUS.md` so their eventual resumption stays visible without polluting the
active port inventory.

---

## 14. Open questions / audits needed before/during port

1. **gevent switch-point audit** (before Phase 4): enumerate every greenlet yield
   site (`QlThread` subclasses, blocking-syscall paths) to confirm the fiber
   scheduler's switch points are a strict superset.
2. **capstone const audit** (Phase 1): verify `qiling/arch/*_const.py` maps 1:1 onto
   the Capstone 5 generated headers (register/insn/group constants) with no Qiling
   extensions lost.
3. **python-registry audit** (Phase 4): confirm exactly which hive structures
   `windows/registry.py` reads, and whether deferring hive ingestion (config.json
   primary) loses any test-reachable behaviour.
4. **Hook-callback exception audit** (Phase 2): walk every `uc_hook_add` site in
   `core_hooks.py` and confirm no Python exception can cross into Unicorn C today;
   the C++ trampoline contract must cover each case found.
5. **Windows PE fixture strategy** (Phase 4): the DLL-collector scripts must run on
   a Windows host to build fixtures; decide the CI recipe (cached fixture artifact
   vs on-host collection).
6. **unicornafl / r2libr C-API stability** (Phase 6): pin versions and confirm the
   C APIs behind the optional features are stable across the vcpkg ports.
7. **Snapshot format** (Phase 2): define the versioned binary format (header, section
   table, component blocks) so save/restore survives additive component growth;
   no Python-pickle compatibility.
8. **configparser interpolation audit** (Phase 0): confirm the `.ql` profiles use
    no `configparser` interpolation/features, sizing the INI reader.
9. **Deferred-subsystem resume criteria**: for each parked subsystem (Sub-scoping
   in 1), record what a future port needs (loader additions, OS-layer surface,
   fixtures) so it slots back into the phase map of 10 without re-planning.

---

## 15. Decision log (to be maintained during the port)

A running record of the choices made against this plan, with rationale. Seed entries:

| # | Decision | Date | Rationale |
|---|---|---|---|
| D1 | C++17, CMake ≥ 3.15, vcpkg toolchain; Windows + Linux targets | plan | same toolchain baseline as the comparable decompiler port for cross-project consistency |
| D2 | Link unicorn/capstone/keystone directly; keep the `unicorn == 2.1.3` hard pin | plan | the ctypes layer is deleted, not ported; the pin is a project-wide event |
| D3 | Reuse Capstone's generated `*_const.h` headers instead of porting `qiling/arch/*_const.py` | plan | the Python const modules mirror those headers 1:1 (audit: OQ 2) |
| D4 | pe-parse for PE, ELFIO for ELF; Mach-O deferred (port the in-tree parser when macOS resumes) | plan | both replacements are the mature readers themselves; Mach-O is already hand-written in-tree |
| D5 | gevent greenlets → stackful fibers (ucontext on POSIX, Windows fibers on Windows); no new dependency | plan | preserves the cooperative one-uc-instance model; boost-context is the fallback (5.3) |
| D6 | Exceptions ported as a C++ `QlError*` hierarchy; no exceptions across Unicorn C frames or fiber switches | plan | UB otherwise; the `internal_exception` mechanism is the re-entry path (5.4) |
| D7 | spdlog for logging; nlohmann-json for JSON; cxxopts for CLI; yaml-cpp only when the MCU path resumes | plan | closest 1:1 to the Python surfaces (5.10, 5.11) |
| D8 | Tiny in-tree INI reader for `.ql` profiles (no dependency) | plan | profiles use a minimal feature set, pending the interpolation audit (OQ 8) |
| D9 | Drop `extensions/idaplugin`, `qltui.py`, Dockerfile; defer the bare-metal path (`qiling/hw/`, `os/mcu/`, `extensions/mcu/`) with it | plan | GUI/hosts out of scope; the MCU database is load-bearing only for bare-metal (1) |
| D10 | Registry hive ingestion deferred; `config.json` primary | plan | no vcpkg equivalent for python-registry; the config path already covers the emulated-registry writes (5.9) |
| D11 | Dynamic dispatch → static factories/registration tables at the `utils.py`/`fncc.py`/`map_syscall.py` sites | plan | single-point-of-resolution invariant preserved, made static (5.2) |
| D12 | Tests ported as gtest suites mirroring the flat `tests/` inventory; rootfs reused unchanged | plan | suite inventory maps 1:1; fixtures are input-only (11) |
| D13 | `std::string` for guest bytes/paths; `std::filesystem` only at the host boundary, with a dedicated traversal test pass | plan | the mapper is the host trust boundary; C++ path semantics need explicit re-verification (5.6) |
| D14 | Format priority: Windows PE first, Linux ELF second; UEFI/DOS/Mach-O/FreeBSD/QNX/MCU and the kernel-module paths deferred | user | stated requirement; keeps the ~48k-line initial path small and the phases re-entrant (Sub-scoping in 1, deferred table in 10) |

Append rows as decisions are taken during implementation.
