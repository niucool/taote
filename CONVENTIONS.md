# qiling (C++ port)

C++17 port of the [Qiling Framework](https://github.com/qilingframework/qiling).
Source of truth for the plan: `PORT_PLAN.md` (what/order) and
`MIRROR_LAYOUT_REORGANIZATION.md` (mapping/layout); this tree tracks per-file
status in `STATUS.md`. The port root is the repository root (PORT_PLAN.md D16).

## Build

Requires CMake ≥ 3.15 and [vcpkg](https://vcpkg.io) (set `VCPKG_ROOT` or pass the
toolchain file). Dependencies come from the manifest (`vcpkg.json`): unicorn
(pinned 2.1.4, decision D15), capstone, keystone, pe-parse, ELFIO, spdlog,
nlohmann-json, cxxopts, Google Test.

```bash
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release

# run the test suite
./build/tests/Release/qiling_tests.exe        # Windows
./build/tests/qiling_tests                    # Linux
```

Targets: `qiling` (static library), `qltool` (CLI), `qiling_tests` (Google Test).
The suites reach the bundled `.ql` profiles via `QILING_SOURCE_DIR` (no install
step).

## Conventions

### Naming and mirror rules
- Python `foo.py` → `foo.hpp` + `foo.cpp` with the identical basename, under a
  mirrored directory; namespaces mirror Python packages
  (`qiling/os/posix/syscall` → `qiling::os::posix::syscall`).
- Class names carry over verbatim (`Qiling`, `QlMemoryManager`, `QlFsMapper`,
  `QlThread`, `Qdb`), so grepping either tree finds the counterpart. Enum types
  keep their Python names (`QL_ARCH`, `QL_OS`, ...); enumerators are unchanged.
- `__init__.py` dissolves into `qiling.hpp` aggregate headers; the CLI lands as
  `qltool/main.cpp` instead of a library module.
- Constant tables are not ported: Capstone's generated headers replace
  `qiling/arch/*_const.py` (decision D3) starting Phase 1.
- C++-only files (hook trampolines, fiber scheduler, INI reader) are documented
  and placed next to their consumers.

### Ownership (PORT_PLAN.md 5.5)
- `Qiling` owns its components (`arch`, `os`, `loader`, `mem`, `hw`) via
  `std::unique_ptr` in the documented init order (composition root, Phase 3).
- Non-owning back-references (`ql` pointers inside OS/DLL classes) are raw
  `Qiling&`/`Qiling*` — the owner outlives them by construction.
- Guest handles that can outlive their creator (hook contexts,
  `QlFsMappedObject`) use `shared_ptr`/`weak_ptr`, documented per site.
- `weakref` → `std::weak_ptr`.

### Exceptions (PORT_PLAN.md 5.4) — hard rules
- The `QlError*` hierarchy (ported in `qiling/exception.hpp`) is thrown from
  syscall/API handlers and hook callbacks.
- **No exception may cross a Unicorn C frame.** From Phase 2 on, every hook
  trampoline catches `QlError*`, records it on the Qiling instance (the
  `internal_exception` mechanism), and returns so Unicorn stops cleanly;
  `emu_start` re-raises on exit.
- **No exception may cross a fiber switch** (Phase 4): a fiber must not unwind
  while suspended; the scheduler re-throws across switches, mirroring gevent.
- `try/finally` patterns → RAII guards.

### Fibers (PORT_PLAN.md 5.3) — Phase 4
Guest threads are cooperative stackful fibers (ucontext on POSIX, Windows
fibers on Windows) under `os/fiber.*` — one Unicorn instance, switched on
blocking syscalls. Host threads (`std::thread`) are only for non-emu concerns
(GDB server, stats).

### Strings, paths, and the host boundary (PORT_PLAN.md 5.6)
- `std::string` for guest bytes/paths (POSIX paths are raw bytes; Windows
  A/W variants are byte-oriented internally).
- `std::filesystem` only at the host boundary (fs mapper, profile loading).
  The `QlFsMapper` containment checks are the host trust boundary and get a
  dedicated traversal test pass in Phase 3/4.

### Tests
- Google Test; test files mirror the Python `tests/` inventory (see
  `PORT_PLAN.md` §11). TDD rule: survey → failing test → red → implement →
  green; never skip red. No silent passes: missing components `FAIL()`, they
  never return early.

## Status

Per-file port status lives in [STATUS.md](STATUS.md) (`Ported` / `Audit` /
`NEW` / `C++-only`; deferred subsystems in a separate section).
