# taote

A C++ port of the [Qiling Framework](https://github.com/qilingframework/qiling) —
an advanced cross-platform, multi-architecture binary emulation framework.

**Status**: Phase 0 (scaffolding and primitives) in progress. The port lives at
the repository root (PORT_PLAN.md D16): `qiling/` (the framework static library),
`qltool/` (the CLI), `tests/` (Google Test suites), tracked per-file in
[STATUS.md](STATUS.md). Implementation proceeds in the phases defined in
[PORT_PLAN.md](PORT_PLAN.md).

## Scope

Windows PE support first, Linux ELF second; all other formats (Mach-O, UEFI, DOS,
QNX, FreeBSD, macOS, bare-metal MCU) are explicitly deferred — see the Sub-scoping
section of the port plan.

## Build

Requires CMake ≥ 3.15 and [vcpkg](https://vcpkg.io) (set `VCPKG_ROOT` or pass the
toolchain file). Dependencies come from the manifest (`vcpkg.json`).

```bash
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release

# run the test suite
./build/tests/Release/qiling_tests.exe        # Windows
./build/tests/qiling_tests                    # Linux
```

Targets: `qiling` (static library), `qltool` (CLI), `qiling_tests` (Google Test).
Conventions (ownership, exceptions, fibers, encoding): [CONVENTIONS.md](CONVENTIONS.md).

## Documents

| Document | Purpose |
|---|---|
| [PORT_PLAN.md](PORT_PLAN.md) | What is ported, in what order, with risks, phases, exit criteria, and tests |
| [MIRROR_LAYOUT_REORGANIZATION.md](MIRROR_LAYOUT_REORGANIZATION.md) | File/namespace mapping, build system, and the final directory layout |
| [PORT_PLAN_RUST.md](PORT_PLAN_RUST.md) | Rust-language port plan (alternative to PORT_PLAN.md; same scope and phases) + the C++-vs-Rust comparison |
| [CONVENTIONS.md](CONVENTIONS.md) | Build instructions and port conventions (ownership, exceptions, fibers, host boundary) |
| [STATUS.md](STATUS.md) | Per-file port status (Ported / Audit / NEW / C++-only / Deferred) |

## Relationship to qiling

The Python source tree lives in the sibling `qiling` checkout
(`../qiling`). The `examples/rootfs/` fixture submodule from that tree is reused
by the C++ test suites unchanged.

## Planned toolchain

C++17 · CMake ≥ 3.15 · vcpkg · Google Test · unicorn 2.1.4 (pinned) ·
capstone · keystone · pe-parse · ELFIO · spdlog · nlohmann-json · cxxopts

## License

GPL-2.0-or-later, matching upstream Qiling.
