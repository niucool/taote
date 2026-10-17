# taote

A C++ port of the [Qiling Framework](https://github.com/qilingframework/qiling) —
an advanced cross-platform, multi-architecture binary emulation framework.

**Status**: planning. No code yet — the repository currently holds the port plan
and the mirror-layout specification. Implementation proceeds in the phases defined
in [PORT_PLAN.md](PORT_PLAN.md).

## Scope

Windows PE support first, Linux ELF second; all other formats (Mach-O, UEFI, DOS,
QNX, FreeBSD, macOS, bare-metal MCU) are explicitly deferred — see the Sub-scoping
section of the port plan.

## Documents

| Document | Purpose |
|---|---|
| [PORT_PLAN.md](PORT_PLAN.md) | What is ported, in what order, with risks, phases, exit criteria, and tests |
| [MIRROR_LAYOUT_REORGANIZATION.md](MIRROR_LAYOUT_REORGANIZATION.md) | File/namespace mapping, build system, and the final `cpp/` directory layout |

## Relationship to qiling

The Python source tree lives in the sibling `qiling` checkout
(`../qiling`). The `examples/rootfs/` fixture submodule from that tree is reused
by the C++ test suites unchanged.

## Planned toolchain

C++17 · CMake ≥ 3.15 · vcpkg · Google Test · unicorn 2.1.3 (hard-pinned) ·
capstone · keystone · pe-parse · ELFIO · spdlog · nlohmann-json · cxxopts

## License

GPL-2.0-or-later, matching upstream Qiling.
