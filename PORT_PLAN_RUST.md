# Qiling Rust Port Plan

**Source tree**: the Python project this plan ports lives in the sibling `qiling`
checkout (`../qiling` relative to this repo). All `qiling/...` file references
are relative to that tree; all `rs/...` references are relative to this repo's
future `rs/` root.

Companion to `PORT_PLAN.md` (the C++ port plan) and `MIRROR_LAYOUT_REORGANIZATION.md`
(the mirror-layout rules, which apply to this plan with `.py → .rs` substituted).
This document is the Rust-language counterpart of `PORT_PLAN.md`: identical
subsystem scope and phase structure, with the language-mechanics decisions
(§5, §9, §15) re-derived for Rust and the toolchain (§6–§8) replaced wholesale.
§16 compares the two plans dimension by dimension.

Everything here targets the **library + CLI** scope, exactly as `PORT_PLAN.md` §1:
`qiling/`, `qltool`. The TUI, IDA plugin, Docker packaging, and the deferred
subsystem set (Mach-O, UEFI, DOS, QNX, FreeBSD, macOS, `hw/`, MCU) are out —
same Sub-scoping, same resume criteria (OQ 9 there).

---

## 1. Scope

Carried over verbatim from `PORT_PLAN.md` §1 — same in-scope subsystem table
(~97,900 lines of Python; the initial PE+ELF port path is ~48,000 of those), same
explicit exclusions, same format priority (**Windows PE first, Linux ELF second**),
same deferred set. The only scope-adjacent difference is toolchain-internal: the
three engine libraries are consumed through their existing Rust binding crates
rather than linked directly (§6).

## 2. Scale and reality check

The three observations from `PORT_PLAN.md` §2, re-read for Rust:

1. **`qiling/os/` is 57,352 lines — 59% of the codebase — and remains breadth, not
   depth.** Unchanged by language choice: ~28 POSIX syscall modules, ~20 Windows
   DLL modules, each small and independently testable. The schedule lives here in
   both plans.

2. **The foundation stays cheap, but gains one thin layer.** Unicorn/Capstone/
   Keystone are already C. C++ links them directly; Rust consumes them through the
   existing binding crates (`unicorn`, `capstone`, `keystone-engine`). The ctypes
   layer is still deleted — but a thin, third-party-maintained Rust wrapper is
   added, which can lag the C releases; OQ-R1 audits its coverage of the hook API
   surface this port needs, with a self-generated `bindgen` `-sys` crate as the
   documented fallback (we would then control the unicorn 2.1.4 pin directly).
   Offsetting advantage: **goblin** replaces both pe-parse *and* ELFIO with one
   pure-Rust reader that also parses Mach-O — simplifying the deferred macOS path
   later (§5.8).

3. **The dynamism tax splits into two smaller taxes.** The Python-dynamic
   mechanisms (name-based resolution, decorator registration, duck typing) are
   *easier* in Rust than C++: `enum` + `match` dispatch and `LazyLock` tables are
   native language constructs, not machinery to build (compare C++ §5.2). What
   replaces that tax is the borrow checker: the `Qiling`↔component mutable object
   graph that C++ ports trivially with `unique_ptr` + raw back-references must be
   given an explicit ownership design in Rust (§5.5), and the Python exception
   control flow becomes `Result` propagation — a mechanical but pervasive signature
   rewrite (§5.4). Net: schedule risk moves from "build dispatch/fiber machinery"
   to "design the ownership graph", which is contained and gated inside Phase 2.

The honest read is unchanged: a multi-engineer, multi-quarter effort. Phase
boundaries and exit criteria are identical; only the risk distribution shifts.

## 3. Architecture recap (invariants carried over)

The pipeline and boot flow are identical to `PORT_PLAN.md` §3. The preserved
invariants, with their Rust form:

- **`Qiling::new` is the composition root** with the fixed instantiation order
  (`qiling/core.py:35`): arch/OS guessing → arch → struct/hook mixins → logger →
  profile → loader → memory manager → OS layer → `loader.run()`. Same order.
- **`Qiling::emu_start` is the only entry into Unicorn** (`qiling/core.py:743`).
  Same rule; the trampoline contract changes from "no exceptions across C frames"
  to "no panics across FFI" (§5.1).
- **Single point of name→component resolution** (the `utils.py` invariant): in
  Rust this is one `match` over the `QlArch`/`QlOs` enums.
- **The fs mapper and path virtualization are the host trust boundary.** Same
  containment checks, same dedicated traversal test pass (§5.6).
- **Emulation fidelity beats abstraction**: syscall/API implementations mirror the
  real platform's observable behavior; the POSIX and Windows layers are *not*
  unified. Same in Rust.
- **`unicorn` pin: 2.1.4** (matches `PORT_PLAN.md` D15; upstream Python pins
  2.1.3 to protect its ctypes ABI — a concern that does not apply to either
  native consumer). Touching the pin remains a project-wide event.
- **Robustness tenet**: guest-controlled sizes/offsets reaching host allocations
  are checked where they occur; unverifiable input degrades to a `QlError`, never
  a host crash — and in Rust, never a panic escaping to a C frame (§5.1/§5.4).

## 4. Dependency graph and porting order

Identical to `PORT_PLAN.md` §4: Util+exceptions+logging (Phase 0) → Arch (1) →
Core services (2) → Facade + PE loader (3) → Windows (4) → ELF + POSIX/Linux (5)
→ Debugger + Extensions (6) → CLI (7) → Integration/hardening (8), with the
deferred branches (UEFI/DOS/QNX/macOS/hw/MCU, freebsd) parked on the same phase
hooks and the same resume criteria.

## 5. Top porting risks and decisions

### 5.1 The hook engine — trampolines and the panic boundary

Same design as C++ §5.1 with Rust mechanics:

- **Trampoline design**: Unicorn takes C function pointers. Each registration
  wraps the Rust callback in a `static extern "C"` trampoline (`unsafe extern "C"`
  under newer editions), with `uc_hook_add`'s `user_data` pointing at a
  heap-allocated context owning the closure and a back-pointer to the `Qiling`.
  One trampoline per UC hook signature, not per callback.
- **No panic may cross into Unicorn C frames** — the exact analogue of the C++
  exception rule (an unwind crossing an FFI boundary is UB / aborts). The
  trampoline wraps the payload in `std::panic::catch_unwind` (`AssertUnwindSafe`),
  records the boxed payload on the Qiling instance (the `internal_exception`
  mechanism, `qiling/core.py:373` analogue), and returns cleanly so Unicorn stops;
  `emu_start` checks the recorded state on exit and re-raises (or returns `Err`).
  The library keeps the default `panic = "unwind"` strategy (never `abort` — the
  trampoline contract depends on catching).
- **Hook lifetime**: RAII hook handles (`Drop` unregisters) — same as C++ §5.1.
  Audit every `hook_*` call site to pin ownership (same as C++).
- **The `unsafe` surface is confined** to: the trampolines, the fiber glue (§5.3),
  and the context dereferences behind `user_data`. Everything else is safe code;
  this `unsafe` inventory is what review gates on.

Exit criteria for the slice are in Phase 2; this decision lands there.

### 5.2 Dynamic dispatch — native, not built

- **Component resolution** (`utils.py`): a `match` on `QlArch`/`QlOs` returning
  the concrete constructor. The single-point-of-resolution invariant is one
  function; there is no registration machinery to design (contrast C++ 5.2).
- **API/syscall registration** (`fncc.py`, `winsdkapi`, `map_syscall.py`): `match`
  statements for the closed sets (the common case) or
  `LazyLock<HashMap<&'static str, Handler>>` for open sets. The lookup key, the
  calling-convention wrapper (`QlFunctionCall`), and the "not implemented"
  degradation path must behave identically to Python — including which
  unimplemented entries raise `QlErrorNotImplemented` versus log-and-continue.
- **Duck-typed contracts**: `QlOs`, `QlLoader`, `QlArch` become traits; call sites
  that relied on duck typing are tightened — same mechanical budget as C++ §5.2,
  spent inside each OS phase.

### 5.3 Guest threads — stackful coroutines via `corosensei`

Same analysis as C++ §5.3: OS-threads-with-per-thread-uc rejected (Unicorn
instances are heavyweight; state sharing breaks `QlOs` assumptions); stackless
`async` rejected (a `Future` cannot be safely suspended across the Unicorn C
stack, and resume points would not align with blocking syscalls). **Decision**:
the maintained `corosensei` crate — stackful coroutines with Windows-fiber and
POSIX-ucontext/asm backends — behind a small `Fiber` abstraction mirroring
`QlThread`/`QlLinuxThread`/`QlWindowsThread` switch semantics. corosensei
propagates panics from a suspended coroutine to the resumer, matching the gevent
greenlet exception-propagation model that the C++ plan had to hand-build (§5.4
there). The switch-point audit (OQ 1 in the C++ plan) applies unchanged: enumerate
every greenlet yield site and every blocking-syscall switch; the fiber switch
points must be a strict superset. No async runtime anywhere in the emulation
path; host-side concurrency stays `std::thread` + channels.

### 5.4 Error handling — exceptions become `Result`

- The `QlError*` hierarchy (`exception.py`) ports to a single `enum QlError`
  (thiserror-derived `Display`); `QlSyscallError` becomes a variant carrying its
  `errno`. Subclass catch-sites → `match` arms / `downcast`-style filtering is
  unnecessary (single enum).
- Handlers return `Result<T, QlError>`; `?` replaces `raise`. Unlike the C++ plan
  (exceptions port *verbatim*), this is a **pervasive signature change** — the
  mechanical churn shows up in every syscall/API module and is budgeted per-phase
  (§12), not as a separate pass.
- `try/finally` → RAII guards (same as C++); fds and mapped regions released by
  destructor.
- Panics are **not** part of the error contract: they are reserved for the
  hook-reentry mechanism (§5.1) and genuine bugs. Any panic crossing a fiber
  switch is re-raised by the scheduler (corosensei semantics, mirroring gevent).
- Rules enforced in review: no panic across an FFI boundary (§5.1); no panic
  across a fiber switch (scheduler re-raises instead); `unwrap`/`expect` allowed
  only where the invariant is statically provable and commented.

### 5.5 Ownership — the borrow graph is the #1 Rust-specific risk

`Qiling` owns its components (arch, os, loader, mem, hw) in the documented init
order — same shape as C++ §5.5, but the Python-style back-references (`&ql`
inside OS/DLL classes) collide with the borrow checker when components call back
into the facade. Design decisions:

- The emulation core is **single-threaded per instance** (R15): debugger/analytics
  threads communicate via channels and never touch emu state directly (OQ-R6
  confirms). This enables `Rc`/`RefCell` instead of `Arc`/`Mutex` in the hot path.
- Internal shared access uses `Rc<...>`/`RefCell<...>` sparingly, with the cell
  discipline documented per field (no `RefCell` held across `emu_start` or fiber
  switches — audited).
- Where a cycle is unavoidable (component back-pointers), the escape hatch is a
  raw pointer with a `// SAFETY:` comment tying its validity to the `Qiling`
  owner — the same shape as the C++ plan's raw back-references, made explicit and
  grep-able.
- Hook contexts and `QlFsMappedObject` handles that can outlive their creator:
  `Rc`/`Weak` (the `weakref` analogue).
- An **ownership audit** is added to the Phase 2 exit criteria: enumerate every
  component back-reference and classify it (owned / borrow / `Rc` / raw+SAFETY)
  before Phases 3–5 build on the facade.

### 5.6 Strings, paths, and the host boundary

Identical decisions to C++ §5.6: `String`/`Vec<u8>` for guest bytes and paths;
`std::path::Path` only at the host boundary (mapper, profile loading, rootfs).
The `QlFsMapper` containment checks are the review-listed host-boundary risk:
re-derive them against Rust path semantics (normalization, prefix comparison) and
add the dedicated traversal test pass — symlinks, `..`, drive-letter and UNC edge
cases — as part of Phase 3/4 exit criteria.

### 5.7 Constant tables — reuse, don't port

Same decision as C++ §5.7/D3, different mechanism: the `capstone` crate re-exports
the generated constants (register ids, instruction ids, groups per arch) —
`qiling/arch/*_const.py` has no Rust counterpart (OQ-R4 verifies 1:1 coverage).
`qiling/hw/const/` peripheral register tables have no upstream and port by hand
when the bare-metal path resumes.

### 5.8 pefile / pyelftools → goblin

- **PE and ELF**: the `goblin` crate (pure Rust, mature, widely used in the Rust
  binary-analysis ecosystem) reads PE headers/imports/exports/relocations and ELF
  segments/sections/symbols/dynamics. Program-header mapping and loader semantics
  stay in our code — the same "reader + our mapping" split as C++ §5.8.
  `object` and `pelite` are documented alternatives (OQ-R3).
- **Mach-O**: goblin already parses Mach-O — the deferred macOS path reuses the
  same reader instead of porting the in-tree `macho_parser/` Python (a net scope
  reduction vs the C++ plan). Deferred either way (Sub-scoping).

### 5.9 Registry (same as C++ §5.9)

`config.json` primary via `serde_json`; NT-hive ingestion deferred behind an
optional feature and, if restored, a minimal hand-written hive reader. No change
from the C++ decision.

### 5.10 Profiles and config

- `.ql` profiles: **`rust-ini`** (pure Rust, no transitive dependencies) — this
  differs from the C++ plan's hand-rolled reader because the "avoid dependency
  friction" rationale is C++/vcpkg-specific. The same configparser-interpolation
  audit gates it (OQ-R5); if interpolation features are actually used, fall back
  to a tiny hand-rolled parser (matching C++ D8).
- MCU board config YAML: **deferred** with the MCU subsystem; `serde_yaml` (or
  successor) when it resumes.
- Registry `config.json` store and `extensions/report` JSON: `serde_json`.

### 5.11 Logging, regex, CLI, threads

- **Logging**: `tracing` + `tracing-subscriber`. Python named loggers → tracing
  targets (e.g. `target: "qiling.win.api"`); the `QL_VERBOSE` levels map onto
  tracing levels; a small custom `Layer` re-implements the Python surface's
  `RegexFilter` (message-regex filtering) and the `[!]`/`[=]`/`[+]` level tags;
  colored console via `tracing-subscriber`'s ANSI support, honoring `NO_COLOR`.
  The thread tag comes from a tracing span installed by the fiber scheduler.
- **CLI**: `clap` (derive) for `qltool run|code`; `qltui.py` stays out of scope.
- **Regex** (`log.py` filter, `utils.py`): the `regex` crate.
- **Threads**: host-side threads (GDB server, stats) → `std::thread` + channels;
  guest threads are corosensei fibers (§5.3).

### 5.12 Dropped Python-only surface

Identical to C++ §5.12: `qiling/extensions/idaplugin/`, `qltui.py` dropped;
`pickle` snapshots (`ql.save`/`ql.restore`) → explicit versioned binary format
(serde-based envelope; exact format per OQ-R7). No Python-pickle compatibility.

## 6. Third-party reconciliation (crates)

| Need | Python source | Rust choice | Notes |
|---|---|---|---|
| CPU emulator | `unicorn == 2.1.3` (ctypes) | **`unicorn` crate** (Unicorn 2.x; pin 2.1.4 in Cargo.lock) | binding-coverage audit OQ-R1; fallback: own `bindgen` `-sys` |
| Disassembly | `capstone ^5` (ctypes) | **`capstone` crate** + re-exported consts | replaces `qiling/arch/*_const.py` (5.7) |
| Assembly | `keystone-engine ^0.9.2` (ctypes) | **`keystone-engine` crate** | |
| PE parsing | `pefile` | **`goblin`** | 5.8; `pelite` fallback (OQ-R3) |
| ELF parsing | `pyelftools` | **`goblin`** | 5.8 |
| Mach-O parsing | in-tree `macho_parser/` | **`goblin`** (already supported) | deferred path simplified vs C++ |
| Guest threads | `gevent` | **`corosensei`** (stackful coroutines) | 5.3 |
| Host threads | `threading` | `std::thread` + channels | |
| JSON | stdlib `json` | **`serde` + `serde_json`** | registry store, report |
| Logging | stdlib `logging` | **`tracing` + `tracing-subscriber`** | 5.11 |
| INI profiles | `configparser` | **`rust-ini`** | pending OQ-R5 audit |
| CLI parsing | `argparse` | **`clap`** | 5.11 |
| Regex | `re` | **`regex`** | |
| Errors | — | **`thiserror`** (`QlError` enum) | 5.4 |
| Flags | — | **`bitflags`** (`QL_STOP`) | |
| Snapshots | `pickle` | **`serde` + versioned binary envelope** (bincode candidate) | OQ-R7 |
| Tests | `unittest` | built-in `#[test]` + `rstest` | 11 |
| AFL fuzzing | `unicornafl` (extra) | deferred; hand-rolled `-sys` shim if resumed | Phase 6, same as C++ OQ 6 |
| radare2 | `r2libr` (extra) | deferred; same treatment | Phase 6 |

All listed crates are MIT/Apache-2.0 dual-licensed — GPL-2.0-or-later compatible.
`gevent`, `pyelftools`, `pefile`, `python-registry`, and the ctypes layer all
drop out. **vcpkg is not needed for this plan**: the three C libraries are built
from source by their binding crates (`cc`/`cmake` in build.rs), or linked to
system installs via features.

## 7. Directory layout under `rs/`

The mirror rules from `MIRROR_LAYOUT_REORGANIZATION.md` apply unchanged — and are
*natively* natural in Rust: Python `foo.py` → `foo.rs` with the identical
basename (both are snake_case); packages → module paths with the same shape;
class names verbatim (`Qiling`, `QlMemoryManager`, `QlThread`, `Qdb`); the
`__init__.py` exceptions become `lib.rs` (package entry) and `qltool/src/main.rs`
(CLI); `*_const.py` modules dissolve into the capstone-crate reuse (5.7).
C++-only files become Rust-side files: `core_hooks_trampolines.rs`, `os/fiber.rs`
(scheduler), `profiles/inireader` (not needed if OQ-R5 passes with rust-ini).

```
rs/
  Cargo.toml                     # workspace: crates/qiling, crates/qltool
  Cargo.lock                     # committed; pins unicorn 2.1.4 etc.
  rust-toolchain.toml            # stable channel, MSRV pin
  README                         # conventions (ownership, panics, fibers, encoding)
  crates/
    qiling/                      # the framework library
      Cargo.toml
      profiles/                  # windows.ql, linux.ql (include_str!)
      src/
        lib.rs                   # <- __init__.py (package entry, re-exports)
        core.rs                  # <- core.py (composition root)
        core_hooks.rs            # <- core_hooks.py (registration surface)
        core_hooks_trampolines.rs  # Rust-side: static C trampolines + ctx (5.1)
        core_hooks_types.rs      # <- core_hooks_types.py
        core_struct.rs           # <- core_struct.py (QlCoreStructs)
        const.rs                 # <- const.py (QL_* enums, casefolded name maps)
        exception.rs             # <- exception.py (QlError enum — 5.4)
        host.rs                  # <- host.py (QlHost)
        log.rs                   # <- log.py (tracing setup, tags, filters)
        utils.rs                 # <- utils.py (match-based resolution, guessing)
        arch/                    # <- arch/ (x86.rs, arm.rs, ..., register.rs,
                                 #   models.rs, utils.rs; consts from capstone)
        cc/                      # <- cc/ (cc.rs, intel.rs, arm.rs, ...)
        loader/                  # <- loader/ (loader.rs, pe.rs, blob.rs, elf.rs)
        os/
          os.rs  const.rs  memory.rs  fcall.rs  mapper.rs  path.rs  struct.rs
          thread.rs  fiber.rs    # fiber.rs: corosensei scheduler (5.3)
          filestruct.rs  utils.rs  stats.rs
          blob/                    # <- os/blob/
          posix/                   # <- os/posix/ (filestruct, structs, stat, msq,
                                   #   shm, kernel_proxy/, syscall/ + abi/)
          linux/                   # <- os/linux/ (linux.rs, syscall.rs,
                                   #   syscall_nums.rs, map_syscall.rs, kernel_api/)
          windows/                 # <- os/windows/ (windows.rs, api.rs, fncc.rs,
                                   #   handle.rs, thread.rs, fiber.rs, registry.rs,
                                   #   ..., dlls/ incl. kernel32/ per-family modules)
        debugger/
          gdb/ (gdb.rs  utils.rs  xmlregs.rs)
          qdb/ (qdb.rs ... arch/ branch_predictor/ render/)
        extensions/
          coverage/ (utils.rs  formats/)
          tracing/ (utils.rs  formats/)
          sanitizers/ (heap.rs)
          report/ (report.rs)
          afl/  r2/                # feature-gated, per Phase 6
    qltool/
      Cargo.toml
      src/main.rs                  # <- qltool script + cli.py (clap)
    tests/                         # integration tests, mirrors tests/ inventory
```

Deferred subsystems park exactly as in the C++ layout (same deferred tree shape,
not built): `loader/macho.rs` (goblin-based), `os/uefi/`, `os/dos/`, `os/mcu/`,
`os/freebsd/`, `os/qnx/`, `hw/`, `extensions/mcu/`.

## 8. Build system

Single-command cargo builds; no CMake, no vcpkg:

```toml
# rs/Cargo.toml (workspace)
[workspace]
members = ["crates/qiling", "crates/qltool"]

[workspace.package]
edition = "2021"
rust-version = "1.83"              # MSRV, pinned (OQ-R9)

[workspace.dependencies]
unicorn = "0.9"
capstone = "0.14"
keystone-engine = "0.1"
goblin = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
clap = { version = "4", features = ["derive"] }
thiserror = "2"
bitflags = "2"
corosensei = "0.3"
rust-ini = "0.21"
regex = "1"
rstest = "0.26"
```

- Targets: `qiling` (lib), `qltool` (bin); unit tests in-crate plus integration
  tests under `crates/tests/` (`cargo test`).
- Lints: `clippy::all` on; `-D warnings` considered after Phase 8 (mirroring the
  C++ plan's no-`-Werror`-initially stance); `cargo-deny` enforces license and
  advisory audits.
- Platforms: Windows (MSVC toolchain) and Linux (GNU) — same CI matrix as the
  C++ plan.
- Engine pins: `Cargo.lock` pins unicorn 2.1.4; the binding crate is verified
  against the C API surface this port uses (OQ-R1).

## 9. Conventions: Python → Rust mapping

| Python | Rust | Notes |
|---|---|---|
| package layout | mirrored module paths | `qiling/os/posix/` → `qiling::os::posix` |
| `Qiling` class | `qiling::Qiling` struct | composition root, init order preserved |
| mixins (hooks, structs) | traits with default methods / composition | |
| ABC / `@abstractmethod` | `trait` + required methods | |
| `typing.Protocol` | `trait` | |
| properties | `get_x` / `set_x` methods | |
| `enum.Enum` / `IntEnum` | `enum` with explicit discriminants (`#[repr(u32)]`) | |
| `enum.Flag` (`QL_STOP`) | `bitflags!` struct | |
| dict dispatch | `match` / `LazyLock<HashMap>` | 5.2 |
| exceptions (`QlError*`) | `Result<T, QlError>` + `?` | 5.4 |
| `with` / context managers | RAII (`Drop`) | |
| `functools.cached_property` | `OnceLock` field | |
| callbacks/closures into Unicorn | `extern "C"` trampolines + closure payloads | 5.1 |
| gevent `Greenlet` | `corosensei` coroutine | 5.3 |
| `weakref` | `std::rc::Weak` | 5.5 |
| duck typing | traits; tightened call sites | |
| decorators (API registration) | plain fns in const tables / `match` arms | 5.2 |
| f-strings | `format!` | |
| `*args/**kwargs` | option structs / enums | |

## 10. Porting phases

Phase structure, dependencies, deliverables, exit criteria, and tests carry over
from `PORT_PLAN.md` §10 verbatim except where noted. The TDD rule (survey →
failing test → red → implement → green) applies unchanged. Phase deltas:

- **Phase 0 — Scaffolding and primitives**: workspace, `QlError` enum (thiserror),
  `QL_*` enums with casefolded name maps (match-based conversion functions with
  the same alias tables as `utils.py`), tracing setup reproducing the `log.py`
  surface (named targets, level filter, regex filter, colored console, `NO_COLOR`),
  serde_json, rust-ini profile parsing with the same configparser-parity exit
  criterion (key/value structure equivalence). Tests: `util`, `log`, `profile`
  modules.
- **Phase 1 — Arch layer**: per-arch classes over the `capstone` crate; same
  x86/x86-64-first exit criteria — a test initializes the CPU, sets/reads
  registers, and disassembles/assembles a fixed corpus with byte-identical results
  to the Python layer's output. Const-coverage audit OQ-R4 closes here.
- **Phase 2 — Core services**: hook engine with trampolines — **the panic-boundary
  rule joins the exit criteria: a test panics inside every hook type and proves no
  unwind reaches a C frame, with `emu_start` re-raising**; memory manager/heap,
  fcall marshalling, host, snapshot save/restore (versioned envelope, OQ-R7).
  **New vs the C++ plan: the ownership audit (5.5) closes this phase** — the
  component back-reference inventory gates Phases 3–5. Tests: hooks (the heaviest
  investment), memory, fcall, struct, snapshot.
- **Phase 3 — Facade + PE loader**: composition root, match-based resolution,
  PE path of the loader over goblin, blob glue, fs mapper/path with the traversal
  test pass (symlink/`..`/UNC). Same malformed-input robustness criterion:
  `QlError`, never a host crash or escaping panic.
- **Phase 4 — Windows**: the full Windows stack; fiber scheduler on corosensei
  lands here with the switch-point audit (OQ 1 analogue). Same fixture-behaviour
  reproduction, serde_json registry round-trip, fiber multithread fixture.
- **Phase 5 — ELF + POSIX/Linux**: same structure; adds the exception→`Result`
  rewrite volume for the syscall modules (already inherent — handlers were written
  with `Result` from their first port). Same fixture parity and fiber reuse
  criteria.
- **Phase 6 — Debugger + extensions**: gdb server, qdb (scripts run as-is),
  coverage/tracing/sanitizers/report; AFL/r2 behind features — both need
  hand-rolled `-sys` shims over their C APIs (OQ-R8), same as the C++ plan's
  optional-feature stance.
- **Phase 7 — qltool CLI**: clap port of `cli.py`; same CLI round-trip parity
  criterion (same invocation string → same emulated behaviour for a PE + ELF
  fixture matrix).
- **Phase 8 — Integration and hardening**: parity harness over the rootfs corpus
  (Python-vs-Rust diffing), performance baselines (at least Python-parity is a
  finding), CI on Windows + Linux, `clippy -D warnings` / `cargo-deny` decision,
  snapshot format freeze, loader-parser robustness fuzz pass, docs updates,
  `rs/STATUS.md` completion. Same deferred-subsystem resume criteria.

## 11. Test strategy

Carried over from `PORT_PLAN.md` §11 with mechanical substitutions: gtest →
built-in `#[test]` + `rstest` fixtures; the suite inventory mirrors `tests/*.py`
one-to-one (same mapping table as the C++ plan, suite names unchanged);
`examples/rootfs/` reused as the fixture submodule, unchanged; the Windows PE
real-DLL collection constraint stays host-gated. The parity harness, no-silent-
pass rule, malformed-binary robustness suites, and the hook-matrix /
fiber-switch-point invariant sweeps all apply unchanged.

## 12. Effort and sequencing summary

Same phase table as `PORT_PLAN.md` §12 (same Python-line volumes; the initial
~47,700-line path and the ~50,200-line deferred set are unchanged). Risk-column
deltas:

| Phase | C++ plan risk | Rust plan risk | Delta driver |
|---|---|---|---|
| 0 | low | low | — |
| 1 | low-medium | low | capstone crate covers const/disasm plumbing |
| 2 | medium-high (hook engine) | medium-high (hook engine + ownership audit) | the hard part moves from building machinery to designing the borrow graph |
| 3 | medium (trust boundary) | medium | — |
| 4 | **high** (breadth + dispatch engine + fibers) | **high** (breadth; fibers are a crate) | dispatch/fiber machinery → library |
| 5 | **high** (breadth + fibers) | **high** (breadth; `Result` churn) | exception→Result rewrite adds mechanical volume |
| 6 | medium | medium | unicornafl/r2 shims uncertain (OQ-R8) |
| 7 | low | low | — |
| 8 | medium | medium | — |

Sequencing notes carry over: Phases 4 and 5 dominate the schedule; Phase 2's hook
engine and ownership audit gate everything above it; Phase 6 decomposes into
independently testable pieces once Phase 4 is green.

## 13. Status tracking

Same as `PORT_PLAN.md` §13: `Ported` / `Audit` / `NEW` / `Rust-only` legend,
`rs/STATUS.md` maintained per mirrored file (all `NEW` initially), deferred
subsystems in a separate section so their resumption stays visible.

## 14. Open questions / audits (Rust-specific)

1. **`unicorn` crate coverage audit** (Phase 1): confirm the binding exposes every
   UC hook type and API the port needs at the pinned version, and that it builds
   against unicorn 2.1.4; fallback is a self-generated `bindgen` `-sys` crate
   (we would then own the pin directly).
2. **corosensei audit** (Phase 2): per-coroutine stack sizes, Windows-fiber
   backend behaviour, panic-propagation semantics vs gevent; alternatives
   inventory recorded before Phase 4 depends on it.
3. **goblin PE surface audit** (Phase 3): imports/exports/relocations/delay-imports
   coverage vs what `loader/pe.py` needs (`pelite` as the documented fallback).
4. **capstone-consts audit** (Phase 1): the C++ plan's OQ 2 applies — verify the
   crate's re-exported constants map 1:1 onto `qiling/arch/*_const.py` (register,
   insn, group ids) with no Qiling extensions lost.
5. **rust-ini audit** (Phase 0): the C++ plan's OQ 8 — confirm `.ql` profiles use
   no configparser interpolation; if they do, hand-roll the parser (C++ D8 parity).
6. **Single-thread contract audit** (Phase 2): confirm no component assumes
   cross-thread access to emu state; debugger/analytics threads interact via
   channels only; document the `RefCell`-across-`emu_start` prohibition.
7. **Snapshot envelope** (Phase 2): same open question as the C++ plan (OQ 7
   there) — define the versioned binary format (serde+bincode candidate) so
   save/restore survives additive component growth.
8. **unicornafl / r2 C-API shims** (Phase 6): same as the C++ plan's OQ 6 — pin
   versions and confirm the C APIs are stable; both likely need hand-rolled
   `-sys` crates since no maintained Rust bindings exist.
9. **MSRV policy** (Phase 0): pin `rust-version` and the CI stable toolchain at
   project start; bumps only as documented decisions.

## 15. Decision log (Rust plan)

| # | Decision | Date | Rationale |
|---|---|---|---|
| R1 | Stable Rust, cargo workspace under `rs/`; `qiling` lib + `qltool` bin | 2026-10-17 | single toolchain; no CMake/vcpkg surface (C++ D1 counterpart) |
| R2 | Consume unicorn/capstone/keystone via maintained binding crates; pin unicorn 2.1.4 in Cargo.lock | 2026-10-17 | mirrors C++ D2 modulo a thin audited binding layer (OQ-R1; bindgen fallback) |
| R3 | Reuse capstone-crate constants; no `*_const.rs` port | 2026-10-17 | same as C++ D3 |
| R4 | goblin for PE + ELF (and Mach-O when the macOS path resumes) | 2026-10-17 | one mature reader covers all three; replaces pe-parse+ELFIO (C++ D4); simplifies the deferred macOS path |
| R5 | gevent greenlets → corosensei stackful coroutines; no async runtime in the emu path | 2026-10-17 | same design as C++ D5; the scheduler is a maintained crate instead of hand-rolled |
| R6 | `QlError` → thiserror enum; `Result` everywhere; panics never cross FFI (catch_unwind trampolines; internal_exception + re-raise at emu_start) | 2026-10-17 | Rust analogue of C++ D6; the UB rule is preserved by construction |
| R7 | tracing/tracing-subscriber for logging; serde_json; clap | 2026-10-17 | same surfaces as C++ D7 |
| R8 | rust-ini for `.ql` profiles (hand-rolled fallback if the interpolation audit fails) | 2026-10-17 | differs from C++ D8: the no-dependency rationale is vcpkg-specific |
| R9 | Same drops as C++ D9 (idaplugin, qltui, Docker; deferred bare-metal path) | 2026-10-17 | scope parity |
| R10 | serde_json registry primary; hive ingestion deferred | 2026-10-17 | same as C++ D10 |
| R11 | Dynamic dispatch → enum `match` / `LazyLock` tables; single resolution point | 2026-10-17 | same invariant as C++ D11, native construct |
| R12 | Tests as built-in `#[test]`/`rstest` mirroring the `tests/` inventory; rootfs reused unchanged | 2026-10-17 | same as C++ D12 |
| R13 | `String`/`Vec<u8>` guest bytes; `std::path` at host boundary only; dedicated traversal test pass | 2026-10-17 | same as C++ D13 |
| R14 | Format priority: PE first, ELF second; deferred set and resume criteria unchanged | 2026-10-17 | same as C++ D14 |
| R15 | Emulation core single-threaded per Qiling instance; host threads use channels; `Rc`/`RefCell` (not `Arc`/`Mutex`) in the hot path | 2026-10-17 | enables the ownership design (5.5); avoids lock overhead on the hot path |

Append rows as decisions are taken during implementation.

---

## 16. Comparison with the C++ plan (`PORT_PLAN.md`)

### What is identical

Scope and exclusions, the subsystem inventory and ~97.9k-line scale, the mirror
layout rules (basenames, class names, deferred tree), the dependency graph and
phase structure 0–8 with the same exit criteria and test mapping, the fixture
strategy (`examples/rootfs/` reused), the parity-harness approach, the deferred
subsystem set and resume criteria, and the engine pins (unicorn 2.1.4, capstone
5.x). The plans are interchangeable at the milestone level: either tree can
proceed phase-by-phase, and the other plan remains a valid fallback without
re-planning.

### Where they differ

| Dimension | C++ plan (`PORT_PLAN.md`) | Rust plan (this doc) | Edge |
|---|---|---|---|
| Engine layer | direct C linkage; ctypes layer deleted | binding crates; ctypes deleted, thin audited Rust layer added (OQ-R1) | C++ (thinnest possible) |
| Format parsers | pe-parse + ELFIO (two libs, two APIs) | goblin (one crate; also covers Mach-O for the deferred path) | Rust |
| Dynamic dispatch | build factory/registration machinery (5.2) | `enum` + `match` / `LazyLock` — native constructs | Rust |
| Guest threading | hand-rolled ucontext/Windows-fiber scheduler (5.3 — the plan's highest design-risk item) | corosensei crate; same audit, less custom unsafe | Rust |
| Error model | `QlError*` exception hierarchy ported verbatim; UB-discipline rules at FFI/fiber boundaries | `Result` + `QlError` enum; no UB by construction, but every handler signature changes | C++ for port fidelity; Rust for safety |
| Shared mutable graph | trivial (`unique_ptr` + raw back-references) | borrow-checker negotiation: ownership audit, `Rc`/`RefCell` discipline, raw+SAFETY escape hatch (5.5 — the #1 Rust-specific risk) | C++ |
| Memory safety | achieved by discipline (review-enforced 5.1/5.4 rules) | achieved by construction (`unsafe` confined to trampolines/fiber glue) | Rust |
| Build & dependency management | CMake ≥ 3.15 + vcpkg manifest; per-platform build files | cargo workspace + Cargo.lock; one command | Rust |
| Test harness | gtest (external framework, JSON output) | built-in `#[test]` + rstest | ~tie (Rust simpler; gtest richer filtering) |
| Runtime performance | baseline | comparable; bounds checks negligible next to emulation cost; C++ marginal micro-advantage possible | ~tie |
| Toolchain risk | vcpkg port drift; MSVC/GCC/Clang variance | binding-crate maintenance lag; MSRV churn (both audited) | different, both small |
| Ecosystem precedent | mirrors the sibling C++ decompiler-port toolchain (cross-project consistency, D1) | strong binary-analysis ecosystem (goblin, capstone-rs, corosensei) | project-specific |

### Reading the verdict

The two plans are the **same plan wearing two languages**. The structural work —
scope, phases, mirrors, tests, risk acceptance — transfers 1:1; what changes is
*where the difficulty lives*:

- **C++** minimizes deviation from the Python source's architecture (verbatim
  exceptions, classes, object graphs) and has the thinnest possible engine layer,
  at the price of building the dispatch and fiber machinery by hand and enforcing
  memory/UB discipline by review.
- **Rust** gets dispatch, fibers, and memory safety from the language and
  ecosystem, and pays with a one-time ownership redesign gated in Phase 2, a
  pervasive exception→`Result` rewrite threaded through every phase, and a thin —
  but third-party — binding layer over the three engine libraries.

Total risk is comparable and the choice stays reversible until Phase 2–3, when
the hook engine and ownership design land. Choose **C++** if minimal deviation
from the Python architecture and the absolute thinnest FFI layer matter most, or
if team fluency is stronger there. Choose **Rust** if offloading UB discipline,
the single-toolchain dependency story, and the unified goblin reader outweigh the
ownership-graph redesign.
