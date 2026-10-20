# PLAN — taote on par with pegasus (and beyond)

Goal: taote should match pegasus on **every measurable emulation and analysis
capability**, and beat it where a qiling port has an inherent edge. The plan is
evidence-driven: each phase raises a number on the scoreboard below, and no
phase closes without its tests.

## 0. The scoreboard (what "on par" means, numerically)

| metric | pegasus | taote today | target |
|---|---|---|---|
| API sample sweep (`../pegasus/tests/bins`, 101 bins) | n/a (their suite asserts dispatch only) | **97 exit 0**, 2 block in `accept`, 2 kernel `.sys` | 99+ (drivers land) |
| PMA corpus (`~/source/capa-testfiles`, 32 PE samples) | 12 curated cases green (their CI), 38 with `PEGASUS_PMA_FULL=1` | **13 exit 0** (32-sample sweep), **0/12 green** (curated ctest cases, now with the reference guards) | ≥ 30 exit 0, all curated cases green |
| reference-suite parity (`../pegasus/tests`, 357 cases) | 357 | **12 ported + 4 ported clusters**, rest mapped in `tests/PEGASUS_TEST_PARITY.md` | every *portable* row ported, none "deferred" |
| taote suite | — | **535 passed / 0 failed / 3 skipped** | grows with every phase, stays 0-failed |
| host support | MSVC/Windows + Linux | MSVC/Windows + Linux | unchanged (regression gate) |

Two supporting tools the plan needs (Phase 0):

* `tests/Pma_Compat_Test.cpp` — the reference PMA cases from
  `../pegasus/tests/test_pma_samples.cpp`, gated on `capa-testfiles` being
  present, with `TAOTE_PMA_FULL=1` for all 38. Each case: run the sample with
  the timeout + instruction-count guards, collect the dispatched API names and
  the file/registry/DNS indicators, assert the expected set, allow exactly the
  reference case's tolerated entry-point errors. This turns the PMA number
  above into ctest cases.
* `tools/gap_census` — for a corpus directory, dump every imported name that
  `ApiRegistry::find` does not resolve, ranked by how many samples import it.
  (The throwaway `/tmp/gap_check` version already produced the lists this plan
  is sequenced from.) This keeps the API-surface work data-driven instead of
  guesswork.

## Phase 1 — the emulation fault clusters (biggest score win)

The 15 failing PMA samples split into five clusters; each cluster is one root
cause class, not a per-sample bug.

1. **Unsupported-API discipline (`UC_ERR_WRITE_UNMAPPED`: 05-01.dll, 17-02.dll).**
   An unimplemented import currently returns with whatever `rax` held, so the
   guest stores through a stale pointer. Port pegasus's model: record the call
   as *unsupported*, keep a counter, and let the config decide abort vs
   continue. Concretely: `QlOsStats::log_unsupported_api(name)`, a
   `QilingOptions::max_api_count` + `unsupported_api_policy`, and the reference
   error taxonomy on the entry point (`unsupported_api`, `invalid_read`,
   `invalid_write`, `max_api_count`).
2. **Dynamic-import resolution (`UC_ERR_FETCH_UNMAPPED`: 01-01.dll, 12-01 .exe/.dll, 18-03, 20-02).**
   Status: **attempted, reverted.** A synthesised `ret` cell (the
   `modules.functions_always_exist` sentinel) for a `GetProcAddress` miss made
   the corpus *worse* (13 → 11 ok): the guests that check the result for NULL
   take their error path, and the ones that call it land in the excel-page
   `ret` whose arg-cleanup the adaptive stdcall peek then gets wrong. What the
   diagnosis did establish: the faults split into (i) `push DWORD PTR [edi]`
   with `edi == 1` — an internal helper called with a value where the reference
   profile would have supplied a module base (03-02.dll, 05-01.dll, 11-02.dll,
   17-02.dll: five samples, one shape), (ii) jumps to 0 from a NULL
   `GetProcAddress` result (18-03, 19-02, 12-01), and (iii) `PC = 0x80000073`,
   a key handle used as a call target (01-01.dll, 20-02.exe). Each needs its
   own root-cause fix; none is the sentinel.
   Diagnose per sample; the likely causes are (a) `GetProcAddress` on a name the
   rootfs dll does not export — pegasus's `modules.functions_always_exist`
   answers a sentinel, (b) `LoadLibraryA` of a module absent from the rootfs,
   (c) a self-unpacking stub jumping to an OEP outside the mapped image. Fix by
   implementing the same three behaviors explicitly (no silent sentinel: log the
   synthesised export so the analysis surface shows it).
3. **CPU exceptions (`UC_ERR_EXCEPTION`: 16-03.exe).** Guest `int3`/`div` must
   route through the same dispatch as AVs (`STATUS_*` record + frame walk);
   today only read/write faults dispatch.
   Status: **landed for `div`/`idiv`.** The trace hook pre-checks the
   instruction (the operand group + a zero divisor in a register), stages an
   `EXCEPTION_RECORD` with `STATUS_INTEGER_DIVIDE_BY_ZERO` (0xC0000094) through
   the same `seh_dispatch` the AV path uses (the record's code is now a
   parameter), and stops; the run loop restarts at the armed retarget when
   `emu_start` returns *without* an error. 16-03.exe no longer reports
   `UC_ERR_EXCEPTION`; it now faults fetching from a non-executable page, i.e.
   the dispatch itself works and the remaining problem is the target.
4. **Hangs (14-01.exe).** The guards from 1. are the mechanism; add the
   virtual-clock slice so `Sleep`/timeouts do not stall the run.
5. **The AV-exit tail (14-02.exe).** An unhandled exception should end the run
   with `STATUS_ACCESS_VIOLATION` *and* a recorded entry-point error, not a bare
   fault text.

Status: **1.1 landed** — `QlOsStats::log_unsupported_api` + the unsupported
count, `QilingOptions::max_api_count` / `unsupported_api_policy` (Continue
answers a zero return value through the calling convention, Abort ends the
entry point), the `EntryPointError` taxonomy (`invalid_fetch`, `invalid_read`,
`invalid_write`, `invalid_cpu_exception`, `invalid_insn`, `unsupported_api`,
`max_api_count`, `timeout`) recorded through `QlOs::on_emulation_error` so the
dll-drive path records it too, and the deterministic instruction budget (a
`count` guard that unicorn stops at exactly). It also fixed a host crash the
corpus surfaced: `WriteFile` on a console handle dereferenced the handle's
cached stream pointer, which `set_stdout` left dangling. Measured after: PMA
raw sweep 13/32 (was 12; the entry/export normalization and the dll drive for
export-less images added one), curated 0/12 — every case now reports *why*
(missing API surface, not a harness bug).

Exit: PMA ≥ 26 exit 0, curated cases green, sweep unchanged at 97.

## Phase 2 — the qiling-surface completions the corpora need

Driven by `tools/gap_census` over both corpora:

* **The census top-N handlers** across kernel32 / ntdll / advapi32 / user32 /
  ws2_32 / ole32 / wininet behind the current long tail.
* **Registry hive reads** — the one accepted deferral (upstream delegates to
  `python-registry`). Malware that reads real hives needs it: implement a
  minimal NT registry hive parser (`nk`/`vk`/`sk` cells, value marshalling)
  behind `RegHive`, with corpus fixtures chosen from the PMA set that query
  installed-software keys.
* **`os/windows/ntdefs.hpp`** — the ~70 `test_win_size_validation_all` rows
  (`UNICODE_STRING`, `OBJECT_ATTRIBUTES`, `PEB`/`TEB`/`RTL_USER_PROCESS_PARAMETERS`,
  …) as a size/offset table with a test, replacing the ad-hoc offsets the
  handlers carry. Unblocks the biggest `[portable, deferred]` block in
  `tests/PEGASUS_TEST_PARITY.md` and hardens every struct-writing handler.

Exit: the parity map has no `[portable, deferred]` rows left.

## Phase 3 — the analysis/tooling surface (pegasus's real differentiator)

taote currently has qiling's `QlOsStats` (name → ret values, tokenised strings).
Pegasus has typed events with arguments, indicators and an artifact store. Port
that surface onto the existing stats object — this is what makes the PMA
assertions possible:

1. **API records with arguments** — `{dll, name, args, retval, address}` so
   expectations can be dll-qualified (`KERNEL32.GetProcAddress`) and
   argument-sensitive (the reference cases assert `InternetOpenUrlA`'s URL).
2. **Indicator events** — file create/open/read/write, registry open/create/
   read/write/list, DNS, HTTP, dropped files. qiling already logs file and
   registry access; DNS/HTTP come from `ws2_32`/`wininet`.
3. **Entry-point error taxonomy** (Phase 1.1) surfaced in the report.
4. **Memory-access tracing + coverage** (`cfg.analysis.memory_tracing` /
   `coverage` in pegasus): per-region read/write/exec counters and a per-entry
   PC set. This is where taote can be *better*: fold it into the existing stats
   instead of a parallel profiler, and gate it behind one option.
5. **Artifact store** — content-addressed (hash) store for memory/file dumps,
   plugging into the existing `Snapshot` envelope, covering the
   `test_artifact_store` / `test_profiler_artifacts` / `test_memory_capture`
   rows.
6. **Config parity** — `QilingOptions` gains `timeout`, `max_api_count`,
   filesystem mapping list, volume specs (`host:guest`), and registry patches.
   That closes the `test_volumes` / `test_config*` rows and is a prerequisite
   for the PMA profile ports.
7. **gdbserver slice** — the `test_gdb` rows; upstream qiling ships one, the
   port deferred it.

Exit: parity map shows every analysis-surface row ported; PMA harness asserts
dll-qualified APIs and indicators (not bare names).

## Phase 4 — deliberately not ported (documented non-goals)

* **JS engine** (`test_js_*`, 54 cases) — excluded by instruction; qiling hooks
  are host-side, a JS layer is a pegasus product feature.
* **Unpacker / JIT-PE / loader classification** (`porting_jitpe`,
  `unpack_smoke`) — a packer product on top of an emulator; outside an emulator
  port's remit.
* **`EmuStruct` class library** (`test_struct`, `test_porting_struct`,
  `test_emu_struct_helper`) — superseded by Phase 2's `ntdefs` + explicit
  writers; the byte layouts are already asserted by the handler tests.

## Phase 5 — beyond pegasus (the "if not better" half)

Ordered by value:

1. **Kernel-mode drivers** — pegasus runs `PMA 10-03.sys`; taote's two
   `wdm_*.sys` still fault. Implement the driver bootstrap (KUSER/EPROCESS,
   import data in the PID-4 system process context, the `DriverEntry`/
   `IRP_MJ_*` dispatch). Closes the `test_wdm` rows *and* the last 2 sweep bins.
2. **x64 exception dispatch** — pegasus has x86 only. Port `.pdata`/`UNWIND_INFO`
   walk + VEH for C++ exceptions on x64.
3. **Deterministic replay** — record the API results (registry/files/network)
   into a profile and replay them so malware runs are bit-reproducible; the diff
   store already models half of it.
4. **Fidelity over stubs where pegasus fakes**: the `ws2_32_tcp_server` samples
   block in a real `accept` (faithful to Windows). Instead of pegasus's fake
   accept, expose a virtual clock + non-blocking option so the two samples
   terminate *and* the semantics stay honest.

## Working agreement

* Each phase = one or more commits in the house style, each with tests; the
  scoreboard table and `tests/PEGASUS_TEST_PARITY.md` are updated in the same
  commit that moves a number.
* Gate for every phase: `ctest` green twice (530+ cases), the sample sweep and
  the PMA sweep re-measured and recorded, no new `-Werror`-class warnings.
* Diagnosis tooling stays out of the tree unless it is reusable — the reusable
  ones are `tools/gap_census` and `tests/PMA` harness; ad-hoc traces are removed
  before committing (the session precedent).

## Suggested first three steps

1. Phase 0 tooling: `tools/gap_census` + the PMA test harness skeleton with the
   curated 12 cases (measurement only, `GTEST_SKIP` where the corpus is absent).
2. Phase 1.1: unsupported-API accounting + `max_api_count` + the error taxonomy
   (fixes the WRITE_UNMAPPED cluster and makes every later diagnosis cheaper).
3. Phase 1.2: the dynamic-import cluster diagnosis with the census output
   (biggest single block: 5 samples).
