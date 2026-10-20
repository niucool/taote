# PLAN — taote on par with pegasus (and beyond)

Goal: taote should match pegasus on **every measurable emulation and analysis
capability**, and beat it where a qiling port has an inherent edge. The plan is
evidence-driven: each phase raises a number on the scoreboard below, and no
phase closes without its tests.

## 0. The scoreboard (what "on par" means, numerically)

| metric | pegasus | taote today | target |
|---|---|---|---|
| API sample sweep (`../pegasus/tests/bins`, 101 bins) | n/a (their suite asserts dispatch only) | **97 exit 0**, 2 block in `accept`, 2 kernel `.sys` | 99+ (drivers land) |
| PMA corpus (`~/source/capa-testfiles`, 32 PE samples) | 12 curated cases green (their CI), 38 with `PEGASUS_PMA_FULL=1` | **14 exit 0** (32-sample sweep), **1/12 green** (curated ctest cases, now with the reference guards) | ≥ 30 exit 0, all curated cases green |
| reference-suite parity (`../pegasus/tests`, 357 cases) | 357 | **12 ported + 4 ported clusters**, rest mapped in `tests/PEGASUS_TEST_PARITY.md` | every *portable* row ported, none "deferred" |
| taote suite | — | **538 passed / 0 failed / 3 skipped** | grows with every phase, stays 0-failed |
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
   The software-interrupt half is now wired too: a `UC_HOOK_INTR` callback
   stages `int3` as `STATUS_BREAKPOINT` and any other `int n` as
   `STATUS_ILLEGAL_INSTRUCTION` through the same walk, and declines (leaving the
   fault on the ordinary path) when no frame is registered.
4. **Hangs (14-01.exe).** The guards from 1. are the mechanism; add the
   virtual-clock slice so `Sleep`/timeouts do not stall the run.
5. **The AV-exit tail (14-02.exe).** An unhandled exception should end the run
   with `STATUS_ACCESS_VIOLATION` *and* a recorded entry-point error, not a bare
   fault text.
   Status: **landed.** An unhandled `invalid_*` fault sets the guest exit code
   to `STATUS_ACCESS_VIOLATION` (0xC0000005) next to the error record, and the
   sample runner reads the code on the faulted path too (it used to report -1).
   Asserted by the `SehDispatchDisabled` twin.

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

## Phase 1.9 — qiling-parity differential (acceptance criterion, highest priority)

The reference implementation is now available locally (`~/source/qiling`, the
Python reference). Every earlier judgement about a sample's behaviour is
subordinate to it: **taote must reproduce what qiling does**, and only then what
pegasus does.

1. **Read the reference contract**: `docs/USAGE.md`, `docs/API.md`,
   `docs/SETUP.md`, the PE examples (`examples/crackme_x86_windows.py`,
   `cachedlls_x8664_windows.py`, `adcache_x86_windows_debug.py`,
   `hello_x8664_windows_customapi.py`) and the PE cases under `tests/`, to pin
   the standard invocation (rootfs, argv/env, profile, verbosity) and the
   observable output (API dispatch sequence, string log, guest stdout, exit
   code, error classification).
2. **The differential harness** (`tools/parity_vs_qiling`): run the same PE, with
   the same rootfs/profile/argv/env/hook set, under both emulators; normalize
   (addresses -> symbols, timings, host paths) and diff the dispatch sequence,
   guest stdout, exit code and entry-point error class. The report clusters
   differences by root cause, and those clusters — not per-sample patches —
   become the work order. 1.2's per-sample disassembly work is superseded
   wherever it conflicts with the reference semantics.
3. **Then** the pegasus bar: `tests/bins` 97/101 and the PMA corpus >= 30 exit 0.

Status: **step 1 (read) + step 2 (the differ) landed.**

What the reference contract turned out to be (`docs/USAGE.md`, `docs/API.md`,
`docs/SETUP.md` are one-line pointers to docs.qiling.io, so the contract was read
off the code and the examples):

* invocation: `Qiling([path] + argv, rootfs, verbose=QL_VERBOSE.X)` then `ql.run()`
  (`qltool run -f FILE --rootfs DIR` is the same thing from the CLI); the rootfs
  is the only ambient input, and it must carry `Windows/registry/*` plus the
  system DLL *images* under `Windows/System32`;
* the observable surface: `ql.os.stats.syscalls` (name -> calls with `params`,
  `retval`, `address`, `retaddr`, `position`, recorded by `QlOsStats.log_api_call`
  from `QlOs.call`), `stats.strings`, the guest stdout (`ql.os.stdout`), the guest
  exit code (`ql.os.exit_code`) and - the one place the reference has no
  vocabulary of its own - the unicorn error text;
* dispatch is `hook_winapi` on `pc in loader.import_symbols`: an import with no
  handler only logs `api X (dll) is not implemented` and falls through the stub
  cell, which is *not* a dispatch record. That single fact explains most of the
  raw divergences, and the harness now uses it to separate "taote extends the
  reference" from "taote disagrees with the reference".

The differ: `tools/parity_vs_qiling.py` (+ `tools/qiling_reference_runner.py`,
`tools/parity_trace.cpp`, `tools/stub_dlls.py`, `tools/mkreg_hive.py`). It seeds a
private rootfs (hives + import-stub DLLs generated from the corpus's own import
tables), runs both emulators with the same sample/argv/guards, normalizes
(addresses -> `sample+0xNN`, guest paths -> `<sample>`, pointer return values ->
`ptr`, both sides' error text -> one vocabulary), diffs dispatch sequence /
per-call return values / stdout / exit code / error class, and prints a report
plus a cluster list keyed by root-cause signature. A dispatch taote makes where
the reference logged "not implemented" is reported as an extension, not a
divergence.

Exit criteria (this phase): the differential clean on the named starter corpus
(`argv_test_x86.exe`, `file_access_test_x86.exe`), gated in ctest as
`Tools.ParityVsQilingSmoke` (skips when no reference checkout / qiling-deps
python is present). Both are clean today; taote's only extra dispatches are
`_initterm`, `_initterm_e` and `__acrt_iob_func`, which the reference leaves
unimplemented.

First clusters the differ found, and what they turned out to be:

* **fixed (harness)**: the reference maps guest paths against its rootfs, so a
  sample living outside it raised `'<path>' is not in the subpath of '<rootfs>'`
  from its own path mapper and aborted the run with `Windows API Implementation
  Error`. That is what made GetProcAddress.exe and most PMA samples look like
  reference handler faults. The differ now stages each sample inside the seeded
  rootfs; GetProcAddress.exe went from 162 aborted calls to 216 calls to exit 0.
* **diagnosed, open**: GetProcAddress.exe's remaining divergence is *not* in
  `FreeLibrary` at all - it is `LoadLibraryExW`. At dispatch #26 the reference
  answers a module handle (`0x18000f000`) for a request where taote answers 0;
  the guest therefore takes its success path (-> `GetProcAddress` at #27, and
  `FreeLibrary` at #214), while taote's guest takes the error path (-> an extra
  `GetLastError` at #27) and never reaches either call. taote *does* answer a
  handle for the same API at #138 (`0x14003f000`), so the difference is which
  requests it is willing to satisfy - the reference synthesizes a module for a
  request taote declines.
* **attempted and reverted**: answering a stable synthetic module handle
  (`0x7f000000 + fnv1a(name) % 0x0fff * 0x1000`) from `LoadLibraryA`/
  `LoadLibraryExW` when the rootfs carries no such module. It moved the trace
  (taote started dispatching `GetProcAddress` from #25) but did **not** reach
  parity: 211 calls vs the reference's 216, still no `FreeLibrary`, and the PMA
  raw sweep stayed at 14/32. A pseudo-handle that maps no image is not the
  reference's behaviour - the reference maps a synthesized *image with an export
  table*, which is what makes the subsequent `GetProcAddress` resolve and the
  guest reach `FreeLibrary`. The next unit has to load a real synthesized module
  image (taote's loader already builds those for imports) rather than a numeric
  handle.
* **root cause narrowed to rootfs content, not semantics**: `QlLoaderPE::load_dll`
  (`qiling/loader/pe.cpp`, the `!std::filesystem::exists(dll_path_host, ec)`
  gate) answers 0 for a module the rootfs does not carry, and taote has no
  loader-side synthesis at all - the import stub DLLs taote runs against are the
  ones *written into the rootfs* by `tests/Pe_Sample_Runner.hpp` and (for the
  differential) by `tools/stub_dlls.py`. The reference answers a base for the
  same request only because in this run it was handed a real image with a real
  export table, so its guest's later `GetProcAddress` can resolve where taote's
  cannot. That is an environment difference (nobody has the genuine
  `user32.dll` on a Linux host), not a handler-semantics difference: the
  differential must classify it as such instead of chasing it. Next unit:
  teach `parity_vs_qiling.py` to mark a divergence as `environment` when the
  reference's answer comes from a module the harness itself synthesized with a
  different export set, and only chase the remainder.
* **not a divergence**: taote's CRT startup dispatches `_initterm`,
  `_initterm_e` and `__acrt_iob_func`, which the reference leaves unimplemented -
  the harness reports those as extensions.
* PMA 18-01.exe is differential-clean (`LoadLibraryA`, `GetProcAddress`,
  `ExitProcess`, same return values).

## Phase 2 — the qiling-surface completions the corpora need

Driven by `tools/gap_census` over both corpora:

* **The census top-N handlers** across kernel32 / ntdll / advapi32 / user32 /
  ws2_32 / ole32 / wininet behind the current long tail.
* **Registry hive reads** — the one accepted deferral (upstream delegates to
  `python-registry`). Malware that reads real hives needs it: implement a
  minimal NT registry hive parser (`nk`/`vk`/`sk` cells, value marshalling)
  behind `RegHive`, with corpus fixtures chosen from the PMA set that query
  installed-software keys.
* **`os/windows/ntdefs.hpp`** — the `test_win_size_validation_all` rows as a
  size/offset table with a test, replacing the ad-hoc offsets the handlers
  carry. **Landed** for the layouts the handlers actually write
  (`UNICODE_STRING`, `OBJECT_ATTRIBUTES`, `IO_STATUS_BLOCK`, `EXCEPTION_RECORD`,
  `EXCEPTION_POINTERS`, `CONTEXT`, `MSG`, `KEY_VALUE_FULL_INFORMATION`), with
  the x86/x64 columns, a `kLayouts` table and a `ptr_field` helper; `seh.cpp`'s
  record writer now reads its offsets from it. The `PegasusParity.NtDefsLayout`
  test pins every value. The `PEB`/`TEB`/`RTL_USER_PROCESS_PARAMETERS` rows are
  still pending (they live in `structs.hpp` already and need the same table).

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
