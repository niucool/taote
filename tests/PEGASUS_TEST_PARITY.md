# The pegasus test-suite parity map

The reference suite is `../pegasus/tests/` (48 translation units, 357 `TEST()`
cases). taote is a port of **qiling**, not of pegasus: pegasus is a separate
C++ re-implementation that adds a report/profiler layer, an unpacker, a JS
engine and its own ctypes-mirroring struct library on top of the same
emulation core. So "passing the pegasus tests" means one of:

* **[ported]** — the test asserts an *emulator behaviour* that qiling also has.
  The taote equivalent lives in `tests/Pegasus_Compat_Test.cpp` (the
  `PegasusParity.*` suite) or an existing taote suite, asserting the same
  behaviour through the port's own surfaces (the guest stdout render, the
  `QlOsStats` API log + string log, the loader images, `QlOsWindows` state).
* **[pegasus-only]** — the test exercises a pegasus feature the qiling surface
  does not have (the report/event/artifact/profiler layer, `PegasusConfig`,
  the CLI, `EmuStruct`, the unpacker). No taote counterpart is meaningful.
* **[skipped]** — excluded by instruction (the JS engine) or because the
  upstream suite itself disables the case.

Running the reference suite is not possible against taote, and not useful
either: it links `libpegasus` and asserts pegasus's own C++ API. This map is the
authoritative record of what was read, what it asserts and where the taote
coverage lives.

## Fixtures

`tests/Pe_Sample_Runner.hpp` runs the `../pegasus/tests/bins` API samples
through the real `QlOsWindows` path: it LIEF-parses each sample's import table,
synthesizes one stub dll per imported module (a PE32+ image with a 16-byte ret
cell per export, the `tests/Pe_Stub.hpp` technique extended to every arch),
stages them into a private rootfs with the sample, runs it and captures the
guest stdout, the `QlOsStats` API/string logs and — for dll fixtures — the
DllMain/export return values.

The seven samples the parity suite drives are vendored under
`tests/data/pegasus/` (they are built from `../pegasus/tests/apis/*.c` by that
repo's own `build_all.sh`, ~180 KB total): `argv_test_x86.exe`,
`GetProcAddress.exe`, `file_access_test_x86.exe`, `file_access_test_x64.exe`,
`dll_test_x86.dll`, `dll_test_x64.dll`, `seh_test_x86.exe`.

## Per-file map

| pegasus file | tests | disposition | taote coverage / rationale |
|---|---|---|---|
| `test_argv.cpp` | `ArgvTest.ArgvPassedToExe` | **[ported]** | `PegasusParity.ArgvPassedToExe` — 10 tail arguments reach the guest (`argc = 11`, every `argv[i]` line renders, ≥10 printf calls). |
| `test_get_proc_address.cpp` | `GetProcAddressTest.MissingFunctionReturnsZero` | **[ported]** | `PegasusParity.GetProcAddressMissingFunctionReturnsZero` — the exported names resolve to mapped addresses, `ThisFunctionIsNotExportedByKernel32` answers NULL. |
| `test_file_access.cpp` | `FileAccessTest.FileAccessEmulation` (x86/x64) | **[ported]** | `PegasusParity.FileAccessEmulationX86/X64` — NtCreateFile opens `C:\myfile.txt` through the fs mapper, NtReadFile fills the buffer, the sample prints `File contained: 0x…` with the real file bytes. |
| `test_dlls.cpp` | `DllEmuTest.DllEmulationRuns` (x86/x64) | **[ported]** | `PegasusParity.DllEmulationRunsX86/X64` — three entry points (DllMain → 1, `emu_test_one` → 0x41414141, `emu_test_two` → 0x42424242), MessageBoxA/W dispatch, the message texts decode. |
| `test_seh.cpp` | `SehTest.SehDispatchEnabled`, `SehTest.SehDispatchDisabled` | **[ported]** | `PegasusParity.SehDispatchEnabled` (the full 7-line DISPATCH_SCRIPT + `In filter` / `Caught AV as expected`) and `PegasusParity.SehDispatchDisabled` (the option is `QlOsWindows::set_seh_dispatch(false)`; the AV surfaces as a write fault instead of reaching the handler). |
| `test_module_system.cpp` | `StaticImportDispatchesApiHandler`, `GetProcAddressDynamicResolution`, `PEBModulesPopulated` | **[ported]** | the static-import dispatch and the dynamic resolution are asserted in the dll / GetProcAddress tests above; `PegasusParity.PEBModulesPopulated` asserts the mapped main image and the loaded module list. |
| `test_find_files.cpp` | 8 × `WildcardMatch*` | **[ported]** | `WinApiFileapi.FindFirstFileAWildcardWalkMatchesCaseInsensitively` — the wildcard semantics are asserted through the real `FindFirstFileA` handler instead of a test-local copy of the matcher: `*.txt` folds case, `?` matches one char, a wildcard miss answers INVALID_HANDLE_VALUE + ERROR_FILE_NOT_FOUND. |
| `test_porting_winemu.cpp` | 18 | **[ported]** (subset) | `PegasusParity.ShellcodeLoadAndRun` (the blob path), `PegasusParity.ReadMemStringRoundTripsAndLogs` (the wide/ascii readers + the stats string log). The TEB read-back, the loader name lookup, the `os.call` return semantics, the per-thread last-error routing and the error-context triage are already covered by taote's `WinApiLoader.*`, `Windows_Subsystem*`, `Fcall_*`, `Thread_*` and `Snapshot.*` suites. |
| `test_porting_struct.cpp`, `test_struct.cpp`, `test_emu_struct_helper.cpp` | 23 | **[pegasus-only]** | these test pegasus's `EmuStruct`/`write_le` class library (its ctypes mirroring). The qiling port writes byte layouts directly (`os/windows/structs.hpp` packs each structure at its documented offsets), so there is no API to assert against. |
| `test_win_size_validation_all.cpp`, `test_win_size_validation.cpp`, `test_porting_ntdefs.cpp`, `test_process_parameters.cpp` | ~70 | **[portable, deferred]** | the NtDefs size/offset tables (`UNICODE_STRING`, `LIST_ENTRY`, `OBJECT_ATTRIBUTES`, `PEB`/`TEB`/`RTL_USER_PROCESS_PARAMETERS`, …). taote carries only the offsets its handlers consume (`TEB_OFF_*`, `WIN32_FIND_DATAA_*`, `SYSTEMTIME`, `SYSTEM_INFO`, `SEH_*`), asserted by the existing handler tests. A full `os/windows/ntdefs.hpp` table is the natural next parity slice. |
| `test_porting_module_name.cpp`, `test_module_name_normalization.cpp` | 10 | **[pegasus-only]** | the reference tests re-implement `normalize_mod_name` *inside the test file* (a 4-line local helper); they assert nothing the emulator does. taote's equivalent lookup path (the casefolded `get_image_by_name` walk) is exercised by the loader tests and `PegasusParity.PEBModulesPopulated`. |
| `test_volumes.cpp`, `test_porting_volumes.cpp` | 11 | **[pegasus-only]** | qiling mounts through the fs-mapper/sandbox root (`options.rootfs`); pegasus's `VolumesTest` asserts its own `host:guest` volume-spec parser, which the qiling port does not have. |
| `test_wdm.cpp` | 2 | **[skipped]** | `DISABLED_DriverLoadUnload` / `DISABLED_IrpHandlers` are disabled in the reference suite itself (the same reason the two `wdm_test_*.sys` samples stay out of the sample sweep). |
| `test_kernel_bootstrap.cpp` | 2 | **[pegasus-only]** | asserts pegasus's `WinKernelEmulator` bootstrap phase guard; the reference bodies are `SUCCEED()`/`GTEST_SKIP()` stubs plus an `#if 0` block. |
| `test_map_view_of_file.cpp` | 2 | **[skipped]** | both reference cases are `GTEST_SKIP()` ("requires capa-testfiles submodule"). taote's `MapViewOfFile` runs in the sample sweep (`kernel32_file_map_*` both reach exit 0). |
| `test_coverage.cpp` | 1 | **[pegasus-only]** | asserts pegasus's per-entry-point code-coverage report (`cfg.analysis.coverage`); the qiling surface has no report layer. |
| `test_section_access.cpp` | 2 | **[pegasus-only]** | asserts pegasus's per-section read/write/exec counters (`cfg.analysis.memory_tracing`). |
| `test_memory_capture.cpp`, `test_profiler_artifacts.cpp`, `test_artifact_store.cpp`, `test_porting_artifact_store.cpp`, `test_porting_profiler.cpp`, `test_config.cpp`, `test_config_memory_dumps.cpp`, `test_porting_config.cpp`, `test_cli_config.cpp`, `test_cli_runtime_flags.cpp`, `test_error_context.cpp`, `test_filename_override.cpp` | ~50 | **[pegasus-only]** | the pegasus configuration/report/profiler/artifact layer (`PegasusConfig`, `EmuReport`, `ArtifactStore`, the CLI flag surfaces, `load_module` from a byte blob, the rich error-context records). qiling's counterparts are `QilingOptions`/`QlOsStats`/`QlErrorBase`, which taote covers in `Profile_Test`, `Exception_Test`, `Snapshot_Test`, `Qiling_Test`. |
| `test_gdb.cpp` | 3 | **[pegasus-only]** | the gdbserver stub. The port has no gdbserver slice yet (a future phase; upstream qiling ships one). |
| `test_examples.cpp` | 5 | **[pegasus-only]** | runs pegasus's own `examples/` programs (dbgview, emu_dll, upx unpack, usb emu). |
| `test_loaders.cpp`, `test_porting_loaders.cpp`, `test_porting_pefile.cpp`, `test_porting_jitpe.cpp`, `test_porting_memmgr.cpp`, `test_module_system.cpp` (loader parts) | ~20 | **[pegasus-only]** | pegasus's image-factory/loader-classification/JIT-PE/packer scaffolding. The qiling loader equivalents (LIEF parse, section mapping, export walks) are covered by `Loader_Pe_Test` and the e2e fixtures. |
| `test_js_engine.cpp`, `test_js_hook.cpp` | 54 | **[skipped]** | the JS engine — excluded by instruction (and a pegasus-only subsystem: qiling hooks are C++/Python-side). |
| `test_pma_samples.cpp` + `pma_harness.h` + `pma_profiles.h` | 1 (12–38 cases) | **[harness landed, 0/12 green]** | the PMA corpus from `capa-testfiles` (`~/source/capa-testfiles`, 33 samples) is now wired in as `tests/Pma_Compat_Test.cpp`: the curated 12 reference cases with their reference API expectations, one child process per case (the samples are live malware and an emulation fault must not take the suite down) with a 45 s budget, ratcheted by `kGreenBaseline`. Measured: **0/12 green** (each case now also carries the reference tolerated-error set and the reference guards — 6 s timeout, `max_api_count` 600, plus a deterministic instruction budget in place of the wall clock) — every case names its blocker (the `FETCH/WRITE_UNMAPPED` clusters, `UC_ERR_EXCEPTION`, `UC_ERR_INSN_INVALID`, the 14-01 hang, the kernel `.sys`), and the cases that do run lack the wininet/registry/profile surface the reference expectations need. That per-case table is the block's Phase 1/2 work. Corpus-wide raw sweep 13 of 32 exit 0 (with the guard-free driver; the reference guards on the curated cases are separate); the reference case list lives at `../pegasus/tests/test_pma_samples.cpp`. |
| `smoke_test.cpp` | 52 | **[pegasus-only]** | the pegasus smoke suite (its `File`/`MemoryManager`/`Profiler`/`ArtifactStore`/`Gdt`/`NtStruct` classes, `nlohmann` JSON). The `GdtTest.AccessBits` / `NtStructTest` assertions have no qiling surface; the descriptor encoding is covered by `Arch_X86_Test`. |
| `test_leak_detector.cpp` | — | **[pegasus-only]** | pegasus's leak-detector harness (no `TEST()` cases). |
| `tests/apis/*` (the TCC sample sources) | — | **[ported]** | the produced binaries are the sweep corpus: 97 of the 101 bins run to exit 0 (the 2 `ws2_32_tcp_server` samples block in a real `accept`, the 2 `wdm_*.sys` drivers are kernel-mode). |

## What the parity pass fixed in the port

Reading the reference tests surfaced four real defects (each is now covered by
a taote test):

1. **The 64-bit parameter slot count on the 32-bit fcall tables.** The windows
   `fcall_table_` entries were built through the `unique_ptr<cc::QlCC>`
   constructor, which cannot see the concrete convention and therefore left
   every accessor at one slot: an x86 `unsigned __int64` head parameter
   (`__stdio_common_vfprintf`'s `_Options`) consumed one stack slot instead of
   two and shifted every following argument — `_Format` was read out of the
   `_Stream` cell and the x86 MSVC samples' formatted output degenerated into
   the "read at address 1" walk. `QlFunctionCall` now rebinds `getNumSlots`
   through a concrete-type owned-pointer constructor.
2. **`RtlInitUnicodeString` was a no-op passthru.** The usermode samples
   initialize their `OBJECT_ATTRIBUTES` name through it, so the
   `UNICODE_STRING` stayed stack garbage and every `NtCreateFile` name walk
   returned `STATUS_OBJECT_NAME_INVALID`.
3. **`read_wstring` never reached the stats string log** (the upstream delegates
   to `read_string`, which logs; the port's standalone wide walk dropped the
   call), so wide strings were invisible to the tooling surface.
4. **Two NT file APIs were missing**: `NtOpenFile` (the `NtCreateFile` twin)
   and `NtReadFile` (the `NtWriteFile` twin) — the usermode samples resolve
   the quartet through `GetProcAddress` and read their input through it.

Also corrected while porting: the dll fixtures now hand the
`(HINSTANCE, DLL_PROCESS_ATTACH, NULL)` arguments to the entry point (the CRT
startup branches on the reason — without it `DllMain` was never called and the
startup answered 0), and `MessageBoxA/W` decode their text/caption so the
dialog content reaches the string log.

## Phase 1.9 — the qiling-parity differential

| surface | status |
| --- | --- |
| reference trace (`tools/qiling_reference_runner.py`) | ported: `stats.syscalls`/`strings`, guest stdout, exit code, unicorn error text, plus the reference's own "not implemented" warnings |
| taote trace (`tools/parity_trace.cpp`) | ported: the same fields from `QlOsStats` + `entry_point_errors()`, plus `--dump-imports` (the loader's `import_symbols` map *and* the guest's own IAT slots) and `--code-trace` (per-instruction `(pc, size)` over a pc window, mirrored on the reference runner) for "why did the guest call that" and "where did the two guests take different code" questions |
| normalization + diff (`tools/parity_vs_qiling.py`) | ported: addresses -> `sample+0xNN`, guest paths -> `<sample>`, pointer retvals -> `ptr`, one error vocabulary for both sides |
| PMA differential baseline | **10/32 match** (`01-02.exe_`, `03-03.exe_`, `03-04.exe_`, `10-03.exe_`, `12-02.exe_`, `16-01.exe_`, `16-02.exe_`, `19-02.exe_`, `20-02.exe_`, `21-01.exe_`), 0 environment, 15 `reference_limit` (`01-01.exe_`, `01-04.exe_`, `06-03.exe_`, `11-02.dll_`, `11-03.dll_`, `11-03.exe_`, `11-01.exe_`, `12-01.dll_`, `14-02.exe_`, `16-03.exe_`, `12-03.exe_`, `12-04.exe_`, `17-03.exe_`, plus the reference's own timeouts on `14-01.exe_` and `18-01.exe_`), 4 diverged, 2 blocked, raw taote exit-0 **24/32**, clustered: dispatch-count 23, extra-dispatch 18, missing-dispatch 10, first-divergence 12, exit-code 5, error-class across the invalid_write/invalid_read/invalid_fetch pairs, stdout 2, environment 1 |
| API records | `ApiCallRecord` carries `dll` + rendered `params` (strings as text, others as hex); `PegasusParity.ApiRecordsCarryTheDllAndRenderedArguments` pins a `kernel32.dll`/`lpLibFileName='ntdll.dll'` record and a scalar one |
| error taxonomy | an entry-point error record carries `{type, message, address}` (the pegasus `get_error_info(addr)` shape), emitted as the trace's `errors` array; `PegasusParity.SehDispatchDisabled` asserts the faulting pc is recorded |
| indicators | `QlOsStats::indicators()` records `file_*`/`reg_*`/`net_*` `(kind, target)` events from the performing handlers; `WinApiStats.IndicatorsRecordFileAndRegistryAccess` pins the registry and file ones |
| regf reader | `WinApiRegistry.RegHiveReadsARealHiveFile`: the base block + hbin + `nk` walk, the `lf` subkey list and the `vk` value walk (a `REG_SZ` read back as a string) over a real hive file, plus the missing-key and missing-value arms |
| handler surface | `tools/gap_census /tmp/pma_corpus`: 169 unresolved import names, none of them implemented in the reference — taote's surface is a superset (the runtime-import samples are scored by the differential; the 4 that diverge fault in the guest) |
| API replay store | `--record-api` / `--replay-api` (`QilingOptions::api_record_path`/`api_replay_path`): records `name\tretval\tlasterror` per dispatch, re-checks a later run against it (naming a `replay_mismatch`) and, with `--replay-serve`, answers from the recording without running the handler (pointer answers above 0x10000 are re-derived; an API that writes guest memory cannot be reproduced by its return value, which is why verify-only is the default); `WinApiReplay.StoreRecordsAndVerifiesADispatchSequence` |
| x64 unwinder | `WinApiNtdll.RtlVirtualUnwindReplaysThePrologueCodes` pins the UNWIND_INFO replay (PUSH_NONVOL/ALLOC_*/SET_FPREG/SAVE_*/PUSH_MACHFRAME), the Rip/Rsp update, EstablisherFrame and the EHANDLER handler RVA |
| loader layouts | `WinApiLoader.X86LoaderLayoutsAreTheUpstreamWordSizeOnes` pins the 32-bit column (TEB 420, PEB 1148, LDR_DATA 48, LDR entry 156, UNICODE_STRING 8, `fs:[0x30]`) beside the 64-bit one; `WinApiLoader.X86TebExceptionListStartsAtZeroLikeTheReference` pins the TEB ExceptionList at 0 and the PEB pointer at `fs:[0x30]` |
| verdicts | `match` / `environment` (module handle only the harness can synthesize) / `reference_limit` (the reference faulted on an import it leaves unimplemented while taote ran on, taote's extras all start at or after the first such import — or the reference never finished at all (its own cost on a spin loop, nothing to diff) — or, with `reference_lacks_handler`, the reference lacks a handler taote has and its guest drifted from that dispatch on, granted on attribution only — every finding with a `from call #N` at or after the first extension dispatch — so a taote fault does not hide it from the raw sweep) / `diverged`; faulted runs skip the exit-code compare (the reference reports 0 where taote reports `STATUS_ACCESS_VIOLATION`) and negative return values fold to their two's-complement 64-bit value before comparing |
| starter corpus | `argv_test_x86.exe`, `file_access_test_x86.exe` — both clean (taote's extra `_initterm`/`_initterm_e`/`__acrt_iob_func` dispatches are imports the reference does not implement) |
| ctest smoke gate | `Tools.ParityVsQilingSmoke` (`--require-match 1`; skips with 77 when the reference checkout or a qiling-deps python is absent) |
| reference rootfs seeding | `tools/mkreg_hive.py` (minimal valid hives) + `tools/stub_dlls.py` (import-stub DLLs) — the reference cannot resolve PE imports on a Linux host without them |
