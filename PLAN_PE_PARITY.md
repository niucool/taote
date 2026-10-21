# PLAN — Windows PE first: on par with upstream qiling, then pegasus

Goal (the directive this document sequences): **taote supports Windows PE first.**
Concretely, in order:

1. **Every Windows-PE-related case in `../qiling/tests/` passes against taote.**
2. **taote matches `../pegasus`** — the sample sweep and the portable part of
   `../pegasus/tests/` (`tests/PEGASUS_TEST_PARITY.md`), plus the PMA corpus in
   `~/source/jim/capa-testfiles`.

The plan is measurement-first, like `PLAN_PARITY.md`: every phase raises a number
below, and a phase does not close without its tests.

## 0. Scoreboard

| metric | upstream | taote today | target |
|---|---|---|---|
| qiling PE suite parity, **stub mode** (default) (`../qiling/tests/test_pe.py`, `test_peshellcode.py`, `test_windows_cpp_*.py`) | passes **on a Windows host only** (its CI runs `test_pe.bat`, which needs `dllscollector.bat` to copy the real System32 DLLs) | **26 passed / 10 skipped / 0 failed** of 36 ported cases (`tests/QilingPe_Compat_Test.cpp`) | all but the documented deferrals |
| qiling PE suite parity, **real-dll mode** (`TAOTE_WINDOWS_ROOTFS=~/source/jim/rootfs-win7`) | the reference's own mode | **21 passed / 0 skipped / 15 failed** | all 36 |
| qiling PE suite parity, real-dll mode (`rootfs-win7-crt`, Win7 + Wine UCRT) | — | **21 passed / 0 skipped / 15 failed** | — |
| pegasus sample sweep (`../pegasus/tests/bins`, 101 bins) | asserts dispatch only | **101 exit 0** | maintained |
| pegasus suite parity (`PegasusParity.*`, 18 cases) | 357 cases | **18 passed** | maintained |
| PMA corpus (`~/source/jim/capa-testfiles`) | 12 curated | **1/12 curated** (raw sweep 24/32 exit 0) | 12/12 |
| taote suite | — | **567 passed / 0 failed / 15 skipped** (582 cases) | 0 failed |

The two modes are reported separately because they measure different things: stub
mode is deterministic and is what the default suite runs; real-dll mode is the
reference's own configuration and is the only mode in which the C++/SEH cases can
even attempt to run. **Neither mode is a superset of the other today** — five
cases pass in stub mode and fail with real DLLs (`PeWinX8664Clipboard`,
`PeWinX8664Tls`, `PeWinX8664Fls`, `PeWinX86Argv`, `PeWinX86RegDemo`), because the
real DLLs execute vendor code the emulator has not finished covering.

### 0.1 Per-case state

`stub` = default mode; `win7` = `TAOTE_WINDOWS_ROOTFS=~/source/jim/rootfs-win7`
(real Microsoft System32, no Universal CRT); `win7crt` = the same tree with
Wine's `ucrtbase`/`msvcp140`/`vcruntime140` injected.

| case | stub | win7 | win7crt | note |
|---|---|---|---|---|
| PeWinX86Hello | pass | pass | pass | |
| PeWinX8664Hello | pass | pass | pass | |
| PeWinX86FileUpx | pass | pass | pass | |
| PeWinX8664FileUpx | pass | pass | pass | |
| PeWinX86Cmdln | pass | pass | pass | `_acmdln`/`__p__acmdln` data-export shim |
| PeWinX8664Cmdln | pass | pass | pass | |
| PeWinX86Crackme | pass | pass | pass | patches + stdin |
| PeWinX8664CustomApi | pass | pass | pass | 12/17/17 `puts` intercept |
| PeWinX8664ReturnFromMainStackPointer | pass | pass | pass | `QL_STOP.STACK_POINTER` |
| PeWinX8664ReturnFromMainExitTrap | pass | pass | pass | `QL_STOP.EXIT_TRAP` |
| PeWinX86ReturnFromMainStackPointer | pass | pass | pass | |
| PeWinX86ReturnFromMainExitTrap | pass | pass | pass | |
| PeWinX86GetLastError | pass | pass | pass | |
| PeWinX86NtQueryInformationSystem | pass | pass | pass | |
| PeWinX86UselessDisk | pass | pass | pass | `\\.\PHYSICALDRIVE0` mapper |
| PeWinX86Wannacry | pass | pass | pass | |
| PeWinAlKhaser | pass | pass | pass | |
| PeWinX8664Libcache | pass | pass | pass | fresh parse (no `QlPeCache`) |
| WindowsShellcodeX86 | pass | pass | pass | |
| ReadPtr32 | pass | pass | pass | |
| ReadPtr64 | pass | pass | pass | |
| PeWinX8664Clipboard | pass | **fail** | **fail** | real DLLs: faults in the sample's own startup (`0x14001233a`) |
| PeWinX8664Tls | pass | **fail** | **fail** | real DLLs: `UC_ERR_WRITE_UNMAPPED` at `0x140001172` after `EtwNotificationRegister` |
| PeWinX8664Fls | pass | **fail** | **fail** | same shape as Tls (`0x140001182`) |
| PeWinX86Argv | pass | **fail** | **fail** | real DLLs: jumps to `0x70000000` (non-executable) |
| PeWinX86RegDemo | pass | **fail** | **fail** | real DLLs: jumps to `0x70000000` after `RegOpenKeyW` |
| PeWinX86GandcrabProfileChangesBehaviour | skip | **fail** | **fail** | needs real DLLs (§Phase C) |
| PeWinX86Multithread | skip | **fail** | **fail** | needs live thread switching (§Phase D) |
| CppHelloWorldX86 | skip | **fail** | **fail** | needs the Universal CRT (§Phase B) |
| CppTypesX86 | skip | **fail** | **fail** | needs the Universal CRT |
| CppHelloWorldX8664 | skip | **fail** | **fail** | needs the Universal CRT |
| CppTypesX8664 | skip | **fail** | **fail** | needs the Universal CRT |
| SoftSehX8664 | skip | **fail** | **fail** | needs the Universal CRT |
| SoftCppExX8664 | skip | **fail** | **fail** | needs the Universal CRT |
| CppExUnhandledFilteredX8664 | skip | **fail** | **fail** | needs the Universal CRT |
| CppExUnhandledUnfilteredX8664 | skip | **fail** | **fail** | needs the Universal CRT |

The ten stub-mode skips are exactly the ten cases that need something the stub
rootfs cannot provide: eight need the real C++ runtime, one needs live thread
switching, one needs the real system DLLs for the malware's environment probing.
They are `GTEST_SKIP`ped with a reason rather than silently passing, and each one
runs (and fails loudly) in real-dll mode.

Run the PE parity suite alone:

```bash
./build/tests/qiling_tests --gtest_filter='QilingPeCompat.*'
```

## 1. The harness (`tests/QilingPe_Compat_Test.cpp`)

One `TEST()` per upstream case, named after it, so a red case names the upstream
case it fails. Each case drives the same fixture from the upstream rootfs
submodule (`../qiling/examples/rootfs`, override with `TAOTE_QILING_ROOTFS`)
through `tests/Pe_Sample_Runner.hpp`.

Two run modes:

* **stub mode (default, deterministic).** The sample's import table is read with
  LIEF and one stub dll per imported module is synthesized into a private rootfs
  (a PE image whose exports are 16-byte `ret` cells). The guest reaches the same
  `QlOsWindows` handlers either way. This is the upstream's *absence* of a
  Windows host, handled explicitly: the reference itself has no stub path.
* **real-dll mode (opt-in).** Set `TAOTE_WINDOWS_ROOTFS` to a directory holding
  `x86_windows/Windows/System32` and `x8664_windows/Windows/System32`; each
  fixture then runs against the real system DLLs, the way the upstream runs on
  Windows. The fixture is auto-staged into `<rootfs>/Windows/<name>`. The three
  trees measured in §0.1 are `~/source/jim/rootfs-win7` (real Microsoft Win7
  System32), `~/source/jim/rootfs-win7-crt` (the same tree with Wine's
  `ucrtbase`/`msvcp140`/`vcruntime140`), and `~/source/jim/qiling-rootfs` (a full
  Wine builtin set — note its `System32` is a symlink into `/tmp/winpkg`, so it
  is not durable).

`REQUIRE_REAL_DLLS()` gates the cases that cannot run on synthesized stubs (the
C++/SEH fixtures and GandCrab); in stub mode they skip with a reason, in real-dll
mode they run and report their real failure.

The zipped malware fixtures (`wannacry.bin.zip`, `al-khaser.bin.zip`,
`GandCrab502.bin.zip`, `UselessDisk.bin.zip`) are extracted with `unzip -P
infected` into a temp dir on first use (the rootfs README's password).

Diagnostics: `TAOTE_PE_TRACE=N` prints the last `N` retired pcs when a case
faults — the tool for the "where did the guest leave the reservation" question.

## 2. What this pass measured and fixed

### 2.1 The structural finding

Upstream's PE suite is **Windows-host-only**: `build-ci.yml`'s Linux job never
runs it, and `test_pe.bat` first runs `examples/scripts/dllscollector.bat`, which
copies `%WINDIR%\System32` and `%WINDIR%\SysWOW64` (plus registry hives) into
`examples/rootfs/*_windows/`. The rootfs git submodule carries **only** the
sample binaries — no system DLLs. So "pass the qiling PE tests" on this Linux
box means either

* (a) a stub-dll rootfs (what the suite does by default — the CRT/vendor code
  that lives *inside* those DLLs cannot run, see §3), or
* (b) a real Windows DLL set supplied by the user.

Wine's builtin PE DLLs are an appealing (b) substitute and were tried:
`apt-get download libwine` gives `x86_64-windows/` and `i386-windows/` trees
with `kernel32.dll`, `kernelbase.dll`, `ntdll.dll`, `ucrtbase.dll`,
`msvcrt.dll`, `vcruntime140.dll`, `msvcp140.dll`, … A rootfs built from them
**segfaults the loader** (crash inside the load walk; no fixture reaches its
entry point). Recorded as an open item: either the loader has an out-of-bounds
on those images or the images use a PE feature LIEF/the loader mishandles. Until
that is fixed, mode (b) needs real Windows DLLs collected on a Windows host.

### 2.2 Defects fixed on the way

1. **The profile cross-file merge was over-strict.** `IniConfig::read_string`
   rejected a duplicate *option* even when it came from a different file, so
   `windows_gandcrab_user.ql` (`[SYSTEM] permission = user`, layered over
   `windows.ql`) failed to load. CPython's `configparser` tracks
   `elements_added` *per read*: a cross-file duplicate overwrites, an in-file
   duplicate raises. Fixed with `options_added_this_read`.
2. **`QlOs::set_api(..., CALL)` had no effect on Windows.** `hook_winapi` never
   consulted `user_defined_api[CALL]` (upstream's first line of dispatch), so a
   user replacement was silently ignored. Now: a CALL replacement runs instead
   of the handler (upstream's `QlErrorSyscallError("Windows API Implementation
   Error")` on a throw) and does its own frame unwinding.
3. **The ENTER/EXIT intercepts did not exist for Windows.** Added
   `QlOs::set_api_enter/set_api_exit` (typed, with the *resolved* params —
   `fncc.py` hands the decoded dict to the hooks) and wired them into the
   dispatch; `os/windows/fncc.hpp: call_api()` is the `@winsdkapi` wrapper
   analogue, so a CALL replacement can keep the ENTER/EXIT chain alive.
   Deviation documented: the C++ handlers take `const` params, so an exit hook
   observes a handler's rewrite by re-resolving the guest memory.
4. **`_acmdln` / `_wcmdln` (data exports) read the stub's `ret` fill as a
   pointer.** A real msvcrt exports the *variable*; the synthesized stub can
   only export a code cell, so the CRT read `0xc3c3c3c3` as `char*`. The runner
   now writes the command line (narrow and utf-16le) into the stub's export cell
   (`tests/Pe_Sample_Runner.hpp: patch_data_export_slots`), which is exactly the
   layout the real export implies. Unlocks `cmdln32.exe`, `cmdln64.exe`.
5. **The nested-emulation scope.** An API handler that runs guest code
   (`_initterm`, the driver init call) re-enters `run()`; a fault there was
   recorded as the program's entry-point error and pushed `run()` into the
   process-exit path. `QlOsWindows::NestedRun` marks the scope so the handler
   owns the failure.
6. **`DllMain` was driven through the wrong calling convention — the attach
   path never ran at all.** `pe.py call_dll_entrypoint` selects CDECL
   explicitly (`fcall = self.ql.os.fcall_select(CDECL)`); the port used the
   *ambient* `ql.os().fcall()`, i.e. whatever the last API dispatch had selected.
   Measured at msvcp140's entry with the ambient fcall: `rcx`, `rdx` and `r8`
   were all **zero** (and on an x86 guest the stack argument slots were never
   written). The guest therefore read `fdwReason == 0` (= `DLL_PROCESS_DETACH`),
   took the detach branch at its first `cmp $1,%edx`, and returned FALSE without
   executing any CRT attach path — which is why `std::cout` stayed zero-filled
   and every C++ fixture died dereferencing it. With the explicit CDECL
   selection the arguments land correctly (`rcx = dll_base`, `rdx = 1`, `r8 = 0`)
   and msvcp140's CRT init runs its gates: the `.data` state words at
   `+0x94250`/`+0x94290` go to 1 and the DllMain counter starts incrementing.
   This was found by logging the faulting pc on a DllMain bail — a
   `DllMain bailed` line with no address is not actionable, and the version with
   the address pointed straight at the `cmp`.
7. **Real-dll import groups were dropped whole, leaving raw hint/name RVAs in
   the IAT.** Four paths did `continue` for a group instead of answering it: a
   missing export table for the loaded module, a module that failed to load, a
   missing symbol, and a missing api-ms-win-* image. The first two now answer
   every entry from the unbound-import stub page (as the last two already did).
   A slot left holding its hint/name RVA is executed by the guest as code — that
   is the `UC_ERR_FETCH_UNMAPPED` at `0x20a88` / `0x24c6` shape the real win7
   DLLs produced. After the fix the clipboard fixture's ucrtbased group reads as
   stub cells (`0x4001xx`) and its first fault moves into the sample's own
   startup code.
8. **Unbound imports were executed as pointers.** (From the same pass, §2.1
   mode (b).) An import no loaded image exports used to leave the slot holding
   its raw hint/name RVA; then Win7's msvcrt (no `_initialize_onexit_table`)
   sent msvcp140's CRT startup straight into `0x90fa4`. Unresolved slots now
   point into a lazily-mapped page of `xor eax,eax; ret` cells, one per symbol
   name. Caveat, learned the hard way: a zero answer is only valid for
   *functions*. UCRT's `___lc_locale_name_func`, `___mb_cur_max_func` and
   `__pctype_func` return **data pointers** and the guest dereferences the
   result immediately (`mov 0x8(%rax),%rcx` → fault at `0x8`), so a stub cannot
   stand in for them — see Phase B.

## 3. The failure clusters left (and their phases)

### Phase A — real system DLLs (unblocks 8 cases + makes the suite faithful)

`CppHelloWorld*`, `CppTypes*`, `SoftSeh`, `SoftCppEx`, `CppExUnhandled*` import
`MSVCP140.dll` (`std::cout`, the stream statics — a *data* export read as
`std::ostream&`) and `VCRUNTIME140.dll`; their static initializers run C++
library code. No stub can provide it. Two ways forward:

1. **Fix the loader crash on Wine's PE images** (preferred: it makes the suite
   runnable on any Linux box). Protocol: bisect `load_dll` over a single
   `kernel32.dll` from the Wine tree with a minimal fixture; the crash is a
   host-side segfault, so a debug build with `-fsanitize=address` should name it.
2. **Collect real DLLs on a Windows host** (`dllscollector.bat`) and run with
   `TAOTE_WINDOWS_ROOTFS`. The suite already supports it.

### Phase B — the Universal CRT (the eight C++/SEH cases)

Superseded the old `_initterm`/`_initterm_e` framing. Those two names now have
**no handler on purpose** (the reference registers neither), so a guest with a
real CRT executes its own initializer table; on the stub rootfs the call lands on
the synthesized `ret` cell. What actually blocks the C++ cases is upstream of
that, and it is now measured end to end:

* The `DllMain` drive used to take the *detach* branch (defect 6). Fixed — the
  attach path runs, its gates pass (`.data +0x94250`/`+0x94290` set, the
  `_initterm_e` table at `+0x517c8..+0x517d8` walking its single entry), and
  msvcp140 proceeds to the winapi-thunk/bootstrap stage.
* That stage imports the **Universal CRT** surface: `___lc_locale_name_func`,
  `___mb_cur_max_func`, `___lc_codepage_func`, `__pctype_func`,
  `_initialize_onexit_table`, `_crt_atexit`, `_execute_onexit_table`. The first
  four return *data pointers* that the guest dereferences immediately, so the
  answer-0 stub page cannot substitute for them: with Win7's msvcrt (which
  exports none of them) msvcp140's startup dies at `mov 0x8(%rax),%rcx` with
  `rax == 0` — measured at `msvcp140+0x1c44`.
* **Windows 7 predates the Universal CRT entirely** (`ucrtbase.dll` ships only
  from KB2999226 on), and `rootfs-win7`'s VC++ 2015 binaries were collected
  *without* `ucrtbase.dll`. So the pure Win7 tree cannot ever run these.
* `rootfs-win7-crt` injects Wine's `ucrtbase.dll` into that tree, but Wine's
  UCRT imports wine-only `ntdll` exports (`__wine_dbg_get_channel_flags`,
  `__wine_dbg_header`, `__wine_dbg_output`, `__wine_dbg_strdup`) that real Win7
  `ntdll` does not export; the stubbed zero answers leave its `DllMain` bailing
  in its own code (`ucrtbase+0x3ddd9`), after which msvcp140's printf path
  recurses until the guest stack is exhausted.
* A **coherent Wine set** (`~/source/jim/qiling-rootfs`, 750 DLLs incl. Wine's
  own `ntdll`) gets further — ucrtbase's `DllMain` runs `_set_app_type` /
  `_set_fmode` and the sample's own CRT startup completes — but `std::cout` is
  still unconstructed, and the same tree makes `PeWinX86GetLastError` throw an
  uncaught `QlErrorBase` that terminates the test binary (a defect to fix before
  that mode can be used: the Wine `System32` is also a symlink into `/tmp`).

**Phase B action:** collect `ucrtbase.dll` (x64 + x86) and the
`api-ms-win-crt-*.dll` set from the machine that produced `rootfs-win7.zip` —
it runs the VC++ 2015 redistributable, so the Universal CRT is present there,
it simply was not copied. That single harvest is what the eight cases need; no
emulator change is implied by the measurements above.

### Phase C — `GandCrab502.bin` (`PeWinX86GandcrabProfileChangesBehaviour`)

The case is now the upstream shape (§1): the admin run hooks the stage-2 gate
`0x40860f` and `emu_stop`s, both runs ride their profile, and the assertion is
that the dispatch counts differ. It is gated on real DLLs like the C++ fixtures
because the sample's environment probing needs real answers.

With real Win7 DLLs the admin run reaches `0x405126..0x405142` and then calls
into `ntdll` at `0x7dee1ecd` — the encoded-pointer walk
(`mov 0x8(%ebx),%esi; xor 0x7df72088,%esi; mov (%esi),%eax`) with a `ebx` that
the obfuscated stub did not build, so it faults and the SEH dispatch lands at
`0xd10c`. Both profiles therefore fault before the gate and before they diverge.
Debug with `TAOTE_PE_TRACE` plus the faulting pc the runner now reports: the open
question is which import the obfuscated stub expects to have filled `ebx`
(candidates: the `EtwNotificationRegister`-class lookup the real DLLs dispatch,
or a registry value the online/diff hive answers differently from a real hive).
Emulation-coverage bug, not a harness one.

### Phase D — the five real-dll-only regressions, and the remaining ports

Five cases pass in stub mode and fail with real DLLs. They are the concrete
worklist for making real-dll mode the better mode:

* `PeWinX8664Tls`, `PeWinX8664Fls` — `UC_ERR_WRITE_UNMAPPED` at `0x140001172` /
  `0x140001182` right after `HeapAlloc`, `EtwNotificationRegister`,
  `GetProcAddress`, `_set_fmode`. `EtwNotificationRegister` is dispatched but is
  not a vendor API the sample should be calling — look at what
  `GetProcAddress` returned there (the real `ntdll`/`kernel32` export walk) and
  at the `_set_fmode` stage's guest state.
* `PeWinX8664Clipboard` — now faults inside its own startup (`0x14001233a`)
  instead of jumping into `.idata`; the import walk itself is clean (§2.2 #7).
* `PeWinX86Argv`, `PeWinX86RegDemo` — both jump to `0x70000000` (a
  non-executable address) after the CRT bootstrap / `RegOpenKeyW`. A jump to one
  fixed address from two unrelated samples looks like a returned pointer that is
  not a function address (an unbound stub answer used as a callback, or a
  real-DLL export the walk resolved to a data symbol) — trace the last
  `GetProcAddress`/`RegOpenKeyW` return value.

### Phase D2 — remaining upstream cases not yet ported

`test_pe.py` cases 5–25 are all ported except the ones listed here; still open:

* `test_pe_win_x8664_libcache` — upstream asserts *its own* `QlPeCache` pickle
  (written once, then loaded, with `msvcrt.dll` carrying 2 cached cmdlines). The
  port parses fresh via LIEF (documented accepted deferral: unobservable to a
  guest). The case currently asserts the run only.
* `test_pe_win_x86_multithread` — **skips on a real gap**: the created guest
  thread never executes its body, so only the main thread (id 0) dispatches
  `GetCurrentThreadId`. The ported scheduler ticks and picks candidates, but the
  live context switch needs the fiber-callback machinery the port does not have
  (STATUS.md, the `QlWindowsThread` row). The case resets the process-global id
  sequence, so it is order-independent, and turns green by itself once guest
  threads switch live.
* `test_pe_sys.py` (sality.dll + custom `CreateThread`/`CreateFileA` hooks) —
  needs the user-hook surface (now present) plus `sality.dll` unchanged; next
  slice.
* `test_windows_stdio.py` — not a unit test (a crackme solver printing the
  flag); its assertion is the instruction-count differential. Port as a
  diagnostic tool rather than a gtest.

### Phase E — pegasus side

* The 101-bin sweep stays green; the parity suite (`PegasusParity.*`, 18 cases)
  stays green.
* PMA corpus: the default directory now also resolves
  `~/source/jim/capa-testfiles` (previously only `~/source/capa-testfiles`), so
  `PmaCompat.CuratedCorpusApiExpectations` runs: **1/12** curated cases green.
  The per-case blockers are named in `tests/Pma_Compat_Test.cpp`; the ratchet
  (`kGreenBaseline`) must only move up.

## 4. Test-fixture hygiene

`tests/data/pegasus/` now carries the 7 pegasus sample binaries the parity suite
drives (`GetProcAddress.exe`, `argv_test_x86/x64.exe`, `file_access_test_x86/x64.exe`,
`seh_test_x86.exe`, `dll_test_x86/x64.dll`), extracted from the `.xz` archives in
`../pegasus/tests/bins`. **They were missing from the tree** because `.gitignore`
ignores `*.exe` globally; `.gitignore` now re-includes `tests/data/**/*.exe` and
`*.dll`. Before that fix the `PegasusParity.*` suite failed 12/18 with "missing
fixture".

## 5. Order of work

Done in this pass: the loader defects (§2.2 #6–#8) and the Wine-DLL loader work
of §2.1 (relocation use-after-free, guest-pointer-width PEB/TEB/LDR writes,
per-symbol api-ms fallback, debug-CRT aliasing, unbound-import stubs). That moved
the default suite from 27 passed / 9 skipped / **1 failed** to
26 passed / 10 skipped / **0 failed**, and real-dll mode from 19/17 to 21/15.

Next, in order:

1. **Phase B harvest** — copy `ucrtbase.dll` (x64 + x86) and the
   `api-ms-win-crt-*.dll` set off the Windows 7 machine that produced
   `rootfs-win7.zip` (it has the VC++ 2015 redistributable, so the Universal CRT
   is there). Nothing else is known to block the eight C++/SEH cases; this is the
   single highest-value action left and it needs no emulator work.
2. **Phase D regressions** — the five real-dll-only failures. Their fault
   addresses and API tails are recorded above; each needs the return value of the
   `GetProcAddress`/`RegOpenKeyW` that precedes it.
3. **Fix the uncaught `QlErrorBase` that terminates the test binary on the full
   Wine rootfs** (`PeWinX86GetLastError`) before that tree is used again, and make
   a stable copy of it outside `/tmp`.
4. **Phase C** — GandCrab's obfuscated stub (which import is expected to fill
   `ebx`).
5. **Phase D2 / Phase E** — `test_pe_sys.py`, live thread switching,
   `test_windows_stdio.py` as a diagnostic, then the PMA curated count.
