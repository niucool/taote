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
| qiling PE suite parity (`../qiling/tests/test_pe.py`, `test_peshellcode.py`, `test_windows_cpp_*.py`) | passes **on a Windows host only** (its CI runs `test_pe.bat`, which needs `dllscollector.bat` to copy the real System32 DLLs) | **27 passed / 9 skipped / 1 failed** of 37 ported cases (`tests/QilingPe_Compat_Test.cpp`) | all but the documented deferrals |
| qiling PE tests with a real system-dll rootfs | — | not yet runnable here (see §2.1) | all 36 |
| pegasus sample sweep (`../pegasus/tests/bins`, 101 bins) | asserts dispatch only | **101 exit 0** | maintained |
| pegasus suite parity (`PegasusParity.*`, 18 cases) | 357 cases | **18 passed** | maintained |
| PMA corpus (`~/source/jim/capa-testfiles`) | 12 curated | **1/12 curated** (raw sweep 24/32 exit 0) | 12/12 |
| taote suite | — | **567 passed / 1 failed / 14 skipped** (582 cases) | 0 failed |

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
  Windows.

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

### Phase B — the CRT initializer walk (`_initterm` / `_initterm_e`)

Implemented once, then reverted to the no-op: running the initializer table
through a nested emulation makes every static initializer in the image execute,
but on a stub rootfs the initializers call *stubbed* ucrtbase helpers that return
garbage, corrupting the CRT state of samples that previously ran clean
(`x8664_tls.exe`, `x8664_clipboard_test.exe`, `Fls.exe`, `RegDemo.exe`,
`GetLastError.exe`, `NtQuerySystemInformation.exe` — 6 regressions against 1 win).
The walk belongs with Phase A: with real ucrtbase the upstream simply executes
the real code, so the walk is only needed for stub mode — and only after the
stubbed helpers return plausible values. Recorded, not lost: the implementation
is in this document's history and `QlOsWindows::NestedRun` (which it needed)
stays.

### Phase C — `GandCrab502.bin` (`PeWinX86GandcrabProfileChangesBehaviour`)

The only remaining red. The two profiles now load (the ini fix) and change the
run, but the guest faults (`UC_ERR_WRITE_UNMAPPED` with the admin profile,
`UC_ERR_READ_UNMAPPED` at `0xffffc88cffffcc8c` with the user profile). Debug
with `TAOTE_PE_TRACE` + `tools/gap_census` on its import list: the profile's
`[REGISTRY]` values drive a path that the diff store answers differently from a
real hive. This is an emulation-coverage bug, not a harness one.

### Phase D — remaining upstream cases not yet ported

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

1. Phase A.1 — the Wine-DLL loader crash (instrument, fix, then flip the 8
   skipped cases to real-dll mode and re-enable the `_initterm` walk for stub
   mode only if the stubbed CRT helpers cooperate).
2. Phase C — GandCrab.
3. Phase D — `test_pe_sys.py`, the multithread id pinning, the libcache note.
4. Phase E — raise the PMA curated count.
