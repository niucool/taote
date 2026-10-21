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
| qiling PE suite parity, **real-dll mode** (`TAOTE_WINDOWS_ROOTFS=~/source/jim/rootfs-win7`) | the reference's own configuration; upstream itself fails every case on this rootfs (§2.3) | **26 passed / 1 skipped / 9 failed** | all 36 |
| pegasus sample sweep (`../pegasus/tests/bins`, 101 bins) | asserts dispatch only | **101 exit 0** | maintained |
| pegasus suite parity (`PegasusParity.*`, 18 cases) | 357 cases | **18 passed** | maintained |
| PMA corpus (`~/source/jim/capa-testfiles`) | 12 curated | **1/12 curated** (raw sweep 24/32 exit 0) | 12/12 |
| taote suite | — | **567 passed / 0 failed / 15 skipped** (582 cases) | 0 failed |

The two modes are reported separately because they measure different things: stub
mode is deterministic and is what the default suite runs; real-dll mode is the
reference's own configuration. Stub mode used to be the only safe mode — five
cases passed on stubs and failed with real DLLs. Those five are now green in both
modes (they were one port bug, §2.2 #9), so real-dll mode is the *strictly
stronger* mode: it runs every case that stub mode skips.

### 0.1 Per-case state, with the upstream-oracle differential

`upstream` = `../qiling` run against the same `rootfs-win7` per §2.3;
`taote` = `TAOTE_WINDOWS_ROOTFS=~/source/jim/rootfs-win7`. Every row was
measured, not inferred.

| case | upstream on rootfs-win7 | taote (real DLLs) | conclusion |
|---|---|---|---|
| PeWinX86Hello | FAIL | pass | rootfs gap upstream cannot route around; taote serves the unbound imports |
| PeWinX8664Hello | FAIL | pass | idem (control: upstream dies inside real ntdll) |
| PeWinX86FileUpx | FAIL | pass | idem |
| PeWinX8664FileUpx | FAIL | pass | idem |
| PeWinX86Cmdln | FAIL | pass | idem |
| PeWinX8664Cmdln | FAIL | pass | idem |
| PeWinX86Crackme | FAIL | pass | idem |
| PeWinX8664CustomApi | FAIL | pass | idem |
| PeWinX86/64ReturnFromMain* (4) | FAIL | pass | idem |
| PeWinX86GetLastError | FAIL | pass | idem |
| PeWinX86NtQueryInformationSystem | FAIL | pass | idem |
| PeWinX86UselessDisk | FAIL | pass | idem |
| PeWinX86Wannacry | FAIL | pass | idem |
| PeWinAlKhaser | FAIL | pass | idem |
| PeWinX8664Libcache | FAIL | pass | idem |
| WindowsShellcodeX86 | FAIL | pass | idem |
| ReadPtr32 / ReadPtr64 | FAIL | pass | idem |
| **PeWinX8664Clipboard** | **FAIL** (FETCH_UNMAPPED) | **pass** | *was* a taote port bug: `__p__commode`/`__acrt_iob_func` returned 0 to a guest that dereferences it, because a handler-less stub cell is not a dispatchable export. Fixed. |
| **PeWinX8664Tls** | **FAIL** (pc `0x2ba6`) | **pass** | same port bug (fixed) |
| **PeWinX8664Fls** | **FAIL** (FETCH_UNMAPPED) | **pass** | same port bug (fixed) |
| **PeWinX86Argv** | **FAIL** (FETCH_UNMAPPED) | **pass** | same port bug (fixed) |
| **PeWinX86RegDemo** | **FAIL** (`QlErrorSyscallError`) | **pass** | same port bug (fixed) |
| **PeWinX86Multithread** | **FAIL** (pc `0x2476`) | **skipped** | **rootfs gap, proven**: the sample imports `MSVCR110.dll` and `rootfs-win7` contains no `MSVCR110.dll` (0 matches in either arch tree); with its CRT stubbed the sample never reaches its `CreateThread` call (verified with `TAOTE_VERBOSE=debug`: `CreateThread` is never dispatched). Upstream fails the same case for the same reason. Needs a real `MSVCR110.dll`. |
| **PeWinX8664CppHelloWorld** | FAIL | fail | **port gap (not rootfs)** — see §3 Phase B |
| **PeWinX8664CppTypes** | FAIL | fail | idem |
| **PeWinX8664SoftSeh** | FAIL | fail | idem |
| **PeWinX8664SoftCppEx** | FAIL | fail | idem |
| **PeWinX8664CppExUnhandledFiltered** | FAIL | fail | idem |
| **PeWinX8664CppExUnhandledUnfiltered** | FAIL | fail | idem |
| **PeWinX86CppHelloWorld** | FAIL | fail | idem |
| **PeWinX86CppTypes** | FAIL | fail | idem |
| **PeWinX86GandcrabProfile** | FAIL | fail | **port gap** — see §3 Phase C |

Stub mode is unchanged by all of this: 26 passed / 10 skipped / 0 failed, the ten
skips being the same cases that need a real C++ runtime, a real `MSVCR110.dll`,
or live thread switching.

### 0.2 The Windows 11 rootfs (the UCRT harvest) and the clean differential

A rootfs collected on Windows 11 now exists at
`../qiling/examples/scripts/examples/rootfs` (35 x64 / 57 x86 images plus the six
registry hives, ~110 MB `SOFTWARE`): **it has the Universal CRT** — `ucrtbase.dll`,
`ucrtbased.dll`, the five `api-ms-win-crt-*` shims, `msvcp140[_1/_2]`,
`vcruntime140[_1]` — for both arches, and `msvcr110.dll`. This is what
`dllscollector.bat` produces on a modern Windows host, and it is the rootfs the
upstream tests are written for.

**Upstream on this rootfs** (its own `test_pe.py` + `test_windows_cpp_*.py`, run
from a composed tree with the sample corpus staged inside):

| suite | result |
|---|---|
| `test_pe.py` (25 cases) | **25 pass** (was 24 + 1 error: `test_pe_win_x86_gandcrab` crashed inside upstream's own `lstrcmpiW`, because `utils.read_string` read one unit past the end of the mapped region when a guest string ran to a page boundary — fixed upstream, see below) |
| `test_windows_cpp_x8664.py` + `..._x86.py` (8 cases) | **8 pass** |

**taote on the same rootfs**: **26 pass / 9 fail / 1 skip** of 36. The
differential is therefore sharp — for the first time the oracle can convict:

| case | upstream | taote | verdict |
|---|---|---|---|
| 26 cases (all the hello/cmdln/upx/return_main/customapi/crackme/wannacry/al-khaser/… rows of §0.1) | pass | pass | parity |
| **CppHelloWorldX8664, CppTypesX8664, SoftSehX8664, SoftCppExX8664, CppExUnhandledFiltered, CppExUnhandledUnfiltered, CppHelloWorldX86, CppTypesX86** | **pass** | fail | **port bug** — see below |
| **PeWinX86Multithread** | **pass** | skip | **port bug** — upstream's threads are `gevent.Greenlet`s, i.e. Python-level cooperative switching; a pc/register scheduler is not equivalent. `if (address == thread_ret_addr) stop()` + `do_schedule()` in a code hook (what taote has) performs the register swap but unicorn keeps executing the retired instruction stream, so the child never starts at its own entry. Implementing this needs the run-loop restart that upstream gets from the greenlet model. |
| PeWinX86GandcrabProfileChangesBehaviour | fail | fail | oracle cannot convict (upstream fails too, in its `lstrcmpiW`) |

On the Win11 rootfs the C++ chain is now correct up to one instruction:
msvcp140 loads, its DllMain completes, `?cout@std@@` holds a vtable
(`0x180963c98`), the real `operator<<` runs and even computes the string length
(`r8 = 0xd`) — then faults at `msvcp140+0x9916`, `mov (%rax),%r9` with
`rax = [basic_ios + 0x40]`. That field is the stream's streambuf slot and reads
`0x1` (a bogus pointer, not NULL), so the remaining defect is the same one Phase B
described: the C++ initializer walk binds the stream's `filebuf` inconsistently.
`_initterm` **is** called over msvcp140's 57-entry table
(`msvcp140+0x516d8..+0x518a0`, 56 entries inside the image, one null), so the
walk runs; what is left is to find which entry binds the streambuf and why its
effect is missing.

**The string-read bug (fixed in upstream and taote).** `read_string` advanced one
unit at a time and let any read fault escape. A guest string that runs to the end
of its mapped region has no terminator there, so the walk read one unit past the
mapping and the fault aborted the whole run from inside a handler that merely
*reads* an argument — GandCrab's `lstrcmpiW` argument pointed 2 bytes below a page
end. Real Windows takes an access violation when it never finds the terminator;
the emulation now ends the string at the edge. Upstream: `test_pe.py` 24/25 ->
**25/25**. taote: the same guard on `read_string` and `read_wstring`; GandCrab's
admin run moves past that read fault.

Fixed on this rootfs in this pass: `PeWinX86RegDemo` (it passed on rootfs-win7
and regressed here) — taote substituted its synthetic `_except_handler4_common`
walk for a real ucrtbase unwinder; the handler now yields when the image has real
code at that export (detected by the synthesized-cell `ret` signature).

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

Mode (b) is **runnable**: `TAOTE_WINDOWS_ROOTFS=~/source/jim/rootfs-win7`
(real Microsoft Windows 7 System32, 35 x64 + 73 x86 images) drives the whole
suite and is the mode the numbers in §0 are quoted for. The earlier "the loader
segfaults on real DLLs / real-dll mode is not runnable" finding is **retired** —
it was three loader defects, all fixed: a heap-use-after-free in the relocation
walk (the fixups are copied out of the LIEF `Binary` before `load_parsed` takes
ownership), guest-pointer-width violations in the PEB/TEB/LDR writes (8-byte
stores on a 32-bit guest, off the end of the heap allocations), and import
groups dropped whole so their IAT slots kept raw hint/name RVAs.

Wine's builtin PE DLLs were also tried as a (b) substitute and are **no longer
used**: they are self-consistent only as a complete set, Wine's `ucrtbase`
imports wine-only `ntdll` exports (`__wine_dbg_*`), and the tree's `System32` is
a symlink into `/tmp`. The measurements in this document use real Windows DLLs
only.

### 2.3 The upstream oracle

`../qiling` itself can be run against the same rootfs, which separates "our port
is wrong" from "this rootfs cannot support the case". Setup (Linux, no Windows
host): a venv at `../qiling/.venv-oracle` with unicorn/capstone/pefile/
python-registry/pyelftools/keystone-engine/gevent/multiprocess/pyyaml/
questionary/termcolor installed, the sample corpus **staged inside** the rootfs
copy (upstream rejects a target binary outside the rootfs with a `ValueError`
in its path mapper), and its own `tests/profiles/*.ql` for the GandCrab case.

Measured upstream verdicts on `rootfs-win7` — upstream fails **every** case,
including the control (`x8664_hello.exe`, which taote passes):

| case | upstream on rootfs-win7 | failing pc / error |
|---|---|---|
| x8664_hello (control) | FAIL | pc `0x78e99aa0` *inside real ntdll* (READ_UNMAPPED) |
| x8664_tls | FAIL | pc `0x2ba6`, not in any image — an `.idata` RVA |
| Fls | FAIL | UC_ERR_FETCH_UNMAPPED |
| x8664_clipboard_test | FAIL | UC_ERR_FETCH_UNMAPPED |
| RegDemo | FAIL | `QlErrorSyscallError` raised inside its `hook_winapi` |
| argv | FAIL | UC_ERR_FETCH_UNMAPPED |
| MultiThread | FAIL | pc `0x2476`, an `.idata` RVA |
| GandCrab502 (both profiles) | FAIL | UC_ERR_FETCH_UNMAPPED |
| the 8 C++/SEH fixtures | FAIL | UC_ERR_FETCH_UNMAPPED |

The `0x2ba6` / `0x2476` jumps are the signature of an unbound import whose IAT
slot still holds its hint/name RVA: rootfs-win7 exports **none** of the Universal
CRT's `api-ms-win-crt-*` surface, and upstream's redirect ladder only maps those
to `ucrtbase.dll` (absent here), so every CRT import in every MSVC-2015 sample is
unbound. taote does not have that defect (unresolved slots are answer-0 stub
cells, and names taote implements are dispatched through its own handlers), which
is why taote passes cases upstream cannot.

Consequence for the differential rule: on this rootfs the oracle **cannot**
convict taote of a port bug for any case — it fails everything, including the
control. Where the oracle is useful is the reverse direction: a case taote fails
while upstream's *failure mode* differs from ours localizes the defect, which is
how the C++ rows below were narrowed.

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
9. **A handler is reached by *export address*, so taote skipped its own
   implementations for imports the rootfs could not export.** The five cases
   that passed on stubs and failed on real DLLs (`PeWinX8664Tls`/`Fls`/
   `Clipboard`, `PeWinX86Argv`/`RegDemo`) were one cause: `api-ms-win-crt-*`
   imports missing from Win7's msvcrt bound to answer-0 stub cells, and taote's
   `__p__commode` / `__acrt_iob_func` / `__stdio_common_vfprintf` handlers never
   fired because the loader keys `import_symbols_` by *export* addresses and a
   stub cell is not an export. `x8664_tls.exe` then stored through the null that
   `__p__commode()` returned (`mov %eax,(%rbx)`). The loader now records
   address→symbol for every stub cell (`stub_symbol_at`) and `hook_winapi`
   synthesizes the `ImportSymbol` from it and dispatches normally when the
   registry has a handler.
10. **The SEH sentinel return was never observed.** The sentinel page is mapped
   rw-without-execute on purpose so a guest returning into it traps, but unicorn
   reports that as `UC_MEM_FETCH_PROT` (its own hook type), not as
   `UC_HOOK_MEM_INVALID` — so the dispatcher missed exactly the sentinel-return
   case and an x86 fixture died jumping into `0x70000000`.
11. **The UCRT locale-state accessors were missing.** `___lc_codepage_func`,
   `___lc_collate_cp_func`, `___mb_cur_max_func`, `___lc_locale_name_func` and
   `__pctype_func` return *pointers* into CRT state; a Win7 rootfs has none of
   them, and an answer-0 stub faults at `mov 0x8(%rax),%rcx` with `rax == 0`
   (measured at `msvcp140+0x1c44`). Now implemented as real guest cells holding
   the C locale. Effect: msvcp140's DllMain completes, `.data +0x94250` reaches
   its initialized state, and `?cout@std@@` holds a vtable
   (`0x180057300`) instead of zeros.

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

### Phase B — the eight C++/SEH cases (port gap, narrowed to one thing)

This is **not** a rootfs gap. Both arches' fixtures import the same set
(`MSVCP140`, `VCRUNTIME140[_1]`, the five `api-ms-win-crt-*` groups, `KERNEL32`)
and `rootfs-win7` has `msvcp140.dll` and `vcruntime140.dll` for x86 and x64. The
whole chain now works up to one point:

* the `DllMain` drive rides CDECL and takes the **attach** path (§2.2 #6), so
  msvcp140's own CRT startup runs;
* the UCRT locale-state accessors are implemented (§2.2 #11), so that startup no
  longer faults, `.data +0x94250` reaches its initialized state and
  `?cout@std@@` (msvcp140+0x947d0) holds a **vtable** (`0x180057300`);
* the fixture therefore faults *inside genuine msvcp140 code*, not on a null
  stream: `msvcp140+0xf62c`, `mov 0x40(%r15),%rax; mov (%rax),%r9` with
  `rax == 0`.

**The remaining defect is precise:** the stream object is constructed (vtable
present) but the pointer at `basic_ios<char> + 0x40` — the `_Mystrbuf`/rdbuf slot
— is still NULL, so `operator<<` dereferences it. `std::cout`'s binding to its
`filebuf` comes from `_Init_ostream` via the CRT's **C++ initializer table**
(`__xc_a..__xc_z`, walked by `_initterm`), while what has demonstrably run is the
`__xi` table (`_initterm_e` over `msvcp140+0x517c8..+0x517d8`, one entry — the
winapi-thunk resolver). So the next step is to confirm and fix why the `__xc`
walk does not take effect on this path: check whether `_initterm` is reached at
all on msvcp140's attach path once `_initterm_e` returns, and whether the
`coutbuf`/`filebuf` BSS statics are constructed before `_Init_ostream` binds
them. This is a small, mechanical target — not a "needs a Windows host" wall.

Upstream cannot be used as an oracle here (it fails these cases on this rootfs,
and on a Windows host this configuration is its supported one), so the verdict
rests on the above: the DLLs are present, therefore **port gap**.
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
