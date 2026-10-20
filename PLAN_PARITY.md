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
| taote suite | — | **540 passed / 0 failed / 3 skipped** | grows with every phase, stays 0-failed |
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

The differ's own vocabulary separates four verdicts: `match` (clean),
`environment` (the only divergence is a module handle the harness can synthesize
only with a different export set - nobody has the genuine Windows images on a
Linux host), `reference_limit` (the reference faulted and taote did not, taote's
extra dispatches are imports the reference reports unimplemented, and every other
disagreement starts at or after the first such import - i.e. taote is executing
code the reference never ran because it leaves that import to the stub cell) and
`diverged` (a real semantic difference). Faulted runs are not
compared on exit code, because the reference leaves `ql.os.exit_code` at 0 when a
unicorn fault kills the run while taote sets the guest's `STATUS_ACCESS_VIOLATION`
(Phase 1.5, a deliberate delta).

PMA differential baseline (32 PE samples, measured this pass):

| verdict | count |
| --- | --- |
| match | **12** (`01-02.exe_`, `03-03.exe_`, `03-04.exe_`, `10-03.exe_`, `12-01.exe_`, `12-02.exe_`, `16-01.exe_`, `16-02.exe_`, `18-03.exe_`, `19-02.exe_`, `20-02.exe_`, `21-01.exe_`) |
| environment | 0 |
| reference_limit | 13 (`01-01.exe_`, `01-04.exe_`, `06-03.exe_`, `11-02.dll_`, `11-03.dll_`, `11-03.exe_`, `11-01.exe_`, `12-01.dll_`, `12-03.exe_`, `12-04.exe_`, `14-01.exe_`, `17-03.exe_`, `18-01.exe_`) |
| diverged | 7 |

Measured after the unsupported-import frame fix below (raw taote exit-0 **19/32**,
was 13/32). Measured after the two differ fixes below (the signed/unsigned return-value fold
and the reference-timeout verdict); was 5 / 1 / 3 / 23 before them. The match
list traded `18-01.exe_` for `10-03.exe_`: `10-03.exe_` is a real gain (its only
finding was `CreateFileA` answering `-1` on the reference and
`18446744073709551615` on taote for the same bit pattern, a normalization bug in
the differ that made a matching run read as divergent), while `18-01.exe_` moved
to `reference_limit` because the reference cannot finish that sample at all - its
guest spins in a retry loop whose `Sleep` hook is a no-op on both sides, so the
Python reference spends its whole budget there and ends on the harness timeout,
while taote completes 3 dispatches in a second. `14-01.exe_` is the same timeout
shape. Neither is a taote defect and neither trace is observable, so both are
scored as reference limitations rather than as divergences. The reference is now
given the same deterministic instruction budget as taote for exactly this reason. `16-02.exe_` is the header fix's direct win - it
reads its own PE header, took the "not an MZ image" branch, and now runs the
same trace as the reference. `12-01.exe_` is the module-load `environment`
verdict the earlier pass's vocabulary added.

Cluster table (samples per signature, after the `reference_limit` split):
dispatch count differs 19, extra dispatch
20, missing dispatch 12, exit code differs 5, error class differs (invalid_write
vs none) 4, (none vs invalid_insn) 3, stdout differs 2, (invalid_fetch vs none) 2,
dispatch order differs 2, then singles for invalid_read/invalid_fetch,
return value, emu_error, timeout vs invalid_insn, invalid_cpu_exception vs
invalid_fetch, invalid_write vs invalid_read, none vs invalid_fetch,
invalid_insn vs invalid_fetch. That table is the phase's work order, and the per-name aggregation of the two
biggest signatures (from `/tmp/pma_parity.json`) shows it is not one systemic
bug but a long tail plus a few repeats:

| direction | API | samples |
| --- | --- | --- |
| taote extra | `_initterm`, `HeapFree` | 5 each |
| taote extra | `UnhandledExceptionFilter` | 4 |
| taote extra | `exit`, `LoadLibraryA`, `GetProcAddress`, `GetModuleFileNameA` | 3 each |
| taote extra | `memset`, `strlen`, `GetSystemDirectoryA`, `_except_handler3` | 2 each |
| taote missing | `ExitProcess` | 4 |
| taote missing | `GetModuleHandleA` | 3 |
| taote missing | `HeapAlloc` | 2 |

The shape of that table is the finding: the reference **stops earlier** than
taote on most samples (a fault ends its run), so taote's "extra" dispatches are
the calls it survives and the reference's "missing" ones are the calls taote
never reaches. The two repeats that are worth attacking first are therefore
`HeapFree`/`HeapAlloc` (a heap-handle divergence on both directions) and
`ExitProcess` (taote not reaching process exit where the reference does), not the
long tail of single-sample APIs.

First dissection of the heap cluster (16-03.exe_, which carries both signatures):

```
#  reference                 taote
0  GetVersion     262148     GetVersion     262148
1  HeapCreate     83888680   HeapCreate     83888280
2  GetVersionExA  1          GetVersionExA  1
3  GetEnvironmentVariableA 0 GetEnvironmentVariableA 0
4  GetModuleHandleA 0x400000 GetModuleHandleA 0x400000
5  HeapAlloc      83892776   VirtualAlloc   83892376
6  HeapAlloc      83893096   VirtualAlloc   88086680
```

The two traces are identical up to and including #4, then **at the same call site**
the reference dispatches `HeapAlloc` and taote dispatches `VirtualAlloc`. taote
registers `HeapAlloc` (`qiling/os/windows/dlls/kernel32/heapapi.cpp:84`), so this
is not a missing handler - the guest's allocation import is resolving to a
different stub cell on taote's side. The next unit is therefore to dump, for one
run, guest IAT slot -> stub address -> export name (`QlLoaderPE::import_symbols`
plus `import_address_table_at`), and compare it against the same map the
reference built: a stub export table whose cell order disagrees with the names
list would produce exactly this (each import answered by its neighbour).

**Checked and ruled out**: sorting the stub's export list before building it
(`tests/Pe_Sample_Runner.hpp::write_stub_dll`, so the name table and the function
table agree by construction) changed nothing - taote still dispatches
`VirtualAlloc` at the `HeapAlloc` call site - so the cell order is not the cause
and the change was reverted. The next probe therefore has to be the guest's own
IAT: dump the slot the guest calls through and what both sides wrote there,
rather than inferring from the dispatch name. Two candidate explanations remain:
the CRT's allocation wrapper genuinely calls a different API on each side (so
the divergence is upstream, in an earlier return value), or taote's IAT write for
this import lands on a different slot.

**Dumped, and the answer is "upstream"**: `tools/parity_trace --dump-imports`
(new) prints the loader's `import_symbols` map, and for 16-03.exe_ it is correct
and distinct - `HeapCreate 0x10001210`, `HeapAlloc 0x10001260`,
`VirtualAlloc 0x100012a0` - while the guest's two allocation calls dispatch at
`0x100012a0` (VirtualAlloc's own cell). So taote's IAT is right and the guest
*genuinely called a different API*: the two emulators run different allocation
wrappers (CRT `malloc` picks heap vs virtual allocation from a size the guest
derives from an earlier return value). The heap cluster is therefore a *downstream
symptom*, and the remaining diagnostic direction is the first differing return
value before #5 (`HeapCreate` answers `83888280` on taote vs `83888680` on the
reference), not the import table.

**Fixed: the PE header page was never mapped (found by the code trace).** A new
instruction-level probe (`parity_trace --code-trace FILE [--code-trace-range A B]`,
and the same flags on `tools/qiling_reference_runner.py`) logs `(pc, size)` per
executed instruction so the differential can see a control-flow divergence
*between* two dispatches. On `11-01.exe_` it put the two runs next to each other
and the difference is one instruction: right after `call [0x407020]`
(`GetModuleHandleA`) both sides execute `0x403246 cmp word ptr [eax], 0x5a4d`,
and then the reference falls through (`0x40324d`, it reads the PE header) while
taote jumps (`0x403261`, "this is not an MZ image"). The cause is the loader:
upstream `loader/pe.py` writes the whole memory-mapped image
(`ql.mem.write(image_base, bytes(pe.get_memory_mapped_image()))`), which includes
the header page, while `QlLoaderPE::load_parsed` staged only the *sections* - so
`word ptr [imagebase]` read zero. The loader now writes `SizeOfHeaders` bytes of
the file at the image base before staging the sections, and `11-01.exe_` goes
from 45 calls ending on `UnhandledExceptionFilter` to the reference's 46 calls
with the allocator cluster gone (its `HeapAlloc`-vs-`VirtualAlloc` divergence was
this branch, not a heap-handle problem).

**`11-01.exe_` after the header fix: a stack-content divergence, one `ret`
before the end.** All 45 leading dispatches now match in name *and* call site;
only #45 differs (reference `ExitProcess` from `0x402ab3`, taote
`UnhandledExceptionFilter` from `0x402c0d`). The `--code-trace` window
`0x402900-0x402c30` shows why: at `0x4029f9 ret` the two guests pop *different
return addresses* - the reference pops `0x4029fa` (its own next instruction) and
taote pops `0x402acf` (the guest's SEH handler entry, i.e. the `Handler` field of
its own registration record). So taote's guest stack is off by a slot by the time
it reaches that `ret`, which means an earlier dispatch left `esp` unbalanced
(`stdcall` cleanup vs the dispatcher's own) rather than the guest branching on a
value.

The `esp` probe ran and **corrected that hypothesis**: both `--code-trace` writers
now print the stack pointer as a third column, and over 121 (reference) / 75
(taote) instructions the two traces agree in *pc and sp* for all 53 shared steps,
including the `ret` at `0x4029f9`. The two guests therefore pop from the *same*
stack address and get different values - so it is the memory at that slot that
differs (`0x4029fa` vs `0x402acf`), not the stack pointer. Something wrote the
guest's SEH-handler entry (`0x402acf`) into a stack slot on taote's side that the
reference left holding a return address, and every preceding instruction matched,
so the write comes from a *value* the guest loaded, not from a different code
path. Next probe: watch writes into the frame holding that slot (a mem-write hook
over the 64 bytes around it, both sides) and compare the writer.

That probe exists now (`parity_trace --mem-watch FILE BEGIN SIZE`, and the same
flag on the reference runner, both logging `pc addr size value`), and it answers
it in four instructions: at `0x401496 mov eax, dword ptr fs:[0]` /
`0x40149c push eax` the reference pushes **0** and taote pushes **0xffffffff** -
i.e. the two loaders disagree about the x86 TEB's initial `ExceptionList`.
taote writes the real-Windows sentinel `0xffffffff`, upstream leaves the field at
its zero default, and the guest stores that value as the `Next` of its first SEH
registration, so on taote the chain head reads as a *live frame* and the guest
walks into the sentinel. Making that field 0 (matching the reference) was tried
and **reverted as not-yet-a-win**: `11-01.exe_` then runs 62 calls instead of 46
(it gets past the `UnhandledExceptionFilter` and keeps dispatching) but still
diverges at call #45 and now ends on `invalid_read`, so the change moved the guest
further along without reaching the reference's trace. Recorded as the next unit
with the corpus measurement it needs (the field is loader-level, so it must be
scored over all 32 samples, not one).

### 16-03.exe_: the last diverged sample with a real reference run

Both emulators dispatch the same **42** calls - same names, same call sites, same
return values, checked position by position - and both then fault, taote with
`Fetch from non-executable memory` and the reference with `Unhandled CPU
exception`. All memory in taote is mapped `UC_PROT_ALL` (there is no
`uc_mem_protect` anywhere in the tree), so the fetch-prot is a fetch *off* the
mapped regions rather than a permission, and the instruction trace pins it: the
last instruction executed on taote is `ret` at **0x401261** and the fault is the
fetch of the address it popped from `0xffffca5c`. That is the third instance of
the same class this phase has already met twice (`11-01.exe_`'s SEH tail,
`16-01.exe_`'s stub-cell ret): same `sp`, same code, a different value in the
popped stack slot. The recorded next probe is the one that settled `11-01`: a
`--mem-watch` over `0xffffca20..0xffffcad0` on both sides, comparing the write
streams to name the writer.

### `host_to_virtual_path` emits Windows separators

`11-01.exe_` was the last sample with a comparable reference run that still
diverged, and the mem-watch over its frame showed a single upstream cause: 750
writes into the `GetModuleFileNameA` buffer identical on both sides, then
`0x401460` (a `strrchr`-shaped `repne scasb` for `'\\'`) answered `0xffffceae`
(a pointer to the last separator) on the reference and **0** on taote, so taote
wrote through NULL and faulted 46 dispatches later. The buffer was mixed:
`QlOsPath::host_to_virtual_path` returned `anchor + rel.generic_string()`, i.e.
`C:\Windows/System32/...` - the anchor's backslash plus forward slashes -
because `generic_string()` is the host-flavoured form. Upstream rides
`ntpath`/`Path`, so the virtual path is all backslashes. The separator fold now
matches, `11-01.exe_` runs **51 calls to exit 0** (the reference reaches 46 and
never calls the handler at all), and the corpus is **12 match / 0 environment /
13 reference_limit / 7 diverged** with raw taote exit-0 **21/32**.

### The reference stopped before taote did

The last three non-trace-identical cases had the same reading: the reference
faulted mid-run while taote ran on *cleanly* and every extra dispatch came at or
after the reference's final one (`11-02.dll_`: reference one call then an unmapped
read, taote 9 calls to exit 0; `11-03.dll_` and `11-03.exe_` are the same shape,
the latter aborting with the reference's own "Windows API Implementation Error").
`reference_limited` now also grants that verdict when there are no unimplemented
-import extensions to point at, under the guard that taote exited 0 and every
extra dispatch is at or after `len(reference calls)` — a taote that faulted is
never excused this way (`03-02.dll_`, `05-01.dll_`, `17-02.dll_` and `01-01.dll_`
keep their diverged verdicts for exactly that reason). Corpus: **12 match /
0 environment / 12 reference_limit / 8 diverged**.

### `reference_faulted_alone`

`12-01.dll_` reproduced the reference's run exactly - 68 dispatches, same names,
same order, same return values, same stdout - and simply did not fault where the
reference died on an unmapped fetch. Every finding but the error class agreed, so
nothing in the traces disagrees; that is the reference's own limitation and the
new predicate grants it only under exactly that shape (same sequence, same count,
the only findings being error-class ones). Corpus: **12 match / 0 environment /
9 reference_limit / 11 diverged**.

### One rootfs for both emulators (the environment class disappears)

The differ seeded a rootfs for the reference and let taote synthesize its own
per-sample one, so the two stub-dll export sets were not the same: the reference
got the *corpus union* of every imported name, taote only the sample's own. PMA
01-02 asks `GetProcAddress` for a name that only the union carried - the reference
answered a stub-cell address, taote answered 0, and the guest branched. That is a
harness difference, not an emulator one, and it was also what the `environment`
verdict existed to excuse (`12-01.exe_`).

`SampleOptions::rootfs` (and `parity_trace --rootfs DIR`) now runs taote against a
caller-seeded tree instead of synthesizing one, and the differ hands *both* sides
the same staged rootfs and the same staged sample path. The `environment` class is
gone: **12 match / 0 environment / 8 reference_limit / 12 diverged**, with
`01-02.exe_`, `12-01.exe_` and `18-03.exe_` newly matching and raw taote exit-0
**20/32**.

### The reference's missing handler as a verdict (`reference_lacks_handler`)

`06-03.exe_` was the last sample whose divergence taote's *superset* handler surface
caused: the guest asks `InternetGetConnectedState`, taote answers it, the reference
has no handler and leaves the guest to the stub cell with whatever the return
register held — so from that dispatch on, the two emulators are running different
programs (its guest prints "Error 2.1: Fail to OpenUrl", the reference's "Error 2.3:
Fail to get command"). The existing `reference_limited` verdict only covered the
case where the reference *faults* on a missing import; this one keeps going to its
own exit 0 and the traces drift instead. The new `reference_lacks_handler` predicate
covers it, guarded so that it cannot excuse a real defect: it needs a non-empty
extension list, every finding at or after the first extension dispatch, **no taote
emulation fault**, and — the guard that keeps `14-02.exe_` diverged — the same exit
code on both sides, because a run that ends elsewhere took a different end state.
With it the corpus is **9 match / 1 environment / 7 reference_limit / 15 diverged**.

### The unsupported-import frame (the `ExitProcess` cluster)

This closes the cluster the differential kept reporting as *missing dispatch:
ExitProcess* on `03-04.exe_`, `11-01.exe_`, `16-01.exe_` — all three had the same
tail: 43 matching dispatches, then taote dispatched `UnhandledExceptionFilter`
where the reference reached `ExitProcess`, then taote faulted.

The previous unit's `--dump-mem` probe had falsified the IAT hypothesis (taote's
slot held the stub cell, and that cell executed), and the stack write watch over
the frame settled it: both runs push the same return address (`0x401039` at
`0xffffb54c`) and both execute the stub cell's `C3`, yet taote came back to a
runtime thunk instead of its own next instruction. The cause is taote's
unsupported-import path: where the reference logs `api X (dll) is not
implemented` and dispatches **nothing** (leaving the guest's stub-export cell to
`ret` and do the stdcall cleanup itself), taote emulated the return through the
calling convention - `fcall_->return_value(0, 0)`, i.e. set the return register
and unwind **zero** slots. That leaves a stdcall frame unbalanced by its
arguments, so after the `ret` the guest is one frame off and follows a thunk into
its own exception path. It now zeroes only the return register
(`QlFunctionCall::set_return_value`) and lets the guest's `ret` unwind.

Effect: `16-01.exe_` and `03-04.exe_` become **matches** (16-01's only remaining
finding is a taote extension — it implements `ShellExecuteA`, the reference does
not), `16-01`'s code trace agrees with the reference for **all 19,489
instructions**, and the raw taote exit-0 count over the 32-sample corpus goes
**13/32 → 19/32**. The differential went to **7 match / 1 environment / 5 reference_limit /
19 diverged**, and then one more step finished it: zeroing the return register
still diverged from the reference, because the reference leaves the register
alone (PMA 19-02 reads an unimplemented `LookupPrivilegeValue`'s stale `eax` and
branches on it), so the unsupported path now does *nothing* but log - no frame
change and no register change. That takes the corpus to **9 match / 1
environment / 6 reference_limit / 16 diverged** (`19-02.exe_` and `21-01.exe_`
join the match list, `12-03.exe_` is the reference's own invalid-write
limitation). The differ also decodes subprocess output with
`errors="replace"`: a packed sample prints non-utf-8 decoy bytes, which used to
abort the whole sweep.

### The x86 loader layouts (heap-shift unit)

`PLAN_PARITY` Phase 1.9, after the TEB sentinel. `16-01.exe_` and its siblings
(`03-04.exe_`, `11-01.exe_`) all shared one shape: 43 matching dispatches, then
taote dispatches `UnhandledExceptionFilter` where the reference reaches
`ExitProcess`, and taote's guest later faults on an unmapped read. The probes
this pass added (`--mem-watch`, `--dump-heap`, `--dump-images`, all mirrored on
the reference runner) turned that into four separate defects, each a place where
the port used the 64-bit column of the loader's own structures on a 32-bit guest:

1. **LDR entry and UNICODE_STRING sizes.** `LDR_ENTRY_SIZE` was 304 (the x64
   value) and `UNICODE_STRING_SIZE` 16 for both word sizes. Upstream builds them
   from `make_ldr_data_table_entry(bits)`/`make_unicode_string(bits)`, so an x86
   guest gets 156 and 8 — and since both are *heap* allocations, taote's first
   guest allocation landed 0x280 before the reference's. `qiling/os/windows/structs.hpp`
   now carries a `LoaderLayout` with both columns and `loader_layout(bits)`.
2. **The x86 TEB's PEB pointer.** It rode at 0x1c (which is EnvironmentPointer in
   the 32-bit TEB) instead of 0x30, so a guest's `mov eax, fs:[0x30]` read
   garbage and `mov bl, [eax+2]` (PEB.BeingDebugged) took the anti-debug branch.
   The x86 TEB/PEB/LDR_DATA field offsets come from the layout too now.
3. **The command line.** The port composed `targetname + args`; upstream composes
   `ntpath.join(userprofile, 'Desktop', targetname) + ' ' + the quoted argv tail
   + NUL`. A packed sample's argv parser splits on those spaces, so the shape
   matters. Related: `userprofile_` was built as `systemdrive + "\Users\" + user`
   and the profile's `systemdrive` already ends in a backslash (`C:\`), so the
   path came out `C:\\Users\Qiling`; `ntpath.join` does not double it.
4. **The harness's stub set.** The reference's `tools/stub_dlls.py` always seeds
   `kernel32`/`ntdll`/`kernelbase`/`ucrtbase`/`mscoree`, and the loader asks for
   all five on every PE run; `tests/Pe_Sample_Runner.hpp` seeded only the planned
   imports, so `ntdll`/`kernelbase`/`ucrtbase`/`mscoree` were missing on the taote
   side (no LDR entry, no heap allocation for it) and every later heap chunk was
   shifted. It also skipped dlls whose imports are ordinal-only (`WS2_32` in
   16-01), which the reference does load. Both now match the reference.
5. **The thread return-address cell.** Upstream's thread manager allocates
   `heap.alloc(8)` in its constructor, before the loader lays the PEB; the port
   deferred it to `install_hook()`, which lands after, shifting the heap by 8.

Measured: with the harness and loader aligned, `16-01.exe_`'s heap chunk table is
**chunk-for-chunk identical to the reference's** (31 chunks, same sizes, same
order) and its instruction prefix before the first control-flow divergence grows
from **3,954 to 15,412** instructions. The corpus verdicts do not move yet
(5 match / 1 environment / 5 reference_limit / 21 diverged, raw taote exit-0
13/32), because `16-01` now splits later on a different cause: after
`GetShortPathNameA` (unimplemented on both sides, so the guest's `call` lands in
a stub cell) the reference returns to `0x401039` while taote jumps to
`0x406f6c`. The next probe narrows it: `--mem-watch` over that slot
(`0x40b064`, 4 bytes) shows **neither** emulator's guest writing it, and
`--dump-imports` shows taote's slot correctly bound to the stub cell
`0x100210d0` right after load - so either the guest patches the slot through a
path unicorn does not report to a write hook (the handlers ride `uc_mem_write`),
or the slot is re-written by taote's own `init_imports` after the configure
callback. The recorded next probe is therefore a run-end memory dump of the slot
plus both emulators' `init_imports` write paths, not another code trace: the
instruction streams agree up to and including the `call dword ptr [0x40b064]`
at `0x401033` (both at `sp` 0xffffb550), and the two runs disagree only about
*what that slot held*.

That probe exists now (`--dump-mem FILE BEGIN SIZE` with a new
`SampleOptions::after_run` hook, run on both the clean and the faulting path),
and it **falsifies the slot hypothesis**: at run end taote's `0x40b064` holds
`0x100210d0`, the stub cell, exactly like the reference - and the stub cell
*does* execute on taote (a stub-range code trace shows
`100210d0 1 ffffb550`, one byte, `0xC3`). The stub's `ret` therefore pops a
different value in the two runs even though `sp` at the call and at the stub
cell is identical: the reference pops `0x401039` (its own next instruction),
taote pops `0x406f6c` (a runtime-generated thunk inside the sample), and taote
carries on from there into its `UnhandledExceptionFilter` path. So this is the
same shape the `11-01` unit ended on - same `sp`, different memory at the popped
slot - and the next probe is a write watch over the stack frame around
`0xffffb550` (not the IAT slot) on both sides.

Scored, and it lands: over the 32-sample corpus the differential is
**5 match / 1 environment / 3 reference_limit / 23 diverged** before and after,
and the raw exit-0 count is 13/32 before and after. No sample changes verdict
(`18-01.exe_` first read as lost, but its reference run had timed out under host
load; re-run alone it is still a match, and the differ's `reference 0 calls exit
None (error: timeout)` line is the tell). What moves is `11-01.exe_`: 46 calls
ending `UnhandledExceptionFilter` + `invalid_read` become 62 calls, past the
filter and still dispatching, ending one call later in the run. The field now
matches the reference, it costs nothing anywhere else, and a loader test pins it
(`WinApiLoader.X86TebExceptionListStartsAtZeroLikeTheReference`).

**`none vs invalid_insn` dissected (`03-04`, `11-01`, `16-01`).** On
`11-01.exe_` both runs are identical through call #4 (`GetVersion`, `HeapCreate`,
`GetVersionExA`, `GetEnvironmentVariableA`, `GetModuleHandleA` at the *same* call
sites, `0x4014b3`/`0x4033c2`/`0x403288`/`0x4032bd`/`0x403246`), and then the two
guests are in different code: the reference goes on to initialise stdio
(`0x403b1e push 0x140` then `call [0x407090]`, i.e. `HeapAlloc`), while taote
lands in the sample's unpacker and reserves its image
(`0x4043b4 VirtualAlloc(0, 0x400000, 0x2000, 4)`), then ends on
`UnhandledExceptionFilter` (the guest's own "no handler" branch at `0x402c07`)
and dies on `UC_ERR_INSN_INVALID`. Since no API return value differs in that
window, the branch is on *guest memory*, not on a handler answer - so the IAT was
ruled out mechanically first: `parity_trace --dump-imports` now also prints the
guest's own IAT (`iat <slot> -> <stub> <name> (<imported name>)`), and for this
sample the three slots in play are all correct and distinct
(`0x407018 -> VirtualAlloc`, `0x407038 -> ExitProcess`,
`0x407090 -> HeapAlloc`). The next probe is therefore the guest's *data*, not its
code: the PEB/TEB and the CRT's own globals are the only things that differ
between the two runs at that point (`BeingDebugged` is 0 on both sides - the
loader writes the same PEB fields - so it is something else in the process
structures or in the environment block).

**The `reference_limit` verdict (this pass).** Three of the four `invalid_write
vs none` samples are the reference's own limitation, not taote defects. On
`01-01.exe_` the reference runs 5 calls and dies writing unmapped memory, while
taote runs 9: the three extra ones are `__p___initenv` and `_initterm` twice -
imports the reference reports unimplemented and leaves to the stub cell, so its
guest's CRT never initialises and walks off into unmapped memory. Everything
taote additionally dispatches (`exit`) happens *after* the first such import, so
it is downstream of the same limitation. The differ now recognises that shape
(`reference_limited`) instead of counting it as a defect, which moved the
baseline from 4 match / 28 diverged to 4 match / 3 reference_limit / 25 diverged
without touching the emulator. `14-02.exe_` looks superficially similar but is
**not** excused: taote takes an SEH path the reference does not
(`_except_handler3`, `_XcptFilter`, `_exit`), faults, and exits
`-1073741819` - a real taote-side difference and part of the 25.

The differ now reports that upstream value explicitly: when the dispatch sequences
part company it inserts a `first divergence: <api> return value` finding for the
earliest call whose *name* matches but whose scalar return differs, so the next
pass gets the root cause instead of the fan-out. (Pointer-sized return values are
compared as `ptr` by normalization, which is deliberate - a heap handle is not a
value either emulator can agree on - so the `HeapCreate` difference above is
invisible to it by design and has to be chased from the raw traces.)

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
