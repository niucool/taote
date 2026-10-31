# T-024 — the Windows environment probes answer like a 1998 sandbox: `GetVersionExA` writes no struct, `GetVersion` claims NT 4.0, `SYSTEM_INFO` claims x86 on an x64 guest, and no adapter / registry hardware description exists

| field | value |
|---|---|
| severity | **high** (a packer's environment gate reads values a real Windows cannot produce — the class that ends a run before the payload is decoded) |
| area | `qiling/os/windows/dlls/kernel32/sysinfoapi.cpp:26-30` (`get_version_ex_body`), `:115-118` (`GetVersion`), `qiling/os/windows/structs.cpp:125-161` (`write_system_info`, line 149), the **absent** `iphlpapi` module, `qiling/os/windows/dlls/advapi32.cpp` (no HKLM hardware seeding) |
| reference | `../pegasus` — `src/winenv/api/usermode/kernel32.cpp:3278-3300` (`GetVersion`/`GetVersionExA`), `:3244-3262` (`GetSystemInfo`), `src/winenv/api/usermode/iphlpapi.cpp:26-52` (`GetAdaptersInfo` + the OUI rationale), `src/winenv/api/usermode/advapi32.cpp:120-236` (hardware key seeds), defaults `src/config.cpp:26` |
| found in | cross-repo probe census taken against **pegasus `73ac29cd`**, taote `251e673`; re-based onto **pegasus `705d9a76`** (the `73ac29cd..705d9a76` pull, 56 commits) and re-verified line-for-line on 2026-10-30 — see *What changed since the baseline* below |
| status | **in progress** — item 1 (OS version + `SYSTEM_INFO` arch) landed on `task/env-probes`; items 4-5 open. See `PLAN_UNPACK.md` §8 for the measurement that says items 1+2 earn 0 corpus rows here. |

## Scope note — two kinds of item live here

The census compared taote's answers against the **pegasus reference emulator**,
not against upstream Python. Two of the items below are marked *verbatim*:
taote's own comment says the body is a faithful port of upstream's, which
means those are **reference gaps against real Windows** (feature work), not
port defects. They are still first in this ticket because they are the cheapest
high-value wins — the fix is to answer like Windows, and no existing behaviour
can regress (today the guest reads zeros).

`FindWindowA` / `FindWindowW` is **not** in this ticket: it is already fixed in
the working tree (`qiling/os/windows/dlls/user32.cpp:934-962`, the shared
`find_window_body`). Do not duplicate that work.

### What changed since the baseline (`73ac29cd` → `705d9a76`, 56 commits)

The census was measured against pegasus `73ac29cd`; the tree has since pulled to
`705d9a76` (the `Updating 73ac29cd..705d9a76` the reviewer saw). **The probe surface did
not move**, so every row in this ticket still stands:

| area | what the 56 commits did | effect on this ticket |
|---|---|---|
| `src/winenv/api/` (whole API surface) | **two** files touched: `kernel32.cpp` (+18/-7, the `MapViewOfFile` view-offset bug — it read from the file cursor instead of the file start) and `ntdll.cpp` (+9, a **comment only** explaining why `NtCreateSection`/`NtMapViewOfSection` are deliberately not stubbed) | **none** — no handler was added, removed or re-answered; the 122-API presence diff and every "pegasus answer" cell are unchanged |
| line numbers | the `MapViewOfFile` hunk is above all the cited handlers, so every cited `kernel32.cpp` symbol shifted **+4** (`GetTickCount` 3218→3222, `GetSystemInfo` 3240→3244, `GetVersion` 3274→3278, `GetVersionExA` 3283→3287, `Process32First` 3872→3876, `GetSystemFirmwareTable` 5060→5064, `GetVolumeInformationA` 5249→5253, `GlobalMemoryStatusEx` 5313→5317) | the numbers in this ticket are the **`705d9a76`** ones (verified); subtract 4 for a `73ac29cd` checkout. `iphlpapi.cpp:52` and `config.cpp:26` did not move |
| unpacker | 1,472 net lines: the per-fire env-gate hoist in the post-OEP grace, per-family emulation-budget caps, the free-stop policy (`ExitProcess` + per-family hop counts), `SE_PC_HIST`, UPX evidence, `packer_detector` tweaks. (`unpacker.cpp` also went **CRLF→LF**, which is why `git diff --stat` reports ~31k lines for a ~1.5k-line change.) | **none** — all of it is stop-policy / performance / detection plumbing; nothing answers an environment probe. Family row counts below come from the dataset, not from pegasus |
| taote | unchanged at `251e673`; none of the five items below has landed (`get_version_ex_body` still `return 1;`, `GetVersion` still `0x00040004`, `structs.cpp:149` still `put32(0, 0)`, no `iphlpapi` module, no `4D36E968` / `Hardware\description` seeds) | the fix list is still entirely open |

One observation from the range worth carrying: the Yoda-Protector post-OEP cost dropped
(30 s → 14.7 s, `df549cf0`), i.e. pegasus keeps buying Yoda rows with **unpacker** work
rather than by fixing the environment answers — which is the reason its A/B on the
`FindWindowA` hack shows no delta (see the census report) and why item 3 (`SYSTEM_INFO`)
and the `GetTickCount` follow-up below are still the cheapest real wins.

## What is wrong

### 1. `GetVersionExA` returns 1 without writing the caller's `OSVERSIONINFO` (verbatim)

```cpp
// qiling/os/windows/dlls/kernel32/sysinfoapi.cpp:26-30
// the shared __GetVersionEx body (the verbatim 1, no struct write)
std::optional<std::uint64_t> get_version_ex_body(Qiling&, const ResolvedParams&) {
    return 1;
}
```

The caller's buffer is left untouched (zeroed by the guest's own stack/alloc
state), so every field a packer reads back is **0**:

- `dwMajorVersion = 0`, `dwMinorVersion = 0`, `dwBuildNumber = 0`
- `dwPlatformId = 0` — real Windows always reports `VER_PLATFORM_WIN32_NT = 2`
- `szCSDVersion = ""`

A minimum-OS gate (`major >= 5`) therefore fails on a *successful* return —
the worst shape, because the stub believes it asked and got an answer.

pegasus fills the struct from its config (`kernel32.cpp:3287-3300`): size,
major/minor/build from `config.os_ver` (default **6.1 / 7601**, `config.cpp:26`),
`dwPlatformId = 2`, and writes the whole record.

### 2. `GetVersion` reports NT 4.0 (verbatim)

```cpp
// qiling/os/windows/dlls/kernel32/sysinfoapi.cpp:115-118
WinsdkApi("GetVersion", WinCc::Stdcall, {}) =
    [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
    return (0x0004 << 16) | 0x0004;
};
```

`0x00040004` is Windows NT 4.0. Anything predating XP-era APIs is refused by
protectors that require a supported OS. pegasus returns the same configured
version as above (`kernel32.cpp:3278-3286`), so both entry points agree — as
they do on a real machine.

### 3. `SYSTEM_INFO` reports `wProcessorArchitecture = 0` (INTEL) on an x64 guest

```cpp
// qiling/os/windows/structs.cpp:149
put32(0, 0);  // dwOemId (the anonymous union dword)
```

`dwOemId` overlays the union whose low word is `wProcessorArchitecture`
(`0 = PROCESSOR_ARCHITECTURE_INTEL`, `9 = PROCESSOR_ARCHITECTURE_AMD64`). The
writer takes `bits` but never uses it for this field, so a **64-bit** guest is
told it runs on an x86 processor — a self-contradiction a protector can detect
without any host fingerprinting. The other values (`dwNumberOfProcessors = 4`,
`dwProcessorType = 0x24a`, `wProcessorLevel = 6`) are plausible but incoherent
with it (486-class type at level 6).

pegasus sets the architecture explicitly per pointer size
(`kernel32.cpp:3244-3262`): `wProcessorArchitecture = 9` for x64,
`dwPageSize = 0x1000`, `dwActiveProcessorMask = 1`, `dwNumberOfProcessors = 1`.

### 4. No `iphlpapi` module at all — `GetAdaptersInfo` cannot be bound

`grep -rn iphlpapi qiling/` → **no hits**. There is no adapter surface, so a
stub that imports `GetAdaptersInfo` / `GetAdaptersAddresses` (or
`LoadLibraryA("iphlpapi.dll")`) hits an unregistered dll/API and takes the
default answer.

This is the one class where the reference has a **named, measured veto** for a
family we share: pegasus's comment
(`src/winenv/api/usermode/iphlpapi.cpp:26-33`)

> OUI matters: 00:0C:29 is VMWARE, and any protector that fingerprints the
> adapter MAC reads it as "running inside a VM" (measured on
> `E:/tera-re/TERA.packed.exe`, WinLicense 3.x: after `GetAdaptersInfo` the
> loader popped **"A debugger has been found running in your system."** and
> returned from the packed entry with the payload still packed). Use a plain
> Intel OUI (00:1B:21) so the emulated host looks like real hardware.

…and the answers are a plain, consistent `IP_ADAPTER_INFO` chain
(`iphlpapi.cpp:52-160`: 6-byte MAC `00:1B:21:AB:CD:EF`, `Type = MIB_IF_TYPE_ETHERNET`,
`DhcpEnabled = 0`, IPv4 `192.168.1.100/255.255.255.0`, `GatewayList` same subnet).
TERA itself is not in our corpus, but it is the same Oreans/WinLicense engine as
the **Themida** family (122 packed rows here).

### 5. No registry hardware description to cross-check

`grep -n "Hardware\\description\|4D36E968\|CurrentControlSet" qiling/os/windows/dlls/advapi32.cpp`
→ **no hits**. pegasus seeds the four keys a WinLicense-class fingerprint walks
(`src/winenv/api/usermode/advapi32.cpp:121-140`):

> Oreans WinLicense/THEMIDA fingerprints the host through the registry and
> vetoes the run when the keys are missing — measured on
> `E:/tera-re/TERA.packed.exe`, whose four probes are logged by the
> `SE_DEBUG_API` `[api-reg]` line and ALL returned `ERROR_FILE_NOT_FOUND`:
> `SYSTEM\ControlSet001\Control\Class\{4D36E968-…}\0000` (display adapter),
> `Hardware\description\System` (BIOS data), `HARDWARE\ACPI\DSDT\VBOX__`
> (correctly absent — a real machine has no `VBOX__` DSDT), and
> `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-…}` (network adapter).
> Values are consistent with the SMBIOS table
> `Kernel32::GetSystemFirmwareTable` reports, so a protector that cross-checks
> the two sees one machine.

Note the deliberate asymmetry: the VM-flavoured key (`VBOX__`) must stay
**missing**; only the "real hardware" keys are seeded.

## Why it matters (row value)

| item | families in this corpus | rows |
|---|---|---|
| 1+2 OS version | every family with an OS gate; documented consumer is the Oreans engine (**Themida**) and TELock-era stubs | Themida 122, TELock 118 |
| 3 `SYSTEM_INFO` arch | x64-vs-x86 self-checks; VM fingerprinting (Alienyze, Themida) | Alienyze 126, Themida 122 |
| 4 adapters | Oreans WinLicense / Themida (pegasus's measured veto) | Themida 122 |
| 5 registry hardware | Oreans WinLicense / Themida (same four probes) | Themida 122 |

(Armadillo/WinLicense-class samples outside this tree benefit identically; the
numbers above are only what the local corpus can exercise.)

## Suggested fix

Order matters — do them as separate diffs:

**1+2 (one diff).** Give `get_version_ex_body` a real body and make
`GetVersion` agree with it. Copy from `../pegasus/src/winenv/api/usermode/kernel32.cpp:3278-3300`
(`OSVERSIONINFO` layout, `dwPlatformId = 2`, size field, string tail). Take the
version from a profile key so it is configurable, defaulting to 6.1 / 7601
(pegasus: `src/config.cpp:26`). `GetVersion` then packs the same
major/minor from that source instead of the `0x00040004` constant.

**3 (one diff).** In `write_system_info` (`structs.cpp`), write the arch from
`bits` instead of `0`:

```cpp
// qiling/os/windows/structs.cpp:149 — currently put32(0, 0);
put16(0, bits == 64 ? 9 /* AMD64 */ : 0 /* INTEL */);   // wProcessorArchitecture
put16(2, 0);                                            // wReserved
```

and make the neighbouring values coherent with it (pegasus:
`kernel32.cpp:3244-3262`).

**4 (new module).** Add an `iphlpapi` family registering `GetAdaptersInfo` and
`GetAdaptersAddresses` (both exist in the reference: `iphlpapi.cpp:52-126` and
`:129-160`; `GetNetworkParams`/`GetIfEntry`/`GetIfTable` follow at `:162-215` if
the family is opened anyway), porting the record layout from those spans. Keep the OUI decision
explicit in a comment: **never** `00:0C:29` (VMware), use `00:1B:21` (Intel).

**5 (one diff, same class as 4).** Seed the four keys above in the advapi32
registry tree (`qiling/os/windows/dlls/advapi32.cpp`), with values consistent
with the SMBIOS table (once item 6 below exists) — and leave
`HARDWARE\ACPI\DSDT\VBOX__` absent on purpose.

## Acceptance test

Add to `tests/Windows_Api_Test.cpp` (one test per item, each must fail against
the current tree first):

- `GetVersionExAFillsTheStruct` — call it on a zeroed 276-byte guest buffer;
  assert `dwOSVersionInfoSize` is a sane size, `dwPlatformId == 2`,
  `dwMajorVersion >= 5`, and that `GetVersion()`'s major/minor match the
  struct's. **Fails today**: every field is 0 / `0x00040004`.
- `SystemInfoReportsTheGuestArchitecture` — call `GetSystemInfo` on both a
  32-bit and a 64-bit `Qiling` instance; read `wProcessorArchitecture` at
  offset 0 and assert `9` for x64, `0` for x86, plus
  `dwPageSize == 0x1000` and `dwNumberOfProcessors >= 1`.
  **Fails today** for x64 (reads 0).
- `AdaptersInfoDescribesRealHardware` — open `iphlpapi.dll`, `GetAdaptersInfo`
  into a sized buffer; assert one adapter with `Type == 6`,
  `AddressLength == 6`, and that the OUI is **not** `00:0C:29` (the VMware
  signature) and not all-zero.
  **Fails today**: no such module/API.
- `RegistryHardwareDescriptionExists` — `RegOpenKeyExA` / `RegQueryValueExA`
  the four keys above (the display class, `Hardware\description\System`, the
  network class) → success with data; and
  `RegOpenKeyExA("HARDWARE\\ACPI\\DSDT\\VBOX__")` → `ERROR_FILE_NOT_FOUND`.
  **Fails today**: all four return "not found".

## Follow-ups from the same census (separate tickets, not blocking this one)

| gap | pegasus reference | why it might matter |
|---|---|---|
| `Process32First/Next`, `Module32First/Next`, `Thread32First/Next`, `EnumProcesses`, `EnumProcessModules` | `kernel32.cpp:3876-4040` (`Process32First/Next` 3876/3880, `Thread32First/Next` 3910/3914, `Module32First/Next` 4004; the shared `process32_impl` carries the non-zero parent-PID fill — pegasus's `YODA-PARENTPID`), `src/winenv/api/usermode/psapi.cpp` | taote registers only the **W** spellings and returns 1 *without writing the struct* (`dlls/kernel32/tlhelp32.cpp:44-62`) — an A-using debugger scan sees an empty process name; the parent-PID cell is what the yP stub's phase-2 verdict reads |
| `GetTickCount` instruction-clock (`SE_YODA_TICKINSN`) | `kernel32.cpp:3222-3240` | the yP stub busy-waits on `GetTickCount` deltas; an instant emulator makes the delta 0 and fires the anti-emu verdict |
| `GetSystemFirmwareTable` ('RSMB' SMBIOS) | `kernel32.cpp:5064` | VM/BIOS-string detection; the registry seeds must agree with it |
| `GlobalMemoryStatus` / `GlobalMemoryStatusEx` / `GetTickCount64` | `kernel32.cpp:5308`, `:5317`, `:5225` | RAM-size VM checks |
| `GetVolumeInformationA` (stable serial) + `GetDriveTypeA` | `kernel32.cpp:5253`, `:1819` | volume-serial fingerprint |
| `NtSetInformationThread` (HideFromDebugger) | `src/winenv/api/kernelmode/ntoskrnl.cpp:2235` | thread-level anti-debug |
| `EnumWindows`, `GetWindowTextA`, `GetClassNameA` | `user32.cpp` (window enumeration) | desktop-existence sanity checks |

One reverse note (taote is *ahead* here, do not "fix" it): taote implements
`NtQueryInformationProcess` with the canonical anti-debug trio
(`dlls/ntdll.cpp:66-100`: `DebugFlags=1`, `DebugPort=0`,
`DebugObjectHandle=STATUS_PORT_NOT_SET`) and reads `PEB.BeingDebugged` in
`IsDebuggerPresent`; pegasus answers a flat 0 and does not register
`NtQueryInformationProcess` at all.

## Status log

**Item 1 (items 1+2+3 of the fix list) — landed.** `get_version_ex_body` fills
`OSVERSIONINFO[A|W]` (and the `OSVERSIONINFOEX` tail when the caller declares that size:
`wProductType = 1`, not the illegal 0) from the `[SYSTEM]` profile, `GetVersion` packs the
same `(build << 16) | (minor << 8) | major`, and `write_system_info` answers
`wProcessorArchitecture = 9` on a 64-bit guest. `buildNumber = 19045` is a new profile key.

Measured (pin 2, budget 85 s): **0 gains, 0 losses** — Themida+TELock+Alienyze 75/364 →
75/364 all-three, S75 54/75 → 54/75, per-sample verdicts identical on all 439 rows, 0
wall-timeouts.

**The row-value table in this ticket is wrong for this corpus.** `TAOTE_APIDBG` traces show
Themida (5 `LoadLibraryA` + 4 `GetModuleHandleA` + 2 `GetProcAddress` + `GetCurrentThreadId`)
and TELock (3 calls: `GetModuleFileNameA`/`CreateFileA`/`ReadFile`) never call `GetVersion*`
or `GetSystemInfo` at all before the run ends, and Alienyze's 110-call trace is the CRT +
`GetProcAddress`. An import census over all 3,001 packed samples puts the real importers at
**Enigma Virtual Box 122 / Neolite 27 / JDPack 19** for `GetVersionExA` — and EnigmaVB and
Neolite are already 3/3 at S75. `GetAdaptersInfo` is imported by **14 of 3,001**, so item 4
is a 14-sample lane, not a 122-row one. Detail: `PLAN_UNPACK.md` §8.3.
