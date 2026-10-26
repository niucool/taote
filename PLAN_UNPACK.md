# PLAN — unpacking: port pegasus's unpacker to taote

Goal (the directive this document sequences): **taote can unpack packed PEs the
way `../pegasus` does** — detect the packer, emulate the stub to the original
entry point (OEP), dump the image, rebuild a loadable PE with a working import
table, and hand the artifact to normal analysis. Written as a *plan*: nothing
below is implemented yet. Every phase names a number and an exit test.

pegasus is the oracle throughout (its binary builds and runs here — §5), and its
own evaluation harness is reused verbatim so the two tools are graded by the same
code (§0.1).

---

## 0. Scoreboard

### 0.0 What "unpacked" means (the grader, not an opinion)

pegasus ships the evaluation rubric this plan adopts (`tools/unpack_eval/README.md:56-85`,
implemented in `tools/unpack_eval/verify.py`). Per sample:

| check | rule |
|---|---|
| (a) success + OEP | `<stem>_unpacked.exe` exists **and** `<stem>_dump.bin.meta.json` has `oep != 0x0` |
| (b) output PE parses | MZ/PE, magic `0x10b|0x20b`, 1..96 sections, `SizeOfImage >= 0x1000`, EP RVA < `SizeOfImage` |
| (c) entry point | output EP RVA == **original** EP RVA (exact; `ep_delta` + same-section `ep_near` recorded) |
| (d) code similarity | original `.text` raw bytes vs output image at the same RVAs, equal/total (raw-image fallback when the output's section table is degenerate) |
| (e) import DLL coverage | \|original DLLs ∩ (output imports ∪ meta imports)\| / \|original DLLs\| |

Grades as *implemented* (`verify.py:294-352`): `UNPACKED_VERIFIED` = (b)+(c)
exact+(d) ≥ 0.90+(e) ≥ 0.80, on top of `_unpacked.exe` existing; `PARTIAL` = (b)
with (d) ≥ 0.50 or (e) ≥ 0.30; `MANAGED` = as PARTIAL for a .NET original (c is
meaningless; `README.md:85-90`); else `FAILED`. Check (a) is computed but not
consulted by the grade — see the next bullet.

Three properties worth internalising before phase 1:

* **byte identity is not required** — a correct OEP with ≥90% of `.text`
  matching and ≥80% dll coverage grades VERIFIED;
* **(a) is advisory in the reference grader**: `verify.py:279-282` computes
  `a_success_oep` but the grade decision (`:344-350`) only enforces
  `has_unpacked`. Measured consequence on S75: 6 samples (3 MEW, 3 Molebox) have
  `meta_oep == 0x0` — their `meta.json` is **not valid JSON** (pegasus's
  hand-rolled serializer mis-escapes an import name; `python3 -m json.tool`
  fails at char 6827) — and they still grade UNPACKED_VERIFIED. So this plan
  reports a **strict** number too: `grade == VERIFIED ∧ a_success_oep`, and
  taote's own artifacts must emit valid JSON (nlohmann is already linked);
* **artifacts are cheap, OEP is cheap, recovery is the work** — measured at S75:
  75/75 produced all three artifacts, 69/75 have a non-zero OEP, 66/75 grade
  VERIFIED, **60/75 grade VERIFIED strictly**.

### 0.1 Corpus (measured here, 2026-10-22)

`~/source/jim/dataset-packed-pe` (fork of PackingData, `README.md:1-8`):

| tree | files | note |
|---|---|---|
| `packed/<Family>/` | **3,001** `.exe` across **25** family dirs (109 Packman .. 152 Amber) | the unpack workload |
| `not-packed/` | 424 `.exe` (432 files) | the ground-truth originals |
| `outliers/packed/` | 142 | extra packed samples |
| `outliers/not-packed/` | 10 | packed-looking originals |

Pairing is mechanical: `<packer>_<original>.exe` → `not-packed/<original>.exe`
(`build_manifest.py`, and confirmed empirically — the cap-1 and cap-3 manifests
report `skipped_no_original == 0`, i.e. **every** sampled packed file has an
original to grade against).

Two scoreboard scopes are fixed by this plan:

* **S75** — `build_manifest.py --cap 3` (3/family, 75 samples). Fast enough to
  re-measure after every phase (measured: 75 runs in ~7 min at `--pin 4`).
* **S500** — `--cap 20` (pegasus's own default, 500 samples). The regression
  gate; run at phase boundaries only.

### 0.2 Oracle baseline on this host (measured, not quoted)

`~/source/jim/pegasus/build/cli/pegasus-cli`, `--unpack --unpack-output …
--unpack-timeout 85`, graded with `verify.py`:

| scope | artifacts | non-zero OEP | UNPACKED_VERIFIED | strict (VERIFIED ∧ (a)) | PARTIAL | FAILED |
|---|---|---|---|---|---|---|
| S75 | 75/75 | 69/75 | **66 / 75 (88.0%)** | **60 / 75 (80.0%)** | 2 | 7 |
| cap 1 (25 samples) | 25/25 | 25/25 | 22 / 25 | 22 / 25 | 1 | 2 |

Wall time at S75: median 5 s, max 87 s; **0 wall-timeouts** (`run_all.sh` report).

Per family at S75 (VER/PART/FAIL):

```
ASPack 3/0/0   Alienyze 2/1/0   Amber 2/0/1   BeRoEXEPacker 3/0/0  EXpressor 3/0/0
EnigmaVB 3/0/0 Eronana 3/0/0    Exe32pack 3/0/0  FSG 3/0/0          JDPack 3/0/0
MEW 3/0/0      MPRESS 3/0/0     Molebox 3/0/0    NSPack 3/0/0       Neolite 3/0/0
PECompact 3/0/0 PEtite 3/0/0    Packman 3/0/0    RLPack 3/0/0       TELock 3/0/0
Themida 0/0/3  UPX 3/0/0        WinUpack 2/1/0   Yoda-Crypter 3/0/0 Yoda-Protector 0/0/3
```

The residual failure classes at S75, with the grader's own reason strings:

| family | sample | reason |
|---|---|---|
| Themida ×3 | 7z / ADExplorer / ADInsight | `no-recovery(sim=0.107/0.054/0.065)` — OEP latched, image not decrypted (VM protector) |
| Yoda-Protector ×3 | ADExplorer / ADInsight / AccessEnum | `no-recovery(sim=0.054/0.065/0.043)` — same class |
| Amber | AddInProcess32 | `no-recovery(sim=0.060,cov=0.0)` |
| Alienyze | ADExplorer | `code-sim<0.90` (sim 0.0 — the on-demand page decrypter never ran) |
| WinUpack | ADExplorer | `imp-cov<0.80` (code sim 1.0 — imports only) |

For scale: pegasus's canonical full-corpus census (2,757 samples, its own
instrument) is OEP 2,083 · CODE-full 1,925 · IAT 1,569 · **strict-green 1,459
(52.9%)** (`docs/unpacking-roadmap.md:5`). The 88% at S75 is the *easy* third of
each family; the honest full-corpus expectation is ~50-60%.

### 0.3 Detection baseline (measured, static only)

Running pegasus's detector over 3 samples/family (`SE_DEBUG_DETECTOR=1`):

| result | count | families |
|---|---|---|
| detector name == family dir (case/hyphen-normalised: `YodaCrypter` ≈ `Yoda-Crypter`, `Eronana` ≈ `Eronana Packer`) | 22/25 | ASPack Alienyze Amber EnigmaVB Eronana Exe32pack JDPack MEW MPRESS Molebox NSPack Neolite PECompact PEtite Packman RLPack TELock Themida UPX WinUpack Yoda-Crypter Yoda-Protector |
| misnamed | 1/25 | **BeRoEXEPacker → "Eronana"** (3/3): BeRo's EP matches Eronana's `60 68` EP signature |
| unknown | 2/25 | **EXpressor (3/3)**, **FSG (3/3)**: the `.ex_cod`/`.ex_dat` and `fsg` name sigs miss — these samples fall to the generic path and *still verify* (3/3 each), so detection is a routing signal, not a prerequisite |

### 0.4 taote today

| metric | at plan time | after round 1 (§0.5) | target |
|---|---|---|---|
| S75 UNPACKED_VERIFIED | 0 | **33 / 75** (round 2) | P1 45, P3 60 |
| S500 UNPACKED_VERIFIED | 0 | not yet run (gated on the family work) | ≥ 250 (≈ oracle's 52.9% census) |
| detector name-exact, 25 families | 0 (no detector) | 22/25 (the tool's name guess; Phase 2 has not landed as a library) | P2 25/25 |
| artifact contract (`<stem>_dump.bin`, `.meta.json`, `_unpacked.exe`) | absent | **met** (valid JSON, asserted) | P0 |
| host crashes (S75) | n/a | **0** across all rounds (+80 mutated images) | **0**, always |
| taote suite | 574 passed (stub) | **578 passed** (4 unpack cases) / 586 + 1 known red (real dlls) | unchanged at every phase |

---

## 0.5r1 Measured status (implementation round 1, 2026-10-22)

The unpacker is implemented as `qiling/unpack/` (library), `tools/taote_unpack`
(the flag-compatible CLI) and `tests/Unpack_Compat_Test.cpp` (contract, meta-JSON,
rebuilt-PE round-trip and host-safety cases). Measured with the *same* harness and the
*same* 75 samples as §0.2 (`--unpack-timeout 85`, wall 120, `--pin 4`):

| phase | S75 UNPACKED_VERIFIED | notes |
|---|---|---|
| 0 artifact-only (`--no-hop`) | **0 / 75** | 56 partial, 19 failed — the entry-state dump |
| 1 generic core (hop + dump + rebuild) | **7 / 75** | UPX 3, EXpressor 2, Packman 2 |
| 1b GPA sentinel + decoy dlls + salvage | **9 → 20 / 75** | the sentinel lane is a *Phase 1* prerequisite, see below |
| OEP pick (incumbent prior) + header-EP + MEW static + shadow | **18 / 75** | 43 partial, 14 failed |
| **oracle, same 75** | **66 / 75** (strict 60) | §0.2 |

Wall time: median 1 s, max 25 s, **0 wall-timeouts** (oracle: median 5 s, max 87 s).

Per family (VER / PART / FAIL), taote:

```
UPX 3/0/0        Eronana 3/0/0     FSG 2/1/0        JDPack 2/1/0     ASPack 1/2/0
BeRo 1/2/0       EXpressor 1/2/0   EnigmaVB 1/2/0   MEW 1/2/0        MPRESS 1/2/0
Packman 1/2/0    WinUpack 1/1/1    Molebox 0/3/0    NSPack 0/3/0     Neolite 0/3/0
PECompact 0/2/1  PEtite 0/3/0      RLPack 0/3/0     TELock 0/3/0     Themida 0/3/0
Yoda-Crypter 0/3/0  Yoda-Protector 0/0/3  Alienyze 0/0/3  Amber 0/0/3  Exe32pack 0/0/3
```

The oracle's cells for the same families are in §0.2 (66/75): the gap is **one
class** — the OEP of the trampoline/VM families.

## 0.5 Measured status (implementation round 2, 2026-10-22)

| phase | S75 UNPACKED_VERIFIED |
|---|---|
| round 1 (generic core + pick + salvage) | **18 / 75** |
| round 2a: the decode-only ladder (Pass-C / Borland / MSVC frame) | **30 / 75** |
| round 2b: Pass-B ordering, degenerate-layout fallback, inter-map salvage | **33 / 75** |
| round 2c: orphan import-list mining (the FSG string-blob reconstruction) | **36 / 75** |
| round 2d: MEW full shadow overlay, exec-page view, NSPack start override | **36 / 75** (all three measured inert) |
| round 2e: the marker-tolerant blob walk + per-dll union | **36 / 75** (coverage moves: BeRo imp 2 -> 80, WinUpack 2 -> 122, MEW 0.786/0.769) |
| round 2f: ordinal-flag (0x80) skipping + single-import dll blocks | **37 / 75** (FSG 2/3 -> 3/3) |
| round 2g: Pass B ahead of Borland, static entry over a distant hop | **39 / 75** (JDPack 1/3 -> 3/3) |
| **round 2 final** | **39 / 75 VERIFIED, 26 PARTIAL, 10 FAILED** |
| oracle, same 75 | 66 / 75 (strict 60) |

Per family (VER / PART / FAIL), round 2:

```
UPX 3/0/0        ASPack 3/0/0       Eronana 3/0/0     MPRESS 3/0/0      Packman 3/0/0
RLPack 3/0/0     Exe32pack 3/0/0    Yoda-Crypter 3/0/0  EnigmaVB 3/0/0   FSG 3/0/0
JDPack 3/0/0     EXpressor 2/1/0    BeRo 1/2/0        MEW 1/2/0         Molebox 1/2/0
WinUpack 1/1/1   NSPack 0/3/0       Neolite 0/3/0     PECompact 0/2/1   PEtite 0/3/0
TELock 0/3/0     Themida 0/3/0      Alienyze 0/1/2    Amber 0/0/3       Yoda-Protector 0/0/3

Eleven families are fully verified; the residual is dominated by payloads that are
never decoded (`code-sim<0.90`: PEtite 3 with the exact EP but 0.80 similarity, MEW 2,
and the NSPack/Neolite/PECompact/TELock group at 0.004-0.19).

Wall time at S75: median 1 s, max 25 s, 0 wall-timeouts (oracle median 5 s, max 87 s).
```

Everything the ladder touched is now green in the families where the payload decodes:
the six compressor families (UPX, ASPack, Eronana, MPRESS, Packman, RLPack) are 3/3,
Yoda-Crypter went 0/3 -> 3/3 on the Borland pre-check, and Exe32pack 0/3 -> 3/3 on
the degenerate-layout fallback.

### 0.5.1a What round 1 already proved

* the write-claim → section-hop → dump → `.pgimp` rebuild chain works: **UPX,
  ASPack, FSG, Eronana, JDPack, Packman** reach the exact original EP and dump a
  90-100% identical `.text` (e.g. `upx_AccessEnum`: OEP `0x407a98` = the
  original's EP, sim 1.0, coverage 1.0);
* import recovery is solved for the generic path: the GPA sentinel lane +
  on-demand decoy dlls + the dump's own import descriptors give FSG 14/15 dlls
  (the oracle: 15/15) where the first cut had 1/15;
* the host-safety rule holds: 80 mutated/degenerate images through the rebuilder,
  zero crashes (`UnpackCompat.UnpackHostSafety`), and no run in S75 took the
  process down.

### 0.5.2 The remaining 42 samples, diagnosed (round 2)

Failure reasons across the 42 non-verified (verify.py):

| reason | count | what it means |
|---|---|---|
| `ep-mismatch(near), code-sim<0.90` | 11 | the decode is incomplete (NSPack 3, Neolite 3, PECompact 2, TELock 2, …) |
| `imp-cov<0.80` | 6 | EP and code are right, the import table is not recoverable from memory (EnigmaVB 2, BeRo 2, FSG 1, WinUpack 1) |
| `ep-mismatch, code-sim<0.90, imp-cov<0.80` | 4 | undecoded + no imports (TELock) |
| `code-sim<0.90, imp-cov<0.80` | 3 | MEW 2 + JDPack 1 |
| `code-sim<0.90` | 2 | PEtite 7zFM/7zFMn: EP exact, .text only ~0.80 decoded |
| `ep-mismatch(near)` | 2 | JDPack 7zFM/7zFMn |
| `no-recovery` | 2 | Alienyze (the page decrypter never runs) |

Per-family causes with evidence:

* **NSPack (3)** — the packed header EP (0x101b) points at ZERO bytes: nsp0's raw
  head is 0xe9 bytes of zeros, so the first instruction is `add [eax],al`, the write
  to 0 faults and the run ends before any decode. The oracle reports stages=2 plus a
  *dynamic-region* dump at 0x8000, so its flow maps/executes something taote does
  not. This is the only family where the failure is *before* the OEP pick.
* **Neolite / PECompact / TELock** — the payload is never decoded into the image
  (`.text` similarity 0.03-0.19). Neolite needs its registry IAT build, PECompact
  its `family_capture_hop_`/`family_post_terminal` seam, TELock the JIT shadow
  transform + second-latch exec defer.
* **PEtite / JDPack (6)** — the *decoded* body is close but not whole: PEtite's 7z
  payloads sit at 0.80 similarity with the exact EP found (Pass B), JDPack's at
  0.46-0.93. A full first-write shadow overlay was implemented and measured to make
  this WORSE (0.93 -> 0.47): their stubs write transient ciphertext pages before
  the real decode, so the first-write capture is not the decoded view. What is
  needed is the reference's per-page decrypt tracking (PETITE_INT_RUNS), not an
  overlay.
* **EnigmaVB (2)** — EP exact, similarity 1.0, coverage 0.36: the payload's import
  descriptors are rebuilt by EVB's VFS at runtime and the slots hold EVB
  trampolines, so neither the dump's IDir nor the loader's export map finds them.
  Needs the VFS import walk (`family_reconstruct_orphans`).
* **BeRo / WinUpack / MEW (5)** — the stub restores the IAT itself and the payload's
  descriptors are overwritten; scanning the image AND every other mapped region for
  loader-known addresses finds nothing (measured: FSG AccessEnum's whole image holds
  20 dll-region dwords, none of them an export cell). The first half of the
  reference's orphan mining is now in (`mine_orphan_descriptors`): FSG AccessEnum's
  bare string blob is reconstructed exactly (8 dlls / 215 names, first pair
  KERNEL32.dll!GetModuleHandleA after undoing FSG's +3 first-character shift) and
  that is what took EnigmaVB to 3/3. BeRo, MEW and WinUpack store the list
  differently (no blob found), and fsg_AccessEnum's coverage reaches 0.667 — one dll
  short of the 0.80 bar. The blob walk is now marker-tolerant (MEW separates its
  blocks with one-character pieces, so the first version dropped all but one group)
  and it unions a per-dll pass; that took MEW to 11/14 dlls (0.786) and BeRo's
  ADInsight from 2 pairs to 80, and WinUpack's from 2 to 122 — but the last two or
  three dlls of each remain: their name blocks are not adjacent to their dll string,
  and pairing them needs the reference's ordinal dll-list-to-group join (attempted,
  did not fire on the real layout, not shipped).
* **Alienyze / Amber (6)** — the decrypter never runs; Amber allocates nothing at
  all (its only non-image map is one heap page), so the embedded-PE scan is inert
  (implemented and measured — see the round-2 commit).
* **Themida / Yoda-Protector (6)** — the oracle is 0/3 on both.

### 0.5.3 The original (round 1) diagnosis

Failure reasons across the 57 non-verified, from `verify.py`:

| reason | count | what it means |
|---|---|---|
| `ep-mismatch` (± code-sim / imports) | 37 | the OEP is not the payload's entry — the dump is taken from terminal memory, so this is purely the **candidate selection** |
| `ep-mismatch, code-sim<0.90` | 12 | OEP wrong **and** the decode incomplete at the moment the stub stopped |
| `bad-output-PE` | 3 | Exe32pack's degenerate header — the rebuild now falls back to the verbatim dump, but the artifact still fails (b) |
| `no-recovery` | 2 | Alienyze: the on-demand page decrypter never ran |

Per-family cause, evidenced by the debug traces (`TAOTE_UNPACK_DEBUG=1`):

* **NSPack / RLPack / MPRESS** — the stub `ret`s through trampolines into the
  decoded payload; the section-hop sees the mid-decode excursions and the run ends
  before the final transfer. Needs the reference's decode-only ladder
  (`decode_only_ladder`, unpacker.cpp:7814-7930) and its Pass-C scan. Measured:
  MPRESS picks the right EP on 1/3 (the `0x407a98` shape), the others park on a
  stub address.
* **PEtite** — needs the transition-history pick (`unpacker.h:623-650`): the
  stub's last hop before it stops writing is the hand-off. Measured: the ledger
  contains both the mid-decode hop and the final one; the current pick prefers the
  former.
* **TELock** — the decode is just-in-time (decrypt → execute → re-encrypt); the
  terminal dump is re-encrypted. The shadow overlay restores wiped zeros only, so
  TELock needs the full shadow transform (`family_transform_dump_image`) and the
  second-latch exec defer.
* **Themida / Yoda-Protector** — the oracle fails these too (0/3 each). Not
  attempted; the plan's tier D.
* **Alienyze** — the per-sample XOR recovery (`recover_alienyze`,
  alienyze.cpp:1-1544) is the only path; the stub's page decrypter never runs
  under emulation (2 of 3 samples have no image at all).
* **Amber** — `try_embedded_pe`: the payload PE is built in a heap buffer, so the
  image dump is empty; needs the map scan (unpacker.cpp:10430-10520).
* **Molebox / Neolite / PECompact / EnigmaVB / Exe32pack** — container/registry/
  header-specific recovery (the plan's tier B/C rows). EnigmaVB improves with the
  header EP (1/3 now); its import coverage (0.36-0.38) needs the VFS import walk.

### 0.5.3b Measured-and-reverted in round 2 (so round 3 does not repeat them)

| attempt | measurement | conclusion |
|---|---|---|
| full first-write shadow overlay for PEtite/TELock/JDPack | JDPack `.text` 0.93 -> 0.47, PEtite 0.80 -> 0.69 | the stubs write transient ciphertext pages before the real decode; only the zeros-restore is generic |
| exec-page snapshot overlay (page captured at first execution) | no change on any family (S75 33/33) | the payloads stop before executing the undecoded pages — the blocker is upstream |
| MEW full shadow overlay (the reference's own family exception) | restores 9.8-11.2 KB/sample, similarity unchanged (0.758 / 0.832), coverage 0.07 | MEW's deficit is not the memset |
| embedded-PE adoption for Amber | never fires: Amber allocates nothing (its only non-image map is one heap page) | the stub dies before building the payload |
| NSPack: force the emulation start (`TAOTE_UNPACK_START`, tool flag) | both 0x42a000 (nsp1 start) and 0x401047 still end at pc 0x40101b with 0 writes | the stub itself jumps to the zero-filled head; needs the oracle's flow, not a different start |
| inter-map IAT salvage + all-scattered-slots rule | adds only MEW's two known pairs; FSG/BeRo/WinUpack hold no loader-known addresses at all | those families need name mining, not pointer mining |

### 0.5.3c TELock: why it is undecoded (probed, not guessed)

`telock_AkelAdmin.exe`: the stub claims its own section (`claim [0x407000,0x40b000)`,
6481 writes) and then dies with **`UC_ERR_INSN_INVALID` at pc 0x408a08** — an opcode
unicorn's CPU model cannot decode (the same limitation already recorded for AVX/XSAVE
in the corpus sweep). The payload is therefore never decompressed, which is why its
similarity is 0.19 and the pick's candidates sit at `…0x3c` offsets inside the stub.
Nothing about the OEP or the shadow transform can change that: the first work item for
TELock in round 3 is the faulting opcode, not the dump transform.

Round-3 probes on that opcode (both measured, both reverted):

* **a bare skip** (`pc + 1`) makes the stub loop forever — the unpack call hits the
  wall timeout (`rc=124`, no artifacts). Reverted.
* **real #DB delivery** — a public `QlOsWindows::deliver_cpu_exception(pc)` calling the
  same `seh_check_cpu_exception` path the trace hook uses, invoked from an
  `insn_invalid` hook when the byte at pc is `0xf1` — fires at exactly the right
  address (0x408a08 / 0x419a08) but **re-fires at the same pc**: no handler consumes
  it, no `seh_retarget`, no progress (capped at 256 deliveries). Reverted.

The bytes at the fault say why: `f1 ff 02 eb e8 eb 02 cd 20 98 2b c1 e8 0a 00 00` —
ICEBP, then `inc [edx]`, a short jump, `int 0x20`, `cwde`, `sub eax,ecx`, `call`. That
is a self-modifying marker sequence whose trap handler does the work, i.e. TELock's
handler (or the VEH that installs it) must already exist when it executes. Since
delivery finds no handler, our stub reached this point having **skipped whatever
installs it** — the divergence is in an earlier anti-emulation branch, not at `f1`.
Round 3's TELock step therefore starts by tracing the branch that leads here (compare
the API sequence up to the fault against the oracle's), not by touching the exception
path or the dump transform.

### 0.5.3d Round 3 entry points (measured state, exact first move per class)

| class | rows | measured blocker | first move |
|---|---|---|---|
| TELock | 3 | stub dies on `0xf1` (ICEBP) at pc 0x408a08 / 0x419a08; a bare skip makes it loop forever (wall timeout, `rc=124`, measured) | deliver a debug exception through the guest's own handler (the SEH path exists: `QlOsWindows::seh_*`), not a skip |
| PEtite | 3 | entry exact on 7z but similarity 0.798: lazy per-page decrypt, payload faults at its first import | `PETITE_INT_RUNS`: keep emulating past the OEP with imports answered by the stub arena so the pages decrypt |
| Neolite | 3 | similarity 0.03-0.04, imports fine: demand-paged decryption, only touched pages decrypt | replay the page-decrypt routine for every page before the dump |
| PECompact | 3 | similarity 0.004-0.05; the dump holds no chunk of the original `.text` at any offset (byte-searched) | `family_capture_hop_` + `family_post_terminal` seam |
| NSPack | 3 | packed EP (0x101b) points at zero bytes; forced starts at 0x42a000 and 0x401047 both end at pc 0x40101b with 0 writes | the oracle's flow (it reports stages=2 plus a dynamic-region dump at 0x8000) |
| Alienyze / Amber | 6 | the decrypter never runs; Amber allocates nothing (one heap page) | `recover_alienyze` port; Amber's embedded-PE is inert until the stub allocates |
| Molebox / WinUpack / BeRo | 6 | container prepass; table merge; one more import-blob shape (2 dlls short) | tiers B/C of §3 |
| Themida / Yoda-Protector | 6 | oracle 0/3 on both | deferred |

### 0.5.3e Round 3 measured so far (three commits, one +1)

S75 stands at **40 / 75** (25 PARTIAL, 10 FAILED). The three round-3 commits
and what they actually measured:

1. **The exception dispatch is now real** (`cd1761b`). TELock's ladder rides
   `0xf1` (ICEBP), the `#UD` `lea reg,reg` form and the TF single-step trap.
   Unicorn reports the first two as `UC_ERR_INSN_INVALID` and the third as
   `int 1` (`UC_HOOK_INTR`); none were delivered before. Now: an
   `insn_invalid` hook advances Eip past `0xf1` and dispatches
   `STATUS_SINGLE_STEP`; `int 1` maps to `STATUS_SINGLE_STEP` (not the
   illegal-instruction class) and clears TF after the CONTEXT snapshot; and a
   shared `seh_dispatch_cpu` maps the sentinel on demand. **The §0.5.3c
   hypothesis is wrong in one detail**: the fs:[0] handler *is* installed
   (frame at `0xffffcfb0`, handler `0x4089fa`) — the stub never skipped the
   installer. The measured divergence is later: after the first single-step
   ladder stage the stub's `les edi,[esi]` (pc `0x408a92`) loads selector
   `0xc1eb` from `[esi+4]` and faults `#GP`, where the oracle's flow instead
   re-enters the main decrypt loop at `0x40708d` (`int 3`). That is a
   register-state divergence inside the ladder, not a missing handler and not
   the dump transform. TELock stays 0/3.
2. **The candidate-ledger cap was the Molebox bug** (`e324cbf`). The SFX stub
   executes >4096 distinct addresses in its own sections before transferring
   to the embedded PE's entry, so the 4096-entry hop ledger filled on
   stub-section addresses and the true section-hop (`0x407a98`) was never
   ledgered; the pick fell back to the container's `.text` head `0x42a000`.
   Raising the cap to 65536 fixes it: Molebox AccessEnum now picks the
   original EP (sim 0.93, cov 1.0). **S75 39 → 40; Molebox 1/3 → 2/3**
   (ADExplorer still fails with sim 0.05 — the embedded PE never decodes,
   a different variant).
3. **PEtite's writability probe needs a read-only header page, but that is
   downstream of an earlier divergence** (`282f93d`).
   `QlOsWindows::seh_on_write_prot` + the `UC_HOOK_MEM_WRITE_PROT` trampoline
   now deliver a write-protection fault as `STATUS_ACCESS_VIOLATION` (with the
   reference's survive fallback); it is inert because nothing is mapped RO.
   Mapping the header page RO and seeding fs:[0] with the reference's
   synthetic SEH frame (win32.cpp SE_SEH_SEED) was measured and **left out**:
   the stub's first header store lands at pc `0x418179` addr `0x400780`, where
   the oracle stores at pc `0x418217` addr `0x400000` — the flow diverges
   before the probe, so the AV fires on the wrong store (survives after the
   repeat guard) and the decryptor walker dies on a read from `0x1`
   (`sim 0.80 -> 0.07`, exact OEP lost). PEtite stays 0/3.

4. **The exception-vector → NT-status map was wrong for #GP/#PF** (round 3
   follow-on). `seh_on_interrupt` mapped every non-int1/int3 vector to
   `STATUS_ILLEGAL_INSTRUCTION` (`0xC000001D`); the reference's
   `intr_to_ntstatus` maps `#DE→0xC0000094`, `int1→0x80000004`,
   `int3→0x80000003`, `#BR→0xC000008C`, `#UD→0xC000001D`,
   `#GP/#PF→0xC0000005`, `#AC→0x80000002`, and **ignores** every vector
   outside the table (the `int 0x20/0x29/0x2d` probes become NOPs). Fixed to
   match; S75 re-run confirms no regression (still 40/75).

5. **TELock's real blocker is a self-modifying-decryptor register divergence,
   not the exception path.** A fs:[0] write trace on telock_AkelAdmin.exe
   shows the ICEBP frame is installed (`fs:[0]=0xfffeffb0` at `0x408a05`),
   the relocation tail intentionally restores `fs:[0]=0` (`pop fs:[edx]` at
   `0x408a2f`), the single-step ladder re-installs it (`0x408a4d`) and pops it
   back to 0 (`0x408a61`) — all correct. The run then reaches the `les
   edi,[esi]` at `0x408a92` with `esi=0x408992`, `[esi+4]=0xc1eb` (invalid
   selector → #GP), while the oracle's next interrupt after the same
   single-step is `int 3` at `0x40708d` (the main decrypt loop) over ~1.79M
   insns. The bytes at `0x408a61..0x408a90` are identical in both dumps, so
   the divergence is the *runtime* (decrypt-execute-re-encrypt) code, i.e.
   bit-exact register parity through TELock's self-modifying decryptor — the
   `test esp,esp;jns` / `or esp,esp;jne` branches read the (high-address,
   sign-negative) guest stack and self-modify the handler (`setno [edx+3]`).
   TELock stays 0/3.

6. **NSPack's zero-byte EP relies on a non-zero initial EAX** (probed, not
   guessed). `nspack_AccessEnum.exe` has EP RVA `0x101b` inside nsp0's raw
   head, and the EP bytes are genuinely zero (`add [eax],al`). The oracle
   starts at `0x40101b` too, but its first fault is at pc `0x407b6f` (a real
   write to address 0), not at the EP — its initial `Eax=feedf338` (an
   import-sentinel leftover from the loader's import walk) makes the zero-byte
   `add [eax],al` write to a *valid* sentinel page instead of the null page.
   taote initialises EAX to 0, so the first instruction faults on a null
   write with no SEH handler and the run ends with 0 writes. The oracle's
   later null write IS handled by a real guest SEH frame (handler `0x407a3e`).
   Seeding EAX with a mapped scratch page was measured: it walks the zero
   head to `0x401027` where the first non-zero stub byte (`00 80 00 d0 03
   00` = `add [eax+0x3d000],al`) reads EAX as an image-relative base and
   faults on the scratch-page offset — so EAX alone is not the fix; the
   oracle's mapping of nsp0's raw head (or its register setup) must differ
   further. NSPack stays 0/3.

7. **Neolite (and PEtite's probe) share one root cause: the whole image is
   mapped RWX.** taote's PE loader maps the image `UC_PROT_ALL`, so the
   packed `.text` (`0x401000-0x40fe00`, exec=0 in the PE header) is
   executable and the PEtite header page is writable. Neolite's demand-paged
   decryption drives on an *execute-on-non-exec-page* fault (the stub installs
   a handler that decrypts `.text` pages on first fetch), and PEtite's second
   stage drives on a *write-to-read-only-header* fault — both are permission
   probes taote's RWX map silently survives, so the stub takes the wrong path:
   Neolite ends at `kernel32!ExitProcess` (`pc 0x10021240`) with `.text`
   never written and picks the false hop `0x4246bb` inside `.neolit`;
   PEtite's probe survives and it dies on a read from `0x1`. The fix is real
   section permissions + the already-built write-prot/`seh_on_fault` dispatch,
   but the PEtite header-RO alone was measured worse (the stub diverges
   before the probe, §0.5.3e entry 3), so it must land together with the
   register-state parity fixes. Neolite stays 0/3.

   *Measured follow-on (this round):* a gated `TAOTE_UNPACK_REALPERM` loader
   path (map `.text` read+write-no-exec, header page RO, `.rdata`/`.rsrc`/
   `.reloc` RO) plus `UC_MEM_FETCH_PROT` dispatch into `seh_on_fault` (access
   type 8) was built and measured on `neolite_Autologon.exe`: **no change** —
   the run still ends at `kernel32!ExitProcess` with 2110 writes and 0 faults,
   so the stub's exit is an *anti-emulation branch independent of the section
   permissions*, not the execute-on-noexec probe. The permission infra
   (`change_mapinfo` fix, write-prot dispatch, fetch-prot dispatch) is correct
   and landed, but it is necessary-not-sufficient; the real Neolite/PEtite
   blocker is the anti-emulation/register-state divergence upstream of the
   probe.

### 0.5.3f Round 3 late: S75 40 -> 50 (four measured fixes)

The budget/dispatch work found four general fixes, none of them family-specific
guesses:

8. **The 40M instruction budget truncated the slow decoders** (`faf40c3`).
   The reference has no instruction cap at all (`max_instructions_ = -1`); with
   the budget at 200M, nine families moved to 3/3 in one run: **S75 40 -> 45**.
   ASPack 2->3, BeRo 2->3, EXpressor 2->3, Eronana 1->3, JDPack 1->3, MEW 2->3,
   Molebox 2->3, Packman 2->3, UPX 2->3 (all exact EP, sim >= 0.93).
   The per-sample `--count` flag remains for experiments.
9. **A function-boundary CRT-init thunk is a decode-only OEP candidate**
   (`3681466`). The ADInsight payload's original entry is
   `ret | e8 <__security_init_cookie> e9 <rel32> | 6a 14 68 <imm32> e8`;
   MPRESS's runtime fixups rewrite both rel32 operands, so the reference's
   `e9 00000000` test does not survive the decode — the *boundary prefix* does.
   Corpus-unique (exactly one hit) so it is inert on ADExplorer/AccessEnum:
   **MPRESS 2->3, RLPack 2->3** (ep_delta 2714454 -> 0). S75 45 -> 47.
10. **The unpack-mode raw-chain continue** (`d39d36e`). A guest handler that
    answers `EXCEPTION_CONTINUE_SEARCH` with no outer `fs:[0]` frame used to end
    the run; the reference restores the saved CONTEXT and resumes at its Eip
    (winemu.cpp:4859-4920), because the handler has usually patched the trapping
    instruction. Bounded by `seh_dispatch`'s identical-fault repeat guard.
    **PECompact 0/2/1 -> 2/1/0** (AccessEnum sim 0.0039 -> 0.8411, exact EP).
    S75 47 -> 49.
11. **PECompact's family signature + first-write overlay** (`45d402b`).
    PECompact compresses in place and keeps the original section names; the only
    signature is the stub entry `b8 <imm32> 50 64 ff 35` (measured over the whole
    packed corpus: **118/118 PECompact, zero false positives**; PEtite shares the
    `b8 <imm32> 50` head but continues `6a 00 68`). With the family labelled the
    full first-write overlay applies (PECompact re-encrypts each page after
    executing it): **PECompact 2/1/0 -> 3/3** (sim 0.906/0.939/0.921).
    S75 49 -> 50.

Also landed this round: the exception-vector map (`#GP/#PF` ->
`STATUS_ACCESS_VIOLATION`, non-table `int` probes ignored, `a8f7e4d`), the
`change_mapinfo` sub-range fix (`ed4c2a7`, the prerequisite for real section
permissions), and the execute-on-noexec dispatch **gated off**
(`c0c841d`: it SIGSEGV'd `aspack_AccessEnum` at the 960th dispatch — the host
safety rule outranks the feature; opt in with `TAOTE_SEH_FETCHPROT`).

Measured status after these: **S75 = 50/75 UNPACKED_VERIFIED**, 16 PARTIAL,
9 FAILED, 0 wall-timeouts, 593 tests green.

Remaining (measured blockers, all re-probed this round):

| family | S75 | measured blocker |
|---|---|---|
| TELock | 0/3 | decodes nothing: bit-exact register parity through the self-modifying ladder (§0.5.3e 5); the first-write overlay changes nothing |
| PEtite | 0/3 | the stub's own integrity check fires: `MessageBoxA("ERROR!", "Corrupt Data!")` then `ExitProcess`, so ~12% of the decoded bytes are wrong (scattered single bytes, not shifts) and only a third of `.text` is ever written |
| Neolite | 0/3 | the stub resolves its IAT (CreateFileMapping/MapViewOfFile/GlobalAlloc) and then calls `ExitProcess` with `.text` never written — an anti-emulation branch, not the section-permission probe (§0.5.3e 7) |
| NSPack | 0/3 | the packed EP points into nsp0's zero head; the oracle walks those zeros (its loader leaves EAX = an import sentinel) into nsp1's stub, taote faults on the first non-zero byte (EAX is not an image-relative base) |
| Alienyze | 0/3 | the decrypter never runs; not a whole-image single-byte XOR (all 256 keys measured: best is the identity, 0.145) |
| Amber | 0/3 | the stub allocates nothing and exits at the first API; the embedded PE is never built |
| WinUpack | 2/3 | ADExplorer's section names are deliberately mangled (`PS\xff\xd5...`), so detection fails and the stub's decoder never writes |

### 0.5.4 What this changes in the plan

1. **The GPA sentinel lane is Phase 1, not Phase 1b.** UPX's import restorer calls
   `ExitProcess` on the first NULL `GetProcAddress`; without the sentinel the run
   dies before the payload is ever transferred (measured: `stages=0`, OEP guessed).
2. **The sentinel must be *callable and attributed*.** A bare fake address faults
   the moment the stub calls it (ASPack's `VirtualAlloc`: `UC_ERR_FETCH_UNMAPPED`),
   so it is minted from the loader's stub arena and registered; and attribution
   needs the *decoy dll* (a LoadLibrary of a dll taote lacks is materialized as an
   export-less image) or the last-LoadLibrary name, else verify.py's dll coverage
   collapses (FSG 1/15 → 14/15 once fixed).
3. **The dump is emitted once, at pick time, from terminal memory.** Emitting per
   candidate burned the 16-stage cap on junk hops; the reference does the same
   (ledger during the run, `emit_final_dump` at pick).
4. **The incumbent prior matters more than the score.** A pure prologue-shape
   score demoted 11 verified samples; the first accepted hop is the true OEP for
   every single-hop compressor. The pick only replaces it when the incumbent is in
   the stub's own section or is a data blob.
5. **Every non-zero claim in the reference's `meta.json` is worth checking**: its
   own MEW/Molebox metas are invalid JSON (§0.0), so taote's must be valid
   (nlohmann, asserted by `UnpackCompat.UnpackMetaJsonValid`).

---

### 0.6 Aggregate measurement, 8 samples per family (S200) — the first real comparison

S75 (3 per family) is a fine regression gate but a poor estimate: it cannot show
whether a family "works" or just happened to work three times. The same harness
with `--cap 8` gives 200 samples, run for both tools on the same manifest
(`/tmp/m200`, `/tmp/m200o`), 4-way pinned, 0 wall-timeouts on 196/171 completed
rows (the rest were disk-quota casualties and were re-run):

| | taote | oracle |
|---|---|---|
| UNPACKED_VERIFIED | **108 / 200** | **154 / 200** |
| PARTIAL | 56 | 8 |
| FAILED | 35 | 38 |

Per family (taote VER / oracle VER, of 8):

```
ASPack        7 / 8     Alienyze    0 / 7     Amber      0 / 7     BeRo       7 / 8
EXpressor     6 / 7     EnigmaVB    8 / 8     Eronana    7 / 8     Exe32pack  4 / 8
FSG           7 / 8     JDPack      6 / 7     MEW        7 / 8     MPRESS     6 / 8
Molebox       8 / 8     NSPack      0 / 8     Neolite    0 / 8     PECompact  4 / 7
PEtite        1 / 6     Packman     7 / 8     RLPack     5 / 8     TELock     0 / 7
Themida       0 / 0     UPX         8 / 2     WinUpack   3 / 0     Yoda-Cryp   7 / 0
Yoda-Prot     0 / 0
```

Two results worth acting on:

1. **taote already beats the oracle on four families**: UPX 8/2, WinUpack 3/0,
   Yoda-Crypter 7/0 and (on S75) the Eronana/EnigmaVB/Molebox rows. The oracle's
   UPX/Yoda/WinUpack failures are its own post-OEP grace stop cutting the import
   resolution (it scores 2/8 UPX where S75 showed 3/3), so those are *not* a
   target.
2. **The whole aggregate gap is six families**: Neolite 8, NSPack 8, Alienyze 7,
   Amber 7, TELock 7, PEtite 5 = **42 of the 46 samples** between 108 and 154.
   Everything else together is 4 samples. That is the worklist, in that order:
   the anti-emulation / decryptor-parity class (Neolite, NSPack, TELock, PEtite)
   and the two payload-builder families (Amber, Alienyze).

The measured conclusion for the plan: **do not port more seams for the families
already at parity** (they cost samples: PECompact 4/7 and RLPack 5/8 are the next
two on the list, then Exe32pack 4/8). The six above are where the files are.

### 0.7 Module layout after the structural port (matches the reference)

`unpack.cpp` had grown to ~2650 lines with every family's policy inline. It now
mirrors `../pegasus/src`:

```
qiling/unpack/unpack.{hpp,cpp}          the engine: classification, write-claim,
                                        section-hop, ledger, pick, dump, rebuild
qiling/unpack/packer_detector.{hpp,cpp} the detector (section sigs, Molebox
                                        digit-names, the PECompact entry signature)
qiling/unpack/iat/iat_search.{hpp,cpp}  Scylla's ApiReader + IATSearch: SymbolMap,
                                        IatScanner (pointer scan, coherent runs,
                                        scattered-table rule), descriptor walk
qiling/unpack/iat/import_rebuilder.{hpp,cpp}
                                        Scylla's ImportRebuilder: group_imports +
                                        build_import_section (descriptors, INT/IAT,
                                        hint/name strings)
qiling/unpack/packers/packer.hpp        the seam interface (PackerContext,
                                        ShadowPolicy, Packer) + the shared
                                        decode-only ladder
qiling/unpack/packers/generic_packer.cpp    GenericPacker + make_packer (the
                                            detector-name -> subclass table)
qiling/unpack/packers/decode_only_packer.cpp  NSPack/RLPack/MPRESS + the ladder
qiling/unpack/packers/mew_packer.cpp    the header-table OEP parse + shadow policy
qiling/unpack/packers/pecompact_packer.cpp  the re-encrypting shadow policy
qiling/unpack/packers/embedded_pe.cpp   Amber/Alienyze payload adoption
qiling/unpack/packers/family_packers.cpp    the still-generic families (one class
                                            each, a place for the next seam)
```

`unpack.cpp` is 2084 lines (from 2653) and the family policy is now one
`packer_->…` call per seam. Behaviour-preserving: S75 stays 50/75 and the suite
stays at 0 failed.

### 0.8 Head-to-head: taote vs the reference on the same 2678 samples

This supersedes every earlier aggregate in this plan. The 52.9% / ~57% figures
quoted before were different **censuses** (pegasus's own counters, and a
200-sample slice graded on the DLL-coverage rubric); the numbers below are one
corpus, one grader, both tools.

**Reproduction (exact):**

```
# corpus: every packed/ file that has a not-packed/ original (2678 of 3001)
build_manifest.py --dataset ~/source/jim/dataset-packed-pe --cap 99999 \
    --out /home/jim/runs/full/manifest.json

# taote  (harness tools/unpack_eval/run_all.sh, 4-way pinned)
run_all.sh --manifest /home/jim/runs/taote4/manifest.json \
    --cli /path/to/taote_unpack --pin 4  > /home/jim/runs/taote4/run.log
# reference (same harness, same flags, same pinning)
run_all.sh --manifest /home/jim/runs/oracle/manifest.json \
    --cli ~/source/jim/pegasus/build/cli/pegasus-cli \
    --repo ~/source/jim/pegasus --pin 4  > /home/jim/runs/oracle/run.log

# grade both with the SAME tool
tools/unpack_report.py --manifest /home/jim/runs/taote4/manifest.json \
    --results /home/jim/runs/taote4/results.json --out /home/jim/runs/taote4/TAOTE_REPORT.md
tools/unpack_report.py --manifest /home/jim/runs/oracle/manifest.json \
    --results /home/jim/runs/oracle/results.json --out /home/jim/runs/oracle/ORACLE_REPORT.md
```

Per-run flags: `--unpack --unpack-output <dir> --unpack-timeout 85`, wall cap 120s.
Grader: a valid PE (parses, sane headers, entry mapped by a section) + OEP exact vs
the original's EP RVA + imports >= 95% of the original's `(dll, function)` set.

| criterion | taote | reference |
|---|---|---|
| valid PE | 2568 / 2678 (**95.9%**) | 2546 / 2678 (**95.1%**) |
| OEP exact (all 2678; managed excluded from the grader denominator) | 1490 (**55.6%**) | 2197 (**82.0%**) |
| imports correct (all 2678) | 1682 (**62.8%**) | 2069 (**77.3%**) |
| **all three** | **1416 (**52.9%**)** | **1996 (**74.5%**)** |

**Per family (all three; delta = taote - reference):**

| family | n | taote | reference | delta |
|---|---|---|---|---|
| ASPack | 94 | 91 | 93 | -2 |
| Alienyze | 126 | 0 | 116 | -116 |
| Amber | 152 | 0 | 111 | -111 |
| BeRoEXEPacker | 107 | 99 | 103 | -4 |
| EXpressor | 95 | 92 | 91 | +1 |
| Enigma Virtual Box | 122 | 122 | 122 | +0 |
| Eronana Packer | 151 | 136 | 84 | +52 |
| Exe32pack | 124 | 0 | 0 | +0 |
| FSG | 97 | 75 | 90 | -15 |
| JDPack | 100 | 97 | 98 | -1 |
| MEW | 106 | 97 | 105 | -8 |
| MPRESS | 106 | 64 | 103 | -39 |
| Molebox | 93 | 87 | 91 | -4 |
| NSPack | 97 | 49 | 97 | -48 |
| Neolite | 93 | 1 | 92 | -91 |
| PECompact | 97 | 41 | 94 | -53 |
| PEtite | 73 | 23 | 56 | -33 |
| Packman | 105 | 104 | 102 | +2 |
| RLPack | 104 | 0 | 7 | -7 |
| TELock | 116 | 0 | 59 | -59 |
| Themida | 122 | 0 | 0 | +0 |
| UPX | 108 | 107 | 107 | +0 |
| WinUpack | 97 | 39 | 83 | -44 |
| Yoda-Crypter | 92 | 92 | 92 | +0 |
| Yoda-Protector | 101 | 0 | 0 | +0 |

**Reading it.** taote is at **52.9%**, the reference at **74.5%**: the real gap is
**580 samples**, not the 46 the old census implied. Six families are already at or
above parity (Eronana +52, Packman +2, EXpressor +1, and Enigma Virtual Box / UPX /
Yoda-Crypter level at 0), and three are *both* at zero (Themida, Yoda-Protector,
Exe32pack) - those are not taote regressions, they are limits of the corpus or of
both tools.

The gap by size (taote -> reference): Alienyze 0->116, Amber 0->111, Neolite 1->92,
TELock 0->59, PECompact 41->94, NSPack 49->97, WinUpack 39->83, MPRESS 64->103,
PEtite 23->56, FSG 75->90, MEW 97->105, RLPack 0->7, Molebox 87->91, BeRo 99->103,
ASPack 91->93. Every one of those is decoder/emulation parity, not picker work:
the reference's 88.4% OEP rate shows what the same pick machinery achieves once
the payload is actually decoded.

Run-to-run noise: three taote passes of the same tree gave 1408 / 1414 / 1416
all-three (6 samples flip under CPU contention - `aspack_HWMonitorPro_x32`,
`bero_md5summer`, `molebox_Hasher`, `molebox_puttytel_32`, `packman_HDDScan`,
`winupack_disk2vhd`), so treat the taote column as +/-6 samples and any change
below that as unmeasured.

Artifacts: `/home/jim/runs/taote4/{manifest.json,results.json,TAOTE_REPORT.md}` and
`/home/jim/runs/oracle/{manifest.json,results.json,ORACLE_REPORT.md}`.

### 0.9 Porting the reference's OEP machinery: the full corpus goes 40.2% -> 51.0%

The full-corpus report (§0.8) said the biggest defect was the OEP *pick*, not the
decode, so the next step was to port the reference's pick machinery rather than
write new heuristics. Three pieces, all from `src/unpacker/unpacker.cpp`:

1. **The claim ledger** (`on_section_exec`, :5710-5810). The reference detects a
   hop only while a *claim* (`written_ranges_`) is live and consumes the claim
   when the hop is accepted; taote walked `ever_written_` (never erased) and
   ledgered every distinct executed address in a decoded section. Measured: the
   reference ledgers **2 candidates** on `aspack_Cacheset` where taote ledgered
   **2695**. With the port the ledgers are byte-identical (`0x42602f@1`,
   `0x4024a2@35973`). MPRESS keeps its range (the lazy trampoline hands off
   twice, :5770-5800).
2. **The pick order / incumbent** (`pick_and_emit_oep`, :8156-8360). The
   incumbent is the last candidate that passes the V1 shape vote (a real entry
   starts like a function), else the first non-latch candidate (the reference's
   `kJunkLatchMaxInstrs=32`, here the write ordinal), and the static ladder only
   answers when nothing in the ledger survives. taote's ladder used to override a
   correct accepted hop - `aspack_Cacheset` picked the look-alike prologue
   0x406c29 over the true 0x4024a2.
3. **F41c/F47 precedence** (`decode_only_ladder`, :7861-7910): for NSPack/RLPack
   an accepted hop out of the stub's own section outranks the static ladder;
   MPRESS keeps the ladder first because its ledger is stub-internal.

Measured over the whole corpus (2678 samples, same harness and grader):

| | before | after |
|---|---|---|
| OEP exact | 1153 (45.0%) | **1442 (57.7%)** |
| imports correct | 1556 (60.6%) | 1557 (60.6%) |
| valid PE | 2568 | 2568 |
| **all three** | 1076 (40.2%) | **1365 (51.0%)** |
| harness rubric | 1126 (42.0%) | **1414 (52.8%)** |

**289 samples gained, 0 lost**: Eronana 71->136, Packman 63->104, Yoda-Crypter
52->92, ASPack 56->91, EXpressor 56->91, JDPack 71->97, Molebox 67->88, BeRo
90->98, UPX 99->107, PEtite 16->23, WinUpack 36->38, FSG 74->75.

What is left, in the order the reference's own code says to take it:

* **NSPack (97 samples, 0%)**: the stub decrypts into a *VirtualAlloc'd* region
  (the reference's NSPack profile shows `VirtualAlloc(0, 0x1000, 0x1000, 0x40)`
  first and 15.9M instructions to the hand-off), so the payload is not in the
  image at all and the ladder is scanning stub bytes. Needs the dyn-region path
  (`on_dyn_code` + `meta_.stages > 0` gate, :6096 and :7831).
* **RLPack imports (104 samples, recall 1/314)**: the OEP is now often right but
  the rebuilt table is the stub's own (16 descriptors, wldap32/mspdb80/hhctrl)
  instead of the payload's - the reference's `salvage_iat_scan` (:8670) chooses
  the table from the code's references, not from coherence alone.
* **Amber (152), Alienyze (126), TELock (116), Neolite (93)**: per-family modules
  the reference has and taote does not (`packers/amber_unpacker.cpp`,
  `alienyze.cpp`, `telock_unpacker.cpp`, `neolite_unpacker.cpp`); taote's
  family files are still name-only placeholders.
* **Exe32pack (124)**: the artifact is the raw dump with a degenerate section
  table, so its entry is unmapped - 107 samples fail criterion 1 only.

### 0.10 Round 4 so far: the loader's FileAlignment rule, and what it unlocked

**The finding that mattered was not in the unpacker.** NSPack sat at 0/97 with
`stages=0`: the run executed the header EP and stopped, with zero writes, zero
hops and no ladder hits. The stub's real entry is not where the header says -
`nspack_AccessEnum` has `PointerToRawData = 0x1a9` with `FileAlignment = 0x200`,
and Windows maps a section at FileAlignment granularity, i.e. from the page
boundary BELOW the raw pointer. So RVA 0x101b reads **file 0x1b** (a
`e9 rel32` relay into the nsp1 stub), while taote read at the declared pointer
(zeros). The loader now maps misaligned sections from the aligned offset -
inert for well-formed images (all 593 tests unchanged), decisive here:

| | before | after |
|---|---|---|
| NSPack all-three | 0 | **49** (OEP 53, imports 83) |
| WinUpack imports | 39 | **78** |
| corpus all-three | 1365 (51.0%) | **1414 (52.8%)** |
| corpus OEP exact | 57.7% | **59.6%** |
| corpus imports | 60.6% | **65.4%** |

49 gains / 0 losses. Same mechanism explains winupack_ADExplorer's mangled
layout (`sim 0.001` before).

Also landed: Amber detection (the reference's randomized-9th-section-name rule -
all 152 samples now carry the right label instead of "unknown"), the
embedded-payload recovery moved to the Packer base class (packer-agnostic, as in
the reference), a startup sweep of stale temp rootfs trees (a host abort skipped
the RAII guard; 11k dirs / 5.3 GB had accumulated), and an unparsable input now
reports a per-sample error instead of `std::terminate` (two FSG samples).

**What this says about the remaining families.** Amber's payload is built inside
the low `0x6000` map as raw code plus hand-built import descriptors - the harvest
already sees those "orphan descriptors at 0x6000" - but *not* as an MZ+PE file
image, so the embedded-file recovery finds nothing (verified with
`TAOTE_EMBEDDBG`: every map head is 00/90/00/00). Amber, Alienyze and Neolite
therefore need the reference's **dyn-region candidate** path
(`on_dyn_code` :6096 -> `SCF_DYN_REGION` ledger entry -> pick), not more dump
scanning. That is the next structural port, and it is worth ~370 samples
(Amber 152 + Alienyze 126 + Neolite 93).

### 0.11 Round 4, second half: what did NOT land, and why it matters for the next round

Three attempts this round, one landed:

* **WinUpack parked-stack OEP** (the reference's `wu_oep_cand8_`,
  `winupack_unpacker.cpp:651-690`): the dword at `[esp+8]` when the engine's
  import loop executes its `call ecx`. taote has no hook at that instruction, so
  the frame was harvested from the section-exec hook instead (4096 snapshots of
  `esp` inside the stub section) and yielded **one** candidate in 4096 harvests;
  the shape-validated pick it produced cost one sample (`winupack_disk2vhd`
  0x2bf34 -> 0x179d48). Removed. To port it, the loop anchor must come first -
  the reference finds the loop by scanning back from a GPA caller for
  `5e 5d 59 46 ad 85 c0 74` and only then computes `callmod = loop + m2 + 3`.
* **Amber**: the payload is not a file image in a heap buffer (what
  `try_embedded_pe` looks for) but raw code + hand-built import descriptors
  inside the low `0x6000` map - `TAOTE_EMBEDDBG` shows every map head as
  00/90/00/00, so the scan finds nothing. taote's Amber run also stops at
  `pc = 0x10051030`, i.e. inside the *msvcrt stub DLL*, right after the
  `msvcrt!__p__acmdln` hook fires: the guest's CRT init calls a return path the
  stub cannot complete. Amber needs both the dyn-region candidate path
  (`on_dyn_code`) and that stub-return fix before its 152 samples move.
* **WinUpack detection** (mangled section names) landed: first section with a
  non-printable name byte, `raw < 0x1000`, `vsize >= 0x10000` - all 97 samples
  label correctly now, measured neutral on the family score.

Status: corpus **1414/2678** all-three (52.8%), OEP exact 59.6%, imports 65.4%,
valid PE 95.9%, 0 wall-timeouts, 593/593 tests.

### 0.12 Round 5, first probe: the Amber CRT wall (and why the fix was reverted)

Amber's run stopped after **10 API calls**, the last being `msvcrt!__p__acmdln`.
Root cause found: the synthesized stub msvcrt has no `_acmdln` slot, so taote's
`__p__acmdln` **throws** (`msvcrt.cpp:247-262`), which ends the run. Returning a
heap-allocated NULL `char**` instead gets the stub past CRT init - measured on
`amber_ADInsight`: the run then calls VirtualAlloc, `memcpy`s the payload into
the `0x5000000` heap map and executes it there, ending at `pc=0x5426b80` (a
computed jump into unmapped space, i.e. the next blocker is the payload's own
entry computation, not the CRT).

Full corpus with the fix: **1411** all-three vs 1414 without - it costs three
samples (`bero_md5summer` 0x9ec68->0x933ad, `molebox_Hasher`
0x82628->0xa85a4, `winupack_disk2vhd` 0x2bf34->0x179d48, all OEP/dump trajectory
flips after the run continues past the API). So the fix alone is a net loss and
stays reverted until the Amber chain is finished; re-measured explicitly: with
the old code those three return to their correct OEPs.

Two other measurements worth keeping:

* Amber is gradeable and pegasus really does nail it - `amber_ADInsight` and
  `amber_ShareEnum` oracle artifacts have sim 1.000, ep == the original's, and
  the full import list (328/328, 237/237). So the family is not a ground-truth
  mismatch; taote is simply not reaching the in-place decode.
* `amber_AddInProcess32` is an outlier in the other direction: the oracle's own
  artifact there is the packer's image (ep 0xe000, sim 0.06) - that sample's
  payload is not the paired original, so it should not drive the design.

### 0.13 Round 7: OEP first - 612 of the 637 remaining misses are OEP-only

Classifying every sample the reference gets and taote does not, by the FIRST
failing criterion, reframed the worklist:

| criterion that blocks | samples |
|---|---|
| OEP only (valid PE + imports already correct) | 612 |
| imports only | 24 |
| valid PE | 1 |

So the picker was not exhausted after all: 612 samples have a decoded payload
with the right imports and only the entry wrong. (The per-family aggregate in
§0.8 hid this, because the decode-blocked families dominate the totals.)

**What was wrong (two rules, both in the decode-only path).**

1. The accepted-hop gate required the hop to leave the packed EP's own section.
   That is exactly wrong for NSPack: its payload decodes INTO that section, so
   the true OEP shares it. `nspack_Cacheset` already held the true `0x4024a2`
   in the claim ledger at write ordinal 156337; the section filter discarded it
   and Pass B's three MSVC frames then overrode it with the LAST one
   (`0x406c29`). Acceptance now uses the same strength test as the non-decode
   path (ordinal >= 32 and an entry-shaped target).
2. Pass B's "unique `55 8b ec 6a ff 68 <imm>` frame" is false for programs that
   share the shape across several functions (Cacheset 3, AccessEnum 2, DarkNamer
   4). The run's own last hop lands INSIDE the entry, measured at exactly +0x16
   on both Cacheset and AccessEnum, so the frame just below the hop wins
   (`hop_hint` in the packer context); with no such frame the scan keeps the
   last hit, which is what AccessEnum and DarkNamer need. Taking the first hit
   instead cost both (0x7a98 -> 0x3a53 and 0xa71e -> 0x4fa0), so the hint is
   what makes it safe.

**Measured** (full corpus, same pin-4 harness, `tools/unpack_report.py`):

| | before | after |
|---|---|---|
| valid PE | 95.9% | 95.9% |
| OEP exact | 59.6% | **61.1%** |
| imports | 65.5% | 65.5% |
| all three | 1416 (52.9%) | **1455 (54.3%)** |

39 gains, 0 losses (NSPack 49 -> 81, PECompact 41 -> 48). Against the reference
head-to-head of §0.8 that is 1455 vs 1996; the gap is now 541 samples, of which
573 are still OEP-only.

**The import side (next, per the same data).** The 24 import-only misses split
into two classes, and neither is a coherence problem:

* 9 near-misses (MEW 8, MPRESS 1) at recall 0.90-0.95 whose *entire* missing set
  is **ordinal imports** (`oleaut32#12`, `odbc32#24`, `cabinet#20`,
  `wsock32#2`, ...). The artifact carries no `oleaut32` descriptor at all:
  ordinal-only blocks have no name strings, so the string/blob lanes cannot see
  them, and the runtime lane (`GetProcAddress(hmod, ordinal)`) records nothing
  because the payload resolves those slots itself. The reference reaches
  105/106 here, so it keeps an ordinal-aware stub map - that is the port.
* 15 catastrophic misses (recall 0.004-0.12: Procmon/procexp/7zFM/ADInsight/Ps*)
  where the artifact's table has the right *slot count* but shuffled DLL
  attribution (`hal`/`hhctrl.ocx`/`fltlib` blocks, shell32 names under
  advapi32). The cause is visible in the log: the string-group miner fires on
  the program's own 800-entry API-name table (`import-string groups: 66 groups,
  14 dlls, 801 names (first hhctrl.ocx!permission_denied)`), and those blocks
  carry no slot evidence. Gating that lane on evidence, and preferring the
  runtime table the way the reference does, is the fix.

### 0.13b passA: the CRT-init thunk at a function boundary

Second picker fix of round 7, measured separately (full corpus, pin 4):

| | r7 (accepted hop + frame hint) | r7d (+ passA) |
|---|---|---|
| OEP exact | 61.1% | **62.3%** |
| all three | 1455 (54.3%) | **1471 (54.9%)** |

Round total: **1416 -> 1471 (+55), 0 losses** (NSPack 49 -> 81, PECompact
41 -> 60, MPRESS 64 -> 66, ASPack/BeRo +1 each).

The rule: a `<ret|int3|nop|retn> e8 <call __security_init_cookie> e9 <body>` at a
function boundary, accepted only when it is the image's ONLY such hit. Evidence
first: of the 142 corpus programs whose entry is that thunk, 140 have the entry
among these hits and 111 are unique - so the gate is safe and the class is big
(MPRESS 14, WinUpack 23, PECompact 22 of the round's OEP-only misses).

Two details are load-bearing:
* the `e8` operand is often unrelocated in the dump (winupack_Contig holds
  0xd62cbd79) and the `e9` may jump BACKWARDS, so only the `e9` target must be
  in-image; that target must be a real body prologue (`6a ?? 68 <imm> e8`,
  `55 8b ec`, or `e8 .. e9`). mpress_Dbgview carries 4 copies of the thunk shape
  and exactly one lands on the Borland frame - without the prologue test the
  uniqueness gate never fires.
* hits must be de-duplicated by VA: the dump's sections OVERLAP, which is why
  Pass B counted 2 frames on pecompact_AccessEnum where the image holds 1.

Next lever in this same class: when more than one thunk survives the prologue
test, score the body (Borland/`55 8b ec` = 3, `e8 .. e9` = 2) and take a unique
maximum - that is what mpress_Dbgview needs (2 hits, the true one is the Borland
body). Not measured yet.

### REPRO for §0.13

```
run_all.sh --manifest /home/jim/runs/r7full/manifest.json \
    --cli /home/jim/runs/bin/taote_unpack_r7c --pin 4 > /home/jim/runs/r7full/run.log
tools/unpack_report.py --manifest /home/jim/runs/r7full/manifest.json \
    --results /home/jim/runs/r7full/results.json --out UNPACK_REPORT.md
```
Baseline for the diff: /home/jim/runs/taote4/results.json (same harness, pin 4).

### 0.14 Round 8: what the import gap actually is, and +16 on WinUpack

Four experiments, all measured on the full corpus with the same pin-4 harness.

**1. The 9 "ordinal near-misses" are not an attribution problem.** MEW's 8
samples (recall 0.90-0.95) were the round's first priority, on the theory that
taote drops ordinal-only DLL blocks (no `oleaut32` descriptor at all). Measured
diagnosis instead:

* the *packed* file's own import table is just `kernel32!LoadLibraryA` +
  `kernel32!GetProcAddress` (2 pairs) - there is nothing to inherit, and LIEF
  cannot parse the packed file at all (`Address of new exe header is
  corrupted`), so the loader-harvest lane silently contributes nothing;
* the run never loads `oleaut32`/`odbc32`/`comctl32` (mapped modules: ntdll,
  kernelbase, kernel32, mscoree, ucrtbase) and ends **inside MEW's LZMA
  decompressor** (final pc in the 0x6000000-0x7400000 map, 5.34M writes), i.e.
  the stub's import-resolution loop never runs;
* the reference reaches the same OEP (0x5b5d42) with `stages=3`,
  `reason=mew_terminal_full_fill` in 45s and emits all 861 pairs including
  `oleaut32#6..#185` and `odbc32#136`, i.e. it finishes the decode.

So MEW is a **decode-parity** item (MEW LZMA completion / finalize), not an
ordinal-naming item; its GPA lane already records `ordinal_<n>`, and the
emitter already writes `0x80000000|ord`.

**2. The 15 catastrophic import misses are a GPA-attribution problem, not a
miner problem.** The artifact's *names* are all present; the DLL is shifted by
whole blocks (`kernel32` holds 139 of the original's USER32 names, `fltlib`
holds 107 of kernel32's, plus invented stems `hal`/`fltmgr.sys`/`hhctrl.ocx`
that the program merely mentions in strings). The shift starts at the GPA hook:
the run binds a name to the handle's module (`last_ll_name_`/`handle_names_`),
which the code itself calls a decoy ("the handle is often a decoy"). The
reference never trusts name-time attribution - it builds `stub_map_` from the
emulated modules' export tables and attributes by SLOT ADDRESS at salvage time.
That port (address-keyed attribution + the F52 guest-EAT ordinal lane) is the
import work that remains.

Two miner experiments were measured and are neutral, so neither is in the tree:
clearing the stale DLL marker on a block flush (397 samples: 0 gains, 0 losses)
and the passA body-score tie-break (`6a ?? 68 <imm> e8` / `55 8b ec` = 3,
`e8 .. e9` = 2, unique maximum; 373 samples: 0 gains, 0 losses - several
programs genuinely carry two such thunk copies).

**3. An unshaped lead hop is not an entry (WinUpack).** Its stub hops into the
buffer it is still decompressing, so the run's strongest hop can land on zeros
(winupack_Cacheset 0x42e80b) and the pick ends up outside the payload that was
already decoded. `shape_at(lead) >= 1` fixes 18 samples. Corpus-wide the gate
costs 37 (ASPack/BeRo/EXpressor/Eronana/JDPack/Packman/UPX/Yoda-Crypter/PEtite,
whose entries are plain code: 0x12d6c, 0x829a, 0x1504 all score 0), so it is
scoped to WinUpack; every other family's path is unchanged.

| | round 7 close | round 8 close |
|---|---|---|
| OEP exact | 62.3% | **63.1%** |
| imports | 65.5% | 65.5% |
| all three | 1471 (54.9%) | **1487 (55.5%)** |

Gap to the reference (§0.8): 1487 vs 1996 = 509 samples. Open refinement, with
the measurement that defines it: the narrow "lead is all-zero or unmapped" test
keeps winupack_calc/cmd but also keeps the zeros, so the two objectives need a
better discriminator than either variant has today.

### 0.15 Round 9: both import causes are emulation-depth, and the corpus has a contention-sensitive class

Round 8 named two import causes: GPA attribution (15 catastrophic) and MEW decode
parity (8 near-misses). Round 9 measured both to their root, and the root is the
same for both: **taote does not get far enough, and under the harness's 4-way
pinning it runs out of wall time before it would.**

**Evidence (winupack_Procmon, the catastrophic class).**

* idle, `--unpack-timeout 300`: the run COMPLETES in 40-45s with
  `imports=715` and the same (wrong) attribution - so it is not a budget cap on
  the guest, it finishes on its own;
* under the harness (`--pin 4`, timeout 85): the `.rc` records `dur=86`, i.e. the
  budget cut it;
* the reference on the same sample: `dur=46` under the same contention, so it
  finishes;
* the mechanism is visible in the dumps: the reference's `winupack_Procmon`
  dump contains `USER32.dll` at 0x1d2a04 (the payload's own loader resolving its
  import table); taote's dump does not contain it at all.

So the payload's bootstrap (walk LoadLibrary per DLL, then GetProcAddress per
name) never runs under taote, which is also why only ntdll/kernelbase/kernel32/
mscoree/ucrtbase are ever mapped and why a GPA call for a user32 name has no
exporting module to be attributed to.

**The stub_map port is blocked, measured.** The reference attributes slots by
walking each loaded module's guest export directory (F52). Ported and measured:
`ql.loader().save()` holds the five DLL stubs at 0x10000000+, they start with MZ,
but they carry no usable export directory, so the walk registers 0 modules and
`symbols=2` - the payload IAT's 791 dll-arena pointers stay unattributable. The
port is reverted; it needs the loader to synthesize real export directories for
its stub DLLs first, which is the same "load the payload's DLLs properly" work
as above.

**What was kept: throughput headroom.** Two hot-path changes (gated shadow
bookkeeping, cached written-range test) make the heaviest samples 5-8% faster
(mew_Bginfo 42.7 -> 38.6s, winupack_Procmon 43.3 -> 40.6s) with the corpus
unchanged at 1487 (0/0). That is not enough to convert the class - the idle run
needs ~40s and the contended run needs ~86s, so roughly a 2x speedup (or a
larger effective budget) is what "finish the payload bootstrap" actually costs.

**The contention-sensitive class is 69 samples.** Under 4-way pinning 69 of the
2678 runs take >= 60s: ASPack 4, BeRo 10, MEW 10, MPRESS 9, RLPack 9, NSPack 7,
PECompact 5, WinUpack 5, Eronana 3, EXpressor 3, Molebox 3, Packman 3, UPX 1.
That is the same population that produces the +/-6 sample noise band in §0.8 and
the source of every "wall-timeout" in the corpus logs - a measurement caveat and
a throughput target, not a per-family code defect.

| | round 8 close | round 9 close |
|---|---|---|
| OEP exact | 63.1% | 63.1% |
| imports | 65.5% | 65.5% |
| all three | 1487 (55.5%) | 1487 (55.5%) |

Gap to the reference: 509 samples, unchanged.

### 0.16 Round 10: the fairness measurement, and the instruction cap it found

**The fairness run (both tools, same 86 samples, same pinning, 300s budget,
420s wall cap, `--unpack-timeout 300`).** The set is the union of the 27
import-gap samples and the 71 samples that took >= 60s under the corpus harness
(86 distinct). Runner: `/home/jim/runs/fair/run_big.py` (same policy as
`run_all.sh`, larger caps), manifests `fair/taote.json` and `fair/oracle.json`.

| 86-sample fair set, 300s | taote | reference |
|---|---|---|
| valid PE | 86 | 86 |
| OEP exact | 63 (73.3%) | 83 (96.5%) |
| imports | 28 (32.6%) | 75 (87.2%) |
| **all three** | **23 (26.7%)** | **74 (86.0%)** |

Only 11 samples are beyond BOTH tools (RLPack 9, Eronana 1, WinUpack 1); 52 are
reference-only, 1 is taote-only. So this class is not a definitional problem.

**What the measurement actually found.** taote's runs were ending at exactly
200000000 instructions - the CLI default `--count`, which the harness never
overrides (it passes only `--unpack-timeout`). With `--count 600000000` the same
`winupack_Procmon` run finishes in 40-46s (well inside the budget) and its import
recall goes **0.005 -> 1.000**: the payload's own loader (LoadLibrary per DLL,
GetProcAddress per name) had simply been truncated mid-resolution. That also
explains the round-9 finding that the reference's dump carries `USER32.dll` and
taote's did not.

**The change and its two measurements.** Default cap 200M -> 2e9 (the time budget
stays the real limiter for spinning stubs):

| | fair set (300s) | full corpus (85s harness) |
|---|---|---|
| all three | 23 -> **60** (+37, 0 losses) | 1487 -> **1499** (+12, 0 losses) |
| OEP | 63 -> 79 | 63.1% -> 63.5% |
| imports | 28 -> 63 | 65.5% -> 66.0% |

The corpus gains less than the fair set because the same samples need 40-90s
when run alone and roughly twice that under 4-way pinning, so the 85s budget cuts
most of them anyway. That gap between the two numbers (60/86 at 300s vs 35/86 at
85s) is the exact size of the throughput work still outstanding: **~2x on the
emulation loop is worth ~25 corpus samples of this class alone.**

Gap to the reference: 1499 vs 1996 = 497 samples.

### 0.16b Two micro-optimizations that did NOT help (do not repeat)

Both measured at a fixed 200M instruction count on mew_Bginfo, alternating the
two binaries to cancel load drift:

* **exec hook early return** - every test after the written-range check ends in
  `return 0` when the address is not in a claim, so the packed-EP proximity probe
  and `inside_inplace()` were computed for nothing on every stub instruction.
  Provably equivalent, and measured 37.7-39.3s vs 38.3-39.1s: **neutral**,
  because the exec hook only fires inside *watched* sections and MEW's
  decompressor runs in an unwatched map.
* **write-ordinal map cache** - caching the `last_write_seq_` node for the last
  section (5.34M stores into one section) measured 40.4-41.5s vs 39.5-40.0s:
  **neutral to 3% worse**.

So the remaining ~2x is not in the hook bookkeeping: it is in the emulator's
per-instruction dispatch and the sheer instruction count the payload's own loader
executes. The measured shape of the problem (fair set, 300s budget) is
`imports 63/86 vs the reference's 75/86` and `OEP 79/86 vs 83/86` - i.e. taote is
now within ~10 samples of the reference on OEP and ~12 on imports *when it has
the time*, and the corpus gap in that same population is entirely the 85s budget
under 4-way pinning.

### 0.17 Round 11: PE32 stub DLLs + the F52 guest-EAT walk (measured NEUTRAL)

Round 9/§0.15 measured the stub_map port as blocked: `ql.loader().save()` held
five stub DLLs at 0x10000000+ that start with MZ but expose no export directory
a 32-bit walk can read. That blocker is now fixed and the walk landed; the fair
set says the *scoreboard* effect is nil, and here is why.

1. **The stub DLLs were PE32+ for 32-bit guests.** The loader answered
   LoadLibrary and the API dispatch covered what it implements, but every
   32-bit reader of the image — including the unpacker's own F52 walk — saw no
   exports. `write_stub_dll` now renders PE32 (magic 0x10b) for x86 guests and
   PE32+ for x64, **by hand** (mirroring `tools/stub_dlls.py`, which already
   seeds the reference emulator's rootfs). The hand-roll was forced: the vcpkg
   LIEF 0.17.6 Builder cannot round-trip PE32 — reproduced here, a PE32 build
   drops the `.text` section, writes `SizeOfOptionalHeader = 0x60` and a section
   table its own parser cannot read, so the export table is lost on re-parse.
   (The Python `build_stub_pe` port parses clean: magic 0x10b, exports + base 1
   ordinals.)
2. **The F52 walk itself** (`salvage_iat`): for every loaded module, read the
   guest export directory and register each non-forwarded EAT address as
   `(dll, name)` in the symbol map, plus the ordinal-dominant lane (`ordinal_N`
   for name-sparse EATs). This is the reference's `stub_map_` slot-address
   attribution (§1.7) — attribute a dump slot by the ADDRESS it holds, not by
   whichever GPA handle happened to be current when the name was asked. Before
   this fix the walk registered **0 modules**; now it registers every loaded
   stub DLL (`[salv] module exports: 17 modules` on winupack_Procmon).

**Measured (86-sample fair set, 300s, pin 4, `tools/unpack_report.py`):**

| | round-10 close (taote2) | round 11 |
|---|---|---|
| all three | **60 / 86** | **60 / 86** (0 gains, 0 losses) |

A first probe on 7 catastrophic samples looked like +6, but that compared
against the WRONG baseline (`fair/taote_results.json`, the pre-instruction-cap
23/86) — against the real round-10 baseline (`fair/taote2_results.json`, 60/86)
six of the seven were already all-three, and the seventh (aspack_adwcleaner)
is a 302s budget-bound flake that reverted to its baseline shape in the full run.

**Why the walk is neutral despite working.** The 15 catastrophic import samples
of §0.14 (winupack_Procmon/procexp, the Ps*/7zFM/ADInsight set) were already
fixed by round 10's instruction cap (bf49143) — they are inside the 60/86. The
fair set's remaining `recall < 0.5` population is 21 samples: RLPack (13),
PEtite (5), and two 302s budget-bound flakes (aspack/eronana adwcleaner). RLPack
and PEtite are decode-blocked (their `.text` never decodes; §0.5.2), not
attribution-blocked, so a slot-address map cannot move them. And the F52 walk
registers only what the stub DLLs actually export — which, for a packed file, is
the packed file's own minimal import table (2 names for kernel32 on WinUpack),
so its contribution to the symbol map is ~0. The walk is therefore *mechanically
unblocked but starved*: the remaining step is to seed the stub DLLs with a full
per-DLL export surface (the ApiRegistry's implemented names, not the sample's
import table), which is what would let slot-address attribution beat the GPA
handle-decoy attribution on the catastrophic class. That is a separate, larger
change and is NOT in this commit.

Kept (not reverted) because it is the correctness foundation the next step
needs: 32-bit guests now see PE32 stub images, the hand-rolled writer removes a
LIEF Builder round-trip footgun, and the F52 walk is a faithful port that
registers the modules it is given. Suite stays 593/593 green; 0 wall-timeouts,
0 host crashes across the 86-sample fair run.

### 0.17b Round-11 lever 2 profiled: dispatch_trace is 174 ns/insn, and the micro-opts are neutral

`perf`/`valgrind` are unavailable on this host (kernel.perf_event_paranoid=4,
no valgrind), so the profile came from a throwaway `rdtsc` probe gated by
`TAOTE_HOOKPROF` (built, measured, then reverted — the tree is back at 777d5fb).

Measured on mew_Bginfo (50M instructions, taskset -c 0): taote runs at
**~5.2M insn/s** where bare unicorn runs the same tight loop at ~450M insn/s
— an ~86x gap, i.e. ~190 ns/insn of overhead. The breakdown:

| path | ns/call | calls (50M run) | share |
|---|---|---|---|
| `dispatch_trace` (code-hook dispatch, incl. every callback) | **174** | 50M | ~86% |
| `dispatch_mem` (write-hook dispatch) | 57 | 10.4M | ~6% |
| scheduler `on_hook` | 9 | 50M | ~4% |
| `hook_winapi` early return (2 symbol-map finds) | 34 | 50M | — (inside dispatch_trace) |

So the code-hook dispatch is the cost, and it is spread: the three *global*
code hooks (winapi dispatch, thread scheduler, stack-pointer guard) fire on
every instruction, each doing small work, plus the per-section watchers'
`bound_check` loop. Three micro-optimizations were applied and measured neutral
(10.16s vs 10.12s baseline at 50M, within noise):

* `hook_`/`insn_hook_`/`addr_hook_` and `import_symbols_`/`stub_addr_names_` as
  `unordered_map` (O(1) vs O(log n) find);
* dispatchers iterate the hook list by index instead of `const auto copy =
  it->second;` (the copy heap-allocated per instruction);
* `const std::shared_ptr<Hook>&` element reference instead of a per-element
  shared_ptr copy (avoids the per-instruction atomic refcount bumps).

The rdtsc probe says `dispatch_trace` drops 174 -> 115 ns/call after the
shared_ptr-reference change, yet the *wall* time is unchanged, so the probe's
absolute numbers are not actionable and the wall clock is what we trust. The
remaining ~2x is therefore not in these dispatch micro-ops — it is unicorn's
own per-instruction dispatch plus the sheer guest instruction count, i.e. the
reference's family accelerators (UPX NRV/LZMA, MEW LZMA) that replace hot guest
loops with host code. Do not re-try the hook-bookkeeping angle (§0.16b is now
confirmed at the rdtsc level). The accelerator work is lever 3 (MEW LZMA) and
is large; lever 4 (OEP residuals) is the cheaper next move.

### 0.17c Round-11 lever 4: the PECompact mini-stub EP fix (+2 fair set, 0 losses)

Three of the fair set's four OEP-only misses are PECompact/MPRESS and decode
fully (code_sim 0.88-1.0, imports recall 1.0) — only the entry RVA is wrong.
`pecompact_PEViewer` showed the bug: the section-hop latch records 0x40151a =
the header EP 0x401504 + 0x16 (PECompact keeps the original entry in the packed
header and plants a ~0x16-byte mini-stub there that CALLs the decompressor; the
latch records the resume point, reference `unpacker.cpp:11936-11958`). taote's
picker then let the shared decode-only ladder's Pass-C CFG-thunk scan override
that correct hop with a 0x4f99f0 look-alike.

Ported the reference's `SE_NO_PECOMPACT_EPFIX` fix (default ON): when a hop
lands within 0x40 bytes past the packed header EP in the same section, the
header EP is the entry — gated on **no unique CRT-init thunk (Pass A)** in the
image, because `pecompact_Bginfo`/`cpuz_x32` have exactly one such thunk as
their real entry (0x5b5d42 / 0x4f7c76) AND a hop latch near the header mini-stub;
the ungated version hijacked them (Bginfo 0x5b5d42 -> 0x401000, cpuz 0x4f7c76
-> 0x401000) and was reverted in the same session.

Measured (7-sample probe, 300s, pin 4, `tools/unpack_report.py`):

| sample | before | after |
|---|---|---|
| pecompact_HashCalc | OEP wrong | **exact** |
| pecompact_PEViewer | OEP wrong | **exact** |
| pecompact_Bginfo / ComIntRep / cpuz_x32 | exact | exact (no regression) |

PECompact goes 3/5 -> 5/5 on the probe. Suite 593/593 green. The full 86-sample
fair set is running in the background (`fair/r11b`); expected 60/86 -> 62/86.
`mpress_HDDScan` is a separate MPRESS picker case (still OEP-wrong) and is not
touched by this fix.

### 0.17d Round 12: seed the stub dlls with the full per-dll export surface

The F52 walk was unblocked in §0.17 but starved: the stub dlls exported only the
packed file's own import table (~2 names). Round-12 lever 1 fixes the starvation:

1. **Per-dll attribution in the ApiRegistry.** `ApiEntry` now carries a `dll`
   field, captured from a registration scope (`set_current_dll`) that
   `register_dlls()` sets around each family (kernel32's ~26 subfamilies +
   advapi32/msvcrt/user32/wininet/msi/ntdll/ucrtbased/wsock32/ws2_32/ucrtbase/
   ole32/shlwapi/crypt32/mscoree/msvbvm60/shell32/ntoskrnl/wudfplatform/
   oleaut32). `ApiRegistry::names_for_dll(dll)` exposes the surface.
2. **`write_stub_dll` unions the sample's import names with
   `names_for_dll(dll)`**, so every synthesized stub dll exports what taote
   actually implements for it.

Measured on winupack_Procmon: the F52 walk now registers **4 modules / 308
named exports / symbols=660** where the pre-round-12 tree registered 1 module /
2 named / 467 symbols.

**Also fixed while landing it:** a pre-existing heap-use-after-free in the
unpack teardown — `~Unpacker` called `hooks_.clear()`, and each `HookRet`
walked `QlCoreHooks::hook_` which the `Qiling` had already freed (the ASAN
build catches it; it also flaked the release build as
`UnpackCompat.UnpackMetaJsonValid (SEGFAULT)` under ctest). `~Unpacker` now
`release()`s the handles (detach, no walk) and `detach_hooks()` also clears
`dyn_hooks_`. Suite 593/593 green; the ASAN build's UnpackMetaJsonValid passes
5/5.

**Measured (86-sample fair set, 300s, pin 4, `tools/unpack_report.py`):**

| | round-11 close (with epfix) | round 12 |
|---|---|---|
| all three | **62 / 86** | **62 / 86** (0 gains, 0 losses) |

Scoreboard-neutral, but the import side moved where it is still decode-blocked:

| sample | recall before | recall after |
|---|---|---|
| rlpack_HDDScan | 0.032 | **0.181** |
| rlpack_dfrgui | 0.058 | **0.301** |
| rlpack_geek | 0.037 | **0.308** |
| rlpack_procexp | 0.040 | 0.056 |

RLPack is decode-blocked (§0.5.2: the payload `.text` never fully decodes), so
recall 0.18-0.31 stays under the 0.95 "imports" bar and the three do not flip
all-three — but the full surface is demonstrably feeding the slot-address
attribution (recall up 3-8x). Throughput is unchanged (fair-set median 72s ->
71s, mean 95s -> 96s). Suite 593/593 green; the ASAN build's
UnpackMetaJsonValid now passes 5/5 (the teardown fix).

Verdict: keep as the enabler for the attribution class, with the measured caveat
that it only converts once the RLPack/PEtite decode lands (lever 4). The corpus
run is deferred (the fair set is the import-gap population this lever targets).

### 0.17e Round 13: lever 2 — the throughput gap is hook FREQUENCY, not dispatch

The round-13 lever-2 work profiled the per-instruction hot path properly (the
round-11 rdtsc numbers were noise) and located the real gap:

1. **The herdr's map-find hypothesis is disproven.** With the round-12 full
   export surface, the per-instruction `import_symbols_at`/`stub_symbol_at`
   map finds looked like the hot cost — but an instrumented run shows the
   cheap pre-check skips **100%** of 50M MEW instructions (`skip=49999999
   find=0`): the hot loop never lands on a dispatch address, so the map finds
   never even run. The cheap range test (in_dll_range / is_import_stub) and the
   native-ranged code-hook split are both wall-clock neutral on the MEW
   benchmark (~9.5s at --count 50000000, unchanged).
2. **The gap is unicorn's per-instruction CODE hook.** A bare-unicorn loop does
   450M insn/s; one empty UC_HOOK_CODE drops it to ~58M insn/s; taote's
   trampoline+map+vector+std::function dispatch is ~39ns/insn (28M insn/s).
   taote runs 5.2M insn/s because it pays the per-*instruction* hook on the
   MEW LZMA loop (large working set → the cold-callback cache pollution is the
   remaining ~150ns/insn, not the dispatch arithmetic).
3. **The reference pegasus's bundled unicorn fires UC_HOOK_CODE once per basic
   block** (src/unpacker/unpacker.cpp:509 comment, verbatim), so its whole
   architecture is per-block, not per-instruction. taote's vcpkg unicorn fires
   CODE per instruction. That is the 2x lever.

Landed (measured-neutral on MEW by design; the win is for payloads executing in
watched sections, i.e. the budget-bound samples):
- bounded-range code/block hooks are now **native uc hooks** (unicorn enforces
  the range; out-of-range instructions never enter the trampoline), with a
  `trace_blocked_` flag preserving the QL_HOOK_BLOCK suppression across the
  global/native split;
- the unpacker's section-hop and dyn-exec watchers switched from `hook_code` to
  **`hook_block`** (per basic block, matching the reference);
- the winapi dispatch gained the cheap `in_dll_range`/`is_import_stub` pre-check
  before the symbol-map lookups (kernel-mode keeps the full lookup).

Suite 593/593 green. The 86-sample fair set is running (`fair/r13`).

### 0.17f Round 14: finish lever 2 — winapi dispatch + scheduler to per-block

The round-13 result was neutral on the MEW benchmark by design (MEW's LZMA loop
sits in an unwatched map, so the section watchers never fire there); the win
showed only on the fair set (median 71s -> 52s). The remaining per-instruction
cost was the global winapi dispatch + scheduler code hook, which fires on every
instruction even in unwatched regions. Round 14 moves those two to per-block:

1. **winapi dispatch split** (windows.cpp): `hook_handle_` is now a per-
   *instruction* guard that keeps only the instruction budget and the two SEH
   pre-checks (`seh_check_cpu_exception`/`seh_check_iret`); the actual
   `hook_winapi` dispatch rides a new per-*block* `hook_dispatch_`. An import
   call is a jump to a one-instruction stub cell — a basic-block entry — so
   block granularity fires the dispatch exactly once per call.
2. **scheduler to per-block** (thread.cpp): `scheduler_hook_` is now
   `hook_block` — the thread return address is reached via a `ret` (a block
   boundary) and the timeslice counts blocks, matching the reference's per-block
   CODE hook.

Measured (MEW --count 50000000, taskset -c 7, clean host): **9.5s -> 7.5s
(~21% faster, 5.2M -> 6.7M insn/s)**. Suite 593/593 green; correctness
spot-checks (winupack_Procmon/pecompact_HashCalc/mpress_Bginfo/upx_adwcleaner/
aspack_ADInsight) all reproduce their oep+imports exactly. Fair set: 62/86 ->
**63/86** (aspack_adwcleaner OEP False->True).

**Corpus (2678 samples, 85s harness budget, pin 4, round-14 tree):**

| criterion | round-14 | baseline (2b6ba33) | delta | reference |
|---|---|---|---|---|
| valid PE | 95.9% | 95.9% | — | — |
| OEP | **64.3%** (1609) | 63.5% (1587) | **+22** | 82.0% |
| imports | **66.4%** (1706) | 66.0% (1694) | **+12** | 77.3% |
| all three | **56.9%** (1524) | 56.0% (1499) | **+25** | 74.5% (1996) |

The round-13/14 speedup converted to +25 all-three corpus samples (and +22 OEP /
+12 imports) at the 85s budget, exactly the contention-sensitive class the
herdr predicted. Gap to reference: all-three -472, OEP -17.7pp, imports -10.9pp.

**Remaining 2x blocker (documented, not shipped):** the per-instruction guard
still has to exist because (a) the instruction budget is counted per instruction
(`++instructions_` + `instruction_budget_hit_`, which feeds the "timeout"
entry-point error), and (b) `seh_check_cpu_exception` pre-checks div/idiv per
instruction so a mid-block divide-by-zero is staged before unicorn raises the
uncatchable `UC_ERR_EXCEPTION` (the reference avoids both: its bundled unicorn
fires CODE per block and catches #DE via an interrupt hook — `intnum == 0` at
winemu.cpp:7549). Eliminating the per-instruction hook needs re-homing the
budget onto unicorn's native `count` (losing the clean timeout record) and
making the div guard a dynamically-installed hook that exists only while
`seh_sentinel_ != 0`. Not attempted — it is subtle and the measured stop was
~1.5x combined, not 2x.

### 0.17g Round 15: lever 1 — the remaining 2x is blocked at the budget counter

Round 15 attempted the full per-instruction-hook removal. Result, measured:

1. **div pre-check removal — landed (`ebc4d42`).** The bare-unicorn probe proved
taote's unicorn raises a catchable #DE interrupt (not the `UC_ERR_EXCEPTION` the
pre-check's comment claimed), and the existing `UC_HOOK_INTR` dispatch already
maps int 0 -> 0xC0000094 (the reference's winemu.cpp:7549 shape). Removed
`seh_check_cpu_exception` from the guard; throughput-neutral (MEW ~7.5s), suite
593/593 green.
2. **budget removal — blocked.** Moving the budget onto unicorn's native `count`
and detecting the hit via the `emu_stop_requested` latch regressed the PMA
parity test: a clean stop that ran off into the thread-return sled
(pc=0x10021050, no `emu_stop`) was misreported as "timeout". The normal
thread-return stop is indistinguishable from a count hit without per-instruction
counting, and taote's `InstructionBudgetStopsRunawayGuest` + the PMA hang guard
depend on that "timeout" record. The reference has no instruction budget (wall
timeout only), so there is no reference shape to port. Reverted the budget
change; the per-instruction counter stays.

Net lever-1 outcome: the per-instruction hook now carries only the instruction
budget (`++instructions_`) + the x64 iretq check. The remaining ~2x (removing
the budget counter) needs either a count-hit signal unicorn does not expose or
a redefinition of the PMA "timeout" contract — both out of scope for a
throughput-only round. Moving on to the OEP residuals (the largest criterion
gap, 64.3% vs 82.0%) and the decode-blocked families.

## 1. How pegasus unpacks, end to end

### 1.1 Lifecycle and where it hooks in

`Pegasus::run_module` (`src/pegasus.cpp:340-400`) is the whole story:

```
PackerDetector::detect_from_file(config.original_file)      // pegasus.cpp:346
  -> PackerDetector::create_unpacker(detection)             // :351-352  (family subclass)
  -> unpacker->install(*this, module, original_file, out_dir)  // :360-369  (before emulation)
  -> emu_->run_module(module, ...)                          // :372
  -> unpacker->finalize()                                   // :385        (dump+sidecar+rebuild)
```

`install()` runs *after* the module is loaded (so sections/base are known) but
*before* the first instruction of the stub. `finalize()` runs after the
emulation stops for any reason (payload exit, `ExitProcess`, timeout, unicorn
error) — so every artifact decision is made from terminal memory plus the
event history collected during the run. The CLI surface the eval harness drives
is `-t/--target`, `--unpack`, `--unpack-output`, `--unpack-timeout`
(`cli/cli.cpp:51-57`, wired at `:88-122`).

### 1.2 Detection

`PackerDetector::detect` (`src/unpacker/packer_detector.cpp:116-320`) tries, in
order, each returning `{name, sig_kind, sfx_format}`:

1. **section-name substrings** (`:37-63` sig table, matched at `:132-146`) —
   `.aspack/.adata`, `upx0/upx1`, `.mpress1/2`, `mew`, `nsp0/nsp1`, `petite`,
   `.packed/.rlpack`, `.neolit`, `.alien`, `.yp`, `$win8`, `fsg`, `.upack`,
   `.bero`, `.eronana`, `.ex_cod/.ex_dat`, `.enigma1/2`, `.themida`, `.jdpack`,
   `.packman`, `yc`. A family whose list has several entries requires **all** of
   them (`all = !pk.empty()`, `:133-145`).
2. **UPX PackHeader probe** (`:148-191`) — scan the first 0x800 bytes for `UPX!`
   plus validated version/format/method/size fields; survives renamed sections.
3. **Molebox** (`:193-205`) — every section name is a single digit (the stub NULs
   the names: `0text` → `"0"`).
4. **Amber** (`:207-227`) — ≥9 sections whose last name is `.` + 7 mixed-case
   alnum chars, ≥2 character classes.
5. **EP-prefix signatures** (`:229-275`) — a minimal PE header walk to the EP
   bytes, with a **file-alignment down-round** for degenerate headers
   (`:250-256`), then `ep_sigs()` (`:65-72`): PECompact `b8`, Eronana `60 68`,
   Exe32pack `3b c0 74 02 81`, TELock `e9`, WinUpack `be`.
6. **Stub-head signatures** (`:277-299`) — search the first 0x4000 bytes when the
   EP points at encrypted bytes (Ldpinch's 21-byte loader, `:90-96`).
7. **SFX probe** (`:301-315`) — embedded archive magic (rar4/rar5/zip/7z/cab) →
   family `SelfExtracting`.

`detect_from_file` (`:322-355`) re-implements the section parse from disk so the
**factory can pick a subclass before `install()`**, and `create_unpacker`
(`:357-386`) maps 15 names to subclasses, everything else to `GenericUnpacker`
(which is a deliberate no-op subclass: `packers/generic_unpacker.cpp:1-8`).

### 1.3 install(): sections, shadow buffer, header capture, hooks

`install` (`unpacker.cpp:178-189`) → `family_install_pre` (SFX short-circuit) →
`install_classify_and_parse` (`:191-248`) → `install_arm_generic_hooks`
(`:4816-5152`).

**classify_sections** (`:95-171`) turns the loader's sections into `PackSection`
{name (NUL-truncated, non-printables → `.`), start/end VA, vsize, raw, is_exec},
then picks a **watch set**:

* every exec section with vsize > 0, plus every "hollow" section (raw == 0)
  (`:115-131`);
* an **in-place** subset (exec, not hollow, not tiny-raw) — an exec *inside*
  these is only interesting if the stub wrote there (`:127-133`);
* a JDPack fallback when no exec candidate exists (`:136-143`);
* **plus every remaining section except the packed EP's own** (`:145-157`): the
  secondary watch set, because Amber/MEW payloads land in sections that look
  non-exec in the packed layout.

**install_classify_and_parse** also (`:203-230`) allocates the **shadow image**
(`shadow_image_`/`shadow_seen_`, image-sized: first write per address, the cure
for TELock's decrypt-execute-re-encrypt, `:207-211`, `unpacker.h:919-945`) and
saves the packed file's first 0x400 bytes (`orig_pe_header_`, `:213-221`)
because anti-emu stubs zero the in-memory MZ header.

**The hook set** (`install_arm_generic_hooks`, `:4816-5152`; helpers below):

| hook | where | what it does |
|---|---|---|
| API `GetProcAddress` (wildcard `*`) | `install_api_hooks_` `:250-353` | reads the requested name, returns a **sentinel** (`0xfeedfXXX`, `on_gpa_api` `:6145-6496`), registers `sentinel → (dll, func)` in `WindowsEmulator::import_table` (`winemu.h:245`, `:756-765`); ordinal names become `ordinal_<n>` and are recorded in `ordinal_evidence_` (`:6226-6231`). This is what makes a stub's IAT rebuild survivable *and* harvestable. |
| API `ExitProcess`/`ExitThread` | `:333-334` | `on_exitprocess_api` (`:6128-6144`) — a stub that bails on an anti-emu check still triggers the dump path |
| API `LoadLibrary*`/`GetModuleHandle*` | `:336-347` | remembers `last_ll_name_` so GPA attribution can name the dll the stub just opened, plus the Alienyze pre-walk snapshot (`:290-330`) |
| memory **write** per watched section | `install_section_watchers_` `:4708-4738` | `on_section_write` (`:5197-5381`) |
| code **exec** per watched section | same | `on_section_exec` (`:5520-5810`) |
| module-wide code hook | `install_cf_hook_` `:4739-4772` | `on_cf_transition` (`:5820-5964`) — installed only for RLPack/Yoda/NSPack by default (`:4757-4766`, measured ~11% wall) |
| invalid-instruction hook | `install_invalid_insn_` `:4773-4815` | `0xF1` = lazy `int1` → emulated SEH (`dispatch_seh(0x80000004)`); other `#UD` → `dispatch_seh(0xC000001D)`. TELock/Yoda ladders need this |
| shadow (first-write) feed | `install_shadow_hook_` `:355-460` | fused image-wide write hook feeding `shadow_image_` |
| accelerator hooks (UPX NRV2B/NRV2E, UPX LZMA, MEW LZMA, Alienyze checksum loop) | `:557-4262` | host-side decoders that replace hot guest loops; large, family-specific, optional (see §6) |

### 1.4 Emulation: write tracking → section claims → exec hop

The primary OEP mechanism is **write-then-execute per section** — OllyDump's
"section hop", but with the false-positive work pegasus learned:

*`on_section_write`* (`:5197-5381`) claims a **whole section span** on the first
write into it:
* self-writes are suppressed: if the stub is *executing* in the same section and
  that section is not the EP's (NSPack's stub writing its own `.nsp1`), the hook
  **disables itself** and claims nothing (`:5251-5284`) — otherwise the stub's
  next instruction fires a bogus hop;
* the claim is recorded in both `ever_written_` (never erased, read by the CF
  hook) and `written_ranges_` (consumed on first hop), and the per-section write
  hook then self-disables (`:5349-5376`) so a byte-at-a-time decoder does not pay
  a callback per byte;
* **hollow-predecessor cap** (`:5324-5350`): when a raw==0 section precedes the
  stub's EP section, the claim is capped at `packed_ep - 0x100` so the stub's own
  unfilter loop cannot consume the range (UPX puttytel);
* the TELock import-write filter (`:5285-5310`) skips claims for writes landing in
  the packed file's own Import/IAT directories.

*`on_section_exec`* (`:5520-5810`) is the other half:
1. record the last 64 section transitions (`sec_trans_hist_`) and the per-section
   last-write instruction stamp (`:5523-5540`) — PEtite's OEP pick walks this
   history backwards (`unpacker.h:623-650`);
2. post-OEP grace check (`oep_grace_check_` `:5417-5519`: a wall window + an
   instruction cap + an import-quiet window; a stalled payload stops the run
   instead of burning the whole budget — UPX accesschk's anti-tamper park);
3. gates: skip stub code within `ep_skip_distance_` (0x1000) of the packed EP
   unless that range was written (`:5633-5656`); skip in-place exec unless
   written; family suppression seam (`family_suppress_exec`);
4. for each claimed range containing the pc: family overrides first, then
   MPRESS's lazy-trampoline back-hop rule (`:5688-5712`), the UPX/NSPack
   **replacement-hop gates** (internal-hop skip, `:5721-5750`; import-growth ≥32
   gate in `dump_module`), then `dump_module(addr, "section_hop")` and erase the
   range.

`on_cf_transition` (`:5820-5964`) is the trampoline-class complement: it watches
every instruction, and when EIP crosses from one section into one that was ever
written, records a `CfHop` (`:5980-6088`). `finalize` takes the **last** hop
(`last_cf_hop_`) as an OEP candidate for the stubs whose epilogue `ret`s into the
payload (RLPack).

### 1.5 OEP: three sources, one ledger, one pick

Candidates are appended O(1) during the run to a ledger
(`unpacker.h:747-775`, `oep_ledger` `:6549-6609`) with a provenance bit:
`SCF_CF_HOP_W2X`, `SCF_SECTION_HOP_DUMP/REJ`, `SCF_WATERMARK`, `SCF_CLEAN_HOP`,
`SCF_DYN_REGION`, `SCF_WU_STACK`, `SCF_STATIC_PARSE`, `SCF_LADDER_PASS`,
`SCF_FALLBACK`, `SCF_INCUMBENT_FILL`, `SCF_ESP_TRICK`.

`dump_module` (`:6610-6834`) is the accept gate every hop goes through:
* cap: 16 stages (`:6611`);
* reject a zero page (`:6637-6660`);
* reject an **import-quiet replacement hop** for UPX/NSPack/Molebox when the
  import count grew by < 32 since the last accepted hop (`:6679-6700`);
* reject a landing back in the packed EP's own section when the incumbent is
  elsewhere (Amber junk trampolines, `:6700-6712` — `ep_sec_junk`);
* reject a data blob: read 16 bytes at the target, each byte overlaid from the
  shadow where the stub later re-zeroed/re-encrypted it (`:6708-6719`), and
  accept only when ≤12 of 16 are printable or the target section is exec/hollow
  (`:6727-6746`, unreadable target ⇒ exec/hollow only);
* `family_pre_dump_accept` seam; then latch `meta_.oep`, `last_oep_`,
  `last_accepted_hop_imp_`, `oep_widx_`;
* write the dump (`emit_final_dump`) and optionally the vtrace snapshot
  (`:6789-6805`, `vtsnap.cpp:1-30`).

`finalize` (`:8367-8566`) then runs a fixed order:
`family_finalize_diag` → `family_pre_terminal_oep` (MEW's cf-hop adoption) →
`family_pre_chain_fill` (the NSPack/RLPack/MPRESS decode-only ladder,
`decode_only_ladder` `:7814-7930`) → `family_terminal_fill` (per-family terminal
recovery: MEW's *static* OEP parse `packers/mew_unpacker.cpp:28-64,68-88`,
WinUpack's parked-stack OEP, Neolite's header OEP, EnigmaVB's in-memory header
`packers/enigma_vb_unpacker.h:8-24`, …) → `try_embedded_pe`
(`:10430-10520`: scan non-emulator maps for a complete PE *file* image — Amber
and friends build the original PE in a heap buffer) → `pick_and_emit_oep`
(`:7991-8366`) → `salvage_iat` → `slot_hist_resolve_` → `resolve_iat_addresses`
→ `validate_imports` → `write_sidecar` → `reconstruct`.

`pick_and_emit_oep` is the modern replacement for the deprecated standalone
`OepDetector` (`oep_detector.cpp:1-4` says so explicitly). It scores the ledger
with voters V0..V3 — a PECompact artifact-head veto, a prologue-shape vote
(capstone: MSVC `6a xx 68 imm32 e8` / `55 8b ec` / CFG `e8 … e9` +2.0, Borland
push-family +0.5, printable blob −1.5, `:8060-8110`), a region-class vote
(written-then-exec +1.5, exec +1.0), a quiescence vote (no GPA after the
candidate), an entropy vote, and an **incumbent prior** (`+1e6` strong) so a
family's terminal fill wins unless a challenger carries a strong source bit.

### 1.6 Artifacts (the contract taote must match)

`emit_final_dump` (`:6836-6919`) writes `<out>/<stem>_dump.bin` = `mem_read(base,
image_size)` + the TELock shadow overlay. `write_sidecar` (`:6982-7090`) writes
`<stem>_dump.bin.meta.json`:

```json
{ "base": "0x400000", "oep": "0x407a98", "oep_last_hop": "0x407a98",
  "is_64": false, "stages": 1, "reason": "section_hop",
  "imports": [["kernel32","GetModuleHandleA"], ...],
  "oep_candidates": [ ... optional, SE_DUMP_CANDIDATES ... ] }
```

`reconstruct()` writes `<stem>_unpacked.exe`. Verified locally on
`packed/UPX/upx_AccessEnum.exe`: `oep 0x407a98`, 232 imports, output with
sections `UPX0/UPX1/.rsrc/.pgimp`, EP RVA 0x7a98 — the `.pgimp` section is the
rebuilt import table.

### 1.7 IAT: harvest, salvage, attribute, validate

Imports arrive three ways:
1. **the loader's import table** snapshot (`loader_imports_`, `:6995-7015`);
2. **the GPA hook** — every `GetProcAddress` the stub makes, with the dll
   attributed from the module handle, the last `LoadLibrary` name, or the
   packed file's own import table as alias evidence (`:6145-6496`);
3. **family table walks** — WinUpack's static runtime table
   (`packers/winupack_unpacker.cpp`), MPress's shadow hints
   (`mpress_shadow_hints_` `unpacker.h:983-990`), Molebox/Exe32pack's strict
   IDir walk (`salvage_e32_*` `:8905-9443`).

`salvage_iat` (`:8584-8651`) = scan → attribute → write:
* **scan** (`salvage_iat_scan` `:8652-8824`) builds `stub_map_`: every GPA
  sentinel and every **JIT export stub address** of every emulated module →
  `(dll, func)` — plus an ordinal-EAT walk over the guests' own export
  directories for the ordinal-only-IAT class (`:8703-8830`);
* **write** (`salvage_iat_write` `:9480-9560`) walks every mapped region
  pointer-sized, looks each value up in `stub_map_` (in-image slots are read from
  the **frozen dump**, not live memory, so post-OEP runtime resolutions cannot
  pollute the static IAT `:9499-9512`), decodes the PEtite `push imm32; rol
  [esp],k; ret` dispatcher indirection (`:9533-9554`), and records a
  `SlotFixup{img_off, jit_addr, dll, name}`. Runs of adjacent same-dll slots
  become **anchor runs** (`AnchorRun`, `unpacker.h:68-73`) — the `FirstThunk`
  anchor the OS loader will rewrite.
* **validate** (`validate_import_pair` `:9691+`) re-attributes a name to the dll
  that really exports it, rejects host-absent names, and applies the ordinal
  gate.

### 1.8 Rebuild (`reconstruct`, `:11581-13700`)

1. read the dump; family transforms (`family_reconstruct_fixup`), MEW shadow
   overlay + residue sanitizer (`:11600-11660`);
2. if the in-memory MZ was zeroed, restore `orig_pe_header_` (`:11675-11690`);
3. parse the dump's own PE header: `e_lfanew`, OptSize, `SectionAlignment`,
   `FileAlignment`, data-dir base (**normalised to the 16-dir layout when
   `NumberOfRvaAndSizes != 16`**, the WinUpack corrupt-header case
   `:11720-11735`), section table (with a **sanity clamp** on
   `NumberOfSections`, observed `0xFFCD` on TELock/7z, `:11745-11770`);
4. normalise the OEP to an RVA (some families store one already, `:11780-11795`)
   and apply family EP fixes (PECompact's `EP+0x16` mini-stub, `:11800-11830`);
5. **build `.pgimp`** (`:12968`): `new_va = align_up(max_va_end, SectionAlignment)`;
   `build_import_section` (`:10031-10420`) emits, per dll group, an INT
   (`OriginalFirstThunk`) of name/ordinal thunks and an IAT
   (`FirstThunk`) that **anchors at the run's RVA** so the payload's own call
   sites keep working; a **noisy-IAT guard** drops the runs entirely when
   `slots > 3× meta imports` and anchored coverage < 75% (`:10075-10100`), and
   the family evidence filters (`SE_IMPORT_INTERSECT`, boot-face drop
   `:12990-13120`) decide which harvested pairs may enter;
6. **rewrite the in-image slot bytes** so static tools see real names, with a
   stale-slot guard (`:13596-13625`);
7. lay out the file: recompute `SizeOfHeaders`, every section's `PointerToRawData`
   from the dump, append `.pgimp` (`:13630-13680`), write
   `<stem>_unpacked.exe`.

### 1.9 Family seams: what the 15 subclasses actually add

`UniversalUnpacker` exposes ~35 virtual seams (`unpacker.h:133-520`, the
`InstallSlot`/`ReconStage` enums `:150-176`, `:340-410`). The subclasses override
one or two each; `generic_unpacker.cpp` overrides nothing. The ones that matter:

| family | what it adds (file:line) |
|---|---|
| **MEW** | static OEP parse from the header table (`mew_unpacker.cpp:28-64`); terminal full-dump when the import restorer desyncs (`:68-88`); shadow overlay + residue sanitizer in reconstruct |
| **WinUpack** | engine-exec suppression; **import-loop emulation** — emulate the stub's own `call ecx`/`call ebp` resolver pair and answer with real module bases / sentinels (`unpacker.h:464-500`, `winupack_unpacker.cpp:1-1258`); parked-stack OEP dword (`unpacker.h:830-840`); 64-char name truncation repair |
| **RLPack/MPRESS** | the shared decode-only ladder (`decode_only_ladder` `:7814-7930`) + MPRESS lazy-trampoline back-hop (`:5688-5712`) and static OEP read |
| **PEtite** | exec suppression, stale-hop rejection, the transition-history OEP pick (`unpacker.h:623-650`), INT-run salvage (`RECON_STAGE_PETITE_INT_RUNS`) |
| **NSPack** | decode-only ladder + ntdll bootstrap-slot filter (42-line subclass) |
| **TELock** | import-write filter + second-latch exec defer (Approach D/E, `:5280-5310`, `:5670-5690`), dump transform = shadow image (decrypt-execute-re-encrypt), SEH-driven ladders via the invalid-insn hook |
| **Themida** | mem-invalid forensics hook; **PEB LDR unlink** so the protector's injection probe cannot see the main image (`themida_unpacker.cpp:19-70`); RDTSC/CPUID counters |
| **Yoda-Protector/Crypter** | 4,324 lines of gates: canary replay, junk-skip, fast-forward scans, plateau write stamps — the single largest family file, and still 0/3 at S75 |
| **Amber** | `try_embedded_pe` (recover the original PE file image from a heap map) |
| **PECompact** | decoy preload, scrambled-entry guard, watermark/clean-hop OEP capture, EP+0x16 fix |
| **Alienyze** | per-sample single-byte-XOR recovery of the image (`recover_alienyze`, `alienyze.cpp:1-1544`), pre-walk snapshot of the name bands, `.alien` import store parsing |
| **Molebox** | static container pre-pass, orphan-name mining in the strict IDir walk |
| **Neolite** | registry-backed IAT, declared-FT singleton anchoring |
| **EnigmaVB** | OEP from the in-memory PE header written by the TLS-callback loader (`enigma_vb_unpacker.h:8-24`), VFS gates in winemu |
| **SFX** | `family_install_pre` short-circuits install entirely (`sfx_unpacker.cpp:75-203`) |

### 1.10 SFX / containers (not emulation)

`sfx_probe_archive` (`sfx_extract.h:31-46`) magic-scans for rar4/rar5/zip/7z/cab;
`sfx_extract_entries` (`:48-58`) extracts with **libarchive**
(`CMakeLists.txt:222-240`, compiled only under `PEGASUS_HAVE_SFX`, graceful
fallback to the generic path when absent). `SfxUnpacker::family_install_pre`
(`sfx_unpacker.cpp:75-203`) classifies entries by **content** (PE parse via
pe-parse), ranks candidates (same machine as the wrapper, then size), publishes
the primary as `<stem>_dump.bin`/`<stem>_unpacked.exe`, the rest as
`<stem>_sfx<N>_<name>`, plus a `_sfx_manifest.json` and a normal meta sidecar with
`reason: "sfx_extracted"`. No emulation is involved; the stub is never run.

### 1.11 Multi-stage and nesting — what does *not* exist

`meta_.stages` counts *dumps within one run* (max 16, `:6611`): a stub that
decodes in waves, or the MPRESS trampoline back-hop, produces several dumps and
the last accepted one wins. There is **no rescan loop**: pegasus unpacks the
sample once and stops (`pegasus.cpp:340-400`); `sfx_unpacker.cpp:139-141` notes
that its extra artifacts are named for an *external* consumer ("blade's peel
loop"). Measured on the S75 VERIFIED artifacts, re-running the detector on them
names a packer for **44 of 66** — but mostly because the rebuilt PE *keeps the
packer's section names* (`.aspack`, `.alien`, `.enigma1`), so a detection-driven
rescan would loop forever. Transitively packed samples (`packed/` has none
labelled as such) are out of scope for parity; nesting has to be a driver policy
keyed on evidence, not on the name detector (§3 Phase 5).

---

## 2. Concept → taote primitive mapping

taote already has most of the *emulation* substrate from the PE-parity work; it
has none of the *unpacker*. The table is the port's real content.

| concept (pegasus) | taote today | verdict |
|---|---|---|
| per-instruction code hook (`add_code_hook`) | `QlCoreHooks::hook_code(cb, begin, end)` (`qiling/core_hooks.hpp:69`) | **have** |
| per-range memory **write** hook with value | `hook_mem_write(cb, begin, end)` + `MemHookCallback(access, addr, size, value)` (`core_hooks.hpp:96`, `core_hooks_types.hpp:31`) | **have** — the section-claim machinery maps 1:1 |
| read / invalid-mem / invalid-insn / intr hooks | `hook_mem_read`, `hook_mem_invalid`, `hook_mem_unmapped`, `hook_insn_invalid`, `hook_intr` (`:87-118`) | **have** |
| `add_dyn_code_hook` (new map = code?) | **absent** (no map-notification hook) | **build** (small: taote's `QlMemoryManager::map` is the single choke point; a `map_observer` callback is ~20 lines) |
| memory map walk (`get_mem_maps`, base/size/tag) | `QlMemoryManager::get_mapinfo()` → (lbound, ubound, perms, label, container) (`qiling/os/memory.hpp:99`) | **have** |
| read a whole image | `ql.mem().read(base, size)` | **have** |
| protect/map/find_free_space | `map`, `protect`, `find_free_space` (`memory.hpp:134-146`) | **have** |
| `WindowsEmulator::import_table` sentinel registry + `register_sentinel` | `QlLoaderPE::import_symbols()` / `import_symbols_at(addr)` / **`register_import_symbol(addr, dll, name)`** (`qiling/loader/pe.hpp:76-93`) — the dispatcher keys on these addresses | **have** — this is exactly pegasus's sentinel lane |
| API interception by name (`add_api_hook`) | `set_api` / `set_api_enter` / `set_api_exit` (`qiling/os/os.hpp:196-204`); `set_api_enter("GetProcAddress", …)` can rewrite the return value with `register_import_symbol` | **have** (proven by the ntoskrnl-rider and PMA work) |
| `dispatch_seh` for int1/#UD | `seh_dispatch` / `seh_check_iret` / `NtContinue` delivery (this repo, `qiling/os/windows/seh.cpp`) | **have** (built for PE parity) |
| section table of the main image (name, vsize, raw, exec) | loader keeps `Image{base,end,path}` only (`loader/loader.hpp:23-27`); LIEF sections are parsed but not retained (`loader/pe.cpp:84`) | **build** (expose `QlLoaderPE::sections()` from the LIEF parse, or re-parse the in-memory header) |
| module export enumeration (JIT stub map, ordinal EAT walk) | `import_address_table_at(dll)` + `export_symbols()`; no *guest-memory* EAT walk | **partial** — the EAT walk for ordinal IATs is new (~80 lines) |
| packed-file header snapshot (`orig_pe_header_`) | trivial (`std::filesystem` read) | **build** |
| shadow first-write image | `hook_mem_write` global range | **build** (small) |
| OEP candidate ledger + scoring (V0..V3) | — | **build** (the biggest single piece; ~600 lines with capstone shape vote) |
| section-hop accept gate (`dump_module`) | — | **build** |
| `.pgimp` PE rebuilder | LIEF has `PE::Builder` (`build/vcpkg_installed/.../LIEF/PE/Builder.hpp`) and `nlohmann/json` is available | **build**, and decide LIEF-vs-hand-rolled (§3 Phase 1) |
| IAT salvage scan + anchor runs | — | **build** |
| SFX extraction (rar5/zip/cab) | no libarchive in `vcpkg.json` | **build + new dependency** (§3 Phase 4) |
| snapshot at OEP (vtrace JSON) | taote has its own binary snapshot envelope (`qiling/snapshot.hpp`) and `QilingSavedState` | **have (different format)** — not needed for parity; skip |
| unpack CLI (`-t --unpack --unpack-output --unpack-timeout`) | taote has `tools/parity_trace` + `tools/sweep_samples.py` (sample sweeps) | **build** (`tools/taote_unpack`, flag-compatible so the grader runs unmodified) |

Two taote-specific advantages worth using: the **EA/`import_symbols_` dispatcher**
already gives us the sentinel lane with no new registry, and LIEF is already linked
(so the PE *parser* half of the rebuilder is free; the *writer* is the work).

Two taote-specific hazards to plan around: taote has no "run to entry and then
stop" lifecycle — `Qiling::run()` goes to the exit point (`qiling/core.cpp:220-265`)
and the unpacker needs `install → run → finalize` with the run's *terminal memory*
preserved (that is already how taote behaves: nothing frees guest memory before
`run()` returns), and taote's API surface is narrower than pegasus's for the
*sentinel* lane (`GetProcAddress` attribution quality depends on the loader's
import tables — §4).

---

## 3. Phased plan

Each phase ends with a measured number and a test that fails when the number
regresses. All numbers are for the corpus of §0.1 with the grader of §0.0.

### Phase 0 — harness, artifacts, metrics (no unpacking yet)

Build: `tools/taote_unpack` with the **flag-compatible** surface
(`-t/--target`, `--unpack`, `--unpack-output`, `--unpack-timeout`, plus
`--json`), writing the three artifact names of §1.6 (contents may be a raw dump
+ empty imports at this stage), and `tests/Unpack_Compat_Test.cpp`:
`UnpackArtifactContract` (names + meta keys + valid JSON),
`UnpackGraderSmoke` (the grader accepts a *hand-made* good artifact:
dump = the original not-packed file, meta oep = original EP ⇒ must grade
UNPACKED_VERIFIED **and** pass `a_success_oep` — this calibrates the grader
against taote before any unpacking exists; the strict flag matters because the
reference grader ignores (a), §0.0), `UnpackMetaJsonValid` (every artifact's
meta must parse with nlohmann — the reference's MEW/Molebox metas do not), and
`UnpackHostSafety` (a malformed-PE fixture must raise `QlErrorBase`, never
crash).

Exit test: `run_all.sh --cli build/tools/taote_unpack --manifest S75` completes
75/75 runs, `verify.py` prints a per-family table, and `UnpackGraderSmoke` grades
VERIFIED. Scoreboard row added: **taote S75 = 0/75 VERIFIED** (baseline
recorded), wall median/max recorded.

### Phase 1 — the generic unpacker core (no families)

Port, in this order (each is independently testable):

1. **section classification + watch set** (§1.3) — needs `QlLoaderPE::sections()`;
2. **write-claim tracking** (§1.4 first bullet, including the self-write
   suppression and the hollow-predecessor cap);
3. **section-hop exec + accept gate + 16-stage cap** (§1.4/§1.5) with a *minimal*
   accept gate (zero-page + printable-ratio + `near_ep` skip), no OEP pick yet
   ("first hop wins", like pegasus's pre-pick trunk);
4. **dump + sidecar** (exact §1.6 JSON keys);
5. **imports from the loader table only** (no GPA sentinel yet) — enough to make
   `.pgimp` non-empty and gradeable;
6. **rebuilder** (§1.8): decide **hand-rolled** (byte-identical control, ~700
   lines, same code shape as pegasus's `reconstruct`) over LIEF Builder (less
   code, but LIEF's writer normalises headers and would make (c)/(d) comparisons
   fuzzy). Recommendation: hand-rolled, because the grader compares EP RVA and
   `.text` bytes at identical RVAs and pegasus's own layout rules (header
   normalisation, degenerate-section clamp) are already known-good.

Exit test: `UnpackGenericCore` (a UPX sample: dump written, `.pgimp` present,
output loads in taote's own loader), then

| metric | target |
|---|---|
| **S75 UNPACKED_VERIFIED** | **≥ 45 / 75** (oracle 66; strict 60) |
| families with ≥1 VERIFIED | ≥ 18 / 25 |
| mean (e) dll coverage on VERIFIED | ≥ 0.80 |
| meta.json valid (nlohmann) for every run | 75 / 75 (oracle 69/75 — §0.0) |
| host crashes | 0 |

The 45 is anchored on the oracle's *generic-solvable* set: at S75 the oracle
verifies 3/3 in 20 families whose stubs are plain decoders — even the three
detector-blind families (EXpressor, FSG, BeRo) verify 3/3 on the generic path,
which is the evidence that detection is not required for them.

### Phase 1b — GPA sentinel + IAT salvage (the import half)

Add the `GetProcAddress` wildcard interception + `register_import_symbol`
(sentinel lane), the `stub_map_` build (sentinels + module exports + ordinal EAT
walk), the pointer scan over the frozen dump, anchor runs, `validate_import_pair`,
and the noisy-IAT guard. This is where winupack-style `imp-cov` failures get
fixed (the oracle's only `PARTIAL` at S75 with code-sim 1.0 is an import-coverage
case).

Exit test: `UnpackIatSalvage` (a Upack sample: ≥ 80% dll coverage), then
**S75 VERIFIED ≥ 55/75** and **mean dll coverage ≥ 0.85**.

### Phase 2 — detector + family dispatch

Port `PackerDetector` verbatim (§1.2: section sigs, PackHdr probe, Molebox
digits, Amber shape, EP-prefix with alignment down-round, stub-head, SFX probe)
plus `create_unpacker`. Add the family-routing **measurement** the oracle lacks:
a per-sample `--json` field `detector` + a test asserting the family mapping.

Exit test: `UnpackDetector` with the measured scoreboard of §0.3 as the target:

| metric | target |
|---|---|
| families whose detector name == family dir | **25/25** (oracle 22 — fix BeRo→`BeRoEXEPacker`, EXpressor, FSG; keep pegasus's answers available behind a flag for differential runs) |
| S75 detector == family dir | ≥ 73/75 |
| dispatch table coverage | 15/15 pegasus-mapped names → a subclass |

Rationale for exceeding the oracle: two of the three misses are cheap (`fsg`
does not substring-match these samples; `.ex_cod` requires both names), and
misrouting costs a whole family. A/ B the new sigs against the *not-packed* 424
originals so no unpacked file is ever misdetected (precision check, same method
pegasus used for Ldpinch, `packer_detector.cpp:85-96`).

### Phase 3 — per-family ports, ordered by sample yield

Ordered by *measured* yield per unit work at S75, not by family size. Every port
is one seam override (or a small set) on the base core; the gate for each is
**no regression on the other 24 families** (pegasus's own protocol, e.g. the
`SE_PERF_CFOPT` A/B `unpacker.cpp:4757-4766`).

| # | family | seam(s) | S75 oracle | why now |
|---|---|---|---|---|
| 1 | **UPX** | none (base) + replacement-hop gates + grace stop | 3/3 | largest single-family share of real malware; already covered by the core; only the gates are extra |
| 2 | **ASPack** | none (in-place claim already handles it) | 3/3 | second-largest; validates in-place decode |
| 3 | **MEW** | static OEP parse + terminal fill + shadow overlay | 3/3 | the `_getptd`-class anti-emu is generic; the parse is 40 lines |
| 4 | **FSG / EXpressor / BeRo / Eronana / JDPack / Packman** | none (generic) — but detector names (Phase 2) | 3/3 each | verifies that the core is family-agnostic |
| 5 | **PEtite** | transition-history OEP pick + stale-hop reject | 3/3 | one well-documented mechanism (`unpacker.h:623-650`) |
| 6 | **NSPack / MPRESS** | decode-only ladder (+ MPRESS back-hop, static OEP) | 3/3 each | shared ladder: one port, two families |
| 7 | **RLPack** | ladder + CF-hook OEP + stage-2 window | 3/3 | as above |
| 8 | **WinUpack** | engine suppression + import-loop emulation + parked-stack OEP | 2/3 + 1 PART | 1,258 lines but it is the only path to `imp-cov` on that family |
| 9 | **TELock** | write filter + exec defer + shadow dump transform | 3/3 | needs the shadow image from Phase 1 |
| 10 | **PECompact** | decoy preload + watermark/clean-hop + EP fix | 3/3 | several small seams |
| 11 | **Molebox / Neolite / Amber** | container pre-pass / registry IAT / embedded PE | 3/3, 3/3, 2/3 | one mechanism each; Amber's `try_embedded_pe` is generic-ish |
| 12 | **Alienyze** | XOR recovery + pre-walk snapshot + `.alien` parse | 2/3 + 1 PART | 1,544 lines of recovery; only pays off for this family |
| 13 | **EnigmaVB** | in-memory header OEP + VFS gates | 3/3 | small; the VFS gates live in the emulator, not the unpacker |
| 14 | **Themida** | LDR unlink + RDTSC/CPUID + mem-invalid forensics | **0/3** | *do not port for score* — the oracle fails too. Port only the LDR-hide if anti-emulation for other families needs it |
| 15 | **Yoda-Protector/Crypter** | 4.3k lines of gates | 3/3 (Crypter), **0/3** (Protector) | port only if a corpus sample outside this dataset needs it; Crypter is cheap-ish, Protector is a research project |

Exit test per row: that family's S75 cells reach the oracle's grade, and S500 does
not regress (`--cap 20`, delta 0). Phase 3 exits at **S75 ≥ 60/75** (the oracle
is 66, and its 9 non-verifies are mostly the two VM families we defer) and
**S500 ≥ 250** (the oracle's 52.9% census scaled).

### Phase 4 — SFX / container extraction (non-emulation)

Add `libarchive` to `vcpkg.json` (pegasus gates the feature exactly this way:
`CMakeLists.txt:222-240`, `PEGASUS_HAVE_SFX`, graceful fallback). Port
`sfx_probe_archive`, `sfx_extract_entries`, the candidate ranking (content-based
PE classification, same-machine first then size), the manifest, and the
`family_install_pre` short-circuit.

Honest coverage note: **the dataset has no SFX family** — `dataset-packed-pe`
labels 25 packers, and probing its samples for archive magics finds none
(the closest, "Enigma Virtual Box", is a bundler, not an SFX). So Phase 4's exit
test cannot be corpus-graded; it needs fixtures: one WinRAR SFX, one 7z SFX, one
IExpress/CAB, one zip-dropper, each compared against the oracle's
`_sfx_manifest.json` (same entry names, same primary, same published bytes).
Target: **4/4 fixtures byte-identical primary + manifest equal**.

### Phase 5 — nesting / rescan (driver policy, not engine)

Because §1.11 shows the oracle has no loop and the name detector cannot be the
trigger (44/66 artifacts re-detect), the policy is:

1. an artifact is a *candidate child* when the dump's entry code is still a stub:
   the first N bytes at the OEP decode as a pushad/`e9`/`call` prologue **and**
   the image contains a section that is hollow or still high-entropy;
2. re-run the unpacker on the child with `--peel N` (default 0 = off, 2 for
   nested corpora), attributing each hop in the meta (`parent`, `depth`);
3. stop on: no new OEP, no grade improvement, or depth > 2.

Exit test: `UnpackPeel` (a synthetic doubly-packed sample: UPX over UPX) reaches
the inner payload at depth 2 and grades VERIFIED against the doubly-unpacked
original; on S75 the policy adds **0 false children** (every VERIFIED artifact
re-detect that is not a real stub stays at depth 0).

### Phase 6 — robustness, performance, safety

| risk | test | target |
|---|---|---|
| malformed rebuilt PE (the `0xFFCD`-sections class) | fuzz the rebuilder with 1,000 mutated dumps | no host crash, always `QlErrorBase` |
| heap corruption in the salvage scan (untrusted pointer arithmetic — pegasus needed an explicit wrap guard `unpacker.cpp:9530-9536`) | `-fsanitize=address` run over S75 | 0 findings |
| per-sample wall budget | `--unpack-timeout 85`, wall cap 120 | 0 wall-timeouts at S75; median ≤ 30 s, max ≤ 90 s |
| API-surface gaps (taote's `GetProcAddress`/`LoadLibrary` attribution) | count un-attributed GPA calls per sample | ≤ 10% of GPA calls unattributed |
| unpacked code is attacker-controlled (it *runs* in later analysis) | keep every unpack step inside the child process boundary already used by the corpus sweeps (`tools/sweep_samples.py` forks per sample) | no unpack-run can take the suite down |

Exit test: all five rows measured and green; `ctest` runtime for the unpack suite
≤ 10 min.

---

## 4. Risks

1. **Single-process host safety.** The dump/rebuild path parses attacker-controlled
   PE headers, section counts and pointer values. We have already been bitten by
   exactly this class twice in taote (the ASan heap-use-after-free on LIEF
   iterators during DLL load, PLAN_PE_PARITY §2.2; and the malformed-PE loader
   segfault that forced the ASan build). Mitigation: ASan build in CI for the
   unpack suite, the "every failure is a `QlErrorBase`" tenet, and the
   fork-per-sample driver for corpus runs.
2. **Anti-emulation.** The corpus's protectors (Themida, Yoda-Protector, Alienyze,
   TELock) detect the emulator and either park or self-corrupt. pegasus answers
   with family-specific counter-measures (LDR unlink, RDTSC/CPUID counters,
   canary replay) and still fails two families outright (§0.2). Do not promise
   these; port the *generic* anti-emu hygiene taote already has (PEB flags,
   BeingDebugged) and treat VM protectors as out of scope until the rest is
   green.
3. **API surface narrower than pegasus's.** The GPA sentinel lane needs
   `GetProcAddress`/`LoadLibrary`/`GetModuleHandle` attribution to be as good as
   pegasus's `import_table`+`last_ll_name_` chain (`unpacker.cpp:6145-6496`).
   taote's version must be measured (un-attributed GPA rate, Phase 6) before the
   import half can be declared done; a stub that resolves through an alias
   (`wsock32` → `ws2_32`, `api-ms-*`) will otherwise emit wrong dll names and
   lose (e).
4. **Emulation-time explosion.** The upstream budget is 85 s/sample and pegasus
   needs accelerators (UPX NRV/LZMA host decoders, `unpacker.cpp:2010-4262`) to
   stay inside it; those are ~2,000 lines of *optional* family-specific work. If
   Phase 1 shows UPX-class samples over budget, the accelerators become a
   prerequisite rather than an optimisation.
5. **Grader blind spots.** `verify.py` decides `MANAGED` from the *original*'s CLR
   directory, so a **managed payload inside a native stub** is graded on the
   native stub's EP/code — measured: 2 of the 66 oracle VERIFIED artifacts are
   .NET assemblies that pegasus's *own* loader refuses to load. Any taote-vs-
   pegasus comparison must also assert "the artifact loads in our loader", not
   only "the grader says VERIFIED".
6. **Nondeterminism.** pegasus documents run-to-run divergence (ASLR-adjacent
   gate flips, `docs/unpacking-roadmap.md` C3 note) and load-sensitive wall
   timeouts (`tools/unpack_eval/README.md:44-54`). Comparisons must be serial
   (`--pin`) and repeated before a delta is believed; a single flip is not a
   regression.
7. **Corpus scope creep.** `packed/` has 3,001 samples but the S75/S500 scopes are
   what we gate on. A full-corpus run takes hours and (per the oracle's own
   README) is not grade-quality under contention.

---

## 5. Differential validation (pegasus is the oracle)

**A usable oracle exists and is verified here.**
`~/source/jim/pegasus/build/cli/pegasus-cli` and `build-cpp17/cli/pegasus-cli`
both exist; the `build/` one was used for every number in §0.2-§0.3.
`--help` confirms `--unpack`, `--unpack-output`, `--unpack-timeout`.

Protocol per sample (identical for both tools):

```sh
timeout 120 <CLI> -t <packed sample> --unpack --unpack-output <dir> --unpack-timeout 85
python3 ~/source/jim/pegasus/tools/unpack_eval/verify.py --manifest <m> --results <r>
```

Comparison axes, in order of strictness:

| axis | how | pass |
|---|---|---|
| grade | `verify.py` both sides, reported **and** strictly (∧ `a_success_oep`) | taote ≥ oracle − 5 at S75 |
| meta.json | `json.load` both sides | taote always valid (the oracle is 69/75 valid, §0.0) |
| **OEP** | `meta.json` `oep` vs oracle's | exact on ≥ 90% of samples where both found one; `ep_delta` distribution recorded |
| **dump** | sha256 of `<stem>_dump.bin` | equality where the oracle's `reason` is the same class; a mismatch must be explained (shadow overlay, family transform) |
| **imports** | set-compare `meta.json` `imports` (normalised `(stem, name)`) | Jaccard ≥ 0.80; (e) coverage ≥ 0.80 |
| **output PE shape** | section table (names, VAs, sizes), EP RVA, `.pgimp` presence | shape-equal; byte hash only for the raw-dump-verbatim families (Exe32pack-style) |
| artifact loads | taote loader parses the artifact | required (catches the .NET-payload blind spot §4.5) |
| downstream analysis | same capa/YARA-ish feature extraction on both artifacts | identical verdict on ≥ 90% |

Pin the oracle's knobs for reproducibility: `SE_OEP_PICK` (default on),
`SE_IMPORT_INTERSECT`/`SE_AUX_IAT`/`SE_IAT_SLOTHIST`/`SE_VTSNAP` default off —
record the env in the results file so a later reader knows which trunk produced
the artifacts.

---

## 6. Effort and ordering recommendation

Samples per unit work, from the measured per-family state and the seam counts:

| tier | families | S75 samples | work | recommendation |
|---|---|---|---|---|
| **A — free with the core** | UPX, ASPack, FSG, EXpressor, BeRo, Eronana, JDPack, Packman, Exe32pack | 27/75 | Phase 1 + Phase 2 only | **do first**; 36% of S75 for no family code at all |
| **B — one mechanism each** | MEW, PEtite, NSPack, MPRESS, RLPack, TELock, PECompact, Neolite, Molebox, EnigmaVB | 30/75 | one 40-120 line seam each | **do second**; best samples-per-line in the whole plan |
| **C — big single-family projects** | WinUpack (1.3k), Alienyze (1.5k), Amber (embedded PE), Themida (LDR) | 6/75 (+2 partial, +4 failed) | 300-1,500 lines each | only if a target sample needs it |
| **D — research** | Yoda-Crypter (3/75, same 4.3k Yoda class), Yoda-Protector (0/3), UPX LZMA/NRV accelerators (2k, budget-only) | 3/75 (+3 failed) | weeks | **defer** — 3 samples for a 4.3k-line class; the oracle wins only the Crypter half |

Recommended sequencing (each step is a shippable commit series with its own
scoreboard row): **Phase 0 → 1 → 1b → 2 → tier A → tier B → 4 (SFX fixtures) →
5 (peel) → 6 (hardening)**, and re-run S500 at the end of Phase 1b, Phase 2, and
after each tier. Tier C/D only on demand.

Deliberate non-goals for the first delivery: byte-identical dumps, the vtrace
snapshot format, pegasus's 40+ env gates (keep three: `TAOTE_UNPACK_DEBUG`,
`TAOTE_UNPACK_FAMILY`, `TAOTE_UNPACK_NO_GRACE`), and any family port whose oracle
grade is 0.

---

## 7. What phase 0 must decide before code lands

1. **Rebuilder: hand-rolled vs LIEF Builder** (§3 Phase 1.6) — recommend
   hand-rolled for byte control; the decision belongs in the phase 1 PR
   description with the first three artifacts compared both ways.
2. **Where the code lives**: `qiling/unpack/` (detector, oep, iat, rebuild,
   families) + `tools/taote_unpack.cpp` (CLI) + `tests/Unpack_Compat_Test.cpp`,
   mirroring `qiling/os/windows/dlls/*` family layout. CMake: one new library
   target `libqiling_unpack` linked by the tool and the tests, so the core
   library stays unpack-free for the existing 574-test suite.
3. **Section source**: expose `QlLoaderPE::sections()` from the LIEF parse
   (cheap, exact) vs re-parse the in-memory header (matches the dump the
   rebuild will see). Recommend *both*: LIEF at load for the watch set, in-memory
   parse at rebuild (pegasus reads the dump's own header, `unpacker.cpp:11695-11770`).
4. **Scoreboard file**: `tests/unpack_scoreboard.json` (per-family grades + the
   env + oracle numbers) so every phase's number is a diff, not a claim.

### 0.17h Round 16: OEP pick residuals — the Pass-B "first frame" half-fix

Re-ran the by-first-failing-criterion classification on the round-14/15 corpus
(2678 samples, 85s):

| class | count |
|---|---|
| all three | 1524 |
| invalid PE | 110 |
| **OEP wrong** | **892** |
| imports wrong (OEP ok) | 85 |

Of the 892, 165 are OEP-only (imports already correct). Splitting that by
`code_sim` separates *pick* failures from *decode* failures:

| class | n | families |
|---|---|---|
| **pick** (code_sim >= 0.80: payload decoded, entry address wrong) | **87** | MPRESS 34, WinUpack 23, PECompact 20, JDPack 3, Molebox 3, NSPack 2, BeRo 1, Neolite 1 |
| decode (code_sim < 0.80) | 78 | Neolite 78 |

81 of the 87 pick failures land in the *same section* as the true entry
(`oep_near`), median delta 47KB. So this is a picker problem, not a decode one,
and it is tractable.

**Root cause found (two defects in the shared decode-only ladder, Pass B):**

1. `decode_only_packer.cpp` Pass B documents "the first frame in address order,
   not the last" in a comment — and then assigned `hit_va = fva` on every
   iteration, i.e. the **last** frame. A half-implemented fix.
2. Pass B was gated `if (!mpress && ...)`, so MPRESS never used it at all and
   fell through to the Borland `6a ?? 68 <image-addr> e8` pre-check, which
   matches a *helper* (`push 3; push 0x423605; call …; ret`) rather than the
   CRT startup entry.

Ground truth confirms it: `mpress_ldmdump`'s claimed 0x402279 is
`6a 03 68 05 36 42 00 e8…c3` (a CRT helper), while the true 0x403024 is
`55 8b ec 6a ff 68 30 71 40 00 68 64 4d 40 00 64 a1…` — the canonical MSVC
`mainCRTStartup` SEH frame, which Pass B holds and skips.

Corpus evidence for the "first frame" rule over the 87 pick failures: 19 have
their true EP at the `55 8b ec 6a ff 68` frame shape, and **14 of those 19 are
the FIRST frame** (all six PsTools-family MPRESS/WinUpack images that share a
3-frame body are first-frame, 6/6). `hits <= 8` still excludes the frame-dense
images where first-frame is wrong (HashCalc 84, disk2vhd 194).

Fix applied: `hit_va = frames.front()`; drop the wholesale `!mpress` gate (the
`hits <= 8` bound keeps the widening safe).

**Measured (full corpus, 2678 samples, 85s budget, pin 4):**

| | r14 baseline | first-frame + mpress gate |
|---|---|---|
| all three | 1524 (56.9%) | **1532 (57.2%)** |
| OEP exact | 1609 | **1619** |

11 gains / 3 losses:
- **+11**: mpress_{Cacheset, adrestore, ctrl2cap, efsdump, ldmdump, pagedfrg} and
  winupack_{Cacheset, ctrl2cap, efsdump, ldmdump, pagedfrg} — all 3-frame
  PsTools-family bodies where the true EP is frame 0.
- **-3**: `jdpack_7z`, `mpress_AccessEnum`, `mpress_DarkNamer` — the true EP is
  the *last* frame there.

**Second fix — the CRT-startup frame discriminator.** The three-push shape
`55 8b ec 6a ff 68 <handler> 68 <scope> 64 a1` (the real `mainCRTStartup`)
is distinguishable from a plain function carrying an SEH try-block, which has
only `55 8b ec 6a ff 68 <handler> 64 a1`. `mpress_DarkNamer`'s four frames are
three two-push functions plus exactly one three-push startup frame (0x40a71e,
the true entry). Preferring the unique startup frame recovered it.

`jdpack_7z` and `mpress_AccessEnum` have *several* frames that all carry the
three-push shape with an identical scope immediate, so no local discriminator
separates the entry from its look-alikes; they stay wrong. That is the honest
cost of the change (net expected +9), recorded rather than papered over with a
rule fitted to two samples.

**Final measured result (both budgets):**

| | r14 baseline | round 16 | delta |
|---|---|---|---|
| corpus all three | 1524 (56.9%) | **1533 (57.2%)** | **+9** |
| corpus OEP exact | 1609 (64.3%) | **1623 (64.9%)** | **+14** |
| corpus imports | 1706 (66.4%) | 1706 (66.4%) | — |
| fair set all three (300s) | 63/86 | 63/86 | 0 / 0 |

11 all-three gains, 2 losses (`jdpack_7z`, `mpress_AccessEnum`). OEP-exact gained
21 and lost 7 — the 5 extra losses are PEtite/RLPack samples whose OEP was exact
by luck while their imports are decode-blocked, so all-three is unchanged there.
Suite 593/593 green.

Remaining OEP-pick worklist, from the same classification (the 68 pick failures
Pass B cannot reach): the dominant class is now **wrong CFG thunk** — true entry
`e8 .. e9` (or `6a xx 68 .. e8`) but Pass C returns a different thunk (10 MPRESS
+ 3 WinUpack + BeRo + JDPack). The Borland pre-check and the Pass-C selector are
the next lever there.

### 0.17i Round 16b: port the reference's MPRESS pass-ladder count heuristics

The remaining 68 pick failures are dominated by Pass C returning a look-alike
thunk. The reference has two extra passes that run **before** its Pass C, inside
`oep_pass_ladder_` and gated `packer_name_ == "MPRESS"` (unpacker.cpp:7336-7405):

1. **unique nop-jmp** `e8 <rel32> e9 00000000` — LoadOrd's OEP (call
   `__security_init_cookie`, then a jmp whose rel32 is zero; only the real entry
   has it).
2. **Borland + SEH LAST count table** — `b_count > s_count → Borland LAST`,
   `s_count >= b_count → SEH LAST`, with the reference's measured table
   (OpenedFilesView 4/2, DarkNamer 4/4, Hash 0/1, shexview 3/0).

Two gates had to be *measured* rather than copied, because taote's pass order
differs from the reference's:

- **Placement after Pass B.** Applied any earlier it regresses the round-16
  Pass-B gain: the six PsTools 3-frame bodies have `b_count 0 / s_count 3`, so
  the rule returns the SEH LAST (0x406c29) where Pass B's first-frame vote
  returns the true 0x4024a2.
- **Cluster-size bound `b_count <= 8`.** A first attempt gated on "Pass C was
  ambiguous (`c_hits != 1`)" and lost 8 samples (winupack_Bginfo, bero_ADInsight,
  bero_ComIntRep, bero_procexp, mpress_ADInsight, mpress_ComIntRep, nspack_cmd,
  mpress_LoadOrd) — `c_hits == 1` does not separate the classes. What does
  separate them is the size of the CRT-init cluster: **every sample the rule gets
  right has `b_count == 4`** (the standard 4-entry cluster, matching the
  reference's "OpenedFilesView: 4 Borland"), while every sample it gets wrong has
  20-174 hits, i.e. the pattern is matching ordinary code. The bound is the same
  shape as Pass B's `hits <= 8`.

Spot-check after the fix: all twelve probes exact, including every former
regression (winupack_Bginfo 0x5b5d42, bero_ADInsight 0x434dac, nspack_cmd,
mpress_ComIntRep, bero_procexp, mpress_LoadOrd) *and* every round-16 winner
(mpress_ldmdump 0x403024, mpress_Cacheset 0x4024a2).

**Measured (full corpus, 2678 samples, 85s, pin 4) — MPRESS-only gate:**

| | r16 | r16b |
|---|---|---|
| all three | 1533 (57.2%) | **1540 (57.5%)** |
| OEP exact | 1623 (64.9%) | **1630 (65.2%)** |

+7 all-three, **0 losses** — all seven are the MPRESS CRT-cluster bodies
(ESEDatabaseView, EventLogChannelsView, FolderTimeUpdate, FullEventLogView,
InstalledPackagesView, LastActivityView, OpenedFilesView). Suite 593/593 green.

**WinUpack widening.** The reference gates this block MPRESS-only, but WinUpack
shares the same decoder generation in taote (the payloads are the same bodies
with the same counts). Offline check over the 19 remaining WinUpack pick
failures: the rule picks **9 correctly and declines the other 10** (every one of
those has `b_count > 8`), i.e. no false positives — so the gate widens to
`mpress || WinUpack`. Measured next.

**Measured (full corpus, 2678, 85s, pin 4) — with the WinUpack widening:**

| | r16 baseline | round 16b | delta |
|---|---|---|---|
| all three | 1533 (57.2%) | **1550 (57.9%)** | **+17** |
| OEP exact | 1623 (64.9%) | **1641 (65.6%)** | **+18** |
| imports | 1706 (66.4%) | 1706 (66.4%) | — |
| fair set (300s) | 63/86 | 63/86 | 0 / 0 |

17 all-three gains, **0 losses**: 7 MPRESS + 10 WinUpack, all of them CRT-cluster
bodies (`*_ESEDatabaseView`, `*_EventLogChannelsView`, `*_FolderTimeUpdate`,
`*_FullEventLogView`, `*_InstalledPackagesView`, `*_LastActivityView`,
`*_OpenedFilesView`, plus winupack_{DriverView, RegDllView, shmnview}).
Suite 593/593 green.

Remaining OEP-pick worklist (the pick failures this cannot reach): the
`b_count > 8` bodies where the pattern is matching ordinary code rather than a
CRT cluster (mpress_PsExec/PsGetsid/PsInfo/portmon/Dbgview, winupack_PsInfo,
HashCalc with s_count 84, disk2vhd 143/138) — those need a different
discriminator (the reference resolves them with its candidate ledger +
region-class scoring, not pattern counts), and the 78 Neolite decode failures
which are not pick problems at all.
