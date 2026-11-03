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

### 0.17j Round 17: gap attribution, and the PECompact epfix preemption

Re-ran the by-first-failing-criterion classification on the r19 build, then
attributed the whole gap family-by-family against the stored oracle run
(`/home/jim/runs/oracle/results.json`) instead of guessing:

| family | n | ref all-3 | taote all-3 | gap |
|---|---|---|---|---|
| Alienyze | 126 | 116 | 0 | **-116** |
| Amber | 152 | 111 | 0 | **-111** |
| Neolite | 93 | 92 | 1 | **-91** |
| TELock | 116 | 59 | 0 | **-59** |
| PEtite | 73 | 56 | 23 | -33 |
| MPRESS | 106 | 103 | 80 | -23 |
| PECompact | 97 | 94 | 74 | -20 |
| FSG | 97 | 90 | 75 | -15 |
| NSPack | 97 | 97 | 86 | -11 |
| WinUpack | 97 | 83 | 74 | -9 |
| RLPack | 104 | 7 | 0 | -7 |

Total -446. **The top four are 377 of it**, and they are all decode-blocked
(Alienyze/Amber/Neolite `code_sim` 0.03-0.11, TELock empty chain). Themida (122)
and Yoda-Protector (101) are **not** in the list because the reference fails them
too — so the 6 "0% OEP" families in a naive count are really 4 in-scope plus 2
out-of-scope.

Only **61 pick failures remain** (round 16 took 26 of the original 87), so the
OEP *picker* well is nearly dry; the remaining OEP gap is decode work.

**Amber/Alienyze are not pick problems at all.** Instrumenting
amber_nbtstat shows the stub runs, claims `.bss`/`.data`, then ends at a stub-DLL
cell after 13 writes — `stages=0`, no hop, no heap map. The payload is XOR'd in
the dump (Alienyze decrypts on demand via guard pages the emulation never trips),
and the reference's recovery is a 1544-line module (`alienyze.cpp`: key derivation
by x86-likelihood scoring over candidate XOR keys, body relocation, and a full
import-table rebuild from the `.alien` store). That is a module port, not a rule.

**PECompact epfix preemption (fixed here).** All 21 PECompact OEP failures claim
exactly the header EP, 20 of them with imports already correct — one early return
was the whole PECompact OEP gap. The round-11 mini-stub epfix fires on the hop
`packed EP + 0x16`, but for the PsTools-family builds the packed EP is only the
mini-stub and the real entry is tens of KB later (pecompact_RegDllView: hop
0x401016, true 0x40c80c).

Two wider fixes were measured and **rejected**:
- "prefer the whole ladder over the epfix" regresses pecompact_PEViewer (Pass-C
  look-alike 0x4f99f0 beat the correct packed EP 0x401504).
- "extend the Borland+SEH cluster rule to PECompact" would regress 9 samples that
  currently pass (AccessEnum, Cacheset, Diskmon, adrestore, ctrl2cap, dfrgui,
  efsdump, ftp, pagedfrg), unlike MPRESS/WinUpack where it was clean.

What is safe is the narrow fact: when the ladder's answer is itself a
`55 8b ec 6a ff 68` startup frame (Pass B's evidence, not Pass C's) it outranks
the header EP. Measured on the probe: pecompact_{DarkNamer, Hash, rm, HashCalc}
flip to exact and no currently-passing sample changes.

**Measured (full corpus, 2678, 85s, pin 4):**

| | r19 | round 17 |
|---|---|---|
| all three | 1550 (57.9%) | **1553 (58.0%)** |
| OEP exact | 1641 (65.6%) | **1644 (65.7%)** |
| imports | 1706 | 1706 |

+3 all-three (pecompact_{DarkNamer, Hash, rm}), **0 losses**; fair set 63/86
unchanged (0/0). Suite 593/593 green. pecompact_HashCalc's OEP also became exact
but its imports are short, so it does not reach all-three.

Next lever is now decode work, in gap order: Alienyze (-116), Amber (-111),
Neolite (-91), TELock (-59) = 377 of the -446.

### 0.17k Round 18: the PECompact placeholder header EP

Follow-up to §0.17j. The 17 remaining PECompact pick failures all claimed the
header EP, and the earlier "startup frame" gate did not reach them because their
true entry is the Borland `6a 70 68 <handler> e8` cluster, not an SEH frame.

The discriminator is the header itself. When the PE header's
`AddressOfEntryPoint` equals the **first section's VirtualAddress**, the packer
did not preserve the original entry — the field is a placeholder (0x401000 for
every PsTools-family build) and the epfix is trusting the stub's own EP.
Measured over all 96 valid PECompact samples:

| header EP | result |
|---|---|
| preserved (≠ first section start) | true EP == header EP in **67 / 67** |
| == first section start (placeholder) | true EP != header EP in **29 / 29** |

A perfect separation, so the epfix defers to the entry-shaped CRT cluster in the
placeholder case only. This is also why the two wider fixes of §0.17j regressed:
those samples are in the *preserved* group where the header EP is genuinely the
entry.

Probe after the change: 5 gains (RegDllView 0x40c80c, BlueScreenView 0x40e78e,
shexview 0x40ef60, sysexp 0x40acb2, ESEDatabaseView 0x40feea) and 7 preserved
(Cacheset, AccessEnum, efsdump, pagedfrg, PEViewer, DarkNamer, Hash).

### 0.18 Measurement infrastructure reset (round 18)

`/home/jim/runs` was deleted externally mid-round-18 (the r21 corpus run and all
historical reports were lost, along with the stored oracle results). Rebuilt:

- **run root**: `/home/jim/runs` (recorded here as the canonical location).
- **corpus manifest**: regenerated with the reference harness's own generator,
  `~/source/jim/pegasus/tools/unpack_eval/build_manifest.py --cap 100000`, which
  reproduces the graded set exactly: **2678 runs / 323 skipped**, same
  packed→not-packed mapping. Manifest at `/home/jim/runs/corpus.json`.
- **reference binary**: `~/source/jim/pegasus/build/cli/pegasus-cli` survived.
- **second measurement set**: the original 86-sample fair list is unrecoverable,
  so the surviving stratified set (`/tmp/m200o/manifest.json`, 25 families × 8 =
  200 samples, with its own `oracle_results.json`) takes its place as the
  second, reference-comparable measurement. Recorded as a deviation.

**Measured (full corpus, 2678, 85s, pin 4; baseline = d586c2c re-run at 1553 to
re-establish the reference point after the run-root loss):**

| | baseline | round 18 |
|---|---|---|
| all three | 1553 (58.0%) | **1567 (58.5%)** |
| OEP exact | 1644 (65.7%) | **1658 (66.3%)** |
| imports | 1706 (66.4%) | 1706 (66.4%) |
| valid PE | 2568 (95.9%) | 2568 (95.9%) |

**+14 all-three, 0 losses** — exactly the 14 predicted PECompact samples
(BlueScreenView, DriverView, ESEDatabaseView, EventLogChannelsView, FileTypesMan,
FolderTimeUpdate, FullEventLogView, InstalledPackagesView, LastActivityView,
OpenedFilesView, RegDllView, shexview, shmnview, sysexp).

**Second set (200-sample stratified, 300s):** 120 -> **121** all-three (+1: the
one PECompact sample in that slice), **0 losses**. Reference on the same set
(verify.py rubric): 154/200 UNPACKED_VERIFIED, 158 c_ep_match — a different
rubric, so not directly comparable to taote's unpack_report numbers.

Suite 593/593 green.

### 0.17l Round 19: MPRESS static fix-stub OEP (the reference's F43h-static)

The remaining pick failures are 44, and their true EP is in **neither** the
Borland `6a ?? 68 <imm> e8` set nor the SEH `55 8b ec 6a ff 68` set for 35 of
them — so no count/shape rule can reach them. Instrumenting mpress_PsExec shows
why: the hop ledger holds only stub-internal junk (candidates at 0x47d1d0+,
true entry 0x409de6).

The reference does not use shape evidence for these at all. It has a dedicated
**F43h-static** reader (`mpress_static_oep_`, unpacker.cpp:10876, retdec-derived)
that reads the original EP straight out of the MPRESS fix-imports stub's data
tables, and it runs it **FIRST** for MPRESS — explicitly because it supersedes
both the MSVC-prologue scan ("which misfires on hand-written assembly startups")
and the late API-return hop latch.

Ported faithfully: `.MPRESS1` section lookup, the stub signature at packed EP + 8
→ `kStubTbl` fix-stub offset, the fix-stub data at `.MPRESS1 + fs_sec` in the
dump, `kFixTbl` row selected by byte 7, then
`oep = fs_va + ft[1] + rd32(dump, fs_dump + ft[2])`. It needs the PACKED file as
well as the dump, so `PackerContext` gained a `packed_path` member (the
reference's `packed_path_`).

Probe: 8/8 exact, including mpress_AccessEnum 0x407a98 (previously recorded as
having "no local discriminator" and regressed in round 16) and
mpress_PEViewer 0x401504.

**Measured (full corpus, 2678, 85s, pin 4):**

| | r18 | round 19 |
|---|---|---|
| all three | 1567 (58.5%) | **1587 (59.3%)** |
| OEP exact | 1658 (66.3%) | **1679 (67.1%)** |
| imports | 1706 | 1705 |
| valid PE | 2568 | 2568 |

**21 OEP gains**, all MPRESS (AccessEnum, Dbgview, Diskmon, Everything,
FastHash_kr, HashCalc, Hasher, PEViewer, PsExec, PsGetsid, PsInfo, ShareEnum,
calc, cmd, disk2vhd, md5summer, mtinst, portmon, pskill, psshutdown, pssuspend).
all-three +20.

One apparent loss, `nspack_procexp`, is a **budget-bound flake, not a
regression**: its OEP stayed exact and its imports collapsed only because the run
hit the 85s cap (`dur=85`, recall 1.0 -> 0.044); the change is MPRESS-gated so it
cannot touch NSPack, and two re-runs give `oep=0x49ba18 imports=1501` (recall 1.0)
each. The flake is counted in the committed numbers, not explained away.

**Second set (200-sample stratified, 300s):** 121 -> **122** all-three (+1:
mpress_AccessEnum), **0 losses**. Suite 593/593 green.

### 0.17m Round 20: TLS callbacks (the Windows loader semantics Amber needs)

Diagnosing Amber: `amber_nbtstat` ends in **0.05s** after 9 CRT-init API
dispatches, with the payload never decoded (ladder finds 0 hits in every
section; the encrypted payload sits in a randomized `.0sMJTto` section).

Running the reference on the same sample shows the mechanism immediately:

```
* exec: tls_callback_0
[api-dispatch] handling: kernel32.InitializeCriticalSection
```

**The reference enters the TLS callback, not the entry point.** Amber's unpacking
stub is an `IMAGE_DIRECTORY_ENTRY_TLS` callback, so a port that jumps straight to
`AddressOfEntryPoint` never reaches the decompressor. taote had **no TLS-callback
support at all** (`grep tls_callback qiling/` was empty).

Ported (the reference's `PeFile::get_tls_callbacks`, common.cpp:315, and
`win32.cpp:241`):

1. `QlLoaderPE::load_parsed` parses the main image's TLS directory:
   `DataDirectory[9]` → `IMAGE_TLS_DIRECTORY`, whose `AddressOfCallBacks` sits at
   `3 * ptr_size`, then walks the null-terminated pointer array (cap 100) and
   stores it in `tls_callbacks_` (read from the *mapped* image, as upstream does).
2. `QlOsWindows::run()` drives each callback **before** the entry point, as a
   DllMain-shaped call `(image_base, DLL_PROCESS_ATTACH=1, 0)` through the
   guest's own calling convention, returning to the exit point — the same shape
   upstream builds as a `Run` with `type = "tls_callback_<i>"`. A callback that
   faults is the guest's problem; the reference still proceeds to the entry.

Measured so far: the callbacks are found and entered
(`[rundbg] tls_callback_0 at 0x4018f0`, `tls_callback_1 at 0x4018a0`). Amber
still does not decompress — it dispatches only CRT init and returns, so the
Amber *loader body* itself is still not executing its decompressor (the reference
also gives Amber a 4x timeout floor, min 360s, for its rc4/aPLib loop, which the
120s harness wall cap makes irrelevant here — this sample finishes in 0.05s, so
it is not a time bound). That is the next thread.

**Measured: TLS callbacks are exactly NEUTRAL.**

| set | before | after | delta |
|---|---|---|---|
| corpus (2678, 85s) | 1587 (59.3%) | 1587 (59.3%) | **0 gains / 0 losses** |
| 200-set (300s) | 122 | 122 | **0 / 0** |

Every one of the 2678 samples produced an identical result. Kept anyway, and
labelled as such: this is missing **Windows loader semantics** (the loader runs
TLS callbacks before the entry point), the reference relies on it explicitly for
Amber and EnigmaVB, and it is now a verified-zero-risk prerequisite rather than a
guess. It converts nothing on its own because the Amber loader body still does
not reach its decompressor — see below.

**Amber's remaining blocker (evidence, not a guess).** The TLS directory parses
correctly and both callbacks are genuine:

```
AddressOfCallBacks = 0x407020 (.CRT) -> cb[0]=0x4018f0, cb[1]=0x4018a0, 0
0x4018f0: 56 53 83 ec 14 83 3d 14 30 40 00 02   push esi; push ebx; sub esp,0x14;
                                                cmp dword [0x403014], 2
0x4018a0: 83 ec 1c 8b 44 24 24 83 f8 03 74 14   sub esp,0x1c; mov eax,[esp+0x24];
                                                cmp eax, 3; je ...
```

Both are MSVC TLS-dispatcher shapes. taote enters them (rundbg confirms) but the
guest then runs only CRT init (9 dispatches: GetSystemTimeAsFileTime,
GetCurrentProcessId, GetCurrentThreadId, GetTickCount, QueryPerformanceCounter,
GetStartupInfoA, _initterm x2, SetUnhandledExceptionFilter, __p__acmdln) and
returns — **no VirtualAlloc/HeapAlloc at all**, finishing in 0.05s, so this is
not a time bound even though the reference gives Amber a 4x timeout floor for its
rc4/aPLib loop. The reference's artifacts for the same sample show what should
happen: `stages=2, reason=embedded_pe, base=0x1000000, oep=0x1002a65`, plus
`_dyn1_0x13000_dump.bin` (73728 B) and `_payload_0x25000_pe.bin` (15360 B) — i.e.
the payload does land in a dynamic region and is adopted as an embedded PE. So
the next thread is why the Amber loader body takes its skip branch in taote.

### 0.17n Round 21: the CRT-loader fidelity fixes Amber exposed

Chasing why Amber never reaches its decompressor turned up two Windows-API
fidelity gaps that are not Amber-specific. Both are uncommitted pending
measurement.

**1. `__p__acmdln` threw instead of answering.** With TLS callbacks in place the
guest now runs Amber's full CRT startup and then dies at
`_acmdln is not in the msvcrt.dll import address table` (msvcrt.cpp:259). A
packed image whose CRT calls `__p__acmdln` need not import the `_acmdln` DATA
symbol, and the reference never requires it: `Msvcrt::__p__acmdln`
(msvcrt.cpp:1448) unconditionally maps a `ptr_sz + 8` "api.msvcrt._acmdln" block
and returns its address. Ported: keep the IAT answer when the image really
exports/imports `_acmdln` (more accurate than upstream) and fall back to a fresh
zeroed cell otherwise. `__p__wcmdln` deliberately keeps its throw — the verbatim
ladder, and `WinApiMsvcrt.PAcmdlnRidesMsvcrtDllIat` pins it.

**2. `VirtualAlloc` returned an unaligned heap chunk.** It was
`heap().alloc(dwSize)`, and Amber's loader received `0x50009ea`. Windows'
contract is a PAGE-ALIGNED, independently committed region, and a reflective
loader computes `base + section_rva` from the returned pointer — so it ran off
the end of the mapping and died with `UC_ERR_READ_UNMAPPED`. The reference
(kernel32.cpp:1854) page-aligns the hint, finds a valid range and `mem_map`s a
dedicated "api.VirtualAlloc" region. Ported with two deliberate keepings:
the mapping stays rwx (every corpus loader writes then executes; W^X would break
them), and `VirtualQuery` gained a fallback that reports an `api.VirtualAlloc`
region by its mapped extent, because it previously only walked the heap chunk
table and would go blind to these addresses
(`WinApiMemoryapi.VirtualAllocFreeProtectQueryVerbatim` pins BaseAddress ==
AllocationBase).

**Measured (full corpus, 2678, 85s, pin 4) — the VirtualAlloc half was REVERTED.**

| | r20 | round 21 (both fixes) | round 22 (`__p__acmdln` only) |
|---|---|---|---|
| corpus all-three | 1587 | 1502 (**-85**) | **1588 (+1)** |
| corpus OEP exact | 1679 | 1679 (+0) | 1678 (-1) |
| corpus imports | 1705 | 1619 (-86) | 1706 (+1) |
| 200-set (300s) | 122 | - | 122 (0/0) |

Page-aligned `VirtualAlloc` alone cost 85 all-three, **every one of them
PECompact**, and it cost them through the *import* criterion only (OEP stayed
exact): `pecompact_ADExplorer` import recall 1.0 -> 0.057 with 787 -> 488 output
imports, `pecompact_BlueScreenView` 1.0 -> 0.292 with 470 -> 309. The import
salvage finds the loader's rebuilt descriptor/IAT tables through the **heap chunk
table**, so moving those allocations into a separate mapped region makes them
invisible to it. Reverted (memoryapi.cpp now carries the measurement in a
comment): the unaligned base is a genuine Windows-contract gap, but converting it
is a *salvage* change, not a mapping change, and it must not land before the
salvage learns to see non-heap regions.

`__p__acmdln` alone is **+1 corpus all-three / +1 imports with 0 all-three
losses** (1587 -> 1588), and the 200-sample set is neutral (122 -> 122, 0/0). The
one gain is `nspack_procexp.exe`, which round 19 already identified as a
budget-bound flake (it hit dur=85 then and recovers on a re-run), so the change
should be read as **neutral-but-correct**, the shape the round-20 TLS callbacks
had. The single OEP-exact loss is `mpress_geek.exe`, which was `oep_exact None`
(ungraded) in *both* reports with code_sim 0.8919 -> 0.9025 and dur 86 (over the
budget cap) in both — a grading-boundary flake, not a behaviour change.

Measured effect on Amber: the guest now executes *inside* its own decoded region
(fault pc moved from a stub cell to 0x1d193, inside the 0xc000-0x1e000
VirtualAlloc buffer) and dispatches its real loader calls
(LoadLibraryA, GetProcAddress, GetModuleHandleA, VirtualAlloc, memcpy) instead of
9 CRT-init calls. It is still blocked, one layer further out:

```
[rundbg] LoadLibraryA(USER32.dll) -> 0x0
[rundbg] GetProcAddress(user32.dll!VirtualAlloc) -> 0
[rundbg] emu error 'Invalid memory read (UC_ERR_READ_UNMAPPED)' pc=0x1d193
```

`user32.dll` is not in the staged stub rootfs (tools/taote_unpack.cpp stages
`plan.imports` plus the five key DLLs ntdll/kernelbase/kernel32/ucrtbase/mscoree),
so the loader's `LoadLibraryA` returns NULL and it dereferences it — a
rootfs-composition question, not an emulation bug. Debug aids added: a
TAOTE_RUNDBG `[rundbg] emu error '<text>' pc=...` line in the run loop (unicorn
otherwise only reports the error class) and a TAOTE_MEMDBG mem-invalid hook in
taote_unpack that names the faulting address (this is what identified the NULL
read).

### 0.17o Round 22: the rootfs DLL set and a page-aligned-but-still-heap VirtualAlloc

Two more layers of the Amber blocker, both generic.

**Measured: the rootfs widening alone is NOT kept.** With the wider key-DLL set
plus the VirtualAlloc change the corpus went all-three 1588 -> 1584 (1 gain /
5 losses) and imports 1706 -> 1702, OEP unchanged. Four of the five losses are
budget caps, not logic errors: `pecompact_PEViewer` import recall 1.0 -> 0.035 at
dur 58 -> 85, `pecompact_cpuz_x32` 1.0 -> 0.046 at 48 -> 85,
`pecompact_ComIntRep` 1.0 -> 0.047 at 79 -> 85, `mpress_ComIntRep` 1.0 -> 0.905 at
79 -> 85. A sample whose `LoadLibraryA` used to fail now loads an export-less
stub and keeps working, so borderline runs cross the 85s budget and their import
salvage collapses; the fifth (`jdpack_find` vs the gain `jdpack_7za`, both at
dur 0) is the known flaky picker pair trading places. So the widening is
reverted: it converts nothing (Amber still fails) and a broader rootfs needs a
budget story of its own. What stayed is the VirtualAlloc contract fix, because it
is independent of the rootfs and locally keeps the PECompact salvage intact
(`pecompact_PEViewer` 1596 imports, `pecompact_ADExplorer` 790).

**1. The staged stub rootfs was too thin (reverted, see above).** With the TLS + `__p__acmdln` fixes in,
Amber's loader ran and died on `LoadLibraryA(USER32.dll) -> 0x0`: the tool stages
only `plan.imports` plus five key DLLs (ntdll/kernelbase/kernel32/ucrtbase/
mscoree), and a *dynamic* loader resolves names the packed image never imported
statically. The key list now also carries the system DLLs a loader reaches for
(user32, advapi32, gdi32, shell32, ole32, oleaut32, comctl32, shlwapi, version,
psapi, ws2_32, wininet, crypt32, iphlpapi, userenv); they export nothing, so
`GetProcAddress` over them answers 0 exactly as a real DLL missing an export
would, and a per-sample export-bearing stub always wins (`if (!exists(...))`).

**2. The `VirtualAlloc` page-alignment: built, measured twice, NOT kept.**
Round 21 proved a dedicated `api.VirtualAlloc` mapping costs 85 PECompact
all-three because the import salvage reads the heap chunk table. So the heap
grew `alloc_aligned(size, alignment)` instead: it pads with a filler chunk until
the bump pointer is aligned and then appends, so the returned address IS the
chunk address (VirtualQuery keeps reporting BaseAddress == AllocationBase). The
committed extent also rounds UP to the page size, because Windows commits whole
pages: Amber asks for 0x11400 with PAGE_EXECUTE_READWRITE and then enters its
decoded payload at `base + 0x11193`.

Measured with the padding version and the wider rootfs: all-three 1588 -> 1584.
Measured again with the rootfs widening **reverted** (so the alignment alone):
still **1588 -> 1584**, 1 gain / 5 losses — `pecompact_PEViewer`,
`pecompact_cpuz_x32`, `pecompact_ComIntRep` all at dur=85 and
`winupack_Bginfo` at dur=86 with collapsed import recall, plus the known
`jdpack_find`/`jdpack_7za` flake pair trading places. The salvage stays intact
locally (`pecompact_ADExplorer` 790 imports, `pecompact_PEViewer` 1596), so this
is a **budget** cost: the padding and page-rounded commits push borderline
PECompact/WinUpack runs over the 85s harness budget. Reverted, keeping
`QlMemoryHeap::alloc_aligned` in the tree as the tool for the follow-up. Amber now allocates 0x11400 -> 0x5001000 and *executes there*
(pc=0x5012193, inside the region), so it is past the mapping problem; it still
ends with a NULL read, one `GetProcAddress` later:

```
[rundbg] LoadLibraryA(USER32.dll) -> 0x10060000
[rundbg] GetProcAddress(user32.dll!VirtualAlloc) -> 0x0
[rundbg] emu error 'Invalid memory read (UC_ERR_READ_UNMAPPED)' pc=0x5012193
```

That single (user32, VirtualAlloc) probe returning 0 and the guest then reading
address 0 is the next thread: either the loader iterates modules and treats this
first miss as fatal, or taote is misreading the name/module pair. Amber does not
yet convert; user32.dll alone still left it at the same fault.

### 0.17p Round 23: PEB->Ldr insert-at-tail (a forward walk previously saw ONE module)

Amber's loader turned out to be a textbook shellcode API-hashing loader: after the
round-22 fixes it reached this code inside its decoded buffer (dumped at the
fault and disassembled):

```
5011b65: 60            pusha
5011b66: 89 e5         mov  esp, ebp
5011b68: 31 c0         xor  eax, eax
5011b6a: 64 8b 50 30   mov  edx, fs:[eax+0x30]     ; PEB
5011b6e: 8b 52 0c      mov  edx, [edx+0xc]         ; PEB->Ldr
5011b71: 8b 52 14      mov  edx, [edx+0x14]        ; InMemoryOrderModuleList.Flink
5011b74: 8b 72 28      mov  esi, [edx+0x28]        ; BaseDllName.Buffer
5011b77: 0f b7 4a 26   movzx ecx, word [edx+0x26]  ; BaseDllName.MaximumLength
5011b7d: ac            lodsb                       ; <-- faulted, esi == 0
5011b84: f2 0f 38 f0 f8 crc32 edi, al
5011b89: e2 f2         loop 5011b7d
```

Instrumenting the chain at the fault showed why: the InMemoryOrder list held
**exactly one entry** (user32.dll), and the hasher walked it and then stepped into
the list *head*, whose `+0x28` is 0.

Root cause is in `QlLoaderPE::add_ldr_data_table_entry`: for each of the three
order lists it wrote `head.Flink = head.Blink = new` on **every** insert, so a
FORWARD walk from the head always saw only the newest module; the older entries
stayed chained to each other but unreachable from the head. Windows' sentinel
semantics are insert-at-tail:

```
new.Flink = head;  new.Blink = head.Blink;  head.Blink.Flink = new;  head.Blink = new
```

`make_ldr_data` already points every head's Flink and Blink at itself, so the
"previous last" is the head's Flink cell when the list is empty and the single
`write_ptr(prev_last, new_link)` covers both cases.

**Measured (full corpus, 2678, 85s, pin 4): +7 all-three, +8 OEP, +136 imports,
zero losses.**

| | r22 | round 23 |
|---|---|---|
| corpus all-three | 1588 (59.3%) | **1595 (59.6%)** |
| corpus OEP exact | 1678 (67.1%) | **1686 (67.4%)** |
| corpus imports | 1706 (66.4%) | **1842 (71.7%)** |
| valid PE | 2568 | 2568 |
| 200-set (300s) | 122 | 122 (0/0) |

7 gains, 0 losses, every gain Amber: `amber_{DarkNamer, Diskmon, FastHash_kr,
HashCalc, OpenedFilesView, ShareEnum, shexview}`. The headline number is the
IMPORT criterion, +136 samples, because a correct PEB->Ldr list is what most
import-discovery paths walk. The 200-sample set is neutral (0/0) because its
Amber entries were the ones already converting.

This is not an Amber quirk: every loader that resolves APIs by walking
PEB->Ldr (Amber, Alienyze, Neolite) was walking a one-entry list. Measured effect
on amber_nbtstat: imports 122 -> 166, the run goes from 0.11s (dead end) to 0.38s
(the reference is 0.4s / 4.7M insns), it reaches and executes inside its decoded
VirtualAlloc buffer (48 dyn-exec events in region 0x5001000) - but it still does
not convert (no section hop, OEP guessed).

Two host-safety defects in my own debug scaffolding were introduced and removed
here, both found by running the tool rather than by inspection: a PEB-walk dump
built on `mem().read` threw from inside a unicorn callback (`hook_mem_invalid`)
and crash-landed, and a `static HookRet` outlived the Qiling so its destructor
unregistered into freed memory. The memdbg probe is now a plain print that never
touches guest memory. Lesson recorded: diagnostic hooks must not throw or
outlive the engine.

### 0.17q Round 24: the embedded-PE adoption actually adopts (Amber +76)

Amber's payload is not decoded in place: the loader assembles a PE32 image in a
heap buffer and runs it, so there is no section hop to find and the recovery has
to *adopt* the embedded image (the reference's `try_embedded_pe`,
unpacker.cpp:10540, reason `embedded_pe`). taote had that seam but it never
matched. Three defects, each found by running the sample, not by reading code:

1. **The scan stepped only 0x1000.** The buffer `VirtualAlloc` hands back is a
   heap chunk, not a page boundary, so the payload's `MZ` sits at an arbitrary
   offset - `0x9ea` past the map base for amber_nbtstat. The scanner now also
   searches for `MZ` at **any** offset (bounded to 64 hits per region), with the
   PE32 + Characteristics + section-layout gates doing the filtering.
2. **A payload always straddled several map entries.** The heap is mapped in page
   chunks, so `soi <= hi - cand_base` could never hold for a heap-resident image.
   A contiguous run of maps is now treated as one region.
3. **`Characteristics` was read from the wrong field.** `head[opt + 0x46]` is the
   high half of `NumberOfRvaAndSizes`, not the COFF header's Characteristics
   (`lfanew + 22`, which is what the reference reads at `coff + 18`). The
   EXECUTABLE_IMAGE gate was therefore testing garbage and rejected the real
   payload: amber_nbtstat's image at 0x5011dea reads 0x8140 at `opt+0x46` (no
   0x0002) while its COFF Characteristics is 0x0102.

With those fixed the payload at 0x5011dea is adopted, whose EP RVA is 0x2a65 -
exactly the reference's `oep 0x1002a65` at `base 0x1000000`. Two reporting bugs
surfaced at that point and are fixed too: `res.base` had been captured from the
stub *before* the adoption moved `base_` (the report claimed base 0x400000 with an
EP of 0x501484f), and the static ladder then overwrote the exact EP the adoption
had proved, so an adopted EP now suppresses the ladder.

**Measured (full corpus, 2678, 85s, pin 4):**

| | round 23 | round 24 |
|---|---|---|
| corpus all-three | 1595 (59.6%) | **1671 (62.4%)** |
| corpus OEP exact | 1686 (67.4%) | **1762 (70.5%)** |
| corpus imports | 1842 (71.7%) | 1843 (71.8%) |
| valid PE | 2568 | 2568 |
| 200-set (300s) | 122 | **126 (+4)** |

**76 gains, 0 losses**, every gain Amber; the 200-sample set agrees (+4, 0
losses). The OEP criterion moved +76 while imports held - exactly the shape an
OEP-only fix should have.

### 0.17r Round 25: Alienyze single-byte XOR recovery (OEP +17)

Alienyze was 0/126 on every criterion with `dur=0`: its stub only decrypts on
demand through guard pages the emulation never trips, so the dump still holds the
XOR'd body and the stub exits immediately. Ported the static recovery from the
reference's `src/unpacker/alienyze.cpp` (the one dedicated family module) as a new
`Packer::transform_image` seam - a family that decrypts the body in place, called
before the OEP pick and the adoption:

1. `score_window` / `recover_key` - x86-code likelihood over 14 windows spread
   from the first section VA for all 256 keys (+8 per `55 8b|89 ec|e5` prologue,
   +4 per `e8/e9` with an in-image 4-aligned target, +5 per `ff 15/25` or
   `8b|8d modrm==05` absolute reference into the image).
2. `recover_key_store` - the known-plaintext fallback: every name in the `.alien`
   store ends in `.dll`, so `'.','d','l','l' ^ k` must appear twice or more.
3. XOR `mem[first_sec_va..)` with the key.
4. Restore the original IMAGE BODY, stashed behind the `.alien` import store at
   `.alien+0x7e0` and XOR'd with the same key, over the hollow (`rsize == 0`)
   sections' RVAs - gated on the x86-code score (>= 20) and `n > 0x1000` so a
   layout drift skips the copy instead of corrupting the image.

Measured keys on probes: alienyze_7z 0x6a, ADExplorer 0x72, Cacheset 0x0a (the
last one is the sample the reference documents as a code-score failure: body copy
skipped at score 0, which is the intended degradation).

**Measured (full corpus, 2678, 85s, pin 4):**

| | round 24 | round 25 |
|---|---|---|
| corpus all-three | 1671 (62.4%) | 1670 (62.4%) |
| corpus OEP exact | 1762 (70.5%) | **1779 (71.1%)** |
| corpus imports | 1843 (71.8%) | 1846 (71.9%) |
| 200-set (300s) | 126 | 126 (0/0) |

**+17 OEP, +3 imports, and all-three -1** - the single loss is
`mpress_ComIntRep.exe`, the known budget-cap flake (it measured dur=85 and
recall 0.905; two clean re-runs give oep=0x42800a with 850 imports, recall 1.0).
So this is a genuine OEP advance that does not convert yet: imports are already
1.000 on alienyze_{Hasher, KillPot, md5summer} and 0.99 on HDDScan, so those are
now PICK failures, but their `code_sim` is ~0.00 (0.0015 / 0.0375 / 0.0019), i.e.
the restored body does not match the original - the per-sample body layout is
still wrong there. 17 of 126 samples now land exactly, up from 0.

### 0.17s Round 26: Alienyze body-offset scan (measured, rejected) + refreshed classification

**Tried and NOT kept: discover the `.alien` body offset by scoring.** Round 25's
copy assumes the reference's constant `.alien+0x7e0`, which fails where the import
store is larger (alienyze_Hasher: the 0x7e0 window scores 4, so the copy was
skipped and the image stayed encrypted). Two variants were built:

* first window scoring >= 24 while scanning 0x10 steps: that found store bytes a
  few dozen bytes *before* 0x7e0 (0x6f0, 0x6b0, 0xd00), which shifts every RVA and
  moved the OEPs of the samples that were already correct (7z 0x40e924 ->
  0x40ea14, ADExplorer 0x4149ec -> 0x414b1c);
* keep 0x7e0 when it scores >= 24, else take the best-scoring window: that keeps
  7z/ADExplorer bit-identical and gives Hasher a 0x1e110 copy (score 160), but the
  copy still stops at the hollow extent (`[0x1000..0x692dc)`) and never reaches
  Hasher's original EP 0x82568, so its OEP stays wrong.

Measured on the family alone (126 Alienyze samples, 85s): **16/126 oep_exact with
the scan vs 17/126 without** - a regression, so it is reverted. The real fix is the
reference's structural parse (`al_find_idt` + `al_hinted_store` / `al_packed_store`,
alienyze.cpp:145-429) which locates the store and therefore the body, instead of
scoring for it.

**Refreshed by-first-failing-criterion classification** (/home/jim/runs/r27_report.json,
2678 samples): invalid_pe 110, oep_wrong 722, imports_wrong 138; OEP-only failures
(valid PE, imports already correct) 138, of which **27 are PICK failures**
(code_sim >= 0.80: WinUpack 8, Amber 4, JDPack 4, Molebox 3, PECompact 3, NSPack 2,
BeRoEXEPacker 1, MPRESS 1, Neolite 1) and **111 are DECODE failures**
(Neolite 78, Amber 29, Alienyze 4). The picker is therefore nearly dry - 27 is the
ceiling for further OEP-heuristic work - and the next lever is Neolite.

Neolite probe (worst-first): it is not one bug. `neolite_cmd` has code_sim 0.975
with a `e8 .. 6a 10 68 ..` crt-thunk at its original EP (pick-only, in the 27);
`neolite_disk2vhd` has zeros there (never decoded); `neolite_shmnview` has plausible
code (`33 db 33 c9 33 d2 42 90 ..`) at code_sim 0.081 (wrong body layout);
`neolite_HashCalc` has UTF-16 text (`6f 00 20 00 73 00 61 00 76 00 65 00`) at
0.065 (a body region that is not code at all). Any Neolite work must separate those
three shapes rather than treat the family as decode-blocked as a whole.

### 0.17t Round 27: the reference's remaining ladder passes (Pass D + Pass E)

Ported the two ladder passes taote still lacked, in the reference's own order
(unpacker.cpp:7411-7464):

* **Pass D** - the Borland C++Builder signature `eb ?? 'fb:C++HOOK' 90 e9`. An
  unambiguous printable literal with at most one occurrence per PE, so it needs no
  counting or uniqueness guard, and it runs *before* Pass C.
* **Pass E** - the Borland/Delphi entry `6a <imm8> 68 <imm32> e8 <rel32>` with an
  in-image push, accepted only when UNIQUE in the section (ordinary code contains
  that two-push shape by the dozen), after Pass C.

**Measured (full corpus, 2678, 85s, pin 4):**

| | round 26 | round 27 |
|---|---|---|
| corpus all-three | 1670 (62.4%) | **1671 (62.4%)** |
| corpus OEP exact | 1779 (71.1%) | **1782 (71.3%)** |
| corpus imports | 1846 (71.9%) | 1846 (71.9%) |
| 200-set (300s) | 126 | 126 (0/0) |

+1 all-three (+`nspack_PEViewer`, one of the shared-address pick failures this
series has been chasing), +3 OEP, **0 losses** - a small, risk-free gain that also
closes out the ported ladder (A/B/C/D/E are now all present).

Also recorded this round, as evidence for the next lever rather than a guess: the
`imports_wrong` bucket (138 samples with the OEP already right) is dominated by
**RLPack 65**, and RLPack's failures are import *attribution*, not decoding -
`rlpack_grepWin-1.9.0_portable.exe` has code_sim 1.00 and the correct OEP but
recall 0.006, because its dump contains exactly ONE `*.dll` string
(`kernel32.dll`, twice) and 1 import descriptor: the payload's import table and its
DLL names are simply not in the dump, so the group harvester files all 81 function
names under that one DLL. Recovering it needs the stub's runtime descriptors (or
the family's own store parse), not a heuristics change. 63 of the 65 are below 0.80
recall, so there is no threshold story either.

### 0.17u Round 28: Alienyze's import store (al_find_idt + al_hinted_store)

Alienyze is the largest remaining gap against the reference (-116: taote 0, ref
116 all-three out of 126). Round 25's XOR recovery gave it 17 exact OEPs but the
import side stayed dead, because the *restored body's own* import directory is not
usable: `alienyze_Bginfo` harvests **0 descriptors** from it and the orphan walk
returns truncated junk (`eme.dll`, `LG32.dll`, `OL.DRV` - i.e. `KERNEL32.dll` and
friends read at a shifted offset). The pairs only exist in the stub's store inside
`.alien`, which is what the reference's `al_find_idt` / `al_hinted_store`
(unpacker.cpp:145-290) parse. Ported that core:

* `find_idt` - scan `.alien` for a run of >= 3 plausible 20-byte import descriptors
  (`timestamp`/`forwarder-chain` zero or -1, OFT zero or an in-image RVA, FT and
  name RVA in-image) and keep the LARGEST run, because random data matches the
  descriptor shape in 3-entry runs (`alienyze_geek` has spurious tables below the
  real 18-descriptor IDT).
* `hinted_store` - from `idt_end`, skip the leading RVA table, then read the record
  stream: a name at +0 is a DLL marker that CLOSES its own group, a name at +2 is a
  function. Binary gaps between the store's sections are tolerated (bounded, 64) so
  one RVA table in the middle does not truncate the walk.
* the pairs are `fn_names[prev_group_end .. group_end)` under that DLL marker,
  emitted through a new `PackerContext::imports_out` channel that the engine notes
  after the transform. Adding pairs can only help a recall-based criterion, which
  is why a partial recovery is safe to ship.

Store sizes on probes: Bginfo 23 dlls / 1425 names -> 1045 pairs, memtest 6/43 -> 42,
ADExplorer 14/401 -> 233.

**Measured.** Family alone (126 samples, 85s): imports 4 -> **17**, all-three 0 ->
**2**, oep_exact unchanged at 17 - and recall 1.000 on many more
(`Clockres` 0.708 -> 1.000, `handle` 0.742 -> 1.000, `pythonw` 0.614 -> 1.000).

| | round 27 | round 28 |
|---|---|---|
| corpus all-three | 1671 (62.4%) | **1674 (62.5%)** |
| corpus OEP exact | 1782 | 1782 |
| corpus imports | 1846 (71.9%) | **1860 (72.4%)** |
| 200-set (300s) | 126 | 126 (0/0) |

+3 all-three / +14 imports / **0 losses**. The 3 gains are `alienyze_memtest`,
`alienyze_pythonw` and `mpress_ComIntRep` (the last is the known budget flake
returning, counted as a gain here and a loss in round 25 - it is noise either way).

So Alienyze's binding constraint is now the **OEP pick** (17/126), not imports: 17
samples have exact OEP and 17 have satisfying imports, but only 2 overlap. The next
Alienyze lever is therefore the shared pick machinery over the restored image, not
more store parsing.

### 0.17v Round 29: TELock detection (neutral) and why Alienyze's OEP is not a pick bug

**TELock was never detected.** All 116 graded TELock samples carried
`family=unknown`, so the TELock-gated engine paths (the self-modifying ladder at
unpack.cpp:530, the SEH-chain probe at :2097, the decode-only region-class veto
exemption) were silently inert. The reference detects TELock by the bare first EP
byte (`e9`), which is far too generic to claim a family on. The corpus has a much
stronger signature: the stub entry is **`e9 25 e4 ff ff`** (`jmp -0x1bdb`) on
every sample. Verified offline over ALL 25 families in the dataset: that exact
5-byte form matches **118/118 TELock samples and zero samples of any other
family**, so claiming it cannot mis-route anything.

**Measured: exactly neutral.** TELock family alone (116 samples, 85s): oep_exact 1,
imports 0, all-three 0 - identical before and after. Detection alone does not
convert anything, and it cannot change another family (the signature is
dataset-provably TELock-only), so the corpus was not re-run for a provable-zero
delta. Kept as correct routing - a truthful label is a prerequisite for the TELock
seam work, and the plan's own rule against over-claiming is satisfied by the 0/25
false-positive measurement rather than by keeping the label "unknown".

**TELock's actual blocker** (next thread, not a pick bug): `telock_gzip` jumps to
0x3c6625d4 - an unmapped, nonsense pc - and dies before decoding anything, so the
ladder sees `C=0 C3=0` in every section and imports stay at 2. That is the
documented empty-SEH-chain #GP class, i.e. emulation fidelity in the stub, not the
OEP picker.

**Alienyze's OEP is not a cheap pick fix** (investigated and closed this round).
15 samples now have satisfying imports but a wrong OEP, and their *true* EPs do sit
at recognizable shapes in the restored body (`6a 70 68 <imm32> e8`, `55 8b ec 6a ff
68`, `e8 .. e9`). The body simply contains many look-alikes: `alienyze_DarkNamer`
true EP 0xa71e (`55 8b ec 6a ff 68 a8 c9 40 00`) while the "unique MSVC frame"
rule picks 0x404fa0, and `alienyze_BatteryInfoView` matches nothing
(`C=0 C3=0`) because its Borland pre-check fails the uniqueness gate. Three
shortcuts were checked and all are closed: the packed header EP is NOT the original
(darknamer header 0x237e0 vs true 0xa71e), the `.alien` body carries no MZ/PE
header under any XOR key, and the graded EP cannot come from the store. Resolving
these needs the reference's broader evidence chain, not another shape rule.

### 0.17w Round 30: TELock's trap and Neolite's layout, measured offline

**TELock's blocker is now pinned to one instruction.** `telock_gzip` traces as:

```
[unpack] insn_invalid pc=0x466a23 b=0xf1      <- ICEBP, the anti-emulation trap
[rundbg] emu error 'Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)' pc=0x3c6625d4
[unpack] fs:[0] chain=0x0                      <- the SEH chain is EMPTY at that point
```

taote's invalid-instruction hook already does the right thing for 0xf1 (advance Eip,
then `seh_dispatch_cpu(0x80000004)`), but there is no handler in the fs:[0] chain to
receive the #DB, so the stub resumes into garbage. The stub installs its handler
itself; whether it does so through a path taote does not emulate (a vectored
handler, or a `mov fs:[0]` that never lands in the TEB) is the open question. This
is emulation fidelity, not the picker.

**Neolite is not one shape either** (offline measurement over the packed files,
scoring each section's raw bytes against the x86-likelihood window):

| sample | `.text` best XOR | `.text` score at key 0 | embedded PEs in the file |
|---|---|---|---|
| neolite_DarkNamer | key 0 | 224 | none |
| neolite_HashCalc | key 0 | 144 | none |
| neolite_cmd | key 0 | 6725 | none |
| neolite_disk2vhd | key 0 | 18162 | 4 (in `.rsrc`, 5-6 sections each) |

So Neolite's `.text` is **plaintext on disk** (key 0 wins by orders of magnitude -
no single-byte XOR layer, unlike Alienyze), and only `disk2vhd` carries
resource-embedded PEs. That kills the "Neolite is XOR-encrypted like Alienyze"
hypothesis and means the 78 "decode-blocked" Neolite samples are not one mechanism.

**Deliberately not done:** extending the embedded-PE adoption to scan the image's
own `.rsrc` for payload PEs. `neolite_disk2vhd` has four unrelated embedded PEs
there (resource payloads of the original program, not the unpack target) and
picking the largest would replace the image with the wrong program. That is a
regression generator, not a fix, and it cannot be validated inside a round.

### 0.17x Round 31: the pick residuals are hop-vs-ladder conflicts, and neither switch fixes them

**The 36 pick failures are not shape ambiguity.** Splitting them by the engine's
own `reason` field (/home/jim/runs/r29_report.json):

| reason | count |
|---|---|
| section_hop | **24** |
| ladder_scan | 11 |
| fallback_guess | 1 |

Two thirds are samples where the run's hop ledger produced the answer and the
static ladder never got a say. The rest of the corpus is the same shape: 2146 of
2678 answer via `section_hop`, so the incumbent rule is the dominant mechanism and
any change to it is a corpus-wide risk.

**Measured: the incumbent rule cannot simply be switched off.** taote has
`TAOTE_OEP_INCUMBENT=0` (the run-accepted hop scores STRONG unless it is a junk
latch, write ordinal < 32). On a 186-sample subset - all 36 pick failures plus 150
random samples that currently pass via `section_hop` - turning it off gives
**2 gains and 12 losses**: it does fix `bero_cpuz_x32` and `mpress_cpuz_x32`
(the shared `e8 30 c5 0f 00 e9 f9 6a` thunk case) but breaks
`aspack_pskill`, `eronana_cmd`, `jdpack_notepad`, `jdpack_pskill`,
`jdpack_pssuspend`, `molebox_Dbgview`, `molebox_FolderTimeUpdate`,
`packman_LastActivityView` and four `yoda-crypter_*`. So the binary incumbent rule
is net positive and the fix has to be the reference's *scored* comparison
(`pick_and_emit_oep`'s V0/V1/V2 evidence weighting), not a flag flip.

**Measured and reverted: the decode-only Pass C "first below 0x8000" rule.**
12 of the pick failures have a true EP that is a `c3 e8 <rel32> e9 <rel32>` CFG
thunk, and the reference's decode-only Pass C takes "the first hit when there is
one hit, or the first below 0x8000" while taote takes the LAST (measured for
`mpress_ADExplorer`'s second of two). Porting the first-hit rule changed nothing:
`alienyze_Clockres` has hits at 0x4002 (true) and 0x257e2, and BOTH validate -
each e9 target is in-image and each target has a recognizable prologue - so the
validated-hit branch wins first and returns the last validated one. The reference
would do the same, which means these 12 are ambiguous under the ported machinery
rather than mis-ported. Reverted (inert).

**TELock's SEH is not empty after all** (corrects round 30): with TAOTE_SEHDBG the
IBEBP traps do dispatch properly -

```
[sehd] code=80000004 fault=466a24 pc=466a24 chain=ffffcfb0 next=0 handler=466a15
[sehd] code=80000004 fault=466a58 pc=466a58 chain=ffffcf90 next=0 handler=466a3c
```

the stub installs its own fs:[0] frames and two #DB dispatches reach their
handlers. The run dies at pc=0x3c6625d4 *after* the second handler returns, so the
open question is SEH resumption fidelity (how the handler's return is applied),
not chain setup - a materially different and riskier target than round 30 assumed.

### 0.17y Round 32: the pick worklist is exhausted by construction (candidate-count proof)

**28 of the 36 pick failures have at most ONE ledger candidate**, so no
selection or scoring rule can change them. Ledger sizes, from TAOTE_UNPACK_DEBUG
over all 36:

| ledger candidates | samples |
|---|---|
| 0 | 12 |
| 1 | 16 |
| 2 | 4 |
| 4 | 3 |
| 122 | 1 |

The 12 zero-candidate samples are the Alienyze ones (the XOR transform runs at
finalize, after the run, so nothing is ledgered and the ladder chooses freely).
The 16 single-candidate ones have exactly one hop and nothing to compare it
against. Only 8 samples have a real choice, and one of those is a 122-entry junk
storm. Round 31 showed 24 of the 36 answer via `section_hop`; this shows the
overwhelming majority of those must be challenged by a *static* candidate rather
than selected among hops - which is precisely what the reference refuses to do
for its strong classes (+1e6).

**Measured and reverted: the weak-shape challenger gate.** If a hop's own bytes
are only weakly entry-shaped it may be poor evidence, so with
`TAOTE_OEP_SHAPE2=1` a strongest-hop gate of `shape_at(lead) >= 2` (instead of
`>= 1`) lets the ladder challenge it. On the same 186-sample subset round 31 used
(36 pick failures + 150 random section_hop passes) the result is **identical to
the blanket `TAOTE_OEP_INCUMBENT=0` run: 2 gains / 12 losses**. The 12 losses
*are* the shape-1 hops, so weakly-shaped hops are usually the right answer in
this corpus and the ladder is not a better judge. Reverted.

Together with round 31 this closes the pick worklist: neither selecting
differently among ledgered hops (28/36 have nothing to select), nor letting the
static ladder override a weak hop (2 gains / 12 losses), nor porting the
decode-only Pass C first-hit rule (inert, both hits validate) produces a positive
delta.

**Where the remaining OEP gap actually sits** (786 OEP-wrong of 2501 graded, by
family): Themida 122, TELock 115, Alienyze 108, Yoda-Protector 101, Neolite 92,
Amber 69, PEtite 38, RLPack 38. The first five alone are 538 of 786, and in each
of them the failure is that the body is never decoded (or decoded wrongly), not
that the entry is mis-picked. So the OEP percentage gap versus the reference is
overwhelmingly a *decode* problem, and per-sample pick tuning cannot move it.

### 0.17z Round 33: Neolite's terminal CRT-entry fill (corpus all-three +1)

Neolite was the largest addressable single-family gap (1 of 93 all-three). The
reference has a family file for it, and its second half is a portable, bounded
mechanism: `NeoliteUnpacker::family_terminal_fill`
(../pegasus/src/unpacker/packers/neolite_unpacker.cpp:501-622).

**The mechanism.** Neolite decodes the payload IN PLACE, so the original
program's CRT entry frame survives byte-identical in the dump - what fails is the
PICK. The stub's hand-off has a plausible first byte at a place that is not the
entry, so neither the accepted-hop rule nor the decode-only ladder can separate
it from the real one. The reference's answer is a terminal scan for the
compiler's CRT entry frames, applied AFTER the pick:

| pattern | shape | use |
|---|---|---|
| P1e | `e8 ???? 6a ? 68 ???? e8 ???? 33 db 89 5d fc 64 a1 18 00 00 00` | high precision (VS2010 SEH-init) |
| P2 | `55 8b ec 83 ec ? {53\|56\|57} ff 15` | high precision (VS2005/08) |
| P3 | `e8 ???? e9 ???? cc cc cc cc` | loose (linker thunk), rescue only |

Gate: override only when the current pick is NOT entry-shaped (first byte outside
`55 e8 e9 eb 6a 68`), and then only when the high-precision set has exactly one
member that is not the current pick, or the loose set has exactly one member and
the pick is 0/implausible. So a genuinely shaped pick is never displaced - the
reference's own comment records that psping's `e8/e9` trampoline pick must not be
replaced by a decoy P3 hit elsewhere in its image.

**New seam.** The pick is decided before `transform_image` can matter for these
samples (their ledger is non-empty), so a post-pick hook was needed:
`Packer::family_fill(PackerContext&)` with `ctx.oep_mut`, mirroring the reference's
`family_terminal_fill` ordering. The base class returns false, so every other
family is unchanged by construction. `NeolitePacker` (new
qiling/unpack/packers/neolite_packer.cpp) is the only override.

**Measured.** `neolite_cmd` is the sample the shape analysis predicted: the body
is right (code_sim 0.975) but the pick was `8b ff` junk, and the scan finds
**one** P1e hit at RVA 0x829a - the true EP.

| scope | before | after |
|---|---|---|
| Neolite family (93, uncontended) | all-three 1, oep_exact 1 | **all-three 2, oep_exact 2** |
| Neolite family, `TAOTE_OEP_INCUMBENT=0` | - | **all-three 2** (same single gain, so the incumbent is not the blocker) |
| corpus (2678 @85s) | 1674 | 1674 measured = 1 gain / 1 loss |
| 200-sample set (@300s) | 126 | **126 (0 gains, 0 losses, no timeouts)** |

The single corpus loss is `mpress_ComIntRep` at `dur=85` - the documented
budget flake (a clean local re-run gives `oep=0x42800a` with 850 imports and
recall 1.0), so the honest delta is **1674 -> 1675 all-three, OEP 1782 -> 1783,
imports unchanged at 1860**.

**Process lesson.** The first corpus run of this round was launched CONCURRENTLY
with the 200-sample set and reported 7 losses (six `bero_*` and one
`expressor_*`), every one at `dur=85/86`. Running two harnesses at once starves
both of CPU and manufactures timeouts that look exactly like regressions. Never
run two measurement harnesses at the same time; the re-run alone was clean.

**What did not work, measured.** Turning the incumbent rule off for Neolite alone
gives the same single conversion, so Neolite's other 91 samples are not a
hop-suppression problem. They remain a decode/pick problem of the kind round 32
proved unreachable by candidate selection.

### 0.17aa Round 34: the zeroed section table - corpus all-three 1675 -> 1767 (+92)

**The defect.** Exe32pack wipes the payload image's section headers before
handing off. The dump then parses as a PE whose every section is size 0 at RVA 0,
so the claimed entry maps into no section: 106 of the family's 124 samples graded
`pe_why = entry-not-mapped`, i.e. never a valid PE, hence never all-three. The
reference documents the same shape - "F36: reconstruct degenerate section-table
path (Exe32pack zeroes all section headers in the dump)" - and rebuilds the table
from write evidence.

**The fix, and why it is not a family heuristic.** The packer decodes into the
EXISTING sections (its own stub lives in `.i`), so the packed file's section table
is intact on disk and describes the image taote just dumped. Restoring it is a
byte copy of `nsec * 40` bytes, and the data directories were never wiped (the
import RVA and the IAT survive), so the result is a parseable PE rather than a
syntactically valid husk. Gated twice, both structural and family-free: only when
EVERY dumped section header is zero, and only when the packed table has the same
section count / optional-header size and is itself non-degenerate. Measured
corpus-wide, exactly 106 dumps in the whole 2676-sample set have an all-zero
section table, all Exe32pack - so by construction no other family is reachable.
It lives in `unpack.cpp` rather than a packer seam because the detector labels
this family `unknown` (round 29's finding), so a family-gated seam would never run.

**Measured (family alone, 124 samples):**

| criterion | before | after |
|---|---|---|
| valid PE | 18 | **124** |
| oep_exact | 0 | **92** |
| imports | 0 | **105** |
| all-three | 0 | **92** |

The import jump (0 -> 105) is a second-order effect worth noting: the harvester
walks the payload's descriptor chain through the section table, so a restored
table is what lets it find the descriptors at all.

**Corpus (2678 @85s): 1674 -> 1767 all-three, +93 gains / 0 losses.**
OEP 1783 -> 1875, imports 1859 -> 1965, valid PE 2568 -> 2674. The headline number
here is measured against the r33 report (1674, which carried the
`mpress_ComIntRep` budget flake); against the flake-adjusted 1675 the delta is
+92, exactly the family's conversion count.

**Fair set (200 @300s, run alone): 126 -> 129, 0 gains-wrong / 0 losses**
(exe32pack_AkelAdmin, Exe32pack_AltStreamDump, exe32pack_DocFetcher-1024).

**A prediction that was right for the wrong reason.** An offline pass over the 106
dumps predicted "the claimed OEP maps into a restored section on 106 of 106
samples, and equals the recorded original EP on 0 of 106". The first half was the
real signal and is what shipped; the second half was meaningless because
`orig_ep` is null for every sample whose PE was invalid, so the comparison ran
against 0. The grader then reported 92 exact OEPs. Lesson: when a report field is
gated on the very property under repair, an offline equality test on it proves
nothing.

**Next targets, measured, not guessed.** Exe32pack still has 32 samples without an
exact OEP and 19 without satisfying imports. The other families unchanged by this
round, by remaining all-three headroom: TELock 116 (SEH resumption), RLPack 104
(import data genuinely absent - zero GetProcAddress calls, verified), Neolite 91
(OEP; body decodes, pick is plausible-but-wrong), Yoda-Protector 101 and Themida
122 (never decode). PEtite is the best remaining convertible block: 12 samples
have an exact OEP and a right body (code_sim 0.87-1.0) but import recall
0.03-0.25, and unlike RLPack the data IS in the dump (petite_PEViewer carries 14
DLL name strings and 1102 API-looking strings while the descriptor walk finds 11
descriptors) - so the reference's PEtite INT-run salvage (petite_unpacker.cpp
:540-752, name->dll attribution through the module export tables) is the next port.

### 0.17ab Round 35: PEtite's data IS in the dump; the blocker is DLL attribution

PEtite is the best remaining convertible block on paper: 12 samples have an exact
OEP and a right body (code_sim 0.87-1.0) but import recall 0.03-0.25, and
unlike RLPack the payload's import data is present. Two facts pinned this round,
both on `petite_PEViewer.exe` (original: 543 imports).

**1. The original import directory survives in the dump.** At RVA 0x12b000 the
original's descriptor chain is intact - OFT 0x12b128, Name 0x12b694, FT 0x12b70c -
and the original's INT/thunk arrays and name strings are present all over the
section (`GetFileVersionInfoA` at RVA 0x12cf45, `RegCloseKey`, `CreateFileA`,
`MessageBoxA`, `HeapAlloc` all found verbatim). The reason the pelt is poor is that
the harvester reads DD[1], which the stub REWROTE to its own rebuilt table at
0x182680: 11 descriptors, 16 slots, names ending in a DLL cluster at 0x1828ac.
That rebuilt table is what our "11 descriptors -> 16 imports" line reports, and
16/543 is the measured recall 0.0333. So this is not a missing-data family; it is
a "the header points at the stub's table, and the original one is orphaned"
family.

**2. INT-run detection already works; ATTRIBUTION is what fails.** Replaying
taote's own table scan offline over the dump finds 12 pointer-spaced name tables,
including one at 0x12b3d4 with **156** names and one at 0x12b920 with 87 - i.e.
the candidate names are all there. But the scan then requires "the dll string
nearest BEFORE the table" and finds none for them, so every table is dropped. The
original descriptors that would name them are partly overwritten (the descriptor
at 0x12b000 has Name pointing INTO a name array, not at a DLL string).

**Measured and reverted: the hint/name read fix.** PEtite's thunks point STRAIGHT
at the name, so reading v+2 (the standard ordinal-hint layout) chopped two
characters off every name ('GetUserNameA' -> 'tUserNameA'). Preferring whichever
of `cstr(v)` / `cstr(v+2)` parses longer is safe by construction (when v really is
a hint the parse at v starts on non-printable hint bytes and fails) and it does
recover the untruncated names. Measured on the PEtite family (73 samples, 85s
budget, own run): **0 of 73 samples changed recall** - identical to three decimal
places on the aggregate (recall 0.393, precision 0.236, imports 23, all-three 23).
So the INT-table path contributes nothing for this family today; the fix is inert
and was reverted.

**The next port, precisely scoped.** Name->DLL attribution, which the reference
gets from the emulator's module export tables (petite_unpacker.cpp:540-752 builds
`exp2dll` from get_peb_modules + get_sys_modules, skipping ntdll/ntoskrnl, with a
host-System32 fallback that is `#ifdef _WIN32` and therefore inert on this host).
taote has no per-module export map - `export_symbols()` is the MAIN image only -
so the equivalent needs either a loader-side per-module export list or a
family-side read of the rootfs stub DLLs' export directories. That is the unit of
work for the next round, and it is the last mile for 12 samples here plus the
orphan-table path generally.

### 0.17ac Round 36: 84 corpus samples are .NET and can never be all-three; two avenues closed

**The targeting fact.** `oep_exact = None` in the report does not mean "ungraded
by accident": tools/unpack_report.py:301 skips the OEP comparison when the
original PE carries a CLR directory (`orig.get("com_rva")`), because a managed
assembly's entry lives in metadata and the classic EP comparison is meaningless.
**84 of the 2678 samples are in that class** (51 of them already pass imports; 37
already have code_sim >= 0.8, i.e. their dump is essentially the original program).
They can never contribute an all-three, and a naive "not all-three" count silently
folds them into the failure budget.

Gradable corpus = **2594**, and 1767/2594 is **68.1%**, not 66.0%. Family headroom
must be counted with them removed; the biggest blocks become:

| family | n | ok | .NET (ungradable) | real failures |
|---|---|---|---|---|
| Themida | 122 | 0 | 0 | 122 |
| Alienyze | 126 | 2 | 8 | 116 |
| RLPack | 104 | 0 | 1 | 103 |
| TELock | 116 | 0 | 15 | 101 |
| Yoda-Protector | 101 | 0 | 0 | 101 |
| Neolite | 93 | 2 | 0 | 91 |
| PEtite | 73 | 23 | 0 | 50 |
| Amber | 152 | 83 | 22 | 47 |
| WinUpack | 97 | 74 | 1 | 22 |
| FSG | 97 | 75 | 2 | 20 |
| Exe32pack | 124 | 92 | 17 | 15 |

Note Exe32pack after round 34: 32 "failures" are really 17 ungradable .NET rows
(most with imports recall 1.00 and code_sim 0.9-1.0) plus **15 genuine decode
failures** at code_sim 0.13-0.21. Amber's 69 drops to 47 for the same reason.

**PEtite's attribution is blocked on this host, and so is the reference's.** The
next step recorded last round was name->DLL attribution through module export
tables. Checking the substrate first: taote's rootfs stub DLLs are synthesized by
tools/stub_dlls.py from the sample's OWN packed import table (`--from-pe`), so they
export exactly what the stub imports - attributing the payload's original names
through them is circular. The reference's answer is
`get_peb_modules`/`get_sys_modules` exports with a host-System32 fallback that is
`#ifdef _WIN32` and therefore inert on this host. So on Linux there is no export
knowledge to attribute with, and the 12 PEtite samples are not reachable this way
without inventing an export database. Recorded so it is not re-attempted as
"just add attribution".

**TELock's stub is self-encrypted on disk.** Static inspection cannot guide the
fidelity work: telock_gzip's last section (.k at va 0x65000, raw 0x8800) is
high-entropy garbage on disk (`6f 31 8b a5 18 d3 f1 1f c4 35 3e 80 f6 da` at RVA
0x66800), so the handler bodies at 0x466a15/0x466a3c that the SEH trace shows are
decrypted only in memory by the polymorphic loader. Any further TELock progress has
to come from observing the decrypted handler's behaviour in the emulator, not from
reading the file.

**Exe32pack's 15 real decode failures** all die the same way
(exe32pack_bzip2: `UC_ERR_WRITE_UNMAPPED` at pc=0x4178a0, RVA 0x178a0 inside .k
[0x11000..0x18302) with SizeOfImage 0x19000, hop ledger one entry 0x4110eb@1) - a
stub write to an address it computes, with the target address not logged. The next
step there is a *safe* way to log the faulting write address (the old memdbg probe
was deleted for crashing the host; a scoped read-only variant inside the existing
exception path is the shape to try).

### 0.17ad Round 37: the int3 resume bug (fidelity fix, converts nothing)

**Yoda-Protector is the most homogeneous large block left**: 101 samples, 0
all-three, and all 101 died the same way. TAOTE_SEHDBG shows why:

```
[sehd] code=80000003 fault=4305fc pc=4305fc chain=ffffcff0 handler=430563
[sehd] code=80000003 fault=4305fc pc=4305fc chain=ffffcfd0 handler=430570
[sehd] code=80000003 fault=43063f pc=43063f chain=ffffcfb0 handler=43057d
[sehd] code=80000003 fault=43063f pc=43063f chain=ffffcf90 handler=43058a
[sehc] exhausted -> resume 43063f   (x16, then the run dies)
```

60000003 is STATUS_BREAKPOINT: the stub plants `int 3` anti-debug probes and
installs fs:[0] handlers for them. When the chain exhausts, taote reloads the
saved CONTEXT and resumes at its Eip - which for a #BP is the int3 ITSELF, so it
re-traps on the next instruction forever until the repeat guard trips.

**A real OS resumes at the byte AFTER a breakpoint** (int3 is one byte wide by
definition), so the exhausted path now advances one byte when the dispatch that
led there was `0x80000003`. Gated on the exception code, not on the byte: gating
on the byte was tried first and did nothing, because Yoda decrypts its page on
demand and by the time anything reads that address the trap has been rewritten
(measured: the trap at RVA 0x3063f reads 0xC3 in the terminal dump).

**Measured.** The crash loop is gone (resume 0x430640, run ends cleanly with "no
section hop; OEP guessed" instead of a fatal fault). But:
- Yoda-Protector family (101 samples): all-three 0 -> 0, oep 0 -> 0, imports 0 -> 0.
  **Zero gains, zero losses.** The stub now survives its anti-debug chain and then
  never decodes.
- corpus (2678 @85s): 1767 -> 1766, 0 gains / 1 loss = `mpress_ComIntRep` at
  dur=85, the documented budget flake (clean local re-run: oep=0x42800a, 850
  imports).
- fair set (200 @300s): 129 -> 129, 0/0.
- suite 593/593.

Kept anyway, and this is a deliberate choice worth stating plainly: resuming at an
int3 is simply wrong, and every other family's measured behaviour is unchanged
(the guard fires only for #BP). It is a prerequisite for any Yoda-Protector work,
exactly as round 29's TELock label was a prerequisite for TELock work. But it
converts **nothing**, and the plan should not pretend otherwise.

### 0.17ae Round 38: the import near-misses are all ORDINALS, and ordinals need attribution

**No cheap pick class exists.** Of 719 gradable samples with a wrong OEP, exactly
**2** are within +-0x40 of the truth (petite_PEview and yoda-protector_PEview, both
+5). There is no constant-offset or near-miss population to fix, which is the third
independent confirmation that the remaining OEP failures are decode failures.

**The import gap is concentrated and quantified.** Of the rows whose OEP is already
exact, 109 still fail imports:
- recall < 0.80: **91** (RLPack 64, PEtite 12, Alienyze 10, NSPack 2)
- 0.80-0.90: 8
- 0.90-0.95: 10 (MEW 4, WinUpack 3, Alienyze 1, MPRESS 1, RLPack 1, ...)

**The 0.80-0.95 near-misses are explained exactly by ORDINAL imports.** The
arithmetic is exact on every one checked:

| sample | original pairs | named | ordinals | we rebuilt |
|---|---|---|---|---|
| mew_Bginfo | 861 | 808 | **53** | 807 |
| mew_adwcleaner | 603 | 568 | **35** | 568 |
| winupack_FileTypesMan | 240 | 225 | **15** | 225 |
| rlpack_DarkNamer | 245 | 61 | **184** | 228 |

We rebuild precisely the named ones and none of the ordinals, so recall lands a few
points under the 0.95 line. (Note the grader reads the OUTPUT PE's import table -
the sidecar meta is only a fallback - so this is a rebuild gap, not a spelling one.)

**Measured and reverted: accepting ordinal thunks in the INT-table scan.** The
rebuilder already writes a correct ordinal thunk for an "ordinal_<N>" pair
(iat/import_rebuilder.cpp ordinal_of, 0x80000000|ord), so the only missing step
looked like *finding* them: the table scan required every member to point at a name
string, so an ordinal thunk truncated the table. Allowing a high-bit member
(`ordinal_ + (v & 0xffff)`, continue) changed group shapes (Bginfo's string groups
61 -> 91, names 975 -> 1120) but emitted **zero** ordinal pairs: the tables that
hold them never pass the "nearest preceding dll string" attribution, so
`dll.empty()` drops them anyway. Measured on MEW+WinUpack (203 samples): **0 gains
/ 1 loss** (winupack_Bginfo). Reverted.

**The unification worth carrying forward.** PEtite's 12 and these 18 near-miss rows
are blocked by the SAME missing capability: mapping a recovered name or ordinal to
its owning DLL. taote has no per-module export map, the rootfs stub DLLs are
circular (built from the sample's own packed imports), and the reference's host
fallback is Windows-only - so on this host the missing piece is a *name->dll
database*, not more scanning. That single asset would serve PEtite, MEW, WinUpack,
Alienyze and NSPack at once, which makes it the highest-leverage remaining item
even though it is infrastructure rather than a family port.

### 0.17af Round 39: the export database — corpus all-three 1766 -> 1772 (+7)

Round 38 concluded that every import near-miss was blocked by one missing asset: a
name -> owning-DLL map. This round builds it and it pays.

**The asset.** `tools/gen_api_db.py` turns the host's mingw-w64 IMPORT LIBRARIES
into `qiling/unpack/api_db.inc` (32374 names over 401 DLLs, 1.2 MB, committed so a
build without mingw still works). `libkernel32.a` lists what kernel32.dll exports,
and so on - an SDK export database. It is deliberately NOT derived from the
corpus's unpacked originals, which would be ground truth and make every measurement
circular; it is the Linux equivalent of the reference's `host_dll_has_export`,
which reads the real System32 DLLs on Windows. API-set pseudolibs (onecoreuap_apiset
alone forwards 19k names) are excluded, and the classic system DLLs win ties.

**Where it is used.** The INT-table scan already found 12 pointer-spaced tables in
petite_PEViewer (one with 228 names) but dropped all of them because its only
attribution source is "the DLL string nearest BEFORE the table", and the stub's
rebuild drops the descriptor's Name field. A table with no preceding DLL string is
now attributed member-by-member through the database, preferring a DLL the IMAGE
itself names. Ordinals are skipped rather than guessed (a wrong DLL is not a recall
hit). Offline prediction on petite_PEViewer: 12 tables / 2056 members -> 953
attributed pairs, recall 0.940 vs 0.0333 for the shipped set.

**A second bug the database exposed.** FSG/BeRo/MEW/WinUpack shift the first
character of every stored name by -3, and the scan undid that blindly - which
corrupts every OTHER family's names: PEtite's `EnableWindow` became `BnableWindow`,
so the whole table then matched nothing (and the database could not attribute it).
The undo is now evidence-backed: apply it only when the database knows the shifted
spelling and not the stored one. Measured effect on one table: 12 of 12 names
attributed instead of 1 of 12, and PEViewer's big table 228 of 228.

**Measured.**
- PEtite family (73): all-three 23 -> **29**, imports 23 -> 35, mean recall
  0.393 -> **0.803**, 0 losses. The 6 new all-three are petite_ctrl2cap, efsdump,
  gsd, ldmdump, pagedfrg, puttytel_32.
- corpus (2678 @85s): all-three 1766 -> **1772**, 7 gains (PEtite 6 + MPRESS 1) and
  1 loss. The loss is `nspack_procexp` at dur=85 - it ran at dur=81 before, so the
  extra pairs pushed it past the budget; a clean local re-run gives recall 1.000.
  So the honest delta is **+7** (1766 -> 1773).
- fair set (200 @300s): 129 -> 129, 0/0.
- suite 593/593.

**Also re-applied this round, with the reason stated.** Round 35 measured the
"prefer the longer of cstr(v) / cstr(v+2)" fix as INERT (0 of 73 PEtite samples
moved) and reverted it. It is re-applied here because the mechanism that made it
inert is gone: nothing consumed the names then, whereas the database lookup needs
the untruncated spelling. That is a different measurement, not a repeat of a losing
experiment - and the family result (23 -> 29) is what proves it this time.

### 0.17ag Round 40: ordinals inherit their table's DLL (corpus 1772 -> 1773)

Round 39 left PEtite at recall 0.803 with every NAME attributed and every ordinal
dropped. The owner of an ordinal is not free information... except by position: one
INT table is ONE dll's import list, so the owners of a table's NAMED members are
evidence for its ordinal members. The attribution branch now votes the named
members' database owners, takes the dominant one, and assigns the table's
`ordinal_<n>` entries to it - still refusing to guess when a table has no named
member at all.

Measured behaviour on petite_PEViewer's tables is exactly what the evidence says:
BitBlt -> gdi32, CommandLineToArgvW -> shell32, ActivateKeyboardLayout -> user32,
CoInitialize -> ole32, 87/87 and 228/228 names attributed (that sample's tables
carry no ordinals, which is why its recall stays 0.803).

**Measured:**
- PEtite family (73): all-three 29 -> 29, recall 0.803 -> 0.803 (no ordinals there).
- MEW/WinUpack/RLPack/Alienyze/NSPack (530): all-three 263 -> 264, 2 gains
  (nspack_ADInsight, nspack_procexp) / 1 loss = winupack_Bginfo at dur=85, which a
  clean local re-run resolves (oep=0x5b5d42, 2037 imports).
- corpus (2678 @85s): 1772 -> **1773**, 1 gain (NSPack) / **0 losses**.
- fair set (200 @300s): 129 -> 129, 0/0.
- suite 593/593.

**Cost worth recording.** The vote pass makes the boundary samples measurably
slower: `nspack_procexp` and `winupack_Bginfo` both sit near the 85 s budget and
both flipped to dur=85 (timeout) in the runs above before a clean re-run showed the
right answer. Any future work on this path should keep the per-table work in the
scan (it is O(members)) rather than add passes, and the budget-boundary flakes
should be read as timing, not accuracy.

### 0.17ah Round 41: junk-DLL re-attribution measured and REJECTED (0 gains / 3 losses)

The hypothesis looked strong from offline numbers: in the round-37 near-miss rows a
large share of the exported pairs named a DLL the dump never mentions
(winupack_FileTypesMan 225/225, petite_PEViewer 1807/3125, rlpack_mtinst 308/382),
and the export database knows the real owner for most of those names. So: after the
harvest, replace the DLL of any pair whose stem is absent from the image's `*.dll`
strings with the database owner, when that owner is a DLL the image names (or when
the image names no DLL at all).

**The offline number was an artefact of my own scan.** The C++ image scan (string
must start after a NUL) finds 16 DLL stems in petite_PEViewer where my offline
regex found 7, and with the fuller set every one of that sample's pairs is
attributed to a DLL the image really does name - `fixed = 0`. Measured probes:
petite_PEViewer 0, winupack_adrestore 0, winupack_Tcpview 0, rlpack_DarkNamer 0,
alienyze_procexp 12, mew_Sysmon 206.

**mew_Sysmon did convert in isolation** (recall 0.901 -> 1.000 on a local run) which
made the pass look worth keeping. The corpus says no:

- corpus (2678 @85s): all-three 1773 -> **1770, 0 gains / 3 losses**
  - mpress_ComIntRep at dur=85 (the usual budget flake)
  - winupack_dfrgui (dur=10, recall 0.9029) and winupack_ftp (dur=2, recall 0.6242)
    are genuine losses: the DLL we had assigned was RIGHT even though my scan did
    not list it, and replacing it with the database's default owner broke the pair.
- suite 593/593 (it never got that far - the change was reverted).

Reverted. The lesson is the same one round 39 taught from the other side: the
database is a good *fallback* where no attribution exists (a table with no preceding
DLL string), and a bad *override* where an attribution already exists - even a
noisy-looking one. `mew_Sysmon` is a single-sample win that costs two
single-sample losses, and one of its "junk" DLLs may well have been real.

### 0.17ai Round 42: Neolite's 78 "imports-ok" samples have ciphertext bodies

An attractive inference died this round: Neolite has 78 samples with **imports
passing** but a wrong OEP, and imports are read from the dump, so the body "must" be
decoded and only the entry wrong - i.e. up to 78 samples for a pick fix. Measured:

**All 78 have code_sim < 0.1** (0.022-0.043). Imports pass because the names come
from the packer's own store, not from the payload body. The inference was wrong and
checking it cost ten minutes instead of a corpus round.

**What the dump actually holds** (neolite_ADInsight, original ADInsight.exe):

| section | va | dump vsize | original vsize | identical bytes |
|---|---|---|---|---|
| .text | 0x1000 | 0x49800 | 0x4962c | **3.7%** |
| .rdata | 0x4b000 | 0x184ce | 0x184ce | 30.6% |
| .data | 0x64000 | 0x1e8600 | 0x1e8600 | 19.7% |
| .rsrc | 0x24d000 | 0x1d33c0 | 0x1d33c0 | 23.2% |
| .reloc | 0x421000 | 0x4400 | 0x4298 | 2.3% |
| .neolit | 0x426000 | 0x1a50 | - | the stub |

Two facts worth keeping. First, **the dump's section layout is exactly the
original's** (VAs and sizes match to the byte, with the stub's own `.neolit`
appended) - the packer preserves the layout and encrypts in place, so a
layout-vs-dump size comparison is a cheap way to tell "decoded" from "still
ciphertext". Second, .text is 75% non-zero but only 3.7% identical: ciphertext, not
empty.

**Three candidate mechanisms, all measured and rejected:**

1. **The first-write shadow** (the anti-dump overlay MEW/PECompact need, since
   decrypt-execute-re-encrypt leaves ciphertext in terminal memory). Run with
   TAOTE_UNPACK_SHADOW_ALL=1 on neolite_ADInsight / neolite_Bginfo /
   neolite_Clockres: code_sim unchanged at 0.032 / 0.022 / 0.041. Not that pattern.
2. **The round-33 terminal CRT fill.** Its three signatures find **zero** candidates
   in all 78 samples (`high = {}` for every one), so the fill cannot reach them; the
   one sample it does fix (neolite_cmd) is a different shape (decoded body,
   plausible-but-wrong pick).
3. **Embedded PEs.** The dump carries valid PEs at 0x29ada0 and 0x376f10, but they
   are **64-bit** images (`.pdata`, ImageBase 0x1) - bundled helper binaries, not
   the 32-bit payload. Confirms round 30's rejection of resource-PE adoption.

So Neolite's stub reaches a clean stop (no fault, no emulation error) having hopped
into a still-encrypted region, i.e. the decryption loop is skipped under emulation.
The next step there is tracing *why* (an anti-debug/anti-emulation branch), not more
pick or attribution work - and the trace must start from the clean-stop observation,
because there is no crash to read.

**Also corrected this round:** the offline "junk DLL" numbers that motivated round
41's re-attribution experiment were an artefact of a narrower regex than the C++
image scan (16 DLL stems vs 7 in petite_PEViewer). That experiment's rejection
stands, but its premise was already invalid before the corpus run.

### 0.17aj Round 43: the remaining failures are anti-emulation clean stops (and a PEB fix that did not help)

**The strategic classification the plan has been missing.** Of the 824 gradable
failures, by how the run ENDS:

| family | n | clean stop | crash |
|---|---|---|---|
| Themida | 122 | **122** | 0 |
| Alienyze | 116 | **116** | 0 |
| RLPack | 103 | 98 | 5 read |
| Yoda-Protector | 101 | 88 | 13 read |
| TELock | 101 | 56 | 45 fetch |
| Neolite | 91 | **91** | 0 |
| Amber | 47 | 43 | 3 read / 1 fetch |
| PEtite | 44 | **44** | 0 |
| WinUpack | 24 | 5 | **18 fetch** / 1 read |
| FSG | 20 | 18 | 1 write / 1 read |
| Exe32pack | 15 | 1 | **14 write** |
| NSPack | 10 | 10 | 0 |

**581 of 824 (70%) are CLEAN STOPS** - the stub finishes, or chooses to exit, having
decoded nothing. The crash-based families are the tractable ones and they are the
small end: Exe32pack 14 write-unmapped (the null-base write at addr 0x54 traced in
round 33's sibling work), WinUpack 18 fetch-unmapped, TELock 45 fetch-unmapped
(its self-encrypted stub). Everything big is anti-emulation.

**What the clean stops look like.** Capturing the last APIs before the stop on 48
samples across 8 families: 18 call NO api at all (detection happens in code - PEB,
CPUID, rdtsc), 12 end in `ExitProcess`, and the Neolite ones all share one tail:

```
GetProcAddress -> MessageBoxA -> LoadLibraryA -> GetProcAddress
   -> ShellExecuteA -> LoadLibraryA -> GetProcAddress -> ExitProcess
```

i.e. "we detected something, show a box, hand off, exit". MessageBoxA returns IDOK
and ShellExecuteA returns 33 (>32 success) in taote, so the trigger is upstream.

**Measured and reverted: the PEB anti-emulation surface.** The PEB image is zeroed
apart from ImageBaseAddress/LdrAddress/ProcessParameters/ProcessHeap/
NumberOfProcessors, so `RTL_USER_PROCESS_PARAMETERS` was an empty blob and the
"heap" a zeroed one - both things packers read (own path for the overlay; heap
Flags = 2 / ForceFlags = 0 as a not-debugged tell). Populating the heap's
Flags/ForceFlags and the parameters' ImagePathName/CommandLine/Length was implemented
and measured on Alienyze + Neolite + PEtite + Themida (414 samples):
**all-three 33 -> 33, oep_exact 54 -> 54, imports 135 -> 132** - no gain and three
imports losses (alienyze_DiskView, alienyze_PsInfo, alienyze_cpuz_x32). The extra
heap allocations perturb the layout the string miners walk, so the change costs
real samples while changing no stub's decision. Reverted.

So PEB self-consistency is not what these stubs test. The next honest probe for the
clean-stop class is instruction-level: find where each family's stub takes its exit
branch (the 18 no-API samples show it happens in code, before any API), which means
a conditional-branch trace around the anti-debug check rather than more environment
plumbing.

### 0.17ak Round 44: the remaining 824 failures, fully classified (a proven ceiling per class)

The plan now has a complete map of what is left, each class measured rather than
estimated. **2594 gradable samples, 824 failures**, split:

| class | n | ceiling / blocker |
|---|---|---|
| OEP wrong (= body not decoded) | **719** | anti-emulation: 581 clean stops, ~138 crashes |
| imports only (OEP already exact) | **105** | 15 ordinal-only, 8 a few names short, 82 data absent |

The 105 imports-only rows, measured by NAMED-only recall (i.e. what recall would be
if the ordinal entries were free):

| named-only recall | n | families | verdict |
|---|---|---|---|
| >= 0.95 | **15** | WinUpack 6, MEW 5, Alienyze 3, MPRESS 1 | blocked ONLY by ordinal values |
| 0.80-0.95 | **8** | Alienyze 5, PEtite 1, RLPack 1, WinUpack 1 | a few names short |
| < 0.80 | **82** | RLPack 65, Alienyze 7, PEtite 5, NSPack 2 | names genuinely absent |

**The 15 ordinal-only rows are not reachable, and that is now proven rather than
assumed.** winupack_FileTypesMan is the exemplar: code_sim is 1.000 (the dump IS the
original program), `imports` misses by exactly its 15 ordinals, and the harvest
reports "image import table harvest: 0 descriptors -> 0 imports" - the packer zeroed
the import directory after its loader resolved it, so the ordinal VALUES exist
nowhere in the image. The names survive as strings, which is why our 225 named pairs
are right; a number has no string form, so nothing in the dump can supply it. The
export database can name the owning DLL (round 40 does) but not the ordinal itself,
and taote's rootfs stub DLLs are synthesized with names only, so the resolved IAT
addresses cannot be mapped back to ordinals either. Recorded as a ceiling.

**The 8 in 0.80-0.95 are Alienyze's, and their missing names are ordinary kernel32
exports** (CreateFileA, CreateThread, EncodePointer, ExitProcess, ExitThread,
CompareStringW, FreeEnvironmentStringsW) - i.e. the payload's own CRT import group,
which the `.alien` store parse (round 28's al_hinted_store port) does not cover. That
is a real, bounded target worth **+5** (the Alienyze rows with an exact OEP), but it
needs the reference's variant coverage improved, not another scan.

**What I deliberately did NOT do.** The quick way to move the imports number is to
attribute every name-like string in the image through the database. That would add
pairs the payload never imports (`kernel32!CreateFileA` because the text appears
somewhere), which is a true fact about the DLL but not about the program - metric
inflation, not recovery. The database stays a fallback for names we actually found
in an import structure.

**So the remaining gap to the reference (1773 -> 1996, 223 samples) lives almost
entirely in the 719 decode failures**, and round 43 pinned their shape: 581 clean
stops (Themida 122/122, Alienyze 116/116, Neolite 91/91, PEtite 44/44, RLPack 98/103,
Yoda-Protector 88/101, TELock 56/101, Amber 43/47) versus ~138 crashes (WinUpack 18
fetch at pc 0x28, Exe32pack 14 write at addr 0x54, TELock 45 fetch). The crashes are
traceable; the clean stops need an instruction-level hunt for each stub's exit
branch, which is the next real unit of work.

### 0.17al Round 45: blob-attribution repair - corpus all-three 1773 -> 1784, imports +68

Round 44's map said Alienyze's CRT import group was a bounded +5 target and that the
names were unreachable by scanning. The scan was never the problem: the names ARE in
the dump, in a bare string blob, and the blob miner attributes them POSITIONALLY -
every name goes to whatever DLL marker preceded it. When the export database says the
assigned DLL does not export the name at all, that guess is provably wrong.

**The repair.** After the harvest, any pair whose name the assigned DLL does not
export is re-owned by the database - but only when EXACTLY ONE of the name's owners
is a DLL the IMAGE itself names. That is much stricter than round 41's rejected
version, which re-owned whenever the assigned DLL was absent from the image's DLL list
and used the database's favourite owner; that one took 0 gains / 3 losses because our
original attribution was often right and the default owner often was not.

The gate needed the full owner list, so `api_db.inc` now carries every owner per name
(comma-separated, priority-ordered) and `api_owners()` returns them; round 39/40's
single-owner `api_owner()` is the first element, so nothing else changed behaviour.

**Offline prediction (named-only recall, before -> after):**

| sample | before | after |
|---|---|---|
| alienyze_procexp | 0.927 | **1.000** |
| alienyze_ADExplorer | 0.818 | **1.000** |
| alienyze_ADInsight | 0.860 | **1.000** |
| alienyze_Procmon | 0.909 | **1.000** |
| alienyze_webhttrack | 0.886 | **0.982** |

The looser variant tried first took webhttrack to 0.474 - that is what the
"exactly one image-named owner" gate is for.

**Measured:**
- Alienyze family (126): all-three 2 -> **8**, imports 20 -> **74**, mean recall
  0.584 -> **0.848**, 0 losses.
- corpus (2678 @85s): all-three 1770 -> **1784**, imports 1975 -> **2043** (+68),
  oep unchanged at 1875. 15 gains (Alienyze 6, RLPack 6, WinUpack 2, MPRESS 1),
  1 loss (jdpack_chglogon, recall 0.9412). Against the last committed baseline of
  1773 the delta is **+11**; the extra 3 are the samples round 41's rejected
  experiment had cost, which this stricter rule returns.
- fair set (200 @300s): 129 -> **131** (alienyze_ADInsight, rlpack_ADInsight), 0 losses.
- suite 593/593.

**Why RLPack gained 6** - worth noting, because round 27 concluded RLPack's imports
were unrecoverable (the payload IAT slots are never written and the stub makes zero
GetProcAddress calls). That is still true of the *slots*; what the database repairs is
the DLL side of names the string miners had already recovered but filed under the
wrong DLL. The names were there, the ownership was not.

### 0.17am Round 46: after the repair, the import side is at its data ceiling

Post-round-45 map: **2594 gradable, 810 failures = 719 OEP-wrong + 91 imports-only**.
Per family headroom (gradable - all-three): Themida 122, Alienyze 110, TELock 101,
Yoda-Protector 101, RLPack 97, Neolite 91, Amber 47, PEtite 44, WinUpack 22, FSG 20,
Exe32pack 15, NSPack 10.

**The 91 imports-only rows split by what they miss.** 26 of them have ordinals as the
majority of their misses; the rest are short by named functions that are absent from
the image. Examples, measured against the original's table:

| sample | recall | misses | ordinals | named | named present in the dump |
|---|---|---|---|---|---|
| rlpack_Procmon | 0.9491 | 22 | 15 | 7 | 3 |
| alienyze_ComIntRep | 0.9450 | 29 | **29** | 0 | 0 |
| mew_procexp | 0.9463 | 28 | 26 | 2 | 2 |
| winupack_HWMonitorPro_x32 | 0.9389 | 28 | 27 | 1 | 1 |
| rlpack_mtinst | 0.9387 | 10 | 0 | 10 | 0 |

**A near-miss cluster I chased and had to abandon, because the evidence evaporated.**
The ordinals are what block the top of that list, and the grader compares
`(dll, "#<N>")` pairs - so the ordinal NUMBERS alone would be enough. Scanning
alienyze_ComIntRep's dump for runs of high-bit dwords found runs of **exactly 29**
twice (0x8f40c, 0xbc654) and **exactly 23** twice, against a sample that misses
exactly 29 ordinals. That looked like the data answering the question.

It is a coincidence. The bytes after the 0x8f7c8 run are UTF-16 strings
("s.t.a.t.i.c", "f.F.b.H", "C.o.n.t.r.o.l. .P.a.n.e.l.\.M.o.u.s.e") - the region is
.NET metadata, where high-bit dwords are ordinary, and the 29/23 counts match only
because a metadata table happens to be that long. Recorded so it is not chased again:
**a dword run whose values merely look like ordinals is not ordinal evidence**; the
real ordinal arrays live behind the import directory the packers zero, which round 44
proved for winupack_FileTypesMan.

**So the remaining import work is exhausted** for these families: 26 of 91 are
ordinal-blocked (no data), and the named remainder is largely absent from the image
(rlpack_mtinst's 10 are all MSVC CRT internals that appear nowhere). What the
database repair bought (round 45: imports 1975 -> 2043) was the part that WAS
recoverable: names present in the dump under the wrong DLL.

The plan's remaining levers are therefore exactly the decode ones from round 43: ~138
crash-based samples (WinUpack 18 fetch at pc 0x28, Exe32pack 14 write at addr 0x54,
TELock 45 fetch) and the 581 clean stops that need an instruction-level hunt for each
stub's exit branch.

### 0.17an Round 47: Alienyze's pick comes from the BOUNDARY pass inside `.alien` (61 samples of headroom, scoped)

Round 45's import repair turned Alienyze from an import problem into a pick problem:
**53 of its samples now have imports + code_sim >= 0.9 and only the entry is wrong**
(the pick worklist grew from 36 to 87 samples, Alienyze 53 of them). Their true-EP
shapes: **crt-thunk 63**, borland 17, msvc-frame 14, other 7 - i.e. mostly
`e8 <rel32> e9 <rel32>`.

**Which rule actually fires.** TAOTE_UNPACK_DEBUG on alienyze_Clockres:

```
[unpack] ladder passA CRT-thunks: 2
[unpack] ladder passB hits=0 first=0x0 last=0x0
[unpack] ladder boundary-thunks in .alien: 1
[unpack] alienyze_Clockres.exe ... oep=0x4257e2 reason=ladder_scan
```

The pick is the **boundary-thunk** pass, and it fires inside `.alien` - the packer's
own name/value STORE, which is data. Code-like signatures there are coincidence. Pass
A saw two CRT thunks (ambiguous, so it declined) and Pass C never got a say.

**What the right answer would be, measured.** Replaying the `c3 e8 <rel32> e9 <rel32>`
scan over the round-39 dumps for Alienyze (87 samples with at least one c3 hit):
taking the **FIRST** hit is the true EP on **58**; the current rule (last validated,
else tail) is the true EP on **0**. That is why the tail preference is wrong here: the
tail hits land in `.alien`.

Corpus-wide the same comparison (samples with 2+ c3 hits, my model of the rule - which
ignores the earlier passes, so it overstates): first-hit would gain **261** and lose
**58** (Alienyze 58 gain / 0 loss, then ~14 each for ASPack, BeRo, EnigmaVB, MPRESS,
Packman, RLPack, UPX). A model, not a measurement - but it says the direction is right.

**Measured and reverted: switching Pass C to first-hit inside the shared ladder.** It
changed nothing observable (alienyze_Clockres still 0x4257e2) because the boundary pass
runs earlier and shadows it. Shipping it alone would be an inert edit, so it was
reverted; the useful change is the ordering, and that has to be a *family seam*:

- `AlienyzePacker::static_oep_from_image` delegating to the shared ladder with the
  boundary-thunk pass disabled (its `.alien` store is not code), which then lets Pass C
  with first-hit preference pick 0x4002/0x7474/0xa71e for the samples above.
- That is ~61 Alienyze samples of headroom (53 pick-only + the 8 already passing
  imports at lower code_sim), the largest single lever left after round 45, and it is
  bounded work rather than open-ended anti-emulation.

### 0.17ao Round 48: Alienyze's ladder seam - corpus all-three 1784 -> 1818 (+34)

Round 47 scoped this and the numbers held. **AlienyzePacker::static_oep_from_image**
now runs the shared ladder with two shaping flags on `PackerContext`:

- `ladder_skip_boundary = true` - the boundary-thunk pass is off, because the
  restored image carries the packer's `.alien` name/value STORE and code-shaped
  signatures inside it are coincidence. That pass was what latched
  alienyze_Clockres' 0x4257e2 (data) and it ran before Pass C ever got a say.
- `ladder_first_c3 = true` - Pass C takes the FIRST `c3 e8 <rel32> e9 <rel32>` hit
  instead of the validated/tail one. Measured over Alienyze's 87 samples with a c3
  hit: first-hit is the true EP on 58, the tail on 0.

Both are opt-in flags defaulting to the previous behaviour, so every other family
keeps the rules it was measured with; the mpress gate around the validated-hit branch
is untouched.

**Measured:**
- Alienyze family (126): all-three 8 -> **43**, oep_exact 17 -> **54**, imports 74 ->
  75, **36 gains / 1 loss** (alienyze_psloglist - C3=2 with a validated hit at the
  second, so the old tail preference was right there; that single case is the price).
- corpus (2678 @85s): all-three 1784 -> **1818**, oep_exact 1875 -> **1912** (+37),
  imports unchanged. 36 gains (all Alienyze) / 2 losses: alienyze_psloglist (real)
  and mpress_ComIntRep at dur=85 (the standing budget flake), so the honest delta is
  **+35** with one known regression.
- fair set (200 @300s): 131 -> **132** (alienyze_Autoruns), 0 losses.
- suite 593/593.

**Where Alienyze now stands:** 43 of 126 all-three (was 2 before round 45), so import
attribution (+68 imports) and this pick fix together took the family from 2 to 43.
The remaining 83 are the `<0.3` code_sim group - bodies that never decode - which is
the anti-emulation class from round 43, not the picker.

**Note for the next pick change:** alienyze_psloglist is the counter-example to keep
in mind. A rule of the shape "prefer the validated hit when the FIRST hit is not
validated" would have kept it while leaving the other 36 gains intact; that is the
obvious refinement if this seam is revisited.

### 0.17ap Round 49: the next Alienyze pick cluster, and a rule I refused to write

After round 48, Alienyze still has 31 imports-ok-but-wrong-OEP rows, 18 of them with
code_sim >= 0.9 (perfect bodies). Their true-EP shapes are the passes our ladder
declines on ambiguity:

| shape | n | truth among the hits? | truth at index / hits |
|---|---|---|---|
| borland (`6a ?? 68 <imm32> e8`) | 7 | yes, every one | **3 of 8** (six samples), 8 of 98 (one) |
| msvc-frame (`55 8b ec`) | 2 | yes | 3 of 8, 452 of 1776 |

Six samples sit at **index 3 of exactly 8 hits**, and one of them is a NirSoft
binary like the rest: the first three matching prologues are other CRT functions and
the fourth is the startup. That is compiler/link ORDER, not a property of the entry
point - a rule of the shape "take hit #4" would convert six samples here and is
exactly the coarse overfitting the round-16 lesson (and the family-detection rule)
forbids. Not written.

The honest options for those 9 need a discriminator that is not positional:

- the reference's Pass E requires only that the pushed immediate is inside the image,
  which all eight hits satisfy, so it cannot separate them either;
- "prefer the validated hit when the first is not validated" (round 48's note) would
  recover alienyze_psloglist but is behaviourally the OLD tail preference for every
  other sample - it would give back part of the 36 gains, so it is not worth +1.

So Alienyze's pick ceiling is reached for now: 43 of 126, with the remaining 83 split
into 83 - 31 = 52 bodies that never decode (the anti-emulation class) and the 31
above whose entries depend on link order.

### 0.17aq Round 50: Alienyze's ladder shaping generalises (+5/-1 on 972 samples), and the structural version does not

Round 48's Alienyze seam is two flags. This round asked two questions about them.

**1. Does the pattern generalise?** With both flags forced on for EVERY family
(`TAOTE_LADDER_SHAPE_ALL=1`, a temporary gate) over 972 samples from the ten families
with pick headroom:

```
all-three 845 -> 849   gains 5 / losses 1
gains : WinUpack 3, BeRoEXEPacker 1, NSPack 1
losses: WinUpack 1
```

Net **+4**, so yes - but a family-agnostic picker change cannot be adopted on a
972-sample subset: the other ~1700 samples (UPX, ASPack, EnigmaVB, EXpressor,
Yoda-Crypter, Eronana, Amber, Neolite, TELock, MEW, Themida, Exe32pack) were never
measured with it on, and every one of those families' current behaviour was measured
WITHOUT it. The honest next step is a per-family gate for the three gainers
(WinUpack net +2, BeRo +1, NSPack +1) validated by a full corpus run.

**2. Can the same rule be expressed structurally instead of by family label?** The
idea: the boundary-thunk pass adds no information when its unique hit is ITSELF a
Pass C hit (`c3 e8 <rel32> e9 <rel32>`) and the section holds more than one - it is
then just a different member of the same family than Pass C's first-hit rule. That is
a property of the bytes, not the family.

Measured (`TAOTE_LADDER_STRUCT=1`) over 1786 samples from 17 families:
**all-three 1574 -> 1573, 0 gains / 1 loss** (bero_ADInsight at dur=86, a timeout
flake). Inert. So the +5 above does NOT come from the overlap case; it comes from
disabling the boundary pass outright and preferring the first c3 hit even where the
boundary hit is unrelated to Pass C - which is exactly the part that needs the
per-family validation in (1).

Both experiments are reverted; the tree is unchanged and the corpus stays at 1818.
The measured lead for the next round is (1): three family gates, +4 expected, one
full corpus + fair-set run to confirm.

### 0.17ar Round 51: the ladder shaping pays on three more families (corpus 1818 -> 1822)

Round 50 measured that forcing round 48's two ladder flags on for EVERY family gains
+5 / loses 1 over 972 samples (WinUpack 3/1, BeRoEXEPacker 1/0, NSPack 1/0, everyone
else neutral or worse) and deliberately did not ship it, because the families outside
that subset were never measured with the flags on.

This round ships the part that was measured. `Packer::static_oep_from_image` now
shapes the ladder for exactly the three families that gained:

```cpp
const std::string fam = ctx.family.empty() && name() != nullptr ? name() : ctx.family;
if (fam == "WinUpack" || fam == "BeRoEXEPacker" || fam == "NSPack") {
    PackerContext shaped = ctx;
    shaped.ladder_skip_boundary = true;
    shaped.ladder_first_c3 = true;
    return ladder_oep(shaped);
}
return ladder_oep(ctx);
```

It is a family label, chosen by measurement — the same basis the detector's own family
decision already rests on. The mechanism is the one round 47 found for Alienyze: these
stubs also leave a packer STORE next to the payload, so the boundary-thunk pass has
code-shaped junk to latch and Pass C's tail preference walks away from the real entry.

**Measured** (1786 samples, 17 families; the gate matches on the family string, so
only the 301 samples of those three families can change and all 301 are in this set):

| scope | before | after |
|---|---|---|
| 17 families | 1574 | **1578** — 4 gains, 0 losses |
| fair set (200 @300s) | 132 | 132 — 0 gains, 0 losses |

Gains: `nspack_cpuz_x32`, `winupack_PsInfo`, `winupack_pskill`, `winupack_psshutdown`.
The BeRo gain round 50 saw (`bero_ADInsight`) does not reappear — in that run its
neighbour lost, so the pair was a coin flip at the budget boundary, not a real win;
with the gate in place BeRo measures 0/0 here.

Fair set neutral because it holds 8 samples per family, 24 of them in the gated
families, and none sat near the pass/fail boundary.

**Corpus confirmation** (2678 samples @85s, /home/jim/runs/r41, report `R41_CORPUS.md`):

| metric | before | after |
|---|---|---|
| all-three | 1818 | **1823** |
| OEP exact | 1912 | **1918** |
| imports | 2042 | **2043** |
| valid PE | 2674 | 2674 |

Five gains, 0 losses: `nspack_cpuz_x32`, `winupack_PsInfo`, `winupack_pskill`,
`winupack_psshutdown` and `mpress_ComIntRep` — the last is the standing `dur=85`
budget flake recovering, so the honest delta is the **+4** the family gate measured,
on top of 1818. WinUpack 74 -> 77 all-three, NSPack 88 -> 89.

### 0.17as The hop-vs-ladder conflict, measured again: the ladder wins 393:4

The five `*_calc`/`*_cmd` pick losses (`winupack_calc`, `nspack_calc`, `molebox_calc`,
`molebox_cmd`, `winupack_cmd`) share a shape: the **hop ledger already holds the true
entry** and the static ladder overrides it with a hit inside the packer's own section
(`.Upack`, `nsp0`, molebox's mangled section names). `winupack_calc` is the clean
example — debug shows `OEP candidate 0x1012d6c (section_hop)`, then `.Upack: C=1 C3=0
valid=0` and the final answer is `0x10266b0`, with `oep_last_hop = 0x1012d6c` (true).

So the question is whether the ladder's override is well-founded. Measured over every
graded r40 row that has both an `oep` and an `oep_last_hop` and where they differ
(515 rows):

| who was right | n |
|---|---|
| ladder | 393 |
| hop | 4 |
| neither | 100 |

The override is not the bug — it is right 99% of the time.

Narrowing to the ladder's **weakest** evidence, a unique `c_count == 1` with
`c3_count == 0` (an unvalidated `e8 .. e9` hit, no CFG thunk): 18 rows, ladder right
**11**, hop right **2** (`nspack_calc`, `winupack_calc`), both wrong 5. Making the
verified runtime hop outrank that weak static hit would therefore **gain 2 and lose
11**, so it is not written. The six hop-right rows are a per-family section-naming
accident (the packer's own section happens to contain one thunk-shaped run), not a
mechanism — the same coarse overfitting round 49 refused for Alienyze's "hit #4".

### 0.17at Round 52: RLPack joins the ladder gate - +7 OEPs on bodies that were already decoded

Round 51 gated three families on the strength of a 10-family measurement and left the
other ten untested. This round closed that gap for the six families that still have
OEP headroom (Amber, Neolite, TELock, RLPack, Eronana Packer, Exe32pack), running the
same two flags on all 740 of their samples:

| family | samples | all-three | oep_exact |
|---|---|---|---|
| all six | 740 | 320 -> 320 (0 gains, 0 losses) | 381 -> **388** |
| RLPack | 104 | 6 -> 6 | 66 -> **73** (8 gains, 1 loss) |
| Amber, Neolite, TELock, Eronana, Exe32pack | 636 | unchanged | unchanged |

So five of the six are exactly neutral and stay on the default ladder; **RLPack** gains
seven OEPs. Its eight gains (`Dbgview`, `PsExec`, `PsGetsid`, `PsInfo`, `portmon`,
`pskill`, `psshutdown`, `pssuspend`) all have `code_sim 1.0` - a fully decoded body -
and lose one (`rlpack_geek`). None converts an all-three row, because RLPack's
remaining block is imports (recall 0.39-0.75 on exactly these samples), not the pick.
That is still worth shipping: the OEP is now right on eight samples whose body is
already right, which is the prerequisite for any future import work on them.

Shipped gate: `WinUpack`, `BeRoEXEPacker`, `NSPack`, `RLPack`.

Corpus confirmation (2678 @85s, /home/jim/runs/r42, report `R42_CORPUS.md`):

| metric | before | after |
|---|---|---|
| OEP exact | 1918 | **1925** (+7, all RLPack) |
| all-three | 1823 | 1822 |
| imports | 2043 | 2042 |
| valid PE | 2674 | 2674 |
| fair set (200 @300s) | 132 | 132 - 0 gains, 0 losses |

The single all-three "loss" is `nspack_procexp.exe` at `dur=85`: it times out
mid-import-mining (recall 0.9463 against a 0.95 bar, `code_sim 0.8999`), and a clean
local re-run rebuilds 942 imports with the same exact OEP, so the honest all-three
delta is **0** — the RLPack OEPs do not convert yet, exactly as the family measurement
predicted. The fair set is neutral for the same reason as round 51: 8 RLPack samples,
none on a pass/fail boundary.

RLPack now stands at **73 of 104 OEP-correct** (66 before) with 6 all-three. The eight
newly-correct samples have fully decoded bodies (`code_sim 1.0`) and import recall
0.39-0.75, so they are 8 potential conversions sitting behind the RLPack import
question that rounds 45/46 pinned as a data ceiling (payload IAT slots never written,
zero GetProcAddress calls).

### 0.17au Round 53: the failure set classified by BYTES AT THE TRUE EP, and RLPack closed with evidence

`code_sim` measures similarity over a whole image and is a poor proxy for "was the
entry decoded". This round classified every graded failure by the direct question: at
the sample's **true EP**, are the dumped 32 bytes identical to the original's 32 bytes?
(Mapping the original's RVA through its own section table; 852 failures with an
`orig_ep` and a readable dump.)

| class | n | families |
|---|---|---|
| ciphertext at the true EP | **503** | Themida 115, Yoda-Protector 94, Neolite 91, TELock 90, Alienyze 35, Amber 43, Exe32pack 7, FSG 8 |
| partial (1-31 of 32 bytes) | 129 | TELock 26, PEtite 26, Amber 22, Exe32pack 12 |
| **decoded (32/32)** | **218** | RLPack 94, Alienyze 43, WinUpack 18, PEtite 17, Exe32pack 13, Eronana 13 |

Cross-tabulating the 218 decoded rows by what actually fails:

| failing criterion | n | families |
|---|---|---|
| pick (imports OK, OEP wrong) | **40** | Alienyze 18, WinUpack 5, Amber 4, PEtite 4, JDPack 4, Molebox 3 |
| imports (OEP exact) | **94** | RLPack 65, Alienyze 11, WinUpack 8, PEtite 6, MEW 3 |
| both | 55 | RLPack 28, Alienyze 14, PEtite 7, WinUpack 4 |

The pick count (40) matches round 49's independent `code_sim >= 0.9` estimate of 43,
so the picker worklist is confirmed at ~40 and is dominated by the Alienyze link-order
cluster that round 49 refused to overfit.

**RLPack stays closed, now with hard evidence.** It looks like the single biggest
convertible block — 93 of its 104 samples are decoded at the true EP and fail only on
imports — so it was worth re-testing rather than trusting round 46's weaker argument.
Extracting the original's full import pair set (hint-byte aware) and comparing with
what taote recovered:

| sample | truth | recovered | recall | missing named | **of those, present anywhere in the dump** |
|---|---|---|---|---|---|
| rlpack_pskill | 122 | 217 | 0.648 | 39 | **0** |
| rlpack_portmon | 291 | 401 | 0.395 | 159 | **0** |
| rlpack_Dbgview | 315 | 405 | 0.400 | 173 | **0** |

**371 missing names, 0 present in the dumped image.** The strings are not there — not
mis-attributed, not behind a bad DLL marker, absent. RLPack's decoder builds the
payload with an import resolver that leaves nothing recoverable, so its 93 decoded rows
are a hard ceiling, not a work item. (Its output is also over-generous: 401 pairs
against 291 true, precision 0.4.)

### The no-API clean stops get a tool

A 240-sample census of the clean-stop failures (30 lowest-`code_sim` per family, 8
families, 25 s budget, `TAOTE_APIDBG=1`) split them sharply:

* **90 of 240 call no API at all** — TELock 30/30, Yoda-Protector 30/30, Alienyze 30/30.
  These bail on an INLINE environment check, so the API log shows nothing.
* 60 end in `MessageBoxA` (the decoy path), 60 in `ExitProcess`, 19 in
  `GetCurrentThreadId`, 10 in `TerminateProcess`.

To see inside the first class, `TAOTE_LASTPC=N` now keeps a ring buffer of the last N
instruction addresses and prints them at finalize (env-gated scaffolding, alongside
`TAOTE_EMBEDDBG`/`TAOTE_SALVDBG`). It confirms the two shapes:

* **TELock** (`telock_cmd`) spins at `0x4ad4a08f..0x4ad4a0a7`, and those bytes in the
  DUMP are ciphertext (`jae/jg/push ss/call/add/adc/outsl/js/...`) — the loop executes
  code the dump never captured, so static reading of the dump cannot recover it.
* **Yoda-Protector** (`yoda-protector_Hash`) spins in an `eb 01 e8` chain at
  `0x41258f..0x4125a7` and the last `[pc]` before the clean stop is `0x70000000` — it
  returns straight into the SEH sentinel, i.e. the AV-handler path round 37's int3
  resumption did not reach.

Both are per-stub reverse engineering, not emulator tuning; the classification above
says so quantitatively (503 ciphertext rows, 390 of them in the four anti-emulation
families).

### 0.17av Round 54: the timing hypothesis for Amber, measured neutral; and the .NET cluster that is not there

The decode class's most obvious emulator-deficiency candidate is the clock: a stub reads
a counter, decodes, reads again and bails if the delta is zero. taote's two counters
made that delta ALWAYS zero:

* `GetTickCount` returned upstream's constant `200000` (unless `Sleep` moved the
  virtual clock).
* `QueryPerformanceCounter` returned 0 and wrote nothing — "the verbatim quirk" the
  port preserves from the reference.

So both were made to advance monotonically (one virtual millisecond per read, derived
from a per-process counter, no host clock), and measured on the family that actually
probes them. The 240-sample census identified it precisely: **Amber is the only failing
family whose clean stops call `QueryPerformanceCounter` and `GetTickCount` (30 of 30)**,
together with `GetStartupInfoA`, `GetSystemTimeAsFileTime`, `GetCurrentProcessId` and
`msvcrt!_initterm` — i.e. the payload's own CRT startup.

Amber family measurement (152 samples, 85 s): **all-three 83 -> 83, OEP exact 83 -> 83,
imports 137 -> 137, 0 gains, 0 losses.** Exactly inert, so the change was reverted
rather than shipped as a deviation from the reference's semantics with nothing to show.

Conclusion: these stubs do not bail on a zero clock delta. Whatever they test, an
advancing tick is not it.

### A trap worth writing down: the third null-vs-false sighting

Amber's 47 wrong-OEP rows include a striking cluster — `jsc`, `RegAsm`, `MacMakeup`,
`DataSvcUtil`, `DatabaseEditor`, `HashCalculator`, `aspnet_compiler` … all with
`code_sim ~1.000`, `imp_recall 1.000`, a claimed OEP near RVA 0x13ef8-0x22e08 and a true
EP near 0x4a0e-0xe00e. They look like a dozen free conversions, and the dump happens to
contain exactly one `ff 25` thunk, sitting precisely at the true EP (the CLR entry stub
of a .NET image; the image imports `mscoree.dll!_CorExeMain`).

They are not conversions. Every one of them has `oep_exact: null` — .NET rows are
ungraded — and `out_ep == orig_ep`, i.e. the rebuilt image's entry is ALREADY correct
even though the claimed OEP is not. Filtering with `o.get('oep_exact') is not False`
(instead of `not o.get('oep_exact')`) makes all fourteen disappear.

That is the third time this session a falsy `null` has invented a cluster (round 52's
"Eronana 13 valid-PE rows at code_sim 1.0" and round 53's first cross-tab both had the
same cause). Any worklist query over the report must test `is False` / `is None`
explicitly.

### 0.17aw Round 55: the adopted heap payload was being thrown away (corpus 1822 -> 1847)

Round 54 left one lead: Neolite never decodes into its own sections, so the payload must
be somewhere else. `TAOTE_HEAPSCAN=1` (new, this round) records every page written
outside the dumped image and looks for an MZ/PE pair there. The answer was immediate and
unexpected — **not Neolite, Amber**:

| family | samples | PE found in heap |
|---|---|---|
| Amber | 10 | **7** |
| Neolite | 10 | 0 |
| Alienyze | 10 | 0 |

And every one of those seven Amber PEs carries `ep == orig_ep` exactly:
`amber_Sysmon` 0x43cc8, `amber_mmc` 0x3fb0e, `amber_ComIntRep` 0x2800a, `amber_PEViewer`
0x1504, `amber_md5summer` 0x9ec68, `amber_ConfigProfile` 0x4434, `amber_Autologon`
0x3980. The payload really is assembled in heap memory — and taote already had the
machinery to adopt it (`adopt_embedded_pe`, the reference's try_embedded_pe), printed

    [unpack] embedded PE at 0x52bbde6 size 0x2bb000 (stub at 0x400000)

and then reported `oep=0x401000 reason=fallback_guess` anyway.

The cause is two lines: `packers::adopt_embedded_pe` replaces the caller's image buffer
with the adopted payload and reports the new base/size, but the BASE `Packer::`
implementation handed it a *copy* and never published it, so the engine's gate
`!actx.adopted.empty()` rejected the find. `AmberPacker`'s override publishes it, which
is why Amber samples whose packer resolves to the Amber class adopted correctly and the
`family=unknown` ones did not. Fixed by publishing the copy on success.

| scope | before | after |
|---|---|---|
| **Amber (152)** | all-three 83, oep 83 | **110, 111** — 27 gains, 0 losses |
| corpus (2678 @85s) | 1822 | **1847** — oep 1925 -> **1952** |
| fair set (200 @300s) | 132 | **133** — 1 gain (Amber), 0 losses |

Corpus gains: **Amber 27**, NSPack 1. Corpus losses: 3, all at the budget boundary —
`packman_HDDScan` (`dur=86`; a clean 400 s re-run gives the exact OEP and recall
**1.0000**), `mpress_ComIntRep` (`dur=86`, the standing flake: 78 s in the previous run)
and `rlpack_procexp` (`dur=85`; 0.9424 at 400 s against 0.9597 in the previous run, i.e.
borderline rather than broken). So the honest delta is **+26 to +27** over the 1823
baseline, not the measured +25.

Note the yoda/neolite/heap idea itself is dead: those stubs write 1-5 pages outside the
image and never build a PE there, so round 53's ciphertext class for them stands.

### 0.17ax Round 56: adopting over a hop, measured and rejected (6 gains, 33 losses)

Round 55's adoption is gated on `hop_ledger_.empty()`. Amber's remaining failures
contain exactly the shape that gate blocks:

| Amber failing rows | n | shape |
|---|---|---|
| embedded_pe, oep null, imports ok | 12 | .NET, ungraded - correct |
| **section_hop, oep WRONG, imports ok** | **7** | a decoy hop shadows the payload |
| fallback_guess, oep wrong, imports bad | 12 | no heap PE found at all |
| section_hop, oep null, imports ok | 9 | .NET |

Three of those seven (`chgport`, `chgusr`, `netcfg`) each **claim the same address
0x401661** - a hop into the stub's own body - while heap memory holds a complete PE
whose `ep` is the true entry (0x4467, 0x3d99, 0x4919). So the gate was dropped and the
scan allowed to run with a hop present (plus a bitness guard: the payload must be the
stub's own PE32/PE32+, because Neolite's dump carries 64-bit helper images).

Amber: 110 -> **113** all-three, exactly the three predicted, 0 losses.

Corpus (2678 @85s): **1847 -> 1820. 6 gains, 33 losses.** Valid PE 2674 -> **2643**,
OEP 1952 -> 1924, imports 2042 -> 2007. The losses are concentrated: ASPack 13, Packman
12, PECompact 5, WinUpack 1, Neolite 1 — families whose stubs MAP THEIR OWN INPUT
(`MapViewOfFile`), so a valid PE really is in memory, and whose hop was already right.

The deeper defect the losses expose is structural, not a tuning issue: adopting replaces
`base_`/`image_size_` while the hop ledger still holds addresses in the OLD base space,
so a sample that adopts and then falls through to the hop pick emits `base = heap-address`
with an OEP from the stub image (`aspack_Dbgview`: base 0x5002774, oep 0x415757) — which
is also why `valid_pe` collapsed. Any future attempt at this must either validate the
adopted EP before mutating the geometry, or translate the ledger.

Both edits reverted; the tree is back to round 55 (1847). The reject-the-input-file test
(compare a candidate's first 4 KB against the packed file's) was implemented and did NOT
fire on the ASPack candidate, so "it is just the mapped input" is not the whole story
either - that is where a future attempt should start.

### 0.17ay Round 57: plan item 3 closed - there is no MEW LZMA failure, the residue is ordinals and one budget row

PLAN_UNPACK has carried "MEW LZMA completion/finalize (8 samples)" as priority 3. It is
stale on both counts: MEW now has **five** failures, and none of them is an LZMA
finalization problem.

| sample | corpus `dur` | OEP | recall | missing pairs |
|---|---|---|---|---|
| mew_Bginfo | 86 | exact | 0.9384 | 53, **all ordinals** |
| mew_ComIntRep | 85 | exact | 0.9013 | 52, all ordinals |
| mew_Sysmon | 86 | exact | 0.9053 | 25, all ordinals |
| mew_adwcleaner_7.2.4.0 | 87 | exact | 0.9370 | 38 = 35 ordinals + 3 named |
| mew_procexp | 85 | exact | 0.9501 | 26, all ordinals |

All five are at the budget boundary (85-87 s), all five have the exact OEP and a fully
decoded body, and every one fails only the import criterion. Clean 400 s re-runs
reproduce the same answers, so the run is not truncating arbitrarily - except for
`mew_procexp`, whose clean recall is **0.9501**, i.e. it passes the 0.95 bar and its
corpus failure is purely the 85 s timeout (recall 0.9463 in the run). That is the
standing budget-flake family, not an accuracy defect.

The other four are the ordinal ceiling, and it is structural, not a harvester bug: the
payload's own import directory in the dump is destroyed (`mew_procexp`: IMAGE_DIRECTORY
ENTRY Import at RVA 0x3a4867 with size 0x14, a single descriptor, **zero** thunks), so
the ordinal values cannot be read from a descriptor chain that no longer exists. The 26
ordinal pairs taote does report come from the ordinal-vote rule of round 40 applied to
the string miners' tables - all the recoverable evidence there is.

So priority 3 is closed: nothing in the LZMA path is missing, and the remaining MEW
headroom is 1 budget flake plus 4 rows behind the corpus-wide ordinal data ceiling.

### 0.17az The throughput lever is measured: the corpus is not timeout-bound

The standing note from round 13 scopes a "throughput restructure" (dispatch_trace at
174 ns/insn, ~86% of taote's overhead). The MEW rows above are all boundary rows, so it
was worth asking how much of the corpus the 85 s budget actually costs:

| failure duration | graded failures |
|---|---|
| < 30 s | **678** |
| 30-59 s | 34 |
| 60-83 s | 3 |
| **>= 84 s (boundary)** | **32** |

Of those 32, only 13 have the OEP already exact, and their median import recall is
**0.044** — i.e. most boundary rows are not truncated successes, they are genuinely
failing runs that happen to burn the budget.

So even an infinite speedup would convert at most ~32 samples, and realistically a
handful. The 747 graded failures are decode-bound (503 ciphertext at the true entry,
round 53) and import-bound (ordinal ceilings), not time-bound. A throughput restructure
is therefore NOT the next lever, whatever its absolute speedup, and the instruction-budget
removal stays blocked for the reasons round 15 measured.

### 0.17ba Round 58: Exe32pack's "valid-PE rebuild" item is closed; its residual is a stub-internal dispatch

PLAN_UNPACK item 2 lists "Exe32pack valid-PE rebuild". Closed: **124 of 124 samples
produce a valid PE** (round 34's zeroed-section-table restore did it). Exe32pack now
stands at 92 all-three, 107 graded (17 .NET), so 15 rows remain and every one fails BOTH
criteria (`oep_bad` + `imp_bad`), all at `dur = 0` — they are clean, fast, wrong.

The shape is the same one round 44 recorded, and it is inside the stub, not the emulator:
`TAOTE_LASTPC` shows the last instructions before `UC_ERR_WRITE_UNMAPPED` on
`exe32pack_bzip2` are a call through a function-table pointer followed by a store into
the structure that pointer belongs to:

```
41781b: push $0x40
41781d: call *(%esi)          ; dispatch through the stub's own vtable
41781f: mov %eax,-0x4(%ebp)
...
4178a0: mov %eax,0x14(%esi)   ; <- faults: esi == 0x40, so this writes 0x54
```

`esi` is `0x40` — a size, not a pointer — so the caller handed the dispatcher its own
argument in the structure slot. That is stub-internal data flow, and the sequence of API
calls before it (`VirtualProtect` x5, `GetModuleHandleA`, `GetProcAddress` x4,
`LocalAlloc` returning 0x418304 then 0x50007ec, `RtlZeroMemory`) offers no obviously
wrong return value to blame.

So Exe32pack's remaining 15 join the anti-emulation class: not a parsing defect, not a
pick defect, and not a PE-rebuild defect.

### Build layout note

While this round was running, a parallel change in this repo renamed the unpacker target
`tools/taote_unpack.cpp` -> `tools/taote.cpp` (target `taote_unpack` -> `taote`), which
makes `cmake --build . --target taote_unpack` fail with "No rule to make target" while a
piped `grep " error"` hides it — a stale binary then gets used for a measurement. The
committed unpack code builds cleanly under the new name (`cmake --build . --target
taote`), and the corpus harness must be pointed at `build/tools/taote`.

### 0.17bb Round 59: adoption-over-hop, third attempt, and the discriminator question is answered NO

Round 56 tried letting the heap-payload adoption run even when a hop exists: 6 gains,
33 losses. It named the defect (the adoption moved `base_`/`image_size_` and only then
validated the entry, so a rejected candidate still left the engine on the heap while the
hop pick emitted a stub-image OEP) and named the missing piece: a discriminator between
a decoy hop that shadows a heap payload and a real hop that already found it.

This round fixed the structural defect properly and tried the discriminator the data
suggested.

**Fixed (both are correct and were kept through the experiment):** the candidate's entry
is now read out of the candidate BEFORE any geometry is mutated, and a committed
adoption outranks the hop pick (`adopted_ep` suppresses `pick_oep`), because the ledger's
VAs belong to the old base space. With these, an adoption can no longer half-commit.

**The discriminator, measured:** a hop that lands very early cannot be a decoder's
product — `amber_chgport`/`chgusr`/`netcfg` claim 0x401661 at write **#25/#25/#24**,
while real landings come after the decoder's work (`aspack_Dbgview` #114955,
`packman_Sysmon` #709491, `amber_pipelist` #188547). Gating the scan on
"latest hop < 4096 writes" gave:

| scope | result |
|---|---|
| Amber (152) | 110 -> **113**, exactly chgport/chgusr/netcfg, 0 losses |
| corpus (2678) | 1847 -> **1819** — 4 gains, **32 losses** |

The 32 losses are not boundary rows: **UPX 5 and Yoda-Crypter 8 at `dur=0`**, PECompact 7,
RLPack 5, Neolite 1, plus boundary rows in NSPack/WinUpack. The reason is now clear and
worth recording: UPX and Yoda-Crypter hop EARLY BY DESIGN (their decompressor runs after
the hand-off), so "few writes before the hop" does not mean "decoy". And the deeper
finding — a complete PE with a validating entry exists in memory for UPX, Yoda-Crypter,
PECompact, RLPack, ASPack and Packman too, and is NOT the payload (aspack's entry 0x45d4
against a true 0x15757; packman's 0x1c058 against 0x43cc8) — means "valid PE in memory"
carries almost no evidence on its own.

So the empty-hop gate is doing real work, not being lazy. Reverted; corpus back to 1847.

**Do not retry this without a discriminator that is grounded in where the payload came
FROM** (e.g. establish which allocation the stub copied the image into, or require the
candidate's bytes to be a superset of the decoded section contents) rather than in the
candidate's plausibility. Three attempts — plausibility-only (56), entry-validation (59),
hop-timing (59) — have each measured negative.

### Tree note

While this round ran, the parallel workstream moved into the import path itself
(`qiling/unpack/iat/iat_search.*`, `iat/import_rebuilder.*`, `unpack.hpp`), so a corpus
run started now measures their changes as well as mine. The 1847 baseline is the r43
measurement, taken before that work, and any later delta needs the `git status` checked
first.

### 0.17bc Round 60: where the anti-emulation stubs actually RUN - and it is not out of image

Round 59 concluded that any future adoption work needs evidence about where the payload
comes FROM. The cheapest form of that evidence is execution: if a stub decodes its
payload into another region, it must also JUMP there. `TAOTE_LASTPC=64` records the last
64 instruction addresses; comparing them against `[base, base + dump size)` answers it
directly (10 lowest-`code_sim` failures per family):

| family | samples | executed outside the image |
|---|---|---|
| Themida | 10 | **0** — all in-image |
| TELock | 10 | **0** — all in-image |
| Neolite | 10 | **0** — all in-image |
| Yoda-Protector | 10 | **10** — but only at 0x70000000 |

So for the three biggest ciphertext-at-entry families (Themida 115, TELock 90, Neolite 91
rows) **the payload is never executed anywhere else**: the decoder simply never runs, and
there is nothing to capture. Every "dump the other buffer" idea — heap scan, embedded-PE
adoption, shadow region — is closed for them by this measurement, not by an argument.

Yoda-Protector is different, and the difference is instructive. Its stubs DO leave the
image, but only into the SEH sentinel page, and the trace says why:

```
[sehd] code=80000003 fault=4125fc pc=4125fc chain=ffffcff0 next=0     handler=412563
[sehd] code=80000003 fault=4125fc pc=4125fc chain=ffffcfd0 next=ffffcff0 handler=412570
[sehd] code=80000003 fault=41263f pc=41263f chain=ffffcfb0 next=ffffcfd0 handler=41257d
[sehd] code=80000003 fault=41263f pc=41263f chain=ffffcf90 next=ffffcfb0 handler=41258a
[fault] access=24 addr=0x70000000 pc=0x70000000
[sehc] ret=0 frames=0 walk=0xffffcf90 ctx=0x70004100 esp=0xffffcf80 eip=0x70000000
```

`0x80000003` is STATUS_BREAKPOINT: the protector raises its own int3s and walks FOUR
registered handlers (0x412563, 0x412570, 0x41257d, 0x41258a), each of which answers
**ret=0 = EXCEPTION_CONTINUE_SEARCH**, so the chain exhausts, round 37's int3 resumption
loads pc+1, and the walk continues into the sentinel page byte by byte (addr
0x70000000, 0x70000001, 0x70000002, ...) until the fetch finally faults.

So Yoda's 101 rows are not a decode or a heap problem at all: they are its own SEH/int3
protocol, where the protector's handlers decline the breakpoint that the protector
itself raised. Whether that is taote mis-reporting the exception to those handlers (code,
flags, or the CONTEXT the handler reads) or the handlers genuinely requiring an
unimplemented disposition is the next question for that family - and it is a contained
one: 4 handler addresses, one exception code, one loop.

One more step was taken on Yoda and it stops there: those four handler addresses point
into an obfuscated `eb 01 / e9 <rel32>` ladder, not real code —

```
412563: jmp 412566      ; eb 01
412565: jmp 41a857      ; e9 e8 82 00 00
412570: jmp 412573
412572: jmp 41de64
41257d: jmp 412580
41257f: jmp 41d171
```

so the handlers themselves are encrypted and reading them statically is useless, exactly
as with TELock's dump. Chasing Yoda further means runtime tracing of the decrypted chain,
which is a much larger piece of work than a measured round and is not started here.

### 0.17bd Round 61: Themida allocates, never decrypts, and exits on purpose

Round 60 established that Themida/TELock/Neolite never execute outside their own image.
This round asked what their image actually contains at the end, and what the stub's last
instructions are.

**The image is mostly untouched.** The true-EP page of the dump, 8 Themida samples:

| sample | dump | true-EP page |
|---|---|---|
| themida_7z | 0x6c4000 | 100% zeros |
| themida_ADInsight | 0xb83000 | 100% zeros |
| themida_AccessEnum | 0x6c5000 | 100% zeros |
| themida_Autoruns | 0x80a000 | 100% zeros |
| themida_BatteryInfoView | 0x6fb000 | 100% zeros |
| themida_Bginfo | 0xb1c000 | 100% zeros |
| themida_ADExplorer | 0x769000 | entropy 7.94 (encrypted) |
| themida_Autologon | 0x730000 | entropy 7.94 (encrypted) |

The dumps are 2-3x the packed files and share 0.1-1.7% of their 64-byte blocks, so the
engine really is holding a fresh `SizeOfImage`-sized image - one the stub allocated and
then left zero-filled at the entry, with a couple of pages encrypted.

**The stub exits on purpose.** `TAOTE_LASTPC` on `themida_Bginfo` ends in a textbook
epilogue, not a fault:

```
713d32: add  $0x27,%edx
713d38: movl $0x0,(%edx)
713d3e: pop %edi; pop %esi; pop %ebp; pop %ebx; pop %edx; pop %ecx; pop %eax
713d45: popf
713d46: ret  $0x0
```

So Themida's run ends because the protector returned from its own dispatch code after
storing a zero - a voluntary exit, exactly the "detected and bail" shape the census found
for the whole class, and consistent with the decoders never running. There is no point in
that sequence where a decoder half-finished; nothing was attempted.

That makes the three biggest ciphertext families one problem, not three: an
environment check that taote answers wrongly, early, before any decoding. Finding it
needs whole-run tracing of the stub (millions of instructions to find one branch), which
is a research task rather than a measured round - and the round-43 PEB surface and
round-54 clock experiments already rule out the two cheapest suspects.

### 0.17be Round 62: the RDTSC a protector reads is a CONSTANT - and the shim that would fix it does not take

Round 61 left "an environment check answered wrongly, early" as the shape behind the three
biggest ciphertext families. The inline probes that leave no API trace are CPUID and
RDTSC, so a `UC_X86_INS` hook (`TAOTE_CPUIDBG`) was added to log them. Note for whoever
re-adds it: `UC_X86_INS_CPUID` is an ENUM VALUE, not a macro, so `#ifdef` around it is
always false and the hook silently compiles to nothing — include `<unicorn/x86.h>` and
test for the strings in the binary.

What it shows, over the five anti-emulation families:

| family | cpuid | rdtsc |
|---|---|---|
| Themida (themida_Bginfo) | 0 | **2, both at pc 0x720edc** |
| TELock, Neolite, Alienyze, Yoda-Protector | 0 | 0 |

And the value unicorn hands the stub is **constant**, not merely jittery: reading
`eax:edx` at the second occurrence (the first occurrence's result) gives
`0x9812de0000000a` on every one of three runs, byte-identical. So a protector that asks
"did the clock advance between two reads?" always sees a delta of **zero** - the standard
emulator fingerprint, and exactly the shape round 54 tested at the API level (GetTickCount
/ QPC), where it measured inert.

**The shim, and why it is not shipped.** Unicorn exposes no TSC control (`UC_CTL_*` has
nothing for it) and the `UC_HOOK_INSN` trampoline returns `void`, so the instruction
cannot be skipped. The approach tried: the INSN hook learns the pc, installs a paired
code hook at `pc + 2` (RDTSC is 2 bytes), and that hook overwrites `eax:edx` with a
monotonically advancing virtual TSC seeded from the first real value. It runs - the
callback fires at 0x720ede with the pending flag set - but **the register write does not
survive to the next read**: the second RDTSC still sees `0x9812de0000000a`. Either
unicorn restores the register file across the hook boundary, or the stub saves/restores
the pair around the read (which would make the delta comparison itself pointless for it).
Unresolved, so nothing shipped; the tree stays at the shipped 1847.

Worth noting for the next attempt: with the TSC constant and only TWO reads, a delta
comparison is not obviously what this stub does at all - the two reads sit at the same pc,
which is more like "read until it changes" (a spin) than "measure an interval".

### 0.17bf Round 63: the RDTSC shim failed for a stub reason, not an engine one - and the semantics are now a test

Round 62 left one ambiguity: its shim fired but its register write "did not survive to the
next read". Two explanations were open - the engine restores the register file across the
hook boundary, or the stub does something of its own.

Answered, with a new regression test
(`CoreHooks.RegisterWriteInCodeHookReachesNextInstruction`): a register written inside a
`UC_HOOK_CODE` callback **is** visible to the next instruction. The test is deliberately
minimal - `mov eax, 0x11111111` then a hook at the following `nop` that writes EAX, then
`uc_reg_read` - so it pins the ordering unicorn gives us (a code hook for an address runs
BEFORE that address executes) rather than any unpack plumbing. Suite is 594 tests.

So the engine is not at fault, and the round-62 shim's failure is a property of
themida_Bginfo's own code: the stub must save/relocate `eax:edx` around the read before it
compares them. That also explains the shape - two RDTSC at the SAME pc returning the same
constant, which is a "read it twice / restore and re-read" pattern rather than "measure an
interval between two reads".

Consequence for the plan: writing a plausible TSC into those registers cannot help unless
the value is what the stub actually carries forward. Patching the instruction instead
(rewrite `0F 31` in guest memory, or trap it as `int3` and emulate in the SEH #BP path of
round 37) would sidestep the save/restore, and is the next concrete idea for that family -
but it needs the patched page to survive the protector rewriting its own code, which
Themida does, so it is not a small change.

Note on the earlier test-writing trap, since it cost a cycle: `A3` is the 64-bit
`mov moffs64, eax` form and faults with UC_ERR_WRITE_UNMAPPED in an x86-64 engine; the
absolute-disp32 store is `89 04 25 <disp32>`.

### 0.17bg Round 64: refreshed classification after the Amber gain - the picker worklist is 41 rows, not 144

Priority 1's standing instruction is to re-run the by-first-failing-criterion
classification. Round 53 did it before round 55 shipped +27 Amber samples, so here it is
again on the current clean report (`/home/jim/runs/r43`, 1847), now also split by whether
the dumped bytes at the TRUE EP match the original's (the round-53 body test):

| criterion | rows | of which decoded | of which ciphertext |
|---|---|---|---|
| pick (imports OK, OEP wrong) | 144 | **41** | 103 |
| imports (OEP exact) | 105 | 94 | 11 |
| both | 498 | 54 | 444 |
| **total** | **747** | **189** | **558** |

The headline is the first line. "Pick" looks like 144 samples but **103 of them are
ciphertext at the entry** - Neolite alone contributes 78, whose imports pass only because
they come from the packer's own store (round 42). The real picker worklist is **41
decoded rows**: Alienyze 18, WinUpack 5, Amber 4, JDPack 4, PEtite 4, and the rest single
samples. That is the same 40-row figure rounds 49/53 arrived at by two other routes, and
round 49 already measured that its Alienyze cluster is link order rather than a rule.

So priority 1 is conclusively capped: 41 rows, 18 of them the documented Alienyze
link-order cluster, and no unexplored family left in that class.

Where the mass actually is, by body state:

| class | rows | biggest |
|---|---|---|
| ciphertext at the true EP | **558** | Themida 122, TELock 100, Yoda-Protector 98, PEtite 23, FSG 20, Alienyze 19, Exe32pack 15 |
| decoded, import-only | 94 | RLPack 65 (data ceiling), Alienyze 11, WinUpack 8, PEtite 6, MEW 3 |
| decoded, pick-only | 41 | Alienyze 18 |
| decoded, both | 54 | RLPack 26 |

Every one of those columns now has a measured reason why it is stuck: RLPack's 91 rows are
a data ceiling (371 missing names, 0 present in the dump), the import-only rows are the
ordinal ceiling (payload descriptor chains destroyed), the pick rows are link order, and
the 558 ciphertext rows are the anti-emulation class whose decoders demonstrably never run
(rounds 60-63). Nothing in this table is unexplored; the remaining work is stub-level
reverse engineering of four protectors.

### 0.17bh Round 65: a mechanical lead in FSG's 20 failures - a scrambled section table

The refreshed classification (round 64) leaves FSG as the one non-protector family with a
double-digit ciphertext block: 20 rows, all `dur=0`, `code_sim` 0.08-0.26, import recall
~0.00-0.03, and all with the OEP wrong. FSG is a trivial decompress-in-place packer, so
that shape is suspicious. What the probes show:

* `fsg_HashCalc`: the run executes **four instructions**, makes **zero** API calls, and
  ends `stages=0 reason=fallback_guess`. The packed EP is 0xab000 and execution stops
  exactly there - but the bytes at that address in the DUMP are not the stub: they are
  `4d 5a 90 00 ...`, i.e. a PE header (the packed file's own).
* The stub's real code (`bb d0 01 40 00` = `mov ebx, 0x4001d0`) appears in the dump at
  offset **0xe00** - which is exactly its *file* offset, not its RVA.
* And the packed file's section table is scrambled in a way FSG is known for: three
  sections with `ro` values 0x0, **0x1000**, **0x0e00** - non-monotonic and overlapping
  (section 2's raw data starts *before* section 1's), with section 1 having `rs=0x28558`
  from `va=0x82000`.

So the most likely story is a mapping defect for non-monotonic raw offsets, not a
protector: the stub is placed at the wrong RVA, executes into a data page, and stops.
75 of 97 FSG samples have sane tables and pass, which fits.

Not yet proven, and recorded as such: the next step is to compare the engine's per-section
mapping against the packed table on `fsg_HashCalc` (and on a passing FSG sample) and see
whether the `ro`-ordering is honoured, then decide whether the loader should clamp or sort
raw offsets when a packed table is deliberately unsorted. That is a bounded, mechanical
change on a family with 20 rows, unlike the protector work.

### 0.17bi Round 66: FSG's entry section is DROPPED BY LIEF - and the obvious repair is unsafe

Round 65's lead proved real, and the mechanism is now pinned:

* `fsg_HashCalc`'s section table is `(va 0x1000, rs 0)`, `(va 0x82000, rs 0x28558,
  ro 0x1000)`, `(va 0xab000, rs 0x200, ro 0xe00)` - the third entry's raw pointer goes
  **backwards** relative to the second's.
* **LIEF reports only the middle section.** A debug print of every section LIEF yields for
  that file lists exactly one (`va 0x82000`); the entry section at 0xab000 is absent. The
  engine therefore never maps the stub, the packed EP 0xab000 executes into whatever is
  there, and the run dies after four instructions with no API calls.
* The passing samples have a monotonic table (`fsg_Bginfo`: ro 0x400 then 0x200 is fine
  because 0x200 is inside the header block and 0x200 < 0x400 is *aligned* at
  FileAlignment 0x200), which is why 75 of 97 FSG samples work.

Two repairs were tried and measured:

1. **Map every section from the raw file instead of `section.content()`.** FSG's own
   family measurement looked good - OEP 75 -> **84**, 0 losses - but corpus-wide it is a
   catastrophe: **1847 -> 1711, 140 losses** (NSPack 90, WinUpack 37, BeRo, Molebox,
   RLPack). Those families *depend* on LIEF's content, so the wholesale replacement is
   out.
2. **Supplement only for sections LIEF never mapped.** Still broken, for a subtler reason:
   FSG's FileAlignment is 0x1000, so its `ro = 0xe00` is *unaligned*, and the loader's
   existing FileAlignment rule ("an unaligned raw pointer means the stub is hidden in the
   page overlap" - the NSPack/WinUpack trick) claims it first and maps the wrong page.
   Excluding unaligned pointers from the supplement restores NSPack
   (`nspack_cmd` back to 0x4ad0829a) but also excludes exactly the FSG case.

So the discriminator cannot be "is the raw pointer aligned" - LIEF's *dropping* and the
loader's *page-overlap* rule both look at the same unaligned pointer and mean opposite
things. What distinguishes them is whether LIEF reported the section at all: the supplement
must fire when LIEF omitted it **and** the section is the one holding the packed EP, and it
must map `ro..ro+rs` rather than the aligned page. That is the next change to try, with
`fsg_HashCalc` (EP 0xab000, ro 0xe00, FileAlignment 0x1000) as the regression and
`nspack_cmd` (EP-side stub at ro 0x1a9, FileAlignment 0x200) as the guard.

Both repairs reverted; corpus back to 1847.

### 0.17bj Round 67: FSG's page-below rule - the two-line discriminator, measured clean (+9 OEP)

Round 66 left the fix scoped as "the supplement must fire when LIEF omitted the section AND
it holds the packed EP", and two broader versions had measured badly. The actual cause is
one line earlier than that, and the discriminator is PE semantics rather than LIEF
bookkeeping:

the loader's **page-below rule** ("an unaligned PointerToRawData means the stub hides in
the page overlap", written for NSPack/WinUpack) fired for FSG too, because fsg_HashCalc
declares its entry section at `ro = 0xe00` and `FileAlignment` is 0x1000. It therefore
mapped the *header page* over the stub - `MZ\x90\x00` at RVA 0xab000 - and the packed EP
executed into data. But a page-below rule only makes sense when **FileAlignment <
SectionAlignment**; when they are equal there is no sub-page padding to compensate for and
the declared pointer is honest. FSG has both at 0x1000; NSPack (0x200/0x1000) and WinUpack
(0x200/0x1000) keep the rule.

```cpp
const auto section_align = ...section_alignment();
if (file_align != 0 && file_align < section_align && raw_ptr != 0 && (raw_ptr % file_align) != 0 && ...)
```

Only 132 of 2677 corpus samples have `FileAlignment >= SectionAlignment` (EnigmaVB 16,
Themida 16, FSG 15, Yoda-Crypter 15, Molebox 14, Alienyze 13, Yoda 13, Eronana 11, JDPack
10, Neolite 9), so the blast radius is bounded by construction.

**Measured as a clean A/B on one tree** (the repo currently also carries another
workstream's import-path changes in `qiling/unpack/iat/*`, which move the baseline, so
r48-vs-r49 is a same-tree pair rather than a comparison against round 55's number):

| run | guard | all-three | OEP exact | imports |
|---|---|---|---|---|
| r49 | off | 1843 | 1953 | 2033 |
| r48 | **on** | 1843 | **1962** | 2033 |

**+9 OEP, exactly FSG, zero all-three movement and zero regressions.** The nine FSG
samples get the right entry but still fail imports, so nothing converts yet - the FSG
`both` class is now a decode-and-import problem rather than a mapping one.

Fair set (200 @300s): 133 -> 132, the single loss being `rlpack_ADInsight`, which fails in
BOTH arms of the A/B, i.e. it belongs to the other workstream's changes, not this one.

**Baseline note:** the corpus baseline is now **1843**, not 1847, because the parallel
import-path work is in the tree; my change is measured against r49 and moves OEP 1953 ->
1962 with all-three unchanged.

### 0.17bk Round 68 (FSG): the decoded string run keeps FSG's +3 first-char shift - block-level vote (+7 all-three)

Round 67's loader fix made FSG's payload decode: 15 of its 22 failures went to
`code_sim 1.000`. That exposed the next block, and it is not a picker or a decoder problem:

* the decoded image carries FSG's bare string run (`ADVAPI32.dll`, `MSVCRT.dll`, then
  `b_mb_cur_max`, `bisctype`, `iopen`, `wolower`, `sutc`, `bpctype`, `igets`, `vtrerror`,
  `iflush`, `iclose`, `uealloc`, `jetchar`, `dbort`, `ytrncpy`...) - i.e. every stored
  import name has its FIRST character shifted by +3 (`_exit` -> `bexit`, `malloc` ->
  `falloc`, `tolower` -> `wolower`);
* the miner DID find them (8 groups, 2 dlls, **128 names**) and still scored recall 0.03,
  because it emitted the shifted spellings - the evidence-backed undo written for the
  INT-table path in round 39 was never applied to the string-group path;
* the per-name undo alone recovers only the names the export database carries
  (`fopen`, `tolower`, `putc`...), leaving `bisctype`, `bpctype`, `b_mb_cur_max` because
  `_isctype`, `_pctype`, `_mb_cur_max` are CRT internals mingw does not export.

So the shift is treated as a property of the **string run, not of a name**: if the
evidence backs the shift for more names than it contradicts, every unknown name in that
block is shifted. `block_is_shifted` / `block_name` implement exactly that, and the block
then reads `_isctype`, `_pctype`, `fopen`, `tolower`, `strerror`, `fflush`, `_exit`.

**Measured:** FSG family all-three 75 -> **82**, imports 75 -> 85, 0 losses. Corpus
1843 -> **1850** (+7, all FSG), imports 2033 -> 2043, OEP unchanged at 1962, 0 losses.
Fair set (200 @300s): 132 -> **133** (`fsg_Cacheset`), 0 losses.

FSG now: **82 of 97**, and its remaining 15 are 6 decoded-but-wrong-OEP, 2 import-only
(`DarkNamer` 0.208, `adrestore` 0.848), 5 still ciphertext (`calc`, `cmd`, `dfrgui`,
`ftp`, `mtinst` - all claiming an OEP in a *different base*: 0x1106f67, 0x4ad4a350,
0x1090aa0, 0x10110f0, 0x10aaa8e) and 2 ungraded (`Snap2HTML`, `livekd`).

### 0.17bl Round 69 (FSG): the last 15, classified per sample with evidence

FSG is at **82/97** (75 before this session's two fixes). The remaining 15 fall into four
groups, each now measured rather than guessed:

**A. Five still ciphertext - these decompress to a HARDCODED 0x400000, and that is not a
mapping bug we can paper over.** `fsg_calc`, `fsg_cmd`, `fsg_dfrgui`, `fsg_ftp`,
`fsg_mtinst` all declare a base that is *not* 0x400000 (0x1000000 / 0x4ad00000), and all
five fault on their FIRST store at exactly **0x401000**:

```
fsg_calc      base=0x1000000  fault write 0x401000 pc=0x113e022
fsg_cmd       base=0x4ad00000 fault write 0x401000 pc=0x4ad61022
fsg_dfrgui    base=0x1000000  fault write 0x401000 pc=0x10ed022
fsg_ftp       base=0x1000000  fault write 0x401000 pc=0x1016022
fsg_mtinst    base=0x1000000  fault write 0x401000 pc=0x113d022
```

The instruction is FSG's LZ `movsb` loop, so the destination pointer is 0x400000-based
regardless of the declared base. Two repairs were tried and both failed: a zero-filled
alias at 0x400000 (the stub then reads zeros as its compressed source and runs away), and a
populated alias (same runaway, fault moving to 0xffffe000), and forcing the load base to
0x400000 breaks the process layout ("Requested memory is unavailable", base ends 0x0). The
decoder's own bit-loop has to be understood before this moves - it is FSG-specific, not a
loader rule.

**B. Six decoded with the WRONG OEP - and the truth IS a ladder candidate, chosen by link
order.** `TAOTE_LADDERDUMP=1` (new) prints every Pass-B offset. For `fsg_HashCalc` the true
entry **0x11e58 is hit #68 of 84**, in a list that is mostly a 16-byte-stride table
(0x8b00..0x91a0) plus ~25 real `55 8b ec` frames. Pass C then overrides with a validated
thunk (claim 0x462bf8). That is the same link-order ambiguity round 49 refused to encode for
Alienyze: the right value is present, and nothing in a single sample says which candidate is
"the entry".

**C. Two import-only rows.** `fsg_DarkNamer` (recall 0.216) and `fsg_adrestore` (0.848).
DarkNamer's decoded run IS shifted (`bcontrolfp`, `bwcmdln`, `bXcptFilter`, `bonexit`,
`zcscpy`) and the block vote handles those, but its C++ MANGLED imports (`B?1type_info@@UAE@XZ`,
`B?0exception@@QAE@ABV0@@Z`) need the shifted first character to be `?`, which the vote
rejected as non-alphanumeric. Extending the shift to accept `?` measured **neither gain nor
loss** (82 -> 82, DarkNamer 0.208 -> 0.216), so it was reverted rather than kept as
unmeasured risk - the mangled names are not what those rows are missing.

**D. Two rows LIEF cannot parse at all.** `fsg_Snap2HTML`, `fsg_livekd`: the run ends
`stages=0 reason=input_parse_failed error=LIEF parse failed` on the INPUT file, so nothing is
loaded and both count as invalid PE. This is the same LIEF weakness as FSG's section table
(section A/B of round 66), one level up: it rejects the whole file. A self-parsed fallback
loader would be needed; that is a different, larger piece of work.

**A, resolved: those five are BROKEN PACKED FILES, and the stub's prologue proves it.**
Disassembling `fsg_calc`'s entry section (`ro 0x200`, VA 0x13e000) shows hardcoded absolutes:

```
113e000: mov ebx, 0x4001d0     ; compressed-stream / output marker
113e005: mov edi, 0x401000     ; DECOMPRESSION DESTINATION - hardcoded 0x400000 base
113e00a: mov esi, 0x11052e8    ; bit stream, 0x1000000-based (this file's declared base)
```

The stub's *data* pointers are 0x400000-based while its own image is loaded at 0x1000000, and
the first `movsb` faults at `edi` before a single API call. On Windows the same file would
load at the header's 0x1000000 and fault at the same instruction, because nothing has mapped
0x401000 - so these five are packer output that cannot run, not an emulator deficiency.
Recovering them would mean re-implementing FSG's LZ stream statically (the bit loop is
visible: `movsb` with a `call *(%esp)` bit reader), which is a new decompressor, not a fix.

**FSG therefore stands at 82 of 97, and that is its ceiling without a static decoder.** The
15 remaining: 5 broken inputs (above), 6 link-order OEPs whose truth is present but
indistinguishable per sample, 2 import-only rows whose missing names are mangled-C++ CRT
imports, and 2 files LIEF refuses to parse at all (`input_parse_failed`).

### 0.17bm Round 70 (FSG): the family is closed at 82/97 - every remaining row is at a named ceiling

The mangled-name shift closes the last spelling gap, and the two "import-only" rows turn out
to be **ordinal-capped**, not misspelled. Per-row evidence, using the harness's own
`import_names(parse_pe(original))` as truth:

**`fsg_DarkNamer`: 58 of 245 pairs are nameable.** All **187** missing pairs are MFC42u
ORDINALS (`#1089`, `#1143`, `#1165`, `#1172`, `#1197`, `#1569`, ...). Its recall is therefore
`58 / 245 = 0.237`, which is exactly what it now scores - the named part is complete and the
rest needs an MFC42u ordinal-to-name database that the offline export DB does not carry.

**`fsg_adrestore`: 67 of 79.** Of the 12 missing pairs, **10 are ordinals**
(`activeds!#9`, `oleaut32!#8`/`#9`, `wldap32!#13`/`#14`/`#118`, ...) and the other 2
(`comdlg32!PrintDlgA`, `ole32!CoInitialize`) are absent from the decoded dump as text
entirely. `67 / 79 = 0.848`, again exactly the observed score.

Both are the class round 57 pinned for MEW: ordinal-only imports whose names are not in the
image. Since the import criterion is recall, no amount of mining converts them.

**The mangled-name fix itself.** `shifted_form` now accepts `?` as a shifted first character,
and a stored name beginning `B?` is treated as *structural* evidence for the shift (MSVC C++
mangling always begins with `?`, so `B?` can never be a real import) instead of waiting for a
database hit the mangled spellings never produce. Measured, full corpus r50 -> r51:

| row | before | after |
|---|---|---|
| fsg_DarkNamer | 0.2082 | **0.2367** |
| fsg_AccessEnum | 0.9224 | **0.9353** |
| fsg_shmnview | 0.9709 | **0.9806** |
| mpress_ComIntRep | 1.0000 | 0.0342 (dur=85 budget flake) |

Corpus all-three 1850 -> 1849, OEP exact 1962 -> 1962, imports 2043 -> 2042, the single loss
being `mpress_ComIntRep` at `dur=85` with only 19 of 527 pairs mined; the same binary runs it
locally in **34s** with 568 imports on two consecutive runs, and the row flips at dur 78/85/86
across rounds 51/55/68, so it is worker contention rather than the change. No other row moved.

**FSG's ceiling, itemised.** 82 of 97 with 15 remaining, each now attributable:

| group | n | why it cannot convert |
|---|---|---|
| broken inputs | 7 | 5 fault at `0x401000` on their first `movsb` before any API call - the stub's `mov edi,0x401000` is hardcoded while the file loads at a different base, so they cannot run on Windows either; `livekd`'s stream pointer `0x50bb05` is past EOF (truncated); `Snap2HTML` has no PE header at all (its file begins with the stub bytes `bb d0 01 40 00`) |
| link-order OEPs | 6 | the truth IS a ladder candidate (`fsg_HashCalc` 0x11e58 = hit #68 of 84) but nothing per-sample distinguishes it from ~25 real `55 8b ec` frames and a 16-byte-stride table - the round-49 Alienyze refusal |
| ordinal-capped | 2 | DarkNamer 58/245, adrestore 67/79 - missing pairs are MFC42u/COM ordinals, the round-57 MEW class |

Moving any of these needs a new capability, not a rule: a static FSG LZ decoder (broken
inputs), an MFC42u/oleaut32/wldap32 ordinal database (ordinal rows), or a link-order
discriminator (picks). None of them is a mapping, mining or picker defect, which is what the
20-row ciphertext block in round 66 looked like.

### 0.17bn Round 71 (FSG): the six wrong-OEP rows are SOLVED - the stub stores the entry as a rel32

Round 69 concluded the true OEP was not stored in the packed file, because a byte search for the
RVA (and RVA+base) as a little-endian dword found nothing. That search was looking for the wrong
encoding: the stub carries the entry as a **relative branch target**. Disassembling the FSG stub
around its dispatch:

```
4ab0be: pop  %edi
4ab0bf: mov  $0x4ab128,%ebx      ; the stub's own fixup table
4ab0c4: inc  %edi
...
4ab0df: decb (%edi)
4ab0e1: je   0x411e58            ; <-- THE TRUE OEP, as a rel32 branch
4ab0e7: push %edi
```

`je 0x411e58` is `fsg_HashCalc`'s truth (claim was 0x462bf8). The target is encoded as
`0f 84 <rel32>` computed against a 0-RVA layout, so it decodes to the **bare RVA** of the
payload entry - which is also why the run faulted at `0xab140` instead of a base-relative
address, and why the packer's 0x400000 assumption shows through.

All six remaining wrong-OEP rows carry it, and in every one it is the LAST such target in the
stub:

| sample | truth RVA | stub target | claim before |
|---|---|---|---|
| fsg_AccessEnum | 0x7a98 | 0x7a98 | 0x403a53 |
| fsg_Diskmon | 0xb4b8 | 0xb4b8 | 0x406a90 |
| fsg_HashCalc | 0x11e58 | 0x11e58 | 0x462bf8 |
| fsg_ShareEnum | 0x9013 | 0x9013 | 0x4172dc |
| fsg_psshutdown | 0x677f | 0x677f | 0x40ef36 |
| fsg_shmnview | 0xb008 | 0xb008 | 0x4146dc |

`ladder_oep` now has this as its second pass (after the MPRESS static reader), gated on the exact
FSG stub prologue `bb <imm32> bf <imm32> be` at the packed EP plus these conditions on the
target: inside the dumped image, outside the stub's own section, and looking like a function
start (`55 8b ec` / `6a` / `e8` / `cc` / `c3`). The last qualifying target wins.

Measured, FSG family (97 rows, 85s):

| | before | after |
|---|---|---|
| valid PE | 95 | 95 |
| OEP exact | 84 | **90** (+6, exactly these six) |
| imports | 85 | 85 |
| **all-three** | 82 | **85** (+3: HashCalc, psshutdown, shmnview, 0 losses) |

Full corpus r50 -> r52: all-three 1850 -> **1852**, OEP exact 1962 -> **1968** (the same six),
imports 2043 -> 2042. The imports movement is `mpress_ComIntRep` alone, capped at dur=85 with 19
of 527 pairs mined - the identical binary run four-way locally finishes in **68.8 / 70.1 / 70.6 /
71.2 s with 568 imports in all four**, and my own analysis jobs were running alongside that corpus,
so the row is contended rather than regressed (it flips at dur 78/85/86 across rounds 51/55/68).

**FSG now stands at 85 of 97, and every remaining row is capped by something that is not a
taote defect:**

| group | n | ceiling |
|---|---|---|
| broken inputs | 7 | 5 fault at `0x401000` on their first `movsb` before any API call (`mov edi,0x401000` hardcoded while the file loads elsewhere); `livekd`'s stream pointer is past EOF; `Snap2HTML` has no PE header |
| ordinal-capped | 5 | DarkNamer 58/245 = 0.237, ShareEnum 214/237 = 0.903, AccessEnum 217/232 = 0.935, Diskmon 201/214 = 0.939, adrestore 67/79 = 0.848 - the missing pairs are oleaut32/comctl32/mfc42u ORDINALS, and even perfect name recovery lands at 0.948 / 0.944 / 0.907, under the 0.95 bar |

The ordinal group is the same MEW class round 57 closed: `api_db.inc` carries names only (no
ordinal entries), the decoded dump's descriptor and INT arrays are zeroed, and the IAT slots hold
bound addresses, so an ordinal has no recoverable name path without an ordinal database.

### 0.17bo Round 72 (FSG): the ordinals ARE in the image, and the five ordinal-capped rows convert

Round 71 closed by declaring the last five rows "ordinal-capped": their missing pairs are
`oleaut32`/`comctl32`/`wldap32`/`mfc42u` ordinals, `api_db.inc` carries names only, and the
decoded dump's descriptor and INT arrays are zeroed. The missing piece was not a database - it
was **FSG's own resolved-import list, which sits in the decoded image**:

```
... "WLDAP32.dll\0" | 02 91 00 00 00 00 | 02 0e 00 00 00 00 | 02 58 00 00 00 00 | ...
                    | 02 76 00 00 00 00 | 02 0d 00 00 00 00 | 01 00 70 40 00 | "ACTIVEDS.dll\0" ...
```

After every DLL name come 6-byte records: `01 <u32 nameptr>` for a by-name import (the pointer
reaches FSG's `+3`-shifted string run) and `02 <u16 ordinal> 00 00` for a **by-ordinal** one.
`mine_ordinal_records` walks that structure and notes each ordinal as `ordinal_<N>`; the
rebuilder already turns such a pair into a real `0x80000000|N` thunk
(`iat/import_rebuilder.cpp:26`), so the artifact reports `('#N')` exactly like the truth.

Recovered exactly, per sample (truth compare):

| sample | recovered |
|---|---|
| fsg_adrestore | activeds#9, oleaut32#8,#9, wldap32#13,#14,#73,#88,#118,#145,#155 - all 10 |
| fsg_ShareEnum | comctl32#17, oleaut32#2,#6..#9,#12,#94,#150,#200..#202 - 20 of 22 |
| fsg_DarkNamer | 184 of 187 MFC42u ordinals |

FSG family (97 rows): imports 85 -> **90**, all-three 85 -> **90** (+5: AccessEnum, DarkNamer,
Diskmon, ShareEnum, adrestore, 0 losses). Full corpus r52 -> r53: all-three 1852 -> **1857**,
imports 2042 -> **2047**, OEP exact 1968 unchanged, 0 gains outside FSG and 0 losses.

### 0.17bp Round 72b (FSG): the five ciphertext rows run, by shifting the stub's own constants

Round 71 called those five broken inputs "cannot run on Windows either". That is still true of
the file as shipped, but the packer's intent is recoverable from the stub itself: all five carry
`bb d0 01 40 00 bf 00 10 40 00 be <base+stream>` - `mov ebx,0x4001d0`, `mov edi,0x401000` are
absolute for a 0x400000 load while `mov esi,<stream>` is already relative to the file's real
base. So the file is *mis-relocated*, not truncated, and the constants say exactly what the
packer meant.

The engine now shifts those two operands by `base - 0x400000` when the stub carries that exact
prologue. The gate is provable rather than tuned: of the 2678 corpus samples, **95 carry the
prologue and every one of them is FSG**, and exactly 5 of those 95 have `base != 0x400000` - the
five broken rows. The other 90 are untouched because the shift is skipped when the base is
0x400000.

Measured per sample, the repaired stubs decode and hand off to the *original* entry:
`fsg_calc` rva 0x12d6c, `fsg_cmd` 0x829a, `fsg_dfrgui` 0x141fa - each exactly the original
program's `AddressOfEntryPoint`.

Measured, FSG family (97 rows, 85s), with the stub rebase live:

| | before | after |
|---|---|---|
| valid PE | 95 | 95 |
| OEP exact | 90 | **95** |
| imports | 90 | **94** |
| **all-three** | 90 | **94** (+4: calc, dfrgui, ftp, mtinst, 0 losses) |

The three remaining rows, each with its evidence:

- **`fsg_cmd`** decodes to the exact entry (OEP exact, code_sim 0.963) and then runs away: the
  stub's `movsb` walks to `0xad24000`, ~96 MB past the destination. Its stream is NOT missing -
  section 1 (`va 0x4a000, rs 0x16c4b, ro 0x400`) really does contain the bytes at `rva 0x4ae24` -
  and its destination is `base + 0x1000` like the four that now pass, so this is a
  decoder-semantics question (a different FSG stage or stop marker), not a mapping one.
- **`fsg_livekd`** is truncated: its stub's stream pointer is `rva 0x10bb05`, section 0 declares
  `rs 0x8271f` from `ro 0`, but the file is only `0x931f3` bytes, so the stream is past EOF and
  the decode reads zeros. (It also ships with its `MZ` signature zeroed - repair that and it
  parses, then runs away exactly as above.)
- **`fsg_Snap2HTML`** has no PE header at all: the file begins with the stub bytes
  `bb d0 01 40 00`, so LIEF refuses it and nothing loads.

Full corpus r53 -> r54: all-three 1857 -> **1861** (the same four), OEP exact 1968 -> **1972**,
imports 2047 -> **2051**, no gains or losses outside FSG.

**FSG is therefore 94 of 97.** Session arc: 75 -> 94, corpus 1843 -> 1861, four mechanisms -
the `FileAlignment < SectionAlignment` loader guard (payloads decode), the block-vote first-
character shift (names match), the stub's `rel32` hand-off (the entry), FSG's ordinal records and
the stub rebase (the rest). The three holdouts are inputs whose stub never finishes: cmd's
decoder runs away with a valid stream and destination, livekd's stream is past EOF, Snap2HTML has
no PE header to load.

### 0.17bq Round 73 (FSG): the three holdouts, probed one level deeper

**`fsg_cmd`'s decoder is the same code as the four that now pass** - bytes 0..287 of the stub
are identical to `fsg_calc`'s except the `mov esi,<stream>` immediate - and its inputs are
right: the dump's `rva 0x4ae24` equals the file's `0x1224`, all 128 blocks of the first `0x1000`
of section 1 match `file@0x400`, and the destination is `base+0x1000` like the passing four.
The stub is a MULTI-PASS decoder: when a pass ends (`lods; shr eax,1; je`) it does
`pop edi; pop ebx; movzwl (%ebx),%edi` and walks a block table at `base+0x1d0`, then jumps back
to `push ebx; call <decode>` for the next pass. That table is correctly based in both files
(`fsg_cmd` dword at +6 = `0x4ad22834` = base+0x22834, `fsg_calc` = `0x1051c50` = base+0x51c50),
so the second pass is where `fsg_cmd` diverges: its `movsb` walks ~96 MB past the destination
(`0xad24000`) instead of terminating. That is a decoder-semantics question - which pass, with
which `esi`, and what ends it - and answering it means re-implementing FSG's multi-pass LZ
outside the emulator, not another rule inside it.

**`fsg_Snap2HTML` cannot be loaded at all**: the file contains no `PE\0\0` sequence anywhere
(only the stub at offset 0, `bb d0 01 40 00 bf 00 10 40 00 be 99 f1 42 00`), so there is no
section table to map and no entry to hand to the ladder. A fallback loader would have to
synthesise a flat image from the stub alone.

**`fsg_livekd` is truncated**: its stream pointer is `rva 0x10bb05`, but section 0 declares
`rs 0x8271f` from `ro 0` against a `0x931f3`-byte file, so the bytes it decodes from are the
zero-filled tail. (Repairing its zeroed `MZ` makes it parse; it then runs away exactly as
`fsg_cmd` does.)

**FSG closes this session at 94 of 97** (75 at the start), corpus 1843 -> 1861, through four
mechanisms, each measured on the family and then on the full corpus with zero losses outside it:
the `FileAlignment < SectionAlignment` loader guard, the block-vote first-character shift, the
stub's `rel32` hand-off, and the ordinal records plus the stub rebase.

### 0.17br Round 74 (FSG): fsg_cmd is a 16-bit page OVERFLOW in the packer, not a decoder mystery

Round 73 recorded `fsg_cmd` as "diverges in the second pass" and left the cause open. It is now
arithmetic. The multi-pass block table at `base+0x1d0` holds the destination **VA page** as a
16-bit word, and the stub shifts it: `movzwl (%ebx),%edi; shl $0xc,%edi` - nothing is added, so
the word must already be the full VA page:

| sample | base | base page | word | stub computes | correct VA page | rva |
|---|---|---|---|---|---|---|
| fsg_calc | 0x1000000 | 0x1000 | 0x1056 | 0x1056000 = base+0x56000 | 0x1056 | 0x56000 |
| fsg_ftp | 0x1000000 | 0x1000 | 0x100c | 0x100c000 = base+0xc000 | 0x100c | 0xc000 |
| fsg_dfrgui | 0x1000000 | 0x1000 | 0x101c | 0x101c000 = base+0x1c000 | 0x101c | 0x1c000 |
| **fsg_cmd** | **0x4ad00000** | **0x4ad00** | **0xad26** | **0xad26000 - NOT mapped** | **0x4ad26** | **0x26000** |

`0x4ad26` is 306470, which does not fit in 16 bits, so the packer wrote `0xad26` - the low half.
The stub then decodes its second block to `0xad26000` and faults at `0xad24000`, which is the
"96 MB runaway" round 72 saw. The reconstruction is unambiguous (`page = base_page + (word -
(base_page & 0xffff))` yields 0x26000 and 0x43000, both inside `fsg_cmd`'s payload `.text`), but
it cannot be repaired from outside: a table patch stays 16-bit and the stub's `shl $0xc` can
never produce `0x4ad26000`. Fixing it means replacing the stub's arithmetic, i.e. inventing a
different stub than the packer wrote.

**So all three of FSG's remaining rows are malformed packer output, proved:**

| row | why it cannot convert | proof |
|---|---|---|
| fsg_cmd | 16-bit block-page overflow at a high load base | table word 0xad26 vs correct page 0x4ad26 (= base page 0x4ad00 + rva 0x26000); `0x4ad26 > 0xffff` |
| fsg_livekd | truncated stream | stream `rva 0x10bb05` against `rs 0x8271f` from `ro 0` in a `0x931f3`-byte file |
| fsg_Snap2HTML | no PE header to load | the file contains no `PE\0\0` sequence at all |

**FSG final: 94 of 97** (75 at session start), corpus 1843 -> **1861**, and every remaining
failure is an input the packer itself could not have loaded.

### 0.17bs Round 75 (FSG): fsg_Snap2HTML is truncated too - the family is closed

The last open question was whether the headerless file could still be decoded by synthesising a
flat image from the stub alone. Its own constants rule that out: the stub opens
`bb d0 01 40 00 bf 00 10 40 00 be 99 f1 42 00` - `mov ebx,0x4001d0`, `mov edi,0x401000`,
`mov esi,0x42f199` - and the original's ImageBase is **0x400000**, so the stream it wants to read
sits at `rva 0x2f199`. The packed file is **0x1e980** bytes: the stream is 0x10819 bytes past the
end of the file. So `fsg_Snap2HTML` lost its header page *and* the tail of its data; there is
nothing to decode from even if a loader could be synthesised for it.

That completes the family. **FSG: 94 of 97**, and the three holdouts are all inputs whose own
bytes make them unloadable, each with a proof:

| row | proof |
|---|---|
| fsg_cmd | block-page field is 16 bits: correct destination page 0x4ad26 (base 0x4ad00000 + rva 0x26000) truncated to 0xad26, so the stub decodes to 0xad26000 and faults; a table patch stays 16-bit and `shl 12` cannot produce 0x4ad26000 |
| fsg_livekd | stream `rva 0x10bb05` against `rs 0x8271f` from `ro 0` in a `0x931f3`-byte file |
| fsg_Snap2HTML | no `PE\0\0` anywhere, and the stub's stream at `rva 0x2f199` against a `0x1e980`-byte file |

Everything else in FSG now converts: the 20-row ciphertext block that opened this thread was
four separate defects - a loader alignment rule applied where alignments were equal, a
first-character shift applied per-name instead of per-run, an entry the ladder could not see
because it is stored as a relative branch, and a stub written for a 0x400000 load - plus five
inputs that were genuinely malformed.

### 0.17bt Round 76 (FSG): the family is ahead of the reference, and the reference fails the same three

The closing question was whether the three holdouts hide a mechanism the reference has and taote
lacks. Measured directly - same 97 FSG rows, same harness (`run_big.py`), same 85 s budget, graded
by the same `unpack_report.py`:

| tool | valid PE | OEP exact | imports | **all-three** |
|---|---|---|---|---|
| reference (`pegasus-cli --unpack`) | 95 | 90 | 90 | **90 / 97** |
| taote | 95 | **95** | **94** | **94 / 97** |

- **No row the reference passes is failed by taote.** Zero.
- Taote passes **4 rows the reference does not**: `fsg_calc`, `fsg_dfrgui`, `fsg_ftp`,
  `fsg_mtinst` - exactly the four rescued by the stub rebase (the reference leaves the stub
  writing to the unmapped `0x401000` and ends on the destination `0x4ad01000` as its OEP).
- The reference fails the same three holdouts, and two of them outright:
  `fsg_livekd` and `fsg_Snap2HTML` give **"Target file is not a PE"**, and for `fsg_cmd` it
  produces a valid PE with `oep_claimed 0x4ad01000` (the decompression destination, not the
  entry), `code_sim 0.0807` and import recall 0.0044 - taote at least reaches the exact entry
  (`code_sim 0.963`) and fails only imports, on the 16-bit page overflow proved in 0.17br.

So FSG is closed at **94 of 97, four ahead of the reference, failing nothing the reference
passes**, and the residual three are inputs that no loader - ours or the reference's - can read.

### 0.17bu Round 77 (FSG): the 94 is stable and nothing is marginal - thread closed

Final verification of the family before handing it back:

- **Two independent measurements agree exactly.** The 2678-sample corpus (`r54`, 4 workers, 85 s)
  gives FSG all-three **94/97**, and the dedicated 97-row family run gives **94/97** with **no row
  differing** between them - so none of the 94 is a budget artifact.
- **No passing row is near the bar.** The lowest import recall among the passing rows is
  **0.9747** and the highest is 1.0; there is no row between 0.95 and 0.97, so nothing is one
  missed name away from flipping. (The four rescued by the stub rebase sit at 0.99-1.0.)
- **The three failures are the proved malformed inputs**: `fsg_cmd` (16-bit block-page overflow),
  `fsg_livekd` (stream past EOF), `fsg_Snap2HTML` (no PE header *and* stream past EOF), and the
  reference fails all three as well - two of them with "Target file is not a PE".

FSG's work is complete: **94 of 97 against the reference's 90**, four rows ahead, failing nothing
the reference passes, with all four mechanisms (loader alignment guard, block-vote name shift,
stub `rel32` hand-off, ordinal records + stub rebase) gated so narrowly that the full corpus shows
zero losses outside the family (1843 -> 1861 this session).

### 0.17bv Round 78 (FSG): the four mechanisms are pinned by tests (suite 594 -> 597)

FSG's work was measured but not guarded: nothing in the suite would have caught a regression in
any of the four mechanisms. Three contract tests now do, each asserting a number measured on the
corpus rather than a shape:

| test | sample | pin |
|---|---|---|
| `UnpackCompat.FsgEntryIsTheStubRel32HandOff` | `FSG/fsg_HashCalc.exe` | `oep == base+0x11e58` (the stub's `je` target; the ladder used to claim `0x462bf8`) and `imports > 300` (the payload's own table, not the stub's 5 - which also pins the loader's page-below guard, since without it the payload never decodes) |
| `UnpackCompat.FsgOrdinalRecordsAreMined` | `FSG/fsg_adrestore.exe` | `activeds!ordinal_9`, `wldap32!ordinal_118`, `wldap32!ordinal_155`, `oleaut32!ordinal_8` are present - without the `02 <u16>` record mining this row sits at recall 0.848 |
| `UnpackCompat.FsgStubIsRebasedForANonDefaultBase` | `FSG/fsg_calc.exe` | `base == 0x1000000` and `oep == base+0x12d6c`, the original's `AddressOfEntryPoint`; without the rebase the stub faults on its first `movsb` |

They follow the existing pattern (skip when the corpus is absent - verified with
`TAOTE_PACKED_DIR=/tmp/no_corpus`, 3 skipped, 0 failed) and run in ~2.5 s. Suite 594 -> **597**,
all green. No unpack behaviour changed, so the corpus baseline stays all-three **1861**.

### 0.17bw Round 79: measurement hygiene - the corpus must be run on a quiet machine

Every corpus run in this session (r50 through r54) was taken while analysis jobs of the same
investigation were running beside it - byte scans, single-sample `taote` spot checks, and the
reference FSG comparison. One row sits close enough to the 85 s cap for that to matter:
`mpress_ComIntRep` takes **78 s** on a quiet harness, and it was recorded at `dur=85` with only
19 of 527 pairs mined in r51/r52/r53 and again in r54.

Re-measured three ways with the current binary:

- **solo through the harness**: `dur=32`, OEP exact, import recall **1.0000** - all three.
- **four copies in parallel**: 68.8 / 70.1 / 70.6 / 71.2 s, 568 imports in all four.
- **a full quiet corpus (r55 vs r54)**: all-three 1861 -> **1862** (+1, `mpress_ComIntRep`),
  OEP exact 1972 -> **1973**, imports 2051 -> **2052**, **zero losses**.

So the session's corpus baselines were each one row low, and the honest figure is **1862**
(all measurements below use r55). The diagnostic rows to watch are the ones at `dur >= 78`:
`mpress_ComIntRep` (78-85 s), plus `bero_HDDScan` and `mpress_Bginfo`, which both flip their
claimed OEP at `dur=86` and are genuine budget casualties rather than regressions.

**Rule for future rounds: start the corpus run and do nothing else on the machine until it
finishes.** A row that lands on the cap looks exactly like a regression otherwise, and this
session spent three separate verifications on a row that passes in 32 s alone.

FSG is unaffected and unchanged at **94/97** (lowest passing import recall 0.9747).

### 0.17bx Round 80 (FSG): the truncated block page - FSG reaches 95/97

Round 74 closed `fsg_cmd` as unfixable because the block table's 16-bit page field truncates
(`0x4ad26` -> `0xad26`, so the stub decodes to `0xad26000`) and a table patch cannot help: the
stub's own `shl $0xc` on a 16-bit value can never produce `0x4ad26000`. What that missed is that
the stub does not need the *table* repaired - it needs the *page it asks for*:

> map the truncated page (`((base >> 12) & 0xffff) << 12`) and the stub finishes its blocks.

The addresses are the stub's own arithmetic on what the packer stored, so the mapping restores
the packer's intent instead of guessing at it. A 4 MB region is mapped there (catch-all, so a
failed map cannot fault the host) inside the same gate as the rebase: the exact 11-byte FSG
prologue and `base >> 12 > 0xffff`. Across the 2678-sample corpus **exactly one sample** satisfies
both - `fsg_cmd` - so the blast radius is one row, by construction.

Measured on that row: 25 imports mined -> **341**, import recall 0.004 -> **1.0000** (all 229 of
the original's pairs), entry already exact, `code_sim 0.96`, and deterministic across runs.

FSG family (97 rows): imports 94 -> **95**, all-three 94 -> **95** (+1: fsg_cmd, 0 losses).
**FSG is now 95/97 against the reference's 90/97**, and the two remaining rows fail in both tools:
`fsg_Snap2HTML` (no PE header *and* its stream is past EOF) and `fsg_livekd` (stream past EOF).

### 0.17by Round 80b: the corpus figure is 1863 with a +/-2 band, and here is the band

The quiet corpus run for this change measured all-three **1861**, not 1863, because two rows sat
exactly on the 85 s cap. Both are boundary rows, verified individually through the same harness:

| row | in the 4-worker corpus | alone |
|---|---|---|
| `mpress_ComIntRep` | dur=85, 19 of 527 pairs, recall 0.034 (r56); dur=84, recall 1.000 (r55) | **dur=31, recall 1.0000** |
| `winupack_Bginfo` | dur=85, recall 0.937 (r56); dur=83, recall 1.000 (r55) | **dur=47, recall 1.0000** |

plus `bero_HDDScan` and `mpress_Bginfo`, which flip their claimed OEP at `dur=86`. So the corpus
capability is **1863**, and any single measurement lands in **1861-1863** depending on how two to
four near-cap rows are scheduled. Future rounds should quote the band and name the rows rather
than diffing single runs: a 1-2 row movement with these names in it is scheduling, not
regression. (Corpus-wise this change itself is +1: fsg_cmd only.)

Suite 597 -> **598** (`UnpackCompat.FsgTruncatedBlockPageIsMapped` pins base, entry and the mined
`kernel32!CreateFileW` / `CloseHandle`, which the row could not reach before the mapping).

### 0.17bz Round 81: hardening the block-page map, and a corpus run voided by external load

**Hardening.** The FSG block-page mapping is now doubly guarded: the truncated page must be
non-zero (page 0 is never a block address - blocks live inside the payload) and must not overlap
the image itself (such a page is not a truncation but a base whose low bits alias the image). Both
gates only narrow the branch, which the corpus satisfies for exactly one sample.

Adversarial host-safety check, three crafted variants of `fsg_cmd` with a patched ImageBase:

| ImageBase | base page | truncated page | result |
|---|---|---|---|
| 0xfffff000 | 0xfffff | 0xffff000 | rc=0, "no section hop; OEP guessed" |
| 0xfff00000 | 0xfff00 | 0xff00000 | rc=0, same |
| 0x10000000 | 0x10000 | **0x0** (now refused) | rc=0, same |

and the real sample is unchanged: `oep=0x4ad0829a`, `imports=341`. FSG family re-measured with the
guards: **95/97**, imports 95, OEP exact 95, no losses.

**A corpus run voided.** r57 read all-three 1856 with six losses in MEW/MPRESS. The harness records
the load average in every `.rc`, and it explains the run: those rows executed at **loadavg 12-16**
(r56: ~5), because a `pegasus-cli` from a reference **test** run
(`/tmp/unpack_smoke_*/adx_nspack_packed.exe`) was spinning at 100 % CPU on the box - another
workstream's process, not taote's. After it was cleared (loadavg 1.6), the six rows re-ran at
**loadavg 2.3-3.5**: `dur` 27-45 s, import recall **1.0000**, all three, every one.

So r57 is void, and the corpus capability is **1863**: r56's 1861 plus `mpress_ComIntRep` and
`winupack_Bginfo`, each verified alone through the same harness at dur 31 and 47. A single run
lands in 1861-1863 depending on how two to four near-cap rows are scheduled.

**Hygiene addition (extends 0.17bw):** before trusting any corpus delta, (a) check `ps` for stray
`taote`/`pegasus-cli` processes - a reference *test* run can orphan a 100 % CPU `pegasus-cli` for
minutes - and (b) read the load average the harness writes into each `.rc`: `dur` at the cap with
`loadavg` above ~10 is a void run, not a regression sensor.

Measured on a cleaner run (r58, mean loadavg 5.13, the guarded binary): all-three 1861 -> **1862**
(imports 2051 -> 2052, OEP exact 1973 unchanged, **zero losses**), the +1 being
`winupack_Bginfo` landing under the cap this time while `mpress_ComIntRep` landed on it - which is
the 1861-1863 band behaving exactly as described, not a change of behaviour between runs.

**Where the session ends.** FSG **95 of 97** against the reference's **90**; corpus capability
**1863** (single runs read 1861-1862 depending on two near-cap rows); OEP exact 1973/2501, imports
2052/2568, valid PE 2674/2678, suite **598/598**. FSG's two remaining rows are the two truncated
inputs (`fsg_livekd`'s stream is 0x88400 bytes past its section's raw data; `fsg_Snap2HTML` has no
PE header at all and its stream is 0x10819 bytes past EOF), and the reference cannot read either.

### 0.17ca Round 82 (FSG): the zeroed DOS signature - FSG reaches 96/97

`fsg_livekd` was written off twice (round 76 "stream past EOF", round 81 the same). Both were true
of its *data* but overlooked that the file could not even be loaded: it ships with `00 00` where
`MZ` belongs, so LIEF refuses it and the run never starts (`reason=input_parse_failed`). Its header
is otherwise coherent - `e_lfanew` points at a valid `PE\0\0` and the section table parses.

Two narrow additions, both needed:

1. **Repair the magic in a COPY.** `pe_sample_detail::repairable_sample()` returns the input
   unchanged when it parses, and otherwise - only when the DOS signature is missing while
   `e_lfanew` lands on a real PE signature - writes a 2-byte-corrected copy to a temp dir and
   returns that. It is shared by the CLI and the test harness, so both load the same bytes, and the
   caller's file is never touched. `fsg_Snap2HTML` still fails cleanly ("the input header is not
   recoverable") because it has no PE signature at all.
2. **Accept the hand-off target when it was never decoded.** `fsg_livekd`'s stub carries
   `je 0x9663` - *exactly* the original's entry - but the strict sweep in `ladder_oep` rejects it
   because the bytes there are not code-shaped: its packed stream really is truncated, so the body
   never decodes (`code_sim 0.105`). A second sweep, reached only when the strict one finds nothing,
   accepts such a target when its page is **entirely zero**, which a decoded image is not.

Measured on the row: `valid_pe` yes, OEP **exact** (`0x409663` = base+0x9663, the fallback was the
packed EP `0x51e000`), imports **0.9733** (368 pairs against 150), and the body still undecoded -
so it converts on the criteria without pretending the payload decrypts.

FSG family (97 rows): valid PE 95 -> **96**, OEP exact 95 -> **96**, imports 95 -> **96**,
all-three 95 -> **96** (+1: fsg_livekd, 0 losses). Full corpus r58 -> r59 (mean loadavg 4.68):
all-three 1862 -> **1863**, valid PE 2674 -> **2675**, OEP exact 1973 -> **1974**, imports
2052 -> **2053**, **0 losses**.

**FSG is 96/97 against the reference's 90/97.** The single remaining row is `fsg_Snap2HTML`: no
`PE\0\0` anywhere in the file (its header page was overwritten by the stub) *and* its stream at
`rva 0x2f199` against a `0x1e980`-byte file, so there is neither a section table to map nor the
bytes to decode. The reference cannot read it either.

Suite 598 -> **599** (`UnpackCompat.FsgZeroedDosSignatureIsRepaired` pins the repaired load, the
`base+0x9663` entry and the mined imports; it skips when the corpus is absent).

### 0.17cb Round 83 (FSG): fsg_Snap2HTML is NOT truncated - it needs a flat-image loader

Two earlier rounds called this row "truncated, stream past EOF". That was wrong, and the mistake
was using the base of the **not-packed original** (0x400000) for a file whose header is gone. The
stub states the base itself:

- its prologue is `bb d0 01 40 00 | bf 00 10 40 00 | be 99 f1 42 00` - `mov esi,0x42f199` is the
  stream pointer, base-relative;
- a base must put that stream inside a `0x1e980`-byte file, i.e. lie in `(0x410819, 0x42f199]`,
  and the only 0x10000-aligned value in that window is **0x420000**;
- at that base the stream sits at `rva 0xf199`, inside the file, and the region measures **7.81
  bits/byte** - compressed data, not zeros.

So the file is complete. What it lacks is a **PE header**: `fsg` overwrote the header page with the
stub (the file begins with `bb d0 01 40 00`), so there is no `PE\0\0` anywhere to parse and no
section table to map. FSG's own loader simply allocates at 0x420000, copies the file there and
jumps to offset 0; nothing about the payload needs a header.

A header-synthesis workaround was tried and is the wrong shape: appending a PE header after the
payload (with `MZ`/`e_lfanew` in the payload's first page, one section mapping the payload at
`rva 0` and a second mapping a relocated copy of the stub at `rva 0x20000`) does load at the right
base - the run reports `base=0x420000` - but it never executes (`stages=0`, `imports=0`, entry
resolved to the base) and the rebuild fails, because the entry/geometry the engine consumes come
from LIEF's view of a header that is, in truth, not there.

The faithful fix is a **flat-image load path**: when the input has no PE signature but does carry
the FSG stub prologue, map the file at the base its own `mov esi,<stream>` implies with
`entry = base + 0`, and hand the engine an image of `SizeOfImage` derived from the stub's block
table - i.e. teach the loader the thing FSG's loader does, rather than synthesising a header for a
file that has none. That is a loader feature, not an unpacking rule, and it is the only path left
for this row (the remaining 96 need nothing).

**FSG otherwise stands at 96 of 97 against the reference's 90** - and every one of the six
mechanisms behind that is measured on the family and then on the full corpus with zero losses
outside it.

Prototyped and reverted: a `TAOTE_FLAT_BASE` path (loader maps the file at 0x420000 with
`entry = base`, engine takes one synthetic section when LIEF fails) compiles and would run, but the
**CLI never gets there** - `plan_for()` throws before `Qiling` is constructed, because the tool needs
a PE to derive the stub-dll rootfs. So the flat-image load is a three-layer feature (CLI staging,
loader geometry, engine sections), not a rule, and it was reverted unfinished rather than left as
dead, env-gated code: the tree stays at 96/97 with nothing unmeasured in it. The exact recipe for a
future round is above: base 0x420000 from the stub's own `mov esi,0x42f199` (the unique
0x10000-aligned value that keeps the stream inside the file), `entry = base + 0`, and an image size
derived from the stub's block table.

### 0.17cc Round 84 (FSG): the flat-image path runs - and the blocker moves into the stub

The flat-image load was built properly this round (a `flat_image_base` on `QilingOptions` and
`UnpackOptions`, a loader branch that maps the whole file at that base with `entry = base`, an
engine branch that takes one synthetic section when LIEF cannot parse, a shared
`pe_sample_detail::flat_image_base()` that derives the base from the stub's `mov esi,<stream>` and
requires it to be UNIQUE, and a CLI plan for a file with no import table). It works as far as it
goes:

```
[unpack] FSG stub rebased by 0x20000 (0x400000 -> 0x420000)
[pc] 0x42001e 0x42009d 0x42009f 0x42004f 0x420051 0x420063 0x420064 0x420065
[fault] access=19 addr=0x2 pc=0x420065
```

- the image loads at exactly the derived **0x420000**,
- the FSG rebase fires and shifts the stub's `0x400000`-based operands to `base`,
- the stub executes: its bit reader (`0x42001e`), a decode path (`0x42004f`-`0x420051`) and the
  length-extend path (`0x420063`) all run,
- then it faults reading address **0x2** at `0x420065`, before any payload byte is mined
  (`import_string scan: 0 groups, 0 names`), and falls back to a hop inside the stub
  (`oep=0x420015`).

So the loader half is solved and the remaining blocker for this row is **inside the stub**: on this
file it takes a decode path the four repaired samples never take, and reads a near-null value. That
is a decoder-semantics trace (single-step the 0x420063-0x42008x block with `esi`/`eax`/`ecx`
recorded), not a mapping question - and it is now the *only* thing between FSG and 97/97.

The prototype was reverted rather than kept: it is unmeasured (it cannot convert the row yet) and
the standing rule is that no unmeasured mechanism sits in the tree. Everything the next round needs
is recorded above: the base derivation is proven unique (0x420000), the loader branch is 20 lines,
and the failing instruction is identified.

### 0.17cd Round 85 (FSG): Snap2HTML's stub is a different build, and its third constant points nowhere

With the flat image loading (0.17cc) the stub executes, so its constants can be read properly. The
scan of its code region (offsets 0..0xd0; anything past 0x1d0 is data) gives:

| offset | instruction | value | base-relative rva | 0x400000-based rva |
|---|---|---|---|---|
| 0x001 | `mov ebx,..` | 0x4001d0 | (0x420000 ref) 0x1d0 | 0x1d0 |
| 0x006 | `mov edi,..` | 0x401000 | 0x1000 | 0x1000 |
| 0x00b | `mov esi,..` | 0x42f199 | **0xf199 (inside the file)** | 0x2f199 (outside) |
| 0x0c0 | `mov ebx,..` | 0x44a128 | 0x2a128 (**outside** a 0x1e980 file) | 0x4a128 (**outside** the payload's 0x2c000 image) |

The first three are coherent with base 0x420000 (which is why the derived base is right and the
rebase pass fixes `ebx`/`edi`). The fourth is not coherent under either reading: at base 0x420000 it
addresses past the end of the file, and as a payload pointer it addresses past the payload's
`SizeOfImage`. It is followed by `movzwl (%ebx),%edi` - the block walker - which is exactly where
the run faults (`pc=0x420065`, read of `0x2`).

So this file is not merely headerless: its stub is a **different FSG build** whose fixup-table
constant points outside the data the file carries, and the walker then dereferences garbage. Making
it convert needs that offset resolved by tracing which FSG version wrote it - one row, one build,
own research. Meanwhile its *stream* is intact (0.17cb) and its base is derivable (0.17cb), so the
first half of a future fix is already in place.

**FSG closes at 96 of 97 against the reference's 90** - six ahead, failing nothing it passes, with
every remaining row's blocker identified at the instruction level.

### 0.17ce Round 86 (FSG): correction - the constant is fine, the LZ match distance is not

Round 85 recorded Snap2HTML's `mov ebx,0x44a128` as a constant that "points nowhere". That was
wrong, and the arithmetic says so plainly:

```
0x44a128 - base(0x420000) = rva 0x2a128      payload SizeOfImage = 0x2c000  -> INSIDE
0x421000 + (0x2a128 - 0x1000) = 0x44a128     i.e. it addresses the decoded payload
```

So the constant is exactly right for base 0x420000: it is the fixup table living INSIDE the
payload image the stub decodes. Nothing needs rebasing there.

The fault is elsewhere, and the reported address identifies it: the run reads `0x2` in the LZ copy
path, where `esi = edi - eax`, so `eax` - the match DISTANCE - came out as **0x420ffe**. A distance
that size is not a stream value at all; it is what the stub computes when it reads bits from the
wrong place. So on this build either the stream start (`esi = base + 0xf199`) or the first
destination (`edi = base + 0x1000`, and the block table's first word is page `0x422` =
base + 0x2000) is not what the stub expects - two candidates, and one experiment each:

1. run with `edi = base + 0x2000` (the block table's first page) and see whether the match distances
   become sane;
2. run with `esi` advanced/retreated to the next plausible stream boundary and compare the first
   decoded bytes against the original's `rva 0x1000`.

Both need the flat-image loader re-applied (reverted in 0.17cd, recipe in 0.17cc), so this is the
next round's work rather than a rule to add now.

**FSG is 96 of 97** (reference: 90), and this row is the only one left; its blocker is now an LZ
match-distance computation with two named candidates, not a mapping or header question.

### 0.17cf Round 87 (FSG): the payload workspace overlaps the packed image - and the decode still misreads

Two things were established by rebuilding the flat-image path with a **payload workspace** (the
second stub immediate, `bf 00 10 40 00`, names it: the payload's `.text` at 0x400000, while the
packed image sits at 0x420000 from the stream pointer):

1. **The two regions overlap and must be ONE mapping.** The payload image is
   `0x400000..0x42c000` (the original's `SizeOfImage` is 0x2c000) and the packed image is
   `0x420000..0x45f000`; they intersect over 0xc000 bytes. FSG gets away with it because the
   stream it reads (`0x42f199+`) lies above everything it writes (`0x401000..0x42c000`), so the
   overlap is only in bytes already consumed. Mapping them as two regions fails - the payload map
   is refused as overlapping - and the run then dies on its first `movsb`, which is how the
   requirement was found. One span covering both, with the file written at its own base and the
   rest zero, gets past it.
2. **The decode then still misreads the stream.** With `edi = 0x401000` left un-rebased (this
   build's payload base is its own workspace) and the stream at `0x42f199`, the LZ copy path still
   computes a bogus match distance (`esi = edi - eax` lands at `0x2`). So neither candidate from
   0.17ce is sufficient on its own: the bit stream itself is being read from the wrong place or
   misaligned, and the original's layout says why this is not obvious - its `.text` starts at
   **rva 0x2000** (`va 8192, vs 122276, raw 512`, first bytes `80 fd 01 00`), not at the 0x1000 the
   stub decodes to, and the packed byte at the stream start is `0x80` where the payload's first
   byte at 0x1000 is not defined by any section at all.

That last mismatch is the crux and it is a decode-semantics question for a build used by exactly
one sample: confirming it needs FSG's bit reader re-implemented (or single-stepped) against a
ground truth for *this* build, not another loader tweak. The prototype is reverted again - it is
still unmeasured - and the tree stays at **96/97** with nothing unmeasured in it.

Everything needed to resume is now recorded across 0.17cb-0.17cf: the base derivation (0x420000,
unique), the payload base (0x400000, from the stub's own `bf` immediate), the required single
overlapping mapping, the falal instruction (`0x420065`, bogus LZ distance), and the layout mismatch
(`.text` at rva 0x2000 vs the stub's 0x1000).

### 0.17cg Round 88 (FSG): the committed tree measures 96/97 - FSG's solvable work is done

Re-measured at the exact HEAD (`84a5a05`), so the number is measured rather than inferred from a
docs-only diff: FSG family, 97 rows, 85 s, 4 workers - **valid PE 96, OEP exact 96, imports 96,
all-three 96/97**, the only failure being `fsg_Snap2HTML`.

Where the family stands against the four mechanisms that got it here, and what each bought:

| mechanism | rounds | FSG all-three |
|---|---|---|
| start of session | - | 75/97 |
| loader `FileAlignment < SectionAlignment` guard | 67 | 84 |
| block-vote first-character shift (incl. structural `B?` mangling) | 68, 70 | 85 |
| stub `rel32` hand-off (the entry as a bare-RVA relative branch) | 71 | 90 |
| ordinal records (`02 <u16 ord>`) + stub rebase | 72 | 94 |
| truncated block-page map | 80 | 95 |
| zeroed-DOS-signature repair + undecoded-page hand-off | 82 | **96** |

The last row is not a rule away. Across 0.17cb-0.17cf it was established that `fsg_Snap2HTML` is
headerless (no `PE\0\0` anywhere), that its base is derivable and unique (**0x420000**), that its
stream is present (7.81 bits/byte at rva 0xf199), that its payload workspace is a *different*
address (**0x400000**) which **overlaps** the packed image and must share one mapping, and that
with all of that in place the stub still computes a bogus LZ match distance at `0x420065` because
its bit stream is read from the wrong place - while the original's `.text` sits at rva **0x2000**,
not at the 0x1000 the stub decodes to. Settling that means re-implementing FSG's bit reader for
this build and single-stepping it against a ground truth, which is a research task on one sample,
not a loader or unpacking rule.

**Conclusion: FSG is solved to its solvable limit - 96 of 97, six ahead of the reference's 90, with
nothing the reference passes being failed - and the one remaining row is a headerless artifact from
a different FSG build, whose blocker is identified at the instruction level.**

### 0.17ch Round 89 (FSG): the decoder is a research item - and it now has a harness

To settle the last row's LZ question without guessing, a faithful x86-subset emulator of the stub
was written (`/tmp/fsgemu.py`, research scaffolding, deliberately not in the tree): it executes the
stub's OWN bytes - the bit reader (`add dl,dl / jne / mov dl,[esi] / adc dl,dl`), the `call [esp]`
bit-read trampoline, the literal run, the three length paths, the `rep movsb` back-reference and
the block walker - against a memory model with the packed file at its base and the payload
workspace at its destination.

State of that harness: it runs `fsg_cmd`'s stub for 17.8k instructions and emits 0x7b5 bytes before
the back-reference walks below the image, which is *not* yet taote's own result for the same stub
(taote decodes that sample correctly: all-three, `code_sim 0.96`). So its semantics still differ
somewhere - most likely in the flag handling of the `adc` bit reader or in `call [esp]`'s operand
order - and it needs a debug loop against two ground truths that already exist:

- `fsg_cmd`, whose dump taote produces correctly and whose stream is intact, and
- `fsg_calc`/`fsg_dftp`-class rows, which pass with `code_sim` 0.96-1.0.

Only once the harness reproduces a known-good decode byte-for-byte is `fsg_Snap2HTML`'s stream
worth decoding, and only then can anyone say whether its bit stream is misaligned (a five-minute
fix) or the file is missing bytes (a closed row).

**Recommendation: close the FSG thread here.** The family is at **96 of 97, six ahead of the
reference's 90**, failing nothing the reference passes; the last row is a headerless artifact from
a different FSG build whose blocker is understood to the instruction and whose remaining work is a
decoder re-implementation with a harness, not another rule. Every mechanism shipped this session is
measured on the family and on the full 2678-sample corpus, guarded by five contract tests, and the
tree carries nothing unmeasured.

### 0.17ci Round 90 (FSG): decoder harness - one bug found and fixed, one remains; the dump is 89.6%

Continuing 0.17ch's harness against `fsg_cmd`, whose decode taote gets right:

- **Found and fixed a real semantics bug**: in the bit reader's reload path (`mov dl,[esi];
  adc dl,dl`) the CARRY-OUT is both the bit the caller reads and the flag the next
  `adc ecx,ecx` in the length readers consumes, so `CF` must be stored rather than recomputed from
  the byte's MSB. The instruction-level emulator (`add8`/`adc8`) already did this correctly, which
  is why the fix did not change its result - the divergence is elsewhere.
- **The target is sound**: taote's `fsg_cmd` dump is **89.6 % byte-identical to the original's
  image** overall (92.0 % over the payload span `rva 0x1000-0x4a000`, 1.2 % in the tail, which is
  the fixup/undecoded area), so the dump is the right thing to reproduce; a naive "first 32 bytes
  must match at the same rva" test was misleading me, not a layout shift.
- **The emulator reproduces 12.8 % of it** (0x7b5 bytes emitted, then a back-reference walks below
  the image at 17.8k instructions). So one semantic difference remains, somewhere in the length
  paths or the `call [esp]` trampoline, and finding it needs a differential trace - log the same
  pc's register state from unicorn (a temporary gate in the stub's hook) and from the emulator,
  then bisect the first disagreement. That is the next concrete step, and it is a debugging
  session, not a design decision.

Nothing from this work is in the tree (the harness lives in `/tmp/fsgemu.py`); FSG remains at
**96/97**, measured at HEAD, six ahead of the reference's 90.

### 0.17cj Round 91 (FSG): the last row's blocker is TWO BYTES in the stub, found by differential tracing

The differential harness from 0.17ch/0.17ci is now validated, and it answered the question.

**The harness.** `TAOTE_FSGTRACE=<n>` (new, env-gated, off by default - the same class of
scaffolding as `TAOTE_LASTPC`/`TAOTE_SEHDBG`) logs one line per executed instruction of the stub's
own section: `pc eax ebx ecx edx esi edi`. Run against `fsg_cmd`, it can be diffed line-for-line
with the hand-written emulator (`/tmp/fsgemu.py`). Getting them to agree took three real
corrections, and the model now matches unicorn **byte-for-byte over 40 000 instructions and 2.1 M
instructions of the full run**, with zero mismatching lines:

| # | what was wrong in the model | evidence |
|---|---|---|
| 1 | `2b cb` decoded as `sub ebx,ecx` | it is `sub ECX, EBX` (the reg field is the destination): unicorn had `ecx=1` where the model had `ebx=-1` |
| 2 | the incoming `ebp` was zeroed | the stub *reads* an incoming `ebp` at `xchg eax,ebp; mov eax,ebp`; unicorn starts it at `0xffffd000` |
| 3 | `rep movsb` hooked once | unicorn re-fires the code hook per iteration *and once more for the `ecx==0` evaluation* |
| 4 | `call [esp]` return address off by one | `ff 14 24` is 3 bytes, not 2 |

**The finding.** Pointing the validated model at `fsg_Snap2HTML` decodes its first literal byte to
**0x80** - exactly the original's `.text` first byte - and then diverges, because stub offset
**0x65-0x67** differs from the sibling build:

| | stub+0x63 | stub+0x68 |
|---|---|---|
| `fsg_cmd` (and the other repaired samples) | `91 48 c1 e0 08 ac` = `xchg eax,ecx; dec eax; shl eax,8; lodsb` | |
| **`fsg_Snap2HTML`** | `91 48 c1 03 00 ac` = `xchg eax,ecx; dec eax; rol dword [ebx],0; lodsb` | |

`shl eax,8` is the match-DISTANCE computation; `rol dword [ebx],0` is a no-op that also does not
touch `eax`, so the distance comes out wrong - which is exactly the `0x420ffe` bogus distance the
real run reports at `pc=0x420065`. So the row is not an LZ-format mystery: **two bytes of the packed
file's stub are mutated**, and the sibling build says what they should be. Patching them back
(`c1 03 00` -> `c1 e0 08`) makes the model progress past that instruction, which is as far as the
model goes until more of the fixup-walker opcodes are implemented.

That is the remaining work for this row, and it is a modelling/debugging task with a validated
harness and a two-byte hypothesis - not another loader rule. Nothing from the harness is in the
tree except the trace gate; FSG remains at **96/97** measured at HEAD.

### 0.17ck Round 92 (FSG CLOSED, 96/97): the last row is damaged stub + non-decodable data, proved by sweep

Round 91 narrowed `fsg_Snap2HTML.exe` to two mutated stub bytes using the validated model. Finishing
that line of work settles the row, and it settles it the other way.

**1. The stub is damaged, not merely a sibling.** Comparing each FSG sample's stub (0x1d0 bytes at
its entry section, the three absolute immediates normalised) against every other sample gives a
tight family: `fsg_cmd`'s nearest neighbours differ by **12 of 464 bytes**, which is just the
immediates and a couple of data words. `fsg_Snap2HTML`'s nearest neighbour differs by **49 bytes**
and its code contains instructions that cannot run at all - `8b 00 a0 04 00` at stub+0x87 decodes
to `mov eax,[eax]; mov al,ds:0x5ea40004`, where every intact build has
`8b f7 2b f0 f3` = `mov esi,edi; sub esi,eax; rep movsb`, the whole match-copy. A file whose own
entry stub cannot execute is not a decoder-semantics puzzle.

**2. Its data does not decode under the family's format either.** Replacing the damaged code region
with the intact build's code (keeping Snap2HTML's own data, block table and stream) and sweeping
both unknowns - stream start and payload destination - over the plausible values leaves nothing:

| stream | dest | result |
|---|---|---|
| 0xf199 (the stub's own constant) | 0x401000 | out-of-buffer match read at 0x3ffa24 after 1 byte |
| 0xf199 | 0x402000 | same at 0x3ffe5e after 0x13 bytes |
| 0x1000 | 0x402000 | wild write to 0xfd8e0001 |
| 0x400 | 0x401000 | out-of-buffer read after 0x100 bytes |
| 0x200 | any | wild write to 0xfd8e0001 |

Every arm dies within a few hundred instructions: match distances that point before the start of the
output buffer (which a valid LZ stream cannot produce, since a match may only reference data already
decoded) or destination addresses that are nonsense (0xfd8e0001). The apparent 21-24 % "match" in
that table is zeros matching zeros, not decoding.

**3. The control is clean.** The same model, same code, same method decodes `fsg_cmd`'s stream to
**0x22c1f bytes** and then enters the block walker, which is why taote's cmd dump is 89.6 %
byte-identical to the original's image.

**Conclusion.** `fsg_Snap2HTML.exe` has no `PE\0\0` anywhere, its entry stub is damaged in the two
places that compute and apply matches, and its data is invalid under the family's format from every
plausible start. It is dead packer output, not a taote defect, and no mapping, mining or picking rule
can convert it - which is what "prove it per-sample and close with evidence" asked for. FSG therefore
closes at **96 of 97** against the reference's **90 of 97**, with the reference also failing this row
("Target file is not a PE"). Both closures are now mechanism-level, and the decoder harness that
proved it is committed as the off-by-default `TAOTE_FSGTRACE` gate.

### 0.17cl Round 92b: closure verified at HEAD, twice

`fsg14` (97 rows, 85 s, 4 workers, tree `65b88a0`) reproduces `fsg13` exactly:

| arm | valid PE | OEP exact | imports | all-three | only failure |
|---|---|---|---|---|---|
| fsg13 (round 91) | 96 | 96 | 96 | 96 | `fsg_Snap2HTML.exe` |
| **fsg14 (HEAD `65b88a0`)** | **96** | **96** | **96** | **96** | `fsg_Snap2HTML.exe` (unparsable) |

So the two docs-only commits between them changed nothing, and the end state of the family is:
75 of 97 all-three at the session start, **96 of 97 now**, against the reference's 90 of 97, with the
single remaining row proved dead packer output (0.17ck) rather than a taote defect. `fsg_livekd.exe`,
the other long-standing holdout, passes.

That is the closure. There is no measured mechanism left on this family: every row either converts
all three criteria or is a file whose stub cannot execute and whose data is invalid under the
family's own format. Further work on it would have to come from new evidence outside the corpus.

### 0.17cm Round 93: the closure's last gap - the dead row is a *graceful* failure, now pinned

Verifying the close turned up one untested edge, and it was worth finding: the shipped CLI handles
the headerless FSG row cleanly

    reason=input_parse_failed imports=0 error=the input header is not recoverable

but the in-process test harness (`tests/Unpack_Compat_Test.cpp::run_unpack`) did **not** - it called
`plan_for()` unguarded, so `LIEF parse failed: ...` escaped as a C++ exception instead of coming
back as a result. The harness's own comment says it measures the library "the same shape the CLI
drives", so it now mirrors `tools/taote.cpp`: the plan attempt is wrapped, and an unrecoverable
header returns `reason=input_parse_failed`, `error=the input header is not recoverable`, zero base /
OEP / imports and no dump.

`UnpackCompat.FsgHeaderlessInputFailsGracefully` pins that contract on `FSG/fsg_Snap2HTML.exe`:
zero base and OEP, no imports, `dump_written == false`, and an `input_parse_failed` reason - i.e.
the dead row stays dead *quietly*, which is the "never crash" rule applied to the one file in the
family that cannot be unpacked. Suite 599 -> **600**, all green; the test skips cleanly when the
corpus is absent (`TAOTE_PACKED_DIR=/tmp/no_corpus`).

Tests-only change, so the shipped binary is untouched and the family measurement stands: fsg14 at
HEAD, valid PE 96, OEP exact 96, imports 96, all-three **96/97**, the single failure being this row.

### 0.17cn Round 94: the highest-value FSG mechanism is now a real regression lock

Five FSG mechanisms bought the family its 75 -> 96 arc; four were pinned in round 78, and the one
that was not is the one that bought the most rows: round 68's **per-block first-character shift
vote**. It was only covered indirectly (`imports.size() > 300` on `fsg_HashCalc`), and a count
survives a lot of damage, so it was not a lock.

`UnpackCompat.FsgStringShiftIsUndoneAsABlockVote` pins the vote itself on `fsg_rm.exe`, which ships
the names that separate the two implementations:

| name | per-name evidence alone | with the block vote |
|---|---|---|
| `_isctype`, `_pctype` | absent - no export-database entry exists for these spellings | **present** |
| `fopen`, `tolower`, `putc` | left as `iopen`/`wolower`/`sutc` | **present** |

The test asserts those five are present and that the shifted spellings (`bisctype`, `bpctype`,
`b_mb_cur_max`) are gone. **It was verified to fail when the mechanism is removed**: with
`block_is_shifted` forced to `false` the case fails with `_pctype missing ... pairs=110`; with the
vote restored the suite is **601/601** green. So this is a lock on the mechanism, not on a number.

Tests-only, so the shipped binary is unchanged: fsg14 stays the family measurement at HEAD
(96/97, single failure `fsg_Snap2HTML.exe`).

### 0.17co Round 95: full corpus at HEAD after the FSG close - 1864, zero losses

The corpus figure quoted through rounds 78-94 was measured at round 82's binary (r59). Every commit
since was docs or tests only, but "no behaviour change" is a claim, not a measurement, so the corpus
was re-run at HEAD (`2682958`): 2678 samples, 85 s, 4 workers, started on a quiet machine
(loadavg 0.27, no stray pegasus-cli) and finished 2678/2678.

| arm | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r59 (round 82 binary) | 2675 | 1974 | 2053 | 1863 |
| **r60 (HEAD `2682958`)** | **2675** | **1974** | **2054** | **1864** |

Exactly one row changed, in the safe direction: `mpress_ComIntRep.exe` all-three False -> True (its
imports land when the machine is idle - the known boundary row that needs ~78 s alone). **Zero
all-three losses, zero OEP changes, zero valid-PE changes.** FSG inside the same run grades 96 of 97,
matching the dedicated fsg14 arm row for row.

So the FSG arc closed with no collateral damage: the honest corpus capability at HEAD is
**1864/2678 all-three** (the 1863-1864 band, since `mpress_ComIntRep` sits on the budget boundary),
OEP exact 1974/2501, imports 2054/2568, valid PE 2675/2678, suite 601/601.

### 0.17cp FSG - AUTHORITATIVE SUMMARY (read this, not the intermediate sections)

The family's record spans sections 0.17bj-0.17co and several of them state conclusions that later
rounds overturned. This section is the single source of truth; where it disagrees with an earlier
section, this one wins.

**Final state, measured at HEAD (`fb5cdb1`).** FSG is **96 of 97 all-three** (valid PE 96, OEP exact
96, imports 96) against the reference's **90 of 97**, so six rows ahead, failing nothing the reference
passes. Reproduced by two dedicated family arms (`fsg13`, `fsg14`: 97 rows, 85 s, 4 workers) and by
the full corpus run (`r60`, 1864/2678 all-three, zero losses). `fsg_livekd.exe` and `fsg_cmd.exe`,
the long-standing holdouts, both pass (`oep 0x409663 / 0x4ad0829a`).

**The five shipped mechanisms**, each measured family-first then corpus, zero losses outside FSG:

| mechanism | effect | pinned by |
|---|---|---|
| `FileAlignment < SectionAlignment` guard in the loader | entry section stops being dropped (9 OEPs) | `FsgEntryIsTheStubRel32HandOff` |
| per-BLOCK undo of the -3 first-char shift (incl. `B?` mangled names) | imports 75 -> 85 (7 rows) | `FsgStringShiftIsUndoneAsABlockVote` |
| OEP from the stub's `0f 84` rel32 hand-off | 6 wrong-OEP rows -> exact | `FsgEntryIsTheStubRel32HandOff` |
| ordinal-record mining + stub rebase for non-0x400000 bases | 4 rows convert | `FsgOrdinalRecordsAreMined`, `FsgStubIsRebasedForANonDefaultBase` |
| truncated block-page map (16-bit page overflow) | `fsg_cmd` converts | `FsgTruncatedBlockPageIsMapped` |

plus `FsgZeroedDosSignatureIsRepaired` for the zeroed-`MZ` repair (which must happen BEFORE Qiling is
constructed, hence the shared `repairable_sample` helper).

**The one failure is dead packer output, not a taote defect.** `fsg_Snap2HTML.exe` has no `PE\0\0`
anywhere, its entry stub is damaged (49 of 464 stub bytes diverge from its nearest neighbour where a
normal row diverges by 12, including `mov eax,[eax]; mov al,ds:0x5ea40004` where every intact build
has the whole match-copy `mov esi,edi; sub esi,eax; rep movsb`), and its data decodes from no
plausible stream start x destination under the family's own semantics - every arm dies on a match
distance pointing before the output buffer or on a nonsense write, while the `fsg_cmd` control
decodes 0x22c1f valid bytes with the same model. The row fails gracefully and that contract is pinned
by `FsgHeaderlessInputFailsGracefully`.

**Superseded sections - do not act on these:**

| section | superseded claim | now |
|---|---|---|
| 0.17bm | "closed at 82/97, every row at a ceiling" | 96/97 |
| 0.17bs | "`fsg_Snap2HTML` is truncated" | complete file, headerless; payload just not decodable |
| 0.17bu | "the 94 is stable, thread closed" | 96 |
| 0.17cd | "Snap2HTML's third constant points nowhere" | the constant is correct (0.17ce) |
| 0.17cg/0.17ch | "solvable work is done / decoder is a research item" | closed with a mechanism-level proof (0.17ck) |
| 0.17cj | "the blocker is two mutated stub bytes" | part of it: the stub is damaged in the match-copy too |

**The harness.** `TAOTE_FSGTRACE=<n>` (env-gated, off by default) logs one line per executed stub
instruction. It enabled a hand-written model of FSG's decoder that matches unicorn **byte-exactly
over 40 000 instructions and 2.1 M instructions of a full run**. That is how the last row was
settled, and it is the tool to reach for if an FSG-like build ever appears again. Traps worth
keeping: `2b cb` is `sub ECX,EBX` (reg field is the destination), the stub reads an INCOMING `ebp`,
unicorn re-fires the code hook per `rep movsb` iteration plus once for `ecx==0`, and `ff 14 24` is
3 bytes.

**Why nothing more is planned.** Every row either converts all three criteria or is a file whose
entry stub cannot execute. New work on this family would have to start from evidence outside the
corpus. Measurement hygiene still applies to any future corpus number: quiet machine, no stray
`pegasus-cli`, and treat `mpress_ComIntRep`, `winupack_Bginfo`, `bero_HDDScan` and `mpress_Bginfo` as
budget-boundary rows (1863-1864 band) rather than diffs.

### 0.17cq FSG - the per-sample ledger (the "state it per row" proof)

Directive item 3 asked for a per-sample statement rather than a family-level claim. This is that
ledger: all 97 FSG rows, measured in one 85 s / 4-worker arm (`fsg14`, tree equivalent to HEAD), with
the load base, the OEP the run claimed (relative to the base), the mechanism that produced it, and
the grading margins.

Clause first: **96 of 97 pass all three criteria**; the mechanism split is 80 rows
`stages=1 / section_hop` (the payload decoded and control transferred through a section hop), 16 rows
`stages=1 / ladder_scan` (the stub's `0f 84` rel32 hand-off is the last-resort ladder), and 1 row
`unparsable`. Bases: 91 at the default `0x400000`, 4 rebased to `0x1000000` (the stub-rebase rescue),
1 at `0x4ad00000` (`fsg_cmd`, the truncated block page). The thinnest margins among passing rows are
`fsg_livekd` (code_sim 0.105, imp_recall 0.973) and `fsg_cmd` (code_sim 0.960, imp_recall 1.000);
everything else is >= 0.857 code_sim and >= 0.975 recall, so nothing passes by luck.

| row | base | oep rva | stages/reason | code_sim | imp_recall | all-three |
|---|---|---|---|---|---|---|
| fsg_ADExplorer | 0x400000 | 0x149ec | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_AccessEnum | 0x400000 | 0x7a98 | 1/ladder_scan | 1.000 | 0.987 | yes |
| fsg_Autologon | 0x400000 | 0x3980 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_Autoruns | 0x400000 | 0x51b4a | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_Bginfo | 0x400000 | 0x1b5d42 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_BlueScreenView | 0x400000 | 0xe78e | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_Cacheset | 0x400000 | 0x24a2 | 1/ladder_scan | 1.000 | 1.000 | yes |
| fsg_Clockres | 0x400000 | 0x4002 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_ComIntRep | 0x400000 | 0x2800a | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_Contig | 0x400000 | 0x7f58 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_Coreinfo | 0x400000 | 0x7474 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_DarkNamer | 0x400000 | 0xa71e | 1/ladder_scan | 1.000 | 0.988 | yes |
| fsg_Dbgview | 0x400000 | 0x15757 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_Desktops | 0x400000 | 0x46c6 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_DiskView | 0x400000 | 0xc983 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_Diskmon | 0x400000 | 0xb4b8 | 1/ladder_scan | 1.000 | 0.995 | yes |
| fsg_DriverView | 0x400000 | 0xa36a | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_ESEDatabaseView | 0x400000 | 0xfeea | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_EventLogChannelsView | 0x400000 | 0xe52e | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_Everything | 0x400000 | 0x145f0d | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_FastHash_kr | 0x400000 | 0x1dffa | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_FileTypesMan | 0x400000 | 0x109f0 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_FindLinks | 0x400000 | 0x4c99 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_FolderTimeUpdate | 0x400000 | 0xc3a6 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_FullEventLogView | 0x400000 | 0x11228 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_HWMonitorPro_x32 | 0x400000 | 0xcb60b | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_Hash | 0x400000 | 0x532c | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_HashCalc | 0x400000 | 0x11e58 | 1/ladder_scan | 1.000 | 1.000 | yes |
| fsg_InstalledPackagesView | 0x400000 | 0xd42a | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_LastActivityView | 0x400000 | 0x127f8 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_Listdlls | 0x400000 | 0x9666 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_LoadOrd | 0x400000 | 0x4e14 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_LoadOrdC | 0x400000 | 0x4de2 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_OpenedFilesView | 0x400000 | 0xfc10 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_PEview | 0x400000 | 0x1000 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_PortableWinCDEmu-4.0 | 0x400000 | 0x1216a | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_Procmon | 0x400000 | 0x755cb | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_ProduKey | 0x400000 | 0xd10a | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_PsExec | 0x400000 | 0x9de6 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_PsGetsid | 0x400000 | 0x7ecb | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_PsInfo | 0x400000 | 0xa0cf | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_PsLoggedon | 0x400000 | 0x5926 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_PsService | 0x400000 | 0x7f52 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_RAMMap | 0x400000 | 0x1ab3f | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_RegDelNull | 0x400000 | 0x5426 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_RegDllView | 0x400000 | 0xc80c | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_ShareEnum | 0x400000 | 0x9013 | 1/ladder_scan | 1.000 | 0.987 | yes |
| fsg_ShellRunas | 0x400000 | 0x3ba0 | 1/ladder_scan | 1.000 | 0.993 | yes |
| fsg_Snap2HTML | - | - | unparsable | - | - | **NO** |
| fsg_Tcpview | 0x400000 | 0x149d8 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_accesschk | 0x400000 | 0xc429 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_adrestore | 0x400000 | 0x2471 | 1/ladder_scan | 1.000 | 0.975 | yes |
| fsg_autorunsc | 0x400000 | 0x408dd | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_calc | 0x1000000 | 0x12d6c | 1/section_hop | 0.973 | 1.000 | yes |
| fsg_cmd | 0x4ad00000 | 0x829a | 1/section_hop | 0.960 | 1.000 | yes |
| fsg_cpuz_x32 | 0x400000 | 0xf7c76 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_ctrl2cap | 0x400000 | 0x221a | 1/ladder_scan | 1.000 | 0.986 | yes |
| fsg_dfrgui | 0x1000000 | 0x141fa | 1/section_hop | 0.948 | 1.000 | yes |
| fsg_diskext | 0x400000 | 0x480c | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_du | 0x400000 | 0x68c9 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_efsdump | 0x400000 | 0x2138 | 1/ladder_scan | 1.000 | 0.986 | yes |
| fsg_ftp | 0x1000000 | 0x834d | 1/section_hop | 0.919 | 1.000 | yes |
| fsg_handle | 0x400000 | 0x7336 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_hex2dec | 0x400000 | 0x47af | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_junction | 0x400000 | 0x64ac | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_ldmdump | 0x400000 | 0x3024 | 1/ladder_scan | 1.000 | 0.986 | yes |
| fsg_livekd | 0x400000 | 0x9663 | 1/ladder_scan | 0.105 | 0.973 | yes |
| fsg_logonsessions | 0x400000 | 0x5f5b | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_movefile | 0x400000 | 0x3f4b | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_mtinst | 0x1000000 | 0x3866 | 1/section_hop | 0.858 | 1.000 | yes |
| fsg_notmyfault | 0x400000 | 0x4f25 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_notmyfaultc | 0x400000 | 0x5810 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_ntfsinfo | 0x400000 | 0x46af | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_pagedfrg | 0x400000 | 0x3d50 | 1/ladder_scan | 1.000 | 1.000 | yes |
| fsg_pendmoves | 0x400000 | 0x4452 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_pipelist | 0x400000 | 0x550b | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_portmon | 0x400000 | 0x13b0e | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_procdump | 0x400000 | 0x171e7 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_psfile | 0x400000 | 0x54a0 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_pskill | 0x400000 | 0x763e | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_pslist | 0x400000 | 0x9bbe | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_psloglist | 0x400000 | 0x9955 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_pspasswd | 0x400000 | 0x5be3 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_psping | 0x400000 | 0x115cc | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_psshutdown | 0x400000 | 0x677f | 1/ladder_scan | 1.000 | 1.000 | yes |
| fsg_pssuspend | 0x400000 | 0x74fe | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_regjump | 0x400000 | 0x4256 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_rm | 0x400000 | 0xcb7b | 1/ladder_scan | 1.000 | 1.000 | yes |
| fsg_ru | 0x400000 | 0x570c | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_sdelete | 0x400000 | 0x699f | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_shexview | 0x400000 | 0xef60 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_shmnview | 0x400000 | 0xb008 | 1/ladder_scan | 1.000 | 0.981 | yes |
| fsg_sigcheck | 0x400000 | 0x1b7cb | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_streams | 0x400000 | 0x4a16 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_strings | 0x400000 | 0x58a6 | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_sync | 0x400000 | 0x49fe | 1/section_hop | 1.000 | 1.000 | yes |
| fsg_sysexp | 0x400000 | 0xacb2 | 1/section_hop | 1.000 | 1.000 | yes |

### 0.17cr Round 98: host-safety audit of the FSG code paths, and a diagnostic hole it found

The one standing rule never yet applied to this family was "never crash" against *hostile* input: all
FSG work had been on well-formed samples (plus the crafted `ImageBase` stress of round 81). So twelve
corrupt variants of the FSG rows were run through the shipping CLI:

| variant | rc | crash | reason |
|---|---|---|---|
| truncated to 0x200 | 0 | no | `dump_verbatim` |
| truncated to half | 0 | no | `ladder_scan` |
| EP past EOF | 0 | no | `fallback_guess` |
| EP inside the headers | 0 | no | `fallback_guess` |
| `NumberOfSections = 0` | 0 | no | `dump_verbatim` |
| `NumberOfSections = 0xffff` | 0 | no | **`init_failed`** (was empty) |
| `SizeOfImage = 0` | 0 | no | `section_hop` |
| entry section raw pointer past EOF | 0 | no | `fallback_guess` |
| base at the 4 GB boundary | 0 | no | `ladder_scan` |
| stub bytes zeroed | 0 | no | `fallback_guess` |
| headerless row + grafted `PE\0\0` | 1 | no | `input_parse_failed` |
| headerless row truncated | 1 | no | `input_parse_failed` |

No crash, no hang, no runaway allocation: every variant finished in <= 1 s with rc 0 or 1. **The
audit's one real find was a diagnostic hole.** A header the loader refuses outright (the absurd
`NumberOfSections`) printed `reason=` with nothing after it, so the single most corrupt class of input
was the least diagnosable one. Three small fixes, all text-only:

1. `Unpacker::finalize` names the state it could not otherwise classify, **at the very end** of the
   function so every specific label still wins (`init_failed` / `no_hop`). The naive placement at
   `res.reason = reason_` was caught immediately: it pre-empted `dump_verbatim` on the
   truncated-header rows and cost them their specific label.
2. `tools/taote.cpp`'s `else` branch - the engine never came up, so no `finalize()` result exists -
   sets `init_failed`.
3. The test harness mirrors it, so an in-process run reports the same words as the CLI.

**Measured after the change:** `fsg15` (97 rows, 85 s, 4 workers) gives valid PE 96, OEP exact 96,
imports 96, all-three **96/97**, and **no row's all-three changed** against `fsg14`; `fsg_cmd`
(341 imports), `fsg_HashCalc` (446) and `fsg_livekd` (368) are bit-identical; suite 601/601.

### 0.17cs Round 99: corpus re-measured after the diagnostic change - bit-for-bit neutral

The corrupt-input audit shipped a change inside `Unpacker::finalize` and `tools/taote.cpp`, so the
"measure the corpus after every change" rule applied even though the change only writes a reason
string. `r61` (2678 samples, 85 s, 4 workers, HEAD `8315001`, quiet-ish machine at loadavg 0.8):

| arm | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r60 (FSG close) | 2675 | 1974 | 2054 | 1864 |
| **r61 (HEAD)** | **2675** | **1974** | **2054** | **1864** |

**Zero gains, zero losses, no row changed any of the three criteria.** FSG grades 96/97 inside the
same run, matching `fsg14` and `fsg15`. So naming the unclassified failure state is corpus-neutral,
as a diagnostic-only change should be - and it is now measured rather than assumed.

### 0.17ct Round 100: the corrupt-input contract is pinned (suite 601 -> 602)

Round 98 fixed a diagnostic hole - a header the loader refuses outright printed `reason=` with
nothing after it - but shipped it unpinned, which is exactly the discipline every other FSG
mechanism got. `UnpackCompat.CorruptSectionCountFailsGracefully` closes that: it reads
`FSG/fsg_cmd.exe`, sets `NumberOfSections` to `0xffff` (so the section table runs past EOF and no
image can be built), runs it in-process, and requires a *result* rather than an exception with
`base == 0`, no imports, and `reason == "init_failed"`.

Verified to be a real lock rather than a formality: with the round-98 fallbacks reverted the CLI path
prints the empty reason the audit found (see the twelve-variant table in 0.17cr), and the library
fallback in `Unpacker::finalize` is what turns it into `init_failed` / `no_hop`. Note the layering:
the test exercises the harness's mirror of the CLI's `else` branch, which is why it keeps passing if
only `tools/taote.cpp` is reverted - the CLI behaviour itself was verified by the audit, and the
library fallback by the twelve-variant table. Suite **602/602**, all green; skips cleanly without the
corpus. Tests-only, so the shipped binary and the corpus figures are unchanged (r61: 1864/2678,
zero losses).

### 0.17cu Round 101: FSG is at its CEILING, and the 96 are structurally stable

Two questions remained after the close, and both now have hard numbers.

**Is 96/97 the ceiling?** Yes, by construction. `fsg_Snap2HTML.exe` is the only failing row and it is
dead packer output (0.17ck), so no FSG row can improve: 96 is the maximum achievable without the
ground-truth original, which taote must never consult.

**Are the 96 stable, or budget-boundary passes?** Measured from the `fsg15` run's recorded durations:
97 rows run in **0-19 s** against the 85 s budget - min 0, median **1 s**, max 19 (`fsg_Bginfo`) -
and **zero** rows fall within 20 s of the cap. Contrast the corpus rows that do flake
(`mpress_ComIntRep` ~78 s alone, `winupack_Bginfo`, `bero_HDDScan`, `mpress_Bginfo` at 83-86 s): FSG
has no such rows at all, because its stubs finish their work in milliseconds once the page mapping is
right. So the family's 96 is not a scheduling artefact - it is the same 96 in every arm, and it would
be the same 96 on a loaded machine.

That closes the thread: ceiling reached, stability proven, every mechanism pinned, the record is
authoritative (0.17cp) and per-row (0.17cq). **No further FSG work is planned, because none exists
that measurement can justify.** A future round touching this family should start only from new
external evidence - a working `fsg_Snap2HTML`-build sample, or a regression in one of the 96.

### 0.17cv Round 102: is any FSG-packed row hiding outside the family gate? No.

The family-gated mechanisms (stub rebase, block-page map, rel32 hand-off) fire on the stub's
`bb .. bf .. be ..` prologue rather than on the family name, so a natural question was whether some
sample filed under another family is actually FSG-packed and would be missed - FSG work, not another
family's queue, and potentially real gains.

Scanned all 2678 corpus samples for that prologue at their own entry point:

| | |
|---|---|
| samples with the FSG prologue at EP | **95** |
| of those, filed under FSG | **95** (all of them) |
| of those, failing all three | **0** |

The two FSG rows the scan does not see are exactly the two already characterised: `fsg_livekd.exe`
(zeroed `MZ`, so the scan's own magic test skips it; taote repairs it and passes) and
`fsg_Snap2HTML.exe` (headerless, dead packer output). So the gate is complete - no FSG-packed sample
lives outside the family directory, and no row the mechanisms could help is currently failing.

That is the last cross-cutting check available: the family is at its ceiling (0.17cu), gated
completely (here), pinned (0.17bv/0.17cn/0.17ct), documented per row (0.17cq) and host-safe (0.17cr).

### 0.17cw Round 103: the post-OEP grace window was PORTED, MEASURED and REJECTED

The next priority after FSG was pegasus's post-OEP grace window (`unpacker.cpp:5980-6035`,
`oep_grace_secs_for_packer_`): after an accepted hop, stop once the deadline has passed AND the
import floor is quiet AND an artifact exists, instead of emulating the already-unpacked application
to the wall. It is the largest mechanism taote lacked, so it was implemented behind a gate
(`--oep-grace SECS`, `TAOTE_OEP_GRACE` env, `< 0` = off) and armed from every accepted hop, with a
block hook installed only when the window is on.

**First arm (window = 0 s, quiet floor 200k blocks / 3 s) read as a huge win - and was wrong.**
Against r61 it showed 13 all-three gains and 20 % wall saved on the 40 wall-bound rows. The gains
came from comparing against a *contended* baseline: re-running the same rows solo showed
`bero_Bginfo` at 63 s / 1957 imports with the window **off** as well, i.e. the r61 figure (86 s /
2 imports) was the row being cut off before its hop under corpus load, not a window effect.
Instrumenting the hook settled it: on the corpus those rows never armed at all (`grace tick
blocks=500000 armed=0 imports=0 stages=0`), because the stub decode alone fills the 85 s budget.

**Back-to-back A/B, same 40 wall-bound rows, same machine, window OFF vs ON** (quiet floor raised to
1M blocks / 10 s after the first corpus arm lost `mpress_ComIntRep` 1.0000 -> 0.0342 and
`winupack_Bginfo` 1.0000 -> 0.9373):

| arm | wall | all-three | recall drops |
|---|---|---|---|
| window OFF | 2717 s | - | - |
| window ON (1M blocks / 10 s) | **2749 s (101 %)** | **0 gains, 2 losses** | `expressor_Bginfo` 1.0000 -> 0.0337, `nspack_Bginfo` 1.0000 -> 0.0314 |

**Why it cannot work here.** The reference's saving (`8b05c902`: `--unpack` 11.08 s -> 1.24 s;
`5ebede29`: UPX corpus 442 s -> 39 s) is earned by not emulating hundreds of seconds of *application*
code after the hop, at 8.3 us/API. In taote the stub's own decode is what fills the budget - the
post-OEP application run is a small fraction - so there is nothing to save, and any window that stops
early stops inside the decode's late import burst (both losses are 1.0000 -> ~0.03, the whole burst).
Raising the floor to 10 s did not fix it, and raising it further would eliminate the window.

So the mechanism is reverted (code back to HEAD, suite 602/602 green, no behaviour change) and
recorded here as measured-and-rejected. The real lever for those 40 rows is **instruction
throughput** (the ~174 ns/insn dispatch cost), not a post-OEP window - stopping earlier cannot help
a run that never gets far enough.

### 0.17cx Round 104: the UPX EP-repair port does NOT apply to this corpus - measured, not assumed

Second lead from the pegasus review: `d08abb3e` repairs an `AddressOfEntryPoint` that points into a
section with **no file bytes** by starting emulation at the UPX stub prologue
(`60 BE ?? ?? ?? ?? 8D BE`) found in a mapped raw section. Before porting, a census of all 2678
corpus samples:

| | |
|---|---|
| rows whose EP bytes are absent from the file (raw 0, or EP offset >= raw size) | **6** |
| of those, carrying the UPX prologue anywhere in a raw section | **0** |

The six are `Alienyze/alienyze_tinytask.exe` (EP section raw size 0, the exact class, but no UPX
prologue - it is Alienyze, not UPX) and five NSPack rows whose `nsp0` destination section declares
3-26 raw bytes while the header EP is `nsp0+0x1b`. Since the reference's gate is the UPX prologue,
the port would fire on **zero** rows: unmeasurable, so it is not shipped.

The six are still real headroom, so they were probed instead of dismissed:

* `nspack_ldmdump.exe` run from three plausible entries - the entry section's virtual start
  (`0x1000`), the raw section's start (`0x26000`) and that start plus the EP offset (`0x2601b`) -
  gives `stages=0 reason=fallback_guess imports=10` in all three, i.e. no hop. What `nsp0` declares
  as its raw data is a copy of the section table itself (`00 00 ... 2e 74 65 78 74` = ".text"), in
  the passing rows too, so the entry bytes are not code in either case; the failing rows simply
  declare even fewer of them.
* The interesting one is `alienyze_tinytask.exe`, where `file size 0xa101` but the declared sections
  stop at `0x4000` - about 0x6101 bytes of overlay the section table never describes, which is where
  an Alienyze stub/payload would live. That is a *generic overlay* gap (map file bytes beyond the
  section table), not a UPX EP-repair, and it is the next item to measure on the Alienyze family
  (110 rows of headroom).

Nothing was changed in the tree this round: no code, suite 602/602, corpus baseline unchanged
(r61: all-three 1864/2678, OEP 1974/2501, imports 2054/2568, valid PE 2675/2678).

Sized before anyone chases it: an overlay census over the Alienyze family finds exactly **one** row
with more than 0x200 bytes of file beyond its last section (`alienyze_tinytask`: 0x6101 bytes of
overlay). So the overlay mechanism is worth at most one row, not the family's 110 headroom - the
Alienyze block is decode/attribution, not layout. That closes both leads from the pegasus review as
"measured, low value" and leaves the family headroom table as the honest map.

### 0.17cy Round 105: descriptor-ANCHORED string mining - corpus 1864 -> 1873, zero losses

Next lead from the pegasus review, in the family-headroom direction this time. RLPack's block is not
layout: 104 rows, OEP-exact 73, **imports-ok 1**, all-three 0. Diagnosed by measuring, for every
missing truth pair, whether the name STRING is in the dump at all:

| | |
|---|---|
| RLPack rows with missing pairs | 103 |
| missing pairs | 19 391 |
| name string PRESENT in the dump (attribution gap) | **4 069 (21 %)** |
| name string absent (runtime resolution - the loader/hash-walk class) | 15 322 (79 %) |

So a fifth of RLPack's gap is taote dropping strings it already has, and recovering exactly those
moves **7 rows over the 0.95 criterion** (`accesschk` 0.048 -> 1.000, `handle` 0.692 -> 1.000,
`livekd` 0.047 -> 0.987, `procexp` 0.038 -> 0.964, `ADInsight` 0.037 -> 0.985, `Coreinfo`
0.052 -> 0.965, `procdump` 0.064 -> 0.959).

**Why they were dropped.** `mine_orphan_descriptors` returns early from every bare-string blob
heuristic when `image_descriptor_count_ >= 4`, because the *unrestricted* blob passes fabricated
phantoms (MSPDB80.DLL, hhctrl.ocx) on images that carry a real chain. RLPack's decoded image carries
a real-but-mostly-EMPTY chain (23 descriptors -> 27 imports on `rlpack_Bginfo`) while the names it
omits sit in the image as plain strings.

**The mechanism (precision-safe by construction).** Instead of returning, run a
descriptor-ANCHORED pass: scan the image for identifier-like runs and accept a name only when its
EXACT spelling is a known export (`api_owner`) AND its owner is one of the DLLs the image's own
descriptors already named. No new DLL can be invented, and a data string can never claim a phantom
module - the failure mode the original gate existed to prevent.

**Measured, family first** (RLPack, 104 rows, 85 s, 4 workers): all-three **0 -> 7**, imports-ok
1 -> 8, OEP-exact 73 (unchanged), recall up on 35 rows and **down on 0**, mean recall
0.220 -> 0.370; mean precision 0.745 -> 0.534 (the added names are real exports of declared DLLs,
but data strings that spell an export name do add entries).

**Then the corpus** (`r63`, 2678 samples, 85 s, 4 workers):

| arm | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r61 | 2675 | 1974 | 2054 | 1864 |
| **r63** | **2675** | **1974** | **2066** | **1873** |

**+9 all-three, zero losses**: RLPack 0 -> 7, NSPack 87 -> 89 (`ADInsight`, `cpuz_x32` - their
strings were being dropped for the same reason). Recall up on 72 rows and down on **0**; mean recall
0.8137 -> 0.8217. Mean precision 0.6717 -> 0.6342, with three families losing more than 0.10
(Enigma Virtual Box 0.527 -> 0.375, Neolite 0.860 -> 0.716, RLPack 0.745 -> 0.535) - the cost of the
extra (real, declared-DLL) names, which the grader does not charge for (its import criterion is
recall >= 0.95; `imp_exact` tracks precision separately). rc distribution 2676 clean, 1 timeout,
1 non-zero, i.e. no new faults.

### 0.17cz Round 106: RLPack's residual is EMULATION DEPTH, not export tables - measured, no code

The next lead was the "real export tables" idea (pegasus `fb9a14a3`, forwarder-module loads): RLPack
resolves imports with its own hash walk over a module's export directory, so giving the synthesized
stub DLLs the real per-DLL export surface should let those walks succeed. Implemented the reverse
query (`api_exports_of(dll)` from the SDK database, 32 374 names / 405 DLLs) and then measured
before wiring it in, which killed it:

1. `write_stub_dll` **already** unions the caller's names with `ApiRegistry::names_for_dll()` - the
   full surface taote can actually serve with a handler. Exporting extra names from the database
   would let a hash walk find them but leave the call without a handler.
2. More importantly the premise is wrong for this family: **103 of 104 RLPack rows have
   `code_sim >= 0.5`** (mean recall on that set 0.373; the one low-decode row,
   `rlpack_adwcleaner`, 0.47). The payload decodes; what is missing is that RLPack's stub resolves
   its imports AT RUNTIME and the names materialise only when the payload actually calls them. So the
   missing 79 % are not strings waiting to be found - they are resolutions that never happen inside
   the emulated window.

That reframes the residual: RLPack's remaining headroom is **emulation depth/throughput** (how much
of the application runs before the budget ends), the same lever the rejected grace-window experiment
pointed at, not an import-mining or export-table mechanism. Reverted (api_db untouched, suite
602/602, tree clean).

Recorded so the next round does not chase it: a hash-walk packer cannot be helped by exporting more
names when the names are only ever produced by calls the run never reaches.

### 0.17da Round 107: Neolite's blocker is HOP SELECTION, not decode and not imports

Neolite (93 rows) is mapped as 91 of headroom, and the family table only says "not all-three". The
breakdown says something much more useful:

| criterion | Neolite r63 |
|---|---|
| valid PE | 93 / 93 |
| **imports ok (recall >= 0.95)** | **80 / 93** |
| OEP exact | **2 / 93** |
| all-three | 2 / 93 |
| code_sim | < 0.3 on **91** rows |

So the family is neither decode-blocked nor import-blocked: a hop IS accepted on 91 rows
(`reason=section_hop stages=1` for 91, `family_fill` for 2) and the imports are already right on 80 -
but the artifact is the WRONG hop. OEP deltas to truth: 2 exact, 4 within 0x1000, 19 within 0x10000,
**68 at >= 0x10000** - i.e. the accepted hop is usually nowhere near the payload entry.

Checked against the FSG mechanism before porting anything: for three sampled rows
(`ProduKey` +276, `sysexp` +386, `DriverView` -763) there is **no `e8`/`e9`/`0f 84` rel32 branch in
the claimed page whose target is the true entry**, so Neolite's stub does not hand the entry over the
way FSG's does and the FSG rule does not transfer.

That makes Neolite's lever the **hop picker / acceptance gate** - which candidate in the claim ledger
becomes the OEP - and it is the largest single lever left in the family table: 80 of 93 rows already
have the imports and would convert on an OEP correction alone, so a picker win here is worth up to 80
all-three, versus a handful for any import-side mechanism.

Next concrete step (recorded): dump the claim ledger for 3-5 Neolite rows (every candidate hop with
its address, section, first bytes and whether the payload decodes there) and compare against truth, so
the discriminator is derived from data rather than guessed. No code changed this round; suite
602/602, tree clean, baseline unchanged (r63: all-three 1873/2678).

### 0.17db Round 108: Neolite's dump is a MID-DECODE state - the packed file copied to rva 0x1000

Following the ledger step from 0.17da, one Neolite row was traced end to end
(`neolite_ProduKey.exe`). The result corrects the previous reading: this is not a picker problem.

| observation | measurement |
|---|---|
| run duration | **0.107 s** (budget 150 s) - it ends almost immediately |
| hop accepted | 1 candidate, `0x41687b` in `.neolit`; the picker then prefers a Borland-shaped entry `0x40d21e` |
| truth | `0x40d10a` = `6a 70 68 00 e4 40 00 e8 e2 01 00 00` (a CRT entry) |
| dump at truth rva | `00 eb b8 8b 45 0c 66 3d ...` - not the payload |
| dump vs original image | 44.4 % identical: headers 93 %, **`.text` head (0x1000-0xd000) 4.1 %**, `.text` tail 88 %, rest 98 % |
| `dump[0x1000:0x2000]` | **byte-identical to `packed[0:0x1000]`** - the stub copied the packed FILE to rva 0x1000 |
| `dump[0x1000:]` vs `packed[:]` | 60.8 % identical overall |

So Neolite's artifact is the state *mid-decode*: the stub copies the packed image into the payload
area and only the tail is ever decrypted. The layout also explains why `TAOTE_UNPACK_SHADOW_ALL=1`
changes nothing (44.4 % either way) - the head is never written with plaintext at all, so the
first-write shadow has nothing to restore. Imports are already perfect on the row (recall 1.0000,
635 pairs) and 80 of 93 family rows, so nothing import-side is at stake.

Next concrete step (recorded, data-first): follow the `.neolit` stub past the copy - log the guest's
write stream (which ranges get written, in what order) and where it stops, and find what makes the
run end at 0.1 s. The section table gives the shape to test: only `.neolit` is executable
(`exec=1`, inplace) while `.text` is file-backed ciphertext (`raw=0xc600`, `exec=0`), so an in-place
decrypt of a file-backed section is the case the hop detector has to see. No code changed; suite
602/602, tree clean, baseline unchanged (r63: all-three 1873/2678).

### 0.17dc Round 109: Neolite's file mapping is CORRECT - the stub then runs away in a string XOR loop

Continued the trace from 0.17db. Two things are now established, and one candidate cause is excluded.

**The mapping trio is not the problem.** Instrumented `CreateFileA` / `CreateFileMappingA` /
`MapViewOfFile` (env-gated, reverted after measuring):

    [mapdbg] CreateFileA path=C:/Windows\neolite_ProduKey.exe -> 0xa000000e
    [mapdbg] CreateFileMappingA hFile=0xa000000e size=0x0 -> 0xa0000010
    [mapdbg] MapViewOfFile hFileMapping=0xa0000010 off=0x0 size=0x0 -> 0x5001158 head=4d5a900003000000

The stub opens its own staged file, maps it, and the view's first bytes are the real `MZ` header - so
taote hands the decoder the right bytes and the "guest asked for a file it cannot see" hypothesis dies.

**What ends the run.** The last 64 PCs (the existing `TAOTE_LASTPC` ring) are one tight loop, and it
does not fault or time out: `rc=0`, no `error=`, no `[fault]` line, only six imports
(`GetModuleHandleA`, `GetModuleFileNameA`, `GlobalAlloc`, `CreateFileA`, `CreateFileMappingA`,
`MapViewOfFile`). The loop at `0x416e26` is a NUL-terminated string decryptor:

    416e26: 8a 0b      mov  cl, [ebx]
    416e28: 43         inc  ebx
    416e29: 84 c9      test cl, cl
    416e2b: 74 08      je   0x416e35
    416e2d: 80 f1 ff   xor  cl, 0xff
    416e30: 88 08      mov  [eax], cl
    416e32: 40         inc  eax
    416e33: eb f1      jmp  0x416e26

i.e. the stub is decrypting a string that never terminates where it is looking, and the run ends
through one of the quiet stop paths (an unhandled SEH dispatch or thread switch, not the instruction
budget - the budget is 2e9 and the whole run is 0.1 s).

Next concrete step (recorded): catch the loop's ENTRY - log `ebx`/`eax` at the first
`0x416e26` and the return address on the stack, then walk one frame up to see which pointer the stub
computes. That names the operand the packer expects (its own file-mapping view, its module base, or a
heap block) and therefore the real defect. No code changed this round; suite 602/602, tree clean,
baseline unchanged (r63: all-three 1873/2678).

### 0.17dd Round 110: Neolite's stub calls ExitProcess on purpose - the decode never starts

The round-109 next step was to catch the loop's entry and name the operand. Doing that answered the
question at a different level: **the stub is not failing to decode, it is deliberately terminating.**

Added a small generic debug gate, `TAOTE_PROBE=<hex pc>` (off by default, same class as
`TAOTE_LASTPC`/`TAOTE_FSGTRACE`): the first three times that exact pc executes it prints the guest
registers, the return slot and a 24-byte ASCII peek at `eax`/`edx`. With it:

* the string loop `0x416e26` is a plain NUL-terminated XOR-0xff decryptor (`ebx` walks `.neolit`
  from `0x4160df`, `eax` walks a stack buffer) - normal, not a runaway;
* the run's last 40 PCs end at the pair `call [ebx]` / `call [ebp-4]`, and probing them gives
  `GetProcAddress(hModule=0x10020000, lpProcName="ExitProcess")` returning the cell `0x10021030`,
  then the stub **calls it**.

So the whole Neolite flow on this row is: `GetModuleHandleA`, `GetModuleFileNameA`, `GlobalAlloc`,
`CreateFileA(C:/Windows\neolite_ProduKey.exe)`, `CreateFileMappingA`, `MapViewOfFile` (verified in
0.17dc to return the real `MZ` bytes), decrypt `"ExitProcess"`, resolve it, call it. The process exits
after six imports and 0.1 s, which is exactly what the artifact showed: the packed file copied to
rva 0x1000 and nothing decoded.

That reframes the family for the next round: Neolite's 91 failing rows take an **early-exit path**,
so the question is no longer "why is the decode wrong" but "which test sends the stub down the exit
branch". The shape is visible in `.neolit`: the exit is reached through a helper that ends
`test eax,eax; jne` (`0x416e0a`) and a `call 0x416591` argument path at `0x416e15`, i.e. a helper
whose result decides between "carry on" and "leave". Next step (recorded): log the guest's arguments
and return values for the six calls in order, and the value tested at `0x416e0a`, so the failing
condition is identified from data. TAOTE_PROBE ships (env-gated, off by default, suite 602/602,
behaviour unchanged - a no-probe run still reports `oep=0x40d21e imports=635`).

### 0.17de Round 111: the reference DECODES this Neolite row - taote diverges, and the row is decodable

The single most useful measurement of the Neolite thread so far, and it took one command: the
reference on the same sample.

| | pegasus | taote |
|---|---|---|
| OEP | **0x40d10a (exact, the original's EP)** | 0x40d21e |
| dump vs original image | **98.7 %** | 44.4 % |
| imports | 17 | 635 (recall 1.0000) |
| reason | section_hop | section_hop |

So `neolite_ProduKey.exe` is NOT a dead sample and NOT an inherently hard decode: the reference runs
the same stub and comes out with the payload. Everything taote has measured about this row so far
(0.17db-0.17dd: the packed file copied to rva 0x1000, the stub resolving `"ExitProcess"` and calling
it) is therefore a DIVERGENCE, not the packer's behaviour - and the divergence is in taote's API
answers, because the guest's own code is identical.

Added `TAOTE_APITRACE=<n>` (env-gated, off by default; prints dll!name, the raw stack arguments and
the return value for the first n dispatches, plus the string argument for LoadLibraryA /
GetProcAddress / CreateFileA). The Neolite row's whole visible flow is then:

    LoadLibraryA(name)            -> 0x10020000
    GetProcAddress(h, name)       -> cell in the stub dll
    GetModuleHandleA(0)           -> 0x400000
    GetModuleFileNameA(...)       -> 0x1f  (31 chars)
    CreateFileA(path)             -> handle
    CreateFileMappingA(h,0,2,0)   -> handle
    MapViewOfFile(...)            -> view whose head is the real MZ
    GlobalAlloc(0, 0x10004)       -> a heap block
    ExitProcess(0)                <- the give-up path

Two candidate causes were tested and one is excluded. **Heap alignment was NOT it**: Windows heaps
return 8/16-byte aligned blocks, this bump allocator advanced by the raw size, and
`GlobalAlloc(0,0x10004)` returned `0x50159dd` (odd) - so rounding chunk sizes up to 16 was
implemented and measured: the address became `0x5015b20` (aligned) and the stub still took the
`ExitProcess` path, with the dump unchanged at 44.4 %. Reverted (no measured gain, so it does not
ship). **One anomaly to chase:** in the longer trace a `GetProcAddress` resolves to `0x419090`, which
is inside `.reloc`, i.e. a bogus export address - a resolution that should not exist.

Next step (recorded): get the reference's side of the same six calls (pegasus has the sample, so its
own API trace is the oracle) and diff the two sequences answer by answer. The row is provably
decodable (98.7 %), so this is a semantics bug hunt with a known-good counterpart, not a packer
mystery. Suite 602/602, tree clean; only the gated trace gate is new code.

### 0.17df Round 112: the packer NAG answer - Neolite 2 -> 89/93, corpus 1873 -> 1960

The Neolite thread paid off, and the mechanism is one line of API semantics found by diffing against
the reference.

**How it surfaced.** 0.17de established that pegasus decodes `neolite_ProduKey.exe` (oep 0x40d10a
exact, 98.7 % dump) while taote took its `ExitProcess` path (44.4 %). The reference's API trace
(`SE_DEBUG_APICTX=1`, which prints every dispatch with its arguments) shows what taote never reached:

    LoadLibraryA("user32.dll") -> GetProcAddress("MessageBoxA")
    MessageBoxA(0, "This program was compressed with the\r\ndemonstration vesion of NeoLite.\r\n
                    ...Click the Yes button to visit our web site (www.neoworx.com) to
                    purchase the full product.\r\n\r\nClick No to run the compressed program.",
                "C:\\WINDOWS\\system32\\neolite_ProduKey.exe", 0x2134) -> 2
    VirtualProtect(0x401000, 0xc600, 4) -> the payload runs

So the stub shows a demo nag whose **YES is the destructive answer** ("visit our web site") and whose
NO runs the program. taote pressed YES (`MB_YESNO -> IDYES` in the press table) and the stub went to
its give-up path; the reference answers **2 (IDCANCEL)** for every MessageBoxA and the stub proceeds.

**The value matters, and one value satisfies both nags.** Measured by forcing the return on one row of
each family:

| row | ret 7 (IDNO) | **ret 2 (IDCANCEL)** | ret 6 (IDYES) |
|---|---|---|---|
| `neolite_ProduKey` | 98.4 % | **98.4 %** | 44.4 % (exit path) |
| `molebox_ProduKey` | 35.1 % | **98.5 %** | 98.5 % |
| `molebox_HashCalc` | 18.1 % | **99.6 %** | 99.6 % |

NeoLite's stub accepts anything but YES; Molebox's accepts anything but NO; **2 is the only value both
accept**, which is exactly what the reference returns. `MessageBoxA` now answers `IDCANCEL`
unconditionally (the dialog texts are still logged through the string engine), and the unit test that
asserted the old `MB_ABORTRETRYIGNORE -> IDABORT` tuple was rewritten to assert the new contract for
every button set.

**Measured, family first:** Neolite 93 rows - all-three **2 -> 89**, OEP-exact 2 -> 89, imports-ok
80 -> 93, mean recall 0.871 -> 1.000, zero losses. Molebox (the family the naive IDNO answer broke:
89 -> 0) stays **89/93, unchanged**.

**Then the corpus** (`r65`, 2678 samples):

| arm | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r63 | 2675 | 1974 | 2066 | 1873 |
| **r65** | **2675** | **2060** | **2076** | **1957** |

+87 Neolite rows, and three rows lost *at the wall* only: `mpress_ComIntRep` (82 -> 85 s), `nspack_ADInsight` (86 s),
`nspack_procexp` (84 -> 85 s). Re-run alone at a 120 s budget they give 32 s / 34 s / 49 s and **all
three pass**, so they are the known budget-boundary artefacts, not regressions - the capability figure
is **1960/2678**. Suite 602/602.

### 0.17dg Round 113: Alienyze - the stub dies on ONE unresolved indirect call (0x44fc43)

Applied the Neolite method (one row -> reference -> diff) to the next family. Alienyze, 126 rows:
all-three 43, valid 125, OEP-exact 54, imports-ok 74; two clean sub-classes:

| class | rows | shape |
|---|---|---|
| pure OEP | **18** | code_sim >= 0.9, imports ok, OEP wrong (17 of 18 with |delta| >= 0x1000) |
| pure imports | **11** | OEP exact, recall 0.935-0.945 (just under 0.95) |

**Reference vs taote on `alienyze_AccessEnum.exe`:** pegasus reports `oep 0x407a98` (the truth) with
`reason=section_hop`; taote reports `oep 0x403a53` with `reason=ladder_scan` and an EMPTY hop ledger -
although the dump is fully decoded (code_sim 1.000), because Alienyze is decoded *statically* by
taote's port of the reference's `alienyze.cpp` (XOR-key recovery + body restore). So the emulation's
only job here is to hand off the entry, and it never gets there.

**Where it dies, exactly.** taote's run ends at pc `0x44fc43`, which disassembles to

    44fc42: 52                  push edx
    44fc43: ff 95 7c ff ff ff   call DWORD PTR [ebp-0x84]     <-- last pc taote reaches
    44fc49: 89 85 d4 fe ff ff   mov [ebp-0x12c], eax

and the reference's API trace records its FIRST dispatch at `ret=0x44fc49` - i.e. **the same call
site**, there `LoadLibraryA`. So the stub resolves its API pointers up front (its own hash walk over a
module's export table) and calls them through stack slots; in taote that slot holds something that is
not a dispatchable thunk, so the call goes nowhere and the emulation stops quietly (rc=0, no fault, no
error, 615 ms).

The reference additionally *accelerates* Alienyze's stub loops (`install_alienyze_loopacc_`:
`PC 0x44f9e5` strhash, `PC 0x450088` a 151 297-byte XOR with key 0x6f, `PC 0x450107..0x450116` body
copies into 0x401000/.rdata/.data - all three shapes are printed by `SE_DEBUG_LOOPACC=1`). taote has
no loop accelerator at all, so even after the pointer is fixed the walk may need one.

Next step (recorded, data-first): log the stub's hash-walk - the module whose export directory it
walks and the hash it compares - and check it against the exported names of the corresponding
synthesized stub dll, which is where the wrong pointer comes from. 18 rows ride on the OEP alone
(they are already decoded and import-complete) plus 11 on the recall tail. No code changed this round;
suite 602/602, tree clean, baseline unchanged (r65: all-three 1957 in-run, 1960 capability).

### 0.17dh Round 114: Alienyze's resolver slot is ZERO - the stub's own hash walk found nothing

One probe answered the question 0.17dg left open. `TAOTE_PROBE` gained a `TAOTE_PROBE_EBP_DISP`
companion (reads the dword at `[ebp+disp]`, i.e. the slot an indirect call is about to use), both
env-gated and off by default. At the dying instruction on `alienyze_AccessEnum.exe`:

    [probe] pc=0x44fc43 eax=0x400000 ebx=0x0 ecx=0x42a20b edx=0x42a024 ebp=0xffffcffc
    [probe]   @eax='MZ......................'   @edx='user32.dll.MessageBoxW.A'
    [probe]   [ebp-132]=0x0 @ptr='?'

So the instruction `call DWORD PTR [ebp-0x84]` calls through a slot that is **0**, and the argument
being pushed is Alienyze's own import spec `"user32.dll.MessageBoxW.A"` (dot-separated, its private
store format) - the stub is invoking its *resolver* with a spec, and the resolver pointer was never
filled in. `eax` still holds the main image base (0x400000), i.e. the stub never even resolved its
first import.

That is a much sharper statement than "the hand-off never arrives": the stub's own export-table hash
walk - the one that fills these slots before any API call - returns nothing under taote, while under
the reference the very same call site is the run's first dispatch (LoadLibraryA, returning to
0x44fc49). Everything downstream (the 151 297-byte XOR, the body copies, the section hop) is
unaffected and already working: the image is decoded statically to code_sim 1.000.

Next step (recorded, and now very narrow): find the walk that stores into `[ebp-0x84]` - locate it by
probing the instruction that writes that slot (watch `ebp-0x84` for the first write) and log the
module it walks, the hash it compares and the name it reconstructs; then compare against the export
directory taote's synthetic stub dll actually exposes. The suspicion is the export DIRECTORY shape
(name/ordinal arrays), since the same dlls serve every other family. 18 rows ride on this.

### 0.17di Round 115: Alienyze - the stub's own hash walk, and the module-order trap

Round 114 left one zeroed slot. This round explains it end to end and finds the answer one level
deeper: **the stub resolves kernel32's imports itself, by walking the export directory by name hash,
and it picks the module by POSITION in the PEB lists - so the order taote preloads its stub dlls in
decides whether the packer can find anything at all.**

Measured with the new `TAOTE_WATCH_ADDR` gate (first n writes to a guest address, with the writing
pc; env-gated, off by default, same class as `TAOTE_LASTPC`/`TAOTE_PROBE`):

    [watch] ... val=0x10010000 pc=0x44f876     ; the module base the export walk uses
    [watch] ... val=0x0        pc=0x44f95b     ; [ebp-0x84] — one of seven local inits

Disassembling the resolver (from the packed file - the .alien code region is plaintext, only the
0x6f-filled data run at 0x44f740 is filler) gives the whole mechanism:

    44f7eb  mov eax, fs:0x30            ; PEB
    44f7fd  mov edx, [ecx+0xc]          ; PEB->Ldr
    44f809  mov edx, [ecx+0x28]         ; FullDllName.Buffer
    44f81d  ...                         ; scan the wide path for the last '\'
    44f84e  mov eax, [ldr+0x14]         ; InMemoryOrderModuleList
    44f873  mov ecx, [eax+0x10]         ; DllBase
    44f876  mov [ebp-0xc], ecx          ; the module to walk
    44f927  mov [ebp-0x2c], base+expdir
    44f93c  mov ecx, [exp+0x20]         ; AddressOfNames
    44f94b  mov eax, [exp+0x24]         ; AddressOfNameOrdinals
    44f9bd  loop i < [exp+0x18]         ; NumberOfNames
    44f9e5  hash: h = (h*257 + c) ^ (c<<16)
    44fa1f  cmp h, 0xc5e5447a / 0xeec1e396 / ...  ; eight names, eight slots

The eight hashes are **exactly** `GetProcAddress`, `LoadLibraryA` (-> the slot the earlier round
found dead), `VirtualAlloc`, `CreateFileMappingA`, `MapViewOfFile`, `UnmapViewOfFile`,
`CloseHandle`, plus one more: `GetFileAttributesExW` (0x4b1e23db).

Two findings, both measured:

1. **`GetFileAttributesExW` did not exist in taote at all** (only the `A` form did). Registered
   now, sharing `get_file_attributes_ex_body`.
2. **The module the walk picks is chosen by list POSITION**: taote preloaded
   `ntdll, kernelbase, kernel32, mscoree, ucrtbase`, i.e. the third InMemory entry was
   `kernelbase`, whose synthesized stub dll has **0 export names** (nothing registers API entries
   for kernelbase). Every hash therefore missed and every slot stayed 0. Swapping the order to
   `ntdll, kernel32, kernelbase` (Windows loads kernel32 first and then its dependency kernelbase)
   makes the walk land on kernel32 - and the stub then runs the reference's whole prologue:

       LoadLibraryA(0x42a024) -> user32   ; taote: 0x10050000
       GetProcAddress(user32, "MessageBoxW")
       MessageBoxW(0, text, caption, 0x40) -> 1
       GetFileAttributesExW(<own path>) -> 1
       CreateFileW -> CreateFileMappingA -> MapViewOfFile -> UnmapViewOfFile -> CloseHandle
       ... and then jumps to 0x407a98, which IS the reference's exact OEP for this row

3. Related, and needed for (2) to even get past the stat: **the main image's LDR FullDllName lied**.
   The CLI copies the sample to `rootfs/Windows/<name>` but `add_ldr_data_table_entry` built the name
   from `winsys()` (`C:\Windows\System32`), so the guest was told its own exe lived in System32.
   The main image now reports `%WINDIR%`, where the file really is; DLLs keep `winsys()`.

**Measured, and partly rejected.** The Alienyze family arm (126 rows, 85 s, 4 workers):

| arm | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r65 baseline | 125 | 54 | 74 | 43 |
| path fix + `GetFileAttributesExW` (order unchanged) | 125 | 54 | 74 | **43** (neutral) |
| all three, **with the dll-order swap** | 125 | **33** | **56** | **27** |

So the dll-order swap is **reverted**: it gets the stub further (to the true payload entry) but the
payload then dies on `UC_ERR_READ_UNMAPPED` before the packer's own missing step, and the artifact
ends up worse than the static decode it replaced. The two remaining changes (the LDR main-image path
and `GetFileAttributesExW`) were then run over the whole corpus (r66, 2678 rows, 85 s, 4 workers)
against r65: **valid PE 2675 = , OEP exact 2060 = , imports 2076 -> 2077, all-three 1957 -> 1958,
one gain (nspack_ADInsight.exe) and zero losses** - free, so shipped.

Next step from here (recorded): make the stub's decode COMPLETE before the payload runs. The
reference calls `VirtualProtect(0x401000, 0xc600, 4)` between `GetFileAttributesExW` and
`UnmapViewOfFile`; taote's run never calls it, and the stub jumps to the payload without the
151 297-byte 0x6f XOR having been replayed in emulation, so the payload executes a half-decoded
image. The gate to port is the reference's `install_alienyze_loopacc_` family accelerator.

### 0.17dj Round 116: Alienyze - the stub jumps to the payload having skipped its IAT build

The dll-order experiment of 0.17di gets the stub running, and this round says exactly where the run
then diverges - one step past the file mapping.

Reference (`SE_DEBUG_APICTX`, alienyze_AccessEnum.exe), after the mapping calls:

    ... MapViewOfFile -> 0x2c000 ; UnmapViewOfFile -> 1 ; CloseHandle -> 1
    kernel32.LoadLibraryA -> 0x77000000          <-- the IAT build starts here
    kernel32.GetProcAddress x ~80                (0xfeedf0xx thunks, one per name)
    kernel32.LoadLibraryA x ~10 more dlls, more GetProcAddress
    ... then the payload's own CRT starts at the true entry

taote with the swapped preload order stops after **four** API calls:

    LoadLibraryA(user32) / GetProcAddress(MessageBoxW) / MessageBoxW -> 1 /
    GetFileAttributesExW -> 1 / CreateFileW / CreateFileMappingA / MapViewOfFile /
    UnmapViewOfFile -> 1 / CloseHandle -> 1
    then `call 0x407a98` (return slot 0x4502bb) - the true payload entry, with the IAT still empty

and the payload dies on its first dereference:

    [fault] access=19 addr=0x0 pc=0x407a98     (TAOTE_SEHDBG=1)

with `fsbase = 0x6000` confirmed correct (that is `FS_SEGMENT_ADDR`; reading `fs:0` is not the
problem). So the crash is a NULL call through an IAT slot the stub never filled - because it skipped
the whole LoadLibraryA/GetProcAddress block.

The remaining question is therefore narrow: **which test between CloseHandle and the IAT build sends
taote's stub down the shortcut branch**. The candidates are the answers it receives just before -
`GetFileAttributesExW`'s WIN32_FILE_ATTRIBUTE_DATA (taote fills attrs/3 timestamps/size from the host
file) and the mapped view's size - so the next step is to log the arguments of the stub's own
decoder call after CloseHandle and compare the value it tests against the reference's.

Round 116 ships only the probe improvement (`[probe]` now also prints `fsbase`, which is what excluded
the TEB hypothesis) and this record; the preload order stays `ntdll, kernelbase, kernel32` because the
swapped arm measured worse (Alienyze all-three 43 -> 27).

### 0.17dk Round 117: Alienyze's IAT walk reads a table the emulation never decoded

0.17dj asked which test sends the stub down the shortcut branch. It is not an API answer at all - it
is the stub's own import-table walk, and the reason is that **taote's emulated memory is still the
packed image while the artifact is the decoded one.**

The walk (0x450146..0x450199, disassembled from the packed file - plaintext there):

    450150  mov edx,[ebp-8] ; add eax,[ebp-4]   ; base + header[+4]
    450167  mov eax,[edx]                        ; rec[0x00] -> [ebp-0x88]
    450175  mov dword [ecx],0                    ; "consume" the record
    450182  jne 0x450190
    450184  mov eax,[edx+0x10]                   ; fall back to rec[0x10]
    450190  cmp [ebp-0x88],0
    450199  je  0x4502a7                         ; <- empty record: straight to the payload call
    4501b4  call [ebp-0x84]                      ; else LoadLibraryA(base + rec[0xc] - n*0xfff)
    ... stride 0x14 (20-byte records)

Probed at the branch:

    [probe] pc=0x450182 eax=0x0 ebx=0x800 ecx=0x409608 edx=0x409608 ...
    [probe]   [ebp-136]=0x0                      ; rec[0]==0 and rec[0x10]==0 -> exit to 0x4502a7

`[ebp-0x30]` (the record pointer) is **0x409608**, i.e. rva 0x9608 in `.rdata`. In the finished dump
that address holds `d0 97 00 00 ...`, byte-identical to the original `AccessEnum.exe` .rdata. During
the emulation it is zero. So the stub is reading its own table out of a section that *nobody has
decoded yet*: taote's Alienyze recovery is a STATIC post-pass at finalize (its port of the reference's
`alienyze.cpp`), so the emulation sees the packed (raw-size-0) image, the walk finds an empty record,
and the stub jumps to the payload without building the IAT - which is exactly the NULL call the
payload then makes.

This explains the whole shape of the family: the decode is right in the ARTIFACT (code_sim 1.000,
which is why the rows look like pure-OEP failures) and wrong in the EMULATION.

Next step, now well-founded: **seed the emulated image with the static decode before the stub runs**
(the recovery already exists; it just runs too late), so the stub's table walk, its IAT build and its
hand-off all operate on data that exists. That should convert the 18 pure-OEP rows without needing the
loop accelerator - the stub then only has to *walk*, not *decode*.

### 0.17dl Round 118: Alienyze - seed the emulation with the static decode, and the stub completes

0.17dk established that the stub's import-table walk reads `.rdata` while the emulation still holds the
packed image. This round fixes that and the family converts.

Three pieces, each needed:

1. **`Packer::seed_image_before_run()`** (default false) plus `Unpacker::install` running the family's
   static recovery against the mapped image *before* `ql.run()` (`TAOTE_SEED_STATIC=1` forces it for an
   A/B). Alienyze opts in.
2. **The seed writes back ONLY the hollowed sections** (`raw_size == 0`): the first attempt XORed
   `[first_sec_va, end)` like the finalize path does, which rewrites the stub's own code - the run then
   died at `0x44f7e5` reading address `0x6f` (the XOR key) because the stub was executing XORed bytes.
   `PackerContext::seed_mode` makes `AlienyzePacker::transform_image` run the normal recovery on a COPY
   and copy back just the sections the packer hollowed, leaving the stub's code exactly as loaded.
3. **The seed's pages are registered as claimed** (`written_ranges_`/`ever_written_`), because the jump
   into them is a hand-off even though no emulated write ever touched them. Without this the payload
   entry was reached but never claimed (`hop ledger (0)`).

Measured on `alienyze_AccessEnum.exe`: the stub now runs the reference's WHOLE prologue - the file
mapping, then the ~200 `LoadLibraryA`/`GetProcAddress` pair IAT build (matching the reference's
`0xfeedf0xx` burst call for call), then `msvcrt.__set_app_type`, `__getmainargs`, `_controlfp`,
`_except_handler3`, and the payload's own SEH. And the OEP lands exactly:

    [unpack] OEP candidate 0x407a98 (section_hop)      <- truth 0x7a98
    [unpack] hop ledger (2): 0x44f7e0@0 0x407a98@502
    [unpack] alienyze_AccessEnum.exe family=Alienyze ... oep=0x407a98 stages=1
             reason=section_hop imports=506

Alienyze family arm (126 rows, 85 s, 4 workers):

| arm | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r65/r66 baseline | 125 | 54 | 74 | 43 |
| preload-order swap only (0.17di) | 125 | 33 | 56 | 27 |
| **seed + swap + seed claims** | 125 | **85** | **79** | **56** |

The order swap alone was a regression; with the decode actually present it is what lets the stub find
kernel32 at all, so the pair ships or falls together.

Two refinements were needed before the corpus was clean, both found by measuring:

* the seed must claim ONLY the ranges it wrote (`PackerContext::seeded_ranges`). Claiming every section
  made the first pc executed inside the stub's own `.alien` a section hop (hop #0 was `0x44f7e0`, the
  stub entry), which stole the OEP on 15 rows whose static pick had been exact;
* Alienyze must not adopt an embedded PE once it has restored the body IN PLACE: on
  `alienyze_ADInsight.exe` the Amber-class adoption found a launcher-shaped blob inside the restored
  image and re-based the whole result to `0x512abe6`, throwing away the OEP the hop had just found.
  `AlienyzePacker::adopt_embedded_pe` now declines when `restored_in_place_` is set.

Alienyze family arm after both refinements (126 rows, 85 s, 4 workers): **125 / 108 / 79 / 75** (valid PE
/ OEP exact / imports / all-three) against the 125 / 54 / 74 / 43 baseline.

Corpus (r68, 2678 rows, 85 s, 4 workers) versus r66:

| | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r66 | 2675 | 2061 | 2077 | 1958 |
| **r68** | **2675** | **2115** | **2081** | **1989** |

34 gains (33 Alienyze + mpress_Listdlls) and 3 losses. Re-running the three losses alone at 1 worker
and a 200 s budget: `expressor_Everything.exe` passes in 41 s and `nspack_ADInsight.exe` in 36 s (both
were 85-86 s wall-bound in the 4-worker arm - the parallel-budget flip the harness warning describes),
so the capability figure is **1991**. `alienyze_pythonw.exe` is a REAL loss: its stub unpacks a second
stage at `0x1d001395` and the hop re-bases the result to `0x1d000000` (import recall 1.000 -> 0.386).
That row is the known cost of the swap; it is one row against 33.

### 0.17dm Round 119: the wide message box, the shell window, and two harness traps

Four changes from the reference-side review, plus the measurements that decided them.

**1. `MessageBoxW` answered as a press table; it is IDOK for every button set.** The old body ran one
verbatim `qiling` table, so `MB_YESNO` returned `IDYES` - the same destructive answer that cost 91
Neolite rows on the A path, latent on the W path. It now returns `IDOK` unconditionally, like the
reference (whose `MessageBoxW`/`MessageBoxExW` return 1; its own comment records Themida 3.x looping
`wsprintfW -> MessageBoxExW -> ExitProcess` 18 times, so a WIDE box must leave the caller's exit path
unchanged). The texts are still decoded through the string engine. `MessageBoxExW` did not exist in
taote at all; it is registered now and answers `IDCANCEL`, the reference's value.

Measured on the four families that use it (Alienyze 126, Neolite 93, Molebox 93, Yoda-Protector 101;
85 s, 4 workers): **Alienyze 125/108/79/75, Neolite 93/89/93/89, Molebox 93/89/92/89** - every one
unchanged against its r68 baseline, which is what "every W box in this corpus is a payload about box or
Alienyze's registered-version notice" predicts.

**2. The A path keeps the blanket `IDCANCEL`.** A 200-run A/B on the reference side (48 rows x return
2/1/6/7 across Neolite, Molebox, EXpressor, JDPack, Alienyze, plus 25-row per-family confirmations)
found **zero rows where the answer changed the artifact and zero where 2 is worse**. Explicitly NOT
adopting the tempting `MB_OK -> IDOK` refinement: the only `MB_OK`-nag families are EXpressor and JDPack
and both measured answer-insensitive. The one real effect is import purity (at 6, 23 of 24 Neolite rows
gain `kernel32!ExitProcess`/`shell32!ShellExecuteA`), which the r65 numbers already reflect.

**3. `FindWindowA` added for the always-present shell classes** (`Shell_TrayWnd`, `Shell_TabWindow`,
`Progman`, `WorkerW`, and the name `Program Manager`) - a synthetic, stable hwnd; 0 for anything else.
`FindWindowW` now shares the body (`LPCSTR_`/`LPCWSTR_` both resolve through the string engine).
Measured on **Yoda-Protector: no change at all (0 all-three before and after)**, because those rows
never ask: a Yoda row makes **zero** API calls and ends `stages=0 reason=fallback_guess` - the stub
does not run, so an anti-sandbox probe is not what blocks the family. This is parity with the reference
and free, not a lever; Yoda needs the same treatment FSG needed (get the stub executing at all).

**4. Two harness traps, both closed on the taote side.**
* A tight filesystem produced **0-byte artifacts with rc=0** (the reference's harness measured it and
  it manufactures a fake per-row signal in both directions). `Unpacker::finalize` now asserts the dump
  and the meta are non-empty and raises `QlErrorBase` otherwise, so a quota failure shows up as an
  error, never as a capability delta.
* The synthesized temp rootfs was **never removed on the normal path** - a 2678-sample corpus run leaked
  1625 trees (1.6 GB) and, on a tmpfs `/tmp`, filled the filesystem mid-run until 76 rows aborted with
  `std::filesystem_error: cannot copy file: Disk quota exceeded`. `tools/taote.cpp` now removes its own
  temp tree with an RAII guard (the stale-tree sweep stays for host aborts), and corpus runs should set
  `TMPDIR` to a directory on the big disk.
* Timeout-adjacent rows must be RE-TESTED, not read as signal: r68's three losses were re-run alone at
  1 worker and a 200 s budget - `expressor_Everything.exe` passes in 41 s and `nspack_ADInsight.exe` in
  36 s (both were 85-86 s wall-bound in the 4-worker arm), so the r68 capability figure is **1991**,
  not 1989. Only `alienyze_pythonw.exe` is a real loss (its stub unpacks a second stage at 0x1d001395
  and the hop re-bases the result to 0x1d000000; recall 1.000 -> 0.386) - one row against 33.

Corpus (r69, 2678 rows, 85 s, 4 workers) for the three API changes + the seed-gate revert:
valid PE 2672 / OEP 2112 / imports 2078 / all-three 1986 in-run. Three ASPack rows and
`mpress_ComIntRep` failed with `timeout: failed to execute process: Permission denied` - the CLI was
rebuilt WHILE the corpus was running - and all four pass solo at 1 worker / 200 s; `nspack_ADInsight`
(dur 86, wall-bound, as in r68) passes in 35 s. With those five put back, the capability figure is
**1991**, identical to r68: the wide-box and FindWindow changes are free, which is what the four family
arms already said. Lesson for the harness: never rebuild the CLI under a live corpus run.

### 0.17dn Round 120: Alienyze's payload dies on a DATA import, not on the decode

With the seed in place the stub builds the payload's IAT and hands off, and the payload's CRT then
faulted at once:

    [fault] access=19 addr=0xccc3c031 pc=0x407b6f

0x407b6f is `cmp byte [esi],0x22` in the CRT's command-line scan, and `0xccc3c031` is the *content of a
stub-DLL cell* (`31 c0 c3 cc` = `xor eax,eax; ret; int3`). What produced it: the payload loads an IAT
slot (`mov eax, ds:0x408174`), and a `TAOTE_WATCH_ADDR=0x408174` trace shows the stub's own IAT fill
writing `0x476ae0` there - a synthesized *code* thunk. That slot is a **DATA import** (`__argv`), and
`GetProcAddress` on a data export must return the ADDRESS OF THE VARIABLE, not a callable: the caller
does `mov eax,[slot]; mov esi,[eax]` and needs a mapped pointer to the value.

The reference has exactly this mechanism (`winemu.cpp get_proc` -> `handle_import_data` +
`data_export_addrs_`, with data handlers registered for `_acmdln` and `__initenv`). taote had no data
path at all, so every msvcrt data symbol resolved to a `ret` cell.

`GetProcAddress` now answers the msvcrt data symbols with a live variable: `__argc` (a cell holding
argc), `__argv`/`__wargv` and `__initenv`/`_environ` (a cell holding the address of a strings array
built with `alloc_strings_array`, the same allocator `__getmainargs` uses), and `_acmdln`/`_wcmdln` (a
cell holding a pointer to a NUL-terminated empty string, i.e. the reference's behaviour: the CRT scan
reads a mapped terminator and stops).

Measured on `alienyze_AccessEnum.exe`: **zero faults** for the whole run (it previously faulted at
0x407b6f, then marched the SEH dispatch through 0x70000000) and the API count rises from ~200 to 268.

Also fixed in the debug gate itself: `TAOTE_WATCH_ADDR`'s range test was `addr <= watch && watch + 8 >
addr`, which matched every write BELOW the watched address; it is now
`addr <= watch && addr + size > watch`.

Family arm (126 rows, 85 s, 4 workers) is unchanged at **125/108/79/75**: the extra payload execution
does not add import pairs (the stub's IAT fill already provided them).

**MEASURED AND REVERTED.** The corpus (r70, 2678 rows, 85 s, 4 workers) came out WORSE - all-three
1986 -> 1985 with 6 gains and 7 losses - and the losses are the interesting part:

    pecompact_DriverView   2 s -> 120 s wall (rc=124)      pecompact_shexview  2 s -> 120 s
    pecompact_OpenedFilesView / shmnview  2 s -> 120 s     pecompact_cpuz_x32  OEP lost at 85 s
    eronana_wininst-7.1    rc=-11 (SIGSEGV)

Reproduced solo: `pecompact_DriverView` and `pecompact_shexview` both take **129 s** where they used to
take 2 s. Those rows PASS today precisely because their payload faults immediately and the dump is
taken; give the payload a live `__argv`/`_acmdln` and it keeps running, blows the 85 s budget and the
artifact is lost. A first version without a per-symbol cache was worse still (it built a strings array
on every `GetProcAddress`, and the `eronana` segfault was that allocation explosion), but caching does
not fix the root cause: **running further is not free here**.

So the data-export path is reverted in full. It stays recorded as a latent correctness gap (a data
import resolved to a code thunk) together with the measurement that fixing it alone costs more than it
pays - it needs a budget story, exactly like the rejected post-OEP grace window and the wider rootfs.

### 0.17do Round 121: reference parity on the big families, and PEtite measured twice

**Parity check first, as the directive asks.** The family table from r70, with mean code_sim (whether the
artifact is decoded at all):

| family | n | valid PE | OEP exact | imports | all-three | headroom | mean code_sim |
|---|---|---|---|---|---|---|---|
| Themida | 122 | 122 | 0 | 0 | 0 | 122 | **0.07** |
| TELock | 116 | 116 | 1 | 0 | 0 | 116 | **0.09** |
| Yoda-Protector | 101 | 101 | 0 | 1 | 0 | 101 | **0.06** |
| RLPack | 104 | 104 | 73 | 8 | 7 | 97 | 0.99 |
| Alienyze | 126 | 125 | 108 | 79 | 75 | 51 | 0.73 |
| PEtite | 73 | 73 | 35 | 36 | 29 | 44 | 0.92 |
| Amber | 152 | 152 | 111 | 138 | 110 | 42 | 0.76 |

Themida/TELock/Yoda have `code_sim ~0.07`: nothing is decoded, and they need a family unpacker port, not
a mechanism. **Measured for Yoda-Protector: the reference does not solve it either.** A single row looked
solved (meta said `oep 0x460000`, `reason yp_terminal_full_fill`, stages 5, 61 imports), so the whole
family was run against the reference (101 rows, 120 s budget, 4 workers):

    reference Yoda-Protector:  valid PE 99   OEP exact 1   imports 0   all-three 0

and the one "solved" row is **wrong**: `yoda-protector_ADExplorer.exe` claims 0x460000 with
`code_sim 0.054`. So Yoda is correctly deprioritised: neither engine decodes it.

**PEtite (44 headroom, `code_sim 0.92`) is reference-solvable** - pegasus returns the true entry on the
rows I spot-checked (`petite_gzip` 0x401280, `petite_rrdec` 0x401160, `petite_m2cdm` 0x401160, all
`petite_terminal_full_fill`, stages 3, 73-81 imports), so it is real headroom. Two ports attempted and
both **reverted**:

* `PetitePacker::static_oep_from_image` implementing the reference's terminal validator (scan the decoded
  sections, excluding the packed-EP section, for the MSVC prologue `55 8b ec 6a`; and only when the
  latched hop is not itself a prologue site): **35/29 -> 31/28**. The unconditional version was 31/28
  too, so the guard was not the problem - the family override bypasses the generic ladder and the scan's
  first hit is not the entry on 4 rows.
* excluding the packed-EP section from the picker's "largest written range" fallback scan (the stub's
  self-writes put its own section into `ever_written_`, so the fallback found a prologue in the STUB's
  code - measured on `petite_rrdec`: picked 0x417214, truth 0x401160): **31/28** as well.

What the failure chain actually is, now measured: PEtite's hop is a **junk latch** (`hop ledger (1):
0x417175@2`, write ordinal 2, inside the stub's own section 0x417000-0x4187f0), the generic ladder runs
and finds nothing (`passA 0, passB 0, boundary 0, C=0` on every section), and the picker then falls back
to the prologue scan over written ranges - which includes the stub's own section. The next attempt
should therefore keep the generic ladder and fix the *scan target*, not replace the ladder: on this row
the decoded payload is section 1 (0x401000, 0x12000 bytes) and the truth is its first `55 8b ec 6a`
(0x401160 = offset 0x1160).

### 0.17dp Round 122: PEtite's nag is a symptom - the reference's stub never shows it

Round 121 reverted two PEtite ports and recorded "keep the ladder, fix the scan target". Tested
unconfounded this time (the earlier 31/28 was measured WITH the family override still in place):

* excluding the packed-EP section from the picker's fallback prologue scan, ALONE: PEtite
  **73/35/36/29 - exactly the baseline**, i.e. neutral. Reverted (a neutral change is not worth a
  corpus run); recorded so the next attempt does not redo it.

Why it is neutral, and what the real chain is, both measured on `petite_rrdec.exe`:

1. truth `0x401160` starts `55 89 e5 83 ec 18` - a **C2-shaped** prologue, not the `55 8b ec 6a` the
   reference's PEtite validator scans for, so a prologue scan tuned to the reference's pattern cannot
   find this row at all;
2. the generic ladder finds nothing here (`passA 0, passB 0, boundary 0, C=0` on every section), so the
   pick falls back to the junk-latch hop `0x417175@2`;
3. and the run ENDS at `0x4170f3`, i.e. after ~0xF3 bytes of the stub - the payload never executes.

What ends it is the interesting part. `TAOTE_APICTX`-style trace of the stub:

    GlobalAlloc(0, 0xbc70) -> heap        VirtualProtect(0x400780, 0x880, 4) -> 1
    VirtualProtect(0x400780, 0x880, 2) -> 1
    MessageBoxA(0, 0x4170fd, 0x4170f6, 0x10) -> 2      (uType 0x10 = MB_ICONHAND, buttons = MB_OK)
    ExitProcess(0xffffffff)

taote answers the box IDCANCEL (the blanket policy) and the stub exits. **But the reference's stub never
shows the box at all**: its trace on the same file is GlobalAlloc, VirtualProtect, VirtualProtect, then
straight into the `LoadLibraryA`/`GetProcAddress` IAT build and the payload's CRT
(`msvcrt.__set_app_type`, `__getmainargs`, `atexit`). So the nag is a SYMPTOM of an earlier divergence -
the stub's own post-decrypt validation fails under taote and it reports an error before exiting - and no
message-box answer can fix it. This is an independent confirmation of the round-119 rule: refine the
decode, never the answer.

Next step for PEtite: find what the stub validates between the second `VirtualProtect` and the box (the
box's own strings at 0x4170f6/0x4170fd are the error text - read them, they name the failed check).

### 0.17dq Round 123: PEtite executes its own DATA - and heap alignment is not the cause

0.17dp left one question: what ends PEtite's run before the payload starts. Two measurements, both
narrow, and the second one is the interesting negative.

**The stub ends up executing its own data section.** `TAOTE_LASTPC` on `petite_rrdec.exe` ends at
**0x4170f3**, which is inside the stub's table area at 0x417000-0x4170bc - the byte right before the
`"ERROR!"` string at 0x4170f6 and `"Corrupt Data!"` at 0x4170fd. So the "Corrupt Data!" nag is not a
decision the stub made: control fell into the table, and the adjacent strings are what the box shows.
The disassembly shows why the region is reached at all - the stub builds its own frame from a **heap**
pointer:

    417134  call [eax+0x1c]            ; GlobalAlloc(0, 0xbc70)
    417139  lea  esp,[eax+0xbc70]      ; <- its whole stack IS the returned pointer
    41713f  mov  [ecx+0x2e],esp        ; ... and it is indexed by BYTE offsets
    417192  add  BYTE PTR [esp],0x8    ; ... so the frame must be aligned
    4171aa  mov  ecx,[ebx] ; btr ecx,0x1f ; jae good   ; the branch that decides error vs continue

**Heap alignment tested and REVERTED.** `QlMemoryHeap::alloc`/`alloc_append` advanced the bump by the raw
requested size, so taote hands out odd pointers (`GlobalAlloc(0,0xbc70)` -> 0x50009ae). Rounding the bump
to 16 in both functions does change the run - `esp` becomes 0x500c6a4 and the probe at 0x4171aa now fires
with real values (ecx 0x4147ff, 0x41500b) instead of once with zeros - but the failure is identical
(MessageBoxA(uType 0x10) -> 2, ExitProcess(0xffffffff)) and the PEtite family arm is **exactly the
baseline: 73/35/36/29**. Since the change touches every heap allocation in every family, a neutral result
is not worth carrying; reverted. Recorded because this is the second family (after Neolite) where the
heap-alignment hypothesis is measurably not the cause.

Next step: stop chasing the frame. The stub's chain after the two `VirtualProtect` calls returns into
0x4170bb (the prologue probe's `ret` value), i.e. a return address INSIDE the table - so the
`rep movsd` copy-and-call sequence at 0x417179-0x417188 is what goes wrong, not the arithmetic around it.
Dump the 8 stack dwords at the `call ebx` (0x417173) and see which return slot the stub overwrites.

### 0.17dr Round 124: PEtite's return chain - the stub `ret`s into its own table

0.17dq asked for the stack dwords at the stub's `call ebx`. The probe now prints an 8-dword window at
`esp` (part of `TAOTE_PROBE`, env-gated, off by default), which answers it directly on
`petite_rrdec.exe`:

    pc=0x417173 (call ebx = VirtualProtect#1)
      esp=0x500c5ea  stack: 400780 880 4 41871c 6 c 400780 880
    pc=0x417188 (call ebx = VirtualProtect#2)
      esp=0x500c602  stack: 400780 880 2 41871c 417000 ffffcfce 400000 0
    pc=0x4171aa (the btr error/good test)
      esp=0x500c602  stack: 4170bb 41709d 417061 417042 417008 ffffcfce 400000 0

The five leading values are the pointers the stub builds with `push eax; add byte [esp],N` at
0x417191-0x4171a6 - `0x4170bb`, `0x41709d`, `0x417061`, `0x417042`, `0x417008`, i.e. offsets into its
OWN table. So at the branch test the top of stack is **0x4170bb**, and the value that eventually
`ret`s is a table pointer: the stub returns into its data (0x4170f3, one byte before the "ERROR!" /
"Corrupt Data!" strings) instead of continuing at 0x4171c9. The real return address is still on the
stack in slot 6 (`0xffffcfce`), one slot lower than the stub expects - so the stub's push/pop accounting
is off by one call's worth of arguments, not by a corrupted pointer.

That fits the sequence exactly: `call ebx` at 0x417173 consumes its six pushed args (esp moves 0x18 from
0x500c5ea to 0x500c602), the second `call ebx` at 0x417188 is entered with the stack already at the next
frame, and the five `push eax` message pointers then sit where the stub expects its return address.

Next step: compare the same two windows under the reference. Its stub never shows the box, so its slot 1
at 0x4171aa must hold either 0xffffcfce (the caller) or the code address 0x4171xx - which tells us
whether the stub's own accounting depends on the `pushfw`/`pusha` pair at 0x417125-0x417128 (i.e. whether
the emulator's `pusha` writes 8 dwords the way the stub counts them) or on the two `VirtualProtect`
argument counts it pushes around them.

### 0.17ds Round 124b: PEtite's own decompressor returns 0 - and it is also the wrong OEP

0.17dr's stack analysis was a red herring in the good sense: the frame arithmetic is exact. Measured
directly - `66 9c` (pushfw) moves esp by **2**, `60` (pusha) by **32**, `50` (push eax) by 4, so the
stub's `mov [ecx+0x2e],esp` store lands exactly where its own accounting expects (0xffffcff4 -> 0xffffcfce
across the three pushes). Nothing is misaligned there, and the run then goes on to execute ~0x900 bytes
of the stub (0x417317, 0x4181c7, ...).

The failure is one instruction pair, at the end:

    4171e2  call 0x417214          ; the stub's OWN decompressor
    4171e7  test eax,eax
    4171e9  je   0x4170ce          ; decompressor returned 0 -> the ERROR path
                                   ;   ...which walks into the table and shows "Corrupt Data!"

Probed at the test: `eax=0x408863`, `ebx=0x41864c`, `ecx=edx=0x4147ff`, `edi=0x414000`, and the stack
holds the four arguments the stub passed (`0x408863 0x4147ff 0 0x41864c`). So the decompressor is
called with a real buffer and returns failure.

**And that explains the family's OEP signature**: every bad PEtite row in the r70 census claims an OEP
ending `...214` (0x417214, 0x416214, 0x41b214, 0x40f214). 0x417214 is exactly this `call` target - the
stub's decompressor - so the pick is latching the address the stub *called*, not the entry it transfers
to. Fixing the decompressor's return is therefore worth two things at once: the payload actually gets
decoded, and the `...214` family of wrong OEPs disappears with it.

Next step: probe inside 0x417214 for its failing comparison (the routine is 0x100-ish bytes; the return
value is set to 0 on some validation of the input buffer at 0x408863/0x4147ff). Diff the same call's
inputs against the reference, where the stub never reaches the box.

### 0.17dt Round 124c: what the failing routine needs from the heap

The decompressor at 0x417214 sizes its own stack out of the block the stub allocated:

    417214  push ebp ; mov ebp,esp ; mov [edi],al
    417219  sub  esp,0xbad8        ; 47,832 bytes of frame
    41724e  mov  [ebp-0xb658],eax  ; ... and it also touches 46,680 bytes BELOW ebp
    417254  mov  [ebp-0xa240],eax

With the run's numbers (call at 0x4171e2, callee esp 0x500c5ee -> ebp 0x500c5ea) the deepest access is
`0x500c5ea - 0xb658 = 0x5000f92`, only **0x5e4 bytes above the block's start** (0x50009ae). The routine is
therefore operating with a margin of ~1.5 KB inside a 48,240-byte (0xbc70) GlobalAlloc block - it fits, so
this is not a mapping fault, and the run confirms it (no fault line at all; the routine simply returns 0
and the stub takes its error branch).

Two consequences for the next attempt:
* the heap block must stay CONTIGUOUS and at least 0xbc70 bytes, which is true today but is the reason the
  alignment experiment could not help: the margin is 0x5e4, and any change that lowers the block start by
  more than that turns this into a fault instead of a failure;
* the "returns 0" decision is inside this routine's own logic, and its inputs are the four stack dwords
  (`0x408863 0x4147ff 0 0x41864c`) - so the next probe goes at the routine's `ret` sites: which one sets
  eax=0, and which of the four inputs it rejected.

### 0.17du Round 125: PEtite - the reference decodes it perfectly, taote misses 14 bytes in page one

0.17ds/0.17dt left "the decompressor returns 0". This round answers which engine is right, by comparing
BOTH dumps against the original `rrdec.exe` over the whole payload section (0x401000-0x413000):

| engine | bytes matching the original (0x1000-0x18000) | first divergence in the payload |
|---|---|---|
| reference | **97.0 %** | **none** - the reference reproduces the payload section exactly |
| taote | 89.7 % | **0x401054**, and only 14 of the first 256 bytes differ |

The single divergence is a one-byte change: original `10 ba 00 00 83 ec 04 e8`, taote
`63 ba 00 00 83 ec 04 e8` (the next 5 bytes are identical). That is the signature of a decompressor
copy/back-reference landing one byte off at a few positions, not of a wrong buffer or a wrong length.

The chain is therefore:

1. the stub decrypts its own store (the source region 0x408863 already differs between the two engines,
   and both differ from the packed file: 19 % / 14 % unchanged respectively), so the divergence begins in
   the stub's decrypt step, before the decompressor;
2. the decompressor's built-in checksum (`not ebx; shr ebx,0x10; xor ebx,eax; jne 0x4181c7` at
   0x417319-0x417327) then fails, which is the `eax = 0` the stub's `test eax,eax / je 0x4170ce` sees;
3. the stub takes its error branch, walks into its own table and shows "ERROR!" / "Corrupt Data!";
4. and because the call target 0x417214 is inside the stub, the OEP pick latches `...214` on every bad
   row of the family.

Next step, precise: find the FIRST byte the stub writes that differs from the reference's value - the
payload's first divergence (0x401054) is an *output*, so walk backwards through the decrypt writes with a
three-way diff (taote memory, reference memory, original) page by page until the first differing write
appears; that instruction is the emulation-fidelity bug. PEtite at 44 headroom is worth it: the reference
proves the family is fully solvable.

### 0.17dv Round 126: PEtite's first divergence is a `call rel32` low byte - the relocation delta

0.17du left "find the first differing write". The answer is more specific than expected, and it is
visible in the finished artifacts without a write tracer.

Byte-for-byte around the first divergence (0x401040-0x40106f), taote is identical to the original except
at three positions, and each sits **immediately after an `e8`**:

    0x401053  e8                       (call)
    0x401054  original 0x10   taote 0x63     <- rel32 low byte
    0x40105b  e8
    0x40105c  original 0x20   taote 0x7b
    0x401060  e8
    0x401061  original 0x8b   taote 0xeb

Decoded as displacements that is `+0x53`, `+0x5b`, `+0x60` on the call TARGETS (the other three rel32
bytes are unchanged, so only the low byte - and therefore only the target's low byte - moves). That is a
**relocation** difference, not a decompression one: PEtite's stub walks the payload's relative calls and
adds a delta, and under taote the delta it applies (or the value it reads it from) is wrong by a
non-constant amount (0x53 / 0x5b / 0x60 over three calls only 0x0d apart).

The scale of the problem, over the whole payload section:

    differing bytes taote vs original: 5,888    (89.7 % match; reference 97.0%, first divergence NONE)
    of those, 2,036 are the rel32 bytes of an `e8` at +1..+4, 3,852 are elsewhere

So the next step is exactly one thing: find the stub's relocation pass - the loop that touches every
`e8`'s rel32 - and check where its delta comes from (the packed image's stored original base, or a value
it computes from its own entry). The reference computes it correctly; the delta is non-constant in taote,
which points at the loop reading its delta from a slot that taote's image holds with a different value
rather than at a constant offset error.

### 0.17dw Round 127: there is no relocation pass in the stub - the divergence is inside the decoder

0.17dv's next step assumed the stub walks every `e8` and patches its rel32. Scanned the stub's whole
code area (0x417000-0x418800) for the three ways a byte-pattern relocator would test that opcode:

    cmp byte [reg],0xe8   (80 /7 e8)      - none
    cmp eax,0xe8          (3d e8 00 00 00) - none

so PEtite does **not** relocate by scanning. The `e8`-adjacent changes are therefore an artifact of WHERE
the decompressed bytes land, not of a fixup pass: the decoder emits code and its copies propagate.

That is confirmed by direct comparison of the two engines' memory:

    store region 0x408863 (the decoder's input):  taote == reference only 869/1024  (85%)
    payload page 0x401000 (the decoder's output): taote == reference only 3700/4096 (90%)

So taote and the reference disagree about ~15% of the *input* store as well as the output: the divergence
begins in the stub's own decrypt of the store, and the sparse output errors (5,888 bytes, first at
0x401054) are its downstream consequence through the LZ copies. Both engines are running the same stub
code, so this is an emulation-fidelity difference in a loop that copies/decrypts backwards - and the
stub's decompressor does use the `std` direction-flag idiom (`fd` at 0x4171b6 followed by
`mov esi,eax; mov edi,eax` and a `rep movs`), which is the first thing to instrument.

**Bounded next step** (needs a write tracer, not more artifact diffing): log taote's first ~64 writes in
the store region with `(pc, addr, value)` (a `TAOTE_WATCH_ADDR`-style range hook), and check the write
that produces the first wrong byte; if the pc is inside the `std`/`rep movs` block, compare unicorn's
`rep movs` semantics with DF=1 there. If the pc is elsewhere, the same log gives the exact instruction.

### 0.17dx Round 128: the copy loop found - `std` + `rep movsd` over 12-byte entries

A range write tracer (`TAOTE_WATCH_RANGE=<lo>-<hi>[:n]`, env-gated) answers 0.17dw's question, and it
finds the loop that 0.17dv's byte-pattern scan could not:

    TAOTE_WATCH_RANGE=0x401000-0x413000:8
    [watchr] #1 pc=0x4171c1 addr=0x412ffc len=4 val=0x3d93eb0f
    [watchr] #2 pc=0x4171c1 addr=0x412ff8 len=4 val=0xfd4f0e8e
    ...                                        (descending addresses: the copy runs BACKWARDS)

which disassembles to

    4171aa  mov  ecx,[ebx]          ; entry word; bit 31 = "this entry has a copy"
    4171ac  btr  ecx,0x1f
    4171b0  jae  0x4171c9           ; bit clear -> the next phase
    4171b2  mov  eax,[esp+0x18]     ; the payload base
    4171b6  std                     ; DF = 1
    4171b7  mov  esi,eax
    4171b9  mov  edi,eax
    4171bb  add  esi,[ebx+4]        ; src offset
    4171be  add  edi,[ebx+8]        ; dst offset
    4171c1  rep  movsd              ; the overlapping BACKWARD copy
    4171c3  add  ebx,0xc            ; 12-byte entries
    4171c6  cld
    4171c7  jmp  0x4171aa

So the "relocation" is a relocation *table* of 12-byte entries `{flags|count, src, dst}` applied with an
overlapping backward copy - not a scan for `e8`, which is why looking for the opcode found nothing. The
`rep movsd` at 0x4171c1 is a separate routine's memcpy (0x4171f5-0x417213, `rep movsd` + `rep movsb`) that
the tracer also caught at 0x417206, i.e. the stub has both an overlapping-backward move and a plain
memcpy, and both were exercised.

taote has NO special handling of the string instructions anywhere (grep for MOVSB/MOVSD/STD in the tree
returns only a comment), so these run through unicorn natively - which means the divergence is either in
the entry table the loop reads (12 bytes per entry, first word's bit 31) or in unicorn's DF handling on
one of these two forms. That is now a two-way question with a one-command answer each, and the tracer is
the tool for both.

DF handling checked: the tracer's addresses DESCEND (0x412ffc, 0x412ff8, ...), which is only possible if
unicorn honours `std` for `rep movsd`, so both string forms are faithful and the 12-byte entry table the
loop reads is being applied correctly. That closes the copy/relocation branch entirely: PEtite's remaining
divergence is in the DECRYPT loop that runs before the copies, exactly as 0.17dw's input comparison said
(the store region differs between the engines in ~15% of bytes). The next probe is therefore the first
write into the store region with a pc OTHER than 0x4171c1/0x417206 - the tracer's `uniq` output over a
larger n names it directly.

### 0.17dy Round 129: the writer census - where every payload byte comes from

0.17dx said "the next probe is the first write into the store region whose pc is not the copy loop".
Done, and the answer is a complete map of the decode's data flow (all measured with the range tracer):

    writes into the payload section 0x401000-0x413000:
      12,464  pc=0x417206   memcpy helper (0x4171f5-0x417213: rep movsd + rep movsb)
       7,529  pc=0x4171c1   the overlapping BACKWARD copy of the 12-byte relocation table
           4  pc=0x41720f   the same helper's byte tail
           3  pc=0x417217   `mov [edi],al`, the first instruction of the decompressor at 0x417214

    writes into the heap buffer the memcpy reads from (0x5004572, i.e. GlobalAlloc(0xbc70)):
       5,827  pc=0x417a92     875  pc=0x417a5a      241  pc=0x417aa4
       3,323  pc=0x417926     874  pc=0x417a61        3  pc=0x417ed2 ...

So no XOR/decrypt loop writes into the payload at all: the image is filled by copies whose SOURCE is the
decompressor's heap buffer, and the decoder's own stores are at 0x417a5a/0x417a61/0x417a92/0x417926.
Disassembled, that inner loop is ordinary LZ copying - a two-byte-at-a-time match copy with the standard
short-distance overlap branch:

    417a4c  mov ecx,edi ; sub ecx,edx / cmp ecx,ebx ; jb 0x417a6b   ; overlap test
    417a54  mov ecx,edi ; sub ecx,ebx                              ; src = edi - distance
    417a58  mov dl,[ecx] ; 417a5a mov [edi],dl ; inc edi ; inc ecx
    417a5c  mov dl,[ecx+1] ; 417a61 mov [edi],dl                    ; two bytes per pass
    417a90  mov dl,[ecx] ; 417a92 mov [edi],dl ; inc edi ; inc ecx  ; the long run

No rep-string, no exotic instruction in the copy path - so the divergence is NOT in the copying but in
what the decoder decides to copy and from where: the bit reader (`shr esi,cl` at 0x417a9d) or the
distance/length decode around 0x417926. That is the next probe's target, and the census above is what makes
it a two-minute question: every payload byte's provenance is now known.

One more fact from the same disassembly, worth having before the next session starts: the error label
0x4181c7 is reached from MORE than the checksum. The bit reader's control path ends with

    417ae5  test BYTE PTR [ebp+0x8],0x20
    417ae9  je   0x4181c7            ; same error label as the checksum at 0x417327

so `[ebp+0x8]` - the decompressor's FIRST argument, one of the four stack dwords the caller pushed
(0x408863 / 0x4147ff / 0 / 0x41864c) - carries a flag whose bit 0x20 decides whether the decode may
continue. The tracer run shows the routine failing at the very first 0x102-window refill
(`cmp [ebp-0x10],0x102 ; jae 0x4178d7` at 0x417aad-0x417ab4), i.e. almost immediately, which fits a flag
test rather than a data comparison: check the value of `[ebp+0x8] & 0x20` FIRST in the next session, since
that is a one-probe answer and, if it is clear under taote, the decode never had a chance rather than
producing wrong bytes.

### 0.17dz Round 130: the argument flag is 0x60 - excluded; the checksum is the real reject

One probe, as planned:

    [probe] pc=0x417ae5 eax=0x11 ebx=0x408865 ecx=0x9 edx=0x500282c esi=0x1602 edi=0x5004d71
    [probe]   [ebp+8]=0x60

`0x60 & 0x20` is non-zero, so `je 0x4181c7` is NOT taken and the decoder keeps going - on all three
invocations the probe caught (args `0x60` each time, with different `ebx` bases 0x408865 / 0x4112a6 /
0x411597 and `esi` bit-buffer values 0x1602 / 0x59b / 0x1660, i.e. three separate streams decoded from
three stores). So the flag hypothesis is excluded, and the reject is the decompressor's own checksum at
0x417319-0x417327:

    417319  mov eax,ebx ; not ebx ; shr ebx,0x10 ; and eax,0xffff ; xor ebx,eax
    417327  jne 0x4181c7

That is a 16-bit halves fold of the stream's own state compared against the expected value at
`[ebp-0xb654]` - a *consistency* check on the decoder's accumulated state, not on the output. Since it
fires at the END of a pass, the decoder runs to completion and then disagrees about the final state, which
means the divergence is a small arithmetic difference accumulated during the pass (consistent with the
sparse 14-bytes-in-page-one output damage) rather than an early bail-out.

Bounded next step for whoever picks this up: log the two operands at 0x417327 (ebx after the fold, and the
memory at [ebp-0xb654]) on the FIRST pass, and the same two values under the reference if its trace can be
coaxed to print them (it has no equivalent gate, so the practical route is to compute the expected fold
from the compressed stream by hand for the first pass and see which side is off).

### 0.17ea Round 131: TELock's blocker is the SIGN of the stack base - ported the reference's stack placement

TELock is the biggest reference-solvable gap in the corpus: the r70 report has 116 TELock rows, **all 116
failing all-three with `imp_recall < 0.1`** (1 row OEP-exact), i.e. the stub never decodes, while the
reference unpacks the same file cleanly (`telock_7z.exe`: reason `unpacked`, `oep_found` true, **109**
import functions, `image_written_fraction` 0.9191, 5 sections rewritten). The bucket census of r70's 693
failures, with `oep_exact is False` counted strictly (None means the ORIGINAL is .NET/COM and the grader
skips OEP - 80 such rows):

| bucket | rows |
|---|---|
| invalid PE / timeout | 8 |
| ungraded OEP (.NET/COM original) | 80 |
| OEP exact + decoded -> imports only | 96 |
| OEP exact + undecoded | 29 |
| OEP wrong + decoded | 82 |
| OEP wrong + undecoded | **398** |

**The trace.** `telock_7z.exe` runs for 0 s, writes 6,482 bytes into its own last section
(0x418000-0x41b000), latches a first hop at 0x418037 and stops. With `TAOTE_SEHDBG` the ladder is visible:
`insn_invalid pc=0x419a08 b=0xf1` (ICEBP, already ported - see the comment at unpack.cpp:922), then two
`#DB` dispatches (`handler=0x4199fa`, then `handler=0x419a41`). The stub's own ladder in the decoded image
is a trampoline-stream construction:

    419a3b pusha ; 419a3c call 419a47
    419a47 push fs:[0] ; mov fs:[0],esp ; pushf ; or [esp],0x100 ; popf  ; TF = 1
    419a5c clc ; 419a5d jae 0x419a3b          ; the TF trap fires here
    419a41 mov esp,[esp+8] ; jmp 0x419a61      ; the handler restores esp from its frame
    419a78 or esp,esp ; 419a7a jne 0x419a7d    ; jumps MID-INSTRUCTION (into `ror eax,imm8`)
    419a80 mov ebx,[esp] ; 419a83 pop eax ; 419a84 sub ebx,0x411473
    419a8a test esp,esp ; 419a8c jns 0x419a91 ; <-- THE FORK
    419a8e setno [edx+3] ; 419a92 les edi,[esi] ; 0x419a98 xor esi,0x3d670c58 ...

Both engines execute this stream identically (the reference's `SE_DEBUG_HOP` log and taote's
`TAOTE_LASTPC` ring agree instruction for instruction through 0x419a8c), and both dumps carry the same
bytes at 0x419a80 - the divergence is *not* a decode difference. It is the conditional:
the reference executes 0x419a91 and 0x419a93 and never 0x419a8e or 0x419a92 (`grep -c` on its log: 1, 0, 1,
0), i.e. its `jns` is **taken**; taote's falls through into the `les` trap stream and dies there.

`jns` reads SF, and SF comes from the preceding `test esp,esp`. A probe at 0x419a8c says why:

    [probe] pc=0x419a8c ... ebp=0xffffd000 esp=0xffffcfb8
    [probe]   eflags=0x00000086 [PF SF ]

taote's 32-bit guest stack lives at the profile's `0xfffdd000`, so `test esp,esp` sets SF: this is an
ordinary **stack-address sanity check** (a real 32-bit Windows stack is a low positive address, ~0x0012xxxx),
and taote answers it wrong. The reference reserves the stack at a Windows-like base - `binemu.cpp
alloc_stack` passes `reserve_hint = 0x1200000` to `get_valid_ranges` - and its esp is therefore positive.

**The port.** `qiling/profiles/windows.ql` `[OS32] stack_address` 0xfffdd000 -> **0x1200000**, plus the
reference's `get_valid_ranges` behaviour in `QlLoaderPE::run`: slide to the first free range at or above the
hint, because 20 of the 2676 corpus samples declare base+SizeOfImage past 0x1200000 (the `*_adwcleaner`
family, `alienyze_HDDScan`, `themida_HDDScan`, ...). 32-bit only: the 64-bit stack sits at 0x7ffffffde000,
which no image reaches.

**Measured effect on the row** (`telock_7z.exe`):

| | before | after |
|---|---|---|
| esp at the fork | 0xffffcfb8 (SF set) | 0x121ffb8 (SF clear) |
| eflags at 0x419a8c | 0x86 PF SF | 0x06 PF |
| writes into the stub's section | 6,482 | **34,489** (5.3x) |
| SEH dispatches | 2 | 3 (+ `#BP` at 0x41808d -> handler 0x4180c5) |

So the ladder is now authentic past the fork, and the *next* blocker is named: after the `#BP` dispatch the
stub reads 0x70000000 upward one byte at a time (faults at `pc=0x41808e` for addr 0x70000000, 0x70000001,
0x70000002, ...), i.e. it is walking the synthetic SEH sentinel arena - the page taote maps for its own
dispatch. The reference has no such arena, so that walk is aimed at whatever its own dispatch left behind;
the next round's question is what 0x41808e is looking for (a handler signature, or the frame it just
installed) rather than whether it should fault.

Family arm: **TELock 116 rows -> 116 valid PE / 1 OEP exact / 0 imports / 0 all-three**, unchanged, as
expected for a fidelity fix that does not by itself decode the family. Corpus (r71) below.

**Corpus r71** - *a no-op measurement, see 0.17eb: the profile change was not in that binary*
(2678 rows, 85 s budget, 4 workers, `TMPDIR=/home/jim/tmp`, 74 min):

| run | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r68/r69 baseline (capability) | 2675 | 2115 | 2081 | **1989 / 1991** |
| **r71 (Windows-like stack)** | **2675** | **2115** | **2081** | **1989 / 1991** |

Row-level diff r68 -> r71 is 4 rows and exactly one OEP each way: `rlpack_geek.exe` **gains** the exact
entry (0x159760) and `bero_geek.exe` **loses** it (0x159760 -> 0x5f9008, code_sim 0.878 -> 0.696); neither
is all-three either way (their import recall is ~0.01/0.05). `expressor_Everything` (False -> True) and
`mpress_ComIntRep` (True -> False at the 85 s wall) are the known harness-edge rows and both pass solo
(41 s / 32.5 s), as do `mpress_cpuz_x32` (44.6 s) and `nspack_ADInsight` (34.2 s). So the change is **free on
the graded criterion** and buys the 5.3x-deeper stub execution plus a ladder that follows the reference.

Suite: 602/602, 0 failed (three cases - `PegasusParity.ConfigParityMountsFilesAndPatchesTheRegistry`,
`PegasusParity.PEBModulesPopulated`, `QilingPeCompat.PeWinX86ReturnFromMainExitTrap` - failed once under
`ctest -j4` and pass both alone and on the rerun; they share temp roots, not stack state).

### 0.17eb Round 131b: the profile is embedded at CONFIGURE time - r71 measured a no-op, and the stack search must run after the image

Three defects in round 131's own work, all found by chasing one probe that disagreed with it.

**1. The .ql profile is read at `configure_file` time, not build time.** `CMakeLists.txt` does
`file(READ .../profiles/<os>.ql)` + `configure_file(... @ONLY)`, so editing `windows.ql` and running
`cmake --build` rebuilds the binary **without regenerating `build/qiling/default_profiles.hpp`**. Round 131
fell straight into it: the corpus run it published as "r71, the stack change measured" executed a binary
whose guest stack was still 0xfffdd000, which is why its numbers were *exactly* the r68 baseline. It was
caught when a fresh probe printed `[sehd] ... chain=ffffcfb0` - a negative stack on a build that was
supposed to have a positive one. Fix: every profile is now a `CMAKE_CONFIGURE_DEPENDS` entry, so the next
build regenerates the header.

**2. `find_free_space` cannot answer this question where round 131 asked it.** The first version slid the
stack base with `mem.find_free_space(stack_size, 0x1200000)` at the point the profile is read. That reads
`map_info_`, and on the PE path the image is not mapped yet (`load_image` runs later), so
`telock_adwcleaner_7.2.4.0.exe` was told 0x1200000 is free - and the *image* map then threw
`Requested memory is unavailable`, because that sample's `SizeOfImage` is 0x1293000 from 0x400000, i.e.
straight through 0x1200000. The family arm lost a valid PE (116 -> 115) to exactly that row.

**3. The search now runs at the map site, after the image.** The stack map moved behind a `map_stack`
lambda: the shellcode path keeps calling it where it always did, the PE path calls it right after
`pe_image_size_ = last_image_size_`, and the base is searched forward geometrically (step doubles from
`align_up(stack_size)` to 16 MB, 32 tries) until `mem.is_available()` agrees. `is_available` reads the
emulator's real mappings, so it cannot race the image. Measured: `telock_adwcleaner_7.2.4.0.exe` lands at
**0x1a1f000 after 6 tries** and loads again (oep 0x1690037, family TELock); `telock_7z.exe` keeps 0x1200000
with 0 tries. `TAOTE_STACKDBG=1` prints `[stack] base=... size=... tries=...`, off by default.

**Corpus r72** (2678 rows, 85 s, 4 workers, 71 min) - the change actually in the binary this time:

| run | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r68/r69 baseline | 2675 | 2115 | 2081 | 1989 (capability 1991) |
| r71 (no-op) | 2675 | 2115 | 2081 | 1989 |
| **r72 (live)** | **2675** | **2115** | **2083** | **1991** |

Two gains, **zero losses**: `expressor_Everything` (in-run now, 60 s) and `nspack_ADInsight` (86 s, the row
that used to need an isolated re-run) - i.e. r72 is the first corpus run that reaches the whole 1991
capability figure in one pass. Row-level OEP/import movements are three: the two gains plus
`bero_geek.exe`, which loses its exact entry (0x159760 -> 0x5f9008), the same trade round 131 recorded
(`rlpack_geek` gained it there and does not here); neither geek row is all-three either way. TELock arm
unchanged at 116 valid PE / 1 OEP / 0 imports / 0 all-three. Suite 602/602 serially (one flaky case under
`ctest -j4`, `PegasusParity.FileAccessEmulationX86`, passes alone - these parity cases share temp roots).

**Lesson to keep:** a profile edit is a *configure* input. Verify with `TAOTE_STACKDBG`/a probe that the
value is live BEFORE spending a corpus run on it.

### 0.17ec Round 132: TELock's ladder is a *handler-driven* trap stream - and taote was advancing the resume pc twice

Round 131 left the stub walking taote's synthetic SEH sentinel arena one byte per fault. The live bytes
(the probe now prints 48 hex bytes at pc - a self-decrypting stub's code cannot be read from the terminal
dump) name the mechanism completely. `telock_7z.exe`, at 0x418086, is a stretch of deliberate traps:

    418086  64 ff 30            push  dword ptr fs:[eax]     ; eax = 0 -> push the chain head
    418089  64 89 20            mov   dword ptr fs:[eax],esp ; install the frame (handler = 0x4180c5)
    41808c  cc                  int3                        ; trap #1  (#BP)
    41808d  90                  nop
    41808e  8b c0               mov   eax,eax
    ...
    4180a6  33 db               xor   ebx,ebx
    4180a8  f7 f3               div   ebx                       ; trap #2  (#DE, divide by zero)
    4180aa  64 67 8f 06 00 00   pop   dword ptr fs:[0]
    4180b0  83 c4 04            add   esp,4

so the "decryptor" is a sequence of instructions that **must raise exceptions**, and the handler that owns
them is the guest's own 0x4180c5:

    4180c5  8b 44 24 04         mov  eax,[esp+4]        ; ExceptionRecord
    4180c9  8b 4c 24 0c         mov  ecx,[esp+0xc]      ; ContextRecord
    4180cd  ff 81 b8 00 00 00   inc  dword [ecx+0xb8]   ; CONTEXT.Eip += 1      (0xb8 = Eip)
    4180d3  8b 00               mov  eax,[eax]          ; ExceptionCode
    4180d5  3d 94 00 00 c0      cmp  eax,0xC0000094     ; #DE?
    4180da  75 24               jne  0x418100
    4180dc  ff 81 b8 00 00 00   inc  dword [ecx+0xb8]   ; Eip += 1 again -> past `div ebx`
    ...
    418100  3d 04 00 00 80      cmp  eax,0x80000004     ; #DB -> 0x418113
    418107  3d 03 00 00 80      cmp  eax,0x80000003     ; #BP -> 0x418120
    41810e  6a 01 / 58 / eb 4d  push 1; pop eax; jmp 0x418160   ; anything else: CONTINUE_EXECUTION
    418120  8b 81 b4 00 00 00   mov  eax,[ecx+0xb4]     ; CONTEXT.Esp
    ...                        (Dr0 = Esp+0x24, Dr1 = Esp+0x1f, Dr2 = Esp+0x1a, Dr3 = Esp+0x11)
    418150  33 c0               xor  eax,eax
    418152  81 61 14 f0 0f ff ff   and dword [ecx+0x14],0xffff0ff0   ; Dr6
    418159  c7 41 18 55 01 00 00   mov dword [ecx+0x18],0x155         ; Dr7 (arm the breakpoints)
    418160  c3                  ret                          ; eax = 0 -> CONTINUE_SEARCH

taote's CONTEXT layout already matches (`kCtxEip = 0xb8`, `kCtxEsp = 0xc4`) and the frame it builds puts
ExceptionRecord at `[esp+4]` and ContextRecord at `[esp+0xc]`, which is exactly what the handler reads -
so the dispatch itself was right. The bug was one line of *arithmetic*: after the handler answers
CONTINUE_SEARCH and no outer frame exists, `seh_continue`'s exhausted path bumped the resume pc by one for
`#BP` (a rule added for Yoda-Protector's int3 probe) - but TELock's handler had **already** advanced
`CONTEXT.Eip` itself. The stub was therefore resumed one byte past the instruction the handler pointed at:

| | resume pc | what is there |
|---|---|---|
| handler's intent | 0x41808e | `8b c0` (mov eax,eax) |
| taote, before | **0x41808f** | `c0 f9 90` - the middle of `mov eax,eax` (`sar cl,0x90`) |
| taote, now | 0x41808e | the instruction boundary the handler chose |

That mid-instruction entry is what produced the 0x70000000 byte-per-fault walk: the "code" from 0x41808f
onward is garbage that reads the sentinel page.

**The fix** is one condition: bump only when the handler left the CONTEXT's Eip on the trap pc
(`resume == seh_trap_pc_`), which preserves the Yoda rule for handlers that do not touch the context and
stops TELock's handler being double-counted. `seh_trap_pc_` is recorded in `seh_dispatch`.

**Also shipped:** `TAOTE_PROBE` now prints 48 hex bytes at pc (`[probe]   @pc= 8b 44 24 04 ...`). Without
it the ladder was unreadable: the terminal dump of that page is still ciphertext, and the handler is only
reachable live.

**Measured** (arms, 314 rows: TELock 116 + Yoda-Protector 101 + PECompact 97) - identical to r72 on every
counter:

| family | r72 | now |
|---|---|---|
| PECompact | 97 / 96 PE / 91 OEP / 94 imp / 91 all | 97 / 96 / 91 / 94 / 91 |
| TELock | 116 / 116 / 1 / 0 / 0 | 116 / 116 / 1 / 0 / 0 |
| Yoda-Protector | 101 / 101 / 0 / 1 / 0 | 101 / 101 / 0 / 1 / 0 |

So this is a *correctness* fix with no graded row movement: the ladder now resumes where its own handler
says, and the remaining TELock blocker is the next one in the stream - the handler answers
CONTINUE_SEARCH (eax = 0) for both traps, so taote's raw-chain continue applies the handler's context, runs
on to 0x4180a8's `div ebx`, and the same handler handles #DE; what still does not happen is the *third*
step, the pop of the frame at 0x4180aa and the jump into the payload. Corpus r73 below.

**Corpus r73** (2678 rows, 85 s, 4 workers, 76 min), against r72:

| run | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r72 (stack fix) | 2675 | 2115 | 2083 | 1991 |
| **r73 (#BP resume fix)** | **2675** | **2115** | **2082** | **1990** |

Exactly one row moved: `nspack_ADInsight.exe`, which failed at the **86 s wall** (the same row that passed
at 86 s in r72) - it passes solo twice at 1 worker / 200 s (35.3 s and 35.7 s, 776 imports), so the graded
delivery is unchanged at 1991/2678 and this fix is neutral on the corpus as it was on the arms. Suite
602/602 serial.

### 0.17ed Round 133: the sentinel return staged a retarget WITHOUT stopping the emulation - a stale `seh_retarget_` was dropping every later CPU exception

Chasing the frame teardown at 0x4180aa (round 132's named next step) ended one level *up* from the ladder.
`TAOTE_SEHDBG` showed the run reaching the two traps and then, at the ladder's own divide:

    [intr] intno=0x0 pc=0x4180a7 ... ebx=0x0     <- #DE, delivered by unicorn
    [intr] intno=0x8 pc=0x4180a7 ... ebx=0x0     <- #DF (double fault), one instruction later
    [unpack] final pc=0x4180a7

`intno 0` is in taote's `kIntrToNt` table (`{0, 0xC0000094}`), so `seh_on_interrupt` should have dispatched
it - but no `[sehd] code=c0000094` line ever appeared, and the run ended with `[rundbg] emu_start returned
cleanly`. The reason is `seh_on_interrupt`'s first guard: `seh_retarget_ != 0` means "a dispatch is already
staged", and it returned false. `seh_retarget_` was **stale**: left over from the sentinel-fetch spin.

`seh_continue` (the "a guest handler returned" path, called from `seh_on_fault`'s sentinel branch) staged
`seh_retarget_ = resume` and returned true - "handled, keep going" - while the pc was still on the
non-executable sentinel page. Unicorn re-fetched, so the hook ran again, hundreds of times (572 `[sehc]`
lines on telock_7z.exe *and* on pecompact_cmd.exe), each iteration re-staging the same retarget. The
retarget that eventually stuck was never consumed by the run loop, so from that point on every CPU
exception was silently dropped: `#DE` escalated to `#DF` and the run ended.

**Fix**: `seh_continue` now calls `ql_->emu_stop()` after staging a retarget (both the exhausted branch and
the CONTINUE_EXECUTION branch), which is the contract `seh_dispatch_cpu` already followed: the run loop then
does `begin = seh_retarget_; seh_retarget_ = 0;` and the state is consistent again. Measured on
telock_7z.exe, in order:

| | before | after |
|---|---|---|
| `[sehc]` spins at the sentinel | 572 | 1 |
| `#DE` at 0x4180a7 | dropped (`intno 0` then `#DF`) | `[sehd] code=c0000094` → the guest handler at 0x4180c5 |
| writes into the stub's section | 34,489 | 34,489 |

so the ladder's second trap is now handled the way the stub intends, and TELock still does not decode (its
handler answers CONTINUE_SEARCH and the walk continues past 0x70000000 as access violations) - but the
*mechanism* is now correct, which is what makes the next step readable.

**Measured** (arms, 314 rows):

| family | before | after |
|---|---|---|
| PECompact | 97 / 96 PE / 91 OEP / 94 imp / 91 all | **97 / 97 / 92 / 95 / 92** |
| TELock | 116 / 116 / 1 / 0 / 0 | 116 / 116 / 1 / 0 / 0 |
| Yoda-Protector | 101 / 101 / 0 / 1 / 0 | 101 / 101 / 0 / 1 / 0 |

The whole PECompact delta is one row: `pecompact_HashCalc.exe` used to spend its **120 s wall** in the spin
(rc=124, no artifact) and now finishes in **6 s** with the exact OEP and recall 1.000. The spin was pure
waste - the same 572-iteration loop was running on every row that reached the sentinel.

**Corpus r74** (2678 rows, 85 s, 4 workers, 71 min):

| run | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r72 | 2675 | 2115 | 2083 | 1991 |
| **r74 (sentinel retarget fix)** | **2676** | **2116** | **2084** | **1992** |

One gain, **zero losses**, and every counter moved by exactly that row: capability **1992/2678**. Suite
602/602 serial.

#### 0.17ee Round 133b: the resume target is right, and the divergence is the ladder's own self-modification

Three measurements against the reference's `SE_DEBUG_HOP` log pin where the remaining TELock gap sits,
without changing any code:

1. **The reference resumes at 0x41808e, not 0x41808d.** Its log has `0x41808c` once (the `int3`), **no**
   0x41808d (the `nop`), then `0x41808e` once and on to 0x418090/0x418091. So TELock's handler at 0x4180c5
   is written for `CONTEXT.Eip = int3 address` plus its own `+1`, which lands on 0x41808e - exactly the
   value taote now computes (round 132's fix). The resume target is therefore correct and is not the gap.
2. **The reference does reach the frame teardown**: `0x4180a9` (the `pop fs:[0]`) appears exactly once in
   its log, and `0x418160` (the handler's `ret`) six times - so the trap ladder really is the path to the
   payload, and it is one pass, not a loop.
3. **taote's `[fault]` pc is the *branch* instruction, not the fetch address.** After resuming at 0x41808e
   taote faults with `access=24 addr=0x70000001 pc=0x41808e`, then `addr=0x70000002`, `0x70000003`, ... -
   i.e. the instruction at 0x41808e is a `ret` that pops successive stack dwords (the sentinel and the
   handler frames above it), while unicorn reports the fault with eip still on the branch. `seh_on_fault`
   prints `regs.arch_pc()`, which is why the pc looks pinned.

**Correction (same round, measured):** the probe says taote's live bytes at 0x41808e are `8b c0` too -

    [probe] pc=0x41808e ... @pc= 8b c0 f9 90 8d 04 5d 34 12 00 00 f8 90 c1 eb 05 fc ...

so there is NO decode divergence there and the clause above is wrong: the `ret` in the sled was never a byte
at 0x41808e. The `[fault] ... pc=0x41808e` lines pin the pc on the *staged retarget*, not on the faulting
instruction, and `TAOTE_WATCH_RANGE=0x418000-0x418200` confirms the whole page is written by one decryptor
loop at `pc=0x418030` (2,597 single-byte writes) in both engines.

**Next probe**: read the live bytes at 0x41808e with `TAOTE_PROBE=0x41808e` in the run that gets there and
compare with the reference's `8b c0`; if they differ, diff the *decrypted* page (0x418000-0x418200) against
the reference's dump at the same moment - the write that first diverges is the instruction to chase, and
`TAOTE_WATCH_RANGE=0x418000-0x418200:200` names its pc directly.

#### 0.17ef Round 133c: the sentinel hook must SURFACE (return false) - measured, and it is not enough on its own

The `[run] emu_start begin=...` trace added for this round named the mechanism: after
`[sehc] exhausted -> resume 41808e` there is **no further `[run]` line at all** - the run loop never
restarts, so the sled happens *inside* one `uc_emu_start` call. The sentinel branch of `seh_on_fault`
returned `true`, which in unicorn's raw hook contract means "handled, retry this access": unicorn retried
the STALE translation block, and because the handler's `ret` had already moved the fetch one byte past the
sentinel, each retry faulted at sentinel+1, +2, +3, ... with the pc pinned on the staged retarget.

`seh_fault_trampoline`'s own comment states the contract the branch was violating: *"Returns false (the
fault surfaces to uc_emu_start's error) whenever the retarget is armed - the run loop then restarts the
emulation at the staged target."*

**Measured, and NOT kept.** Making the sentinel branch surface (`seh_continue(); return false;`) does what it
says on TELock: the `#DE` at 0x4180a7 is now dispatched (`[sehd] code=c0000094`), i.e. the trap stream is
handled end to end for the first time. But the ladder then executes *the stack* instead - `TAOTE_LASTPC`
shows the pc pinned on 0x121ffd8 (the frame address) after the resume - so the frame teardown still does not
reach the payload, and the arms measure a **loss**: Yoda-Protector 101 -> **100** valid PE, TELock and
PECompact unchanged (PECompact still 97/97/92/95/92). Zero gains, one loss, so the change was reverted and
the tree is back at f3845d2.

The two facts worth keeping from the attempt:
1. The sentinel branch of `seh_on_fault` violates its own documented hook contract (returns true while a
   retarget is staged). Any future attempt on TELock must fix the *resume* side in the same change, or the
   sled simply relocates from the sentinel page to the stack.
2. After a surfaced `#DE`, the value the ladder resumes at is the frame address (0x121ffd8), not
   `CONTEXT.Eip = 0x4180a9` - so the CONTEXT the #DE handler patches is not the one taote loads afterwards,
   which is the concrete next question (log `CONTEXT.Eip` inside `seh_load_context` and compare it with the
   handler's `[ecx+0xb8]` writes).

#### 0.17eg Round 133d: the CONTEXT is right and the ladder reaches its MZ scan - the surface fix is still net-negative

Round 133c's open question was "the CONTEXT the #DE handler patches is not the one taote loads afterwards".
It is: a gated `[ctx]` line in `seh_load_context` settles it,

    [sehd] code=80000003 fault=41808d ... chain=121ffd8 handler=4180c5
    [ctx]  load addr=0x70003100 eip=0x41808e esp=0x121ffd8 ebp=0x41807f eflags=0x46
    [sehc] exhausted -> resume 41808e
    [sehd] code=c0000094 fault=4180a7 ... handler=4180c5                 <- the ladder's own div
    [ctx]  load addr=0x70004100 eip=0x4180a9 esp=0x121ffd8 ebp=0x41807f eflags=0x46
    [sehc] exhausted -> resume 4180a9                                    <- past `div ebx`, exactly right

i.e. each dispatch gets a fresh page (0x70003100 then 0x70004100) and the handler's `inc dword [ecx+0xb8]`
(+1 for the trap, +1 more for the #DE branch) lands on 0x41808e and 0x4180a9 - both of which match the
reference's own hop log. With the 133c surface change in place the ladder then *progresses*:

* `0x4180a9` `64 67 8f 06 00 00` (`pop dword ptr fs:[0]`, 16-bit address size) executes - the frame is
  uninstalled and esp advances 0x121ffd8 -> 0x121ffdc;
* `0x4180af` `83 c4 04` (`add esp,4`) executes, and the dword below it is 0x4180c5 (the handler address);
* the ladder jumps `e9 9c 00 00 00` to **0x418163**, which is:
  `88 85 99 00 00 00` (`mov [ebp+0x99],al`), `8b 95 af 1b 00 00` (`mov edx,[ebp+0x1baf]`),
  `81 e2 00 00 ff ff` (`and edx,0xffff0000`), `8b c4`/`33 e4`/`8b e0` (the obfuscation no-op),
  `66 81 3a 4d 5a` (`cmp word [edx],0x5a4d` = "MZ"), `74 08` (`je`), else
  `81 c2 00 00 ff ff` (`sub edx,0x10000`) + `eb f1` - **a downward MZ-header scan**, the classic "find my own
  image base" step.

So the teardown is no longer the blocker: the ladder walks its image base and then dies with the pc pinned on
0x121ffd8 (the frame address, i.e. it executes the stack), which is a *different* place from where 133c left
it.

**Still not kept**: the arms are unchanged except for the same Yoda loss (99 of 101 valid PE, TELock
116/1/0/0, PECompact 97/97/92/95/92), so the surface change is reverted again and only the `[ctx]` diagnostic
ships. Two things are now established for the next attempt: the CONTEXT/resume arithmetic is correct in both
trap cases, and the remaining failure sits *after* the frame teardown, in the MZ scan at 0x418163 - where
`[ebp+0x1baf]` supplies the start address and the scan steps down by 0x10000. That value is the thing to log
next (a `TAOTE_PROBE_EBP_DISP=0x1baf` reading), because the scan can only run off the image if it is wrong.

#### 0.17eh Round 133e: the MZ scan's anchor is kernel32's base, which taote maps INSIDE the scan range

The recorded probe (`TAOTE_PROBE=0x418163 TAOTE_PROBE_EBP_DISP=0x1baf`, run with the 133c surface change so
the ladder gets there):

    [probe] pc=0x418163 ... ebp=0x41807f esp=0x121ffe0
    [probe]   @pc= 88 85 99 00 00 00 | 8b 95 af 1b 00 00 | 81 e2 00 00 ff ff | 8b c4 33 e4 8b e0 |
                   66 81 3a 4d 5a | 74 08 | 81 c2 00 00 ff ff | eb f1
    [probe]   [ebp+7087]=0x10011000

so the scan is `edx = [ebp+0x1baf]; edx &= 0xffff0000` -> **0x10010000**, then it walks DOWN by 0x10000
checking `cmp word [edx],0x5a4d` ("MZ"), and in taote the very first test hits: 0x10010000 is the base of the
**kernel32 stub DLL** that the CLI writes for the run (`map 0x10010000-0x10014000 rwx kernel32.dll`, and
`[ebp+0x1baf]=0x10011000` is that base + 0x1000, i.e. the stub found kernel32 through the PEB LDR walk and
used it as the anchor). The ladder then takes the `je` branch and parses *kernel32's* PE header
(`mov eax,[edx+0x3c]; cmp eax,0x200`) instead of the packed image's.

Confirmed with `--set OS32.dll_address=0x77000000`: the stub DLLs stay at 0x10000000/0x10010000, because
`QlLoaderPE` takes a DLL's base from the DLL's own `AddressOfImageBase` when it is non-zero
(`pe.cpp:475`), and the CLI's synthesized stubs declare 0x10000000. So the knob for a "map the DLLs high"
experiment is the stub-DLL writer in `tools/taote.cpp` (the profile's `dll_address` only supplies the
fallback for a DLL whose declared base is 0).

**Measured, not kept** (the surface change again): the ladder reaches the scan and dies with the pc pinned on
0x121ffd8; arms 99 of 101 valid PE for Yoda, TELock 116/1/0/0, PECompact 97/97/92/95/92 - the same result as
133c/133d, so nothing further shipped from this round.

**Correction (same round): the MZ hit is NOT the divergence.** The reference's own hop log runs the same
scan exactly once - `0x418163, 0x418169, 0x41816f, 0x418175, 0x41817b, 0x418180`, one hit each, so its loop
body never repeats either - and then continues `0x41818a -> 0x41818d -> 0x418192 -> ... -> 0x4181aa`, the
12-byte-record copy interpreter. So "the scan finds an MZ at its anchor" is the *intended* behaviour (any
loaded module starts with one) and moving the stub DLLs high would change nothing: the anchor is the module
base, so its first test always succeeds. The 133e framing above is therefore withdrawn; what remains true
and useful from it is the probe value itself (`[ebp+0x1baf]=0x10011000`, scan anchor 0x10010000, one-byte
`cmp word [edx],0x5a4d` test, `sub edx,0x10000`, loop) and the fact that the ladder reaches 0x418163 only
with the (measured-negative) surface change in place.

**Where this leaves TELock**: the ladder is decoded from its entry to the copy interpreter, the SEH side is
correct in all three respects measured (stack sign, #BP resume, #DE dispatch), and taote dies between
0x418163 and 0x4181aa in a run that needs the surface change to get there at all. The next attempt should
start from the *surface* problem (a sentinel return that must surface, but currently costs Yoda a row)
rather than from the family's later stages - without it the ladder never reaches the code that is already
understood.

### 0.17ei Round 134: the shape vocabulary was missing the CRT entry shapes the payloads actually use (`e8 <rel32> 6a ?? 68`, `e8 <rel32> 85 c0`)

The target this round was the census's cleanest bucket: **29 rows with the payload decoded (code_sim >= 0.9)
and the imports already passing, where only the claimed entry is wrong**. They are not parity cases - the
reference gets every one of the six sampled exactly: `winupack_cmd` 0x829a, `winupack_PEview` 0x1000,
`winupack_HashCalc` 0x11e58, `jdpack_7z` 0xebc5, `molebox_cmd` 0x829a, `amber_pipelist` 0x550b, all matching
the originals' `AddressOfEntryPoint` byte for byte.

**Where taote loses it** - `TAOTE_UNPACK_DEBUG` on winupack_cmd is unambiguous:

    [unpack] OEP candidate 0x4ad0829a (section_hop)
    [unpack] hop ledger (1): 0x4ad0829a@2186565          <- the candidate IS the truth
    [unpack] family=WinUpack base=0x4ad00000 oep=0x4ad01430

The hop that the run itself accepted (write ordinal 2,186,565 - as strong as a hop gets) is the correct
entry, and the picker then *replaced* it with 0x4ad01430. The replacement is the WinUpack policy gate's
shape test, `shape_at(lead) >= 1`, and the truth scores **0** there: its bytes are

    truth 0x829a:  e8 ea f9 ff ff 6a 10 68        (`call ...; push 0x10; push imm32`)
    taote 0x1430:  55 8b ec 8b 45 08 85 c0        (a `push ebp; mov ebp,esp` look-alike)

`shape_at` knew exactly four shapes - `55 8b ec` (3), `6a ?? 68 .... e8` (3), `e8 .. .. .. .. e9` (2),
`e9` (1) - and a CRT startup entry of the form *call the security-cookie initialiser, then push the
arguments* is none of them. winupack_PEview's true 0x1000 (`e8 d7 00 00 00 85 c0 75`, *call; test eax,eax*)
scores 0 for the same reason.

**First attempt (measured, reverted): the reference's statistical test.** pegasus does not test prologue
patterns at all at that point - its hop acceptance is "not all zero, and at most 12 of the 16 bytes
printable" (unpacker.cpp:7502, the 12-of-16 cap calibrated on Borland `55 8b ec 6a ff 68 <imm32>` prologues
measuring 10/16). Ported verbatim into the WinUpack gate it is far too permissive *in taote*: WinUpack
97 rows went to OEP 43 and all-three 42 against the baseline's 85/77 - **2 gains, 37 losses**. The reason is
that the reference applies that test to a candidate set its own hop filtering has already pruned; taote's
gate is the only filter, so "looks like code" accepts ordinary payload hops as entries.

**Second attempt (kept): add the two shapes to the vocabulary.** Narrower, same finding:

    if (p[0] == 0xe8 && p[5] == 0x6a && p[7] == 0x68) return 2;   // call; push imm8; push imm32
    if (p[0] == 0xe8 && p[5] == 0x85 && p[6] == 0xc0) return 2;   // call; test eax,eax

**Measured** (WinUpack arm, 97 rows): **97 valid PE / 87 OEP exact / 82 imports / 78 all-three** against the
baseline's 97/85/82/77 - **2 gains, 0 losses**. `winupack_calc` and `winupack_cmd` now report the exact entry
(0x4ad0829a for cmd, matching the reference). `winupack_Bginfo` failed in-run at the 86 s wall and passes
solo at 1 worker / 200 s (**49.8 s**, oep 0x5b5d42), so the arm is +2/-0 in capability terms.

**Corpus r75** (2678 rows, 85 s, 4 workers, 71 min):

| run | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r74 | 2676 | 2116 | 2084 | 1992 |
| **r75 (CRT entry shapes)** | **2676** | **2122** | 2082 | **1996** |

**Six gains, two losses, and both losses are the wall**: `molebox_PEview` (3 s), `molebox_calc` (21 s),
`molebox_cmd` (7 s), `nspack_calc` (16 s), `winupack_calc` (26 s), `winupack_cmd` (4 s) - the shape class is
global, so it also repaired rows outside WinUpack (the same `e8 <rel32> 6a ?? 68` CRT entry is what Molebox
and NSPack payloads use). The two losses are `mpress_ComIntRep` (85 s) and `nspack_ADInsight` (86 s), and both
pass solo at 1 worker / 200 s (35.1 s and 37.4 s, same entries) - so the graded delivery is **1998/2678**,
+6 on the round and the biggest single-round gain since the Alienyze seed. Suite 602/602 serial.


### 0.17ek Round 136: "the last startup frame" for jdpack_7z - tried on the arm, refuted by the corpus

The next row in the "payload decoded, imports passing, OEP wrong" bucket was `jdpack_7z.exe` (truth 0xebc5,
taote 0xe924). The ladder names both candidates:

    [unpack] ladder passB hits=4 first=0x40e924 last=0x40ebc5
    [unpack] ladder: unique MSVC frame entry 0x40e924

Pass B's startup override (a three-push `55 8b ec / 6a ff / 68 <handler> / 68 <scope> / 64 a1` frame beats
the first/last vote) fires only when `startup_count == 1`, and here TWO frames carry that shape, differing in
nothing but the handler they install:

    0x40e924: 55 8b ec 6a ff 68 f8 14 41 00 68 e2 ec 40 00 64 a1   handler 0x4114f8
    0x40ebc5: 55 8b ec 6a ff 68 28 15 41 00 68 e2 ec 40 00 64 a1   handler 0x411528  <- the truth

so the override declined and `frames.front()` ("the entry sits before its look-alikes") picked the sibling.
The change tried was `startup_count >= 1` keeping the last match; on the 407-row ladder arm (NSPack 97,
RLPack 104, MPRESS 106, JDPack 100) it looked like +3/-0 (`jdpack_7z`, `nspack_procexp`, `nspack_ADInsight`
gained; the single loss, `mpress_ADInsight`, was the 86 s wall and passes solo in 29.0 s).

**Corpus r76 measured the opposite and the change was REVERTED.** With `startup_count >= 1` (last):

| run | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r75 | 2676 | 2122 | 2082 | 1996 |
| r76 (last startup frame) | 2676 | **2113** | 2082 | **1987** |

**1 gain, 10 losses**, every loss a fast run (0-9 s, not a wall artifact): PEtite `ctrl2cap`, `efsdump`,
`gsd`, `ldmdump`, `pagedfrg` and WinUpack `Cacheset`, `ctrl2cap`, `efsdump`, `ldmdump`, `pagedfrg`. The gain
was `jdpack_7z`. So "the last startup-shaped frame" is wrong far more often than right - the ten losers are
images where several three-push frames exist and the FIRST is the entry - and `decode_only_packer.cpp` is
back at `startup_count == 1` with `hit_va = frames.front()`.

**What that means for jdpack_7z**: its two startup frames are byte-identical except for the SEH handler
address (`1` in the dump: 0x4114f8 vs 0x411528, same scope 0x40ece2), so no ordering heuristic can separate
them - "first" is right ten times for every time it is wrong here, and the discriminator must be something
else (which handler is the one the *decoded image's own* data references, or which frame the run's exit path
reaches). That is the concrete next question for this row; it is one row, so it is a low priority next to the
remaining buckets.

### 0.17el Round 137: the remaining "decoded + imports ok + OEP wrong" rows classified by shape pair (no code)

The whole remaining bucket is 23 rows. Classifying the truth's bytes against the claimed ones with the
picker's own vocabulary (`shape_at` classes, plus `e8 <rel32> 6a ?? 68` / `e8 <rel32> 85 c0` from round 134):

| truth shape | claim shape | rows | what it means |
|---|---|---|---|
| 3 `55 8b ec` | 2 `e8 .. .. .. .. e9` | 5 | the claim UNDER-scores a real prologue |
| 3 `6a ?? 68 ... e8` | 2 `e8 .. e9` | 4 | same, and 3 of these are Alienyze `ladder_scan` |
| 3 `55 8b ec` | 3 `55 8b ec` | 4 | same shape, wrong instance (jdpack_7z, neolite x2, ...) |
| 2 `e8 .. e9` | 3 `55 8b ec` | 3 | the claim OVER-scores (amber pspasswd/ru/psshutdown) |
| 2 `e8 .. 85 c0` | (claim outside the file) | 2 | the claim is in the decoded body, not in file bytes |
| 2 `e8 .. e9` | 3 `6a/68/e8` | 1 | amber_pipelist - over-scored |
| others | | 4 | mixed |

So a simple "the bigger shape wins" ranking is contradicted in *both* directions: nine rows want the
higher-scoring truth over a shape-2 claim, and four rows want a shape-2 truth over the shape-3 claim taote
made. There is no ordering rule to extract from this bucket - each row needs its own discriminator (and
`jdpack_7z`, the one same-shape pair with two byte-identical candidates, is the clearest proof: the two
candidates differ only in which SEH handler they install).

**Why the Alienyze trio is not a cheap fix.** `alienyze_EventLogChannelsView` reports
`hop ledger (0)`, `passB hits=0`, `.text: C=2 C3=2 valid=0x98ec` and then picks **0x407249** because Alienyze
sets `ladder_first_c3`, which returns the FIRST c3 hit and *ignores* the validated one. The truth 0xe52e is
not a c3 hit at all - it carries the Borland `6a ?? 68 <image> e8` shape, i.e. Pass E's answer, and Pass E
only runs after Pass C has already returned. Reordering would have to beat the round-47 measurement that
made `ladder_first_c3` the rule (58 Alienyze samples where the first hit is the true EP and the tail hits land
in the `.alien` store), so it is a family-tuning change with a large blast radius for at most three rows.

**Where the remaining value is, in order**: (1) the 96-row "OEP exact + decoded -> imports only" bucket minus
RLPack's 63 blocked rows; (2) the 398-row "OEP wrong + undecoded" mass, which needs family ports and where
Yoda/Themida are excluded by parity; (3) these 23 rows.

### 0.17em Round 138: the largest remaining single class is IMPORT DLL ATTRIBUTION (19 rows measurable, one bug)

While sizing the 96-row "OEP exact + decoded -> imports only" bucket, the missing pairs were classified by
whether the *name* is already emitted under a different dll - i.e. taote mined the function but attributed it
to the wrong module. That test (a missing pair counts as "attribution" when the same name is present under
another dll) says **19 rows would pass**: Alienyze 10, PEtite 8, Amber 1, JDPack 1.

The dll moves, over all failing rows:

| truth dll | dll taote used | pairs |
|---|---|---|
| msvcrt | **crtdll** | 929 |
| msvcrt | version | 132 |
| msvcrt | shell32 | 89 |
| msvcrt | mingwm10 | 69 |
| msvcrt | user32 | 68 |
| msvcrt | gdi32 | 56 |
| msvcrt | ws2_32 | 44 |
| msvcr90 | kernel32 | 26 |

Two different stories live in that table, and only the first is a simple alias:

1. **`crtdll` for `msvcrt`** (929 pairs) is a *name* problem, not an alignment one: `petite_Hash.exe` emits the
   whole CRT (`_initterm`, `__getmainargs`, `_acmdln`, `_XcptFilter`, ...) under `crtdll.dll`, which is the
   dll the PACKED file's own descriptor chain names, while the original imports `msvcrt`. (It also emits
   `crtdll` and `crtdll.dll` as two separate modules - that duplication is a small bug on its own.)
2. **`msvcrt` functions under `version` / `shell32` / `mingwm10` / `libgcj-11`** (the rest) is a real
   attribution defect: `alienyze_dat2file.exe` is a MinGW/GCJ build whose payload imports
   `mingwm10.dll` + `libgcj-11.dll` + `msvcrt`, and taote emitted the CRT names under `mingwm10.dll` (38)
   and `libgcj-11.dll` (2) while the truth has 35 in `msvcrt` and 21 in `kernel32`. Names are being assigned
   to the wrong descriptor, which is the "loose pair" attribution problem the reference solves with anchored
   runs + `idir_self_evidenced` evidence.

**Why this is the best remaining lead**: 19 rows is more than any other single mechanism left in the census
(the whole "decoded + OEP wrong" bucket is 23 rows and needs a per-row discriminator; the "imports only"
bucket's RLPack half is blocked). The first story (crtdll vs msvcrt) is a one-line alias; the second needs
the in-image IDir's dll attribution to win over the thunk-owner guess - the same "trust the payload's own
descriptor" mechanism already sketched for RLPack.

**Cheapest first slice, with its measurement plan**: emit `msvcrt` (and `msvcr90`/`msvcr100`...) alongside
`crtdll` for CRT-shaped names, i.e. treat the legacy CRT dll as an alias of msvcrt in the rebuilt table; that
alone should move `petite_Hash` (22 missing, all CRT, recall 0.741 -> 1.0) and is exactly the class the
crtdll/mingwm10 rows belong to. Measure the PEtite arm (73 rows) first - 30 PEtite rows carry such a move -
then the corpus. Do NOT just accept any dll that carries the name (that is grader-fitting, not a fix).

**The cheapest slice was tried and measured, and it does NOT pay (reverted).** Emitting the `msvcrt` spelling
alongside `crtdll` for CRT-decorated names (gate: the API database's word, or a leading `_`/`?`) does work -
`petite_Hash.exe` went from `[unpack] crt alias: +12 msvcrt pairs` to an artifact recall of **0.8588** against
0.7412 - but the row still fails the 0.95 bar, and the reason corrects the hypothesis in this section: its
remaining **12** missing pairs are not an aliasing problem at all, they are **absent from the artifact**:

    msvcrt ??2@YAPAXI@Z  ??3@YAXPAX@Z  __dllonexit  __getmainargs  __p__commode  __p__fmode
           __set_app_type  __setusermatherr  _acmdln  _adjust_fdiv  _beginthreadex  _except_handler3

No dll in the artifact carries any of those names - the payload's CRT-init imports are simply not mined, which
is the *emulation depth* story again (those slots are resolved by the CRT startup that taote never reaches),
not a dll-attribution one. So the 19-row "attribution" class is really three classes:

1. **crtdll vs msvcrt naming** (the 929-pair bulk) - alias-able in one line, but no single row flips on it
   (`petite_Hash` stops at 0.859), so it needs a row whose *only* deficit is that class;
2. **names emitted under a completely wrong dll** (`alienyze_dat2file`: MinGW/GCJ images whose CRT names land
   under `mingwm10.dll` / `libgcj-11.dll`) - the real "loose pair" defect, needs the in-image IDir's dll
   attribution to outrank the thunk-owner guess;
3. **names not emitted at all** (the CRT-init set above) - emulation depth, same class as RLPack's residual.

The alias patch was reverted (artefact contract unchanged, corpus untouched). Class 2 is where the 19 rows
actually live, and it is a rebuild-attribution project, not an alias.

**Class 2's planned fix does not exist: these images have no import descriptors left.** The next step was
"let the in-image IDir's attribution outrank the thunk-owner guess", the mechanism RLPack's case had pointed
at. Measured on `alienyze_dat2file.exe`, that data is not there:

* the decoded dump at the ORIGINAL's import RVA (0xc000) holds **strings**, not descriptors -
  `libgcc_s_dw2-1.dll`, `__reg...` - because the payload is rebuilt at a different layout (dump 0x20000 bytes
  against the original's 0x8200);
* scanning the whole dump for 20-byte `IMAGE_IMPORT_DESCRIPTOR` shapes whose `Name` RVA points at a dll
  string finds **zero** hits, and `kernel32.dll` does not even appear as a string (`msvcrt.dll` at 0x8834,
  `mingwm10.dll` at 0x7b10, `libgcj-11.dll` at 0x7639 do).

So the payload's imports survive only as *names* (the runtime GetProcAddress surface), with no module
attribution anywhere in the image - which is why taote falls back to the thunk owner, and why a MinGW/GCJ
image's CRT names end up under `mingwm10.dll`. The fix therefore is not "prefer the descriptor"; it is a
name-to-module decision on evidence taote must synthesise: which stub dll the slot resolved through, whether
that dll really exports the name (dll/name cross-evidence beats a single thunk), and - for the aliasing case -
the API database's own dll lists, which file those CRT names under `crtdll,ucrt,ucrtbase` rather than msvcrt.
That is a rebuild-attribution project with several moving parts, not a one-line port, and it is the honest
state of the 19-row class.

**Lead 2 is CLOSED: there is no honest data source for those CRT names on this host.** The API database is
generated from mingw-w64's import libraries (`tools/gen_api_db.py --libdir /usr/i686-w64-mingw32/lib`), i.e.
from real Windows export knowledge rather than the corpus - which is what keeps it non-circular. Checked
against that source, the names class 3 misses are simply not there:

    nm /usr/i686-w64-mingw32/lib/libmsvcrt.a | grep __imp_<name>
      _initterm          0      __getmainargs      0      _acmdln        0
      __set_app_type     0      _adjust_fdiv       0      _except_handler3  0
      _onexit            1

so `_initterm` reaches the database only through `libcrtdll.a` (hence `crtdll,ucrt,ucrtbase`) and the CRT-init
internals are in no mingw import library at all. Adding them would mean typing in exactly the names the corpus
happens to miss - measuring against the answer key - so this lead is not taken. What would make it honest is a
second, independent export source (a real msvcrt.dll export dump, or an MSVC-compiled binary's import table);
neither exists on this host, and the reference gets it from System32 at runtime.

**Net state of the 19-row class**: class 1 is aliasable but flips no row alone; class 2 needs a rebuild
cross-evidence mechanism (real work, up to 19 rows); class 3 is emulation depth and its only data source here
would be circular. The class is therefore parked with a clear map rather than a working fix.

**Class 2's cross-evidence mechanism was simulated against the API database before writing any code - it flips
zero rows, in both phrasings.** The rule "a name the claimed dll does not export but another dll in the row's
set does should move there", evaluated with `api_db.inc` (32,374 names, 405 dlls - the mingw-w64 export
database, so the oracle is an SDK export table and not the corpus) over every failing r75 row:

| phrasing | rows affected | pairs moved | rows that would pass |
|---|---|---|---|
| relocate whenever the claimed dll is not an exporter of the name | 26 | 129 | **0** |
| relocate only OFF a dll the database has never heard of (mingwm10/libgcj class) | 24 | 103 | **0** |

So the 19-row estimate in 0.17em was too optimistic: the "name present under another dll" test counted rows
where the name sits under a dll that *does* export it (so the rule correctly declines to move it), or where
the database does not know the name at all (the CRT-init class, which 0.17eo closed as circular). The
mechanism is therefore NOT implemented - a simulation was enough to refute it, which is the cheapest possible
outcome.

**That closes the whole import-attribution class** with measurements rather than a half-finished change:
class 1 alias: measured, +0 rows, reverted; class 2 cross-evidence: simulated, +0 rows, not written;
class 3 CRT-init names: closed, no non-circular data source on this host. The value that IS recorded here is
the map plus the refutations, so nobody re-derives any of the three.

#### 0.17eq Round 142: TELock's ladder runs to the copy interpreter - the two engines part company INSIDE it

With the (measured-negative) sentinel-surface change applied only to observe, the ladder is now traced well
past the point where earlier rounds lost it. Probe hits against the reference's own hop sequence:

| pc | reference | taote |
|---|---|---|
| 0x41808e (after the int3 handler) | 1 | 1 |
| 0x4180a9 (after the #DE handler) | 1 | 1 |
| 0x418163 (MZ scan) | 1 | 1 |
| 0x418180 (the `cmp word [edx],0x5a4d`) | 1 | 1 |
| 0x41818a (`je` taken) | 1 | 1 |
| 0x4181aa (the 12-byte-record copy interpreter) | 1 | 1 |
| 0x4181ae, 0x4181bf | 1 each | 1 each |
| **0x4181dc** (one iteration further into the loop) | **1** | **3** |

So both engines follow the identical path - trap ladder, teardown, MZ scan, and into the record interpreter -
and they part company *inside* the interpreter: the reference passes the loop once, taote executes it three
times. After that taote's pc ends up on a stack scratch stub the ladder has built (`eb fe` = `jmp $` at
0x121ffd8) and parks there with payload-like registers (`eax=0x10013991 ebx=0x100129ce esi=0x100127e0 edi=1`
- all in the synthesized DLL region), i.e. it never transfers to the payload.

**The concrete next measurement** (recorded, not yet taken): dump the record table the interpreter walks -
`[ebx]`, `[ebx+4]`, `[ebx+8]` for each of the three iterations - under taote, and compare the *count* and
*values* with what the reference's single pass consumes. A record table with three entries where the
reference has one means the stub decrypted one table three times or decrypted the wrong table, which is the
same class as PEtite's decoder divergence and is a *decryption* question, not an SEH one.

**Why the surface change stays reverted**: it is what gets the ladder this far, but alone it measures -1
(Yoda) with no gains, and the hand-off above shows why one more mechanism (the record interpreter's input)
is still missing. The two have to land together or not at all.

#### 0.17er Round 143: TELock's ladder does not fail at all - it PARKS itself, because its export walk cannot see "KERN" in taote's stub kernel32

The recorded measurement was "dump the record table at `[ebx]`". It answered a different and better question.
The instruction at 0x4181aa is not a record interpreter at all in this image - the live bytes are

    4181aa  8b 74 10 20        mov  esi,[eax+edx+0x20]
    4181ae  8b 4c 10 18        mov  ecx,[eax+edx+0x18]
    4181b2  8b 44 10 0c        mov  eax,[eax+edx+0xc]
    4181b6  03 c2              add  eax,edx
    4181b8  8b 00              mov  eax,[eax]
    4181ba  25 5f 5f 5f 5f     and  eax,0x5f5f5f5f      ; uppercase the ASCII
    4181bf  3d 4b 45 52 4e     cmp  eax,0x4e52454b      ; "KERN"
    4181c4  74 07              je   0x4181cd          ; found it -> carry on
    4181c6  68 eb fe 00 00     push 0x0feeb            ; = the two bytes `eb fe`
    4181cb  ff e4              jmp  esp                ; ...i.e. `jmp $`

and the probe at 0x4181aa reports `eax=0x2000 ebx=0x27e0 edx=0x10010000` - so the reads are at
0x10012020 / 0x10012018 / 0x1001200c, **inside taote's synthesized kernel32 stub** (0x10010000-0x10013000, the
dll base the stub found through the PEB LDR walk). The ladder is doing a classic kernel32 **export-directory
walk**, upper-casing a dword read through an RVA table and looking for "KERN" ("KERNEL32.DLL"); when it does
not find it, it executes `push 0xfeeb; jmp esp` - the deliberate `eb fe` (`jmp $`) hang, which is exactly the
stack stub this round's predecessor saw at 0x121ffd8.

So **TELock's ladder is not crashing and not diverging in its SEH handling: it parks itself on purpose**, because
taote's hand-written stub DLL does not have a real module's export-directory layout where the walk looks. The
reference does not park because its kernel32 is a real (or real-shaped) module.

**Correction (same round, measured): the stub layout is NOT the problem.** The first reading of the park was
"taote's stub DLL has no real export-directory layout", and that is wrong on inspection. `write_stub_dll`
(tests/Pe_Sample_Runner.hpp:174-285) writes a genuine `IMAGE_EXPORT_DIRECTORY`: `Name` RVA at +0xc patched to
`edata_rva + strings_off`, `NumberOfNames` at +0x18, `AddressOfNames` at +0x20, and the *module name is the
first string* at `strings_off`, so `[Name RVA]` really does read "kernel32.dll" (which the guest's
`and eax,0x5f5f5f5f` uppercases into "KERN"). A probe at the park site confirms the guest is reading a REAL
export-name pointer - `eax=0x10013991`, `@eax='lstrlenW'`, i.e. the first entry of kernel32's name table - so
the walk is iterating export NAMES, not validating the module name, and it parks afterwards.

So the ladder does park itself (that part stands: `push 0xfeeb; jmp esp` is the deliberate `eb fe` hang), but
not because the stub's export table is malformed. What is left to explain is why its name walk gives up after
finding `lstrlenW` - and the page it runs from is self-modifying, so the mask/cmp sequence must be dumped live
in the SAME run that parks (TAOTE_PROBE at 0x4181ba and 0x4181c6, immediately before the push), not read from
a terminal dump. That is the next measurement, one round's work, and it is the last thing between the decoded
ladder and the payload.

#### 0.17es Round 144: the stub is NOT starved - the walk finds LoadLibraryA and moves on to resolve it

Round 143's correction left one question: why does the export walk give up. It does not. Measured, with the
sentinel-surface change applied only to reach the code (reverted after):

| probe | fires | meaning |
|---|---|---|
| `0x4181ba` (`and eax,0x5f5f5f5f`) | yes, `eax=0x6e72656b` | the module name reads back "kern" - the Name RVA is correct |
| `0x4181dc` (name-table loop tail) | 3x, `esi=0x10012404` `+4`, `ecx=0xf7..0xf5`, `edi=0xd` | it iterates kernel32's **AddressOfNames** table (247 entries) |
| `0x4181fc` (after `"Load"`/`"Libr"`/`"aryA"`) | **fires** | a name matched all three dwords - `LoadLibraryA` WAS found |
| `0x418226` (the `jne` target) | fires too | non-matching names take this path |

And the stub is not starved: `ApiRegistry::names_for_dll("kernel32.dll")` returns **247** names, exactly the
count the walk uses, and `LoadLibraryA` and `GetProcAddress` are both among them (checked offline by linking
against `libqiling.a` and calling `register_dlls()`). `write_stub_dll` already unions the registry surface with
the sample's own imports (tests/Pe_Sample_Runner.hpp:174-193, whose comment names this exact walk), so the
"the stub only exports what the sample imports" hypothesis is **refuted**.

What the walk does after the match is the live code at 0x4181fe:

    4181fc  75 28             jne 0x418226
    4181fe  68 c3 03 00 00    push 0x3c3
    418204  58 58             pop eax; pop eax       ; obfuscating no-ops
    418205  50                push eax
    418206  83 ec 04          sub  esp,4
    418209  53                push ebx
    41820a  03 c2             add  eax,edx

i.e. after finding the name it goes on to **resolve the export's address** (an RVA taken from the EAT/ordinal
side, 0x3c3, plus the module base) and call it through the stub cell. So the divergence is downstream of the
name lookup, in address resolution, not in the name table.

**Three hypotheses about this walk were refuted this round and must not be re-derived**: (1) that the stub's
export directory layout is malformed; (2) that the stub is starved of names; (3) that the name lookup fails.
The stub is faithful enough for steps 1-3 and the next measurement is the resolution step at 0x41820a - what
address the stub's EAT hands back for `LoadLibraryA` and what the packer does with it. Note every cell in the
synthesized stub is a bare `ret` (0xC3) and dispatch happens by address through `hook_winapi`, so a packer that
*reads the cell bytes* or expects a real function body sees a one-byte stub - that is now the prime suspect and
it is testable without touching the ladder.

#### 0.17et Round 145: TELock's resolver is real and writes the payload IAT - but its 13-target loop never finishes

Probe at 0x41820a (the resolution step 0.17es named), first two hits: `eax=0x2028 edx=0x10010000`, then
`eax=0x2028 edx=0x10010000` with `edi` going 0xd -> 0xc, `esi=0x1001241c -> 0x10012438`, `ecx=0xf0 -> 0xe9`.
The live code is a textbook name -> ordinal -> EAT resolver:

    41820a  03 c2          add   eax,edx            ; AddressOfFunctions (0x2000+0x28 = the stub's real offset)
    41820c  0f b7 1b       movzx ebx,word [ebx]     ; ordinal
    41820f  8b 1c 98       mov   ebx,[eax+ebx*4]   ; EAT[ordinal]
    418212  03 da          add   ebx,edx            ; export VA
    418214  8b 44 24 04    mov   eax,[esp+4]
    418218  89 1c 28       mov   [eax+ebp],ebx    ; <- writes the payload IAT slot
    41821b  5b 58 4f 75 b8 pop ebx; pop eax; dec edi; jnz 0x4181d8
    418220  0f 84 e5 01 00 00  je 0x41840b

and `0x2028` is exactly the stub's `AddressOfFunctions` RVA (`edata_rva 0x2000 + funcs_off 0x28`), so the
resolver walks taote's own export tables correctly and **stores resolved addresses into the payload's IAT**.

The loop, however, never completes: `0x418220` (the `je` after `dec edi`) fires **0 times**, as does
`0x41840b` beyond it, while `edi` is measurably decrementing (0xd -> 0xc across hits). So the 13-target loop
dies *inside* an iteration - the scan exhausts and parks - not at its exit.

That refutes the obvious "missing name" theory: every plausible TELock target is in the stub's surface
(`lstrlenW`, `lstrlenA`, `ExitProcess`, `GetProcAddress`, `LoadLibraryA`, `GetSystemTimeAsFileTime`,
`GetCurrentProcessId`, `IsBadReadPtr`, `UnhandledExceptionFilter`, `GetCommandLineA`, `VirtualAlloc`,
`GetModuleHandleA`, `GetSystemInfo`, `GetVersion`, `Sleep` - all present, checked offline).

**Next measurement, one round:** the resolver's *requested* name has to be observed, not inferred. The only
places it can be read are the three-dword comparisons (`"Load"`/`"Libr"`/`"aryA"` at 0x4181e4, `"Exit"` at
0x418226) or a gated print in the stub's cells, and the page is self-modifying, so this needs an env-gated
debug line in the emulation (like TAOTE_PROBE) that prints, at the park, the last compared name, the loop
index `edi` and the IAT slot it had just written - i.e. which of the 13 targets it died on. Everything else
about this family is now measured: the ladder, the frame teardown, the MZ scan, the module-name check, the
name-table walk, the ordinal/EAT resolution and the IAT store all behave.

#### 0.17eu Round 146: the synthesized stubs now sort their export names (corpus-neutral, TELock resolver advances)

Real DLLs' `AddressOfNames` is sorted - the PE spec's binary-search contract, and what GetProcAddress assumes.
`write_stub_dll` emitted the names in **registry order**, and TELock's resolver scans the table *advance-only*
(it keeps `esi`/`ecx` across the 13 targets it fills, measured: `ecx` 0xf7 -> 0xf0 -> 0xe6 while `edi`
decrements), so a target sitting earlier than the current position could not be seen.

Change: `std::sort(all_names)` in `write_stub_dll` (tests/Pe_Sample_Runner.hpp), which is the shared writer the
CLI uses. The cell/name/ordinal tables are all built from `all_names` after the sort, so they stay consistent.

Measured on **corpus r77** (2678 rows, 85 s budget, 4 workers, `/home/jim/runs/r77_results.json`,
`R77_CORPUS.md`):

| | valid PE | OEP exact | imports | all-three |
|---|---|---|---|---|
| r75 | 2676 | 2122 | 2082 | 1996 |
| **r77** | **2676** | **2122** | **2082** | **1996** |

**0 gains, 0 losses, every counter identical** - a free fidelity fix, kept. Suite 602/602 serial.

Its effect on the family it was written for is real but not yet a row: with the sort, TELock's resolver walks
`edi` 0xd -> 0xc -> 0xb (three probe hits, `esi` +0x1c) where before the sort it died after the second target,
and `AddressOfFunctions` stays exactly the stub's `0x2028`. TELock itself stays 116 rows / 116 valid PE /
1 OEP / 0 imports / 0 all-three because the ladder still needs the sentinel-surface change to reach the
resolver at all - that combination (+sort, +surface) is the next experiment, and it must be measured on the
TELock arm and the corpus because the surface change alone was -1 Yoda valid PE.

#### 0.17ev Round 147: correction - "the 13-target loop never finishes" is NOT established, and the +sort +surface pair does not complete it

Two corrections, both forced by measurement.

1. **0.17et's "the loop never completes" overstated the evidence.** `0x418220` and `0x41840b` were probed and
   fired 0 times, but `TAOTE_PROBE` fires only on an **instruction start**, and both addresses were derived from
   a *static* read of a page that is demonstrably self-modifying (two contradictory byte images in one session).
   An address that is mid-instruction never fires. So the honest statement is: the loop fills IAT slots
   (`edi` 0xd -> 0xc -> 0xb, `0x2028` = the stub's AddressOfFunctions) and execution **ends on the `eb fe` park
   stub** (the `TAOTE_LASTPC` ring is 30/30 `0x121ffd8`); *when* it leaves the loop is not known.

2. **Sorting the stub's export names + the sentinel-surface change together still do not complete the
   resolver.** With both applied (build since reverted), `0x418220` and `0x41840b` still fire 0 times and
   telock_7z.exe still reports `oep=0x418037 reason=section_hop imports=2` - the packed stub's own imports, not
   the payload's. So the sort is *not* the missing piece, and the pair was not taken to an arm measurement: the
   surface change costs 1 Yoda valid PE (measured in round 134's arm) and pays nothing here.

That shifts suspicion away from the export walk entirely and onto **when taote stops emulating**. The run ends
with `stages=1` and a `section_hop` latch, and the reference's own hop log keeps emulating long past its first
accepted hop on this sample (0.17dc), so the park may simply be where taote's *run* ends rather than what the
guest executes to. That is the "post-OEP grace window" idea that was rejected earlier for budget reasons, which
is why it must come back with a TELock-scoped budget story, not as a global change.

#### 0.17ew Round 148: TELock's resolver target list, read straight off the live compare chains

Probing the region after the name walk (each probe prints a 48-byte live window) decodes the dispatcher: for
every export name it compares three dwords and, on a match, jumps to a resolver that fills one IAT slot. The
targets so far, with the slot constant each one stores:

| live bytes | name | slot |
|---|---|---|
| `81 38 4c 6f 61 64` `75 3a` `81 78 04 4c 69 62 72` `75 31` `81 78 08 61 72 79 41` `75 28` | **LoadLibraryA** | 0x3c3 |
| `81 38 45 78 69 74` `75 19` `81 78 04 50 72 6f 63` `75 10` `81 78 08 65 73 73 00` `75 07` | **ExitProcess** | 0x3c7 |
| `81 38 56 69 72 74` ... `75 61 6c 41` ... `6c 6c 6f 63` + `80 78 0c 00` | **VirtualAlloc** | 0x3cb |
| `81 38 56 69 72 74` ... `75 61 6c 46` ... `72 65 65 00` | **VirtualFree** | 0x3cf |
| `81 38 43 72 65 61` ... `74 65 4d 75` ... `74 65 78 41` | **CreateMutexA** | 0x3d3 |
| `81 38 4f 70 65 6e` ... `50 72 6f 63` ... `65 73 73 00` | **OpenProcess** | 0x3db |
| `81 38 47 65 74 43` ... | **GetC**... (next chain) | ... |

Two facts follow, and they change the picture again:

1. The comparison is **exact, null-terminated, case-sensitive** (`65 73 73 00` = "ess\0"), i.e. the stub's
   names must match a real kernel32 spelling exactly - and they do, because every one of the names above is in
   `names_for_dll("kernel32.dll")` (verified offline in 0.17et).
2. The payload's IAT slots (0x3c3 ... 0x3db, one every 4 bytes) are **being filled**, so the resolver's
   product exists; what is still unexplained is only where the pass ends.

So the family is no longer "the walk cannot find its APIs" and no longer "the stub lacks the names": the walk
finds them and writes the payload IAT. The open question is the single one 0.17ev already narrowed to - what
taote does at the end of the scan - and it must be answered by probing a **real instruction start** (a 0-hit
probe on this self-modifying page proves nothing, 0.17ev).

#### 0.17ex Round 149: TELock's run does not stall - it DIES on a fault, and the fault is the sentinel page being executed

`dur=0` on all 116 TELock rows was the clue: the run is not burning a budget, it ends in under a second. The
summary line names the reason, which no earlier round had read:

    [unpack] telock_7z.exe family=TELock base=0x400000 oep=0x418037 stages=1 reason=section_hop imports=2
    error=emulation error: Invalid memory read (UC_ERR_READ_UNMAPPED)

So there is no early latch to fix: **taote aborts on a guest fault**. `TAOTE_SEHDBG` localises it:

    [sehd] code=80000003 fault=41808d pc=41808d chain=121ffd8 next=0 handler=4180c5
    [sehc] ret=0 frames=0 walk=0x121ffd8 ctx=0x70003100 esp=0x121ffc8 eip=0x70000000
    [sehc] exhausted -> resume 41808e              <- correct, the handler patched CONTEXT.Eip
    [sehc] ret=0 frames=0 walk=0x121ffd8 ctx=0x70003100 esp=0x121ffd8 eip=0x41808e
    [sehc] exhausted -> resume 41808e              <- repeats with the context already at 41808e
    ...
    [fault] access=19 addr=0x1 pc=0x70000000       <- 19 = READ_UNMAPPED
    [sehd] code=c0000005 fault=1 pc=70000000 chain=121ffd8 next=0 handler=4180c5

The run ends with the guest **executing the sentinel arena at 0x70000000 as code** (access 19 is a *read*
fault at address 0x1, i.e. an instruction there dereferenced 0x1) and then the SEH dispatcher handing that
fault to TELock's own handler, which cannot help.

That makes the remaining TELock blocker a **mapping/permission** question, not a decode one: the sentinel
arena holds DATA (the CONTEXT at 0x70003100, the exception record at 0x70003010) yet it is executable in the
emulator, so any resume that lands on the sentinel runs garbage instead of surfacing. This is the same
sentinel-surface family as 0.17ef (which cost 1 Yoda valid PE when changed globally) - but the framing is now
sharper: the fix is not "make fetch faults surface", it is "**the sentinel arena must never be executable**",
which is what real Windows guarantees for a heap region, and which no family can legitimately depend on.
Measurement plan for the next round: map the arena non-exec (or make the fetch there a fetch-prot fault that
the existing sentinel branch handles), then judge TELock's 116 rows and Yoda's 101 together - the previous
global attempt lost exactly one Yoda valid-PE row, so the pair has to be re-measured rather than assumed.

#### 0.17ey Round 150: the fatal fault is the handler's `ret` landing on the sentinel - and the sentinel branch does not take it

`TAOTE_LASTPC=12` names the end exactly:

    4180d3 4180d5 4180da 418100 418105 418107 41810c 41810e 418110 418111 418160 70000000

i.e. TELock's handler runs its tail (`xor eax,eax` ... `mov dword [ecx+0x18],0x155`), executes its `ret` at
**0x418160**, and the return address it pops is **0x70000000** - the staged SEH sentinel page. The next pc is
the sentinel, and the run then aborts with `UC_ERR_READ_UNMAPPED` at addr 0x1.

One experiment was run and **reverted**: the per-dispatch structures page (EXCEPTION_POINTERS / record /
CONTEXT) was mapped `UC_PROT_READ|UC_PROT_WRITE` instead of `UC_PROT_ALL`, on the theory that executing the
arena was the fault. It changed nothing - `telock_7z.exe` still ends with the same error - which is consistent
with the sentinel page *already* being RW-only (`seh_map_sentinel`, qiling/os/windows/seh.cpp:86) and with the
fault being something else.

So the open question is narrow and mechanical: the sentinel page is non-executable, the guest's `ret` targets
it, yet the run dies with a *read* fault at 0x1 rather than the `UC_MEM_FETCH_PROT` that
`seh_on_fault`'s sentinel branch (seh.cpp:283, `in_sentinel_page`) is written to intercept. The next round must
determine whether that branch is entered at all for this fetch - one `TAOTE_SEHDBG` print inside the branch is
enough - because every other stage of the ladder is measured correct and the ret to the sentinel is exactly the
hand-off the branch exists for.

#### 0.17ez Round 151: the run ends in a CONTINUE_EXECUTION loop on a read at 0x1 - which real TELock would not do

Reading `seh_on_fault` against the trace closes the loop: its sentinel branch is gated on
`access == UC_MEM_FETCH_PROT || UC_MEM_FETCH_UNMAPPED` (seh.cpp:287), and this run's fatal access is
`UC_MEM_READ_UNMAPPED`, so **the branch is correctly not taken** - the fault is dispatched to the guest, as a
data fault must be. The full chain is then:

1. the stub performs a **read at address 0x1** (`[fault] access=19 addr=0x1`);
2. `seh_dispatch(address, 0u)` calls TELock's handler at 0x4180c5 with a genuine 0xC0000005 record;
3. that handler's dispatch (`cmp eax,0xc0000094` / `0x80000004` / `0x80000003`, else `push 1; pop eax`) falls to
   its "anything else" arm, i.e. **EXCEPTION_CONTINUE_EXECUTION** - and it patches *nothing* in the CONTEXT on
   that path (only the #DE arm bumps Eip, only the #BP arm arms Dr0-Dr3);
4. `seh_continue`'s `ret == kExceptionContinueExecution` arm loads the context and retargets at the same Eip;
5. so the stub re-executes the instruction that reads 0x1, faults again, and the run dies when the repeat guard
   trips - exactly the observed `UC_ERR_READ_UNMAPPED` at addr 0x1 after the handler's `ret` at 0x418160.

That is self-consistent and it also says where the *real* divergence must be: on real Windows this ladder does
not read address 0x1 in the first place, because TELock's own handler cannot repair a 0x1 read either - it would
loop forever there too. So the 0x1 read is a **taote-side state artifact** (a pointer the stub derived that
should not be 1), not a disposition problem, and the next round should find which register/stack slot the read
takes its base from by probing the instruction *before* the fault. Note the two experiments this idea has
already refuted: the sentinel branch is not involved (measured above), and the structures-page protection is
irrelevant (0.17ey).

#### 0.17fa Round 152: the end is a 15-instruction cycle that re-enters the handler from the sentinel - and that corrects 0.17ez

`TAOTE_LASTPC=220` shows the run's last 220 instructions are one **repeating 15-instruction cycle**:

    4180c5 4180c9 4180cd 4180d3 4180d5 4180da 418100 418105 418107 41810c 41810e 418110 418111 418160 70000000 | 4180c5 ...

i.e. TELock's handler entry -> its body -> its `ret` at 0x418160 -> the sentinel 0x70000000 -> **the handler
entry again**, forever, until the repeat guard aborts the run.

That corrects 0.17ez. The faulting instruction is *not* re-executed by a CONTINUE_EXECUTION disposition: the
pc that follows the sentinel is the **handler's own entry** (0x4180c5). The mechanism that fits all the
evidence is that the handler's second instruction pair is
`mov ecx,[esp+0xc]` (ContextRecord) then `inc dword [ecx+0xb8]` (CONTEXT.Eip) - the bump happens **before** the
exception-code dispatch, so for the "anything else" arm (0xC0000005 included) the handler answers
CONTINUE_EXECUTION with Eip = fault_pc + 1. If fault_pc is the byte before the handler (0x4180c4), the resume
lands exactly on 0x4180c5, the handler re-enters itself, and the loop is closed without the ladder ever
advancing.

Two things follow, and they are the next round's whole job:

* the value of `fault_pc` for the first dispatch of the cycle has to be read (it decides whether the stub is
  really faulting one byte before its own handler, or whether the CONTEXT taote builds is off by something);
* the disposition is only sound if a handler call is *in progress*: when the sentinel fetch is seen with no
  handler call outstanding, treating eax as the verdict re-applies a stale answer. `seh_continue` has no such
  guard today (`ret` is read straight from the live eax).

Both are small, and both are the difference between a loop and the ladder's continuation.

#### 0.17fb Round 153: the stale-verdict guard breaks TELock's cycle but the CRT needs its double return (reverted)

Implemented the 0.17fa item 2 guard: a `seh_call_outstanding_` flag set in `seh_call_frame`, cleared in
`seh_continue`, and the sentinel branch surfacing the fault (`return false`) when it fires with no call
outstanding.

Measured on telock_7z.exe **it works exactly as predicted**:

* the 15-instruction cycle is gone - `[sehc] sentinel fetch with no call outstanding -> surface` prints twice;
* the run no longer aborts: the `error=emulation error: Invalid memory read (UC_ERR_READ_UNMAPPED)` line is
  **gone** from the summary;
* execution now ends where the previous rounds predicted it would once the loop was broken - `TAOTE_LASTPC`
  is 12/12 `0x121ffd8`, the deliberate `eb fe` park on the stack.

But the serial suite went **602 -> 601**: `PegasusParity.SehDispatchEnabled` fails, i.e. the `seh_test_x86.exe`
nested-fault fixture. That fixture's path is the guest CRT returning to the sentinel more than once per staged
call (its `_except_handler` chain answers filter-then-handler), so "one staged call == one answer" is too
strict: the flag is cleared by the first return and the second one is surfaced, which changes what the CRT sees.

So the guard is **reverted, not kept** (suite must stay 602/602), and the refinement is precisely specified:
the flag has to model the *walk*, not the single call - it must stay set until the dispatch that staged it is
fully unwound (the synthetic frame list drains), so the CRT's own multi-return path keeps working while
TELock's no-call-in-progress repeat still surfaces. That is the next change to make, and its acceptance test is
both the 602 suite and telock_7z.exe showing no abort plus the park at 0x121ffd8.

#### 0.17fc Round 154: the walk-scoped guard ships - TELock's spurious handler re-entry is gone (corpus-neutral, 0 losses)

The refinement from 0.17fb, implemented: `seh_call_outstanding_` is set in `seh_call_frame` and cleared **only
on an exhausted walk** (the branch that stages `resume` and prints `[sehc] exhausted`), not on every
`seh_continue` entry. The sentinel branch then surfaces the fault (`return false`) when a sentinel fetch
arrives with the flag clear.

Why that lifetime is right: the CRT's filter-then-handler path (`seh_test_x86.exe`) answers *twice* for one
staged call and both answers arrive through the sentinel, so clearing per call broke it (0.17fb, suite
602 -> 601). An **exhausted** walk, by contrast, has nothing left to answer, so a later fetch there can only
be a stale re-entry - which is exactly TELock's loop.

Measured:
* serial suite **602/602** (the 0.17fb failure is fixed by the narrower lifetime);
* `telock_7z.exe`: the `error=emulation error: Invalid memory read (UC_ERR_READ_UNMAPPED)` line is **gone**,
  the 15-instruction handler cycle is gone, and the run ends on the guest's own deliberate `eb fe` park at
  0x121ffd8;
* TELock's rows now consume the **full 85 s budget** (`dur=85`) instead of aborting at `dur=0` - the ladder
  runs on instead of dying, which is a real behavioural change for the family even though it has not yet
  produced a row;
* **corpus r78**: valid PE 2676, OEP 2122, imports 2083, all-three **1997** against r77's 2676/2122/2082/1996.

The one row-level difference is `mpress_ComIntRep.exe`, which failed at the wall in r77 and passes in r78:
it is a **known flake** (passes solo in ~35 s), so the graded +1 is that flake landing rather than a
capability gain. Diffing against r77 row by row gives **0 gains, 0 losses, 0 real movements**: the guard is
fidelity, not score. Kept because it removes a defect that was aborting the run on taote's own stale state,
and because a run that keeps emulating is the precondition for every remaining TELock hypothesis.

Cost, recorded honestly: 152 rows now finish at 84-86 s (up from ~110), i.e. the corpus takes ~110 min at
4 workers instead of ~70.

#### 0.17fd Round 155: the park is a resolver MISS - 13 targets, 12 filled, `edi=1`

With the round-154 guard in place the run survives, so the park site itself can finally be probed. At 0x4181c6
(the `push 0xfeeb; jmp esp`), the first hit reports:

    eax=0x10013991  ebx=0x100129ce  ecx=0xffffffff  edx=0x10010000  esi=0x100127e0  edi=0x1
    @eax='lstrlenW............'
    @pc= 68 eb fe 00 00 ff e4 ...

`ecx=0xffffffff` is the name-table scan **exhausted**, `eax` holds the last name it compared (`lstrlenW`), and
**`edi=1`** - the counter that started at 13. So the resolver resolved **twelve of its thirteen targets** and
then ran off the end of the export name table looking for the thirteenth.

That is a much sharper statement than any earlier round could make: TELock's ladder is not failing to start, not
failing to find its table, and not failing to resolve - it is **one API short**, and that single miss is the
whole 116-row family.

The chains decoded so far, in order, with the payload-IAT slot each fills (4 bytes apart):

    0x3c3 LoadLibraryA   0x3c7 ExitProcess   0x3cb VirtualAlloc   0x3cf VirtualFree
    0x3d3 CreateMutexA   0x3db OpenProcess   0x3df VirtualProtectEx   ... (six more)

Every name above is present in `names_for_dll("kernel32.dll")`, so the missing one is very likely a name taote
does not implement at all. Two ways to identify it, both cheap, recorded for the next round:

1. **The unfilled slot**: the slots are sequential, so after a run the payload's IAT has twelve written entries
   and exactly one zero, and its index names the target.
2. **Probing further chains**: the window at 0x418316 already shows `VirtualProtectEx` followed by `"Crea"`
   (CreateFileA/W? CreateProcessA?), so the list continues past the seven decoded; the remaining probes must
   use real instruction starts (0x418344/0x418374/0x4183a4 do not fire, so the chain blocks are not laid out on
   that stride).

Also recorded as a cost: with the guard, every TELock row now spends the full 85 s in this park (r78 shows
`dur=85` on the family), which is why corpus r78 ran ~110 min instead of ~70.

#### 0.17fe Round 156: `IsBadCodePtr` was the obvious candidate for the missing target - measured, it is not

0.17fd left the family one API short (13 targets, 12 filled, `edi=1`). Diffing the registry's 247 kernel32 names
against the plausible TELock API set left exactly **one** absent name: `IsBadCodePtr` (its siblings
`IsBadReadPtr`/`IsBadWritePtr` are implemented in winbase.cpp, it was not). So it was added as a WinsdkApi
answering FALSE, built, and measured:

    [probe] pc=0x4181c6 ... ecx=0xffffffff edi=0x1 ...        <- unchanged
    [unpack] telock_7z.exe ... oep=0x418037 stages=1 imports=2  <- unchanged

So **`IsBadCodePtr` is not the missing name**, and the addition was reverted rather than shipped unmeasured
(a stub-surface change needs a corpus run, and this one buys nothing here).

What this narrows: the missing target is a name that is neither in the registry's kernel32 surface *nor* in the
seven-byte-aligned chains decoded so far (LoadLibraryA, ExitProcess, VirtualAlloc, VirtualFree, CreateMutexA,
OpenProcess, VirtualProtectEx, plus a `"GetC..."` chain at slot 0x3d7). The cheapest way to name it is now to
**count matches per chain** rather than guess: an env-gated counter at the common resolver tail
(0x41821d's `dec edi`) that prints the slot constant each successful chain pushes, i.e. which of the thirteen
slots never gets written. That is one gated print, one build, and it names the API exactly.

#### 0.17ff Round 157: TELock's missing API is VirtualProtectEx - the park is gone and the ladder reaches its CRC phase

The chain list was finally read *exactly* rather than probed around: `TAOTE_WATCH_RANGE=0x418000-0x418400`
prints the decryptor's byte writes with addresses, so the decrypted chain table can be reconstructed offline
and disassembled. All thirteen targets, in code order, with the payload-IAT slot each fills:

    LoadLibraryA 0x3c3   ExitProcess 0x3c7   VirtualAlloc 0x3cb   VirtualFree 0x3cf
    CreateMutexA 0x3d3   OpenProcess 0x3db   GetCurrentProcessId 0x3d7   VirtualProtectEx 0x3df
    CreateFileA 0x3eb    CloseHandle 0x3e3   ReadFile 0x3e7       GetModuleFileNameA 0x3ef
    GetProcAddress (last chain)

Differencing those against `names_for_dll("kernel32.dll")` leaves exactly **one** absent name:
**`VirtualProtectEx`** (taote implements `VirtualProtect`, not the Ex form). Implementing it in memoryapi.cpp
(the sibling's `return 1` body) removes the park outright:

* `TAOTE_PROBE=0x4181c6` **no longer fires** - `push 0xfeeb; jmp esp` is never reached;
* the ladder runs on into TELock's **CRC-32 integrity phase**: `TAOTE_PROBE=0x4189de` fires with
  `edi=0xedb88320` (the CRC polynomial), `ebx=0` after `0x400` bytes and `esi=0x418408`, i.e. the block CRC
  completes and is salted into `[ebp+0x1b5f]`;
* telock_7z.exe's artifact is still not the payload (`code_sim` 0.078), and a 12-row TELock sample grades
  0 OEP / 0 imports - so this is a **lock removed, not a row won**.

Corpus **r79** against r78: valid PE 2676, OEP 2122, imports 2082, all-three **1996** vs 2676/2122/2083/1997.
The single row difference is `winupack_Bginfo.exe`, which hit the 85 s wall (it passes solo in one pass:
oep 0x5b5d42, imports 2002), so **0 real gains and 0 real losses**. Kept on fidelity grounds: it implements a
real Windows API taote lacked, and it removes a hard stop in the one family the reference solves.

#### 0.17fg Round 158: two family-agnostic lessons from the reference's ASPack work, audited against taote

**(b) A packed source window is not bounded by its containing section.** Real counter-example from the
reference: ASPack's `.data` entry sits 0x3400 bytes into a 0xC00 raw window and a `.rsrc` entry 0x74EC0 into
0x17CC0; clamping the source to the section produced false bails.

taote had exactly one such clamp, in `adopt_embedded_pe`'s Alienyze body copy
(qiling/unpack/packers/embedded_pe.cpp):

    const std::size_t n = std::min<std::size_t>(avail, hollow_end - hollow_start);

i.e. the copy was truncated to the **hollow section's virtual size** - the same assumption that hid Alienyze's
own overlay gap (0x6101 bytes the section table never describes). Widened to `n = avail`, which is already
bounded by the image and by the packed EP.

Measured on the **126-row Alienyze arm** (`/tmp/al.json`): valid PE 125, OEP 108, imports 79, all-three **75** -
identical to r79's Alienyze numbers, **0 gains, 0 losses**, and `alienyze_dat2file.exe` byte-identical
(code_sim 0.0784 both ways). So the truncation is real but this corpus never exercises it; kept because it is a
construction defect with zero measured cost, and the path is gated on an actual `.alien` section, so no other
family can reach it.

**(a) Never mirror a decorator's one-shot state in a local flag.** The reference kept a local mirror of ASPack's
one-shot filter byte and got one wrong byte at `.rsrc+0x6502` when a section bailed; the fix is to re-read the
guest's own byte at every fire.

Audited taote's unpack state for that shape and found none: the run-time caches are either re-validated on
every access or record taote's own actions rather than the guest's. Specifically:

* `wr_cache_lo_/wr_cache_hi_` (the hot-path claim cache) is negative-cached only - a miss is never remembered -
  is refreshed on every hit, and is cleared whenever the claim ledger consumes a range (unpack.cpp:1258);
* `exec_page_seen_` / `dumped_addrs_` / `muted_` are one-shot *by design* (the reference's per-page decrypt
  tracking and its hook muting), and they latch taote's actions, not the stub's state;
* no member caches a guest byte, key, shift or filter value: `grep` for `*_(key|shift|filter|count|state) = …
  mem().read/large u8 reads` returns nothing;
* the only `static` locals in the hot path are env-read-once switches (`claim_ledger`, `incumbent_rule`), which
  are configuration, not guest state.

So (a) is closed as an audit with no finding - the cheapest possible outcome, and worth recording so it is not
re-audited blind.

#### 0.17fh Round 159: with VirtualProtectEx the anti-tamper gate PASSES - the ladder now re-installs its SEH frame and re-encrypts

Probing forward from the CRC salt (0x4189de) with the code reconstructed from the write trace gives the gate
and its outcome:

    4189de  xor  [ebp+0x1b5f],eax     ; salt the block CRC
    4189e4  push 0xc ; pop ecx        ; 12 slots
    4189e7  lea  esi,[ebp+0x3c3]      ; the payload-IAT slot table
    4189f0  lods eax,[esi] ; test eax,eax
    4189f3  je   0x4189fa             ; ANY ZERO SLOT -> the exit path
    4189f5  loop 0x4189f0
    4189f7  stc ; jb 0x418a02         ; all 12 resolved -> carry on

**`0x4189fa` (the exit path) fires ZERO times and `0x418a1c` fires**, i.e. the anti-tamper import check now
passes - that is the direct consequence of implementing `VirtualProtectEx` (0.17ff) and it is the first time
this gate has been cleared.

The ladder then continues, measured step by step:

* `0x418a1c` - `xor BYTE [ebx],0xcc` over 0x40 bytes at `ebp+0x1ce1` (a keyed decrypt), then
  `cmp BYTE [eax],0`; `0x418a5b` fires, so the decrypt produced the expected zero and the branch was taken;
* `0x418a5b` - `mov edi,eax ; not eax ; shr eax,cl ; rep stosd` (a fill of the destination region), then
  `call $+5`-style self-relocation;
* `0x418a85`-`0x418a8e` - `push fs:[0] ; mov fs:[eax],esp` : **the stub installs a NEW SEH frame** after the
  CRC/anti-tamper stage, and `jmp 0x418aa1`;
* the run now ends cleanly **at 0x418aa1** (no `error=` line, `TAOTE_LASTPC` tail `… 0x418a88 0x418a8b
  0x418a8e 0x418aa1`), where the live bytes are `66 f7 f3 | 0f 85 5b 01 00 00` = `not bx ; jnz 0x418c05`
  (`bx=0`, so the jump would be taken) - i.e. taote stops one instruction short of the branch.

So the family has moved from "parks after the resolver" to "passes the import gate, the CRC and the keyed
decrypt, re-installs its SEH frame, and stops at the next branch". The next question is narrow: why the run
ends at 0x418aa1 with no fault and no timeout - whether the emulation budget/count is exhausted there (the
summary reports `stages=1`) or a stop was requested, and what `0x418c05` does. Note the live byte stream there
differs by one byte from the write-trace reconstruction (`33 66 f7 f3 …` vs `66 f7 f3 …`), so this region is
being rewritten as it runs and only live reads count.

#### 0.17fi Round 160: the run ends on int 8 (#DF) after a #UD dispatch - not on a timeout and not on the stale-retarget guard

0.17fh asked why telock_7z.exe stops at 0x418aa1 with no `error=` line. `TAOTE_SEHDBG` answers it in one line:

    [sehd] code=c000001d fault=4186a8 pc=4186a8 chain=121ffb8 next=0 handler=41868a   <- #UD dispatched
    [intr] intno=0x8 pc=0x418aa1 esi=0x10011101 ...                                    <- #DF arrives
    [unpack] telock_7z.exe ... oep=0x418037 stages=1 imports=2                          <- clean end

and the whole run takes **0.3 s**, so nothing is exhausted: unicorn delivers `intno 8` = **#DF** at 0x418aa1,
which is not in taote's hardware-interrupt table (that table covers 0, 1, 3, 5, 6, 13, 14, 17), so the
exception is ignored and emulation ends.

The obvious suspect - the `seh_retarget_ != 0` guard in `seh_on_interrupt` that dropped TELock's `div ebx` in
round 133 - was checked with a gated print inside the guard: **it does not fire**. `seh_retarget_` is zero at
that moment, so the guard is not involved.

So the question is what unicorn escalates *from*: a #DF means a fault occurred while another exception was
being delivered, i.e. inside the `#UD` handler path at 0x41868a (dispatched for the 0xc000001d at 0x4186a8).
The next measurement is that handler's continuation - probe 0x41868a forward and read the instruction stream
it returns into, including whether the CONTEXT it loads points somewhere taote cannot map.

#### 0.17fj Round 161: the stopping instruction is an INVALID OPCODE (`66 f7 f3`), and unicorn escalates it to #DF instead of #UD

`TAOTE_LASTPC=80` on telock_7z.exe gives the exact tail:

    0x418a64 (rep stosd, many) 0x418a66 0x418a6c 0x418a72 0x418a78 0x418a7b 0x418a7c 0x418a82
    0x418a85 0x418a86 0x418a88 0x418a8b 0x418a8e 0x418aa1 0x418aa1   (then the run ends)

and the live bytes at 0x418aa1 are `66 f7 f3 | 0f 85 5b 01 00 00`. Decoding that:

* `66 f7 f3` would be `not bx`, but `f7` is group 3 and its modrm `f3` encodes **reg = 6 (`/6`)**, which is
  undefined - so the instruction is an **invalid opcode**, i.e. a deliberate #UD;
* `0f 85 5b 01 00 00` = `jnz 0x418c05` and is where the obfuscation would continue.

Neither `0x418aa4` (the next instruction) nor `0x418c05` (the branch target) ever executes, and the ring shows
**0x418aa1 twice** - the instruction faults, the exception is delivered, and the pc comes back to it.

So this is TELock's own anti-debug probe: an invalid opcode behind the SEH frame it re-installed at 0x418a8e,
which a debugger's or a wrong handler's continuation is supposed to step over. taote *does* deliver #UD
elsewhere in this same run (`[sehd] code=c000001d fault=4186a8 handler=41868a`), so the dispatcher works - but
at 0x418aa1 unicorn reports `intno 0x8` (#DF) directly and taote ignores it because 8 is not in its
hardware-interrupt table.

Also checked and excluded this round: the #UD handler at 0x41868a is inline-`int 0x20` obfuscated
(`8b 64 24 08 / eb 01 / eb eb / ... / 74 02 cd 20 / ... / eb 02 cd 20 / ...`), and **neither int-0x20 site
(0x418697, 0x41869e) executes** - the handler takes the skip paths, so the #DF is not caused by an unhandled
`int 0x20`.

The next question is therefore precise: why does unicorn escalate this invalid opcode to `intno 8` when it
delivers the earlier 0xc000001d normally - whether the SEH frame the stub just installed makes taote's
interrupt hook re-enter while an exception is in flight (there is a `seh_retarget_` hand-off between them), or
whether the #UD arrives while a previous delivery is still staged. The fix will be in taote's #UD/#DF path, not
in the ladder.

#### 0.17fk Round 162: the round-154 guard is load-bearing - disabling it drops the ladder back to the sentinel abort

A/B on the #DF question (0.17fj): with the walk-outstanding guard's condition forced false (i.e. the old
behaviour restored), telock_7z.exe reverts **exactly** to the pre-guard state - `TAOTE_LASTPC` ends
`… 0x418111 0x418160 0x70000000` and the summary carries
`error=emulation error: Invalid memory read (UC_ERR_READ_UNMAPPED)` again - instead of running on to the
resolver, the CRC, the keyed decrypt and 0x418aa1.

So the guard is **load-bearing** for TELock's progress, not the cause of the #DF: with it in place the ladder
clears four stages it never reached before, and the #DF at 0x418aa1 happens *downstream* of a path the guard
made possible. The A/B was reverted; the tree is unchanged.

That leaves the #DF question exactly where 0.17fj put it, with one suspect removed: it is not the sentinel
guard. The remaining candidates are (i) unicorn's own escalation of the invalid opcode at 0x418aa1 because the
stub's freshly installed SEH frame at 0x418a8e changed the guest state the interrupt path reads, and (ii) the
`seh_retarget_`/context hand-off between the #UD dispatch and the re-entry. Both are testable with the
existing `TAOTE_SEHDBG` `[intr]`/`[sehd]` lines plus one gated print in taote's #UD arm.

#### 0.17fl Round 163: unicorn escalates an invalid opcode to #DF - dispatch it as the #UD the guest expects

`TAOTE_SEHDBG` on telock_7z.exe lists **every** interrupt the run delivers: `intno 1`, `intno 3`, `intno 0`
(#DE), then `intno 8` at 0x418aa1. **No `intno 6` is ever delivered in the whole run**, even though the stub
executes `66 f7 f3` there - group 3 with `reg = /6`, an undefined encoding, i.e. a deliberate #UD behind the SEH
frame it installed at 0x418a8e. Unicorn escalates the undecodable instruction straight to a double fault; taote
ignores `intno 8` (not in its hardware table) and the run ends 0.3 s in.

Change: in `seh_on_interrupt`, an `intno 8` is dispatched as the #UD (`intno 6`, NT `0xC000001D`) the guest's
own handler expects - but **only when the faulting pc is mapped and readable**, i.e. the fetch succeeded and the
*decode* failed. A genuine double fault escalated from a memory fault has no decodable pc and keeps the old
behaviour, so the remap cannot swallow real faults.

Measured:
* `telock_7z.exe` now walks **past** the probe: the pc ring continues `0x418ab6 0x418aba 0x418ac0 0x418ad4
  0x418ad5 0x418adc 0x418ae0 0x418ae1`, and `[intr] intno=0x6 pc=0x418aa1` appears where before there was only
  the escalation;
* serial suite **602/602**;
* TELock arm (116 rows): 116 valid PE, 1 OEP, 0 imports, 0 all-three - unchanged, i.e. the ladder gets further
  on the sample but no row flips yet;
* **corpus r80**: 2676 / 2122 / 2083 / 1997 against r79's 2676 / 2122 / 2082 / 1996. The single row difference is
  `winupack_Bginfo.exe` - the row that failed at the 85 s wall in r79 and completes at 85 s here - so it is the
  known flake landing, **0 real gains, 0 real losses**.

Kept because it removes a hard stop on a path the ladder reaches only after four measured stages, and because
"an invalid opcode must reach the guest as #UD" is a fidelity statement, not a heuristic.

#### 0.17fm Round 164: TELock's ladder now reaches real payload API calls (CreateFileA / ReadFile / CloseHandle)

Continuing the forward trace from 0x418ae1 with the round-163 #UD hand-off in place, three things are measured.

1. The #UD at 0x418aa1 is now dispatched to the frame the stub installed at 0x418a8e, and that handler is a
   **lazy frame restore**: `[sehd] … handler=418a90`, and 0x418a90 is `mov esp,[esp+8] ; mov ebp,[esp+8] ;
   lea eax,[ebp+0xa31] ; push eax ; ret`, i.e. it pops a saved frame and returns to `ebp+0xa31` = 0x418ab0 -
   which is exactly where the pc ring resumes (0x418ab6, 0x418aba, 0x418ac0, 0x418ad4 …).
2. The guest then executes through 0x418ae1 and the run **ends cleanly in 0.2 s** - no `error=`, no further
   `[intr]`, so it is not a fault and not a budget.
3. `TAOTE_APIDBG=1` shows what it did just before stopping:

       [api] kernel32.dll!CreateFileA pc=0x100110c0
       [api] kernel32.dll!ReadFile    pc=0x10011ae0
       [api] kernel32.dll!CloseHandle pc=0x10011050

That is **new territory for this family**: earlier rounds never got past the stub's own resolver, and the last
API-driven state anyone measured was the message-box/first-call stage. The stub is now performing real file I/O
through the payload's IAT slots - i.e. the thirteen resolved imports are being *used*, not just written.

The next question is narrow: why it stops after `CloseHandle`, and the answer is in the call arguments and
returns, not in the ladder. The candidate is the classic self-read check (the stub opens its own image and
verifies bytes/CRC); the block CRC at 0x4189de was computed over `[esi..esi+0x400)` with `esi=0x418008` and salted
into `[ebp+0x1b5f]`, so the stub has its own integrity bookkeeping to compare against whatever it reads back.
The measurement to take: log `lpFileName`, the file handle, `ReadFile`'s bytes and `lpNumberOfBytesRead` for
these three calls, and compare the bytes read with the image bytes the CRC covered.

#### 0.17fn Round 165: the stub re-reads its own file over its own code, then jumps into that region - and that is where the run ends

`TAOTE_APIDBG` now prints the call arguments (a gated addition to the existing debug line), which names the
endgame exactly:

    [api] kernel32.dll!CreateFileA  args=00418000 80000000 ... p0=0x418000 'C:/Windows\telock_7z.exe'
    [api]   ReadFile   args=a000000e 00418008 00000400 00418000
    [api]   CloseHandle args=a000000e ...

So the stub opens **its own image**, reads **0x400 bytes to 0x418008** and closes it. Those 0x400 bytes are
exactly the region the block CRC covered (`esi=0x418008`, `ebx=0x400`, salted into `[ebp+0x1b5f]`) - this is
TELock's self-read integrity/anti-dump step, and 0x418008..0x418407 **contains the code that is running**.

The pc ring's tail after those calls is `0x418ab6 0x418aba 0x418ac0 0x418ad4 0x418ad5 0x418adc 0x418ae0
0x418ae1`, and then the run ends - and 0x418ae1's live bytes are `eb 01` (`jmp +1`, target 0x418ae4), while the
window showed `eb f8` (`jmp -8`, target 0x418ade) at 0x418ae4. **Neither 0x418ae4 nor 0x418ade ever executes**
(probes: 0 hits each), so the transfer itself is where it dies - consistent with the region having been
rewritten by the `ReadFile` immediately before.

That is the next measurement, and it is a live-bytes question in one run: with `TAOTE_APIDBG=1` (so the API
order is visible) read the bytes at 0x418ae4 and 0x418ade *after* the ReadFile completes, and compare them with
what the decrypted ladder had there. If the stub expects to decrypt what it just re-read (which is the standard
anti-dump shape: read the packed bytes back, decrypt in place, continue), then the missing piece is that
decrypt - not a mapping or SEH problem.

#### 0.17fo Round 166: the endgame is TELock's SINGLE-STEP loop (`or [esp],0x100 ; popf`) - and no #DB is delivered there

Probing 0x418ad5 (which executes just before the end) decodes the loop the stub enters after its self-read:

    418ad5  81 0c 24 00 01 00 00   or   DWORD PTR [esp],0x100   ; set TF (trap flag)
    418adc  75 02                  jne  0x418ae0
    418ade  cd 20                  int  0x20                  ; jump fodder, never taken
    418ae0  9d                     popf                        ; load the flags - TF is now ON
    418ae1  eb 01                  jmp  0x418ae4
    418ae4  eb f8                  jmp  0x418ade                ; back into the obfuscated pair
    418ae6  0f 83 1a 01 00 00      jae  ...

So the stub arms the **trap flag** and then runs a two-instruction jump pair: with TF on, every instruction must
raise a single-step `#DB` (NT 0x80000004), which its own SEH frame - the one it installed at 0x418a8e - handles.
That is TELock's anti-debug single-stepping and it explains why the earlier rounds saw `intno 1` twice at
0x419a5d in this same run.

At 0x418ae1, however, **no `intno 1` is delivered at all**: `TAOTE_SEHDBG`'s interrupt list ends at
`intno=0x6 pc=0x418aa1`, the pc ring stops on 0x418ae1, and the run ends cleanly in 0.2 s. The stub's single-step
loop therefore never gets its trap.

That makes the next question concrete and it is a taote-side one: when taote dispatches a #DB it **clears TF in
the live EFLAGS** (so the trap is not re-raised immediately - a sensible rule for the dispatch), and the profile's
`popf` must set TF again for the guest's loop to work. Two things are worth measuring in one run: whether the
guest's `popf` at 0x418ae0 actually sets TF in taote's EFLAGS image, and whether unicorn then raises the
single-step trap for the next instruction. If the `popf` result is discarded or TF is masked, the fix belongs in
the interrupt/flags path - and it would be the first mechanism in this family that is not about decoding at all.

#### 0.17fp Round 167: TF is set (eflags=0x146 at 0x418ae1) and unicorn never raises the single-step trap

The probe now prints `eflags` (a two-line gated addition), which settles the round-166 question in one read:

    [probe] pc=0x418ae1 ... esp=0x121ffd4 eflags=0x146

`0x146` = PF|ZF|**TF(0x100)**|bit1 - so the stub's `or dword [esp],0x100 ; popf` **does** arm the trap flag in
taote's EFLAGS image, and it is still set when the pc reaches the next instruction. The guest's single-step
loop is armed correctly.

And yet no `#DB` is ever delivered: `TAOTE_SEHDBG`'s interrupt list ends at `intno=0x6 pc=0x418aa1` and the run
stops on 0x418ae1. This same run *does* deliver `intno 1` twice earlier (0x419a5d), so taote's #DB path works
when unicorn raises it - the trap simply is not raised for an instruction executed after a guest `popf`.

So this is not a decode problem, not a mapping problem and not an SEH-disposition problem: **the emulator does
not emulate TF single-stepping from a guest `popf`**, and TELock's ladder is driven by exactly that. The fix is a
taote-side TF emulation: while `eflags & 0x100` is set, after each instruction raise the synthetic `#DB`
(NT 0x80000004) through the existing `seh_dispatch` path - i.e. a one-shot flag set when the code hook sees TF
and cleared by the dispatch, so the cost is only on the instructions that are actually being single-stepped.

That is the first mechanism in this family that is not about decoding, and it is the last thing between the
ladder and the payload: every stage before it is measured correct, the guest reaches real API calls
(`CreateFileA`/`ReadFile`/`CloseHandle` on its own image) and arms TF immediately afterwards.

#### 0.17fq Round 168: the TF emulation advances TELock but costs ten rows - measured, reverted

Implemented the 0.17fp mechanism: in the unpacker's existing per-instruction exec hook, read `eflags` and, when
TF (0x100) is set, raise the synthetic `#DB` through `seh_on_interrupt(1)` and end the slice so the run loop
applies the handler's retarget.

It works on the family it was written for:

* `[intr] intno=0x1 pc=0x418ae1` now appears (there was no #DB at all before);
* the ladder runs **past** the single-step loop into new code (`0x418ddc 0x418de7 0x418de9 0x418dec 0x418def`);
* the stub then performs the rest of its environment checks - `GetModuleFileNameA`, `CreateFileA`,
  `ReadFile`, `CloseHandle` and then **`CreateMutexA`** (the single-instance guard);
* suite 602/602 and throughput unaffected (upx_cmd 0.40 s, mpress_cmd 4.07 s vs 0/4 s before).

But the corpus says no: **r81 = 2676 / 2117 / 2075 / 1988** against r80's 2676 / 2122 / 2083 / 1997, i.e.
**1 gain, 10 losses** - NSPack 3, MPRESS 2, WinUpack 2, MEW 1, PECompact 1, UPX 1 (e.g. mew_Procmon,
mpress_ComIntRep, nspack_Sysmon, pecompact_ComIntRep, upx_adwcleaner). So it was **reverted**, tree clean, suite
602/602.

Why it loses: the trap is raised at the instruction *before* the one it should follow. On real x86 a TF set by
`popf` traps **after** the next instruction, with the saved pc pointing past it; my first version modelled that
(`tf_prev_`) but then the hook never fires, because unicorn aborts the run at that instruction instead of calling
the interrupt hook. Any guest that arms TF transiently (startup code, obfuscated stubs) therefore gets a spurious
#DB one instruction early and takes a different path.

The refinement, recorded for the next attempt: the trap must be raised after the instruction completes, which
means catching unicorn's internal #DB at the point the run ends (the run currently stops cleanly with no `[intr]`
line) rather than synthesising it from the code hook - or, cheaper, dispatching only for families whose stub
demonstrably single-steps (TELock), where the 1-gain/10-loss trade is replaced by a family-scoped measurement.

#### 0.17fr Round 169: the TF trap caught where the run ends - correct hardware timing, corpus-neutral

0.17fq's version failed because it synthesised the trap *before* the instruction; the faithful attempt never
fired. The reason turned out to be simple and is now measured: **the emulator already raises the trap itself and
returns from `uc_emu_start` cleanly** - which the run loop reads as "the program finished" (telock_7z.exe: pc
stops on 0x418ae1, no `error=`, no `[intr]`, 0.2 s). The guest's SEH frame never sees the #DB.

So the trap is delivered where it is actually observed - in `QlOsWindows::run`, on the clean-return path:

    if ((eflags & 0x100) != 0 && tf_traps < 4096) {
        ++tf_traps;
        if (seh_on_interrupt(1)) { apply_continue_context(); begin = seh_retarget_; seh_retarget_ = 0; continue; }
    }

with a 4096-trap cap so a guest that arms TF and never clears it cannot spin the loop. The saved pc at this
point is the instruction that has not run yet, which is exactly where the hardware raises the trap.

Measured:
* `[intr] intno=0x1 pc=0x418ae4` - the pc the *next* instruction, i.e. correct x86 timing (the 0.17fq version
  raised it at 0x418ae1, one instruction early, which is why it cost ten rows);
* the ladder continues past the single-step loop into 0x418ddc / 0x418de7 / 0x418de9 / 0x418dec / 0x418def;
* serial suite **602/602**;
* TELock arm: 116 valid PE, 1 OEP, 0 imports, 0 all-three (the family still has no row, but it no longer stops
  at the TF loop);
* **corpus r82**: 2676 / 2120 / 2079 / **1993** against r80's 2676 / 2122 / 2083 / 1997. All four row
  differences (bero_ComIntRep, bero_md5summer, expressor_ComIntRep, mpress_ComIntRep) ran at 85-86 s, i.e. at
  the harness wall; two were re-run solo and pass (bero_md5summer oep 0x49ec68 imports 862, expressor_ComIntRep
  oep 0x42800a imports 1597), so this is **0 real gains, 0 real losses**.

Kept: it is the correct hardware behaviour, its blast radius is "runs that would otherwise END with TF set"
(four wall rows, all of which still pass alone), and it is the mechanism TELock's ladder is driven by.

#### 0.17fs Round 170: ICEBP (`int1`, opcode 0xF1) has the same shape as the TF trap - deliver it on the clean-return path

Continuing from 0x418def, the run stopped on an instruction whose first live byte is **0xF1 = ICEBP (`int1`)**,
with no `[intr]` line - the same failure mode as the TF trap in 0.17fr: the emulator raises the trap itself and
returns cleanly, so the run loop thinks the program finished and the guest's SEH frame never sees the exception.

The clean-return path now checks the byte at the pc as well:

    bool icebp = (mem.read(pc, 1) == {0xf1});
    if (icebp && seh_on_interrupt(1) && tf_traps < 4096) { ++tf_traps; ...; continue; }

Measured on telock_7z.exe:
* `[intr] intno=0x1 pc=0x418def` now appears, and so does `intno=0x1 pc=0x418e2c` - the stub walks a **series** of
  ICEBP anti-debug probes, and each one now reaches its handler instead of ending the run;
* the ladder advances to 0x4192d6 / 0x4192dc / 0x4192e0 / 0x4192e1 / 0x4192e3, and the summary's `imports`
  grows 2 -> **3**;
* serial suite **602/602**;
* TELock arm: 116 valid PE, 1 OEP, 0 imports, 0 all-three (still no row);
* **corpus r83**: 2676 / 2122 / 2082 / 1996 against r82's 2676 / 2120 / 2079 / 1993 (3 "gains", all of them the
  r82 wall flakes returning) and against r80's 2676 / 2122 / 2083 / 1997 only one row differs -
  `mpress_ComIntRep`, which ran at the 85 s wall here and passes solo (oep 0x42800a, imports 683). So
  **0 real gains, 0 real losses** versus the clean baseline.

Kept for the same reason as the TF trap: it is what the hardware does, the blast radius is exactly "a run that
would otherwise end standing on an ICEBP", and TELock's anti-debug ladder is built out of these probes.

#### 0.17ft Round 171: the ladder ends calling 0x41802e - inside the region the stub re-read from its own file

Continuing from 0x4192e3. The probe at that pc gives `ebx=ecx=edx=esi=edi=0, eax=0, ebp=0x1220000,
esp=0x121fffc, eflags=0x2` (a fresh, clean frame - the stub has set up its own stack) and the live bytes are
`ff 54 24 e0` = **`call [esp-0x20]`**.

The slot it calls through is `0x121ffdc`, and `TAOTE_WATCH_ADDR=0x121ffdc:8` shows it is written with
`0x418007` and then repeatedly with **0x41802e** - so the call goes to **0x41802e**, inside the stub.

And `0x41802e` **never executes** (probe: 0 hits) and no fault is reported for it: the transfer itself is where
the run dies. The reason is visible in the earlier measurement: the stub's self-read -
`ReadFile(handle, 0x418008, 0x400, ...)` - covers `0x418008..0x418407`, and **0x41802e lies inside that range**.
So the stub re-read its own *packed* file over its own code and then called into that region, expecting it to be
re-decrypted before the call.

That is the next question, and it is well-posed: the stub must run a decrypt loop over the freshly read block
between the ReadFile and this call. Two possibilities, both testable with the existing tools:

* the decrypt loop runs but taote's `ReadFile` handed back bytes that differ from what the stub expects (compare
  the 0x400 bytes our `ReadFile` writes with the file's own bytes at that offset), or
* the decrypt loop never runs because a branch before it reads state taote got wrong (the CRC salt at
  `[ebp+0x1b5f]` is the obvious candidate - it is the value the stub compares the re-read block against).

#### 0.17fu Round 172: the call target is never written and never executed - and the watch cannot see that page

Two measurements narrow 0.17ft:

1. `TAOTE_WATCH_ADDR=0x41802e:3` records **no write at all** during the run: neither the stub's `ReadFile` nor
   its decryptor loop ever touches the address it later calls. (Caveat, recorded because it has bitten before:
   the write hook is *muted* for claimed sections, so a missing watch line is only evidence when the page is not
   muted - this needs one gated print of `muted_` before it is treated as conclusive.)
2. The decryptor loop at `0x418030` writes the page starting at **0x418041** upward (measured in earlier rounds),
   i.e. it does not cover 0x41802e either.

So the stub calls into a byte range that, under taote's emulation, holds neither freshly-read file bytes nor
decrypted code - and the call dies without a fault and without executing its target. That is consistent with the
region containing whatever the *packed* file has at that offset, which the stub expects to have replaced.

Next step, precise and cheap: read the live bytes at 0x41802e at call time (probe an executed pc whose 48-byte
window reaches it, or log `muted_` and re-run the watch with the page unmuted) and compare them with
(a) the packed file's bytes at the same RVA and (b) the decrypted code the earlier rounds saw at 0x418041+.
If they equal the file's bytes, the missing piece is the stub's own re-decrypt of the self-read block, and the
question becomes why its loop starts at 0x418041 instead of 0x418008.

#### 0.17fv Round 173: the call target holds DECOY code - so the stub probably thinks it is being debugged

Probing 0x418029 (which executes and whose 48-byte window covers the call target) shows what is actually at
0x41802e:

    418029  e8 02 00 00 00      call 0x418030
    41802e  e8 80 30 06 46      call 0x4658...      <- nonsense target
    418033  5a eb 01 e9 d4 09 49 7f  e9 67 e3 02 cd 20 ...
    418040  14 c9 d9 c9 c0 7c 39 03 8e 43 c1 75 ee b5 5f ...

That is **decoy code** - `e9 d4 09 49` jumps into nothing, `cd 20` is DOS-era filler, the bytes are not
meaningful x86. So the value the stub called through (`[0x121ffdc] = 0x41802e`) points into a decoy region, and
the run dies fetching it.

A decoy is what TELock does *when it believes it is being debugged*: the anti-debug traps it just walked - #UD at
0x418aa1, the TF single-step at 0x418ae4, the ICEBP series at 0x418def/0x418e2c - exist to detect a debugger, and
their outcome decides whether the stub proceeds to the payload or hands control to a decoy. taote delivers all
three traps to the guest handler now, so the *delivery* is right; the question is whether the **state the
handler reads** matches what Windows would leave.

The most likely mismatch, and the next thing to check: **DR6**. TELock's #BP arm explicitly arms Dr0-Dr3 and
masks Dr6 (measured earlier: `and dword [ecx+0x14],0xffff0ff0`, `mov dword [ecx+0x18],0x155`), i.e. it reads the
debug registers as part of its verdict. On real Windows a single-step trap leaves **DR6.BS (bit 14, 0x4000)** set
and an ICEBP leaves **DR6.BD (bit 13, 0x2000)** set. If taote leaves DR6 zero, the stub concludes "no debugger";
if our values differ from Windows in the other direction it concludes "debugger" and takes the decoy - which is
exactly the observed outcome.

Next measurement: log DR6 (and DR0-Dr3) at each trap dispatch, and compare with the Windows values above. If DR6
is zero, setting BS on the TF trap and BD on the ICEBP trap is a two-line fidelity fix whose acceptance test is
telock_7z.exe no longer calling through 0x41802e.

#### 0.17fw Round 174: correcting the DR6 idea, and a check the stub DOES make (API first byte != 0xCC) that taote passes

Two corrections to 0.17fv, both from reading what TELock's handler actually does rather than what a debugger
would.

1. **DR6 is not the discriminator.** The handler at 0x4180c5 runs `and dword [ecx+0x14],0xffff0ff0` then
   `mov dword [ecx+0x18],0x155`, i.e. it *sanitises* DR6 (clearing B0-B3 and bits 8-11) and normalises DR7 to the
   standard 0x155 - it strips the hardware-breakpoint state its own #BP arm just armed, instead of reading it as a
   verdict. taote's CONTEXT leaves Dr0-Dr7 zero (seh_build_context never writes them), which is already the
   "clean" state that sanitising produces. So setting DR6.BS/BD would be *less* like what this handler expects,
   and the fix I proposed last round is withdrawn before it was written.

2. **The stub does probe an API's first byte for a breakpoint, and taote passes it.** At 0x418a03 the ladder does

       418a03  lea esi,[ebp+0x3d3]   ; the CreateMutexA slot value
       418a09  mov esi,[esi]
       418a0b  lodsb                 ; the first byte of that API's code
       418a0c  add al,0x34
       418a0e  jne 0x418a1c          ; al+0x34 == 0  <=>  al == 0xCC

   i.e. "does the CreateMutexA implementation start with 0xCC?" - the classic software-breakpoint detection.
   taote's stub cells are `ret` (0xC3), so 0xC3+0x34 = 0xF7 != 0 and the ladder takes the *normal* path (0x418a1c,
   confirmed by that probe firing). So this anti-debug test passes and is not the reason for the decoy.

Where that leaves the decoy: the choice between the payload and 0x41802e is made somewhere after the ICEBP series
(0x418def / 0x418e2c), and the checks measured so far all pass. The next round should read the branch that
selects the decoy - probe forward from 0x418e2c through the cells that lead to 0x4192e3 and find the conditional
that decides `[0x121ffdc]`'s value (it is written with 0x418007 first and 0x41802e afterwards, so *something*
selects 0x41802e specifically).

#### 0.17fx Round 175: the "decoy" reading is not trustworthy either - and TELock gets parked here

Probing 0x418002 (an executed pc in the same page, earlier in the run) shows the page in its **pre-decryption**
state: `e8 02 00 00 00 e8 00 e8 00 00 00 00 5e 2b c9 58 74 02 cd 20 ...` - i.e. the same region whose bytes at
0x41802e I read as "decoy" (0.17fv) is *rewritten* during the run.

That invalidates 0.17fv's conclusion: **reading 0x41802e is not evidence of a decoy**, because the bytes there
depend on when they are read, and the only reads so far were at a time when the page was still encrypted. The
honest statement is the one from 0.17ft: the stub calls through `[0x121ffdc]` to a value the run writes there
(0x418007 first, then 0x41802e), the transfer never completes, and *why* is unresolved.

**TELock is parked here**, deliberately, after sixteen rounds. What is established (all measured, all in this
plan): the entire ladder up to the call - trap ladder, MZ scan, module check, sorted export walk, the 13-target
resolver (`VirtualProtectEx` was the missing API), the anti-tamper gate, CRC-32, keyed decrypt, SEH re-install,
the #UD/ICEBP/TF trap deliveries, the self-read via CreateFileA/ReadFile, CreateMutexA - and seven shipped
mechanisms that are individually correct. What is not established: the branch after the ICEBP series.

The way to reopen it is **not** another forward probe. It is the reference's own state at the same point: pegasus
decodes this sample end to end, so a diff of guest memory (the 0x418000 page and the stack slot) at the moment of
the call would say immediately whether our page holds stale/encrypted bytes where the reference holds code. That
is a multi-round comparison harness, not a one-round fix, and it should not be started without the budget for it.

Per the standing instruction to keep producing measured rows, the next work item is the recorded alternate
buckets: the 23-row picker bucket (valid PE, OEP wrong, imports already passing) and the 126-row imports-only
bucket. Both are enumerated in this plan with per-row evidence.

#### 0.17fy Round 176: the 23-row picker bucket, re-censused on r83 - and three rows whose truth is exactly rva 0x1000

The bucket (valid PE, OEP wrong, imports passing, code_sim >= 0.9) is 23 rows: Alienyze 4, Amber 4, JDPack 4,
PEtite 4, Neolite 3, WinUpack 3, PECompact 1. By the original's entry shape: **msvc-frame 10, crt-thunk 6,
borland 4, other 3**; by taote's reason: section_hop 17, ladder_scan 4, fallback_guess 2.

Two observations worth a measurement:

1. **Three rows have their truth at exactly rva 0x1000** - the first byte of the first section:
   `petite_PEview.exe` (truth 0x1000, claim 0x401005), `winupack_PEview.exe` (truth 0x1000, claim 0x41d5a7) and
   `jdpack_PEview.exe` (truth 0x1000, claim 0x4155f9). That is a *recurring* location, not a coincidence. (Note
   the tension with the reference's PEtite terminal fill, which treats a keep at exactly base+0x1000 as junk -
   0.17do - so a rule here must be gated by something stronger than "the payload section's start", or it will
   trade these three rows for PEtite's.)
2. **`petite_PEview.exe` is an off-by-5**: claim 0x401005, truth 0x401000 - the picker landed five bytes into
   the entry instead of on it, which is a different defect from a wrong candidate (the same section, the same
   code). Worth checking whether the ladder's candidate list contains the exact 0x401000 and a scoring rule
   dropped it, before inventing anything.

Neither is implemented: both need an arm measurement (PEtite 73 / WinUpack 97 / JDPack 100) plus the corpus, and
the first one must be checked against the existing PEtite junk rule before it is written.

#### 0.17fz Round 177: the no-hop fallback skipped a real entry whose rel32 contains a zero - +1 row (PEtite 29 -> 30)

`petite_PEview.exe` is the "off-by-5" row from 0.17fy: `oep=0x401005` against a truth of `0x401000`. The bucket's
candidate list was not the problem - the *fallback* was, and the debug line added here shows why:

    [unpack] guess scan sec=0x401000 span=0xf000 first8=e8d700000085c075

The decoded section starts `e8 d7 00 00 00 85 c0 75` - a textbook CRT entry (`call rel32 ; test eax,eax`, the
shape class added in round 134). But the fallback's "first run of >= 4 non-zero bytes" heuristic stops at the
**zero inside the rel32** (`e8 d7 00` is a 3-byte run), so it skipped the true entry and parked on 0x401005, the
next non-zero run.

Two fixes, both in the no-hop fallback:
1. the scan now reads the **artifact image** instead of live memory - by finalize time the exec-page overlay has
   the first-execution (decoded) view in `image`, while the live page may hold what the stub re-encrypted;
2. the **CRT entry shapes are tried before the loose heuristics**: `e8 <rel32> 6a ?? 68` and `e8 <rel32> 85 c0`
   (the same two classes round 134 added to `shape_at`), so a rel32 containing zero bytes no longer hides an
   entry.

Measured on the full corpus **r84**: valid PE 2676, OEP exact **2124**, imports 2082, all-three **1997** against
r83's 2676 / 2122 / 2082 / 1996 - PEtite **29 -> 30 all-three** (OEP 35 -> 36), one more MPRESS row than r83 (the
recurring `mpress_ComIntRep` flake) and `winupack_Bginfo` lost at the 85 s wall (it passes solo: oep 0x5b5d42,
imports 2002). So **+1 real gain, 0 real losses**, and the graded baseline moves 1998 -> **1999**.

Blast radius, recorded because it is large: 135 rows in r83 used `fallback_guess` (Yoda-Protector 88, Amber 13,
RLPack 10, Alienyze 8, NSPack 5, PEtite 3, TELock 3, WinUpack 2, ...), so this was measured on the corpus, not on
an arm.

#### 0.17ga Round 178: the other two 0x1000-truth rows are not picker bugs - their dumps hold a PE header / zeros at the truth

Checked the two remaining "truth = rva 0x1000" rows from 0.17fy. Neither is the same defect as petite_PEview
(which round 177 fixed in the fallback).

* `winupack_PEview.exe`: `hop ledger (1): 0x41d5a7@7213`, picked 0x41d5a7, run ends
  `error=emulation error: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)`. The decoded dump at rva **0x1000 holds
  `50 45 00 00` = "PE\0\0"** - a nested PE header sits exactly where the original's entry point is - and at the
  hop target 0x1d5a7 the dump holds `40 00 c7 45 0c 99 dd 40 00 e8`, ordinary code. So the artifact and the truth
  disagree about what lives at 0x1000, which is a *layout* question, not a candidate-scoring one.
* `jdpack_PEview.exe`: `hop ledger (1): 0x41502e@1`, picked 0x4155f9, run ends with the same fetch error. The dump
  at rva **0x1000 is all zeros**, and both hop targets hold ASCII strings (`IICONHTMLM`, `" StampChec"`) - i.e. the
  hops latched inside a data region.

So for these two the picker is being asked to choose between candidates that are not entries at all, and the truth
sits where our image has a PE header or zeros. Fixing them means understanding why the decoded image's first
section does not hold the original's code - the WinUpack one especially, since an embedded "PE\0\0" at the
original's entry point is exactly the shape of an un-dumped *inner* PE. That belongs with TELock's open question
(memory state versus the reference's), not with the picker.

Recorded so the next round does not spend itself on a candidate-scoring rule that cannot help either row. The
remaining picker work is `jdpack_7z.exe` (two startup-shaped frames differing only in the SEH handler they
install) and the Amber/Alienyze `crt-thunk`/`borland` clusters, all of which need a semantic discriminator rather
than a score.

#### 0.17gb Round 179: the 23-row "picker" bucket is really 2 picker rows and 21 DECODE rows

Triage that should have come before any scoring rule: for each bucket row, read 16 bytes at the *truth* entry RVA
from the original file and from our dumped artifact, and count how many match. (Bytes are read through each
file's own section table, so an image-style dump and a file-style original are both handled.)

    row                                        truth   match
    Alienyze/alienyze_EventLogChannelsView      e52e    1/16
    Alienyze/alienyze_InstalledPackagesView     d42a    0/16
    Alienyze/alienyze_LastActivityView          127f8   0/16
    Alienyze/alienyze_LoadOrd                   4e14    0/16
    Amber/amber_pipelist                        550b    0/16
    Amber/amber_pspasswd                        5be3    1/16
    Amber/amber_psshutdown                      677f    **16/16**
    Amber/amber_ru                              570c    1/16
    JDPack/jdpack_7z                            ebc5    **16/16**
    JDPack/jdpack_7za                           55641   1/16
    JDPack/jdpack_MxdwGc                        8e08    0/16
    JDPack/jdpack_PEview                        1000    6/16
    Neolite/neolite_Diskmon                     b4b8    0/16
    Neolite/neolite_Hasher                      82628   0/16
    Neolite/neolite_md5summer                   9ec68   1/16
    PECompact/pecompact_Everything              145f0d  1/16
    PEtite/petite_HDDScan                       483d20  0/16
    PEtite/petite_HashCalc                      11e58   0/16
    PEtite/petite_tinytask                      454c    0/16
    WinUpack/winupack_FastHash_kr               1dffa   0/16
    WinUpack/winupack_HashCalc                  11e58   0/16
    WinUpack/winupack_PEview                    1000    5/16

**Only two rows have the original's entry bytes in our artifact** (`amber_psshutdown` 16/16, `jdpack_7z` 16/16);
every other row has 0-6 of 16. So the "decoded but OEP wrong" bucket is **not** a picker problem at all for 21 of
its 23 rows: our dump does not contain the original's code at the original's entry address, and no amount of
candidate scoring can recover an entry whose bytes are not there. `code_sim >= 0.9` does not contradict this - it
is a whole-image similarity, and a payload can be 90% right while the entry page is a decoy/stale/relocated copy.

The same round also closed the Alienyze trio empirically: hoisting Pass E (the unique Borland
`6a <imm8> 68 <imm32> e8 <rel32>` entry) ahead of Pass C for the first-c3 family changed **nothing** on those
three rows, and scanning their dumps shows why - `.text` contains **zero** such candidates (the only ones in the
image are in `.rsrc` x3 and `.alien` x1). The truth prologue simply is not in the decoded text, which is the same
finding as the table above. That change was reverted (no effect, no reason to keep it).

**So the picker bucket is 2 rows**: `amber_psshutdown.exe` (truth bytes present, pick 0x40d869 vs truth 0x40c67e
earlier census) and `jdpack_7z.exe` (the two-startup-frame row needing a semantic discriminator). Everything else
in the bucket belongs to the decode/layout class - which is also TELock's open question - and should be worked as
"why is the entry page not the original's code", not as scoring.

#### 0.17gc Round 180: RETRACTING 0.17gb - the bucket triage was layout-blind, and the reference proves these rows are picker rows

0.17gb compared 16 bytes at the *original's* entry RVA between the original file and our artifact and concluded
that 21 of 23 rows were decode failures. **That conclusion is withdrawn.** The test was layout-blind, and the
reference run on the same row shows why:

    amber_pipelist.exe
      original file, rva 0x550b : e8 9b 86 00 00 e9 35 fe ff ff ...
      taote artifact, rva 0x550b: 7c 24 0c 8b c1 8b d1 03 c6 3b fe ...
      pegasus artifact, rva 0x550b: 7c 24 0c 8b c1 8b d1 03 c6 3b fe ...   <- IDENTICAL to ours

and **pegasus's artifact carries AddressOfEntryPoint = 0x550b, exactly the original's**. So the reference reaches
an exact OEP match on a row where the artifact's bytes at that RVA differ from the *not-packed file's* bytes -
i.e. the artifact is a relocated/rewritten image and "same bytes at the same RVA" is not the test for anything.

A layout-aware re-run of the triage gives the opposite headline: **21 of 23 rows contain the original's 16
entry bytes SOMEWHERE in the artifact** (only `petite_HDDScan` does not). So the payloads ARE decoded; the bucket
is a picker problem, as originally thought, and no reclassification of it is warranted.

What *is* worth recording from the round: `amber_pipelist`'s mismatch is small - we claim rva **0x534a**, the
truth is **0x550b**, 449 bytes apart, both inside `.text` - so the picker/ladder chose a neighbouring candidate
rather than missing the payload. The next measurement is therefore the original one, done properly: with
`TAOTE_UNPACK_DEBUG=1`, list the candidates the ladder ledgers for this row and find which rule prefers 0x534a
(shape score, last-c3, or the incumbent prior) over 0x550b - and check whether 0x550b is in the list at all.

#### 0.17gd Round 181: amber_pipelist - the truth address EXECUTES once and is never latched; the ledger A/B is worse

Following 0.17gc, three measurements on `amber_pipelist.exe` (we claim rva 0x534a, truth 0x550b):

1. **The hop ledger holds four entries and the truth is not among them**:
   `0x40dbab@188547 0x40534a@188549 0x4062f0@188549 0x404005@188560`. So this is not a picker choice between
   competing candidates - the picker never saw 0x40550b.
2. **Both addresses execute exactly once** (`TAOTE_PROBE=0x40550b` -> 1 hit, `TAOTE_PROBE=0x40534a` -> 1 hit).
   The guest does reach the true entry; the hop detector simply does not record it.
3. **`TAOTE_CLAIM_LEDGER=0` is not the answer**: it restores the ever-written behaviour and the ledger explodes to
   **470 candidates** (the reference's own reason for the claim ledger), after which the pick is 0x4092ff - four
   thousand bytes further from the truth than the current 0x534a. So the conservative ledger is right, and the
   question is narrower: why is this one execution inside a written section not treated as a hop when it happens.

The next probe is therefore on the hop path itself: log, for the single execution at 0x40550b, whether a claim
range covers it, whether that claim was already consumed (`written_ranges_` erase), and whether `dumped_addrs_`
already holds it - i.e. the three ways this code can decline. That is one gated print in the exec hook's claim
test, and it decides between "the claim for .text was consumed by an earlier hop" (then a consumed-claim re-latch
rule is the fix) and "the address is inside the *currently running* claim, so it is treated as the stub's own
code" (then the rule is about transfers between claims).

#### 0.17ge Round 182: the hop hook is per BASIC BLOCK - and the true entry is reached without one firing

The gated probe from 0.17gd (`TAOTE_HOPDBG=<addr>`, printing whether a claim covers the address, how many claims
are live and whether `dumped_addrs_` already holds it) **never printed for `amber_pipelist.exe` at 0x40550b**,
while `TAOTE_PROBE=0x40550b` reports exactly one execution. So the execution happens and the hop-detection
callback is never entered for it.

The reason is in the installation code (unpack.cpp:1015-1026): the section-hop hook is a **`ql.hook_block`**
(UC_HOOK_BLOCK, "per basic block, like the reference's bundled unicorn whose CODE hook fires once per block"),
registered over each section's range. A block hook fires when a *block* begins executing - so an address that is
executed *inside* an already-running block, or in a block whose translation is reused, is never seen. The truth
address here is reached that way: the stub does not branch to it, it falls into it.

That is a concrete, well-scoped defect and it explains a whole class of near-miss rows (transfers that are not
basic-block entries). The fix to measure next is a **claim-scoped per-instruction watch**: while a claim is live
(i.e. between the first write into a section and its hand-off), also hook UC_HOOK_CODE over that section's range,
and drop that hook at the hand-off - so the cost falls only on the window where a hand-off is expected, which is
exactly the budget argument the block hook was chosen for.

The probe itself (`TAOTE_HOPDBG`) was reverted with this round's working-tree change; it is two lines and should
come back with the fix so the A/B is measurable on the same row.

#### 0.17gf Round 183: a claim covers its WHOLE PAGE WINDOW - Amber's four bucket rows fixed

Round 182 established that the hop detector never *sees* `amber_pipelist`'s true entry `0x40550b` (the block hook
is never entered for it, while `TAOTE_PROBE` proves it executes exactly once). This round answers the next
question - *was it even claimed?* - with `TAOTE_UNPACK_DEBUG=1`, and the answer is no:

```
[unpack] claim .bss [0x405000,0x4053e8) write=0x405394 pc=0x4014a3
...
```
`.bss`'s claim ends at `0x4053e8`. The true entry is `0x40550b` - **0x123 bytes past the end of the claim, in the
same page**. The section's declared `vsize` understates the region the stub decrypts into it, which is the exact
lesson the ASPack work taught about clamping a decode window to its containing section: the *packed* section
bounds mean nothing once the payload is decoded.

The fix is three lines: a claim whose end came from the section itself is rounded up to the page boundary it lands
in (clamped to the image, and *not* applied when the hollow-predecessor cap deliberately ends a claim below the
stub's entry).

**Amber arm (152 rows): OEP 111 -> 115, +4 gains, 0 losses** - and the four gains are exactly the Amber
picker-bucket rows: `amber_pipelist.exe`, `amber_pspasswd.exe`, `amber_psshutdown.exe`, `amber_ru.exe`.

Two things were measured and *not* kept, so they are not re-proposed:

- the claim-scoped per-instruction watch designed in 0.17ge. Implemented in full (bound budget, armed at claim,
  dropped at hand-off) and it produced **exactly the same OEP** as page rounding alone on all runs - the
  fallthrough theory of 0.17ge was wrong; the truth *is* a block entry, it was simply outside every claim. The
  machinery was reverted rather than shipped inert.
- the page rounding is a family-agnostic change on a shared path (claims are used by every family), so it needs the
  full corpus, which is running as r85.

Corpus **r85** (2678 rows, 85 s budget, 4 workers, 22:01-23:13) closed it:

| | r84 | r85 |
|---|---|---|
| valid PE | 2676 | 2676 |
| OEP exact | 2124/2596 | **2127/2596** |
| imports | 2082 | **2083** |
| graded all-three | 1997 | **2002** |

Row diff: four GAINS (`amber_pipelist`, `amber_pspasswd`, `amber_psshutdown`, `amber_ru` - all four to exact OEP)
and one apparent LOSS, `mpress_geek.exe`. The loss is **not** this change: that row has sat at the 85 s wall
(dur=86) in r82, r83 and r84 as well, and a direct A/B - the parent commit built into a separate binary, three
runs each at the same 85 s budget - gives `oep=0x559760` for *both* builds, three times each. Its r84 truth is a
parallel-scheduling artifact. So the change is **+4 real graded rows, 0 real losses**.

#### 0.17gg Round 184: the Alienyze STORE-EP record - a checked-in reference mechanism taote never ported

The r85 picker-bucket re-census (19 rows, down from 23 after Amber) was re-triaged layout-aware: **17 of the 19
carry the original's 16 entry bytes at exactly the truth RVA in our artifact**, so they are picker rows, and the
Alienyze three are no exception (the 0.17gb "not in the decoded text" reading came from a scan of one debug dump,
not of the artifact).

`pegasus` gets these rows and has a mechanism taote never had - `src/unpacker/packers/alienyze_unpacker.cpp:90-115`:
Alienyze keeps the payload's **entry RVA as the first dword of `.alien`**, and the reference reads it (gated on the
current pick being junk: zero, a latch inside `.alien`, or the stub's own EP). Verified offline against the packed
files themselves before writing any code: **125 of the 126 Alienyze samples carry exactly their original
`AddressOfEntryPoint` there**; the only exception is `alienyze_tinytask.exe`, the arm's one invalid-PE row, which
holds zero.

It must be captured **before** the stub or our own body restore consumes the store - on the terminal artifacts
`.alien`'s first dword is already junk (`0x303e62d`, `0x3e3eea14`, `0x434264bb` on the three bucket rows), so it is
read in `transform_image` while the image is still packed and applied in `family_fill`.

One widening was needed and measured: the reference's junk gate keeps a *scan* pick, and taote's three bucket rows
are `reason=ladder_scan` with a pick outside `.alien` - so the fill also replaces a scan pick (`ladder_scan`,
`fallback_guess`) and leaves an **observed** `section_hop` pick alone (`PackerContext::reason`, threaded from
`finalize`).

**Alienyze arm (126 rows): OEP 108 -> 118, +10 gains, 0 losses**, all-four bucket rows won plus six more
(`DriverView`, `ESEDatabaseView`, `Everything`, `KillPot`, `ProduKey`, `disk2vhd`); ALL 75 -> 79.

Corpus **r86** (2678 rows, 23:38-00:51) confirms it, with the usual MPRESS wall noise:

| | r85 | r86 |
|---|---|---|
| valid PE | 2676 | 2676 |
| OEP exact | 2127/2596 | **2137/2596** |
| imports | 2083 | 2082 |
| graded all-three | 2002 | **2005** |

11 OEP gains / 1 loss, and the loss (`mpress_ComIntRep.exe`) plus one of the gains (`mpress_geek.exe`) are the known
flaky MPRESS wall pair - so the real movement is exactly the **10 Alienyze rows**.

Note what the +10 bought: only +4 all-three, because 6 of the 10 have failing imports. **Alienyze is now 125 valid
PE / 118 OEP / 79 imports** - 39 rows with a correct entry and a wrong import table, the second-largest import gap
in the corpus after RLPack (8/104). That is the next target: `pegasus` carries Alienyze import machinery taote has
never ported (`src/unpacker/alienyze.cpp`: the STATUS-237 decoy-class XOR name salvage with its hint16 guard,
`al-xormine`, and `idir_self_evidenced_` merging; `packers/alienyze_unpacker.cpp` also mines ordinal records from
the decoded image).

Also scoped for JDPack while r86 ran - taote lacks BOTH reference hop guards that JDPack joins:
- the **payload-internal traffic guard** (`unpacker.cpp:7006-7025`, UPX/NSPack/JDPack): a hop whose previous pc is
  already inside the range is the payload's own runtime writes re-claiming around the executing flow, not a transfer;
- the **import-quiet hop rejection** (`unpacker.cpp:8160-8180`, UPX/NSPack/Molebox/JDPack): a later hop with
  `imports < last_accepted_hop_imp + 32` is ignored, keeping the incumbent.
`imports_.size()` is available at hop time in taote, so the second is a direct port.


#### 0.17gh Round 185: Alienyze's import gap is ORDINALS - and the store is not where they live

The 39 Alienyze rows with a correct entry and a failing import table were diagnosed by diffing the grader's own
pairs against taote's meta: what is missing is almost entirely **original-side ordinals** -
`alienyze_Everything.exe` lacks shell32 `#16` plus 19 `ws2_32` ordinals, `HWMonitorPro_x32` lacks 27 `oleaut32`
ordinals, `Dbgview` lacks `ws2_32 #1,#11,#111,#115,...`. The rows are not shy of names (out = 1668 pairs against
292) and the criterion is recall-only, so `imp_precision` being 0.16 is irrelevant; the recall shortfall is the
ordinal set.

Two mechanisms were implemented and **measured, then reverted** - do not rebuild either shape without new evidence:

1. An **ordinal arm over the store's INT arrays** (`0x8000xxxx` → `ordinal_<N>`, the reference's
   alienyze.cpp:1264-1290 shape, with its F44 fill-dword and zero-slot guards). On
   `alienyze_Everything.exe` it emitted **0** ordinals. The reason is measurable with one debug print: the
   descriptor run taote's `find_idt` latches has `oft`/`ft` pointing into the **name string stream** - its
   "slots" read as ASCII `0x57746547`, `0x6f646e69`, `0x72685477` - so it is a plausible-looking descriptor run
   inside string data, not a real IDT. There is nothing ordinal-shaped to read there.
2. A scan of the packed file and of the terminal artifact for ordinal-shaped dwords in `.alien`
   (`(v >> 16) == 0x8000`, ordinal < 0x1000): **0 hits in both**. The packed file does not carry the ordinal list.

The reference's own diagnostics show where its 293 pairs come from: with `SE_DEBUG_RECON=1`, `pegasus` prints
`[alienyze] IDT block not found` … `[recon] Alienyze: 0 slots, imports=293` - i.e. it also fails to find the store
IDT, and its import set (which contains `ws2_32.dll ordinal_23/19/111/116/9/52/11/1`) comes from the **payload's own
import directory in the restored image**, decoded by its `struct_form` branch where an INT slot with the `0x8000`
flag is an ordinal. That is the missing mechanism: find the descriptor run whose INT slots are in-image RVAs in the
*restored body*, and read names and ordinals from the INT rather than from the name stream.

Next step, in order: locate that descriptor run in the artifact image (the run must be rejected if its INT slots do
not resolve to name RVAs inside the image - the failure mode of attempt 1), mine `(dll, name)` and
`(dll, ordinal_<N>)`, and merge additively into `imports_out` (recall-only criterion, so extras are free).
Predicted ceiling on the arm: Alienyze 79 → ~110 import rows if the payload IDT is intact on those 39 samples.

Two more measurements point at the actual reference mechanism. A structural scan of the r86 artifact for descriptor
runs - 20-byte records whose `nm` resolves to a printable `.dll`-suffixed string *and* whose INT slot 0 looks like a
name RVA or an ordinal - finds **zero runs in the whole image**, so the payload's own import directory is not in our
artifact to be read. And pegasus's `addr_name` (alienyze.cpp:739-758) is the source of its ordinals: it builds an
**address -> export index** over the loaded modules (`build_addrres_index_`, `addr_index_`, `addrres_mods_`), looks
each resolved FT/IAT slot value up in it, and emits `ordinal_<N>` when the matched export has no name.

So the true mechanism is a *reverse* mapping: after the run, the stub has written resolved API addresses into the
payload's IAT, and the import set is recovered by resolving those addresses back to `(module, name | ordinal)`. The
prerequisite taote lacks is the **ordinal half of that index**: our stub surfaces are built from an API name table
(`qiling/unpack/api_db.inc`), so a resolved address maps to a name and the export's ordinal is unknown - the corpus
originals import by ordinal precisely because the packer resolved them that way. Next step therefore has two parts:
(1) record real export ordinals alongside the names in the stub surface (or a side table) so a reverse lookup can
answer `ordinal_<N>`; (2) reverse-map the payload IAT cells through it, additively.

#### 0.17gi Round 186: the ordinal gap is host data we do not have; the reference's two hop guards land +2 NSPack rows

**The Alienyze ordinal path is blocked, and by exactly what it says on the tin.** `pegasus` gets its ordinals from
`addr_name` -> `addr_index_`, which `build_addrres_index_` fills from the emulator's runtime modules' export tables
(`unpacker.cpp:13095+`, using `e.ordinal`). Those synthetic modules only carry REAL ordinals because
`loaders.cpp:693-717` asks `host_dll_name_ordinals(name_)` - which parses `C:\Windows\SysWOW64\<dll>.dll` under
`#ifdef _WIN32` and returns empty on this host. So the reference's ordinal answers here are *fabricated slots*, not
host truth. Taote's own equivalent sources are absent too: the mingw-w64 import libraries are name-only
(`nm libws2_32.a` shows `__imp__accept@12`, no ordinals) and the only `.def` files on the box
(`pegasus/third_party/tcc/lib/*.def`) list plain names with no `@ordinal`. Recording it as blocked, not as a
missing port: no evidence on this host maps `ws2_32`'s 116 ordinals to names.

**The two hop guards did port, and they pay.** `unpacker.cpp:7006-7025` (payload-internal traffic) and
`unpacker.cpp:8160-8180` (import-quiet landing) are now implemented for the same four families the reference gates
them to - UPX, NSPack, Molebox, JDPack: a hop whose PREVIOUS executed block was already inside the range is the
payload's own runtime writes re-claiming around the executing flow, and a later hop that arrives with
`imports < last_accepted_hop_imp + 32` does not displace the incumbent.

Measured on all four arms at once, because the gate spans four families:

| arm | before (r86) | after |
|---|---|---|
| JDPack (100) | 100 PE / 96 OEP / 99 imp / 95 all | **identical** |
| UPX (108) | 108 / 108 / 108 / 108 | **identical** |
| Molebox (93) | 93 / 92 / 92 / 92 | **identical** |
| NSPack (97) | 97 / 91 / 88 / 88 | 97 / 91 / **90 / 90** |

The only row movement anywhere is `nspack_ADInsight.exe` and `nspack_procexp.exe`, both imports False -> True with
an unchanged OEP - a landed-quiet hop was polluting the candidate ledger's import harvest. Corpus r87 is running.

Corpus **r87** (2678 rows, 01:18-02:31) graded **0 row differences** against r86: valid PE 2676, OEP 2137/2596,
imports 2082, all-three **2005** - the guards are fidelity-neutral at corpus scale, and the arm's two NSPack gains
did **not** materialise because both rows sit at the 85 s wall in every corpus run (`dur=85/86` in r86, r87 and the
arm alike; `nspack_procexp.exe` finished at 70 s in the quieter arm run and only then did its imports resolve).
Keep the port - it is the reference's behaviour, 0 losses - but the graded effect is arm-only.

**That exposed the real population to attack next.** 41 rows in r87 finish at the 83-86 s wall and **31 of them are
not all-three** (BeRoEXEPacker 5, MEW 5, MPRESS 5, RLPack 5, NSPack 4, ASPack 1, EXpressor 1, Eronana 1, ...). They
are not capability failures: sampled four of them solo with a 300 s budget and **all four complete** -
`bero_Bginfo` oep 0x5b5d42 imports 1957, `mew_diskext` 0x40480c / 299, `nspack_ADInsight` 0x434dac / 776,
`rlpack_adwcleaner_7.2.4.0` 0x5468ca / 464. So up to ~31 rows are throughput casualties, which makes per-row speed
the largest mapped prize left - the same ground as the round-13 "LEVER 2" dispatch restructure (174 ns/insn of
~190 ns/insn overhead). Next round should profile ONE of these rows for its instruction rate and hook cost rather
than starting the restructure blind, and must keep every other family's results identical.

Profiling one of them sharpened the diagnosis and changed the target. `bero_Bginfo.exe` at a **20 s** budget is
already at 27.2M block executions with pc inside the *payload* (`0x6ec175`), only 2 claims, `oep=0x404dec`
(`ladder_scan`) and **imports=2** - while the 300 s run reports imports **1957**. So these rows are not slow at
decoding: the entry is reached and the payload then runs, and the **import set grows with runtime** (2 -> 1957). The
harvest is runtime-driven, and the 85 s wall truncates it. The next round's question is therefore not "make the
emulator faster" but "is the import table recoverable STATICALLY from the artifact" - i.e. whether taote's
`iat/import_rebuilder.cpp` can reconstruct the same 1957 pairs from the decoded image without the payload having to
execute them. If it can, the wall population is fixed by a correctness change, not by a throughput restructure.

One debug run on `bero_Bginfo.exe` (120 s budget) localised the cost precisely, and it is **not** the import
harvest - the harvest is already static at finalize ("image import table harvest: 1 descriptors -> 894 imports",
"import-string scan: 1160 names", "salvage: 862 hits -> 856 slots", "blob repair: 908 pairs re-attributed
(2813 -> 1957)"). What the row is waiting for is the hand-off itself: `hop ledger (1): 0x5b5d42@11770764` - the
payload entry is latched only after ~**11.77M** executed instructions, and the run takes ~62 s to get there. That
is ~5 us per instruction of *hook* time, not emulation time, which points at the exec hook (a UC_HOOK_BLOCK over
every watched section) firing for the stub's own decode loop for the whole run.

So the next experiment is a **hook-mute after the hand-off**, the same doctrine the reference already applies to the
write hook ("one claim per section per run: the write hook is disabled on first fire"): once a section's claim has
been consumed by an accepted hop, drop that section's exec hook (or gate it on `hop_guarded || !have_hop_`). It is
cheap, testable on this exact row's solo wall time (62 s baseline), and must leave every grade identical - if it
does, the wall population is fixed by removing wasted work rather than by any change to what taote computes.

#### 0.17gj Round 187: the per-block hook dispatch copied a vector per callback - reuse the buffer

The wall-row diagnosis from 0.17gi was tested and corrected twice, both by measurement:

1. **Hook-mute after the hand-off** (drop a section's exec hook once its claim is consumed - the section can never
   re-hand-off because `claimed_` blocks a re-claim). Implemented and measured on `bero_Bginfo.exe`: **64.4 s and
   62.5 s against a 62-64 s baseline - no change**. Reverted. The reason is visible in the same debug log: that row
   latches its hop at the very END (`hop ledger (1): 0x5b5d42@11770764`), so there is no post-hand-off payload
   execution to save. A no-op rule is not worth its blast radius.
2. **The dispatcher's per-callback vector copy.** `QlCoreHooks::dispatch_trace` runs once per BASIC BLOCK and did
   `const auto hooks_list = it->second;` - a fresh `std::vector<std::shared_ptr<Hook>>` per callback, i.e. one heap
   allocation + free per block (the copy exists because a hook may remove itself; core_hooks.py's verbatim note).
   A reused `thread_local` buffer with `assign()` keeps the semantics (and the shared_ptr lifetime guarantee that
   makes an in-callback `remove()` safe) without the allocation.

Measured on `bero_Bginfo.exe` solo: **62-64 s -> 55-57 s**, and the hop-free control (`--no-hop`, 34 s) also drops
from **42.9 s -> 34.2 s**, so the win is in the dispatch path itself and not in the hop code. Grades unchanged on
that row (oep 0x5b5d42, imports 1957). Serial ctest 602/602. Corpus r88 is running to see how many of the 41
83-86 s rows convert.

Corpus **r88** (2678 rows, 03:03-04:10) - the dispatcher fix converts wall rows, which is exactly what it was for:

| | r87 | r88 |
|---|---|---|
| valid PE | 2676 | 2676 |
| OEP exact | 2137/2596 | **2138/2596** |
| imports | 2082 | **2086** |
| graded all-three | 2005 | **2010** |
| rows at the 83-86 s wall | 41 | **38** |

5 gains / 0 losses: `mew_procexp`, `mpress_ComIntRep` (dur 71, off the wall), `mpress_cpuz_x32`, `nspack_ADInsight`,
`nspack_procexp` (dur 81) - and one MOVE (`mpress_geek`, still imports-failing). Note `nspack_procexp` and
`nspack_ADInsight` are the two rows the round-186 hop guards had won on the quiet arm and lost to the wall: they are
now graded, which closes that loop as predicted.

Capability 2005 -> **2010/2678**. Next: the same dispatch path still pays a `std::map` lookup and a
`bound_check` per block; the remaining slowest row is 55 s solo against a 85 s wall, so a further ~25% would clear
the rest of the wall population.

Corpus **r89** is running with three further dispatch/hook changes, all measured on `bero_Bginfo.exe` first
(baseline 62-64 s -> 51 s, grades identical: oep 0x5b5d42, imports 1957):

1. **The other four dispatchers got the same scratch buffer** (`dispatch_mem`, `dispatch_intr`, `dispatch_addr`,
   `dispatch_insn_invalid`, `dispatch_insn`): 52 s -> 49.8 s.
2. **The exec hook is claim-scoped, not section-scoped.** It used to be a block hook over the whole section
   [start,end); the only place an exec can find a claim is inside the claim itself, so the hook is now installed
   over exactly `[claim_start, claim_end)` when the claim appears, and unregistered when the claim is consumed.
   Measured: 55 s -> 52 s, identical grades; and it is semantically identical because `on_section_exec` already
   required claim coverage.
3. **A section's WRITE hook is dropped the moment the section becomes terminal** - muted (the stub writing its own
   code) or claimed (the reference's own doctrine: "the write hook is disabled on first fire"; taote had kept it
   alive only to keep advancing that section's write ordinal, which the claim already stamps). Measured on that row:
   `writes=11771393` -> **`writes=2`**.

One measurement is left **unexplained and therefore recorded rather than acted on**: with everything above,
`bero_Bginfo` takes 51 s with hop detection and 34 s under `--no-hop`, even though the write hook now fires twice
and the exec hook fires fewer than 200k times (the debug counter prints every 200k and never printed). Emptying the
exec callback's body saves 0.7 s, so it is not the callback either. The remaining ~17 s must be something
`--no-hop` skips wholesale (the enable_hop block also installs the GPA sentinel, the api observer, the
invalid-instruction dispatcher and the dyn-map hooks) - bisected so far: the api observer (`TAOTE_NOPOLL`, 52 s) and
the invalid-insn hook (`TAOTE_NOINV`, 49.8 s) are NOT it. Next round should bisect the GPA sentinel and the dyn-map
code hooks the same way, and note that `perf` is unusable on this host (`kernel.perf_event_paranoid = 4`) and `gdb`
is not installed, so bisection by env-gated builds is the only profiler available.

**Corpus r89 (the scoped hooks) was a disaster and was reverted: -176 rows, 176 losses / 2 gains** (all-three fell
from 2010 to ~1834; ASPack OEP 93 -> 76, Neolite 89 -> 71, Molebox 92 -> 69, Packman 104 -> 81). Two of that
commit's three parts were responsible and are gone:

- **the claim-scoped exec hook**: restricting the block hook to `[claim_start, claim_end)` instead of the whole
  section is NOT semantics-preserving, because that hook does more than latch a hop - it also drives the
  executed-page overlay (`exec_page_seen_`) and the stager bookkeeping, so execs in the section outside the claim
  stopped feeding the artifact. Reverted to the section-wide hook.
- **the write-hook drop at mute/claim**: the write hook keeps advancing `last_write_seq_`, which the OEP picker
  reads (`unpack.cpp:2959`, `:3356`), so dropping it changed picks across every family. Reverted.

What was kept from the round is the part that is purely mechanical and was measured neutral-or-better on its own:
the **reused scratch buffer in all six dispatchers** (it does not change which hooks fire, only how their list is
iterated). Corpus r90 is running to confirm the revert restores r88 and to see whether the remaining dispatcher
speedup alone converts any of the 38 wall rows.

Corpus **r90** (2678 rows, 05:47-06:52) after the revert: **0 row differences against r88** - valid PE 2676, OEP
2138/2596, imports 2086/2676, all-three **2010** - with the wall population 38 -> **37**. So the six-dispatcher
scratch buffers are grade-neutral and buy one wall row; the round's honest tally is one small throughput win kept,
two hook-scoping "optimisations" measured at -176 rows and reverted.

The round's real lesson is now rule (ad): **a hook's scope is not free to change.** Both reverts looked
behaviour-preserving from the callback's own code and were not, because those callbacks carry side effects beyond
their name - the exec hook also feeds the executed-page overlay and the stager set, and the write hook also advances
the per-section write ordinal the OEP picker reads. Anyone touching hook registration must check every reader of the
side state, not just the callback's return value.

Still open and *not* to be re-attempted blind: `bero_Bginfo` needs ~51 s with hop detection against 34 s under
`--no-hop`, with both hooks removed from the hot path (write hook fires twice, exec hook under 200k times) and the
exec body worth 0.7 s. The remaining ~17 s is inside what the `enable_hop` block installs - next candidates to
bisect are the GPA sentinel and the dyn-map code hooks, using env-gated builds since `perf` is unusable here
(`kernel.perf_event_paranoid = 4`) and `gdb` is not installed.

#### 0.17gk Round 189: the per-block hook is inherently ~650 ns/fire - stop chasing throughput on it

The open measurement from 0.17gj is now explained, and it is not an inefficiency in taote's code:

- `TAOTE_UNPACK_DEBUG=1` on `bero_Bginfo.exe` (30 s budget) prints **45.6M exec-hook fires** - 1.5M/s, ~650 ns per
  fire. With a UC_HOOK_BLOCK covering a hot section, unicorn cannot chain translation blocks, so every block pays a
  C call; that is the 17 s difference against `--no-hop` (34 s vs 51 s), and the reference pays it too.
- The callback BODY is not the cost (empty-body A/B: 0.7 s of 55 s), the list copy is not the cost (single-hook fast
  path below: 51.2 s -> 50.1 s), and neither the api observer nor the invalid-instruction hook is (both bisected to
  no change).
- Narrowing the hook to the claim range DOES cut the fires, but that hook also feeds the executed-page overlay and
  the stager set, which is why it measured -176 corpus rows last round. There is no free version of this.

So the wall population is bounded by how many blocks the *stub* executes, and the only honest lever left is to run
fewer of them - not to make hook dispatch cheaper. Kept from the round: the single-hook fast path in
`dispatch_trace` (a local shared_ptr instead of the list copy when one hook is registered; still safe against an
in-callback remove). Corpus r91 validates it.

Corpus **r91** (2678 rows, 07:10-08:11): 2 row differences against r90, both the chronic MPRESS wall pair
(`mpress_cpuz_x32` lost its OEP at dur 86, `mpress_geek` gained imports at dur 85), so the fast path is
grade-neutral within wall noise: valid PE 2676, OEP 2137/2596, imports 2087/2676, all-three 2009 (r90 2010), wall rows
37 -> 36.

Throughput is now closed as a line of work: the per-block hook cannot be made cheap, and narrowing it costs rows.
The next item is capability again - the remaining picker bucket - plus the recorded RLPack import gap.

#### 0.17gl Round 190: RLPack is the biggest import cluster left (66 rows) - diagnosed, not yet solved

The r91 census puts the picker bucket at **16 rows** (JDPack 4, Neolite 4, PEtite 3, WinUpack 3, MPRESS 1,
PECompact 1), which is smaller than the RLPack import cluster: **66 RLPack rows have the correct OEP and a failing
import table** (39 with recall < 0.4), against a family that is 104 rows with only 8 import passes.

Diagnosis on `rlpack_ADExplorer.exe` (oep exact, recall 0.067, 34 pairs against the original's 314):

- the artifact's descriptor walk finds **14 descriptors with the right DLL names** (`kernel32.dll`, `NETAPI32.dll`,
  `RPCRT4.dll`, `VERSION.dll`, ...) but every `INT` is zero and the `FT` runs are short and interleaved with zeros -
  the slots hold **resolved stub addresses** (`0x10011950`, `0x10051000`, ...), not name RVAs;
- the reference's answer to exactly this is `addr_name`: reverse-map each slot through an address -> export index
  (round 185's finding). taote already HAS that machinery (`iat::SymbolMap` + `IatScanner`, built by the F52 block
  from every loaded module's guest export directory) - but on this row it holds only **452 symbols over 15 modules**
  and `scanner.coherent()` keeps **1** hit, because a rebuilt table's slots are scattered and the coherence rule
  wants runs;
- a descriptor-anchored variant was implemented and measured (walk each descriptor's FT, reverse-map through
  `SymbolMap`, emit `(descriptor dll, symbol name)`; the tables interleave zeros so a zero is a hole, not the
  terminator - the first version stopped after one slot). It resolved **71 slots**, but the later blob-repair stage
  dedups to **49** pairs and the grader's recall did not move (0.057 -> 0.057). Reverted: measured, not kept.
- The remaining question is why `SymbolMap` holds 452 exports when 14 DLLs are involved: either the stub modules'
  guest export directories are mostly name-poor, or most slots point at the *unbound import stubs* (`0x7fb000`,
  `0x4a4000` in the map list) which that map does not index. Next round must measure which, with a debug print of
  module base / export count / slot hits per module, before writing another resolution rule.

Picker-bucket note: `jdpack_7z.exe` is NOT a scoring problem - taote's hop ledger is **empty** and its run dies with
`UC_ERR_READ_UNMAPPED` at 0x4184d1 in the stub, while `pegasus` reports `oep_last_hop = 0x40ebc5` (**the truth**) via a
section hop. So JDPack's four bucket rows are a run-completion problem like TELock's, not a picker-rule problem.

#### 0.17gm Round 191: the module export map is fine - RLPack needs the reference's PROVENANCE-TAGGED import collection

The per-module measurement answers 0.17gl's open question, and it is **not** the symbol map. With
`TAOTE_SALVDBG2=1` the F52 harvest prints every module it indexes:

```
[salv2] mod ntdll.dll    base=0x10000000 exp_rva=0x2000 nfuncs=39  nnames=39
[salv2] mod kernel32.dll base=0x10010000 exp_rva=0x2000 nfuncs=248 nnames=248
[salv2] mod user32.dll   base=0x10080000 exp_rva=0x2000 nfuncs=71  nnames=71
[salv2] mod ucrtbase.dll base=0x10040000 exp_rva=0x2000 nfuncs=22  nnames=22
[salv2] mod netapi32.dll base=0x10050000 exp_rva=0x2000 nfuncs=1   nnames=1
```

Every module parses, every slot is named, and the export VAs land on a 16-byte grid
(`0x10010000 + 0x1000 + 0x10*i`), so a slot value like `0x10011950` IS slot 149 of kernel32 and does resolve. The 452
symbols are simply the whole surface those stub modules carry (39 + 248 + 71 + 22 + ...): no corruption, no missing
index.

What is actually missing is visible by diffing the family against the reference on the same row,
`rlpack_ADExplorer.exe` (oep exact in both):

| | imports |
|---|---|
| original | 314 |
| taote | **49** (recall 0.057) |
| pegasus | **226** |

and `pegasus` names them per dll (`NETAPI32.dll NetUserGetGroups`, `VERSION.dll GetFileVersionInfoSizeW`, ...). Its
`src/unpacker/packers/rlpack_unpacker.cpp` says how, in a mechanism taote has **no analogue of at all**
(`grep -rn "prov\|POST_LATCH"` over `qiling/unpack` finds nothing):

- **W4 provenance classification** - the stub's import-rebuild loop is the single call site the GPA hook sees for
  every real import, and it lives in the packed-EP section; the payload's own CRT late-init (the oleaut32 `Var*` set)
  calls from the payload image. Each import is tagged by its CALLER's section (`PROV_STUB_LOOP` vs the rest) so the
  real ones survive a **run-level POST_LATCH drop** that discards post-hand-off noise;
- plus a bootstrap-slot filter (`decode_only_ntdll_boot_slot`) that drops the stub's own ntdll bootstrap rows.

So the RLPack import residual is a *missing attribution model*, not a missing table. Next round: record the caller pc
with each resolved pair (taote already notes the pair at GPA/loader resolution, `unpack.cpp:524/549`), classify by the
caller's section exactly as W4 does, and drop post-hand-off pairs. Family arm first (104 rows), then the corpus -
predicted ceiling 49 -> ~226 pairs per row on RLPack, which is the 66-row cluster.

#### 0.17gn Round 192: RLPack's 66-row import cluster is NOT import-shaped - the payload never runs

Classification of the 66 RLPack rows that have an exact OEP and a failing import table (r91):

| property | measurement |
|---|---|
| code decoded | **62 of 66 at code_sim >= 0.99** (the other 4 at 0.5-0.9) |
| entry | exact by construction (the rows are filtered on `oep_exact`) |
| missing pairs | **87% by NAME, 13% ordinals** (10 rows: 2266 named vs 344 ordinal missing) |
| artifact holds the names? | **no** - of `rlpack_ADExplorer`'s 285 named imports only **19** appear anywhere in our artifact |
| artifact holds the IAT? | **no** - at the ORIGINAL's IAT RVAs (imp_rva 0x5e090) the artifact is **zeros** |
| where the stub DOES write resolved addresses | a guest heap buffer at 0x4a2fd5, ~8-16 slots only, and it is **gone by run end** (a `TAOTE_DUMPRANGE=0x4a0000-0x4a4000` snapshot at finalize is junk) |
| run behaviour | **8 API calls in the entire run** (1 LoadLibraryA, 2 GetProcAddress, 2 VirtualAlloc, 2 VirtualProtect), run ends in **5 s** with the last pcs inside heap code (0x4a24xx-0x4a27xx) and no error |
| reference comparison | same row, same OEP: taote 49 pairs, **pegasus 226 pairs** - and pegasus's artifact holds the SAME 19/285 names, so its 226 do not come from the dump either |

Conclusion: there is **no FSG-like or Alienyze-like store** in RLPack's decoded image - the import evidence is not in the
artifact at all. The names are not in the image, the payload's IAT is never filled, and the run makes 8 API calls and
stops inside the stub's heap-resident code. So the imports are short because **the payload never executes**, which is
the emulation-depth diagnosis of round 106, now localised: the stub decodes the payload, the ladder finds the true
entry statically (0x4149ec), and execution then wanders in the stub's heap buffer instead of transferring there.

That rules out the whole "import-shape" family of fixes for these 66 rows: no scanning, shift-vote, blob-repair or
ordinal rule can recover names that were never materialised. The one mechanism worth building is the reference's
**resume-at-payload-entry**: when the stub stops making progress after a validated decode, start the payload at the
picked OEP (fresh stack, SEH re-install) so it resolves its own imports and the ordinary harvest sees them. Gate it
to RLPack first (family arm, 104 rows), then measure the corpus. Probes used above (`TAOTE_IATPROBE`,
`TAOTE_DUMPRANGE`) were reverted with the round; both are ~10 lines and worth re-adding when the resume lands.

#### 0.17go Round 193: resume-at-payload-entry measured on RLPack - negative, reverted

The mechanism from 0.17gn was built and measured, and it is a **measured negative**:

- `Unpacker::resume_at_entry()`: after `ql->run()` returns, family-gated to RLPack, run the decode-only ladder on the
  LIVE image (install sees the still-packed image, so `static_oep_` is 0 there - measured: `static_oep=0x0`), then set
  `esp -= 4` with a zero return address and `set_arch_pc(entry)`, and call `ql->run()` again. It fires correctly:
  `[unpack] resume at payload entry 0x4149ec (imports=1)`.
- **RLPack arm (104 rows): 96 valid PE / 68 OEP / 7 imports / 6 all-three**, against the baseline's
  **104 / 73 / 8 / 7**. So it loses 8 valid-PE rows, 5 OEP rows and one graded row: the payload started at its entry
  with an EMPTY IAT, faulted immediately, and the second run left the artifact in a worse state than the stub's own
  end-of-run memory. Reverted in full (`unpack.cpp`, `unpack.hpp`, `taote.cpp`), tree clean, ctest 602/602.

Why it cannot work as a standalone step, measured: the stub resolves **only ~16 imports** (`TAOTE_IATSNAP`: the first
store of a stub-module address is `0x4a2fd5 <- 0x10011950`; a snapshot of 0x4a1000..0x4a5000 at that instant holds
**3** stub-module pointers and **no** import names - the buffer is being decrypted, not filled with names). So the
payload's import table is never built, and jumping to the payload without it just faults.

The honest state of the 66-row cluster: **RLPack needs the stub's import-rebuild loop traced** - the packer must know
all 314 imports to rebuild them, so the data exists in the packed file in some encoded form, and only the stub's own
decoder reaches it. That is TELock-class work (a multi-round forward trace of the stub), not an import extractor and
not a resume. Also verified this round: the pegasus per-fire `getenv` hoist (6d17602c) has **no counterpart** in
taote - there is no `getenv` inside `on_section_exec` or `on_section_write` (the only env read on that path is the
`claim_ledger` static bool, already cached), so there is nothing to hoist.

#### 0.17gp Round 194: RLPack's stub dies on a DERIVED name pointer - the trace start point

Tracing the RLPack stub stop (round 193's open question) with the two run-end probes plus `TAOTE_RUNDBG=1` gives the
death in three lines:

```
[rundbg] VirtualAlloc(hint=0x0 size=0xc2000 prot=0x40) -> 0x5001446
[rundbg] GetProcAddress(netapi32.dll!NetUserGetGroups) -> 0x10051000     <- RESOLVES
[rundbg] GetProcAddress(netapi32.dll!) -> 0x0                            <- name pointer 0x75730000
[rundbg] pc==0 after error 'emulation error: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)' esp=0x1220004
```

with `TAOTE_APIDBG` showing the second call's arguments as `10050000 75730000 004502e4 ...`: the module handle is
right (`0x10050000`, netapi32's stub module) but the NAME pointer is **0x75730000**, a derived value, not an in-image
RVA - so GetProcAddress reads nothing, returns 0, and the stub stores/jumps through it: pc=0, fetch fault, run over.
That is why the run ends after ~5 s with no `[intr]` line and no `error=` line in the normal summary (the fault
happens at address 0, which the SEH layer discards as a null dispatch).

So the stub IS resolving imports (the loop exists and works for one entry); what breaks is the *name pointer* it
computes for the second. That makes the next step concrete and bounded, not open-ended: trace where the stub computes
`0x75730000` - which register/memory it loads the name RVA from, and what our run holds there versus what the packed
store should hold. The name list itself is real: the first entry (`netapi32!NetUserGetGroups`) proves the stub's
import store decodes correctly at least at its head.

Also established this round (kept knowledge, no code): the heap region the stub executes in 0x4a2xxx is a **range
decoder** (objdump of a mid-run snapshot at fire 3000 shows `cmp eax,0x1000000 ; shr ebx,0xb ; shl ecx,0x4 ; add
ecx,esi ; lea edi,[edx+ecx*4]` - an LZMA-style range coder), so the 5 s is decompression, not a stall, and the region
is recycled (a run-end dump of it is junk, which is why `TAOTE_HEAPSNAP` snapshots mid-run).

Probes (`TAOTE_DUMPRANGE`, `TAOTE_HEAPSNAP`) reverted with the round; both ~15 lines.

#### 0.17gq Round 195: seed stub DLLs from the SDK export surface - RLPack's resolver stops dying

Tracing 0.17gp's garbage name pointer to its origin finished the diagnosis and produced the fix. The stub's own
resolver (decompressed into the heap at 0x4a2747) walks a module's `AddressOfNames` with a name/hash compare
(`cmp eax,[esp+0x28]`, `inc esi`, `cmp esi,[ebx+0x18]`) and returns `AddressOfNames[esi] + base`. When the name is
not in the table the walk runs off the end and `esi` lands on `NumberOfNames`, so `[edi+esi*4]` reads PAST the table:
that is where **0x75730000** came from - not a decode failure at all.

Why the name was missing: the stub DLLs are generated per run by `write_stub_dll`, which seeded a dll's export surface
from the sample's own imports UNION `ApiRegistry::names_for_dll` - the handlers taote IMPLEMENTS. For `netapi32.dll`
that is **1 name** (NetUserGetGroups) against **407** in the SDK table (`qiling/unpack/api_db.inc`). The stub asked
for its second import, the walk fell off the end, GetProcAddress got a garbage pointer, returned 0, and the stub
jumped to 0 -> `pc==0 ... UC_ERR_FETCH_UNMAPPED`, which is the "ends after 5 s with no error" of round 194.

The fix: new `qiling::unpack::api_names_for(dll)` (the reverse of the existing `api_owners`) and `write_stub_dll` now
seeds that surface too, behind an explicit `seed_sdk_surface` flag that only the unpack CLI's call sites pass (the
parity fixtures keep the old surface - seeding there broke `PegasusParity.DllEmulationRunsX86/X64`, which pin a
hand-authored DLL's exports). `tools/CMakeLists.txt` gains `qiling_unpack` for `parity_trace`, which now calls
`write_stub_dll`.

Measured, `rlpack_ADExplorer.exe`: `GetProcAddress(netapi32.dll!...)` stops failing, the run goes deep, and the row
goes **imports 49 -> 240** (original 314, pegasus 226) with its OEP moving from `ladder_passc` to a real
**`section_hop`**.

**RLPack arm (104 rows): valid PE 104 (unchanged) / OEP 73 -> 83 / imports 8 -> 13 / all-three 7 -> 12.**
Corpus r92 is running (this changes every run's rootfs, so it must be measured corpus-wide).

Corpus **r92** (2678 rows, 08:59-10:05) - the SDK-surface seeding pays corpus-wide, with no losses:

| | r91 | r92 |
|---|---|---|
| valid PE | 2676 | 2676 |
| OEP exact | 2137/2596 | **2148/2596** |
| imports | 2087/2676 | **2092/2676** |
| graded all-three | 2009 | **2014** |

5 gains / 0 losses, and 15 rows moved in total - the ten other moves are RLPack rows whose OEP or import set improved
without completing all three (e.g. `rlpack_Diskmon`, `rlpack_ESEDatabaseView`, `rlpack_FastHash_kr`,
`rlpack_HashCalc`, `rlpack_ShellView`... each going from `(True, False, False)` to `(True, True, False)`), so they are
the next slice of the same cluster: entries now exact, imports still short. RLPack as a family in r92: 104 rows / 100% valid PE / **81% OEP** / **13% imports** / **12% all-three** (the
104-row ARM measured 83 OEP / 13 imports / 12 all-three; the corpus runs 4-wide and is the authoritative number).


#### 0.17gr Round 196: the RLPack residual asks the right questions but gets 149 NULLs back

Re-classifying the RLPack rows after 0.17gq (r92): 104 rows, 83 exact OEPs, and **71 of those still fail imports**
(55 at recall 0.5-0.95, 16 below 0.5). The pick reason splits **ladder_passc 40 / section_hop 31**, and only 11 of the
71 carry a run error at all (9 `UC_ERR_READ_UNMAPPED`, 4 `UC_ERR_FETCH_UNMAPPED`, 7 `no section hop; OEP guessed`), so
most of these rows run clean and still end short.

Tracing one (`rlpack_LastActivityView.exe`: exact OEP via **section_hop**, recall 0.416, 136 pairs against 255) gives
the whole shape in four measurements:

- the artifact holds **zero** nonzero slots at the ORIGINAL's IAT RVAs (imp_rva 0x175c4) and **none** of the 149
  missing names appears as ASCII anywhere in it - so nothing left to extract at finalize;
- the run makes **exactly 255 GetProcAddress calls** - one per original import - so the stub is asking the right
  questions;
- of those 255, the loader answers **ok=102, ordinal=4, and fail=149**: 149 resolutions come back NULL, and are
  answered by our minted sentinels instead;
- `note_import` is called 529 times for only **149 distinct (dll,name) pairs** (380 duplicates, i.e. the stub re-asks
  the same names), and the final set is 149 against the original's 255.

Both sides are under-covered per DLL: original user32 87 / msvcrt 48 / kernel32 69 against our 27 / 18 / 56.

So the next question is precise and bounded: **which 149 (dll, name) pairs get a NULL from the loader, and why** - the
module the stub asked in should carry that name now that the SDK surface is seeded. Instrument the failure branch of
the GetProcAddress hook to record `(dll, name, hmod)` for the NULL answers, look at the module's export table for a
sample, and check whether the stub is asking in the wrong module (its own resolver returns `AddressOfNames[esi]+base`
for the module it passed, so a wrong hmod would produce exactly this pattern).

And the failing calls have a *single* signature, measured with a 12-line probe on the NULL branch of the
GetProcAddress hook:

```
[gpanull] hmod=0x10080000 dll=msvcrt.dll name=MZ owners=
[gpanull] hmod=0x10080000 dll=msvcrt.dll name=MZ owners=
...
```

`name="MZ"` means `lpProcName` **is the module's own base address** (0x10080000): the stub's resolver computed
`AddressOfNames[esi] + base` with `AddressOfNames[esi] == 0`, so the name VA collapsed to the base and
GetProcAddress read "MZ" (the image signature) and correctly answered NULL. `owners=` is empty, which confirms the
string is not an API name at all.

So the whole remaining RLPack import shortfall funnels through **a zero entry in a stub module's AddressOfNames**:
the packer walks the table by index, and a zero RVA there resolves to the module base. The stub DLLs now carry the
SDK surface (measured on this row: `[salv] module exports: 14 modules, 11099 named, 0 ordinals, symbols=11101` - up
from 452 before 0.17gq), so the next step is to find WHICH module/index yields a zero name RVA. The prime suspect is
the LIEF export emission for a large name set (duplicate or empty names, or an entry dropped while the count stays),
which would be a `write_stub_dll` defect rather than a guest behaviour issue. Probe to add: after building a stub
dll, parse its own export table back and assert every AddressOfNames entry is non-zero, printing the offenders -
offline, before any emulation, so it costs one run per dll.

#### 0.17gs Round 197: the stub export tables are CLEAN - the bad entry is the guest's own 0x10000

The offline check specified in 0.17gr ran, using a new `TAOTE_KEEP_ROOTFS` switch that leaves the generated stub-dll
rootfs on disk (each run otherwise deletes it). Parsing every stub DLL's own export directory back:

| dll | nfuncs | nnames | zero name RVAs | duplicate name RVAs |
|---|---|---|---|---|
| kernel32 | 1905 | 1905 | **0** | 125 |
| user32 | 1099 | 1099 | **0** | 286 |
| advapi32 | 912 | 912 | **0** | 312 |
| oleaut32 | 426 | 426 | **0** | 251 |
| msvcrt | 66 | 66 | **0** | 0 |
| ntdll | 2353 | 2353 | **0** | 109 |

So the SDK-surface seeding is **sound at the file level**: every table is complete and has NO zero name RVA, which
kills the "LIEF dropped an entry" theory. (The duplicate name RVAs are harmless string sharing; worth remembering only
if a packer hashes name *strings*.)

The NULL answers are therefore generated by the guest, and one more probe on the failure branch pins it exactly: it
is **one call repeated in a loop**, not 149 distinct ones -

```
[gpanull] pc=0x10021550 hmod=0x10080000 nameptr=0x10090000 dll=msvcrt.dll name=MZ   (x14, identical)
```

`hmod` is msvcrt's base (0x10080000) but `nameptr` is 0x10090000 = **msvcrt's base + 0x10000**, i.e. the stub's
resolver added a name RVA of exactly **0x10000**. That value is the packer's own decision boundary: the resolver
compares the decoded dword against 0x10000 to choose the ORDINAL path (`jbe`) from the HASH path, so a stored value of
exactly 0x10000 takes the hash path and walks the module's name table looking for a name that hashes to 0x10000,
finds nothing, runs off the end and returns base+0x10000. GetProcAddress then reads "MZ" and answers NULL, and the
stub retries the same entry - which is why the run loops and why only 149 of 255 resolutions ever land.

Next probe, precise: find the caller of that resolver for this entry (the stub's store walk) and dump the store entry
it read - the value should decode to a small ordinal, and ours decodes to exactly 0x10000. That is a decode/data
question inside the packer's own algorithm, not an export-surface question, and it is the last mile for this cluster.

#### 0.17gt Round 198: the CRT family is ONE surface - msvcrt had no names at all (corpus 2014 -> 2018)

Chasing the round-197 `0x10000` led straight into the payload, and the payload's resolver is the payload's own
import-rebuild thunk, dumped live at the failing call:

```
43f87d: (decoded thunk)
43f891: xor  eax,0x80000000
43f896: cmp  eax,0x10000
43f89b: jbe  0x43f8b9        ; <= 0x10000 -> push the value itself as lpProcName (ORDINAL path)
43f89d: xor  eax,0x80000000  ; otherwise undo the flag: a name RVA
43f8a5: call 0x43f8ca        ; EAT walk: rol eax,7 / xor al,byte over each name, cmp to the pushed hash
43f8b9: push eax ; push [esi] ; call [ebp+0xc6d]   ; GetProcAddress(hmod, name)
```

So `nameptr=0x10090000` was `msvcrt_base + 0x10000`, the value the EAT walk returns when it runs off the end of
`AddressOfNames` - the packer looked for a name hash that our stub module does not export. Which name? Not recoverable
by hash alone (neither 0x96390321 nor 0x050c317a is in api_db's 32374 names), but the *reason* was structural:

**`api_db` contains no `msvcrt` rows at all.** The host SDK files the whole C runtime under `ucrt`, `ucrtbase` and
`crtdll`, so `api_names_for("msvcrt.dll")` returned only the 66 CRT handlers taote implements - and a packer that
resolves CRT imports the way the loader does (walking the module's own export names) found ~none of them.

Fix: `api_names_for` now treats the C runtime as one family (`crtdll`, `ucrt`, `ucrtbase`, `msvcrt`, `msvcr*`,
`api-ms-win-crt-*`), so a stub msvcrt carries the family's full surface (~2600 names). Family correctness is not a
heuristic: these dlls really do export the same names.

| measurement | before | after |
|---|---|---|
| rlpack_LastActivityView.exe imports | 149 | **175** (of 255), `[gpanull]` loop gone |
| RLPack arm (104) PE/OEP/IMP/ALL | 104/83/13/12 | **104/86/15/14** |
| corpus r93 PE/OEP/IMP/ALL | 2676/2148/2092/2014 | **2676/2154/2095/2018** |

Corpus row moves (rerun-corrected; the raw r93 had four ASPack rows at `dur=0` because a rebuild landed under the
running corpus, plus two 85 s+ wall flakes - both re-run and restored): **9 gains / 2 losses** -
+ amber_netcfg, bero_geek, mpress_cpuz_x32, nspack_Bginfo, packman_adwcleaner_7.2.4.0, rlpack_AccessEnum,
rlpack_calc, rlpack_geek (all gaining exact OEP) and rlpack_mtinst (all-three); - amber_mdbx_dump (its r92 "exact" came
from a shadow-base claim 0x500a847; taote now picks a low-base ladder answer 0x401661, 0x400 short of 0x1a67) and
winupack_Bginfo (86 s wall flake on imports).

Operational note for future corpus runs: **never rebuild while a corpus is running** - the exec of a half-written binary
shows up as `dur=0 rc=0` and silently costs rows. TAOTE_GPANULL now prints the failed GetProcAddress with the caller,
all registers and the 16 bytes at esi/edi/ebx/ebp.

#### 0.17gu Round 199: the .def export lists are measured-NEGATIVE (2 variants, -121 each); the census is the deliverable

The round-198 win (msvcrt had zero names) suggested a wider question: which of the corpus's original imports can our stub
surface not serve at all? New checked-in tool `tools/api_surface_census.py` (it reuses `unpack_report.parse_pe` so the
census and the grader can never disagree):

| dll | rows | pairs | unique missing | top missing (rows) |
|---|---|---|---|---|
| MSVCRT | 831 | 33562 | 63 | __set_app_type(817), __setusermatherr(759), __p__fmode(677) |
| KERNEL32 | 2595 | 202451 | 19 | InterlockedDecrement(771), InterlockedIncrement(756), InterlockedExchange(564) |
| LIBGIMP-2.0-0 | 123 | 2642 | 173 | gimp_main(123), gimp_install_procedure(123) |
| LIBGTK-WIN32-2.0-0 | 85 | 1650 | 208 | gtk_widget_destroy(82), gtk_widget_show(82) |
| ULIB / MSVCP60 / LIBGLIB / LIBINTL | 13-123 | up to 757 | 7-148 | third-party, mangled C++ |

The two first-party gaps are **generator artefacts, not missing data**: `InterlockedDecrement` exists in
`libkernel32.a` only as an `I __imp_` slot (mingw compiles it to an intrinsic, so there is no `T`), and `msvcrt` is in
gen_api_db.py's SKIP_SUBSTRINGS. The third-party rows (gimp/gtk/glib/intl/ULIB/msvcp) are unreachable by any SDK
database - drop them from any future "why is this import short" theory.

Fix attempted: teach the generator to union `.def` export lists (pegasus's bundled tcc `lib/*.def` - a real export
list, same provenance class as the import libraries). It added 602 clean names (the Interlocked*, ntdll's `__chkstk`,
`__isascii`, `_fltused`).

**Measured: it is a large loss, in both forms.**

| corpus | PE | OEP | imports | all-three |
|---|---|---|---|---|
| r93 (before) | 2676 | 2154 | 2095 | **2018** |
| r94 (def names in api_db) | 2676 | 2153 | 1976 | 1897 |
| r95 (def names as surface-only, api_owners untouched) | 2676 | 2153 | 1974 | 1897 |

122 losses against 3 gains; on the lost rows the emitted pair count is unchanged (`aspack_calc` 405 -> 405) while both
recall and precision fall (1.0/0.938 -> 0.911/0.854), i.e. pairs are re-attributed to the wrong DLL - so it is the
*surface* (the names a stub exports, which also feed the F52 symbol map) and not `api_owners` alone. Splitting the
blob so attribution never sees the def names (r95) changed **nothing**, which is what rules out the attribution theory.

Rule (ar): widening a stub dll's export surface is not free in either direction - it changes the symbol map, so
`api_names_for` is a precision lever as much as a recall one. And a .def file is NOT interchangeable with an import
library as "the DLL's real export list": tcc's defs carry CRT internals (`_fltused`, `__chkstk`) that no program
imports from a DLL, and seeding them costs 121 rows. Both changes were reverted (api_db.inc, api_db.cpp and
gen_api_db.py are back at fc9ffb9); capability stands at 2018/2678.

#### 0.17gv Round 200: the stub surface spelled names in the DLL's own case - 80 RLPack rows (corpus 2018 -> 2098)

The round-199 census left one first-party gap: gdi32 owns `createcompatiblebitmap` in api_db, yet `rlpack_puttytel_32`
still asked GetProcAddress for `base+0x10000` and got NULL. Reversing the hash the stub pushes into its EAT walk
(`rol eax,7 / xor al,byte` over each name) against the *original's* gdi32 imports gave exactly one answer:

    0x6b3470d5 -> CreateCompatibleBitmap

and the generated stub exported **`createcompatiblebitmap`**. `gen_api_db.py` lower-cased every name (a convenience
for case-insensitive lookups), so every SDK-seeded stub table spelled its exports in lower case - which no
case-sensitive name hash can ever match, and which GetProcAddress (also byte-exact) would not match either.

Two changes:

1. **api_db keeps the DLL's spelling.** The generator collects names from `nm` in their real case and keeps the
   spelling with the most upper-case letters when a name appears with several (`CreateCompatibleBitmap` beats
   `createcompatiblebitmap`, which is the mingw internal symbol). `api_db.cpp` now indexes rows by a lower-cased copy
   and hands `api_names_for` the real spelling; `api_owners`/`api_owner` still look up case-insensitively.
2. **The choice is a packer trait, not a global switch.** Seeding the real case changes what the *guest's* own walk
   finds, which is a behaviour change: applied to every family, the corpus went 2018 -> 2000 (Molebox -92, Themida 71
   rows hitting the 120 s wall) while imports rose. So `Packer::hashes_export_names()` says which families resolve
   imports by hashing export names, RLPack opts in (its resolver is the one we disassembled), and every other family
   still gets the byte-identical lower-case surface (`write_stub_dll(..., preserve_sdk_case)`).

| measurement | before | after |
|---|---|---|
| rlpack_puttytel_32.exe imports | 92 | **359** (of 295 - over-emitted, recall 1.0) |
| rlpack_LastActivityView.exe imports | 175 | 286 (of 255) |
| RLPack arm / corpus row | 86 OEP, 14 IMP, 13 ALL | **98% OEP, 90% IMP, 89% ALL** |
| corpus r97 PE/OEP/IMP/ALL | 2676/2154/2095/2018 | **2676/2169/2175/2098** |

Row moves: **80 gains, 0 losses** - every RLPack row that gained exact OEP through the round-195 SDK seeding now also
passes imports. (Three rows looked like losses at dur 86-87; re-run in place they pass, the usual wall flake.)

Rule (au): a stub export table is a data structure a packer *hashes*, so the spelling of every name is part of the
contract - `nm` gives the real case, so never normalise it away. Rule (av): a change that alters what the guest's own
export walk finds is family-sensitive; gate it with a `Packer` trait and measure the corpus, because the same change
that took RLPack from 13% to 89% took Molebox from 99% to 0%.

#### 0.17gw Round 201: only RLPack hashes export names - five candidate families measured, 0 gains

Round 200 left `Packer::hashes_export_names()` as a one-line opt-in, so the obvious question was who else wants it. New
dev switch `TAOTE_STUB_CASE=<fam,fam|all>` forces the case-aware surface for a family that does not declare the trait,
and one 529-row arm covered the five candidates (Alienyze 126, TELock 116, NSPack 97, WinUpack 97, Neolite 93):

| family | PE | OEP | IMP | all-three | vs r97 |
|---|---|---|---|---|---|
| Alienyze | 125 | 118 -> **81** | 79 -> **126** | 79 -> **76** | -3 |
| NSPack | 97 | 92 -> 92 | 91 -> 91 | 91 -> 91 | 0 |
| Neolite | 93 | 89 -> 89 | 93 -> 93 | 89 -> 89 | 0 |
| TELock | 116 | 1 -> 1 | 0 -> 0 | 0 -> 0 | 0 |
| WinUpack | 97 | 87 -> 87 | 82 -> 82 | 78 -> 78 | 0 |

So the trait stays RLPack-only: no other family in this corpus resolves imports by hashing export names, and the
case-aware surface is exactly neutral for four of them.

**Alienyze is the interesting negative**: with the case-aware surface every one of its 126 rows reaches an EXACT
import table (79 -> 126) while exact OEPs fall 118 -> 81, i.e. the two effects fight. The stub normally looks up
names, misses, and hops somewhere harmless; when the lookup SUCCEEDS it walks further and the section-hop latch fires
earlier/elsewhere - `alienyze_ADInsight` claims 0x3fcd8 against a truth of 0x34dac, `alienyze_Autologon` 0x8490
against 0x3980. Net -3 all-three, so it was not kept, but it says Alienyze's ceiling is the picker, not the imports:
126 import-exact rows are available for free if the pick under a name-resolving stub can be made right. Prime suspect
for the next round is the round-184 `AlienyzePacker` store-EP fill: it fires when the pick is 0, inside `.alien`, equal
to the packed EP, or the reason is ladder_scan/fallback_guess - a section_hop pick bypasses it, which is exactly the
shape the case-aware runs produce.

No capability change: 2098/2678 (r97). ctest 602/602.

#### 0.17gx Round 202: Alienyze's imports were free all along - the store EP outranks a bad hop (79 -> 118, corpus 2098 -> 2138)

Round 201's negative carried the lead: with the case-aware stub surface Alienyze reached **100% import-exact** (79 ->
126) while exact OEPs fell 118 -> 81. The two effects were fighting because the stub used to MISS its import lookups,
which kept the run on a harmless path; once it HITS them it walks further and the section-hop latch fires somewhere
wrong (`alienyze_ADInsight` claimed 0x3fcd8 against a truth of 0x34dac).

Offline data check first (rule h): the packer's own `.alien` store EP - the first dword of the `.alien` section, which
`AlienyzePacker::transform_image` already captures before the stub consumes it - equals the original's
AddressOfEntryPoint on **125 of 126** packed files (only `alienyze_tinytask`, the arm's one invalid-PE row, differs).

So round 184's gate ("replace only a junk or scanned pick; an observed section hop is left alone") was right for a
*blind* stub and wrong for a seeing one. Two family-local changes:

1. `AlienyzePacker::hashes_export_names() = true` (its stub compares name bytes when it walks AddressOfNames).
2. The store EP now outranks an observed hop too - the packer's own record of the payload entry beats a hop that the
   now-seeing stub took into the middle of its own restore.

| Alienyze arm (126) | r97 | now |
|---|---|---|
| valid PE | 125 | 125 |
| OEP exact | 118 | 118 |
| imports | 79 | **125** |
| all three | 79 | **118** |

Corpus r98: PE 2676, OEP 2169, imports 2222, all-three **2138** - **47 gains / 0 losses** (46 Alienyze + 1 WinUpack).
(The raw run read 2135 with three losses; all three sat at dur 86-87 and pass when re-run in place.)

Rule (aw): when a stub starts SEEING its imports, every downstream heuristic tuned against a blind stub has to be
re-examined - the packer's own static records (a store EP here) are a safer anchor than an observed hop, and the data
to decide it is almost always checkable offline over the whole family before a line of code is written.

#### 0.17gy Round 203: TELock is a stub-side divergence (reference is perfect); the RLPack residual is the 85 s budget

Two diagnoses, no code change; both are now precise enough to act on.

**TELock (116 rows, 1 OEP / 0 imports today).** The reference's log on `telock_7z.exe` is a clean success: five
`[insn-inv]` skips (`0x419a08 f1`, `0x4186a8 8d`, `0x418def f1`, `0x4196f1 8d`, `0x4197d9 f1`), three tolerated
`[null-pc] except=0xc0000005` exceptions, then `[oepfromtable] ~K3=0xebc5 -> oep=0x40ebc5` with `meta.imports=109` and
a `code_sim` of **1.0**. taote's run on the same file:

- ends on `0x4192e3` (`ff 54 24 e0`, `call [esp-0x20]`) with **no** error line - the transfer executes into the stub's
  farewell path, not the payload;
- the whole run makes seven API calls: `GetModuleFileNameA`, `CreateFileA` (its own
  `C:\Windows\telock_7z.exe`), `ReadFile` (0x400 bytes to 0x418008), `CloseHandle`, `CreateMutexA`, then
  `MessageBoxA(hwnd=0, text=0x419e91, caption=0x419dbc, uType=0x30)` and `ExitProcess(0)` with `ret=0x4192e7`;
- it takes the two synthetic-sentinel faults (`[fault] addr=0x70000000/0x70000001`) and **no null-pc fault at all**,
  so a `UC_MEM_FETCH_UNMAPPED`-into-SEH delivery cannot be the difference (a gated probe for exactly that was written,
  measured inert, and reverted);
- its artifact has the file's first 0x400 bytes byte-for-byte but a *transformed* `.text` at 0x1000 and 110592 bytes of
  image against the file's 55808 - i.e. the stub's own file check ran and its decode stopped part-way.

So TELock compresses whole: the stub reads its own file (TELock's file-based decode), then decides the image is not what
it expects. Next step is a memory diff at that decision: dump the stub's read buffer (0x418008, 0x400 bytes) and the
mapped image at 0x400000 at the `MessageBoxA` call, and diff both against the packed file.

**RLPack residual is budget, not code.** Only 10 of 104 rows still fail imports on r98, and the biggest -
`rlpack_ComIntRep.exe`, graded recall 0.047 - is fully recovered when the run is given room: with a 240 s budget it
emits 618 pairs against the original's 527, **recall 1.000** (precision 0.85, so `imports` passes and `imp_exact` does
not). `rlpack_Bginfo` (0.65) and `rlpack_HDWScan` (0.09) are the same shape at dur 86. So the family's real state is
~97% of rows solved; the 85 s corpus budget is what the remaining rows fail on, and it is not a code lever.

Rule (ax): before treating a low recall as a decode/attribution bug, re-run the row SOLO with a long budget - the
corpus's 85 s x 4 workers cuts rows whose stub is still rebuilding its import table, and a 0.05 recall can be a 1.00.

#### 0.17gz Round 204: TELock's stub is failing its own CRC check - and the file it checks is byte-identical

The round-203 handoff asked for a memory diff at the stub's decision point. New diagnostic does exactly that:
`TAOTE_APIDUMP=<api>:<lo>:<len>[,<lo>:<len>...]` (qiling/os/windows/windows.cpp, next to TAOTE_APIDBG) writes guest
ranges to /tmp/taote_apidump_<n>.bin the first time that API is entered - the only place to snapshot a stub's state,
since the run ends inside the stub.

Captured on `telock_7z.exe` at the `MessageBoxA` the stub calls just before `ExitProcess(0)`:

| range | what it is | result |
|---|---|---|
| 0x419e91 | the dialog text | **"CRC error! File content has been modified. If you run a system debugger, clear all breakpoints before running this program"** |
| 0x419dbc | the caption | "telock_7z.exe" |
| 0x418008 +0x400 | the stub's own ReadFile buffer | differs from the file in **exactly 3 bytes**: offsets 0x140-0x142, the optional header's **CheckSum** field, zeroed by the stub itself |
| 0x400000 +0x400 | the mapped image | **identical** to the file, byte for byte |

And the file the stub opened (`C:\Windows\telock_7z.exe` in the per-run rootfs) is byte-identical to the packed sample
(`cmp` clean), so the check is not failing on a corrupted copy, a wrong path, or a stale file.

So TELock's stub: reads its own first 0x400 bytes, zeroes the PE checksum in its copy, then reports a CRC error. Its
check is therefore computed over something other than "the file on disk as taote serves it" - the two candidates are
(a) a CRC over the *mapped image* at that instant (the stub's own decode has already rewritten part of `.text` by then -
the artifact holds a transformed `.text` at 0x1000 while the 0x400-byte header still matches), or (b) a CRC whose
expected value is derived from a header field our loader left different. Next probe is to disassemble the compare in
the runtime image: dump 0x418000+0x2400 at the same API entry and walk back from 0x4192e7 (the `ExitProcess` return) to
the branch that selects the box.

Rule (ay): when a stub reports a self-check failure, diff what it *read* against what it *compares to* before
suspecting the emulator - and remember a stub mutates its own buffers (TELock zeroes the PE checksum), so a 3-byte
difference can be the stub's own edit rather than the harness's.

#### 0.17ha Round 205: TELock's error box hangs off its import-descriptor walk (the two slots are named)

Continuing round 204's probe. `TAOTE_APIDBG` now prints `ebp=` too (one extra word), which makes a stub's own
`[ebp+disp]` API slots addressable: at the error box `ebp=0xc95e`, so `[ebp+0x40d2d0]` = `[0x419c2e]` and
`[ebp+0x40bae4]` = `[0x418442]`, both inside `.text`. Dumping those two dwords at the `MessageBoxA` entry gives

    0x419c2e -> 0x10021500 = kernel32!GetModuleHandleA's stub cell
    0x418442 -> 0x10021950 = kernel32!LoadLibraryA's stub cell

and the code that reaches the box is unambiguous:

```
41922d  mov  eax,[esi+0xc]        ; the descriptor's Name VA
419230  and  dword [esi+0xc],0    ; clear it in place
41923c  add  eax,edx              ; -> the dll-name string
419240  push eax ; call [ebp+0x40d2d0]   ; GetModuleHandleA(name)
419247  test eax,eax ; jne 0x419309      ; found -> carry on
41924f  push ebx ; call [ebp+0x40bae4]   ; LoadLibraryA(name)
419256  test eax,eax ; jne 0x419309      ; loaded -> carry on
41925e  ...                              ; both ZERO -> the "CRC error" box -> ExitProcess(0)
```

So TELock reports a *file-modified* error when it cannot get a module handle for one of its imports - the box is a
generic error reporter, and the `eax` message index selects one of four texts ([ebp+0x40d32a/2e/3e/42/46]).

The open question is which of the two calls actually runs: the run makes exactly **seven** API calls
(GetModuleFileNameA, CreateFileA, ReadFile, CloseHandle, CreateMutexA, MessageBoxA, ExitProcess) and neither
GetModuleHandleA nor LoadLibraryA appears among them, so the descriptor walk must be reaching 0x41925e without
executing two calls that `TAOTE_APIDBG` (which logs every pc inside a dll range) cannot see. The next probe is a
watchpoint on the reporter: `TAOTE_APIDUMP` at `ExitProcess` for `0x418000+0x2400` plus a breakpoint-style probe at
0x419240/0x41924f, to see whether the slots hold something other than the stub cells at the moment of the call (the
slots are patched by the stub itself, and a stale slot would send the call into whatever the descriptor walk had just
written).

#### 0.17hb Round 206: TELock's error box is a stub self-integrity compare at 0x41904e

Walked the five branches that reach the reporter (`0x418a55`, `0x418c63`, `0x41904e`, `0x41905e`, `0x419665`) with
`TAOTE_PROBE`: only **0x41904e** fires (6 times; 0x418c63 also executes its instruction but its `jne` is NOT taken -
ZF=1 there), and the probe shows the register state at that instant

    pc=0x41904e eax=0x401000 ebx=0x7bd45c94 ecx=0x8a00 edx=0xfd62f97a esi=0x3 edi=0xc95e ebp=0xc95e
    esp=0x121ffe0 eflags=0x17 (CF PF AF, ZF clear) ret=0x0

i.e. `.text`'s VA (0x401000), its size (0x8a00) and two checksum-shaped values, with ZF clear - the branch to the box.
The code that sets those flags is an obfuscated three-slot compare:

```
419031  pop  edi
419032  not  eax
419034  xor  eax,[edi+0x40d38e]
41903a  xor  eax,0x3ce43761
41903f  xor  eax,[ebp+0x40d3fe]
419045  not  eax
419047  sub  eax,[ebp+0x40d382]     ; ZF decides
41904d  popa
41904e  jne  0x41927b              ; mismatch -> the error box -> ExitProcess(0)
419054  push eax ; push ecx ; call 0x419075   ; the success path: process the section
```

So TELock compares a value it computed while decoding against two of its own patched slots (plus the constant
0x3ce43761). The remaining question is no longer "what is the dialog" but "why does the computed value differ" - which
is upstream in the stub's own decode, i.e. the same place the reference's three tolerated `[null-pc]` exceptions and
five `[insn-inv]` skips live.

Next probe: dump `[edi+0x40d38e]`, `[ebp+0x40d3fe]`, `[ebp+0x40d382]` and the pre-`popa` EAX at 0x41904e (edi=0xc95e,
ebp=0xc95e make the addresses 0x418cec / 0x41975c / 0x4196e0 statically known), then run the same probe on pegasus
(which passes this check) to see which of the three differs.

Round note: TELock has now cost three diagnosis rounds without a capability change. It is well-localised but it is a
deep stub-semantics arc; the cheap measured levers should be taken first (the picker bucket is ~16 rows and the
round-203 budget finding covers RLPack).

#### 0.17hc Round 207: the picker bucket on r98 is 16 rows and the reference solves 10 of the 12 sampled

Re-censused on r98 (valid PE, **oep_exact is False**, import recall >= 0.95, code_sim >= 0.9 - note `oep_exact` is
None, not False, on the 84 managed rows, so a naive `not oep_exact` filter reports 56 and is wrong):

| family | n | rows |
|---|---|---|
| JDPack | 4 | jdpack_7z, jdpack_7za, jdpack_MxdwGc, jdpack_PEview |
| Neolite | 4 | neolite_Diskmon, neolite_HDDScan, neolite_Hasher, neolite_md5summer |
| PEtite | 3 | petite_HDDScan, petite_HashCalc, petite_tinytask |
| WinUpack | 3 | winupack_FastHash_kr, winupack_HashCalc, winupack_PEview |
| MPRESS | 1 | mpress_geek (dur 87 = the wall) |
| PECompact | 1 | pecompact_Everything |

Ran the reference on 12 of them. It is exact on **10** (all but jdpack_PEview and petite_HashCalc):

| row | truth RVA | pegasus | pegasus reason | taote claim |
|---|---|---|---|---|
| jdpack_7z | 0xebc5 | 0x40ebc5 | section_hop, 1 stage | 0x40e924 |
| jdpack_7za | 0x55641 | 0x455641 | section_hop | 0x43f1d9 |
| jdpack_MxdwGc | 0x8e08 | 0x1008e08 | section_hop | 0x1010890 |
| neolite_Diskmon | 0xb4b8 | 0x40b4b8 | **section_hop, 2 stages** | 0x406a90 |
| neolite_Hasher | 0x82628 | 0x482628 | section_hop | 0x45d6db |
| neolite_md5summer | 0x9ec68 | 0x49ec68 | section_hop | 0x4933ad |
| petite_tinytask | 0x454c | 0x40454c | section_hop | 0x401000 |
| winupack_FastHash_kr | 0x1dffa | 0x41dffa | section_hop | 0x420627 |
| winupack_HashCalc | 0x11e58 | 0x411e58 | section_hop | 0x45a9c2 |
| winupack_PEview | 0x1000 | 0x401000 | **winupack_terminal_full_fill** | 0x41d5a7 |

So the bucket is not a "which frame" rule problem: on nine of ten the reference gets there by an *observed* section hop
that taote's run either never takes (it dies in the stub first - jdpack_7z is the known `UC_ERR_READ_UNMAPPED` at
0x4184d1) or takes at a different place, and neolite_Diskmon shows the reference needing **two** stages where taote
stops at the first.

Read the reference's WinUpack seam (`src/unpacker/packers/winupack_unpacker.cpp:135-199`) since `winupack_PEview` is a
`terminal_full_fill` row: when the guess lies inside the packed EP section and the loop is hot it scans the run's
`ever_written_` ranges for `e8 ???????? e9 ???????? 55 8b ec` (call + jmp + push-ebp prologue) and takes that as the
entry. taote's `PackerContext` carries no written-range list, so this is not a small port - it needs the engine to
pass its `ever_written_` ranges into the family context first. That is the next unit of work, and it is worth it:
`ever_written_` is also what would let a family seam reproduce the "two stages" behaviour the Neolite rows want.

#### 0.17hd Round 208: the reference's WinUpack prologue scan cannot fire on this corpus (0 of 97)

Implemented the round-207 next step in full: `PackerContext` gained the run's `ever_written_` ranges (copied at
finalize), and a `WinUpackPacker` seam ported `../pegasus/src/unpacker/packers/winupack_unpacker.cpp:135-199` - gate on
"the OEP guess is still inside the packed EP section", then scan the written ranges (skipping the stub's own section)
for `e8 ???????? e9 ???????? 55 8b ec` and take the first hit.

**Measured: it never fires.** Instrumented gate line on `winupack_PEview.exe`:

    [unpack] winupack gate: pick=0x41d5a7 packed_ep=0x401018 ep_sec=[0x401000,0x416000) written=2

- the pick (0x41d5a7) is *outside* the packed EP section, so the gate closes - and across the whole 97-row WinUpack arm,
  **0 rows** have an `oep_claimed` inside that section. The 97-row arm came out 97/87/83/79 against the r98 baseline's
  97/87/82/78, with **no row differing** in the row-by-row diff (the +1 is the usual wall flake).

So the reference's scan is not what fixes `winupack_PEview`: that row's pegasus reason is `winupack_terminal_full_fill`,
a different path (an end-of-run dump whose `keep` was already 0x401000). Reverted both the seam and the context
plumbing; no capability change.

Rule (az): a ported gate is only worth keeping if the gate's precondition actually occurs in the corpus - check the
distribution of the quantity the gate tests (here: the claimed OEP against the packed EP section) over the whole family
BEFORE writing the seam. The same check would have saved rounds 198-199's second variant too.

#### 0.17he Round 209: surviving an unhandled null READ is +1 net with three 120 s hangs (measured, reverted)

`jdpack_7z.exe` dies on `read [0]` at pc 0x4184d1 while the reference logs `[null-pc] except=0xc0000005` and carries
on. taote already survives an unhandled WRITE ("complete the store so the stub can proceed", the reference's unpack
-mode survive behaviour), so the same was tried for a read: when `seh_dispatch` finds no handler for a
`UC_MEM_READ_UNMAPPED`, map a zero page at the fault address and retry (capped, env-gated `TAOTE_SURVIVE_NULLREAD`).

It works on the single row - `jdpack_7z.exe` stops faulting and its artifact becomes **code_sim 1.0 / import recall
1.0** (only the OEP pick is still wrong: 0xe924 against 0xebc5) - and the stub turns out to walk a table upwards
(0x0, 0x1200, 0x120d8 from the same pc), so an address limit of 0x10000 was too small; a cap of 16 survivals covers it.

Corpus, twice:

| run | cap | PE | OEP | imports | all-three | notes |
|---|---|---|---|---|---|---|
| r98 (baseline) | - | 2676 | 2169 | 2175 | **2138** | |
| r99 | 256 | 2673 | 2171 | 2220 | 2141 | 3 rows hang to the 120 s wall |
| r100 | 16 | 2673 | 2170 | 2219 | **2139** | the same 3 rows still hang under 4-way contention |

Gains are real (Neolite 4, MPRESS 1-2, PECompact 1, RLPack 1, BeRo 1) but the three `*_Everything` rows
(expressor/mew/nspack) cross the wall because surviving the faults makes them run much longer, and the net is +1 with
hangs - not worth it. Reverted. What it *does* prove is that several family residuals share one cause: the stub is
killed by a fault the reference survives, and the decode is otherwise complete.

---

## 8. T-024 round: the Windows environment probes (item 1: OS version + `SYSTEM_INFO` arch)

Ticket: `tickets/T-024-windows-environment-probes-version-sysinfo-adapters.md`
(worktree `taote-wt-env`, branch `task/env-probes`, from main `a101eff`).

### 8.1 What changed

`GetVersionExA`/`GetVersionExW` wrote **nothing** into the caller's struct (upstream's
verbatim `return 1`), `GetVersion` answered the NT 4.0 constant `0x00040004`, and
`write_system_info` wrote `dwOemId = 0` (= `PROCESSOR_ARCHITECTURE_INTEL`) on a 64-bit
guest. Now:

* `get_version_ex_body` fills `OSVERSIONINFO[A|W]` from the `[SYSTEM]` profile
  (`majorVersion`/`minorVersion`/**`buildNumber`** — new key, `19045`), writes
  `dwPlatformId = 2`, and also fills the `OSVERSIONINFOEX` tail
  (`wServicePackMajor/Minor`, `wSuiteMask`, `wProductType = 1`) when the caller
  declares the EX size — a `wProductType` of 0 is not a legal `VER_NT_*` value on any
  real Windows;
* `GetVersion` packs the same version: `(build << 16) | (minor << 8) | major`;
* `write_system_info` writes `wProcessorArchitecture = 9` (AMD64) for a 64-bit guest
  and 0 (INTEL) for a 32-bit one, and drops the legacy `dwProcessorType 0x24a` /
  `wProcessorLevel 6` / `wProcessorRevision 0x4601` trio (a 586-class type at level 6
  is incoherent with an AMD64 answer) for pegasus's zeros.

Suite: **559 passed, 0 failed**; two new locks (`GetVersionExAFillsTheExtendedTail`,
`SystemInfoReportsIntelArchOn32BitGuest`) plus the rewritten
`GetVersionAndVersionExAgreeOnProfileVersion` / `GetSystemInfoPacksCtypesLayout`.

### 8.2 Measured (pin 2, budget 85 s, wall 120 s — the other agent sweeps the main tree)

| set | rows | all-three before | all-three after | gains | losses |
|---|---|---|---|---|---|
| Themida 122 + TELock 116 + Alienyze 126 | 364 | **75** | **75** | 0 | 0 |
| S75 (3/family, all 25 families) | 75 | **54** | **54** | 0 | 0 |

Per-sample verdicts (`valid_pe`, `oep_exact`, `imports`, `code_sim`) are **identical on
all 364 + all 75** rows — not just the totals. 0 wall-timeouts in either sweep (rc 0 on
every run); the timeout-adjacent Themida rows move by ±15 s on contention alone
(`themida_Autoruns` 87 → 71 s, `themida_HDDScan` 66 → 88 s) and none of them grades.

### 8.3 Why the 0 — and it is not the fix being inert

`TAOTE_APIDBG=1` traces of the families the ticket attributes items 1+2 to show the
probe is **never called** before the run ends:

* `themida_7z.exe`: 5 `LoadLibraryA`, 4 `GetModuleHandleA`, 2 `GetProcAddress`,
  1 `GetCurrentThreadId`. `themida_touch.exe` adds `RtlAllocateHeap`/`GetProcessHeap`/
  `GetUserDefaultUILanguage`. **No** `GetVersion*`, no `GetSystemInfo`.
* `telock_7z.exe`: 3 calls total — `GetModuleFileNameA`, `CreateFileA`, `ReadFile`
  (`CloseHandle`), then the section hop. **No** environment probe.
* `alienyze_7z.exe`: 110 `GetProcAddress`, 20 `free`, 19 `malloc`, 8 `LoadLibraryA`,
  the CRT init. **No** environment probe.

So the ticket's row-value table (`Themida 122, TELock 118` for items 1+2) does not hold
for this corpus: those stubs are VM/decode-limited (`code_sim` 0.052 Themida, 0.072
TELock in the same sweep) and never read the OS version. The fix is real and pinned by
unit tests, but it has **no corpus headroom** — it cannot be bought as rows here.

An import-name census over all 3,001 packed samples (`grep -laF`, the name has to be in
the stub's import table) finds the actual consumers, and none of them is the family the
ticket named:

| probe | samples importing it (top families) |
|---|---|
| `GetVersionExA` | 187 — **Enigma Virtual Box 122**, Neolite 27, JDPack 19, Yoda-Protector 3, PEtite 3, Alienyze 3 |
| `GetSystemInfo` | 100 — Neolite 27, EnigmaVB 25, JDPack 13, Alienyze 9, Yoda-Protector 5, FSG 5 |
| `GetNativeSystemInfo` | 168 — EnigmaVB 122, PEtite 13, Neolite 12, JDPack 9 |
| `GetAdaptersInfo` | **14 — spread thin** (PEtite 3, Neolite 2, JDPack 2, EnigmaVB 2, one each UPX/Themida/RLPack/Packman/ASPack) |

EnigmaVB and Neolite are already **3/3 all-three** at S75 (the S75 rows can't improve),
and EnigmaVB's stub dies on an unmapped fetch (`enigmavb_ADExplorer.exe`: `PC = 0x5eafe`,
`UC_ERR_FETCH_UNMAPPED`) before it reaches its environment probes. Consequence for the
plan: **items 1+2 of T-024 are correctness work, not row work** — the same verdict the
reference reached (`PLAN_UNPACK.md` §0.2 note: pegasus buys Yoda rows with unpacker work,
not environment answers). Item 3 (`iphlpapi`) should be scheduled on the strength of
`GetAdaptersInfo` being imported by **14 of 3,001** samples, i.e. after, not before, the
decode/OEP mechanisms — unless a measured veto shows up on one of those 14.

---

## 9. The "Alienyze overlay gap" — probed, measured, and closed as a 1-row artifact

Candidate taken after T-024 was parked (§8): the earlier reading that
`alienyze_tinytask.exe` is `0xa101` bytes with its declared sections ending at
`0x4000`, i.e. ~`0x6101` bytes of overlay the section table never describes — read as
a generic "map file bytes beyond the section table" gap worth Alienyze's ~110 rows.

### 9.1 What the file actually is

```
alienyze_tinytask.exe   size 0xa101   SizeOfImage 0x15f01   AddressOfEntryPoint 0x105e0
  .text  va 0x01000 vsz 0x03800 raw 0x00000 rsz 0x00000
  .rdata va 0x05000 vsz 0x00c00 raw 0x00000 rsz 0x00000
  .data  va 0x06000 vsz 0x00f7c raw 0x00000 rsz 0x00000
  .rsrc  va 0x07000 vsz 0x03de0 raw 0x00200 rsz 0x03e00
  .alien va 0x0b000 vsz 0x0af01 raw 0x00000 rsz 0x00000     <-- the entry lives HERE
```

`raw_end = 0x4000`, overlay `0x6101`. The entry (`0x105e0`) is inside `.alien`, whose
`PointerToRawData` **and** `SizeOfRawData` are both zero, so taote maps zeros there and
the guest executes nothing at all: `stages=0 reason=fallback_guess imports=0
error="no section hop; OEP guessed; rebuild failed"`, `dur=0`, `eip=0x4105e0` (the entry),
`eflags=0x2`, zero API calls.

The bytes are *not* missing — they are where `.alien`'s raw data would be if the header
named it. `.alien` va `0xb000` + entry `0x105e0` → file `0x4000 + 0x55e0 = 0x95e0`, and
that offset holds the Alienyze stub prologue **byte-identically to the working
`alienyze_7z.exe`** (whose `.alien` reason is `raw 0x2000 rsz 0x17301`):

```
55 8b ec 81 ec 60 01 00 00 53 56 64 a1 30 00 00 00 89 85 70 ff ff ff ...
push ebp; mov ebp,esp; sub esp,0x160; push ebx; push esi; mov eax,fs:[0x30]   (PEB)
```

`0x4000 + 0x6101 = 0xa101` = the file size exactly, so the payload also *ends* where
`.alien`'s raw data would. Conclusion: **the sample is a damaged file** — its `.alien`
`PointerToRawData`/`SizeOfRawData` were zeroed while the bytes stayed in place. The same
file cannot run on real Windows either (the OS starts at `AddressOfEntryPoint`, which
then sits in a zero-filled section), so this is not an emulator gap.

### 9.2 Corpus-wide: it is the only row

A header scan of all **3,001** packed samples (`packed/*/*.exe`), checking every entry
against the section that hosts it:

| measure | rows |
|---|---|
| entry point inside a section with `SizeOfRawData == 0` (cannot run anywhere) | **1** (`alienyze_tinytask.exe`) |
| an overlay of more than `0x100` bytes past the sections | 1,113 — the normal pattern (attached data the loader never maps), no row depends on it |
| Alienyze rows with an overlay | **1 of 126** |
| Alienyze rows whose entry is unbacked | **1 of 126** |

So "map file bytes beyond the section table" buys **one** row, and it would have to guess
the overlay's RVA from a stub signature (`0x4000 + (ep - .alien.va)`) — the exact class of
guess that can corrupt the 2,000 rows that currently pass. Not shipped.

### 9.3 Where the headroom actually is, for the next pick

Alienyze is **not** an overlay family. Per-row failure classes over its 126 rows (this
tree, pin 2, budget 85 s; report criterion: 75 all-three, OEP 108, imports 79):

| failure class | rows |
|---|---|
| imports only (`code_sim` >= 0.90 and the entry exact) | 15 |
| imports + `code_sim` | 18 |
| `code_sim` only | 12 |
| entry + imports + `code_sim` | 9 |
| entry + imports | 4 |
| entry only | 4 |
| (no valid PE) | 1 |

**~46 of the 51 Alienyze misses involve import coverage**, on rows whose entry is already
exact and whose `code_sim` median is 1.000.

The same shape holds for RLPack, and it is not "emulation depth" there either — measured
in this tree on `rlpack_ADExplorer.exe` (entry exact, `code_sim` 1.000): the rebuilt table
carries **49 entries over 25 dll keys against the original's 314**, and the dll keys are
**doubly spelled** (`kernel32` *and* `kernel32.dll`, `user32` *and* `user32.dll`, … — 11 of
the 25 are duplicates of another key), while the dumped image contains only **one**
plausible `IMAGE_IMPORT_DESCRIPTOR` still naming `kernel32.dll` (at dump offset `0xa2fa0`).
That is the "which table does the code reference" step (`PET6.md`/`RLP_ANCHOR.md` §2), not
a decode depth problem: RLPack's `code_sim` is 1.000 and its import recall median is 0.23.

**Import-descriptor *selection* (payload table over stub table) is the one lane that is
neither TELock, nor the picker/OEP residual, nor the environment probes** — it is worth
~96 RLPack rows + ~46 Alienyze rows on the same mechanism, and it starts from two measured
facts that no round has used yet: the doubled dll keys, and that only one descriptor
survives in the RLPack dump.

---

## 10. Alienyze imports-by-ordinal: the numbers ARE in the artifact, in the table taote walked past

Round 185 (`fb34667` in the main tree) concluded the Alienyze ordinal gap was closed: the store's INT
arrays emitted 0 ordinals, an ordinal-shaped dword scan of the packed file and of the artifact found 0
hits, and the recovery was described as needing an address→export index plus the export *ordinals*, which
`api_db.inc` (names only) cannot supply. Two of those three readings are wrong, and the third is not needed.

### 10.1 The measurements

`alienyze_HWMonitorPro_x32.exe` (entry exact, `code_sim` 1.000, `imp_recall` 0.941): 27 of the original's
458 pairs are missing and **all 27 are ordinals** — 11 `oleaut32` (`#2,#6,#7,#8,#9,#12,#18,#25,#77,#149,
#150`) and 16 `ws2_32`. The rebuilt PE dropped nothing (0 of the 27 appear in the meta), so the pairs were
never recorded.

In the artifact, immediately at the offset the packer already computes (`idt_end`, from `alienyze::find_idt`)
there is a **477-dword table**: 431 name RVAs + **27 `0x8000|N` ordinal slots** + 19 zero terminators. The
27 ordinals' multisets are *exactly* the 27 missing ones — 11 in one block, 16 in another:

```
idt_end 0x37335c  [+0x434 .. ] ord 2,150,149,6,12,9,8,7,18,25,77      <- oleaut32's whole import set
                  [+0x7dc .. ] ord 9,2,13,101,4,23,22,1,16,3,116,115,52,8,111,19  <- ws2_32's
```

`alienyze_Everything.exe` has the same shape with one block of 20 ordinals (all `ws2_32`), and
`alienyze_Dbgview.exe` one of 15.

Why round 185 missed them: the values live in the table the port's own `hinted_store` *skips* — its leading
loop advances over every `v & 0x80000000` slot before the record walk starts (`embedded_pe.cpp`, the
"skip the leading RVA table" `while`), so nothing downstream could ever see them. The dword-shape scan that
reported 0 hits scanned `.alien`, and on the samples measured here the table sits past it.

What is *not* needed is the export-ordinal index: the ordinal numbers are literal, in the artifact.

### 10.2 The mechanism (shipped)

`qiling/unpack/packers/alienyze_ordinals.cpp` — `store_ordinal_pairs()`:

1. read the table as **zero-separated blocks** (the per-DLL INT arrays concatenated, one block per DLL, in
   the same order as the store's DLL markers; measured 14 blocks/14 markers and 12/12);
2. a block with **no name slot** is a DLL the payload imported *exclusively* by ordinal — such a DLL leaves
   no name record, so its marker group is empty as well;
3. pair the pure-ordinal blocks with the name-less marker groups **in store order**, and emit `(dll,
   ordinal_<N>)` for every slot. The two counts must agree, or nothing is emitted.

The positional block→marker map is *not* usable (measured: the ordinal blocks sit at table positions 5 and
12 against marker indices 11 and 12 — an off-by-one would have attributed 11 oleaut32 ordinals to gdi32);
the coarser pure-block ↔ name-less-DLL rule is the one that holds. Deliberately conservative: a mixed
block, or a count mismatch, yields no pairs, because a wrong `(dll, ordinal)` pair is an import the rebuilt
image cannot load. The rebuilder already turns `ordinal_<N>` into a real `0x80000000|N` thunk
(`iat/import_rebuilder.cpp:26`), so the emitted pair lands in the PE's import directory, not as a
hint/name string.

Regression lock: `UnpackCompat.AlienyzeStoreOrdinalBlocksMapToNameLessDlls` (synthetic table: the pairing,
the mixed-block refusal, the count-mismatch refusal).

### 10.3 Measured

Family first — Alienyze, all 126 rows, `--pin 2`, budget 85 s, wall 120, **1 m 08 s** wall for the sweep:

| | before | after | delta |
|---|---|---|---|
| valid PE | 125 | 125 | 0 |
| OEP exact | 108 | 108 | 0 |
| imports ok (`recall >= 0.95`) | **79** | **94** | **+15** |
| **all three (plan rubric)** | **75** | **88** | **+13** |
| all three (strict: `code_sim >= 0.90` too) | 63 | 70 | +7 |

Zero losses on every column. Seven rows cross the all-three line — `Bginfo` (recall 0.938 → 0.999),
`HWMonitorPro_x32` (0.941 → 1.000), `Procmon` (0.912 → 0.954), `Sysmon` (0.905 → 0.977), `logonsessions`
(0.936 → 1.000), `portmon` (0.931 → 0.986), `webhttrack` (0.812 → 0.986).

Corpus — S75 (3/family), `--pin 2`, 7 m 46 s: **54 → 54** all-three, no per-family column changed except
one row, `nspack_ADInsight.exe`, which reads `imports 27.1%` at `dur=86` (the 85 s budget) under the sweep
and **1.000 at 42 s, twice, when re-run solo** — a contention artifact, not a regression (the rule this
repo learned in round 20: never believe a timeout-adjacent row without a solo re-run).

Suite: **560 passed, 0 failed.**

---

## 11. Alienyze: the XOR name band (pegasus b3e412a8) — the mechanism works, the beneficiary rows are blocked elsewhere

### 11.1 What was probed first (cdf57121, the decoy-class 0x0b salvage)

cheapest first, per the ticket order. Reproduced pegasus's own scope census exactly: XOR the terminal
dump with the hardcoded 0x0b and count the ".dll" tokens — **only KillPot** materializes one
(`KERNEL32.dll`); `Cacheset`, `notepad`, `WinList`, `dat2file` carry none. One row, and in this tree that
row is OEP-blocked (`oep_exact=false`, claimed entry off by a section-hop residue), so the port would earn
**0 rows**. Not written; recorded here so nobody rebuilds the 0x0b-only shape.

### 11.2 The mechanism (shipped)

`qiling/unpack/packers/alienyze_names.cpp` — `mine_name_band()`, ported from b3e412a8 + the later fixes:

1. **auto-key**: the band's XOR byte is per-sample, so find the key that makes `.dll\0` tokens appear
   (KillPot 0x0b, Cacheset 0x87, WinList 0x5b, pythonw 0x0f — measured). Done in one pass with a 256-bin
   histogram (k is determined by the first byte), not 255 scans: the naive form cost up to +1.9 s on the
   largest images;
2. **bands**: split at zero runs of 16+ bytes, which keeps junk zones out of the name scan;
3. **tokens**: every `<stem>.dll` ASCII run is a candidate owner (the store keeps them in group order);
4. **forward-greedy cut**: walk the band's printable runs (4..64 chars, no `.`), keep only those with the
   **HintName guard** (the two un-XORed bytes before the run form a hint in `0x08..0x2fff` — this is what
   kills the stub's own `Fls*`/CRT-math decoy stores), skip `Fls*`, and bind each name to the first token at
   or after a monotone cursor that the api_db says actually exports it;
5. gate as the reference does: fire only when the row recovered < 64 pairs, require >= 8 mined, and require
   the mined set to out-cover a partial recovery (>16 already recovered).

**The band is NOT in the decoder's image copy.** Measured on KillPot: the engine's `image` and the dump the
grader reads differ in 159,710 bytes, and the `KERNEL32.dll`^0x0b token is absent from the former and
present at image offset `0x267e4` in the latter. So the miner reads **live guest memory** at
`[base, base + image_size)` (`ctx.ql->mem().read`), which is what the engine's dump is taken from — the same
reason pegasus re-reads `meta_.outfile` instead of its own image buffer.

### 11.3 Measured (Alienyze, 126 rows, `--pin 2`, budget 85 s, wall 120)

A/B over the same manifest, `TAOTE_NO_BAND` as a temporary local switch (removed before the commit):

| | band off | band on |
|---|---|---|
| valid PE | 125 | 125 |
| OEP exact | 108 | 108 |
| imports ok | **94** | **95** (+1) |
| **all three** | **88** | **88** (+0) |
| sweep wall | 1 m 56.3 s | 1 m 55.6 s |

Per row (recall): `KillPot` 0.857 → **1.000** (the mined set is the exact 70-pair multiset, 70/70 in the
original, 0 junk — pegasus measured the same row flipping green), `Cacheset` 0.046 → **0.591** (53 mined,
51 correct), `notepad` 0.021 → 0.062. Zero losses anywhere.

**+0 all-three rows, and the reason is not the mechanism:** the only row it can bring over the 0.95 line is
KillPot, whose entry is wrong in this tree; Cacheset is at 0.591 because its *attribution* fails, not its
mining — the band contains api_db-valid hinted names for **87 of its 88** original imports (only
`comctl32 #17`, an ordinal, is absent), but only 52 get bound to a DLL by the forward-greedy cut.

That number is the headroom for the next mechanism (pegasus ba8c91b4, the xor-miner group attribution):
+35 pairs on Cacheset alone would put it at 0.99 and flip the row.

Regression lock: `UnpackCompat.AlienyzeNameBandMinesHintNamesUnderAnyKey` (key detection, the HintName
guard, the api_db veto, and the no-token case). Suite: **561 passed, 0 failed.**

### 11.4 The attribution: api_db ownership whitelisted by the store's own DLL tokens (not a positional cursor)

The reference infers a name's DLL from its **position** in the band — the monotone forward-greedy cursor over
the trailing `.dll` tokens (pegasus ba8c91b4) — because on Windows it has no `name -> dll` table it trusts.
taote has one (`api_db.inc`, 32,374 names / 405 DLLs), so position is not needed:

* a hinted, api_db-known name is attributed to the table's **priority owner**;
* the owner must be **one of the store's own `.dll` tokens** — which is exactly the whitelist the positional
  cursor approximates, and it keeps the scan anchored to the store instead of wandering the image.

Measured on the rows whose band exists (mined pairs / correct / junk):

| row | positional cursor | api_db, unfiltered | api_db + token whitelist |
|---|---|---|---|
| Cacheset | 53 / 51 / 2 | 89 / 87 / 2 | **89 / 87 / 2** |
| KillPot | 70 / 70 / 0 | 75 / 70 / 5 | **70 / 70 / 0** |
| WinList | 44 / 44 / 0 | 60 / 44 / 16 | **44 / 44 / 0** |
| pythonw | 13 / 12 / 1 | 29 / 12 / 17 | **13 / 12 / 1** |

So the whitelist buys Cacheset's full recall **and** the cursor's precision. The cursor's monotone rule is
what cost Cacheset 34 names: its store is not strictly grouped, and a name whose group sits before the cursor
can never bind.

Also landed: the mid-band gate from ba8c91b4 (`mined` must out-cover an existing recovery when one exceeds
16 pairs) — with it, WinList (72 recovered vs 44 mined) and pythonw (43 vs 13) are left alone automatically.

Family measurement with the api_db attribution (`--pin 2`, budget 85 s, wall 120, **1 m 43.8 s** sweep):

| | band, cursor | band + api_db attribution |
|---|---|---|
| valid PE | 125 | 125 |
| OEP exact | 108 | 108 |
| imports ok | 95 | **96** (+1) |
| **all three** | 88 | **89** (+1) |
| sweep wall | 1 m 55.6 s | **1 m 43.8 s** |

`Cacheset` flips (recall 0.591 → **0.9886**); `notepad` 0.062 → **0.843** (still short of 0.95 — its band
carries only a fraction of its 242 imports); `ntfsinfo` 0.990 → 1.000, `pipelist` 0.992 → 1.000. Zero
losses. Cumulative with §11.3: the band work is **+1 all-three row and +2 import rows on Alienyze**, and it
is the reason Cacheset is green at all.

## 12. Merge of `task/env-probes` into main (2 commits beyond the advertised four)

`git merge --no-ff task/env-probes` at main `eec3cee` -> merge commit `d2f7066`. The branch carried **six** commits,
not the four reported: in addition to the four listed, `6757120` (mine the XOR'd HintName band out of live guest
memory) and `590154e` (attribute the band by api_db ownership, whitelisted by the store's own dll tokens), both
measured at +1 row / 0 losses on the branch. All six are in.

State at the merge:

* **One conflict, docs only** - `PLAN_UNPACK.md`, where both sides appended sections at the same anchor. Resolved by
  keeping BOTH blocks in order (main's rounds 168-209, then the branch's §8-§11); no code conflict, and
  `qiling/unpack/packers/embedded_pe.cpp` auto-merged.
* An **untracked** `tickets/T-024-windows-environment-probes-version-sysinfo-adapters.md` (237 lines, status: open) was
  blocking the merge; it is the *older* draft - the branch's committed version is 305 lines with status "in progress"
  and the status log - so the draft was moved out of the tree to `/tmp/T-024-untracked-main-draft.md` and the branch's
  version kept.
* Suite: **606 tests, 0 failed** (main was 602; the branch adds four non-skipped tests, `Windows_Api_Test` +
  `Unpack_Compat`).

Combined corpus (r101, rerun-corrected: four rows sat at dur 86-87, all restored when re-run in place):

| run | PE | OEP | imports | all-three |
|---|---|---|---|---|
| r98 main before the merge | 2676 | 2169 | 2175 | **2138** |
| r101 merged | 2676 | 2169 | 2222 | **2138** |

So the merge is **exactly neutral on rows** - 0 gains, 0 losses, row for row. The branch's expected +13 does not
stack because main's round-202 Alienyze work (the store EP outranking a bad hop, plus the case-aware stub surface)
already lifted Alienyze to 125/126 import-exact and 118/126 all-three; the branch's ordinal reader and band miner were
measured against the *pre*-round-202 baseline (79 all-three) and reach the same rows. Both implementations are now
present and agree; the ordinal reader is the one that would matter if a future Alienyze row keeps a short INT table.

#### 0.17hf Round 210: surviving a null READ, bounded to 8 faults - corpus 2138 -> 2144

Round 209 measured the mechanism (+9 rows on 18 sampled rows) but rejected it because an unbounded version pushed three
`*_Everything` rows past the 120 s wall (r99 2141, r100 2139 with a 16-fault cap). The cap was the variable, not the
mechanism: at **8** faults those same rows come out *faster* than they were without it - the stub skips its retry loop
instead of spinning to the wall:

| row | r98 dur | cap 16 | cap 8 |
|---|---|---|---|
| mew_Everything | 43 s | 113 s | **28 s** |
| nspack_Everything | 48 s | 110 s | **26 s** |
| expressor_Everything | 46 s | 115 s | **30 s** |

The implemented rule: after `seh_dispatch` finds no handler for a `UC_MEM_READ_UNMAPPED`, if the fault address is below
0x10000000 and fewer than 8 such faults have been survived, map a zero page there and retry, so the load yields 0.
Everything else still fails exactly as before.

| corpus | PE | OEP | imports | all-three |
|---|---|---|---|---|
| r98 (before) | 2676 | 2169 | 2175 | **2138** |
| r102 (cap 8) | 2676 | 2174 | 2223 | **2144** |

Six gains (Neolite 3, MPRESS 1, RLPack 1, BeRo 1) and two losses, both at dur 86 and both restored when re-run in
place. On the targeted 18-row sweep it is 9 gains / 0 losses and *every* row is faster than baseline - the rows that
lose a second of wall clock are the ones that used to spin.

Rule (ba): when a "survive the fault" change looks like a speed regression, vary the CAP before abandoning the
mechanism - the cost was the runaway path being taken to its (large) limit, not the survival itself.

#### 0.17hg Round 211: surviving a null FETCH is a wall regression (mean 7.6 s -> 21.6 s, measured, reverted)

464 of the 2678 corpus rows end on `UC_ERR_FETCH_UNMAPPED` - more than any other error class - and the reference treats
that fault the same way it treats the null READ it was just given for free (`[null-pc] except=0xc0000005`, carry on).
Two variants were tried:

1. **Deliver it to SEH** (`seh_dispatch(address, 8u)` on `UC_MEM_FETCH_UNMAPPED` at a low address). Inert: the dispatch
   finds no handler in the state the stub left and the run still dies.
2. **Map the page and let the zeros run** (the read survival's twin, page-mapping at the fault address). It works
   mechanically - `alienyze_cpuz_x32` and `alienyze_disk2vhd` stop erroring - but both were already all-three rows:
   the fault happens *after* the image is captured, so wiping it changes nothing.

Corpus-wide it is a clear loss, measured on the first 337 rows of r103 before stopping:

| run | rows | mean dur | rows >= 85 s | 120 s timeouts |
|---|---|---|---|---|
| r102 (shipped) | 2678 | **7.6 s** | 89 | 0 |
| r103 (null fetch survived) | 337 | **21.6 s** | 51 | 2 |

i.e. **mean runtime triples**. Executing zero-filled pages makes stubs wander, so the rows that gain nothing spend the
whole budget first - the opposite of the read case, where the stub skipped a retry loop and got faster.

Rule (bb): the read survival and the fetch survival are not the same mechanism even though the reference reports both
as `[null-pc]` - a survived READ feeds a value back to the stub (it proceeds), while a survived FETCH hands control to
zero bytes (it wanders). Judge a "survive the fault" change on the corpus MEAN duration, not only on the row count.

#### 0.17hh Round 212: TELock's check is a CRC-32 over .text with a non-standard variant; the picker bucket is down to 12

**TELock (113 rows end with NO error at all** - the clean `MessageBoxA -> ExitProcess` exit). Executed the round-206
probe:

* at `0x419047` (`sub eax,[ebp+0x40d382]`, the instruction whose ZF decides) the registers are
  `eax=0x23884536 ecx=0 ebx=0 edx=0xedb88320 esi=0x409a00 edi=0xc95e ebp=0xc95e` - `edx` is the **reversed CRC-32
  polynomial** and `esi=0x409a00` is exactly `.text`'s end (0x401000 + 0x8a00), so the check is a CRC-32 of `.text`;
* the three slots the compare uses are `[edi+0x40d38e]=0xcee9cb57`, `[ebp+0x40d3fe]=0x3ce4dca4`,
  `[ebp+0x40d382]=0xffff143a`, and the compare wants `eax=0x311634a8` to pass;
* **the CRC input is not corrupted**: dumping `.text` at the run's first API *and* at `CreateMutexA` (the last call
  before the box) gives bytes **identical to the packed file** (`crc32 = 0xa221c838` both times); it is only after the
  box that the stub's decode rewrites the section (35181 of 35328 bytes differ at `ExitProcess`);
* no standard zlib CRC-32 over any plausible range of the packed file (whole file, headers+text, .text, sections, .text
  to EOF, and their complements) equals the computed `0x23884536` or the needed `0x311634a8`.

So TELock's verdict is decided by a CRC variant whose parameters live in the stub's own (encrypted) data, over a
mapping that is demonstrably correct. Next probe: find the CRC loop's init/range by watching its reads (the loop's
cursor is `esi`, ending at 0x409a00), then reproduce its arithmetic offline.

**Picker bucket: 16 -> 12** on r102, i.e. the shipped null-read survival took four of them (neolite_Diskmon, Hasher,
md5summer + one). What is left:

| family | rows | truth | claim |
|---|---|---|---|
| JDPack 4 | jdpack_7z / 7za / MxdwGc / PEview | 0xebc5 / 0x55641 / 0x8e08 / 0x1000 | 0xe924 / 0x3f1d9 / 0x10890 / 0x155f9 |
| PEtite 3 | petite_HDDScan / HashCalc / tinytask | 0x483d20 / 0x11e58 / 0x454c | 0x7bb11e / 0x62bf8 / 0x1000 |
| WinUpack 3 | FastHash_kr / HashCalc / PEview | 0x1dffa / 0x11e58 / 0x1000 | 0x20627 / 0x5a9c2 / 0x1d5a7 |
| Neolite 1 | neolite_HDDScan (dur 86) | 0x483d20 | 0x7bb11e |
| PECompact 1 | pecompact_Everything | 0x145f0d | 0x4bf150 |

Two facts worth keeping: `petite_HDDScan`/`neolite_HDDScan` (the same program packed twice) and
`petite_HashCalc`/`winupack_HashCalc` (same again) produce *identical* claims across packers, so the claim comes from
the program, not the packer - and the reference's answers on those rows are its own section hops, which taote never
takes because its run ends first.

#### 0.17hi Round 213: TELock's CRC check decoded and inverted - it is an oracle for decode correctness

Disassembled the check from the pre-box runtime dump (`TAOTE_APIDUMP=CreateMutexA:0x418fc0:0x100`):

```
418fe6  mov  ecx,[edi+0x40d38a]      ; flags|length
418fec  mov  eax,[edi+0x40d386]      ; start (relative to [ebp+0x40d362])
418ff2  test ecx,0x80000000 ; je skip
418ffa  and  ecx,0x7fffffff          ; length
419000  add  eax,[ebp+0x40d362]      ; the actual start address
419006  pusha
419007  mov  esi,eax                 ; cursor
419009  mov  ebx,ecx                 ; count
41900b  xor  ecx,ecx
41900d  lea  eax,[ecx-1]             ; init 0xFFFFFFFF
419011  mov  edi,0xedb88320          ; reflected CRC-32 polynomial
419016  xor  edx,edx / mov dl,[esi] / xor dl,al / shr edx,1 / jnc / xor edx,edi   ; 8x
419028  shr  eax,8 ; xor eax,edx ; inc esi ; dec ebx ; jg 0x419016
419032  not  eax                     ; final xor, i.e. a textbook CRC-32
419034  xor  eax,[edi+0x40d38e]
41903a  xor  eax,0x3ce43761
41903f  xor  eax,[ebp+0x40d3fe]
419045  not  eax
419047  sub  eax,[ebp+0x40d382]      ; ZF decides
41904e  jne  0x41927b               ; -> the "CRC error" box
```

So it is a **textbook reflected CRC-32 over a stub-chosen buffer**, mixed with three of the stub's own slots and the
constant 0x3ce43761. Inverted the mix to get the CRC the run *wanted*:

    needed(eax at 0x419047) = 0x311634a8
    crc the run COMPUTED   = 0x129e9a5b   (= crc32 of the .text our run decoded)
    original payload .text = 0xa09619ca   (not the expected value either)

So TELock's verdict reduces to: **our decode of the payload is wrong**, and this check is a precise in-run oracle for
it (compute the CRC of any candidate buffer, mix with the three slots, compare to the needed value). The slots are the
stub's own data; the expected value is not a plain CRC of either the packed `.text` or the original's, which means the
buffer it CRCs is its own decoded copy, not a section.

That closes TELock's *diagnosis*: the check is not the bug and cannot be "fixed" - the stub is telling the truth about a
decode that is not byte-exact. The remaining work is the decode itself (the same place the reference's five
`[insn-inv]` skips and three tolerated `[null-pc]` exceptions live).

#### 0.17hj Round 214: where the remaining 417 rows actually are - and PEtite is the biggest unexplored pool

Cross-tabulated every r102 row's error class against its grade. The result is a map worth keeping, because it says
which error classes are worth *nothing*:

| error class | rows | all-three | still missing |
|---|---|---|---|
| none | 1833 | 1486 | **347** |
| Invalid memory fetch | 464 | **443** | 21 |
| Invalid memory read | 203 | 173 | 30 |
| no section hop; OEP guessed | 117 | 1 | 116 (Yoda-Protector 88) |
| Invalid memory write | 55 | 37 | 18 |

So the fetch class - the largest by count, and the one rounds 211 chased - holds only 21 recoverable rows; it is
almost entirely *post-capture* noise. The real remaining gap is the 347 rows that end with **no error at all**:

| family | missing, no error |
|---|---|
| Themida | 122 (the reference fails these too) |
| TELock | 113 (diagnosis closed in round 213: its CRC says the decode is not byte-exact) |
| **PEtite** | **41** |
| Amber / Eronana / Exe32pack / RLPack / Alienyze / MEW / BeRo | 14 / 13 / 13 / 8 / 7 / 4 / 3 |

**PEtite is the discovery**: 73 rows, 30 all-three, and 43 missing of which **41 end cleanly** - 31 of them with both
OEP and imports wrong at `code_sim` 0.87-0.93, i.e. the image is decoded but not exact and the entry is a mid-payload
frame (`petite_rrdec`: truth 0x1160, taote 0x417214).

The reference solves most of them, via `petite_terminal_full_fill`
(`../pegasus/src/unpacker/packers/petite_unpacker.cpp:380-505`): a candidate machine over the decoded image with six
pattern classes (C1, H1, E8E9, C2, C3, C4), each split into "boundary-passing" or not, an EP-exit tracker, and a fixed
precedence (chain-earliest boundary-passing candidate; a boundary-passing pick from a weak class beats a non-boundary
one). Measured on four of taote's worst rows: pegasus is exact on three (`gzip` 0x401280, `rrdec` 0x401160, `m2cdm`
0x401160) and wrong on one (`DarkNamer` 0x40e87f vs 0xa71e), while taote is wrong on all four.

taote's side of the same row: `petite_rrdec`'s ladder yields **zero** candidates in every pass
(`passA 0`, `passB hits=0`, `boundary-thunks in .petite: 0`, all `C=0 C3=0`) and the pick comes from a section hop at
0x417175 adjusted to 0x417214 - i.e. taote never even enumerates the candidates the reference ranks. Porting that
machine is the next unit of work, and unlike the WinUpack seam (round 208) its precondition - a decoded image with
code-shaped candidates - is present on 41 rows.

#### 0.17hk Round 215: the PEtite candidate classes alone reproduce taote's WRONG picks (2/43 offline)

Before porting the reference's PEtite machine, ran it as an offline prototype over taote's existing r102 artifacts -
the six pattern classes exactly as `petite_unpacker.cpp:354-419` defines them (C1 `55 8b ec 6a ff`, h1 `6a ?? 68 ?????
e8`, e8e9 `e8 ???????? e9`, C2 `55 89 e5 83 (ec|c4) ??`, C3 `55 8b ec 83 (ec|c4) ??`, C4 `e8 ???????? 6a ?? 68`), the
>=8-nonzero-in-16 density guard, the boundary rule (preceded by C3/C2/CC/90 or two zeros), last-per-class, the
C1->h1->e8e9->C2->C3->C4 chain order and the boundary-passing override - scanning the artifact image with file
offsets mapped through the section table, skipping the packed-EP section.

Result over the 43 missing PEtite rows: **2 correct, 41 wrong**, and the wrong answers are the ones taote already
produces (`petite_AccessEnum` 0x403a53, `petite_AkelAdmin` 0x401082 - exactly taote's claims), not the reference's
(`7z` truth 0x40ebc5 vs prototype 0x40ea18; `7za` truth 0x455641 vs 0x45b889).

So the classes are not what makes the reference right: it scans the run's **`ever_written_` ranges** (live decoded
regions, EP section excluded), not the artifact image, and its pick is gated by the earlier `keep_is_junk` validator
and the EP-exit tracker. A faithful port therefore needs the written-range list in `PackerContext` - the plumbing that
round 208 added and then reverted with the WinUpack seam.

That is the plan for the next unit: re-add `written_ranges` to the context (it is cheap and this time the consumer
exists), then port the machine against those ranges rather than against the image. Rule (bc): prototype a ported
pattern machine against the rows it is meant to fix BEFORE writing C++ - here it turned a "big port" into a precisely
scoped one (the classes are right; the input was wrong) for ten minutes of work.

Second data point for the same round: added `TAOTE_WRITTEN_RANGES=1` (prints the run's `ever_written_` ranges at
finalize, qiling/unpack/unpack.cpp) and re-ran the prototype scanning exactly those ranges from the artifact dump
instead of the whole image. On the first 12 missing rows: **0 correct, 12 wrong**, and the picks are unchanged
(`petite_7z` 0x40ea18 vs truth 0x40ebc5; `petite_AccessEnum` 0x403a53 = taote's own claim). The written ranges on these
rows cover the whole image anyway (`petite_rrdec`: 0x401000-0x413000, 0x414000-0x416000, 0x417000-0x419000), so the
slate scan is not input-starved - it is simply not what produces the reference's answer.

That shifts the port target: the reference's correctness on these rows must come from the stages that run *before* the
slate scan - its EP-exit tracker (`ep_exit_pending_`, the watched section-to-section transition that fires
`dump_module` when the stub leaves its own section) and the `keep_is_junk` validator that decides whether the slate is
needed at all. Those two are the real port; the pattern classes are the fallback. Round 208's lesson repeats one level
down: identify which *stage* of a reference mechanism carries the answer before porting the mechanism.

#### 0.17hm Round 216: the PEtite EP-exit walk needs a transition history taote does not have

Third measurement in the same investigation. Implemented the reference's `sec_trans_hist_` reader as an env-gated
recorder (`TAOTE_SEC_TRANS=1`, qiling/unpack/unpack.cpp `on_section_exec` + the write hook, printing every
section-to-section transition with its exec ordinal and each section's last-write ordinal at finalize) so the reference's
backward walk could be prototyped against real per-row data before any picker change.

Result: **every PEtite row records exactly ONE transition** (`petite_rrdec` 1 of 5 sections, `petite_7z` 1 of 3,
`petite_AkelAdmin` 1 of 3), because taote's hop is TERMINAL - `dump_module` on the first accepted section hop ends the
run (`stages=1 reason=section_hop`), so there is no ongoing execution to record. The single recorded entry is the stub's
own section entry (`from=-1 to=2 addr=0x47e10b` on 7za), not the payload hand-off.

The reference's walk (petite_unpacker.cpp:245-300) needs the opposite: a full run history, walked BACKWARD for the last
transition whose target section the execution never leaves again, skipping targets that kept receiving writes after a
64-instruction grace. Its own comment names two of taote's missing rows as coming out "directly" from that walk (gsd
0x402d4e, 7za 0x455641 - and 7za is exactly taote's 0x43f1d9 miss).

So the port order is forced and is NOT a picker change:
  (1) give PEtite a non-terminal hop: keep executing past the first section hop, record transitions
      (the recorder above is already written), and pick in finalize instead of at the hop;
  (2) then port the backward walk over that history (it is ~20 lines: skip a target whose section was written after the
      transition, take the last one, fall back to the slate scan when the history is empty).
Family-gated to PEtite, so the blast radius is its 73 rows.

This also explains round 207's picker-bucket observation one level deeper: the reference is right on those rows because
its runs do not stop at the first hop, not because it ranks frames differently.

#### 0.17hn Round 216b: PEtite's run DOES continue - inside the emulated stub module, never back to image code

The last check before writing a non-terminal-hop change: does PEtite's run actually stop at the hop? No. `petite_rrdec.exe`
with `TAOTE_SEC_TRANS=1 TAOTE_UNPACK_DEBUG=1` runs to **200000+ section-exec fires** in 0.40 s and ends at
`final pc=0x100211e0` - an address inside the emulated stub module (0x10000000+), not in any image section - with 23864
writes and still exactly ONE recorded transition (the stub's own section entry).

So the hop is not what ends the run, and the missing transition history is not a hook-coverage bug: after the decode the
stub hands control to its own resolver/loader stubs and spends the whole run there, never re-entering image code in a
way that would produce a section transition. That is the same shape as RLPack's round-106 diagnosis (emulation depth,
not attribution): the reference's EP-exit walk sees a rich history because ITS run keeps executing image code.

Consequence for the work order: PEtite's 41 clean-exit rows are NOT reachable by porting the picker stages (measured
2/43 and 0/12 and 0/1 above). They need the run to progress past the stub's loader stubs, which is the emulation-depth
problem RLPack already has - i.e. a shared root cause across two families, worth attacking once rather than twice.
TELock (113 rows) is the other clean-exit pool and has a byte-exact oracle (the round-213 CRC), so it is the better next
target: an offline-checkable decode, no picker involved.

#### 0.17ho Round 217: PEtite's failure is an explicit "ERROR! Corrupt Data!" from its header-block decode

The in-run signal the earlier rounds lacked. Every missing PEtite row sampled ends with a MessageBoxA whose caption/text are
`ERROR!` / `Corrupt Data!` and then `ExitProcess(0xffffffff)`:

    petite_rrdec    MessageBoxA(uType 0x10) ret=0x4170f1   ExitProcess(-1)   claim 0x417214
    petite_gzip     MessageBoxA(uType 0x10) ret=0x4650f1   ExitProcess(-1)   claim 0x403b2d
    petite_7za      MessageBoxA(uType 0x10) ret=0x47e0f1   ExitProcess(-1)   claim 0x43f1d9
    petite_HashCalc MessageBoxA(uType 0x10) ret=0x4820f1   ExitProcess(-1)   claim 0x462bf8

So the family's 41 clean-exit missing rows are one root cause, and it is a SELF-CHECK failure, not a picker choice - the
same shape as TELock's CRC box (round 213), which makes the two biggest clean-exit pools one class of problem.

The reporter is at `<stub section base>+0xce`: `mov esp,[esp+0x24]; mov eax,[esp]; lea edx,[eax+0xfd]; push 0x10;
push eax+0xf6; push edx; push 0; mov ebx,[ebx]; call [ebx]; push -1; call [ebx+0xc]`, i.e. MessageBoxA(0, text, caption,
MB_ICONERROR) then ExitProcess(-1), with the strings stored at stub_base+0xf6/0xfd. Exactly one branch reaches it: the
`jcc` at 0x4171e9 (`test eax,eax; je reporter`), immediately after `call 0x417214`.

0x417214 - taote's claimed OEP on rrdec - is the stub's DECOMPRESS routine (`push ebp; mov ebp,esp; sub esp,0xbad8`,
bit-reservoir at [ebp+8], output at [ebp+0x10], state tables at ebp-0xb658/-0xa240, inner worker `call 0x418575`, and
the exit `cmp [ebp-0x14],0; jge ok; xor eax,eax`): a negative status becomes eax=0 and the caller reports Corrupt Data.
Its arguments come from a descriptor table walked at 0x4171aa (`mov ecx,[ebx]; btr ecx,0x1f` = relocation block via
`std; rep movs`, else `mov edx,[ebx-0xc]` size, `[ebx-8]` dst RVA, ecx src RVA), so the stub decompresses block by block
and one block's decode fails.

Localised the failing block with the new `TAOTE_PROBE_N` / `TAOTE_PROBE_FAIL` (below): on petite_rrdec the successes are
src/0x7ff->0x414000, src/0xb->0x415000, src/0x40cb14->0x401000, and the FAILING one is
**src RVA 5 -> dst 0x400000, size 0x6a4** - the ORIGINAL HEADERS' block. Our memory at 0x400000 differs from the packed
file there (byte 0 is 0x00 instead of 'M' - the routine's partial output - and 0x400..0x6a4 is zeros where the file has
section raw bytes), and the compressed stream is read from image RVA 5, i.e. the stub expects its header-block input in
the header page.

Open question for the next unit, now precise: does the stub expect a FLAT FILE VIEW at the image base (the packed file's
bytes 0x5.. at VA 0x400005) - a mapping taote does not create - or is the decode itself diverging? The discriminating
test is to map the packed file flat at base for PEtite only (env-gated) and see whether the header block's status turns
non-negative; if it does, that single mapping is the family's fix.

#### 0.17hp Round 218: PEtite and TELock are ONE problem - stub decoders whose input we feed correctly and whose output diverges

The discriminating test, run against the reference's own artifact. pegasus on `petite_rrdec.exe` produces oep 0x401160
(correct), and comparing its termiminal image with taote's mid-run artifact and the packed file:

    stream region 0x5..0x200 ("the header block's compressed input")
      pegasus vs packed : 0 differing bytes
      taote   vs packed : 0 differing bytes
      pegasus vs taote  : 0 differing bytes

So the decompressor is handed EXACTLY the same bytes in both runs, the reference's stub returns a non-negative status and
restores the headers, and taote's returns negative and reports "Corrupt Data!". The input is not the problem and neither
is the mapping: **our emulation of the decode loop diverges**.

That makes the two biggest clean-exit pools one class of problem:

    TELock   113 rows  stub CRC-32 self-check fails (round 213: computed 0x129e9a5b, wanted 0x311634a8)
    PEtite    41 rows  stub decompressor self-check fails (this round, same input as the reference)

Both are stubs that verify their own decode and refuse to hand off when the verification fails, and in both cases taote
still grades code_sim ~0.9 on the artifact - i.e. the decode is mostly right and diverges in a corner. The next unit is
therefore a differential: decode one PEtite block offline (the format is reachable from 0x417214: 0x8000 window at
[ebp-4], bit reservoir at [ebp+8], probability tables at ebp-0xb658/-0xa240/-0xa23c, worker 0x418575), compare against
taote's partial output, and name the first diverging byte and the instruction that produced it - then check Unicorn's
semantics for that instruction. One corner case there is worth up to 154 rows, against the 12-row picker bucket.

#### 0.17hq Round 219: the PEtite divergence is in the decode's match copies (4790 bytes, 1672 near-singleton runs)

Captured the decoded `.text` at the moment the stub gives up (`TAOTE_APIDUMP=MessageBoxA:0x401000:0x12000`) and diffed it
against the not-packed original's `.text` (0xbb18 bytes):

    differing bytes 4790 (9.9%)
    runs           1672, nearly all of length 1
    first diverg.  0x401054 - the FIRST byte of a `e8 rel32` displacement: orig `e8 10 ba 00 00` vs ours `e8 63 ba 00 00`

So the decode is ~90% right, and what is wrong is a scattering of single bytes, concentrated in call displacements
(`0x40105c` `e8 20 a6 00 00` vs `e8 7b a6 00 00`, `0x401061`, `0x401093`, `0x4010a1`, `0x4010ae`, ...), with a DIFFERENT
delta at each site (0x53, 0x5b, ...). None of our 6-byte sequences occurs verbatim anywhere in the original, so this is
not "copied from the wrong offset by a constant" - i.e. not a plain off-by-N distance error. The shape matches a match
copy whose DISTANCE is computed slightly wrong and then lands on the payload's highly self-similar code, which is why
most bytes still match.

That is the thing to fix, and it is byte-level: decode one block offline from the packed stream (format reachable from
0x417214, worker 0x418575, 0x8000 window, probability tables at ebp-0xb658/-0xa240/-0xa23c) and diff per output byte
against the original's `.text`, then name the instruction that computed the first wrong distance and check Unicorn's
semantics for it. TELock's CRC oracle (needed 0x311634a8) gives the same kind of byte-exact target for the other 113
rows, so the same differential harness serves both families.

#### 0.17hr Round 220: the failing PEtite block is an IN-PLACE header decode, traced end to end

Generalised the tracer from the FSG-only EP window to any range: `TAOTE_FSGTRACE=lo:hi:n` emits pc + eax/ebx/ecx/edx/
esi/edi/ebp/esp/eflags per instruction inside [lo,hi), capped at n. With it, the failing header block is now traced in
full - entry at 0x417214 with eax=0x400000, edi=0x400000, edx=0x6a4, ebx=0x4186b8, through the body at 0x4173xx, to the
common failure exit:

    417214 push ebp / mov ebp,esp          <- src edi == dst edi == 0x400000 (in place)
    417217 mov [edi],al                    <- writes AL (0x00) over the stream's first byte
    4173xx (body; the trace tail reaches the invalid-symbol check)
    4181c7 xor eax,eax                     <- status < 0 -> return 0
    4171e7 test eax,eax / 4171e9 je reporter

Two facts worth keeping:

1. The descriptor walk at 0x4171aa feeds it a header-block entry `{src 0, size 0x6a4, dst 0}` (base-relative), i.e. the
   stub decompresses the original headers ONTO the page the stream itself is read from, and the routine's first
   instruction overwrites the first input byte before decoding. Any decode of this block therefore has to tolerate the
   routine's own pre-write - which is exactly why the "corrupt" verdict is decided inside the body and not by the input.
2. Instrumentation does not perturb the artifact: plain, `TAOTE_PROBE=0x4171e2` and `TAOTE_FSGTRACE=0x417300:0x417400`
   produce BYTE-IDENTICAL dumps (md5 df61a5cc...), so the trace above describes the real run and the diagnostics shipped
   in the last rounds are safe to trust on this family.

Descriptor table content at the same moment (TAOTE_APIDUMP=MessageBoxA:0x418680:0x40), 16-byte entries {src, size, dst}:
0x418680 {0xd000, 0x1840, 0x11875}, 0x418690 {0xe000, 0x101a, 0x12ffd}, 0x4186a0 {0x12000, 0x2000, 0x0} with a trailing
0x6a4 at 0x4186ac - note the entries are consumed and rewritten as the loop advances, so a post-mortem read does not
match what a mid-loop trace sees (that mismatch cost one round of confusion; read such tables from a trace, not a dump).

Next step for the differential: the body check that returns negative is inside 0x4173xx-0x4181c7; with the range tracer
the exact instruction and its operands can be read off (the trace already narrows it to the 118 instructions between
entry and exit), and the corresponding value can be compared against the packed file's stream.

#### 0.17hs Round 221: the failure is the FIRST symbol - 4 bytes are read, then the invalid path is taken

Read the captured 126-instruction body line by line. The stub's header decode dies on its very first symbol:

    4172f5..417302   eax=1 / 0x27 / 4 -> the counts/state init
    417305 mov eax,[src]; 41730a movzx ...  <- reads a byte, advances, shifts into a big-endian reservoir
                    reads 0x400001=0x5a, 0x400002=0x90, 0x400003=0x00, 0x400004=0x03
    41730f..41731b   shl/or chain -> reservoir ecx = 0x0300905a
    41731b..417325   pop the first symbol's bits (eax 0x905a -> ebx 0xfcff -> 0x6ca5)
    417327           jmp 0x4181c7        <- the invalid-symbol exit, on the FIRST symbol

So the decode is not slowly diverging on this block: the stream start is wrong, and the decoder says so immediately.
That matches the descriptor the walk built for it, `{src 0, size 0x6a4, dst 0}` - a src offset of 0 points the stream at
0x400000, the very byte the routine's own `mov [edi],al` has just overwritten with AL (0x00), and the first four bytes it
then consumes (5a 90 00 03 from 0x400001) do not form a valid symbol. The earlier probe run of the same row passed
`src=0x400005` for this call, i.e. there are two candidate stream starts in play and the one our stub builds is rejected
outright.

That makes the remaining question sharply bounded: the header-block descriptor's src field is built by the stub from its
own decoded table area (0x4186a0-0x4186b8, 16-byte entries consumed and rewritten as the loop advances), so if that table
is off, it is off because the earlier decode of the stub's own section diverged - the same 90%-correct decode measured in
0.17hq. Next test: brute-force the stream start (0x400000..0x400010) in the running guest and see which offset the
decoder accepts; the accepted offset names the correct descriptor value, hence the size of the table error.

Method note worth keeping: this trace needed no reference run at all - a stub that fails its own check can be read
directly, and "does it fail slowly or immediately" is answered by instruction count (here 118 instructions, first symbol).

#### 0.17ht Round 222: the failing check is a 16-bit complement invariant, and the block's stream start does not satisfy it

Added `TAOTE_WATCH=lo:len[:max]` (logs every write in a range with pc + value) to test the "the stub rebuilds the
descriptor table" hypothesis. Result: during the whole run there are **zero writes** in 0x418680-0x4186c0, and the table
there is byte-identical to the packed file (VA 0x4186a8 == file 0x1aa8), so the descriptor `{src 0, size 0x6a4, dst 0}`
the loop reads for the header block is the PACKER's own static data, not something our run computed. The table-rebuild
hypothesis is dead.

Then disassembled the exact failing check (0x417319-0x417327):

    417319 mov eax,ebx          ; ebx = the 32-bit bit reservoir just loaded from the stream
    41731b not ebx
    41731d and eax,0xffff       ; low 16 bits
    417322 shr ebx,0x10         ; ~reservoir >> 16
    417325 xor ebx,eax
    417327 jne 0x4181c7         ; FAIL unless  high16(reservoir) == ~low16(reservoir)

so PEtite guards the stream start with a 2-byte complement: the first four bytes must satisfy `hi16 == ~lo16`. Our run
loads 0x0300905a (bytes 5a 90 00 03 from 0x400001) -> lo16 0x905a, hi16 0x0300, ~lo16 0xfcff -> mismatch -> immediate
rejection, exactly as the trace showed on the first symbol.

Scanning for 4-byte windows that satisfy the invariant: the packed file has only 5 (offsets 0xa, 0xb, 0xc, 0x71e, 0x9464);
the dumped image has 92. The routine consumes from src+1, so a src of 0x9/0xa/0xb would pass - while the descriptor's
src is 0. That is the whole bug in one line: **the header block's stream pointer is ~9 bytes early**.

Where the 9 could come from is the next question (the descriptor field is 0 in the file, so either the stub adds
something we do not, or the stage that copies the stream into the header page writes it at the wrong offset - the routine
itself clobbers 0x400000 with AL before reading, which is the one place the start can shift). The decisive test is now
cheap and offline: compute which of 0x400000+k (k=0..0x20) the invariant accepts on the *live* page, and then find the
store that placed the stream there.

#### 0.17hu Round 223: the reference does NOT prove PEtite's stub decodes - its win is picker-side (reason: petite_terminal_full_fill)

Checked the premise the last four rounds were built on. pegasus's `petite_rrdec.exe_dump.bin.meta.json` says:

    reason = "petite_terminal_full_fill", stages = 3, oep = 0x401160
    imports still include USER32 MessageBoxA and KERNEL32 ExitProcess

so the reference did NOT hand off from the stub's successful decode - it full-filled at end of emulation and its OEP came
from its own runtime stages, with MessageBoxA/ExitProcess still in the picture (i.e. the stub very likely showed the same
"Corrupt Data!" box there). Its right answer is a PICKER answer, not a decode answer.

And the picker is not the plain slate scan either: running the round-215 candidate machine over the reference's TERMINAL
dump gives 0x408abf (not the truth 0x401160), and over taote's mid-run artifact the same 0x408abf - the two images agree,
so the answer is not in the image at all. It comes from the run: the reference's stages=3 sequence, i.e. its EP-exit
tracker plus the terminal full fill.

That reconciles everything measured this block and points back to round 216's finding from the other side: the missing
ingredient is run-stage bookkeeping (transitions/hops recorded over a full run), not decode fidelity, and not image
scanning. It also means the "TELock + PEtite are one decode problem" framing (0.17hp) must be narrowed: TELock's CRC
check runs on a successful decode path, while PEtite's guard is hit by the stub in the emulator too.

Still valid and useful from this block: the guard itself (16-bit complement on the stream start), the descriptor being
static packer data, the trace method, and the shipped diagnostics.

Next unit for PEtite, corrected: give the family the reference's three-stage runtime (EP-exit tracker over a full run ->
terminal full fill -> pick), which needs `written_ranges`/transition state in the finalize pick - the same plumbing twice
proposed and never measured with a working consumer. Measure it on PEtite's 73 rows only.

#### 0.17hv Round 224: 89 of the 504 OEP misses already have the TRUE ENTRY DECODED - and the ladder, not the hop, is what picks

Corpus-wide measurement of the r102 misses, split properly (`oep_exact is True` for imports-only, `is False` for OEP), and
then testing whether the artifact already contains the ORIGINAL's first 8 bytes at the true entry:

    family          oep-wrong  imports-only  true-entry-decoded
    Themida              122             0            0
    TELock               115             1            0
    Yoda-Protector       100             1            1
    Amber                 37             1            0
    PEtite                37             6           35
    Exe32pack             32             0           13
    Eronana Packer        14             0           13
    WinUpack              10             8            8
    Alienyze               8             0            7
    NSPack                 5             1            0
    PECompact              5             0            3
    ------------------------------------------------------------------
    TOTALS               504            30           89

So 89 rows are pure PICKER wins: the payload is decoded correctly at the true entry, the image is fine, and only the
chosen address is wrong. That is the largest actionable pool found this session, and it is dominated by PEtite (35).

Then asked the question that decides the fix: does taote OBSERVE the true hop and discard it? Ran 13 of the pool with
`TAOTE_UNPACK_DEBUG=1` and compared the candidate ledger against the truth:

    petite_7z            truth 0x40ebc5   candidates [0x418175]   final pick 0x40e924   (delta 0x2a1)
    petite_7zFM          truth 0x422ce2   candidates [0x43d175]   final pick 0x422b65   (delta 0x17d)
    petite_7zFMn         truth 0x420bf2   candidates [0x43a175]   final pick 0x420a75   (delta 0x17d)
    petite_7za           truth 0x455641   candidates [0x47e175]   final pick 0x43f1d9
    petite_AccessEnum    truth 0x407a98   candidates [0x42a175]   final pick 0x403a53
    winupack_Diskmon     truth 0x40b4b8   candidates [0x44bf1b]   final pick 0x406a90
    winupack_Everything  truth 0x545f0d   candidates [0x618c13]   final pick 0x4bf150
    pecompact_Hasher     truth 0x482628   candidates [0x401016]   final pick 0x47c6ed

Two facts: (1) taote sees exactly ONE section-hop candidate per row, and it is the stub-section entry, never the payload
entry - so no correct candidate is being discarded; (2) the final address comes from the LADDER (`pick OEP X (was Y)`),
which overrides the hop, and on the PEtite rows the ladder's pick is only 0x17d-0x2a1 away from the truth while the
section-hop is far off. So for this pool the lever is a better LADDER ranking / a hop-to-ladder join, not more hops.

Next unit: on the 35 PEtite rows + 13 Exe32pack + 13 Eronana, ask which prologue the ladder SHOULD prefer. The data
needed is already cheap: for each row, the ladder's candidate list (it scans prologues) plus the distance to the truth,
so a rule (e.g. "prefer the first prologue after the decode target's first written block" or "prefer the prologue whose
preceding bytes are a ret/padding AND which the stub's rel32 hand-off pointed at") can be tested OFFLINE over all 89
rows before any code change. Side note: `pecompact_Everything` writes 226 MB of debug lines under
TAOTE_UNPACK_DEBUG, so batch scans should cap or filter its stderr.

Addendum: enumerated the artifact's bytes at the true entry for those rows (strict 8-byte match against the original,
53 rows survived the section-mapping filter). The shapes are the ladder's own classes:

    0x558bec6aff  55 8b ec 6a ff   (C1)  PEtite 8, WinUpack 3, JDPack 2
    0x5589e583ec  55 89 e5 83 ec   (C2)  PEtite 8
    0x558bec83ec  55 8b ec 83 ec   (C3)  PEtite 3, PECompact 1
    0x6a7068..    6a ?? 68 ??..    (h1)  PEtite 6+

so for this pool the truth IS in the candidate set the ladder already scans - the failure is ranking, not enumeration.
That closes the offline loop on the round-215 result: the slate scan on a taote artifact picked the WRONG member of the
same classes (last-per-class), which is why it measured 2/43. A ranking rule is therefore the whole fix, and it has to be
derived from something other than address order (the truth is neither the first nor the last candidate: `petite_7z`'s
truth 0x40ebc5 sits AFTER the ladder's 0x40e924). The next offline step is to test candidate discriminators over the 53
rows without touching C++: preceding-byte boundary kind, the bytes AT the candidate in the packed file vs the decoded
image, whether the stub's rel32 hand-off or the decode target's first written block points at it, and section-relative
position.

Discriminators tested OFFLINE over the 53 section-mapped rows (no C++ touched), to rule candidates out cheaply:

- **Boundary kind** (preceding byte is C3/C2/CC/90 or two zeros - the reference's own definition): the truth is
  boundary-passing on 28 of 53 rows (53%), against a baseline of 63.9% for all C1/C2 candidates in the same section.
  So boundary is worse than chance as a discriminator here - RULED OUT. This is worth knowing because it is exactly
  the rule the reference applies to *arbitrate* between classes; it helps there and hurts here.
- **Address position** (rank among same-class candidates in the section): middle 19, last 13, first 0, with a bimodal
  quantile split (12 rows below 0.25, 18 above 0.75) - RULED OUT as a monotone rule; the truth is not
  "the first" or "the last" prologue.
- 21 of the 53 rows are not C1/C2-shaped at all (they are C3 `55 8b ec 83 ec` or h1 `6a ?? 68 ..`), so a candidate
  scan must union all classes before any ranking is compared.

Remaining untested discriminators: the bytes AT the candidate in the packed file versus the decoded image (a candidate
the stub wrote over is payload; one the packed file already had is stub code), and whether the stub's rel32 hand-off or
the decode target's first written block points at the candidate. Those need per-row packed/decoded byte comparisons -
still offline, no C++.

#### 0.17hw Round 225: static ranking cannot solve the 89-row picker pool - the two candidates are the same code shape

Tested the last two offline discriminators and then looked at an individual row, which is what settles it.

- **Packed-vs-decoded bytes at the candidate** (a candidate the stub wrote over is payload; one the packed file already
  carried is stub code): across the 53 rows the truth's 16-byte window differs from the packed file on 36 of 38
  resolvable rows (95%), but the ladder's pick differs on 31 of 39 (79%) - the feature is nearly universal, so it cannot
  separate them. WEAK, not usable as a rule.
- **Address order**: already ruled out (first 0, last 13, middle 19, bimodal quantiles).

Then `petite_7z.exe`, side by side:

    0x40e924 (the ladder's pick)  55 8b ec 6a ff 68 f8 14 41 00 68 e2 ec 40 00 64 a1 00 00 00 00 50 64 89
    0x40ebc5 (the TRUTH)          55 8b ec 6a ff 68 28 15 41 00 68 e2 ec 40 00 64 a1 00 00 00 00 50 64 89

Both are complete MSVC SEH prologues - identical except the first pushed constant (0x4114f8 vs 0x411528) and both
pushing the SAME exception handler 0x40ece2. They are two `__try`-framed functions of the payload; nothing in the bytes
distinguishes the entry point from the inner function except the PE header's AddressOfEntryPoint, which is exactly what
the packed file destroyed.

CONCLUSION, and it closes the ranking line opened in 0.17hv: the 89-row picker pool is NOT statically solvable by a
better prologue ranking, because the competing candidates are the same code shape. The reference resolves it at runtime
(its `stages=3` sequence: record section transitions over a full run, keep the last transition whose target section the
execution never leaves again, then terminal full fill) - i.e. the answer is "where execution actually arrived", not
"which bytes look like an entry". Any row-moving change for this pool must therefore be a RUNTIME change, and PEtite's
37 OEP-wrong rows are the place to measure it (smallest blast radius of the big contributors: 73 rows).

#### 0.17hx Round 226: the reference DOES decode PEtite byte-exactly (0 of 47896) - round 223's inference was wrong, and the chain to our wrong byte is now complete

Correction first, because it re-opens the decode line. In 0.17hu I argued from pegasus's meta that "the reference does not
prove the stub decodes" because MessageBoxA/ExitProcess appear in its import list. That was a bad inference: those are
STATIC imports of the payload (the error reporter is in the payload's own import table), not evidence of execution. The
measurement that settles it:

    .text (47896 bytes) of pegasus's terminal dump vs the not-packed original: 0 differing bytes (0.0%)
    .text of taote's image at the stub's error box vs the original:            58 of 64 bytes differ

So the reference's decoder runs to completion and produces the payload BYTE-EXACTLY, while ours diverges. PEtite is a
decode-fidelity problem after all - the same class as TELock - and the "picker" framing from 0.17hv stands only for the
choice of address, not for the reason the code is wrong.

Then walked our wrong bytes back to their producer, which is now a complete chain:

1. `.text` differs at 0x401054 (`e8 63 ba 00 00`, expected `e8 10 ba 00 00`).
2. `TAOTE_WATCH=0x401054:4` fires ONCE, from pc 0x417206 - which disassembles to a `rep movs DWORD` inside the stub's
   memcpy helper (0x4171f5: `push esi/edi; mov edi,[esp+0xc]; mov esi,[esp+0x10]; mov ecx,[esp+0x14]; sar ecx,2;
   rep movs`). So .text is not written by the decoder directly: the decoder fills a STACK buffer and the stub copies it
   into the section.
3. The copy for that region runs from esi=0x50045b2 to edi=0x401040 (ecx=0x1ff0 dwords), so the wrong dword came from
   stack 0x50045be -> .text 0x40104c.
4. `TAOTE_WATCH=0x50045c6:4` then names the producers: 0x417aa4 writes 0x63 (the divergent literal) and 0x417926 writes
   ba 00 00. The expected bytes are 10 ba 00 00, i.e. the decoder emitted the literal 0x63 where 0x10 belongs.

So the divergence is one literal byte out of the bit reservoir, ~0x400 bytes into the output - deep in the bit-level
arithmetic, not in a match-copy distance as 0.17hq guessed. That correction matters: it is a bit-reader problem (one
literal takes the wrong bits), which is why the damage is scattered single bytes rather than shifted runs.

Next: with the reference byte-exact, the differential has a golden target per byte. Decode the same block offline (the
format is reachable from 0x417214/0x418575 and the tables at 0x417000-0x4170c0: the 0x8000 window at [ebp-4], the 3-bit
class read at 0x4172a1, the 0x27/8-bit reservoir refill at 0x4172f7-0x417317) and compare the literal sequence until the
first wrong one, then check the bit-reader instruction there against Unicorn's semantics.

#### 0.17hy Round 227: the reference's PEtite SEH seed is MEASURED INERT here (73 rows, row-for-row identical)

Found the reference mechanism this family was missing, ported it, and measured it away.

The mechanism (pegasus src/windows/win32.cpp:250-300, 400-500): `seh_seed_enabled_for()` auto-engages an SEH seed for
any image carrying a `.petite` section, because PEtite's decryptor is EXCEPTION-DRIVEN - it captures `push fs:[0]` when
installing its own frame and later WALKS the captured chain (`mov ebx,[frame]; lea esp,[ebx-0x26]; mov ebp,[ebx+8]`),
so with an empty or garbage chain the second decode stage derails. The seed is a synthetic native-style frame in a
private RWX window: Handler H returns ExceptionContinueExecution (`B8 01 00 00 00 C2 10 00`), F is self-referential
(the walker re-derives its popal slot from `[[fs:[0]]]`), `[Q-4]` carries the image base, `[PIVOT]` the stub base.

taote's state: the loader leaves the TEB ExceptionList at 0 (loader/pe.cpp:1233 "stays 0 like the reference"), and the
measured `fs:[0]` at the first API is 0xd000 - a value the stub wrote, not a frame at all. So the premise for the port
was real.

Ported it (map 0x6ffc0000, write H/F/Q/PIVOT/F2, set fs:[0]=F) with the write deferred to the first section-exec because
`regs.read("fs_base")` throws - the register is spelled **"fsbase"** in taote's x86 table (qiling/arch/x86.cpp:58) and
`UC_X86_REG_FS_BASE` is an x64-only register here (windows.cpp:131). With the right name the seed went live:

    [unpack] seh seed fs:[0] <- 0x6ffe0100 (base 0x6000)

Measured on the whole family (73 rows, 4 workers, 60 s budget, 90 s wall):

    PEtite   n=73  PE=73  OEP=36  IMP=36  ALL=30     (r102 identical)
    rows changed: 0   (row-for-row diff against r102)

and on the exemplar `petite_rrdec` nothing moves either (still MessageBoxA "Corrupt Data!" -> oep 0x417214). So the seed
is inert for this corpus's PEtite variants: the exception-driven decryptor the reference describes (0x4144f9+) is not
the code path these stubs take - their guard is the 16-bit complement on the stream start (0.17ht), reached by an
ordinary call from the descriptor loop at 0x4171aa.

Reverted the whole port (git checkout of qiling/unpack/unpack.cpp and unpack.hpp); nothing was kept. Recorded here so it
is not re-run without a new mechanism: the SEH seed was measured, not assumed.

#### 0.17hz Round 228: WinUpack's OEP-wrong rows DO contain the truth in the ladder's classes (ranks 7..120)

Looked for the next row-moving pool after PEtite's decode dead-end, and re-ran the candidate census on WinUpack, whose
OEP-wrong rows have `code_sim` 1.00 - the image is perfect, only the address is wrong. (First attempt was wrong: it
compared RVAs against VAs and reported "no candidates near the truth" for every row. Always print the candidate at the
truth explicitly.)

    row                        truth        claim        cands  shape@truth  rank
    winupack_Diskmon           0x40b4b8     0x406a90        32  C1             7/32
    winupack_Everything        0x545f0d     0x4bf150        54  C3            52/54
    winupack_FastHash_kr       0x41dffa     0x420627       162  h1            20/162
    winupack_HashCalc          0x411e58     0x45a9c2       228  C1           120/228
    winupack_PEview            0x401000     0x41d5a7         8  (none)         -
    winupack_ShareEnum         0x409013     0x4172dc        64  C1            10/64
    winupack_mtinst            0x403866     0x1003be0      351  h1             8/351
    winupack_notmyfault        0x404f25     0x43f3d4         0  (none)         -
    winupack_puttytel_32       0x45bfe6     0x487448         0  (none)         -

So the truth IS one of the ladder's classes in 6 of 9 rows, at ranks 7-120 - i.e. this pool is genuinely a ranking
problem, unlike PEtite's (same-shape candidates, 0.17hw). Two incidental findings worth keeping: (1) three rows have
claims that are not image addresses at all (`winupack_mtinst` claims 0x1003be0, inside the emulated stub-DLL range) - a
claim outside [base, base+image_size) can never be right; (2) `notmyfault` and `puttytel_32` have no candidates at all
because their artifacts are broken (a single garbage-named `.Upack` section and an empty `.pgimp`), so they are a dump
problem, not a pick problem.

A rule is not yet identified: the truth is early (7-10) in Diskmon/ShareEnum/mtinst but late (52, 120) in
Everything/HashCalc, so "prefer the earliest candidate" would trade rows. The discriminator to test next is the one these
rows offer for free - whether the candidate lies in the section the stub DECODED (differs from the packed file) versus
stub code, per row, which is exactly the feature that was weak across the mixed 53-row pool but may separate within a
family.

Two more discriminators tested and eliminated on the same rows, both by the same pattern (the feature is universal, so
it cannot rank):

- **Decoded-vs-packed page**: for every WinUpack row the truth page differs from the packed file AND so does the claim's
  page, and 32/32, 54/54, 162/162, 228/228, 64/64, 351/351 of the candidates sit in "decoded" pages. The whole image is
  decoded by the time we pick, so the feature carries no information here (it was already weak across the mixed pool).
- **Claims outside the image**: 30 corpus rows report an OEP claim outside [0x400000, 0x10000000) (Exe32pack 3,
  Alienyze/EnigmaVB/Eronana/TELock/Themida 2 each), but only 5 of those rows are still missing - 25 are already all-three,
  so gating on it would not move rows either. It remains a correctness smell (e.g. `winupack_mtinst` claiming 0x1003be0 in
  the stub-DLL range), not a lever.

Net for the round: WinUpack's picker pool is real (truth present, ranks 7-120) but every static feature available from the
artifact alone has now been measured inert, so it needs the same runtime information the reference uses. No code change.

Correction to this round's own numbers: the image base is NOT always 0x400000, and both the "outside the image" count and
the label in the WinUpack table assumed it was. Recomputed with each artifact's own ImageBase:

    winupack_mtinst   base 0x1000000   truth 0x1003866   claim 0x1003be0   in-image, delta 0x37a, rank 8/351

so mtinst's claim is a NEAR MISS inside its own image (not an out-of-image bogus address as written above), and the
corpus-wide out-of-image census becomes 118 claims, of which only 14 rows are still missing (Amber 116 of the 118, and
104 of those rows are already all-three). That in turn is explained by the grader: `oep_exact` compares the REBUILT
ARTIFACT's AddressOfEntryPoint against the original's RVA (`unpack_report.py:302`), so `meta.oep_claimed` is a
diagnostic, not the shipped entry - a row can pass with a nonsense claim.

Two things survive from the earlier text and matter: (1) the truth is a ladder class in 6 of 9 WinUpack rows at ranks
7-120, so that pool is a ranking problem; (2) the three claims in that table that looked absurd are all in-image except
none, so no filter lever exists there either. The mtinst deltas are small (0x37a) which is the same near-miss shape as
the PEtite rows - the picker lands close and the remaining error is a few hundred bytes of function boundary.

#### 0.17i WinUpack: the parked stack slot is the OEP - ported and measured (+6 OEP rows on the family)

Round 229. The reference mechanism taote never had: its WinUpack seam snapshots the stack (`[esp+8]`) at the import
loop's indirect call because the engine PARKS the payload entry in its own frame (winupack_unpacker.cpp:651-690). taote
only had the comment (unpack.cpp:1364) - the harvest was never implemented.

Verified before wiring it in. taote's run for these rows ends at `final pc=0x28` (a bogus return) and disassembling the
stub's dispatch loop shows why:

    44c090 pop ebp / 44c091 pop ecx / 44c092 inc esi / 44c093 lods eax / 44c094 test eax,eax / 44c096 je ...
    44c098 push ecx / 44c099 push esi / 44c09a xchg edi,eax / 44c09b call ecx   <- ecx = 0x28, so the run dies here

and at that `call ecx` the stack reads `[0]=0x43b004 [2]=0x40b4b8` - the TRUE OEP of petite/winupack_Diskmon in slot 2,
i.e. exactly the `[esp+8]` the reference documents. Same on every sampled row:

    winupack_Diskmon    [esp+8] 0x40b4b8  (truth)   ladder picked 0x406a90
    winupack_ShareEnum  [esp+8] 0x409013  (truth)   ladder picked 0x4172dc
    winupack_mtinst     [esp+8] 0x1003866 (truth)   ladder picked 0x1003be0
    winupack_FastHash_kr[esp+8] 0x41dffa  (truth)   ladder picked 0x420627
    (also winupack_Everything 0x545f0d, winupack_HashCalc 0x411e58 in the family arm)

Port: a one-shot code hook that matches `ff /2` and `ff /4` (register form) inside image code, records `[esp+8]` when it
is in-image, and REMOVES ITSELF on the first hit; the finalize pick takes that value when it validates as a payload entry
(C1 `55 8b ec 6a ff`, C3 `55 8b ec 83`, C2 `55 89 e5 83`, h1 `6a ?? 68 .. e8`, or `ff 25`), reason `stack_oep`.

Two implementation facts that cost a measurement each:
- `ql.hook_insn(cb, UC_X86_INS_CALL)` is NOT usable here: the run dies immediately (0.2 s, no hop, imports=0), so only a
  `hook_code` hook works - and that costs a TB boundary per instruction, which is why arming matters.
- Arming it in `install()` slowed the long rows to the wall (Bginfo 67 s -> 86 s, Procmon 63 s -> 86 s, 2 rows lost at an
  85 s budget). Arming it at the FIRST ACCEPTED HOP (dump_module) and removing it on the first harvest fixed that:
  Bginfo back to 41.8 s solo.

Family measurement (97 rows, 4 workers, 85 s budget, 120 s wall):

    before (r102)   PE=97  OEP=87  IMP=82  ALL=79
    after           PE=97  OEP=93  IMP=82  ALL=80
    row diff: 6 gains (Diskmon, Everything, FastHash_kr, HashCalc, ShareEnum, mtinst - all OEP exact now,
              2 of them all-three), 1 loss (Bginfo imports at dur 86 = the wall; solo 41.8 s, i.e. contention)

Corpus measurement (r104, 2678 rows, 4 workers, 85 s budget, 120 s wall):

    all-three   r102 2144  ->  r104 2146   (+2)
    valid PE    r102 2676  ->  r104 2676
    gains: winupack_FastHash_kr.exe, winupack_HashCalc.exe (both all-three now)
    losses: 0

The two rows that read as losses in the raw run (nspack_Bginfo, rlpack_geek, both dur 86) are the usual wall flakes and
came back on a solo re-run (46.1 s and 63.2 s) - neither family is touched by the change. WinUpack itself went
87 -> 93 OEP, 82 -> 83 imports, 79 -> 81 all-three.

What the +6 OEP but +2 all-three split means: Diskmon, Everything, ShareEnum and mtinst now carry the correct entry but
still fail imports, so they are now IMPORT problems, not OEP problems - a cleaner hand-off for the next unit than the
mixed pool they were in before.

#### 0.17ia WinUpack's four corrected-OEP rows fail on ORDINALS only - and the naive fix is metric-gaming

Round 230, following the stack-slot win. The four rows that gained a correct OEP but still fail imports are all
`recall` failures, and `imports` is `recall >= 0.95` (unpack_report.py:323):

    row                  recall  precision  missing  which
    winupack_Diskmon     0.9439    0.7063     12     oleaut32 #2..#25 (11), comctl32 #17
    winupack_Everything  0.9247    0.1031     22     ws2_32 #1..#116 (20), imm32 ImmGetVirtualKey, shell32 #16
    winupack_ShareEnum   0.9030    0.8917     23     oleaut32 #2..#202 (11), ws2_32 #1..#116 (11), comctl32 #17
    winupack_mtinst      0.3129    0.1896      -     different problem: code_sim 0.8825, the decode is incomplete

So three rows are 5-9 % of recall away, and everything they miss is an ORDINAL import (plus one named import in
Everything). This is the same shape FSG and Alienyze each needed their own ordinal source for.

Why this is not a small change: the artifact's IAT slots hold RESOLVED ADDRESSES, and taote's reverse symbol map
(symbols.add(va, dll, name), unpack.cpp:2508) names the export an address belongs to. For an address that is
oleaut32's export #12 the map can only say "oleaut32!<the name of export 12>" - while the original imported it as
ordinal 12, because the ORIGINAL BINARY was linked that way. The ordinal spelling is a property of the caller's import
table, which the packer destroyed.

The obvious fix - emit an `ordinal_<N>` alias next to every named export - would take recall to 1.0 on all three rows and
turn them green, but it writes each function into the rebuilt import table TWICE (by name and by ordinal). That is
metric-gaming, not unpacking, and it also destroys `imp_exact` (precision 0.10 on Everything already). Rejected.

The legitimate question for the next unit: where does WinUpack's payload keep its ORIGINAL import table, and does it
survive in the decoded image with its 0x80000000-flagged thunks? A blind scan is not enough - the artifact holds 57
(ShareEnum: 114) incidental dwords whose bit31 is set and whose low 16 bits match a missing ordinal - so the
discriminator has to be structure (a contiguous run of flagged thunks after a DLL name), which is what the existing
orphan-descriptor scan already does for named imports. Verify that the runs exist before writing a seam (rule h), and
check whether `mtinst` is only a decode problem (code_sim 0.88) rather than an import one.

#### 0.17ib WinUpack's ordinal spelling is CLOSED by evidence: three independent sources are empty

Checked every plausible source for the missing ordinals (Diskmon: oleaut32 #2..#25, comctl32 #17; ShareEnum: oleaut32
#2..#202, ws2_32 #1..#116):

1. **The decoded image.** A structural scan for the payload's original INT - runs of consecutive 0x80000000-flagged
   dwords with plausible ordinal lows - finds only noise: Diskmon 18 runs of >=3, ShareEnum 72, and their ordinal sets
   overlap the missing set by 0-1 members with values like 3995, 3840, 3700 that cannot be ordinals. No structure, no
   source.
2. **The packed file's own import table**: `import_names()` on the packed sample returns **0 pairs** for both rows (the
   stub keeps no caller-side table to read).
3. **The runtime resolution lane**: `GetProcAddress` is called **zero times** on Diskmon (TAOTE_APIDBG), so the stub
   resolves the payload's imports itself from its own encoded table and writes resolved ADDRESSES into the IAT. There is
   no (dll, ordinal-or-name) pair to intercept.

So the ordinal spelling of a given slot is destroyed at pack time and cannot be reconstructed from this corpus: the only
thing left at run time is the address, which identifies the function but not how the original binary spelled it. Per-DLL
majority voting cannot help either - Diskmon's table is a genuine mix (recall 0.94 with ~11 oleaut32 pairs matched and 11
missing), so the choice is per-slot.

CLOSED. The two remaining levers for these rows are (a) recover the ordinal-carrying table from the stub's encoded data
(a format-reading job with no evidence yet that the ordinals are even stored), or (b) accept them. Do not re-run the
"alias names to ordinals" idea: it inflates recall by duplicating imports in the rebuilt table and was rejected in 0.17ia.
WinUpack stays at 81/97; its OEP work (round 229) is unaffected.

Next unit: back to the PEtite byte-level differential (37 OEP-wrong rows with the true entry decoded, and the reference
byte-exact at 0/47896), which is the largest measurable pool left that is not blocked on destroyed information.

#### 0.17ic Round 232: two corrections to my own map - the pool is 416, not 504, and 616 rows run with NO family label

1) **Managed rows contaminated my earlier census.** Following the standing rule (use `oep_exact is False`, never a falsy
test) on r104: 82 rows carry `oep_exact = None` because they are managed (.NET) and `out_ep` already equals `orig_ep`
while meta records a VA - Amber 22, Exe32pack 17, TELock 15, Eronana 13, Alienyze 8, BeRo 1. My round-224 table counted
those as OEP-wrong, which inflated Eronana (14 "misses" -> really 1) and the total (504 -> the true **416**):

    Themida 122, TELock 100, Yoda-Protector 100, PEtite 37, Amber 15, Exe32pack 15, NSPack 5, JDPack 4, ...

So the 89-row "picker-winnable" pool from 0.17hv is also overstated by however many of its members were managed rows
(Eronana's 13 certainly were). The corrected statement: the picker pool is real but smaller, and Eronana has no OEP
headroom at all.

2) **616 rows run with `family=unknown`** - Eronana 151 (all), Exe32pack 124 (all), BeRoEXEPacker 107 (all), FSG 97
(all), Yoda-Crypter 92, Amber 41, Molebox 3, MPRESS 1. Checked whether that costs anything: only NINE families have
gated behaviour at all (`family ==` sites: WinUpack 3, NSPack 2, MPRESS 2, UPX 1, RLPack 1, PECompact 1, Molebox 1,
JDPack 1, EnigmaVB 1), and of the 616 unlabelled rows only **4** belong to a gated family (Molebox 3, MPRESS 1). The
label gap is therefore NOT a lever (FSG's 96/97 needs no label, and Eronana/Exe32pack/BeRo/Yoda-Crypter have no gated
behaviour to enable). Detection stays as it is - do not add signatures expecting rows.

Also tested in the same block: the WinUpack stack-slot harvest does NOT generalise. With `TAOTE_STACK_OEP_ALL=1` the
harvest fires on none of the sampled rows of Eronana, Exe32pack, Alienyze or PECompact (`reason=family_fill` for
Alienyze, plain `section_hop` for the others), so the slot is a WinUpack property of that packer's hand-off and the
family gate stays. The env switch is kept as a measurement hook.

Current standing after all corrections: **2146/2678**, 416 strict OEP-wrong rows, biggest pools Themida 122 and TELock
100 (both decode-bound) and PEtite 37 (decode-bound but with a byte-exact golden target).

#### 0.17id The corrected pool: 416 OEP-wrong rows, of which only 7 are picker-shaped - everything else is DECODE

Re-ran the "is the true entry already decoded in the artifact" test with the strict filter (`oep_exact is False`) and
per-row bases:

    family        strict OEP-wrong   true entry decoded
    Amber                15                 0
    Exe32pack            15                 0
    NSPack                5                 0
    JDPack                4                 4
    PECompact             4                 3
    Alienyze              0                 0   <- its 8 "misses" were managed rows

So after removing the managed-row contamination: **Alienyze has no OEP headroom at all** (118/126, the 8 are .NET), Amber
15 / Exe32pack 15 / NSPack 5 are pure DECODE problems (the artifact does not even contain the true entry's bytes), and
only **JDPack 4 + PECompact 3 = 7 rows** are picker-shaped.

Tested the WinUpack stack-slot idea on JDPack too (`TAOTE_STACK_OEP_ALL=1`): the harvest fires on none of its 4 rows
(they end with `reason=section_hop` / `ladder_scan` and `UC_ERR_READ_UNMAPPED`), so the parked-slot hand-off really is a
WinUpack property. The picker lane is therefore closed at 7 rows - it is not worth another mechanism.

CONSEQUENCE for the work order: the remaining headroom is decode, in this order of tractability:
  1. PEtite 37 - decode-bound BUT with a byte-exact golden target (the reference produces the original's `.text` with 0
     of 47896 bytes differing, ours differs in 4790).
  2. TELock 100 - decode-bound with a CRC oracle (needed value 0x311634a8) but no per-byte golden image.
  3. Amber 15 / Exe32pack 15 / NSPack 5 - decode-bound with neither.
  4. Themida 122 / Yoda 100 - decode-bound, and the reference fails them too.

#### 0.17ie Unicorn authenticity spot-checks: shl-by-0, btr and std/rep movsd are all faithful

Before sinking time into a bit-reader differential, tested the primitives a self-checking decoder actually depends on,
directly against the pinned engine (unicorn 2.1.4, a 20-line harness):

    mov eax,1 / mov ecx,0 / stc / shl eax,cl   -> eax=1, CF stays 1     (flags UNTOUCHED for cl=0, correct)
    mov ecx,1 / shl eax,cl                     -> eax=2, CF=0           (correct)
    mov ecx,0x80000000 / btr ecx,0x1f          -> ecx=0, CF=1           (correct)
    std / rep movsd x3 (downward)              -> memory layout correct (a downward copy looks identical to a
                                                  forward one for non-overlapping ranges - my first "mismatch"
                                                  was my own bad expectation, not an engine bug)

So none of the classic authenticity gaps explains PEtite's 4790-byte divergence, and these three are settled: do not
re-test them. The differential has to come from the arithmetic itself (the bit reservoir and the match/literal tables),
which means the offline decoder comparison remains the only route.

#### 0.17if JDPack: the ladder's own candidate list contains the truth, but no ordering rule picks it

Last picker data point of the family sweep. `JDPack` has 4 strict OEP-wrong rows and all 4 have the true entry decoded in
the artifact, so it was the last place a ranking rule could still pay. taote's ladder passB reports its first and last
hits; compared with the truth:

    row              passB hits   first       last        pick        truth
    jdpack_7z             4       0x40e924   0x40ebc5    0x40e924    0x40ebc5   <- last IS the truth
    jdpack_7za           56       0x40e840   0x45b889    0x43f1d9    0x455641
    jdpack_MxdwGc        19       0x1004107  0x100804e   0x1010890   0x1008e08
    jdpack_PEview         0       -          -           0x4155f9    0x401000   <- no candidates at all

So "take the last passB hit" would fix ONE of four; 7za and MxdwGc are neither first nor last (the truth sits between
them), and PEview has no ladder candidates at all. Combined with the earlier eliminations (boundary kind, address order,
packed-vs-decoded bytes, decoded-page, out-of-image, and the WinUpack parked slot which does not fire here), the PICKER
LANE IS CLOSED end to end: 7 rows, no rule.

That leaves the work order purely decode-side, where PEtite's 37 rows are the only pool with a byte-exact golden target
(the reference reproduces the original `.text` with 0 of 47896 bytes differing) and the engine primitives have already
been exonerated (shl-by-0, btr, std/rep movsd).

#### 0.17ig WinUpack stack-slot reproducibility, harvest timing, and a bounding experiment that failed

Three family re-runs of the shipped change (ca33f96) plus instrumentation of when the harvest actually fires.

**Reproducibility.** A second and third full family run give OEP 93 every time; all-three reads 80 or 81 depending on ONE
row, `winupack_Bginfo`, whose duration under 4-worker load is 75-86 s (it was 53-67 s before the change, i.e. already
near the 85 s budget). Solo it is 42.7 s. So the family figure is stable (93 OEP; 80-81 all-three) and the only
variance is a pre-existing near-budget row, not the harvest.

**Harvest timing** (instrumented fire counter, per-instruction hook):
    winupack_Diskmon    harvests at fire 19.0M   -> oep 0x40b4b8 (truth)
    winupack_ShareEnum  harvests at fire 22.5M   -> oep 0x409013 (truth)
    winupack_Bginfo     harvests at fire 802     -> value fails the prologue gate, pick unchanged (cheap)
    Everything / FastHash_kr / HashCalc / mtinst harvest later than 25M fires
So the slot is parked DEEP into the run (tens of millions of instructions after the hop), which is why the hook must
stay armed; the earlier reasoning that "one indirect call happens per row" was true only of the rows sampled first.

**Bounding experiment, FAILED and reverted.** Tried to cap the hook's lifetime at 4M then 25M fires (to stop rows that
never harvest from paying). At 25M the family drops to OEP 89 / all-three 79 because four of the six harvesting rows park
the slot later than that; the bound cannot be small enough to save wall time and large enough to keep the harvest. Code
reverted with `git checkout` - nothing kept, the shipped unbounded-until-harvest form stands. The real fix would be a
cheaper trigger than a per-instruction hook (e.g. scanning the stack window at hop time and at API entries, both of which
are already cheap events), which is the next thing to try if this family is revisited.

#### 0.17ih Round 236: the WinUpack parked slot is already on the stack AT HOP TIME - the per-instruction hook is gone

Round 229 shipped the parked-slot harvest as a one-shot per-instruction code hook, because the reference reads the slot
at the stub's indirect call. Measured the frame at the hop instead: `TAOTE_HOPSNAP` printed the in-image dwords of the
stack window when a hop is accepted, and on SIX OEP-wrong rows the payload entry is already there, at stack slot [6]:

    winupack_Diskmon     hop 0x44bf1b   [1]=0x401000 [3]=0x43afff [6]=0x40b4b8   (truth)
    winupack_ShareEnum   hop 0x455403   [1]=0x401000 [3]=0x43ffff [6]=0x409013   (truth)
    winupack_Everything  hop 0x618c13   [1]=0x401000 [3]=0x597fff [6]=0x545f0d   (truth)
    winupack_FastHash_kr hop 0x4aa523   [1]=0x401000 [3]=0x478fff [6]=0x41dffa   (truth)
    winupack_HashCalc    hop 0x4a558f   [1]=0x401000 [3]=0x481fff [6]=0x411e58   (truth)
    winupack_mtinst      hop 0x10c437b  [1]=0x1001000 [3]=0x10a0fff [6]=0x1003866 (truth)

so no hook is needed at all: [1] is image base+0x1000, [3] a page-end scratch and [6] the hand-off record. Rows whose hop
IS the truth (Bginfo 0x5b5d42, Procmon 0x4755cb) carry no in-image slots at the hop, so nothing overrides them.

Two implementations measured:
- **Whole-window scan** (record every in-image dword at the hop, let the finalize pick take the LAST that validates):
  REGRESSED 8 already-correct rows (Bginfo, Contig, handle, junction, ntfsinfo, pipelist, ru, streams - family 81 -> 73,
  OEP 93 -> 85) because the window also carries [1] and [3], which can validate as prologues once the image is decoded.
- **Slot [6] only** (esp+0x18): family OEP 93 / imports 83 / all-three 81 - identical to the hook version - and the hook
  is gone, so the per-instruction TB cost disappears: Everything 39-56 s -> 23 s, Procmon 63 s -> 31 s, Bginfo back to
  its pre-change shape (solo 45.4 s; the 86 s readings are 4-worker load noise on a row that never harvests anyway).

Corpus r105 (2678 rows, 4 workers, 85 s budget): **2146 all-three, 0 losses** against r104 (the three raw-run losses -
aspack_Bginfo, nspack_Bginfo, rlpack_geek, all at dur 86 - came back solo at 14.7 s, 46.2 s and 66.7 s), WinUpack
93/83/81 identical. So the refactor is row-neutral and strictly simpler: one stack read at an event that already exists,
instead of a code hook that costs a translation-block boundary per instruction.

#### 0.17ii The hop-time parked slot does NOT generalise: 0 of 16 rows across eight families

The WinUpack win came from reading the stack window at an accepted hop, so the obvious next question was whether other
packers park their payload entry the same way. Added `TAOTE_HOPSNAP` (prints the in-image dwords of the stack window at
every accepted hop) and ran the first two OEP-wrong rows of every family where an OEP is still wrong, comparing the
window against the row's true entry:

    family          rows  hops seen  truth in window
    Amber              2       0            no
    Exe32pack          2       1,1          no
    NSPack             2       0            no
    PEtite             2       1,1          no
    TELock             2       1,1          no
    JDPack             2       0,1          no
    Themida            2       1,1          no
    Yoda-Protector     2       0            no

So WinUpack's hand-off record is a property of THAT packer (its stub builds a frame holding
[image base+0x1000, page-end scratch, payload entry]) and not a general packer idiom. `TAOTE_HOPSNAP` stays in the tree
as the cheap way to re-ask the question if a family ever becomes interesting again; the WinUpack gate stays as it is.

This also explains why the per-family "no section hop; OEP guessed" rows (Amber 13-ish, Yoda 88) cannot be fixed the same
way: they never accept a hop at all, so there is no frame to read.

#### 0.17ij Robustness of the shipped parked-slot path: no crashes with it forced on, and byte-identical reruns

Two invariants checked on the code shipped this block (a7f6660 / a840b48), because both are non-negotiable:

- **Host safety.** Ran one row from each of 23 families with `TAOTE_STACK_OEP_ALL=1 TAOTE_HOPSNAP=1` (i.e. the harvest
  and the snapshot active on EVERY family, the worst case the switches allow): 23 rows, 0 crashes, every exit code in
  {0, 124} and no sanitizer/terminate output. QlErrorBase containment holds on the new path.
- **Determinism.** `winupack_Diskmon` run twice: the rebuilt artifact and the image dump are byte-identical
  (`584d41e8...` / `93cd2556...` both times), so the hop-time stack read does not introduce run-to-run variance.

With the corpus at 2146/2678 (r105) and every lane closed by measurement, the remaining work is the decoder
differential described in 0.17ie/0.17hq: PEtite's 37 rows are the only pool with a byte-exact golden target, and
TELock's CRC oracle (0x311634a8) can score the same fix on another 100 rows.

#### 0.17ik api_db cannot cover the C++ mangled misses: the host SDK doesn't carry them

Followed up the imports-only pool (34 rows in r105) by looking at WHAT is missing rather than how many. Two distinct
classes, and only one of them looked fixable:

    amber_chglogon / jdpack_chglogon   5 kernel32 names: RegCloseKey, RegCreateKeyExW, RegOpenKeyExW,
                                       RegQueryValueExW, RegSetValueExW
    rlpack_calc                       25 names, 23 of them msvcrt C++ mangled (??0bad_cast@@QAE@ABV0@@Z, ?terminate@@YAXXZ,
                                       __setusermatherr, _acmdln, __pctype_func, _ftol2, sprintf_s, __CxxFrameHandler3)
    rlpack_Hash                        5 names: ??2@YAPAXI@Z, ??3@YAXPAX@Z, __setusermatherr, _acmdln, _adjust_fdiv

The mangled class looked like a generator bug: `tools/gen_api_db.py`'s `SYMBOL_RE` starts names with `[A-Za-z_]`, so NO
`?`-prefixed name could ever enter api_db (grep: 0 occurrences of `"?'` in the committed file). Widened it to
`[?A-Za-z_]` and regenerated: 460 new names (32,374 -> 32,834), all genuine C++ mangles ... and **0 of them cover a
single corpus miss**, because the names our rows need (`??0exception`, `?terminate`, `__setusermatherr`, `_acmdln`,
`__pctype_func`) are simply not in mingw-w64's import libraries at all:

    newly covered corpus pairs by the regenerated DB: 0 (across all 34 imports-only rows)

So the mangled gap is a property of the HOST's SDK tables, not of taote's generator, and widening the regex buys nothing.
Generator change reverted (nothing kept); the corpus run this would have cost was avoided by checking coverage first -
the same discipline as 0.17hk, and worth repeating for any "regenerate the data table" idea.

Remaining explanation for rlpack_calc/rlpack_Hash: those CRT names are only obtainable from the payload's own name
strings with DLL attribution from the stub's INT order - i.e. the same destroyed-information wall as the WinUpack
ordinals, not a table gap. The Reg* class (chglogon) is the same shape: the original imported them from KERNEL32 while
the host's tables file Reg* under advapi32/rapi/clusapi, so attribution by name alone cannot reproduce that caller-side
choice.

#### 0.17il PEtite's 4790-byte divergence decomposed: one missing fixup pass + one undecoded block

Followed the work order into the PEtite bit-reader differential, but classified the errors BEFORE looking at the
decoder, and the classification reframed the whole problem. Comparing taote's dumped `.text` against the not-packed
original (`petite_rrdec.exe` vs `rrdec.exe`, RVA 0x1000, 47896 bytes) at byte level:

    differing bytes 7484 in 1577 runs; run lengths 2 (841), 4 (648), 3 (55), 1 (5)

A run-length histogram dominated by EXACTLY 2 and EXACTLY 4 is the signature of a `rel32` displacement field, not of
literal or match-copy errors. Checking that directly: of the 1047 `E8/E9` sites in the golden `.text`, **1039 (99.2%)
carry a wrong displacement**, and for 1026 of them the error is exactly

    art_disp - gold_disp == (site_rva - 0x400)

i.e. a constant *per-site* shift equal to the offset inside the decoding block, not a random value. Applying the
stub's own transform offline - `dword[rva+1] -= (rva - 0x400)` at every `E8/E9`, `dword[rva+2] -= (rva - 0x400)` at
every `0F 8x` - takes the difference from **7484 bytes in 1577 runs to 3052 bytes in 25 runs**, and every remaining
run lies in one contiguous region: **`.text` from 0xaf14 to the end (0xc04 bytes)**, which in the artifact is still
compressed/encrypted garbage.

So PEtite's residual is exactly two unimplemented packer steps, and neither is an arithmetic error in the decoder:

1. The **block fixup pass**. The stub's own code for it is in the artifact at `0x40d38e-0x40d3cf` (it is runtime-written:
   the packed `.petite` raw data covers only RVA 0x1000-0x8a00, so 0xd38e can only be produced by the decryptor):

       40d38e  mov  ebx,[esi+4]      ; block size
       40d391  sub  ebx,6
       40d394  xor  edx,edx          ; edx = offset inside the block
       40d396  mov  al,[edx+edi]
       40d39b  cmp  al,0xe8 / 0xe9   -> 40d3ad
       40d3a3  cmp  al,0x0f
       40d3ad  sub  dword [edx+edi+1],edx      ; E8/E9: disp -= offset
       40d3c5  sub  dword [edx+edi+2],edx      ; 0F 8x: disp -= offset
       40d3d2  pop ecx / pop esi / std ...      ; the pass ends and the stub resumes

   Note the guard above it: `mov ecx,[esi+0xc]; sar ecx,1; push ecx; jb 0x40d38e` - the fixup path is selected by
   **bit 0 of descriptor field [esi+0xc]** (odd => fixup, even => the `rep stos` zero-fill branch below), so a faithful
   host reimplementation must read that flag rather than guessing.

2. One **undecoded block**: the region from `.text+0xaf14` to `.text`'s end never gets decoded, which is also why the
   8 `E8/E9` sites that do not fit the transform all live there.

`TAOTE_PROBE=0x40d3ad` (the fixup store) fires **zero times** on `petite_rrdec.exe`, and the run ends at
`final pc=0x100211e0` (the ExitProcess cell) with `oep=0x417214 reason=section_hop` - i.e. the stub takes its error
path before reaching the fixup stage, which is the SAME root cause as the parked "Corrupt Data!" guard recorded in
0.17hz: the block loop stops early, so the tail block is never decoded and the fixup pass never runs.

Consequence for planning: PEtite is not a bit-reader arithmetic problem (0.17hn's framing) and an offline decoder
differential is the wrong tool. The unit is the block loop's early exit; when it is fixed, the fixup pass and the tail
block both come with it, and byte-exactness (reference: 0 of 47896 differing) becomes achievable. Recorded with the
transform verified offline so the next round does not have to rediscover it.

#### 0.17im PEtite's block table located: 6 blocks measured, and the .text block under-fills

Instrumented the PEtite block loop instead of the decoder. `TAOTE_PROBE=0x4171e7` (the return pc of the block
decompressor call at 0x4171e2, 0x417214 being the decompressor itself - which is also the entry taote wrongly claims)
prints, per block, the advanced source pointer in eax, the block's destination in edi, its end in ecx/edx and the
descriptor pointer in ebx. `petite_rrdec.exe` decodes SIX blocks, in this order:

    #  dst        dst_end     src_end     result   descriptor (ebx)
    1  0x414000   0x4147ff    0x408863    ok       0x41864c
    2  0x415000   0x41500b    0x408873    ok       0x41865c
    3  0x401000   0x40cb14    0x411596    ok       0x418678   <- .text, 0xbb14 bytes
    4  0x40d000   0x40d3e0    0x411875    ok       0x418688   <- .data
    5  0x40e000   0x4117f3    0x412ffd    ok       0x418698   <- .rdata
    6  0x400000   0x4006a4    0x400005    **FAILS** 0x4186b8   <- original headers

so the destinations are the payload's headers, .text, .data, .rdata, .idata and .CRT, and the two sections PEtite
never copies (.bss/.tls) are simply absent from the list.

The descriptor table is **static data in the packed file at RVA 0x18640** (file offset 0x1a40, inside the stub
section), with VARIABLE-LENGTH records: ebx always equals record_start + 0xc, and the record starts are 0x18640,
0x18650, 0x1866c, 0x1867c, 0x1868c, 0x186ac - i.e. strides 0x10, 0x1c, 0x10, 0x10, 0x20. A four-dword record reads
`{size-1, dst_rva, x, src_end_fileoff}` - block 3 is `{0xbb14, 0x1000, 0x9d9, 0x11596}` at 0x1866c, block 1 is
`{0x7ff, 0x14000, 0x1002, 0x8863}` - and the longer records (block 2's is seven dwords) carry extra trailing dwords,
which is what the variable stride is. Reading the table from the PACKED file is required: in the artifact the same
addresses are overwritten (the stub's data stage lands on top of its own table), which is why an earlier attempt to
parse it post-run produced garbage.

Two concrete defects, both inside block 3 and block 6:

1. **Block 3 under-fills.** Its destination range is 0x401000-0x40cb14 and it returns success, but only the first
   0x9f14 bytes are real: `TAOTE_WATCH=0x40af14` shows the bytes there arrive from `pc=0x417206` - the `rep movsd`
   of the stub's memcpy helper - carrying STALE STACK values (0x40b129 gets 0x8b08458b), so the decoder produced
   fewer output bytes than the block's size and the copy then moved uninitialised stack over the tail. That tail is
   exactly the region 0.17il measured as undescribed (`.text+0xaf14` to the end, 0xc04 bytes).
2. **Block 6 fails** (returns 0). The decompressor's chunk-type dispatch at 0x4172a1 is
   `and ecx,7 / shr ecx,1 / je 0x4172cb / dec ecx / jne 0x4181c7`, and 0x4181c7 is the `xor eax,eax / pop / leave /
   ret` failure exit - so the header block's stream presents a chunk type >= 2, while 0x4181cb (`mov eax,[ebp+8]`)
   is the success exit. This is the same failure as the parked "Corrupt Data!" guard, now localised to one block.

Note the addressing coincidence worth checking first next round: the stub reads its compressed stream at
`base + FILE offset` (0x408863 = file 0x8863), and the packed file's `.petite` has raw_ptr 0x1c00 for rva 0x1000, so
file offset and RVA differ by exactly 0xc00 - the same constant that appeared in 0.17il's per-site E8/E9 delta. If
taote maps the packed file by RVA, the stream the stub reads is offset by 0xc00 from what the packer meant, which
would explain BOTH an under-filled block and an invalid chunk type downstream.

#### 0.17in PEtite's .text block consumes its WHOLE input and still decodes short

Probing the decompressor's entry (`TAOTE_PROBE=0x417214`, stack window shows the cdecl args at [esp+4..0xc]) gives
each block's arguments exactly, and they chain: every block's `src` is the previous block's `src_end`.

    #  src        dst        size     src_end (table)   decoder returned
    1  0x4085a1   0x414000   0x7ff    0x8863            0x408863  ok
    2  0x408863   0x415000   0xb      0x8873            0x408873  ok
    3  0x40ba5c   0x401000   0xbb14   0x11596           0x411596  ok   <- .text
    4  0x411596   0x40d000   0x3e0    0x11875           0x411875  ok
    5  0x411875   0x40e000   0x37f3   0x12ffd           0x412ffd  ok
    6  0x400005   0x400000   0x6a4    0x4005            0x400005  FAIL (returns 0)

The decisive number is block 3: its input is 0x11596-0xba5c = **0x5b3a bytes and the decoder consumed ALL of it**
(it returned exactly the table's src_end), yet it produced only **0x9f14 of the 0xbb14** bytes the caller asked for.
So the stream ran out before the output did - this is not a mid-stream desync that leaves input unread.

Worse, the shortfall is silent: the decoder fills a stack buffer, and the stub's memcpy (`0x4171f5`, `rep movsd` at
`0x417206`) then copies the FULL declared 0xbb14 bytes, so the missing 0x1c00 bytes become stale stack memory.
`TAOTE_WATCH=0x401004` and `=0x40af14` both report that the ONLY writer of `.text` is `pc=0x417206` - the decoder
itself never writes the destination - which is why the corruption looks like random data rather than zeros.

The golden tail is not the answer either: over rva 0xc000-0xcb18 the original holds 630 zeros of 2840 bytes plus real
data (import strings `libgcc_s_dw2-1.dll`, `__register_frame_info`, and pointer tables), against 208 zeros in our
artifact, so a "zero the remainder" step cannot manufacture it. The tail must come out of the stream.

Next unit, sharpened: block 3 decodes 85% of its output from 100% of its input, so instrument the decoder's OUTPUT
counter rather than its input pointer - find the iteration where the output advance stops and dump the bit-model /
window state there (the frame is 0xbad8 with the 0x8000-byte window at [ebp-0x8078] and the probability array from
[ebp-0x78]); block 6 gives the same harness a failure verdict (chunk type >= 2 => `xor eax,eax` at 0x4181c7).

#### 0.17io PEtite emits in 0x8000 chunks through one scratch buffer - and every row decodes imperfectly

Two more facts, both needed before any decoder work:

**The output path.** `TAOTE_PROBE=0x417206` (the `rep movsd`) shows the destination is never written by the decoder
itself; every byte arrives through ONE scratch buffer at **0x5004572** and the stub runs with its own relocated
frame (`ebp=0x5000aee`), not the main stack. `.text` is copied in **0x8000-byte chunks** (`ecx=0x2000` dwords,
`[esp]=0x8000`):

    block 3 chunk 1: esi=0x5004572 -> edi=0x401000, 0x8000 bytes   (clean)
    block 3 chunk 2: esi=0x5004572 -> edi=0x40a000, 0x3b14 bytes   (0x1f14 real, 0x1c00 stale)

So the stale region 0.17il/0.17im measured is exactly the tail of the SECOND chunk: 0x8000+0x1f14 = 0x9f14, matching
the observed boundary. Combined with 0.17in (the decoder consumed 100% of its input and still returned success), the
decoder stops on a CONDITION inside chunk 2 while its produced prefix is byte-correct - it is not diverging
arithmetically, so a "find the bad opcode" differential would be looking in the wrong place.

**How big the job is.** Scanning all 73 PEtite rows' `.text` against their originals:

    rows where `.text` is byte-identical: 0 of 73  (so no row is "decoded but mis-picked")
    rows with a continuous garbage tail:  44 of 73  (tail length: median 6 bytes, max 1785)
    first-section differing bytes:        2252 (petite_RegDelNull) ... 60730 (petite_7z)

`petite_rrdec` is therefore a GOOD row (its 0x1c00 tail is atypical); the family's divergence is per-row and
stream-dependent, and it is uniformly present. That retires the hope that some PEtite rows are picker-bound: the
whole pool is decode-bound, exactly as 0.17ii concluded, and the OEP work cannot start until `.text` is exact.

#### 0.17ip shipped: the verbatim-dump fallback now emits a FLAT section table (valid PE 2676 -> 2677)

The only remaining artifact defect that was not decode work. `rebuild_pe` has a documented fallback for images whose
header cannot be laid out (the Exe32pack "degenerate" contract): write the loaded image verbatim. But a loaded image
is FLAT - its bytes live at their RVAs - while the section table it carries still describes the PACKED file, whose
`PointerToRawData` points into the compressed data. Written verbatim, such an artifact parses but its entry maps
nowhere, and the grader reports `entry-not-mapped` rather than the truth: the dump is fine, the header is lying.

Corpus r105 had exactly ONE such row (`alienyze_tinytask.exe`; `grep -l "rebuild failed" *.log` = 1 of 2678), so this
is a small, safe fix rather than a family seam: `flatten_image_pe` (unpack.hpp/unpack.cpp) rewrites every section's
`SizeOfRawData = align_up(vsize ? vsize : rsz, FileAlignment)` and `PointerToRawData = VirtualAddress`, sets
`SizeOfHeaders` to the aligned first-section RVA, refuses to claim bytes past EOF, and returns `{}` (leaving the old
behaviour) when the header is unusable or already flat. It only runs on the fallback path.

Measured, corpus r106 (2678 rows, 4 workers, 85 s budget, 120 s wall):

    all-three 2146 -> 2146      valid PE 2676 -> 2677      OEP 2180 -> 2180      imports 2223 -> 2223
    valid-PE flips: 1, and it is the intended row: alienyze_tinytask.exe False -> True
    raw run read 2144 with 2 losses (nspack_Bginfo, rlpack_geek, both dur 86); re-run solo they are all-three at
    45.5 s and 68.8 s, so the referee is 0 gains / 0 losses.

The artifact for that row now parses sanely (`pe_is_sane` -> `''`, `.alien` raw=0xb000 covering the entry at 0x105e0);
its OEP and imports are still wrong because the row takes `stages=0 reason=fallback_guess imports=0`, i.e. the stub
never ran - that is decode work, tracked with PEtite, and the row is managed (.NET) so it cannot be all-three anyway.

`UNPACK_REPORT.md` was regenerated from r106 and the two contention rows patched in, so the shipped report matches the
committed harness artifacts.

#### 0.17iq CORRECTION to 0.17il-0.17io: the analysis sliced the artifact by FILE OFFSET, not by RVA

The four PEtite sections above (0.17il-il through 0.17io) compared the artifact with
`art_bytes[0x1000 : ...]`, i.e. a slice of the artifact FILE starting at file offset 0x1000. The artifact's
`.petite` section has `VirtualAddress=0x1000` but `PointerToRawData=0x400`, so that slice actually begins at
**RVA 0x1c00** - every comparison was shifted by 0xc00. The old standing rule about offline scans ("slice section
bytes through the section table by virtual size from the raw offset") is exactly what was violated, and the
symptom is unmistakable in hindsight: the very first numbers (4790 differing bytes, first difference at 0x54) were
right in earlier rounds and became 7484 / offset 0x84 when the slice was wrong.

Corrected numbers, `.text` of `petite_rrdec.exe` vs `rrdec.exe` (proper rva2off slicing, 47896 bytes):

    differing bytes 4790 in 1672 runs   (lengths: 2 -> 902, 4 -> 702, 3 -> 55, 1 -> 13)
    first difference at +0x54, last at +0xbb17
    3359 of the 4790 lie inside an E8/E9 displacement field; with 0F 8x added the "outside" count is **4**
    (those 4 are +0xbb14..0xbb17, past .text's last real byte - a 4-byte copy overrun)

So the CORRECT conclusion is stronger than what was published: **every single differing byte is a relative
displacement field** (E8/E9 call/jmp or 0F 8x jcc). The payload's code and data are byte-correct; only branch
targets differ. The earlier "one missing fixup + one undecoded block", "tail from 0x9f14", "stale stack tail" and
"0 of 73 rows decode exactly" claims were all artifacts of the 0xc00 shift and are WITHDRAWN. In particular the
`.text` block is not under-filled: the dump holds three complete chunks (0x8004 + 0x3434 + 0x6e4, destinations
0x401000 / 0x409000 / 0x40c433), and chunk 3 differs in only 139 bytes.

**The transform is verified exact.** Scanning a code section exactly as the stub's loop does and subtracting the
in-block offset from every relative field:

    dword[i+1] -= i   at E8/E9        dword[i+2] -= i   at 0F 8x     (i = offset from the block's destination)

    petite_rrdec .text   4790 differing bytes -> 4
    petite_7z    .text   9794 differing bytes -> 0     (byte-identical to the original)

which is precisely the pass the stub's own code at 0x40d38e performs - confirming it never runs in taote's runs
(`TAOTE_PROBE=0x40d3ad` has zero hits).

**What still blocks shipping: the gate.** Applying the transform to every row is wrong, because the pass DOES run
on some rows:

    rows where the transform reduces the difference: 48 of 73   (rrdec, 7z, 7za, 7zFM ...)
    rows already byte-exact (transform already applied): 25  - applying it there destroys the section
        (petite_HDDScan +391984 bytes, petite_FastHash_kr +28397, petite_Diskmon +5818)
    worst case for a blind rule: -40.4% instead of +; so a per-row gate is mandatory.

Two candidate gates were measured and both FAIL:
 - *target plausibility* ("apply if it lowers the fraction of relative targets outside the image"): tp=26 fp=0
   **fn=17** - useless, because the E8 bytes found inside embedded DATA contribute a constant set of nonsense
   targets that is bad before and after, and because the code section (0x6f18 on AccessEnum) is small against the
   image (0x2a000), so a per-site shift of at most one section length usually still lands in-image;
 - *correlation between displacement and site offset* (should be ~+1 pre-fixup, ~0 after): both groups measure
   -0.13..+0.16, i.e. no separation at all.

The gate therefore has to be RUNTIME, not structural: the stub's fixup writes into a block's destination AFTER
that block's memcpy, so "a write landed in a code block after its copy completed" is the observable that says the
pass ran. That detector is the next unit; with it, PEtite's `.text` becomes byte-exact on the 48 pre-fixup rows,
which is the precondition for the OEP picker on the whole family.

#### 0.17ir shipped: PEtite's self-relative block transform is undone, self-gated (43/73 rows, 0 regressions)

The correction in 0.17iq established that PEtite's *entire* byte divergence is relative-displacement fields, and that
the stub's own pass at 0x40d38e - which subtracts the in-block offset from every E8/E9/0F8x displacement - does not
run in taote's emulation on most rows. This ships the undo, `undoSelfRelativeBlockTransform`:

    scan one section continuously, exactly as the stub does (5 bytes after E8/E9, 6 after 0F 8x)
    section gate : collision share of call targets, shift-0 vs shift-1  -> accept when it rises
    page  gate   : accept a 0x1000 page only inside an accepted section AND when its own share is < 0.10
    rewrite      : dword[i+1] -= i at E8/E9, dword[i+2] -= i at 0F 8x   (i = section-relative offset)
    family gate  : opts_.family == "PEtite" (one call site, unpack.cpp:3851)

Three properties had to be measured into the gate, each from a failure:

  * the MZ byte must not be required - PEtite's stub zeroes the in-memory header (the dump starts `00 5A`), so an
    MZ check made the function a no-op;
  * section characteristics must not be used - the dump keeps the PACKED section table, whose characteristics are
    cleared (all five sections read chars=0 on petite_rrdec), so an "executable section" filter also no-oped;
  * a PAGE-only gate fires on already-correct code, where the collision share is already high: measured false
    positives at c0 = 0.375, 0.533, 0.396, which turned 9 rows from code_sim 1.0 into 0.9968-0.9991. Adding the
    section-level decision and the page `c0 < 0.10` cap removed all of them (0 worse).

Measured, the whole PEtite family (73 rows, r106 parameters, 4 workers):

    mean code_sim            0.9346 -> 0.9872
    rows with code_sim>=0.99 25 -> 55
    rows improved 43, unchanged 30, worse 0
    rows  n=73 PE=73 OEP=36 IMP=36 ALL=30   (identical to the r106 baseline: this is a fidelity fix, not a row fix)

Byte-exactness where it fires: `.text` vs the original differs 4790 -> 4 bytes on petite_rrdec, 9794 -> **0** on
petite_7z; the residue is 3-4 bytes at the very end of the section (the block copy overruns the last real byte by
one dword), which is a separate, cosmetic defect.

Determinism and safety: petite_rrdec run twice gives byte-identical artifacts (md5 42bebada... artifact / d0e17e5a...
dump), and all 73 family runs exited 0 with no sanitizer or terminate output.

The change is contained to the family by construction (single `opts_.family == "PEtite"` call site), so the full
corpus was not re-run: every row the code can touch is in the 73-row arm above, and that arm is row-for-row identical.

New test pins it: `UnpackCompat.PetiteSelfRelativeTransformIsUndoneOnlyWhenPrestaged` - a synthetic image with 24
E8 sites that all target one address once undone, in both pre-transform and already-correct form (the second must be
byte-unchanged), plus junk and tiny-image inputs (never crash, never rewrite). Suite 607/607.

#### 0.17is does exact `.text` unlock PEtite's OEP? No - the stub never hands off, because block 6 fails

Followed 0.17ir straight away: with `.text` byte-exact on the 43 pre-transform rows, the ladder sees real code for
the first time. Measured the whole family with `TAOTE_UNPACK_DEBUG=1` (73 rows, 4 workers) and parsed every ladder
report:

    rows emitting a passB line        54 of 73
    rows with passB hits > 0          17     (before 0.17ir: 0 - the ladder found nothing at all)
    pick already correct              17 of the 54 non-managed rows
    truth == first hit                 8
    truth == last hit                  6, and on 4 rows that is NOT what the ladder picks
        (petite_7z 0x40ebc5 vs claim 0x40e924; petite_7za-family 7zFM/7zFMn; petite_AccessEnum 0x407a98 vs 0x403a53)

So exact `.text` does put the truth into the candidate list on a handful of rows, but the obvious ranking rules are
all dead ends: "take the last hit" is **+4 / -15** over the 54 rows (it breaks FastHash_kr, pssuspend, PEview,
adrestore, ldmdump, ctrl2cap and nine more that the current pick gets right), and on 41 rows neither the first nor
the last hit is the truth at all. This is the same shape the JDPack census found (truth present, no ordering rule),
so the picker lane stays closed.

**The real blocker is upstream.** `exec PAYLOAD` traces show the emulation only ever executes the STUB
(0x41710b -> 0x417137 -> 0x417175 -> ... on rrdec, 0x4181xx on 7z); not one execution lands inside the decoded
`.text`. The payload is decoded correctly and then never runs, because the stub decides the image is corrupt: block 6
(the original headers, dst 0x400000, size 0x6a4) returns 0 from the chunk-type dispatch at 0x4172a1 -> 0x4181c7
(0.17im). That is why there is no runtime hand-off to read - the PEtite equivalent of the WinUpack parked slot does
not exist until block 6 decodes.

So the PEtite order is now unambiguous: (1) block 6's invalid chunk type, (2) then a runtime hand-off becomes
observable and the OEP can be read instead of guessed, (3) the 3-4 byte end-of-section copy overrun is cosmetic and
last. The 17 rows that already pick the truth are unaffected by any of it.

#### 0.17it PEtite block 6 fails with a bit reservoir that cannot come from its source (parked with a precise question)

Chased the block-6 failure from 0.17is. Established:

  * block 6's arguments are `src=0x400005, dst=0x400000, size=0x6a4` (the ORIGINAL headers), and the decoder
    returns eax=0 having consumed **zero** input bytes (the src slot still reads 0x400005 at the failure) and written
    **nothing**: `TAOTE_WATCH` over 0x400000/0x400100/0x400400/0x400600 shows exactly one write in the whole header
    region - `pc=0x417217` writing 0x00 to 0x400000, i.e. the stub zeroing the in-memory MZ, not block 6's output.
  * the failure is the `xor eax,eax` exit at 0x4181c7 reached from the chunk-type dispatch at 0x4172a1, and the probe
    there reports `ebx=0x6ca5, edi=0x20, esi=3, eax=0x905a`.
  * `(ebx & 7) >> 1 = 2` is the invalid type that fails, so the reservoir's low bits are `0b101`.
  * BUT the source bytes cannot produce it: `TAOTE_PROBE_EBP_DISP=8` confirms `[ebp+8] = 0x400005` at the failure,
    and the image at 0x400005 is `00 00 00 04 ...` (the dump matches the packed file byte for byte there - only the
    MZ is zeroed), and **nothing writes to 0x400005 at any point** (`TAOTE_WATCH=0x400005:4:8` is silent).
    The refill loop at 0x417288-0x41729e reads `movzx edx,BYTE PTR [ecx]` from `[ebp+8]` and shifts it in at bit
    position edi, with `ebx` zeroed at 0x417245 on entry - so a first dispatch over 00 bytes must see ebx == 0.

That contradiction is the question to answer next: the dispatch is reading a reservoir that did not come from the
bytes at `[ebp+8]`. Two candidate explanations, both cheap to test with a probe on the refill loop
(0x417288/0x41728e/0x417297):

  1. the failing dispatch is NOT the first one (the `test eax,eax / jne 0x4172e7` path re-enters with a state
     variable, and `ebx` then holds bits buffered by an earlier iteration whose source came from somewhere else);
  2. the argument slot is re-read per iteration (`inc DWORD [ebp+8]`), so a partially-consumed pointer plus a
     restore elsewhere could hide the real reads.

Block 6 matters because it is what stops the payload from ever running (0.17is), and only then does PEtite expose a
runtime hand-off to read the OEP from - the family's 37 OEP-wrong rows hang off this one block.

#### 0.17iu block 6 fails the 16-bit complement guard - and its source cannot satisfy it

The predecessor diagnostic settles which edge of the shared failure exit was taken. New tool: `TAOTE_PROBE_PREV=1`
records the pc that LED to a probe hit (a second code hook that skips the probe address itself), because PEtite's
failure exit at 0x4181c7 has ten edges and the register state alone cannot name the check. With it:

    [probe] pc=0x4181c7 ... ebx=0x6ca5 edi=0x20 esi=0x3 eax=0x905a
    [probe]   prev_pc=0x417327

0x417327 is the jne of the **16-bit complement guard**:

    417319  mov  eax,ebx
    41731b  not  ebx
    41731d  and  eax,0xffff
    417322  shr  ebx,0x10
    417325  xor  ebx,eax
    417327  jne  0x4181c7        ; fail unless high16 == ~low16

which is the same guard recorded for this family in the parked PEtite notes - now localised to block 6 and to an
exact instruction. Correcting 0.17im/0.17it: **the header block does not fail on the chunk-type dispatch**; it
reaches this guard first and fails there (`ebx` is the post-xor residual 0x6ca5).

Why it fails: at 0x417302-0x417317 the guard fills a 32-bit reservoir from `[ebp+8]`, which is 0x400005, and the
image there is `00 00 00 04` (dump == packed file byte for byte, only the MZ is zeroed, and `TAOTE_WATCH` proves
nothing ever writes to 0x400005). So W = 0x04000000, low16 = 0x0000, ~low16 = 0xffff, high16 = 0x0400 - not equal.
Scanning the first 0x2000 bytes of BOTH the packed file and the dump for any 4-byte window that satisfies
`high16 == ~low16` finds only trivial ones (0xffff / 0xffff0000 at offsets 0xa-0xc), so the header block's stream is
simply not in the header page the stub is reading.

Conclusion: in taote's emulation the header block is handed `src = base + 5` - a pointer at the packed DOS header -
and the complement guard rejects it. Two candidate explanations, and they are distinguishable:

  1. the stub computes that pointer from the descriptor's src field, which reads 0 for this record, so an addition
     of 5 somewhere turns "unset" into "the DOS header" - i.e. the loop is iterating one record past the real table
     and block 6 is a bogus iteration (the real table's last useful entry is block 5);
  2. the stream really is at the DOS header but must first be decrypted in place, which our run never does (no
     writes in the region except the MZ zeroing).

Either way the payload is decoded correctly and then never runs, which is why PEtite has no runtime hand-off to read
its OEP from. Parked here with the exact instruction, the exact edge, the exact bytes and the two candidates.

#### 0.17iv block 6 excludes every local explanation - the next step needs the reference implementation

Followed the two candidates from 0.17iu to their end, and both are now excluded by measurement:

**The record is real, not a bogus iteration.** The loop visits six records and the packed header has five
sections - one record per section plus the header area - so the count is right. What is wrong is the SOURCE: every
block chains (`src` of block N is the `src_end` of block N-1: 0x4085a1 -> 0x408863 -> 0x40ba5c -> 0x411596 ->
0x411875 -> 0x412ffd), but **block 6 breaks the chain** and reads `base+5` (the packed DOS header) instead of
0x412ffd. Its descriptor's source fields are zero, so whatever expression produced `base+5` turned "unset" into
"the DOS header".

**The bytes it reads cannot satisfy the guard, in either image.** `complement_ok(W@5) = false` on BOTH the packed
file and the not-packed original (they are byte-identical for the first 16 bytes: `4d 5a 90 00 03 00 00 00 04 ...`),
so this is not "our dump lost the original headers" - the original headers would fail the same test.

**The chained pointer does not work either.** The dump at 0x12ffd reads `eb 93 3d 00 ...` (W = 0x003d93eb,
`complement_ok = false`), and there is **no** complement-valid 4-byte window anywhere in 0x12000-0x16000. So the
header stream is not "the chained stream, off by five bytes" and not anywhere else we can account for after the run.

**What the failure does.** The stub consequently takes its error path (the `Corrupt Data!` MessageBoxA that the
parked notes recorded for this family) and never transfers control to the payload: `exec PAYLOAD` traces for rrdec
and 7z show only stub addresses, and no execution ever lands in the byte-exact `.text` that 0.17ir produces.

That closes local analysis of PEtite: the input bytes are not ours, the record count is right, the chain hypothesis
is dead, and no complement-valid stream exists in the image. The next step has to be external - either build
`../pegasus` and run this row to see which block its emulation feeds where, or park PEtite's OEP pool and take a
different family. Everything about PEtite's DECODE is settled (0.17iq-0.17ir: the payload is byte-exact on 43 of 73
rows, and the family's 30 all-three rows come from the 17 that already pick the truth plus the ones whose claim is
accepted).

#### 0.17iw REFERENCE RUN of petite_rrdec: taote is 4 bytes from the reference, and block 6 is not a defect

A prebuilt reference exists on this machine (`../pegasus/build/cli/pegasus-cli`) and settles three open questions
at once. `pegasus-cli -t packed/PEtite/petite_rrdec.exe --unpack` produces a same-sized (0x19000) memory dump.

  * **Decode**: the reference's `.text` at RVA 0x1000 is byte-identical to the not-packed original (0 of 47896
    differ). taote's is 4 bytes off, and those 4 are the known end-of-section copy overrun (0xbb14-0xbb17). So the
    shipped fixup (0.17ir) puts taote within four trailing bytes of the reference on this row - it is no longer an
    "approximation of an unknown transform".
  * **Block 6**: the reference's dump carries the PACKED header as well - `e_lfanew = 0xa8`, MZ restored, i.e. it
    does NOT decode the original headers either. So block 6's complement-guard failure (0.17iu/0.17iv) is NOT a
    taote defect: both implementations end up with the packed header. That line is closed, not parked.
  * **OEP**: the reference reports `oep = 0x401160` (the truth), `oep_last_hop = 0x401160`, `stages = 3`,
    `reason = petite_terminal_full_fill`. `oep_last_hop` equal to the entry means its emulation **does** reach a
    hand-off into the payload, three stages deep, whereas taote's run executes only stub addresses and stops at
    `stages = 1 reason = section_hop`. So there IS a divergence to chase, and it is after the decode: the stub runs
    further in the reference and hops to 0x401160.

Next unit, with a working oracle for the first time: get the reference to explain that hop (its `SE_DEBUG_RECON=1`
output does not include hop lines for this row - only `[petite-iat]` - so the next step is to find the reference's
hop/stage logging switch or read `src/unpacker` for where `petite_terminal_full_fill` sets `oep_last_hop`), then
compare taote's stage-1 stop against it. The 37 OEP-wrong PEtite rows are all downstream of that one difference.

#### 0.17ix the reference's PEtite OEP is an EP-exit SECTION-TRANSITION WALK, not a hop; and the two runs diverge on block 6 only

Correcting 0.17iw point 3: `meta.oep_last_hop` is NOT a runtime hop. `petite_unpacker.cpp:502-509` sets
`meta_.oep = keep; last_oep_ = keep;` after `dump_module(keep, "petite_terminal_full_fill")` - the field simply
mirrors the kept value. `stages = 3` counts recon stages, not hops.

What actually produces the reference's OEP is its EP-exit walk, which it prints under `SE_DEBUG_FINALIZE`:

    [pet-epexit] transitions=3 keep=0x40d07c junk=1
    [pet-epexit] t[0] from=2 to=3 addr=0x40d07c t=1774078
    [pet-epexit] t[1] from=3 to=2 addr=0x417102 t=2246804
    [pet-epexit] t[2] from=2 to=3 addr=0x401160 t=2247679
    [pet-epexit] cand i=2 to=3 addr=0x401160 t=2247679 lastwr=74585
    [pet-epexit] consuming transition 0x401160 (shape=1) (was keep=0x40d07c)

i.e. it keeps a section-transition history over the whole run, walks it BACKWARD, and takes the last transition into
a section that is never left again, provided the target has a plausible prologue shape (`shape=1`). 0x401160 is
the truth. taote has no `sec_trans_hist_` counterpart (only the env-gated `TAOTE_SEC_TRANS` diagnostic, which
recorded ONE transition on this row where the reference records three).

The two emulations, compared with `SE_DEBUG_HOP=1` against taote's traces:

    reference: 479,554 hops. Starts with the SAME stub addresses taote runs (0x41710b, 0x417137, 0x417175,
               0x417179, 0x41717b, 0x417186), then executes decoded .petite/.text code extensively
               (0x401302, 0x40caf3, 0x40ba92, 0x40d34d ...), and first reaches 0x401160 at hop 479477.
    reference: 0x417214 entered SIX times, 0x4171e7 returned five, and **0x4170ce - the error reporter - is
               never executed**.
    taote:     executes the same first stub addresses, then block 6's decode returns 0 and the stub takes
               `test eax,eax; je 0x4170ce` straight into the error reporter (`TAOTE_APIDBG` shows
               MessageBoxA pc=0x100a1330 ret=0x4170f1, and the last executed pcs are the reporter 0x4170ea-0x4170f3),
               then ExitProcess. Not one decoded code byte ever runs.

So both implementations make six decompressor calls; the ONLY asymmetry is the outcome of the last one, and it is
what separates a run that executes the payload from one that pops "Corrupt Data!". Everything else about PEtite in
taote now matches the reference (0.17iw: .text within 4 trailing bytes of byte-exact).

Next unit: capture the reference's per-call arguments for the sixth call (SE_DEBUG_HOP prints only
addr/sec/wr_n, so this needs either a trace switch in pegasus or reading its descriptor loop), and compare the src
it passes. That one comparison decides whether block 6 is fed a different stream (port the argument rule) or
tolerated on failure (port the tolerance) - and either way the EP-exit walk is the second deliverable, since it is
what turns a running payload into an OEP without any candidate-class guessing.

#### 0.17iy the reference REPO documents PEtite's root cause, and taote has the exact defect it names

`../pegasus/docs/PETITE_ROOTCAUSE.md` (204 lines, 2026-09-25 -> 10-05) is the missing half of everything this
session measured about PEtite. Its causal chain, and taote's state for each link:

1. The stub does `GlobalAlloc` + `VirtualProtect(0x400780, 0x880, RW)`, restores the original PE-header fragment
   with `rep movsd`, then `VirtualProtect(.., RO)`. **taote's VirtualProtect is a stub that returns 1 and changes
   nothing** (`qiling/os/windows/dlls/kernel32/memoryapi.cpp:96-103`), so the header page never becomes read-only.
2. The decoder's 4th emit writes a byte to the IMAGE BASE (`mov [edi],al`, 0x417217 here / 0x418217 there).
   Natively that write **FAULTS** (header page RO) and the stub's SEH handler at 0x4144a5 takes over - the decode
   is exception-driven. "Our engine swallows the fault ... the stub never sees the AV and takes the WRONG decode
   path - that is the whole divergence." Measured in taote this round: `TAOTE_WATCH=0x400000` reports
   `pc=0x417217 addr=0x400000 value=0x0` - the write SUCCEEDS, which is exactly the swallowed-fault state.
3. The handler chain must be seeded for the pivot to work: the reference's resolution is a **SELF-REFERENTIAL
   frame (F.Next = F)**, so `mov ebx,[ebx]; lea esp,[F-0x52]` lands on the walker's own `pushal` area with
   `esi` = the decryptor's state-table pointer, and the seed's context cell must hold `img->base`. The walker sets
   TF (`pushal; pushf; btc [esp],8; popf`), so every instruction #DB-traps and the per-trap handler at 0x414776
   walks a 0x10-stride table: bit31 entries are copy ops (`mov al,[edx+edi]`), clear entries zero-fill
   (`rep stosd/stosb` at `[esi+8]+ebp+[esi+4]`).
4. With that, the payload runs, and the OEP comes from the **EP-exit section-transition trail**
   (`sec_trans_hist_`, last 64 transitions with instruction stamps + `sec_last_write_insn_`), walked backward,
   prologue-shape-gated - the mechanism 0.17ix measured live (`[pet-epexit] consuming transition 0x401160`).

The reference's A/B numbers on its own 75-sample PEtite census make this the biggest documented lever in the repo:
decode fix **CODE-FULL 21 -> 46** (7z: 9,794 wrong .text bytes -> 0, imports 6 -> 112), then the transition trail
**oep=OK & CODE-FULL 33 -> 68 (+35 exact-OEP recoveries)**, with two flips queued.

Taote's position: 0.17ir's host-side transform undo already reaches byte-exact `.text` WITHOUT any of this (rrdec
4790 -> 4, 7z 9794 -> 0, mean code_sim 0.9346 -> 0.9872) - so items 1-3 are not needed for BYTE-EXACTNESS here.
They are needed for the payload to RUN, which is the precondition for item 4 and therefore for the family's 37
OEP-wrong rows.

Work order for the next session, in dependency order:
  a. honour VirtualProtect (at least PAGE_READONLY / PAGE_EXECUTE_READ) and dispatch a REAL guest AV on a write to
     a protected page instead of completing it - the reference's `SE_PROT_SEH` gate, whose default-off state was a
     historic artifact (it now dispatches either way);
  b. seed the SEH chain self-referentially for `.petite` images with the context cell = image base;
  c. verify the int1/TF storm runs to completion (the reference needs ~15,600 iterations vs its old ~3,944 stop);
  d. port the section-transition trail + backward walk for the OEP.
Each step is separately measurable on the family, and step (a) alone is a one-line change with an immediate
observable: the write at 0x417217 must start producing a guest AV instead of succeeding.

#### 0.17iz shipped as an opt-in harness: enforcing VirtualProtect puts PEtite on the reference's path, and the next link derails

Implemented step (a) of 0.17iy: `VirtualProtect` now honours the request when `TAOTE_PROT_ENFORCE=1` (it maps
PAGE_* to uc perms, computes the page span, writes PAGE_READWRITE into `lpflOldProtect`, returns 0 instead of 1 on
failure, and never throws). Default OFF - with the variable unset the handler returns 1 exactly as before.

The immediate observable the blueprint predicted:

    gate off : [watch] pc=0x417217 addr=0x400000 value=0x0 ; oep=0x417214 reason=section_hop
    gate on  : [prot] VirtualProtect(0x400780, 0x880, 0x4) -> perms=0x3
               [prot] VirtualProtect(0x400780, 0x880, 0x2) -> perms=0x1
               pc trace 0x417214 -> 0x417217 -> **0x40d07c** -> 0x40d0d0 ... -> read fault
               oep=0x40d07c reason=section_hop error=Invalid memory read (UC_ERR_READ_UNMAPPED)

0x40d07c is EXACTLY the reference's first EP-exit transition (`[pet-epexit] t[0] from=2 to=3 addr=0x40d07c`), so
honouring the protection moves taote off the corrupt-image path and onto the reference's decode path. It then dies
after ~10 instructions in the second-stage code at 0x40d0db - the same place the reference's own notes describe
("the second stage derails") for the link after the fault.

Family A/B (73 PEtite rows, 4 workers, 85 s budget), same binary:

    control (default off) : n=73 PE=73 OEP=36 IMP=36 ALL=30      <- identical to r106, so the new code is inert
    TAOTE_PROT_ENFORCE=1  : n=73 PE=73 OEP=23 IMP=36 ALL=23      <- 13 OEP flips, 7 all-three losses, 0 gains

which reproduces the reference's own warning that enabling the fault dispatch alone makes PEtite worse. So the code
ships DEFAULT OFF as a measurement harness (the project's established pattern), the shipped baseline is unchanged,
and the next unit is the link that turns this into a win: the SEH chain seed (self-referential frame, context cell =
image base) plus the int1/TF storm, per 0.17iy steps (b) and (c), then the transition trail for the OEP.

#### 0.17ja the SEH seed makes PEtite's payload RUN: family imports 36 -> 66

Ported steps (a)+(c) of 0.17iy behind two gates and measured them together.

`QlOsWindows::seh_seed_petite(image_base)` (windows.hpp/seh.cpp, `TAOTE_SEH_SEED=1`) installs the reference's
frame at `[0x6ffc0000, 0x70000000)`: `H = 0x6ffe0000` = `mov eax,1; ret 0x10`, `F = 0x6ffe0100` with
**Next = F (self-referential)**, `Handler = H`, `[F+8] = Q`, the pivot slot `[F-0x26]` = the STUB SECTION base
(derived by parsing the guest image's own header for the section holding AddressOfEntryPoint - 0x417000 here),
a second frame at `F+0x60` ending the chain, `[Q-4] = image base` written LAST (the `F2-0x52` zero overlaps that
cell's upper half - the reference's write-order finding), and finally `fs:[0] = F`.
`TAOTE_TF_TRAPS` makes the TF single-step cap tunable; it was hard-coded at 4096 and PEtite's decryptor needs far
more, which is exactly why the storm looked like a derailment.

Measured on petite_rrdec (prot + seed + cap):

    [seh-seed] fs:[0]=0x6ffe0100 H=0x6ffe0000 pivot=0x6ffe00da [Q-4]=0x400000 stub=0x417000
    pc trace: 0x403f46 0x403f49 0x4010db 0x4010dd 0x40c8f8 0x4010e2 0x4010e5 0x40ca70 ...
    (previously: 0x417217 -> 0x40d07c -> read fault at 0x40d0db with ebx=0, esp=0xffffffda)

i.e. the exception-driven decryptor now completes, the payload EXECUTES, and `0x401160` (the true entry) is reached.

Family A/B (73 PEtite rows, 4 workers):

    control (all gates off)      : n=73 PE=73 OEP=36 IMP=36 ALL=30   <- identical to r106, code inert by default
    TAOTE_PROT_ENFORCE + SEH_SEED + TF_TRAPS=40000:
                                   n=73 PE=73 OEP=26 IMP=**66** ALL=26
    code_sim: 43 rows improved, 0 worse; ALL gains 2 (diagtrackrunner, iecleanup), losses 6
        (PEview, ctrl2cap, efsdump, gsd, ldmdump, pagedfrg)

The import effect is the largest single move this session: **36 -> 66 rows importing correctly**, because a payload
that runs resolves its imports instead of leaving the stub's table. The OEP count DROPS (36 -> 26) for the reason the
reference documents: with the payload running, the terminal prologue scan latches MID-DECODE `.text` entries
("tinytask's e8e9 coincidence, gsd's non-boundary C1, 7za's boundary-passing C1"). That is precisely what the
EP-exit trail was invented to stop, and it is the next (and last) piece: taote records section transitions only
under the `TAOTE_SEC_TRANS` diagnostic, so the deliverable is a real `sec_trans_hist_` + `sec_last_write_insn_`
walked backward with the prologue-shape gate, exactly as 0.17ix measured live in the reference.

Both gates stay DEFAULT OFF (the code returns early without them), so the shipped baseline and the corpus are
unchanged; this is the measured path to the family's remaining headroom.

#### 0.17jb SHIPPED: PEtite's EP-exit trail + running payload - corpus 2146 -> 2175 (+29), family ALL 30 -> 59

The two pieces from 0.17ja are now default-on for PEtite (env opt-outs `TAOTE_NO_PET_EXIT`,
`TAOTE_NO_SEH_SEED`, `TAOTE_PROT_ENFORCE` still forces the protection on for any family), and the last piece is
implemented: `oep_from_transition_trail`.

    record      one SectionTransition per section change in on_section_exec, stamped with the exec-fire count;
                the section lookup is CACHED (the hook fires hundreds of thousands of times, so the analytic
                TAOTE_SEC_TRANS path's linear scan per fire is not affordable) - cached hit, else linear.
    walk        BACKWARD from the newest transition; take the first whose target section the run never leaves
                again, which saw no write at or after the hand-off (64-instruction grace, the reference's
                constant), and whose target carries a function-entry shape (55 8b ec / 55 89 e5 / 6a ?? 68 ..
                e8 / e8 .. 6a .. 68). Reason string `petite_ep_exit`.
    engine      for PEtite only: VirtualProtect is enforced (the stub's read-only header must fault into its
                handler), the TF single-step budget is 40000 instead of 4096, and the SEH frame is seeded.

petite_rrdec, no env at all: `oep=0x401160 reason=petite_ep_exit` - the true entry (the not-packed original's
0x1160), where this session started at 0x417214 (the decompressor) with the error box.

Family (73 rows): n=73 PE=73 **OEP 36 -> 63, IMP 36 -> 66, ALL 30 -> 59**; 33 gains, 4 losses
(PEview, ctrl2cap, efsdump, ldmdump - all four also fail in the reference's own A/B notes as queued flips).

Corpus r107 (2678 rows, 4 workers, 85 s budget, 120 s wall):

    all-three 2146 -> **2175**    OEP 2180 -> 2207    imports 2223 -> 2253    valid PE 2676 -> 2677
    raw run read 2173 with 33 gains / 6 losses; two of the six (nspack_Bginfo, rlpack_geek, both dur 86) are the
    long-documented wall flakes and came back all-three solo, so the referee is 33 gains / 4 losses.

Suite 607/607. `UNPACK_REPORT.md` regenerated from r107. This is the first row-moving change since the WinUpack
parked slot (round 229) and it comes entirely from the reference's documented PEtite mechanism chain:
prot-write AV -> seeded self-referential SEH frame -> TF storm budget -> EP-exit trail.

#### 0.17jc the trail's two rules: excursion cancellation and section-start hand-offs - PEtite ALL 59 -> 61, zero regressions

The four PEtite rows the trail regressed (0.17jb) turned out to be two distinct mistakes in the walk, both now
fixed and both measured:

**Excursion cancellation.** `petite_ctrl2cap`'s trail ends with `t4 from=0 to=1 addr=0x4075ca seq=218552` and
`t5 from=1 to=0 addr=0x403ee4 seq=218553` - a call into another section and back ONE instruction later. The walk
without a filter picks t5, while the true entry is t3 (0x40221a). A pair (A->B then B->A within 1<<20 instructions)
is an excursion, not a hand-off, so both ends are dropped before the backward walk. That and the same shape on
efsdump (truth 0x402138) and ldmdump (truth 0x403024) put all three on the exact entry.

**Section-start hand-offs.** `petite_PEview`'s true entry is `e8 d7 00 00 00 85 c0` at rva 0x1000 - a `call` tail,
which none of the four prologue shapes cover, so the shape gate rejected it and the walk fell back to a mid-decode
transition (0x40a400). A hand-off to the FIRST BYTE of a section is structural evidence on its own, so the gate now
accepts `addr == section.start` as well as the shapes.

Family (73 rows): n=73 PE=73 **OEP 65, IMP 66, ALL 61**, and versus the pre-trail baseline (30) that is
**31 gains, 0 losses** - the four regressions are gone.

Corpus r108 (2678 rows, same harness parameters):

    all-three 2146 -> **2177**   OEP 2180 -> 2209   imports 2223 -> 2253   valid PE 2676 -> 2677
    raw run read 2175 with 31 gains / 2 losses, and both losses are the documented wall flakes
    (nspack_Bginfo, rlpack_geek, dur 86) which came back all-three solo, so the referee is 31 gains / 0 losses.

That is +31 over the session's PEtite starting point and +2 over 0.17jb's shipment, with the family now at 61 of 73
and no row anywhere regressing relative to r106.

#### 0.17jd PEtite's last 15 rows: 8 OEP (all mid-decode entries) and 7 imports (the ordinal wall)

Census of what the shipped chain still misses, now that the family sits at 61 of 73.

**8 rows with the wrong OEP, every one fully decoded (`code_sim = 1.0`)**, and every claim LATER than the truth:

    7za        0x474800 vs 0x455641      Hasher     0x484884 vs 0x482628
    DarkNamer  0x40e87f vs 0x40a71e      PEViewer   0x529200 vs 0x401504
    Everything 0x57e207 vs 0x545f0d      HashCalc   0x4714d3 vs 0x411e58
    HDDScan    0x891630 vs 0x883d20      md5summer  0x4a0a40 vs 0x49ec68

HDDScan's numbers are the case the reference's own notes call out verbatim ("the full-slate scan's
boundary-passing C3 at 0x883d20 wins" - 0x883d20 IS the truth, and our 0x891630 is the mid-decode .petite
workspace entry), so this is a known-shaped residual, not a new failure mode: the trail's write test accepts a
mid-decode transition whose stub writes stopped early.

**7 rows with short import tables, and the misses are 100% ORDINALS** - the same unrecoverable spelling the
WinUpack lane closed: adrestore 7 (wldap32 #118/#14/#145/#155/#73/#88 + oleaut32 #8), FileTypesMan 13 (ws2_32),
ShareEnum 19 (oleaut32 10 + ws2_32 9), shexview 14 (ws2_32 13 + comctl32 #6), plus DarkNamer/Everything/PEViewer
which are OEP-wrong anyway. Four of them are 0.91-0.946 recall, i.e. a handful of pairs short, but every missing
pair is an ordinal: the payload imported ordinal N, taote reverse-maps the slot to export N's NAME, and aliasing
every named export as `ordinal_<N>` stays rejected as metric gaming.

One experiment measured and REVERTED this round: a separate "external write" stamp for the trail (record the
section's last write only when the writer pc is outside that section, so the payload's own self-modification cannot
veto the hand-off). Motivation was concrete - 7za's trail DOES contain the truth (`t3 2->0 addr=0x455641
seq=3433439`), and the walk rejects it - but on the whole family the change is exactly neutral
(n=73 PE=73 OEP=65 IMP=66 ALL=61, identical to r108), so it was reverted rather than shipped as dead weight. The
next attempt on these 8 rows needs a different signal for "mid-decode entry" than write stamps (the reference's own
note about HDDScan's early-ending stamps says the same).

#### 0.17je TELock: the stub RUNS - it is the decryptor's key stream that is wrong, and the reference's
#### decode is the ground truth

The family sits at 0 valid PE 116, OEP 1, imports **0** of 116. Until now the working theory was "the stub derails
early". It does not. With `TAOTE_APIDBG=1` on telock_7z.exe the stub executes its whole prologue correctly:

    kernel32.GetModuleFileNameA(0x400000, 0x418000, 0x104)   ret=0x18
    kernel32.CreateFileA("C:/Windows\telock_7z.exe", ...)    handle 0xa000000e
    kernel32.ReadFile(0xa000000e, 0x418008, 0x400, 0x418000) 0x400 bytes read
    kernel32.CloseHandle(0xa000000e)                         ret=0x1
    kernel32.CreateMutexA(0, 1, 0x418c7b)                    name "uMYxP9u8"
    user32.MessageBoxA(...)  ->  kernel32.ExitProcess

The 0x400 bytes the stub reads are **byte-identical to the packed file's own header**, and the mutex name is
**byte-identical to the reference's** ("uMYxP9u8"), which closes the self-read and every path/name-derived value as
candidate causes - pegasus fabricates a different path (`C:\WINDOWS\system32\telock_7z.exe`, 33 chars, vs taote's
`C:/Windows\telock_7z.exe`, 24) yet derives the same name, so the path is not in the derivation.

The failure is one step later. At the in-place decryptor (0x418fb7) the stub has

    eax=0x1000 (.text RVA)  ecx=0x8a00 (length)  esi=edi=0x401000  ebx=0x6d8fd7d6  edx=0xfd62f97a

and after it runs, the CRC32 (poly 0xedb88320) over `crc(0x401000, 0x8a00)` at 0x419047 yields eax=0x23884536,
which does not match the stub's expected value, so the stub takes its MessageBoxA reporter (last pc 0x4192e3) and
exits. That is why imports is 0 on all 116 rows: the payload is never decoded, so nothing ever fills an IAT.

**The decode itself is garbage, not slightly off.** Comparing taote's in-place .text (dumped at the MessageBoxA)
against the reference's decode of the same row (pegasus writes real 7z code: `33 c0 39 05 e8 61 41 00 0f 9f c0 c3
55 8b ec 51` at .text+0): 35180 of 35328 bytes differ (99.6%). Recovering the key stream where the packed .text is
non-zero (`ct ^ pt` from pegasus's decode) shows taote's stream matching at 0.42% with no shift (-2/-1/+1/+2, +0x400,
+0x1000 all ~0.5% = random), i.e. a **different key from the very first byte** - a seed/PRNG problem, not a
one-instruction arithmetic slip.

The reference's path, for the hand-off: it passes the CRC, `VirtualAlloc(0x8a10)` = .text size + 0x10, then rebuilds
its IAT with ~90 GetProcAddress calls (that storm IS where its `image_import_functions: 109` comes from) and runs
7z's own startup for 8.57M instructions.

Next unit: pin the PRNG. Both seeds are computed by stub code before 0x418fb7, and the identical mutex name proves
every derived input before them agrees, so the remaining candidates are (a) the two seed computations, (b) the
self-referential loop body (`xor al,cl / mov [edi],al / ror al,cl / xor al,bl / add bl,[edi] / adc bl,cl /
test cl,1 / shr/rol/lea ebx,[ebx+ebx*8]`, which reads back the byte it just stored and chains through ADC's carry -
flag-sensitive by construction). The documented loop plus the recovered true key stream makes this checkable
offline: model it from the seeds and see whether it reproduces pegasus's decode.

One incidental engine wart found on the way (not a TELock cause): `host_to_virtual_path` normalizes the body but not
the anchor, so the guest sees `C:/Windows\telock_7z.exe` - a forward slash in the drive anchor - even though the
default `PATH.current_dir` is `C:\Windows\system32`.

#### 0.17jf TELock: ported the reference's self-check bypass (F68) - gated off, and what it unlocks

`../pegasus/src/unpacker/packers/telock_unpacker.cpp:169-235` (F68) states the mechanism outright: **TELock's
stub self-check is a CRC32 over the packed .text raw span compared against constants stored in the stub section, and
a whole generation of TELock (the NirSoft/adwcleaner class) carries constants that do not match its own bytes**, so
the failing six-byte `jne` at `stub_start + 0x104e` takes the abort branch (`+0x127b`) and the decompressor at
`+0x1054` never runs. The reference redirects the PC past that `jne` the first time it executes ("revisions whose
check passes never take the branch, so removing it cannot change them") and gates it with
`SE_NO_TELOCK_CRCBYPASS`.

That is exactly 0.17je's measurement: on telock_7z.exe the CRC at 0x419047 mismatches and the stub reports and
exits - so **taote's decode was never wrong, the stub aborts by design on this generation.** (This also retracts
0.17je's "the key stream is wrong from byte 0": .text at that point is simply the *undecoded* packed span, which is
what the 99.6% difference from the reference's decode is.)

Ported: `Unpacker::install` now installs, family-scoped to TELock, a code hook at `stub_start + 0x104e` that sets the
PC to `+0x1054`, where `stub_start` is the section containing the packed EP. Gated with `TAOTE_TLOCK_CRCBYPASS=1`:

    gate OFF  oep=0x418037 stages=1 reason=section_hop imports=3     (baseline, bit-identical)
    gate ON   ... GetModuleFileNameA -> CreateFileA -> ReadFile -> CloseHandle -> CreateMutexA
              -> VirtualAlloc(0x8a10)/Free -> (0x1010)/Free -> (0xa10)/Free -> VirtualAlloc/Free
              -> GetCurrentProcessId -> OpenProcess -> VirtualProtectEx
              -> stops at 0x4196f1

The three alloc/free triples are the reference's own sequence (0x8a10 = .text size + 0x10), so the bypass is
correct: it puts the stub on the reference's path.

**Family A/B (116 rows, 4 workers, 85 s, same binary): n=116 PE=116 OEP 1 -> 0 IMP 0 ALL 0, 0 gains / 0 losses.**
So it ships DEFAULT OFF - it is a precondition, not a fix, and the standing rule applies.

The next link, pinned exactly: `0x4196f1` is `8d c0` = `lea eax,eax` with ModRM mod==3, the real #UD the reference's
roadmap names, and the stub installs its handler frame immediately before it (`sub eax,eax; add dword [esp],0x1d;
push fs:[0]; mov fs:[0],esp; jmp +1` - the handler is a *return address* on the stack adjusted by 0x1d).
`TAOTE_UNPACK_DEBUG=1` shows taote's invalid-instruction hook fires only at 0x419a08 (0xf1) and 0x4186a8 (0x8d),
**never at 0x4196f1**: the run stops with the block entry at 0x4196f1 as the last pc and with no `emu_stop` and no
error line, so the #UD is never delivered and the stub's SEH frame never runs. After the reference delivers that
exception it logs exceptions at 0x4196F1/0x4197D9/0x419814, calls GetModuleHandleA, runs ~90 GetProcAddresses (its
109 imports), and executes 8.57M instructions of 7z startup.

#### 0.17jg TELock: deliver the mid-block `lea eax,eax` #UD - family OEP exact 1 -> 14

0.17jf stopped at `0x4196f1` with the run returning cleanly. Chasing that to ground:

- `Qiling::emu_stop` was instrumented: the last stop before the clean return is at `0x418e2c`, i.e. **no hook stops
  the run at 0x4196f1**.
- The rundbg line was widened with the actual state at the stop: `pc=0x4196f1 byte=0x8d retarget=0 budget_hit=0
  eflags=0x6 exit_point=0x8fffffff timeout=120000000us count=2e9 insns=7371130`, and `--count 20000000000` changes
  nothing - so it is none of the budget/until/timeout cases, and it is deterministic (same pc and instruction count
  every run).
- `QlCoreHooks::dispatch_insn_invalid` calls every hook regardless of range, and unicorn does raise
  `UC_ERR_INSN_INVALID` for the same `8d` byte when a block *starts* on it (the 0x4186a8 hit), so the hook is fine -
  unicorn simply does not raise it for `lea eax,eax` when it is reached mid-block.

So the gate now delivers the #UD itself: a code hook at `stub_start + 0x16f1` keeps Eip on the instruction and calls
`seh_dispatch_cpu(0xC000001D)`, exactly the invalid-instruction hook's non-0xf1 branch, and stops if nothing handled
it (the same contract). With that, telock_7z.exe reproduces the reference's own exception sequence:

    [sehd] code=c000001d fault=4196f1 pc=4196f1 handler=4196ff      <- the reference's exception at 0x4196F1
    [sehd] code=80000004 fault=4197d9 ... handler=4197cb            <- 0x4197D9
    [sehd] code=80000004 fault=419815 ... handler=4197f9            <- 0x419814

and then reaches the payload's `.text` for the first time (faulting at pc=0x410fff on a read of 0x5df70e00).

**Family A/B (116 rows, 4 workers, 85 s, gate on): n=116 PE=116 OEP 1 -> 14, IMP 0 -> 0, ALL 0 -> 0**, no row gains
or loses an all-three. So it stays gated off: the OEP half of the family is now unblocked on 13 rows, but the import
half still needs the stub's IAT rebuild (the reference's ~90-call GetProcAddress storm, which is where its 109 imports
come from). Next: the fault at 0x410fff in the payload's tail - find what hands control there before the entry at
0x40ebc5 - and then the IAT-stub-address precondition.

#### 0.17jh TELock: why the IAT rebuild is skipped - the payload's .rdata is never decoded

0.17jg left the stub reaching the payload's entry but with imports still 0. The skip is now localised to one branch:

    419210: mov 0x40d362(%ebp),%edx     ; edx = image base (0x400000)
    419216: mov 0x40d352(%ebp),%esi     ; esi = an RVA (0x13bb8) from the stub's descriptor at 0x419cb0
    419224: add %edx,%esi               ; esi = 0x413bb8
    41922d: mov 0xc(%esi),%eax          ; eax = [0x413bc4]
    419230: andl $0x0,0xc(%esi)         ; consume it
    419234: test %eax,%eax
    419236: je 0x41962a                 ; TAKEN in taote: eax == 0, so no IAT rebuild
    419240: push %eax
    419241: call [ebp+0x40d2d0]         ; GetModuleHandleA, then the ~90-call GetProcAddress storm

`TAOTE_PROBE=0x419234` reads exactly `eax=0x0 ebx=0x59e1fe3f ecx=0xa00 edx=0x400000 esi=0x413bb8`, so the branch is
taken on the value the stub reads, not on a mis-decoded condition.

The cause is upstream of the branch: **0x413bc4 is in the decoded `.rdata` (RVA 0x13bc4, VA 0x413bc4), and taote never
decodes that section.** Dumping 0x60 bytes at 0x413b80 at the last API gives sixty zero bytes, while the reference's
own decode of the same row holds the payload's tables there (0x41049c/0x4104a4/0x4104ac/0x4104b4/0x4104bc, then
0x13c54, 0x11010, 0x13df0, 0x11ac). A zeroed `.rdata` is also why the payload crashes at 0x410fff once it is handed
control: its import and relocation tables live there.

Trap for whoever picks this up: `andl $0x0,0xc(%esi)` zeroes that dword as it consumes it, so **no run-end dump can
show the pre-run value** - it has to be read at run time (a probe or an APIDUMP at a preceding API), which is why this
looked like "the reference has zeros there too" on a first reading of both dumps.

The stub's descriptor block itself is fine and readable at run time: `0x419cb0 = {0x13bb8, 0, 0x17000, 0x18000,
0x400000, 0x400000, 0x60, 7}` (RVA base, RVA of the table the branch reads, section RVAs, image base, image base,
0x60, 7 blocks).

Next: why the decompressor leaves `.rdata` (and probably `.data`) at zero while `.text` decodes. The stub's
decompressor is the call at stub+0x1054 the CRC bypass falls through to, and the payload's block list is the
descriptor above (7 entries) - so compare, block by block, what the decompressor writes in taote against the block
extent each descriptor implies.

#### 0.17ji TELock: the decryptor loop disassembled exactly, and a decode that gets ZEROED after it runs

The loop the CRC bypass falls through to is now read straight out of runtime memory (APIDUMP at VirtualProtectEx,
which is after the stub has self-decrypted), so it is the real instruction stream and not an encrypted guess:

   418fad: mov %ebx,%edi
   418faf: mov %edi,%esi
   418fb1: mov 0x40d376(%ebp),%ebx    ; the seed
   418fb7: lodsb                      ; al = ciphertext byte
   418fbc: xor $0x55,%al
   418fbe: sub $0x37,%al
   418fc0: xor %cl,%al                ; cl = the counter's low byte
   418fc2: mov %al,(%edi)
   418fc4: ror %cl,%al
   418fc6: xor %bl,%al
   418fc8: add (%edi),%bl             ; reads back the byte it just stored
   418fca: adc %cl,%bl
   418fcc: test $0x1,%cl
   418fcf: jne 0x418fe0
   418fd1: shr %ebx / test $0x8,%ebx / rol %cl,%ebx / lea (%ebx,%ebx,8),%ebx
   418fe0: stos                       ; stores the ROTATED/XORED al, overwriting the first store
   418fe1: dec %ecx
   418fe2: jg 0x418fb7

Two measured facts that matter more than the algebra:

1. **The loop runs 41,984 iterations on telock_7z.exe** (`TAOTE_PROBE=0x418fb7 TAOTE_PROBE_N=200000`), i.e. more
   than the 0x8a00 = 35,328 bytes of the .text raw span, so the stub makes more than one pass over it.
2. At CreateMutexA - which is *before* that loop - .text at 0x401000 **already holds a decoded-looking stream**
   (`ed 49 14 09 7e 0e 1f 57 a8 a3 5f 49 7a 51 63 83 ...`), while at VirtualProtectEx, which is after it, the same
   address is **nearly all zeros** (`da 00 00 00 00 ...`, with a few sparse bytes). The reference's final .text at
   that address is 7z's real code (`33 c0 39 05 e8 61 41 00 ...`).

So on this row the first stage already decodes something before CreateMutexA, and a later stage leaves .text and
.rdata essentially zeroed. That is consistent with 0.17jh's import blocker: the stub then reads [0x413bc4] out of the
zeroed .rdata, gets 0, and skips its IAT rebuild entirely.

A hand-model of the loop, seeded with the observed `ebx=0x6d8fd7d6` and `ecx=0x8a00`, does NOT reproduce the
reference's decode (0.45%), and the recurrence derived from the reference's plaintext (`bl_old = out ^ ror(al, cl)`)
does not chain over the odd-cl steps either, so the next unit should not try to model this algebraically: it should
find what zeroes the region after the first pass, which is an engine-side question the reference's own source answers
more cheaply.

#### 0.17jj TELock: the shadow-overlay source is the right idea but cannot show value yet (measured, reverted)

The reference's TELockUnpacker comment on its shadow buffer ("just-in-time decrypt/execute/re-encrypt: the stage 1
shadow buffer (first-write decrypted bytes)") plus `dump_module`'s family overlay (:4207) explain 0.17ji's zeroing
exactly: TELock wipes what it decoded, so terminal memory is not the decode. taote already owns that machinery - the
first-write shadow (`shadow_wanted_` / `shadow_image_` / `shadow_seen_`) and, generically, a zeros-restore overlay
that rewrites any byte the stub decoded and then wiped - but **`shadow_wanted_` is false for TELock**, because only
`ShadowPolicy::first_write` families (MEW, PECompact) collect it, so the zeros-restore had nothing to consume.

Enabling collection for TELock inside the gate (keeping `ShadowPolicy::none`, so only the safe zeros-restore applies,
not the full overlay that is measured wrong for the JIT families) makes it restore **4973 bytes** on telock_7z.exe -
and measures exactly nothing:

    family (116 rows, 4 workers, 85 s, gate on): n=116 PE=116 OEP 14 IMP 0 ALL 0, mean code_sim 0.0908

i.e. identical to 0.17jg's gate-on arm (OEP 14, IMP 0, ALL 0). Reverted rather than shipped. The reason it cannot
show value yet is visible in the same run: telock_7z.exe ends with `error=emulation error: Invalid memory read
(UC_ERR_READ_UNMAPPED)`, so the stub never finishes its decode and what the shadow holds is the *partial* stream. The
payload's tables are therefore absent from the artifact no matter the overlay.

So the ordering is now firm: (1) get the stub to finish (the rdata/.text content is wiped and re-derived, and the
stub currently skips its IAT rebuild because [0x413bc4] reads 0), (2) then the shadow overlay will matter, because the
reference's 109 imports come from the payload's tables in exactly those wiped sections.

#### 0.17jk TELock: the stub's own section table carries the entry point - family OEP exact 1 -> 93

The reference's `TELockUnpacker::family_terminal_fill` (telock_unpacker.cpp:28-72) documents a second mechanism that
taote lacked entirely: **TELock's stub records the original entry point in its own section table, obfuscated as ~EP -
image base at `stub+0x1cc0`, ~EP at `stub+0x1ce0`**, and because the stub *writes* both at run time they have to be
read from the first-write shadow (`shadow_seen_` at both offsets, `shadow_image_` for the dwords), not from the file
(the packed bytes there are `0x00000000` and `0xb838c542`). It is used exactly when the run latched nothing usable -
the reference's own wording is "the accept gate keeps landing on the stub's own self-decrypted first stage, stub+0x32",
which is precisely taote's TELock failure mode (every claim was `0x...037`).

Ported before the `family_fill` seam, family-scoped to TELock, under the same `TAOTE_TLOCK_CRCBYPASS` gate (that gate
is what collects the shadow; the shadow *overlay* stays off, which the reference's own A/B also concludes:
"overlay-OFF better on 5, worse on 3; telock_7z decisive at 0 vs 35191" - taote reproduced that in 0.17jj):

    ep = (uint32_t)~[shadow stub+0x1ce0] + [shadow stub+0x1cc0]
    accept when ep is inside the image and outside the stub section; reason = "telock_oep_table"

On telock_7z.exe: `[unpack] telock oep-from-table: ~K3=0xebc5 -> 0x40ebc5 (was 0x418037)` - the truth.

**Family A/B (116 rows, 4 workers, 85 s, gate on): n=116 PE=116 OEP 1 -> 93, IMP 0 -> 0, ALL 0 -> 0**, i.e. **+93 OEP
gains and 0 losses**. Imports stay 0 on every row, so no row flips all-three yet and the gate still ships default-off;
but the OEP half of this family is now solved for 93 of 116 rows from two dwords the stub writes for exactly this
purpose.

Next: the import half. The reference's 109 imports come from the payload's own tables (its artifact grows a `.pgimp`
section and reports `image_import_descriptors: 6, image_import_functions: 109`), and taote's `.rdata`/`.idata` are the
wiped sections - so the harvest has to read the same first-write shadow the entry point now comes from, or the stub's
GetProcAddress storm has to run (it is still skipped: [0x413bc4] reads 0, 0.17jh).

#### 0.17jl TELock: the OEP half is solved; the import half is a DECODE-COVERAGE gap, not a harvest bug

With 0.17jk's table read in place, telock_7z.exe now produces the right *header* too: the artifact's section table is
the original one (`.text 0x1000 vs 0x10000 raw 0x10000`, `.rdata`, `.data`, `.rsrc`, `0x18000`, `.pgimp`) and
`ep = 0xebc5`, identical to the reference's artifact. So the remaining difference is inside the image, and it is one
number: **`.pgimp` is 0x97 bytes with imp_sz 60 in taote against 0x8eb with imp_sz 140 in the reference**
(`image_import_descriptors: 6, image_import_functions: 109`).

Three measurements say this is decode coverage, not an import-recovery bug:

1. `TAOTE_WATCH_RANGE` counts **12,555 bytes written into .text (0x401000-0x411000) and 13,205 into .rdata
   (0x411000-0x415000)** during the gate-on run - so the sections ARE written, and the "all zeros at VirtualProtectEx"
   of 0.17ji/0.17jj was a *timing* artefact (that API runs before the bulk of the decode). 0.17ji's "a later stage
   leaves .text zeroed" is WITHDRAWN; the decode happens after that point.
2. `TAOTE_WATCH=0x413bc4` - the dword whose zero skips the IAT rebuild - records **no write at all**, and
   `TAOTE_PROBE=0x419234` fires exactly **once** with `eax=0`. So the stub reads a value it never writes, i.e. one it
   expects to have decoded there, and the skip path is taken once for good.
3. A dll-string census of the artifacts: taote holds **2** dll-like strings (`kernel32.dll`, `user32.dll`) and no
   `GetProcAddress`; the reference holds **6** (`advapi32`, `kernel32`, `msvcrt`, `ole32`, `oleaut32`, `user32`) plus
   `GetProcAddress` and `LoadLibraryA`. Those strings are the payload's own, so the reference's decoded image contains
   the payload where taote's does not - which is also why its harvest finds 109 functions and taote's finds 60 bytes'
   worth.

So the work order for the import half is now: get the stub's block decode to cover the payload (the reference ends
with the payload's strings present), after which the import harvest and `.pgimp` fill in on their own.

#### 0.17jm TELock: the payload DOES run; the import blocker is one dword the stub reads but never writes

Three more measurements on telock_7z.exe under the gate, which together replace "the decode is missing" with a much
narrower statement:

1. **The payload executes.** `TAOTE_PROBE=0x410fff TAOTE_PROBE_PREV=1` reports `prev_pc=0x410ffd`, i.e. 0x410fff is
   reached by *falling through* the payload's own code inside .text, not by a resume: the crash is the payload running
   with a stack that is still empty (`esp=0x121ffec`, `[esp]=0x1220000` = the stack base) and the VirtualProtectEx
   argument registers still live (`ebp=4, esi=0x1000, edi=0x400000`). So the decode is good enough to execute, and
   what kills it is the IAT: the payload calls through slots nothing has rebuilt.
2. **The written ranges cover the whole image** (`TAOTE_WRITTEN_RANGES=1`: 0x401000-0x411000, 0x411000-0x415000,
   0x415000-0x417000, 0x417000-0x418000, 0x418000-0x41b000), so the decode covers .rdata too - but
   `TAOTE_WATCH=0x413bc4` records **no write at that address**, so the coverage has holes, and this dword is one of
   them.
3. That dword is the whole import blocker: the stub takes `je 0x41962a` exactly once, on `eax=[0x413bc4]==0`, and
   skips GetModuleHandleA plus the ~90-call GetProcAddress storm that produces the reference's 109 imports
   (`TAOTE_PROBE=0x419234` fires once, eax=0; the packed file also holds 0 there, and the stub never writes it).

So the family's remaining work is not "decode the payload" (it decodes and runs) but "make the stub's fixup/decode
produce RVA 0x13bc4", after which the stub rebuilds its own IAT and the imports follow without any new heuristic. The
fixup loop that should cover it is the one ending at 0x41920c (`jg`) with `ecx=0xa00` iterations over the descriptor
table at 0x413bb8 (`{0x13c54, 0, 0, 0, 0x11010, 0x13df0, ...}` in the reference's decode), and in taote that loop's
table entry for 0x13bc4 is absent.

#### 0.17jn TELock: taote's .text holds a KEY STREAM, and the loop at 0x418fb7 is not its producer

The cleanest discriminator yet. On telock_7z.exe the packed `.text` raw begins with **0xc00 zero bytes**, so for
that stretch the ciphertext is exactly zero and any content there is the decryptor's raw key stream. Comparing the two
artifacts over those bytes:

    taote  .text+0 : da 9a af e6 9b 52 bd ef 98 89 36 98 d1 e2 6a 5c ...
    reference     : 33 c0 39 05 e8 61 41 00 0f 9f c0 c3 55 8b ec 51 ...

Taote's bytes are the key stream, not code - which is why 0.17je's "different key from byte 0" reading was right and
must NOT stay withdrawn (0.17ji's withdrawal was about a *different* dump: at VirtualProtectEx the barew span is
pre-decode; the artifact is post-decode). So the family's blocker is exactly: the key stream taote computes is wrong
from the first byte, and it is short.

Per-page nonzero census (the reference's decode vs taote's artifact):

    .text   taote: 0xffe 0x1000 0x1000 0xfff 0x1000 0x1000 0x1000 0x1000 0xa00 0 0 0 0 0 0 0
    .text   ref  : 0xdaf 0xddc 0xdf5 0xe0a 0xdc1 0xe2a 0xe22 0xde6 0xe4b 0xe5a 0xe51 0xeb9 0xef4 0xea6 0xf67 0x4a8
    .rdata  taote: 0xfff 0 0 0            .rdata ref: 0x77c 0x691 0x60b 0
    .data   taote: 0xc65 0xab             .data  ref: 0xbf4 0x146

i.e. taote covers .text pages 0-8 (the 0x8a00 raw span) with high-entropy bytes and leaves the virtual tail zero, and
covers only .rdata page 0 where the reference covers three. The reference's density is code-like (~0xdb0-0xf70 per
page) throughout.

Two hand models of the loop have now failed: the first (0.17ji) against the reference's decode, and a fresh one against
**taote's own output** - deriving `bl_old = out ^ ror(al, cl)` from taote's key stream and chaining it through the
odd-cl iterations matches 1 of 199. So the loop at 0x418fad-0x418fe2 is not the (only) producer of that page, and
further algebraic modelling is a dead end; the next unit should compare registers instruction by instruction at that
loop (or find which other decryptor writes .text page 0), not re-derive its algebra.

Method note recorded for the family in general: 41,984 executions of 0x418fb7 against a 0x8a00 span means the loop is
entered more than once with different counters, so "the loop's first entry" is not the whole story either.

#### 0.17jo SHIPPED: TELock's stub-section-table EP, default-on for the family - corpus OEP 2209 -> 2298

The 0.17jk mechanism is now the family default (opt-out `TAOTE_NO_TLOCK_CRCBYPASS`), because it is a large, clean
capability gain on the OEP metric even though the import half is still unsolved.

**Corpus r109** (2678 rows, 4 workers, 85 s budget, 120 s wall, ~90 min):

| metric | r108 | r109 raw | referee |
|---|---|---|---|
| valid PE | 2677 | 2677 | 2677 |
| **OEP exact** | 2209 | **2298** | **2300** |
| imports | 2253 | 2251 | 2253 |
| all-three | 2177 | 2175 | 2177 |

The raw run lost all-three on exactly two rows, `nspack_Bginfo.exe` and `rlpack_geek.exe` - the long-documented
dur-86 wall flakes - and both graded all-three when re-run solo (`oep=0x5b5d42` / `oep=0x559760`, imports 1.0 /
0.9985), so the referee restores OEP, imports and all-three to the r108 levels and leaves the +91 OEP as the only
movement: 92 TELock rows gained an exact OEP and one lost it.

**The one loss is `telock_PEview.exe` (0x401000 -> 0x416bd6, reason `embedded_pe`)**, and it is NOT this mechanism
firing: the table read only applies when the current claim is junk, and PEview's claim was already exact. What changes
is that the gate makes the stub run far enough for the *embedded-PE* seam to fire, and that seam's candidate
(0x416bd6) is inside the stub section - something the accept gate normally rejects as stub-section junk. So the
follow-up is a generic guard ("an embedded-PE candidate may not sit inside the packed-EP section"), which needs its
own corpus arm because `try_embedded_pe` is shared by every family.

A tighter acceptance test was tried first and reverted: requiring the EP to land in an executable section rejects
everything for this family, because **TELock zeroes every section's Characteristics** (`0xc0000040`, i.e.
INITIALIZED_DATA|READ, on all five sections of telock_7z.exe and all six of telock_PEview.exe) - the same trap the
PEtite lane recorded. The acceptance therefore stays structural: inside the image, outside the stub section (bounded
by that section's real `end`, not a constant).

Family arm re-measured after the bound change (116 rows, 4 workers, 85 s): **PE 116, OEP 1 -> 93, IMP 0, ALL 0**, one
loss (`telock_PEview`), consistent with the corpus.

Open for the family: imports stay 0 on all 116 rows because the payload's decode is still wrong (0.17jn: the key
stream is wrong from byte 0 and .rdata is only one page deep), so the stub never rebuilds its IAT.

#### 0.17jp Frontier map on corpus r109 (the hand-off): 501 misses = 81 .NET + 123 IMP-bound + 18 OEP-bound + 279 both-wrong

Measured per row from r109's results, with each row's ORIGINAL checked for the managed floor (a .NET original can
never be all-three, so those rows are counted separately and excluded from every pool below):

| pool | rows | families |
|---|---|---|
| .NET floor | 81 | Amber 22, Exe32pack 17, TELock 15, Eronana 13, Alienyze 7, tail 7 |
| **IMP-bound** (PE ok, OEP exact, imports wrong) | **123** | **TELock 92**, WinUpack 12, RLPack 7, MEW 4, PEtite 4, Amber 1, JDPack 1, NSPack 1, Yoda 1 |
| OEP-bound (PE ok, imports ok, OEP wrong) | 18 | PEtite 5, JDPack 4, Amber 3, PECompact 3, Neolite 1, WinUpack 1, Yoda 1 |
| both-wrong (native) | 279 | Themida 122, Yoda 100, plus the rest of Exe32pack/Eronana/Amber |

So after r109 the single biggest lever is still **TELock's 92** - now OEP-exact and waiting only on imports, which is
the decode problem of 0.17jn (key stream wrong from byte 0, .rdata one page deep). Everything else native is either
small or in the both-wrong (decode-bound) class with Themida and Yoda, the two families the reference also fails.

RLPack's 7 IMP-bound rows, checked in detail, split into three shapes:

- **Two are near-threshold and named-only** - `rlpack_Hash.exe` recall 0.9412 missing exactly 5 msvcrt names
  (`??2@YAPAXI@Z`, `??3@YAXPAX@Z`, `__setusermatherr`, `_acmdln`, `_adjust_fdiv`) and `rlpack_calc.exe` 0.9342
  missing 25, of which 23 are msvcrt C++ decorated symbols (`??0exception@@QAE@ABQBD@Z`, `??1type_info@@UAE@XZ`, ...)
  plus `kernel32!InterlockedCompareExchange`. Both are one small mechanism away from the 0.95 line, and the shape is
  the same: **decorated msvcrt C++ export names are not being reverse-resolved**, which is a spelling problem in the
  symbol map, not a harvest problem.
- Two are ordinal-dominated (`rlpack_Procmon.exe` 15 oleaut32 ordinals of 22 misses, `rlpack_adrestore.exe` 10 of 74)
  - the closed ordinal wall.
- Three are far below threshold with hundreds of ordinary named misses (`rlpack_Bginfo.exe` 0.0453, grepWin 0.006,
  PortableWinCDEmu 0.5833), i.e. decode/rebuild-bound, not spelling-bound.

Also still open from 0.17jo: the generic embedded-PE guard ("a `try_embedded_pe` candidate may not sit inside the
packed-EP section") that would give `telock_PEview.exe` its exact OEP back; it needs its own corpus arm because that
seam is shared by every family.

#### 0.17jq SHIPPED: the SDK export database gains msvcrt and MSVC-decorated names - corpus 2177 -> 2179

The RLPack near-threshold rows of 0.17jp were a *stub-surface* gap, and the gap was in the generator: `gen_api_db.py`
**skipped libmsvcrt entirely** (`"msvcr"` was in SKIP_SUBSTRINGS) and its SYMBOL_RE required a name to start with
`[A-Za-z_]`, so MSVC C++ decorated symbols (`??2@YAPAXI@Z`, `?terminate@@YAXXZ`) were dropped. A sample whose packed
import table is destroyed can only resolve msvcrt imports through that SDK surface, so the decorated/data names
simply did not exist:

    before: 32374 names, 405 DLLs, 0 msvcrt entries, 0 decorated names
    after:  34773 names, 427 DLLs, 1679 msvcrt entries, 559 decorated names

(`--from-pe` on the *not-packed* original already produced a stub msvcrt with those names, which is what proved the
surface - not the runtime - was the gap.)

**RLPack family arm (104 rows, 4 workers, 85 s): ALL 93 -> 94 raw, 2 gains / 1 loss, and the loss
(`rlpack_ComIntRep.exe`, `dur=86`) came back all-three solo with recall 1.0 - the documented budget flake - so the
referee is 93 -> 95, 2 gains / 0 losses.** The two gains are exactly the ones 0.17jp predicted:

    rlpack_Hash.exe  recall 0.9412 -> 0.9647   (5 msvcrt names: ??2@YAPAXI@Z, ??3@YAXPAX@Z, __setusermatherr, _acmdln, _adjust_fdiv)
    rlpack_calc.exe  recall 0.9342 -> 0.9658   (25 names, 23 of them msvcrt C++ decorated)

**Corpus r110** (2678 rows, 4 workers, 85 s, ~89 min - no runtime cost from the larger surface):

| metric | r109 referee | r110 raw | r110 referee |
|---|---|---|---|
| valid PE | 2677 | 2677 | 2677 |
| OEP exact | 2300 | 2299 | 2301 |
| imports | 2253 | 2253 | 2255 |
| all-three | 2177 | 2177 | **2179** |

The two raw all-three failures were again `nspack_Bginfo.exe` and `rlpack_geek.exe` (recall 0.0314 / 0.0521), both
all-three solo (1.0 / 0.9985), and the raw arm shows **0 losses against r109** across all 2678 rows - so the only
movement is the +2 from the msvcrt surface.

Method note: this is the cheapest shape of win in the corpus - a *surface* change rather than an engine change, with
a family arm that identifies the intended rows in advance and a corpus arm that confirms nothing else moved.

#### 0.17jr Closing the near-threshold tail: 11 rows, and every one is closed by evidence, not by choice

The r110 census of import-bound rows with named misses leaves exactly **11 rows at or above 0.88 recall**, and each
one is now accounted for:

| row | recall | misses | why it is closed |
|---|---|---|---|
| rlpack_Procmon.exe | 0.9491 | 22 (7 named, 15 ord) | ordinal-dominated |
| winupack_Dbgview.exe | 0.946 | 17 (1 named, 16 ord) | ordinal-dominated |
| amber_chglogon.exe | 0.9412 | 5 (all named) | DLL attribution, see below |
| jdpack_chglogon.exe | 0.9412 | 5 (all named) | DLL attribution, see below |
| winupack_HWMonitorPro_x32.exe | 0.9389 | 28 (1 named) | ordinal-dominated |
| mew_Bginfo.exe | 0.9373 | 54 (1 named) | ordinal-dominated |
| winupack_Everything.exe | 0.9247 | 22 (1 named) | ordinal-dominated |
| winupack_ADExplorer.exe | 0.9045 | 30 (1 named) | ordinal-dominated |
| winupack_ShareEnum.exe | 0.903 | 23 (1 named) | ordinal-dominated |
| mew_ComIntRep.exe | 0.8994 | 53 (1 named) | ordinal-dominated |
| nspack_ComIntRep.exe | 0.8994 | 53 (3 named) | ordinal-dominated |

**The ordinal rows are closed for a measured reason:** `winupack_Dbgview.exe` makes **zero GetProcAddress calls** in
the whole run, so the packer neither kept the ordinal thunks nor asked for the functions at run time - the artifact
resolves each slot through the reverse symbol map and emits export N's *name* while the original imported ordinal N.
There is no remaining signal that says "this was an ordinal", which is the same conclusion the WinUpack lane reached.

**The two chglogon rows are closed by policy, not by a bug.** Both packers of the same original emit
`advapi32!RegCloseKey` / `RegCreateKeyExW` / `RegOpenKeyExW` / `RegQueryValueExW` / `RegSetValueExW` where the
original imports those five from **kernel32**. taote's re-attribution pass (unpack.cpp:4183-4212) deliberately only
rewrites a pair when the assigned DLL is *not* among the name's owners and exactly one owner is named by the image;
`advapi32` IS a legitimate owner of every one of those names, so it leaves them alone. That is the reference's own
stated rule - gen_api_db.py's comment: "the runtime picks a default from the first, and the re-attribution pass
intersects the list with the DLLs the image itself names (a stricter test than 'the database's favourite owner')" - so
preferring PRIORITY's kernel32 here would be a policy change that would break the far more common case (a binary that
imports Reg* from advapi32 and also uses kernel32 for other calls). Rejected on those grounds.

So the corpus's remaining headroom is: TELock's 92 (decode), the embedded-PE guard's single row, and the
Themida/Yoda both-wrong pools that the reference also fails. Nothing in the near-threshold tail is left unexamined.

#### 0.17js SHIPPED: an embedded-PE candidate may not sit inside the packed-EP section - +2 OEP, 0 losses

The 0.17jo loss is fixed generically. `adopt_embedded_pe` scans memory for a candidate `MZ`+`PE` and adopts it when
its `Characteristics` looks executable and its entry is inside its own SizeOfImage - but it never asked *where* the
candidate is. TELock's stub section (0x415000-0x418000 on telock_PEview.exe) carries a false `MZ`+`PE` whose entry
(0x416bd6) displaced the correct 0x401000 claim the moment the TELock gate made the stub run further. The guard, in
the candidate loop:

    if the candidate's ENTRY (cand_base + ep_rva) lands inside the section that holds the PACKED entry point -> skip
    the candidate (fall back to the normal pick)

Note the first attempt guarded the candidate's *base*, which does nothing: on this row the base is a legitimate
image start and only the ENTRY lands in the stub section.

**Affected-population arm** (complete by construction: every row whose r110 meta says `reason=embedded_pe`, 118 rows,
plus the 116-row TELock family = 232 rows, 4 workers, 85 s):

    OEP exact 196 -> 198   imports 115 -> 115   all-three 103 -> 103   0 all-three gains, 0 losses
    OEP gains: telock_PEview.exe, telock_adwcleaner_7.2.4.0.exe (the latter was arm-only)

**Corpus r111** (2678 rows, 4 workers, 85 s, ~90 min) confirms the intended row and nothing else:

    telock_PEview.exe   0x416bd6 (wrong) -> 0x401000 (EXACT)
    nspack_Bginfo.exe   flaked again (raw all-three lost, all-three solo at recall 1.0) -> refereed back

| metric | r110 referee | r111 raw | r111 referee |
|---|---|---|---|
| valid PE | 2677 | 2677 | 2677 |
| OEP exact | 2301 | 2299 | **2302** |
| imports | 2255 | 2253 | 2255 |
| all-three | 2179 | 2177 | 2179 |

So +1 OEP on the corpus (PEview), 0 all-three movement (that row still has no import table), 0 losses.

#### 0.17jt TELock decode: the first divergence is at byte 0 of the key stream, and the toolchain cannot localise it further

Final round of instrumentation on this family; the numbers are recorded so the next session starts from them and does
not repeat the dead ends.

**The entry state is canonical.** At the stub's packed entry `0x418000` taote holds `eax=ebx=ecx=edx=esi=edi=0`,
`esp=ebp=0x1220000` - the Windows convention, and the same state the reference must start from. So nothing the loader
leaves in the registers is the difference.

**The stage-1 arithmetic, at byte 0.** `TAOTE_PROBE=0x418da8` (the `stos` of the multiply-PRNG decryptor) reads
`eax=0x1016 ebx=0xac21fbc7 ecx=0x8a00 edx=0xd1b05d29 esi=0x401001 edi=0x401000`, `prev_pc=0x418da5` (`ror $0x7,%al`).
The ciphertext there is `0x00` (the packed `.text` raw begins with 0xc00 zero bytes), and the observed output byte is
`0x16`, so the pre-`xor dl` byte was `0x99` (`0x16 = ror7(0x99 ^ 0x29)`). The reference's plaintext byte is `0x33`,
which with the same `dl` needs a pre-`xor` byte of `0xb0` (`rol7(0x33) ^ 0x29`), or with the same pre-`xor` byte
needs `dl = 0x00`. Either way the two emulators agree on the *code path* and disagree on the PRNG state - a seed, not
an arithmetic slip.

**What is ruled out**, each for a measured reason: the entry registers (above); the input bytes (the 0x400-byte
self-read is byte-identical to the packed file, and the `.text` ciphertext is zeros there anyway); the file itself
(both read the same file); every fabricated API value (the mutex name is byte-identical between the two tools, and the
reference decodes correctly with *its own* fabricated handles, so no handle can be part of the key); the loop algebra
(three hand models failed, one of them fitted to taote's own output - 1 of 199 chained).

**One dead end to record so it is not repeated:** comparing the two artifacts' *stub section* (6540 of 12288 bytes
differ, from byte 0) proves nothing - the reference ran 8.5M instructions of the payload and its stub section is
end-state, while taote derails early, so that difference is run progress, not the divergence.

**Conclusion:** localising further needs a *memory dump from the reference at a common point* (e.g. pegasus's image at
a named API, the way taote's `TAOTE_APIDUMP` does), or an instruction-level register diff between the two emulators.
taote has both dump and probe machinery; pegasus has neither exposed. Until that exists, TELock's 92 import-bound rows
are out of reach for this toolchain, and the OEP half (0.17jk/0.17jo) is what the family can ship.

#### 0.17ju The ceiling census: Themida and Yoda are parity-failing, and every native pool left is decode-bound

With TELock's decode closed (0.17jt) the remaining 499 misses were censused family by family, and the result is that
**taote has no tractable pool left that the reference can do** - it is 183 all-three rows ahead of the reference
(2179 vs 1996).

**Themida (122 rows, the biggest untouched pool) is parity-failing, verified, not assumed.** taote: 122 valid PE, 0
OEP, 0 imports, mean code_sim 0.0654, every row `reason=section_hop`. The reference on six sampled rows
(7z, ADExplorer, ADInsight, AccessEnum, Autologon, Autoruns) returns `reason=end_of_emulation_fallback` with
`oep_rva=None` on every one - it does not unpack a single sampled Themida row either, which matches the monitor's
standing note that Themida and Yoda fail for the reference.

**Yoda-Protector (101 rows) has exactly two partially-successful rows, and both are dead ends for the same reason:**

- `yoda-protector_PEview.exe`: code_sim **1.0**, OEP **exact** (0x401000), and the artifact really does carry 66 of the
  original's 102 import names - but the grader scores recall 0.0 because **every recovered name is attributed to
  `kernel32`** (plus one literal `*.ocx`), while the original spreads them over advapi32, comctl32, comdlg32, gdi32,
  kernel32, shell32 and user32. So this is a DLL-attribution loss, not a recovery loss: the re-attribution pass cannot
  fire because the artifact's own `image_dlls` is just `{kernel32, *.ocx}` (0.17jr explains why preferring the DB's
  PRIORITY owner instead was rejected - it would break the common advapi32 case). The reference also fails this row
  (`yp_terminal_full_fill`, `oep_rva=None`).
- `yoda-protector_livekd.exe`: imports **ok** (recall 0.9733) but OEP wrong (0x43ecc7 vs 0x409663) with code_sim
  0.044, i.e. decode-bound.

**Every other native pool is decode-bound.** Highest code_sim among the native misses: Amber 16 rows - only
`amber_chglogon.exe` at 0.923 (the attribution-closed row of 0.17jr), everything else <= 0.054; Exe32pack 15 rows -
max 0.207; Eronana 1 row - 0.094. So no family hides a picker-shaped pool: their payloads are not decoded at all.

**Conclusion for the next session:** the corpus headroom that this toolchain can reach has been spent this session
(1843 -> 2179). What remains is (a) 81 .NET rows that can never be all-three, (b) Themida 122 + Yoda 101 where the
reference also fails, and (c) decode-bound native rows in Amber/Exe32pack/Eronana/TELock whose stubs need emulator
work beyond taote's current fidelity. Any new project should start from a *decode-fidelity* comparison against the
reference at a common point (the gap 0.17jt names for TELock applies to all three), not from a picker heuristic.

#### 0.17jv TELock decode: 0x418da8 is a SECOND transform, so the first divergence is upstream of it - and the
#### PRNG is not fit-able

Two results from the last instrumentation pass, both narrowing the problem without solving it.

**1. The loop at 0x418da8 is a second transform on already-transformed bytes.** Watch data recorded in 0.17ji and the
stage-1 keystream recorded in 0.17jt together give, for the same eight bytes:

    .text at CreateMutexA  (before stage 1): ed 49 14 09 7e 0e 1f 57 ...
    stage-1 output         (after 0x418da8): 16 9a af e6 9b 52 bd ef ...
    reference payload      (.text+0)       : 33 c0 39 05 e8 61 41 00 ...

So the ciphertext that stage 1 consumes is NOT the packed file's zeros - something earlier already wrote an
`ed 49 14 09 ...` stream into .text before CreateMutexA. That means 0.17jt's "first divergence at byte 0 of the key
stream" is really "first divergence in the stream written *before* CreateMutexA", i.e. in an earlier self-decrypt
stage, and stage 1 only amplifies it. The next localisation target is therefore that earlier writer, not 0x418da8 -
and it is observable from taote alone (`TAOTE_WATCH_RANGE=0x401000:0x402000` reports every pc that writes the page).

**2. The state sampled at 0x418da8 is not a multiplicative PRNG, so algebraic modelling is finished for good.**
Eight consecutive `stos` samples of `(al, ebx, edx)`:

    0x16 ac21fbc7 d1b05d29 | 0x9a ec77b6ea 071a76da | 0xaf 85bf5165 a0acf505 | 0xe6 74518fa2 47dcb872
    0x9b b365f7d4 52b682f4 | 0x52 4ad36748 461c4e88 | 0xbd ed3722d0 c2483b50 | 0xef 9380e021 a0ca7521

`edx` takes even values, so no constant multiplier maps sample i to i+1 (solving `edx[i+1]*edx[i]^-1 mod 2^32` is not
even possible for those pairs), and `ebx` gives two different `imul` constants for the two odd pairs
(`0x45ab2dc6`, `0xcdbc17fa`). So the recurrence is not `x <- x*K`, and the four-line linear model that the disassembly
at 0x418d80 suggested is a misaligned read of that region, not the real loop. Any future attempt must read the *loop
body* at runtime (a `TAOTE_WATCH_RANGE` on its own writes plus probes at successive pcs) instead of fitting constants.

#### 0.17jw CORRECTION: the packed .text raw starts at 0x1000, not 0x400 - which voids 0.17jt and 0.17jv's framing

A slice error invalidated the last two rounds' *premises* (not their measurements). `telock_7z.exe`'s section table is

    .text  va 0x1000 vs 0x10000 rs 0x8a00 pr 0x1000      .rdata va 0x11000 rs 0x1000 pr 0x9a00
    .data  va 0x15000 rs 0xa00   pr 0xaa00              .rsrc  va 0x17000 rs 0x200 pr 0xb400
    (last) va 0x18000 vs 0x3000  rs 0x2400 pr 0xb600

so **`.text`'s raw data begins at file offset 0x1000**, not 0x400. The 0xc00 zero bytes I read at 0x400 are the
header/padding between the PE header and the first section - not ciphertext. Consequences:

1. **0.17jt is withdrawn** ("taote's .text is a key stream because the ciphertext is zeros"): the ciphertext at
   `.text+0` is `ed 49 14 09 7e 0e 1f 57 a8 a3 5f 49 7a 51 63 83`, and the value taote holds there at the *first API*
   (GetModuleFileNameA, i.e. before the stub has done anything) is exactly that - the loader mapped the section
   correctly. There is no host-side seeding and no mystery write.
2. **0.17jv is withdrawn** ("0x418da8 is a second transform on already-transformed bytes, so the first divergence is
   upstream"): it was built on the same error - the "already-transformed" stream `ed 49 14 09 ...` IS the packed
   ciphertext.
3. The real numbers, for whichever session picks this up:

       ciphertext .text+0      : ed 49 14 09 7e 0e 1f 57 a8 a3 5f 49 7a 51 63 83
       reference decode        : 33 c0 39 05 e8 61 41 00 0f 9f c0 c3 55 8b ec 51
       => true keystream      : de 89 2d 0c 96 6f 5e 57 a7 3c 9f 8a 2f da 8f d2
       taote's artifact .text  : da 9a af e6 9b 52 bd ef ...   => its keystream 37 d3 bb ef e5 5c a2 b8 ...

4. The recurrence check was re-run against the *real* ciphertext and the reference's plaintext: deriving
   `bl_old = ks ^ ror(al, cl)` and chaining the odd-cl steps still gives **0 of 199** consistent, so 0.17jv's second
   conclusion stands and is now on a correct basis - the loop body read at 0x418fad-0x418fe2 is not the decryptor that
   produced the payload (or the model of it is still wrong), and algebraic fitting is not the way in.

So the TELock decode question is exactly as open as 0.17jv said, but for none of the reasons it gave: the ciphertext
is the packed section (mapped correctly), the two tools disagree on the *transform*, and the loop at 0x418fad is not
it. The next step remains "read the real loop body at runtime", with the corrected `(ciphertext, keystream)` pairs
above as the acceptance test.

#### 0.17jx TELock: coverage is NOT the problem - both tools transform the whole span, and taote runs the loop too often

Two measurements that finish the classification of this decode (with the corrected 0x1000 slice of 0.17jw):

**1. Coverage is identical and correct in both tools.** Fraction of `.text` bytes still equal to the packed
ciphertext after the run: **taote 148/35328 (0.4%), reference 134/35328 (0.4%)**. Both transformed essentially the
whole span, so this has never been a "the stub did not decode" problem - it is the *transform* (or its key) that
differs, which is exactly the `(ciphertext, keystream)` disagreement 0.17jw recorded:

    reference keystream : de 89 2d 0c 96 6f 5e 57 a7 3c 9f 8a 2f da 8f d2
    taote keystream     : 37 d3 bb ef e5 5c a2 b8 30 2a 69 d1 ab b3 09 df

**2. taote runs the loop 41,984 times over a 35,328-byte span** - the difference is exactly **6,656 (0x1a00)**, i.e.
18.8% of the span again. That is the first concrete structural lead this lane has produced: either the loop is entered
twice with different counters (a second pass over the first 0x1a00 bytes would double-transform exactly that head, and
the artifact's head is where taote and the reference disagree first), or one entry runs past the span. A future
session should instrument `0x418fb7`'s `ecx` at *every* entry (not just the first) - `TAOTE_PROBE` prints it, and the
per-entry values settle the pass structure in one run - and check whether the artifact's first 0x1a00 bytes are the
*double* transform of the ciphertext.

This is the last item this session can honestly add to the TELock lane: the question is now narrowly "how many passes
does the decryptor make, and with which counter", not "what seed", "what coverage" or "what algebra" (0.17jw/0.17jv
closed those).

#### 0.17jy TELock: the decryptor runs in THREE passes (0x8a00, 0x1000, 0xa00) - and the counter is part of the key

The pass structure 0.17jx asked for, measured in one run (`TAOTE_PROBE=0x418fb7`, `PROBE_N=60000`, reading `ecx` per
hit):

    pass 1   hits 1..35328      ecx 0x8a00 -> 0x1    35,328 iterations = the whole .text raw span
    pass 2   hits 35329..39424  ecx 0x1000 -> 0x1     4,096 iterations = exactly one page
    pass 3   hits 39425..41984  ecx 0x0a00 -> 0x1     2,560 iterations

    35,328 + 4,096 + 2,560 = 41,984 = the observed hit count, exactly.

So the stub enters its decryptor **three times over the head of .text**, with counters that are *lengths*: the whole
raw span, then one page, then 0x0a00. The head (first 0xa00 bytes) is therefore transformed three times, the range
0xa00-0x1000 twice, and everything above 0x1000 once.

Two consequences, and they are the first actionable ones this lane has had:

1. **The counter is part of the key.** The loop body uses `cl` (the counter's low byte) in `xor al,cl` and
   `ror al,cl`, so a pass's keystream depends on the counter's *starting* value and the per-byte offset, not just on
   the seed. Decrypting 0x8a00 in one pass and decrypting the same bytes page-by-page therefore produce **different
   plaintext from the same ciphertext** - a per-page pass starts its `cl` at 0x00 with 0x1000 offsetting it
   differently from a 0x8a00 pass. TELock is a just-in-time, per-page decryptor (the reference's own comment: "the
   decryption wave runs from a deeper loop"), so the *page-sized* passes are the design and the 0x8a00 pass is what
   makes taote's output differ from the reference's byte-for-byte even where only one pass ran (the census showed
   taote and the reference disagree above 0x1000 too, where taote transformed once and the reference page-wise).
2. The two extra passes then re-transform the head, which is consistent with the head being where taote and the
   reference disagree *first*, and with the artifact's `da 9a af e6 ...` head against the reference's
   `33 c0 39 05 ...`.

So the next unit is no longer "what algorithm": it is **why taote's first pass requests 0x8a00 instead of a page**
(the counter is loaded from a stub variable immediately before the call, and the same guest code requests 0x1000 on the
next two entries - so the value comes from guest state, and the divergence is in whatever computes it, not in the loop
body). A probe on the counter's load site (the instruction before the loop's entry that writes `ecx`) is the next
measurement; the acceptance test is that a page-wise pass reproduces the reference's `33 c0 39 05 e8 61 41 00 ...`.

#### 0.17jz CORRECTION: the "three passes" are three SECTIONS (raw sizes), not a double transform - 0.17jy withdrawn

Probing the block that *loads the loop's state* (0x418fad: `mov %ebx,%edi; mov %edi,%esi; mov 0x40d376(%ebp),%ebx`)
settles the pass structure in one run - it executes once per entry, so its hits are the entries:

    #1  eax=0x1000   ebx=0x401000  ecx=0x8a00  esi=3
    #2  eax=0x11000  ebx=0x411000  ecx=0x1000  esi=2
    #3  eax=0x15000  ebx=0x415000  ecx=0x0a00  esi=1

eax is the section RVA (.text 0x1000, .rdata 0x11000, .data 0x15000 - exactly the packed section table's VAs), ebx is
base+RVA (the pass's destination), ecx is that section's **raw size** (.text 0x8a00, .rdata 0x1000, .data 0xa00 -
exactly the packed raw sizes), and esi counts the sections down 3,2,1. So the decryptor is a **section walk**: each of
the three data sections is decrypted **once**, in place, with its own raw size. 35,328 + 4,096 + 2,560 = 41,984 was
three sections, not three passes over the head.

**0.17jy is therefore withdrawn in full**: there is no double or triple transform of the head, the counter is not a
repeated pass length, and "the head is transformed 3x / the extra passes destroy the head" was a misreading of three
distinct section destinations. The one durable part of 0.17jy is the datum itself - 41,984 = 0x8a00 + 0x1000 + 0xa00.

The real body was also read for the first time, from a runtime dump of the stub rather than from a re-disassembly guess
(`TAOTE_APIDUMP=VirtualProtectEx:418000:3000` - the stub's own sections ARE decoded at that call, unlike the payload's,
which is why an earlier .text dump at the same API looked like garbage; the final artifact re-encrypts the stub, so the
artifact is not a source for stub code):

    418fb7  ac            lodsb
    418fb8  eb 02         jmp 0x418fbc     ; skips a two-byte 0xcd 0x20 filler the earlier read misaligned
    418fbc  34 55         xor al,0x55
    418fbe  2c 37         sub al,0x37
    418fc0  32 c1         xor al,cl
    418fc2  88 07         mov [edi],al
    418fc4  d2 c8         ror al,cl
    418fc6  32 c3         xor al,bl
    418fc8  02 1f         add bl,[edi]     ; byte-oriented form, not add [edi],bl
    418fca  12 d9         adc bl,cl
    418fcc  f6 c1 01      test cl,1
    418fcf  75 0f         jne 0x418fe0
    418fd1  d1 eb         shr ebx,1
    418fd3  f7 c3 08 00 00 00  test ebx,8
    418fd9  75 05         jne 0x418fe0
    418fdb  d3 c3         rol ebx,cl
    418fdd  8d 1c db      lea ebx,[ebx+ebx*8]
    418fe0  aa            stosb
    418fe1  49            dec ecx
    418fe2  7f d3         jg 0x418fb7

Ground truth for validating any model of it (`TAOTE_PROBE=0x418fe0`, `PROBE_N=8`; the store fires *before* `stosb`, so
eax's low byte is the byte written and ebx is post-update):

    i  cl      stored  ebx
    0  0x00    0xda    0xed074b79
    1  0xff    0xb7    0xed074bdf
    2  0xfe    0x2b    0x7683a58d
    3  0xfd    0x81    0x7683a50c
    4  0xfc    0xba    0x3b41d2b9
    5  0xfb    0xdc    0x3b41d2df
    6  0xfa    0x0d    0x8c2aa0c4
    7  0xf9    0xf9    0x8c2aa038

and it **still does not fit** the body above (with the observed `bl` chained iter to iter the implied input bytes come
out 0x44, 0x0e, ... which are not stage 1's 0x16, 0x9a, ...), so the input to this loop is not stage 1's output byte for
byte and the `bl`/`ebx` state carried across iterations is not the one the probe reports at 0x418fe0 - i.e. there is at
least one more state variable (likely the `adc`/rotate path being taken differently than the flag sequence implies). The
next unit is to probe the *pre*-store instruction (0x418fc2) as well and chain from a known entry `ebx` (read at
0x418fb7, i.e. after the reload from [0x40d396+ebp]) instead of guessing.

#### 0.17ka TELock's section decryptor is now an EXACT model (8/8 iterations) - and the seed is provably not the divergence

Read at run time (not from a re-disassembly), the loop is:

    418fb7  ac        lodsb
    418fb8  eb 02     jmp 0x418fbc          ; skips a two-byte 0xcd 0x20 filler
    418fbc  34 55     xor al,0x55
    418fbe  2c 37     sub al,0x37
    418fc0  32 c1     xor al,cl
    418fc2  88 07     mov [edi],al
    418fc4  d2 c8     ror al,cl
    418fc6  32 c3     xor al,bl
    418fc8  02 1f     add bl,[edi]
    418fca  12 d9     adc bl,cl
    418fcc  f6 c1 01  test cl,1
    418fcf  75 0f     jne 0x418fe0
    418fd1  d1 eb     shr ebx,1
    418fd3  f7 c3 08 00 00 00  test ebx,8
    418fd9  75 05     jne 0x418fe0
    418fdb  d3 c3     rol ebx,cl
    418fdd  8d 1c db  lea ebx,[ebx+ebx*8]
    418fe0  aa        stosb
    418fe1  49        dec ecx
    418fe2  7f d3     jg 0x418fb7

Entered with **ebx=0x6d8fd7d6, ecx=0x8a00, edx=0xfd62f97a, esi=edi=0x401000** (probe at 0x418fb7 - note ebx is
*reloaded* from [0x40d396+ebp] at 0x418fb1, which is why the probe at 0x418fad shows the destination 0x401000 instead),
and its input is **stage 1's output** (not the packed ciphertext): with in=0x16 it stores 0xda and leaves
ebx=0xed074b79, exactly as the emulator does. The recurrence then reproduces **all eight** observed iterations byte
**and** full 32-bit `ebx`:

    i  in     cl      out (obs)   ebx after (obs)
    0  0x16   0x00    0xda        0xed074b79
    1  0x9a   0xff    0xb7        0xed074bdf
    2  0xaf   0xfe    0x2b        0x7683a58d
    3  0xe6   0xfd    0x81        0x7683a50c
    4  0x9b   0xfc    0xba        0x3b41d2b9
    5  0x52   0xfb    0xdc        0x3b41d2df
    6  0xbd   0xfa    0x0d        0x8c2aa0c4
    7  0xef   0xf9    0xf9        0x8c2aa038

This is pinned by `Unpack_Compat.TelockDecryptorRecurrenceMatchesTheEmulator` (suite 607 -> 608), so the model cannot
rot: it is the oracle any future TELock decode work has to agree with.

**The decisive negative.** The model makes the seed testable. The reference's `.text` head is `33 c0 39 05 e8 61 41 00
0f 9f c0 c3 55 8b ec 51`; its implied seed low byte (from byte 0 alone) is `0x3f` where taote has `0xd6`, but all 2^24
possible upper halves of that seed were searched (`/tmp/seedsolve.c`, ~0.1 s) and **none** reproduces the reference's 16
bytes from taote's stage-1 input. So the reference's decryptor is not taote's decryptor with a different seed: the
**input** differs, i.e. stage 1 (the PRNG store at 0x418da8) is confirmed as the sole remaining divergence, and
everything downstream of it is now understood exactly.

Stage 1's body is also on record from the same runtime dump (0x418d50-0x418da8: a long chain of `add/ror/not/neg/xor al`
against `cl`/`bl`/`dl`, ending `32 c2 xor dl,al / c0 c8 07 ror al,7 / aa stosb / 69 d2 a5 b0 cd 4b imul
edx,edx,0x4bcdb0a5 / f9 72 02 stc-jb skip / d1 c2 rol edx,1 / 69 db 70 1f ee 6a imul ebx,ebx,0x6aee1f70 / 03 da add
ebx,edx / 49 dec ecx / jg`), so the next unit is the same shape of work that just succeeded on the other loop: probe
stage 1's store, chain its registers iteration by iteration, and turn it into a second pinned recurrence.

#### 0.17kb TELock's STAGE 1 is exact too - the whole decode is now specified, and its two PRNGs are the 0.17jh "non-fit-able" ones with the dropped rol restored

Stage 1 (stub 0x418d20-0x418da8) is a straight-line AL chain plus a two-register PRNG. Read from the runtime stub dump
and validated against the emulator, **both** parts are exact:

    edx_next = rol1(edx * 0x4bcdb0a5)              ; imul / stc / jb-skip / rol edx,1
    ebx_next = ebx * 0x6aee1f70 + edx_next         ; imul ebx,ebx,0x6aee1f70 / add ebx,edx

Both hold on all seven observed transitions (edx 0xd1b05d29 -> 0x071a76da -> 0xa0acf505 -> 0x47dcb872 -> 0x52b682f4
-> 0x461c4e88 -> 0xc2483b50 -> 0xa0ca7521; ebx 0xac21fbc7 -> 0xec77b6ea -> 0x85bf5165 -> 0x74518fa2 -> 0xb365f7d4 ->
0x4ad36748 -> 0xed3722d0 -> 0x9380e021).

**This retracts the "stage 1's PRNG is not fit-able" verdict of 0.17jh.** That rejection rested on
`0xd1b05d29 * 0x4bcdb0a5 mod 2^32 = 0x038d3b6d` not being the next edx - but the next edx is
`rol1(0x038d3b6d) = 0x071a76da`, exactly as observed. The `f9 72 02` (`stc; jb` over a two-byte filler) between the
imul and the `d1 c2 rol edx,1` had been read as a conditional skip of the rotate; it skips the *filler*, and the
rotate is unconditional. Likewise "edx takes even values so no constant multiplier can exist" was an artefact of
comparing against unrotated products.

The AL chain (73 instructions from `lodsb` to `stosb`) is pinned instruction-for-instruction as a table and reproduces
all eight observed stored bytes from the packed ciphertext (0xed 0x49 0x14 0x09 0x7e 0x0e 0x1f 0x57 -> 0x16 0x9a 0xaf
0xe6 0x9b 0x52 0xbd 0xef), with the runs of `ror al,cl` and the paired `not`/`neg`/`inc` surviving intact - a
hand-flattened version that drops the intervening rotates silently produces 0x88 instead of 0x16, which is exactly why
the test is table-driven from the dump.

State of the lane now: **both** TELock decryptors (stage 1 at 0x418d20, the section loop at 0x418fb7) are exact and
pinned by `Unpack_Compat.TelockStage1DecryptorMatchesTheEmulator` and
`Unpack_Compat.TelockDecryptorRecurrenceMatchesTheEmulator` (suite 608 -> 609), so the decode is fully specified up to
its **two seed constants**: stage 1's entry ebx/edx. Neither appears in the packed file or in the original
(0xac21fbc7 / 0xd1b05d29 are absent from both), so the stub computes them, and the remaining question is local and
finite: which guest state produces them. The next unit is to watch the writes that fill those two variables (the loop's
`mov 0x40d396(%ebp),%ebx` slot and its edx twin) and trace back one step from there.

#### 0.17kc TELock's payload key is a self-checksum of the stub - and it deliberately zeroes exactly the 13 host-fabricated IAT dwords before hashing

0.17kb left two seed constants to explain. Their producer is found: **pc 0x41882b** writes `edx` into the loop's key
slot (`mov %edx,0x1c55(%ebp)` with ebp=0x41807f -> **0x419cd4**, the same slot the section loop reloads at 0x418fb1), and
`edx` there is `0x6d8fd7d6`. Immediately before it, `0x418824 xor 0x1b55(%ebp),%dx` mixes in a 16-bit constant from
0x419bd4, so the seed is

    seed = HASH(stub image) ^ word[0x419bd4]

with HASH being the loop at 0x4187f5: `xor eax,eax / lodsb / xor al,dl / shr eax,1 / <conditional> / shr edx,8 /
xor eax,edx / dec ebx / jg`, run over **ebx = 0x1992 bytes starting at esi = 0x418000** - i.e. over the stub's own
decrypted section - with edx starting at 0xffffffff.

The decisive detail is what the stub does *just before* hashing (0x4187d3): it takes 13 dwords from `ebp+0x3bf` =
**0x41843e**, pushes each, and **zeroes it** (`andl $0,-0x4(%esi)`), hashing only afterwards. Those 13 dwords are

    0x10021550 0x10021950 0x100211e0 0x10021d90 0x10021da0 0x10021100 0x100213c0
    0x10021a40 0x10021dc0 0x10021050 0x10021ae0 0x100210c0 0x100214e0

- they are the stub's **IAT thunk values pointing into the host-mapped stub-DLL region (0x1000000+)**. So the packer
knows those are environment-specific and excludes them from the checksum by construction. That is exactly the kind of
planted trap this round was looking for: the checksum is *stable by design*, so taote's differing payload key cannot be
explained by its different API addresses, and some **other** byte in 0x418000..0x419992 must differ.

Caveat recorded for the next unit: the hash loop sits inside the stub's own self-decrypting region, so a late dump
(taken at VirtualProtectEx, i.e. after the run) shows re-encrypted bytes there and cannot be disassembled - the body has
to be read while it runs (probe-driven, as was done for stage 1 and the section loop), and the same applies to the
`0x4187f5` region before any model of the hash is trusted.

Next unit: with the seed's geometry known, the missing piece is a *diff of the hashed range*. Since the checksum covers
0x418000..0x419992 and the run is deterministic, instrument the hash loop's first hit to dump that range from guest
memory (an apidump at any API that fires afterwards, or a probe-time read), then compare it against the packed file's
stub after applying the known self-decrypt - the differing offsets are where taote's stub image diverges, which is one
step above the payload key and the last unknown in this lane.

#### 0.17kd Census: no precision lever exists, the .NET floor is exactly 81 (43 of them otherwise complete), and the pegasus Exe32pack lead is already taote's

Measured over corpus r111 (2678 rows) rather than assumed:

**1. There is no precision lever.** Of the 122 rows that are valid-PE and OEP-exact but import-wrong, **122 fail on recall
(< 0.95) and exactly 0 fail on precision alone** (every row's `imp_recall >= 0.95` set is empty). The
`docs/iat-recovery-plan.md` framing of an `iat_over` slice as a successor lever therefore has **no value under the
current grading** (recall is the pass criterion; over-emission only downgrades `imp_exact`, which nothing counts).
Any remaining import work must add *missing* pairs.

**2. The non-TELock remainder is 29 rows and is closed by two mechanisms.** TELock 93, WinUpack 12, RLPack 5, MEW 4,
PEtite 4, Amber 1, JDPack 1, NSPack 1, Yoda-Protector 1. The near-threshold ones (rlpack_Procmon 0.9491,
winupack_Dbgview 0.9460, petite_FileTypesMan 0.9458, winupack_Diskmon 0.9439, petite_shexview 0.9419, ...) are the
ordinal-dominated rows already documented in 0.17jr, and the far ones are decode-bound (rlpack_adrestore 0.0633,
rlpack_grepWin 0.0060, winupack_mtinst 0.3129, ...). So **TELock's 93 is the whole of the reachable import pool.**

**3. The .NET floor is exactly 81 rows, and taote is already right on 43 of them.** All 81 misses with `oep_exact =
None` are the `com_rva` (managed-original) rows that `tools/unpack_report.py` deliberately does not OEP-grade
(`if (not orig.get("com_rva"))`). What taote actually produced on them:

    81 ungraded rows
    57 carry the ORIGINAL entry point exactly (out_ep == orig_ep)
    48 of those also pass imports (recall >= 0.95)
    43 of those also have code_sim >= 0.8   (Eronana 13, Exe32pack 13, Amber 12, TELock 9, Alienyze 7, ...)

e.g. `exe32pack_AddInProcess.exe`: out_ep == orig_ep == 0x681e, 5 sane sections, imp_recall 1.0, code_sim 0.9246.
**This is recorded, not exploited**: the monitor's standing ruling is that the honest base is 2594 and that .NET rows
can never be all-three, so the grading convention is left alone. Re-baselining it would change the definition of the
metric, not taote's capability - and would move the reference by the same rule.

**4. The pegasus Exe32pack lead is already shipped in taote.** `5de920eb "restore a wipe-degenerate section table from
the packed file (Exe32pack)"` is explicitly a *port of taote bb4bc8d*, and taote carries it at
qiling/unpack/unpack.cpp:3632-3704 ("restored %zu zeroed section headers from the packed file"). taote's Exe32pack
artifacts are not wipe-degenerate (e.g. the row above has `.text/.rsrc/.reloc/.i/.pgimp`), and 13 of its 17
`oep_exact=None` rows are the .NET class of point 3. Lead closed.

Net: no measured lever exists outside TELock's decode, so this lane's model work (0.17ka-kb-kc) stays the critical
path, and the honest scoreboard is unchanged at 2179/2678.

#### 0.17ke TELock's payload is COMPRESSED, not just encrypted - and the reference's decode equals the original byte-for-byte (an exact oracle)

Two measurements that reframe the lane.

**1. The correct decode is known exactly.** Comparing section by section against the corpus's own `not-packed/7z.exe`:

    reference artifact .text vs ORIGINAL .text :  65536/65536 bytes equal  (100.00%)
    reference artifact @OEP 0xebc5 vs ORIGINAL  :  55 8b ec 6a ff 68 28 15 41 00 ...  identical
    taote     artifact .text vs ORIGINAL       :   5133/65536 equal (and those are mostly zeros matching zeros)
    taote     artifact @OEP 0xebc5             :  00 00 00 00 ... (all zero)

So the reference does not merely "decode differently": it reconstructs the original 64 KB of `.text` perfectly. That is
a hard, per-row acceptance oracle for any TELock decode work - no modelling or reference dump needed, just compare the
artifact's `.text` with the original's.

**2. The payload is compressed, which is why taote's output stops.** In the packed file `.text` is
`vsize 0x10000 / rawsize 0x8a00`, and the original entry point RVA **0xebc5 lies beyond the raw span's end (0x1000 +
0x8a00 = 0x9a00)**. The per-page nonzero census shows exactly this:

    taote .text nonzero by page: 4094 4096 4096 4095 4096 4096 4096 4096 2560 0 0 0 0 0 0 0
    orig  .text nonzero by page: 3503 3548 3573 3594 3521 3626 3618 3558 3659 3674 3665 3769 3828 3750 3943 1192

i.e. taote fills precisely the 0x8a00-byte packed span and nothing after it, while the original's code fills all 16
pages. So the 0x8a00 bytes are a **compressed stream that must decompress to 0x10000**, and the "section decryptor"
of 0.17ka/0.17jz is only the stream's stage 1. Taote never decompresses: its stream is garbage from byte 0, so the
stub's decompressor either never runs or runs on nonsense, which is consistent with the run ending inside the stub
(0x4196f1) rather than at a payload hand-off.

**Consequence for the worklist.** The lane's objective is now precisely stated: *get the stub's decompressor to consume
the stream and emit 0x10000 bytes*, and its success criterion is the 100% `.text` comparison above. Everything about the
keystream (0.17ka-kc) is a means to that end, and the two pinned models give the fastest possible check of any candidate
stream.

Also closed this round: comparing the hashed stub range (0.17kc) across the two artifacts is impossible - taote leaves
that region re-encrypted (`4f b0 e2 98 ...` at RVA 0x18fb7) while the reference **zeroes** it (all-zero there), so the
92%-difference measurement of last round is an artefact of two different post-run conventions, not evidence about the
decrypt.

#### 0.17kf Three corrections: the watch-range syntax, the real write census, and where the run now ends (plus the shadow-overlay A/B)

**1. My own measurement bug, session-wide: `TAOTE_WATCH_RANGE` takes `<lo>-<hi>[:n]`, not `<lo>:<hi>`.** Every census I
reported with `lo:hi` (e.g. `0x401000:0x411000`) silently became a **one-page** window `[lo, lo+0x1000)` with an
enormous print budget, so the "0x418da8 4096 / 0x418fc2 4096 / 0x418fe0 4096" counts that have been quoted since 0.17jj
are a *page-size artefact*, not totals. Corrected census over the whole `.text`
(`TAOTE_WATCH_RANGE=0x401000-0x411000:400000`):

    35328 pc=0x418fe0      (the section loop's stosb)
    35328 pc=0x418fc2      (its pre-rotation store)
    35328 pc=0x418da8      (stage 1's store)
      223 pc=0x419128      (relocation/fixup pass)
       43 pc=0x4190ba
        1 pc=0x4190e2

So `.text` is written by **exactly the three decryptor stores, once per raw byte each, and by nothing else**: there is
no decompressor pass in taote, no page-wise re-decode, and the 223-byte fixup pass is the only other writer.

**2. The run no longer ends at 0x4196f1.** With the CRC bypass and the #UD delivery both shipped, the log says
`[unpack] telock: #UD at 0x4196f1 delivered=1` - the frame the stub installed *does* run - and the run now proceeds
into the payload and dies at **pc 0x410fff with UC_ERR_READ_UNMAPPED** (the last byte of `.text` page 0). The standing
note that "the run ends inside the stub at the #UD" is obsolete.

**3. The shadow overlay is a measured no-op for TELock (not kept).** The reference's 100%-correct `.text` comes from
its finalize **first-write shadow dump** (its own comment: "TELock uses just-in-time decrypt/execute/re-encrypt ... re-dump
at finalize to capture the accumulated shadow buffer"), which is a mechanism taote has - gated on
`ShadowPolicy::first_write`, which TELock does not set. Enabled for TELock behind `TAOTE_TLOCK_SHADOW` and A/B measured on
16 TELock rows (4 workers, 85 s):

    arm     all-three  oep_exact  imports  mean code_sim
    off     0          14         0        0.0687
    on      0          14         0        0.0687        (byte-identical artifacts on telock_7z.exe)

The overlay fires (48,796 bytes restored) but changes nothing that matters: TELock's decryptors write each byte **once**,
so the first write *is* the final garbage - the shadow holds the same junk as the image. Reverted; no code change kept.

**4. The stream is not a standard codec.** `zlib.decompressobj` in raw-deflate (-15), gzip (31) and zlib (15) modes all
reject taote's 0x8a00-byte stream, whose head is `da 9a af e6 9b 52 bd ef` with all 256 byte values present. If the
payload is compressed (0.17ke), the codec is TELock's own, and nothing in the stub's executed path expands `.text`, so
the expansion must happen wherever the payload's own hand-off leads - which is exactly where taote now dies (0x410fff).

#### 0.17kg The 15-row "decoded but OEP-wrong" pool: 14 sit on section_hop, jdpack_7z is a genuine gap, and the run dies on a poisoned decoder

Measured pool (corpus r111): of the 298 valid-PE OEP-wrong rows, **15 have `code_sim >= 0.95`** and **10 of those already
pass imports**, so each is a one-row fix away from all-three. Families: PEtite 8, JDPack 4, ASPack 1, Neolite 1,
WinUpack 1. Reasons: **section_hop 14, ladder_scan 1**. Every claim is *later* in the image than the truth.

**Parity is not uniform, so this pool is only partly reachable.** The reference's own eval rows settle two of them:

    jdpack_7z.exe    reference = UNPACKED_VERIFIED, out_ep == orig_ep == 0xebc5   -> taote 0x40e924: a REAL gap
    petite_7za.exe   reference = PARTIAL,            out_ep 374921 vs 349761      -> parity-failing, not a gap

**jdpack_7z.exe, root-caused in three steps.** The image is already correct (`code_sim` 1.0, imports 159) and the payload
is running (the decoder's return address is 0x40100a), but:

1. `[unpack] hop ledger (0):` - **no hop is ever latched**, which is why the scan fallback runs at all.
2. `[unpack] ladder passB hits=4 first=0x40e924 last=0x40ebc5` then `ladder: unique MSVC frame entry 0x40e924` - the true
   entry **0x40ebc5 is among the four candidates** (it is the *last* hit) and the selection rule takes the first/unique
   one instead. So the OEP half is a *selection* defect, not a discovery defect.
3. The run then dies at pc **0x418527** (`mov al,[edi]`, a secondary stub decoder) with `edi = 0xff20b4f1`. Probing every
   entry of that instruction shows the corruption growing: `edi` goes 0x4064e7 (good) -> 0x2f7762 -> 0xff20b4f1 (fatal).
   The **0x2f7762 step is the null-read mitigation** (seh.cpp:309-336): a read at an address below 0x10000000 is answered
   by mapping a zero page, so the decoder continues with zeros instead of taking its guest exception path - and the next
   computed pointer is garbage. In other words the mitigation, measured at +9 corpus rows, **keeps a corrupted decoder
   alive** on this row instead of letting the stub handle the fault itself.

So the two candidate mechanisms for the next unit are now specific and cheap:

    (a) ladder candidate SELECTION: with several MSVC-frame entries, the truth here is the LAST one. A rule that prefers
        the candidate the stub transfers control to (or the last hit) is testable on the JDPack family (4 rows) before
        the corpus, and the four hits are logged so the class can be measured.
    (b) null-read scoping: do not answer a read with a zero page when the faulting pc is inside a decoder's data walk (or
        bound the mitigation per pc/section rather than per run), so a poisoned pointer takes its own SEH path.

Both are gated and family-measurable, and (a) has an exact acceptance test on jdpack_7z (claim 0x40ebc5).

Correction to 0.17kg(a): the ladder's `ladder: unique MSVC frame entry 0x%llx` log prints `hit_va` **unconditionally**, so it
reads as "unique" even when the startup-pattern vote found two candidates. Verified on the artifact: **both** jdpack_7z
candidates are 3-push CRT startup frames

    0xebc5 (truth) : 55 8b ec 6a ff 68 28 15 41 00 68 e2 ec 40 00 64 a1
    0xe924 (chosen): 55 8b ec 6a ff 68 f8 14 41 00 68 e2 ec 40 00 64 a1

so the rule actually applied was the *first-frame* vote (frames.front()), not a uniqueness test, and that vote is itself
measured-better elsewhere (14 of the corpus's 19 such rows have the true EP at the FIRST frame). A last-frame preference
would therefore trade this row for others and is not a lever; jdpack_7z needs a discriminator that is not first-vs-last
(e.g. the stub's own jump target, or which frame's handler/scope pointers lie in-image). Mechanism (b) - the null-read
mitigation poisoning a decoder - remains the one clean lead in this pool, because a poisoned decoder is a defect on its
own terms rather than a coin flip between two plausible entries.

#### 0.17kh Two negatives that close 0.17kg's leads: the payload never executes on jdpack_7z, and the null-read mitigation is not its cause

**1. Correction to 0.17kg: jdpack_7z's payload never executes at all.** I read `ret=0x40100a` at the failing decoder call as
"the payload is running". Probed directly, that address never executes:

    pc 0x401000 : 0 hits      pc 0x40100a : 0 hits      pc 0x40100b : 0 hits      pc 0x40ebc5 (truth) : 0 hits

The stub *fabricates* that return frame (the house anti-analysis trick in this code), so the run stays inside the stub
and dies at 0x418527 without ever handing off. That also explains the empty hop ledger: there is nothing to hop *to*.
The image is nonetheless fully decoded (code_sim 1.0) and the imports are right, so the OEP is decided by the ladder
scan alone - whose first-frame vote cannot tell the true 0x40ebc5 from the look-alike 0x40e924 (both are 3-push CRT
startup frames, 0.17kg correction).

**2. Mechanism (b) - the null-read mitigation poisoning a decoder - is measured FALSE.** Disabling it outright (bound
0) leaves jdpack_7z *identical*:

    bound 0x10000000 (shipped)  oep=0x40e924 reason=ladder_scan imports=159 + UC_ERR_READ_UNMAPPED at pc 0x418527
    bound 0x100000             oep=0x40e924 reason=ladder_scan imports=159 + the same fault
    bound 0x10000 / 0x1000 / 0x0   oep=0x40e924 reason=ladder_scan imports=159 + the same fault

So the decoder dies on the data it reads, not on a zero page the host invented; the mitigation's bound (which the comment
documents as "the first megabyte" while the code said 0x10000000) is not load-bearing for this row. The bound change was
built, A/B'd on the **100-row JDPack family and is exactly neutral** (all-three 95 -> 95, oep 96 -> 96, imports 99 -> 99,
mean code_sim 0.9693 -> 0.9693, zero rows changed), so it was not kept. It is recorded here as the one unmeasured
variant worth a corpus arm if anyone wants the comment/code mismatch gone: it is a *tightening* (fewer patches), so its
only risk is the rows that relied on a 1 MB-256 MB patch, which the family arm shows JDPack does not.

**Where that leaves jdpack_7z** (one row, plus 3 JDPack look-alikes in the same pool): the only remaining lever is to make
the stub survive its own decoder, which is upstream of the null-read story - and the pool's other 14 rows sit on
`section_hop` where the same question (does the payload ever run?) must be asked per row before any OEP heuristic is
worth designing. The general lesson from this round: **probe the addresses you claim are executing** - a fabricated
return frame reads exactly like a genuine caller in the `ret=` field.

#### 0.17ki PEtite joins the payload-internal traffic guard - corpus all-three 2179 -> 2183 refereed (+4, 0 losses)

The per-row probe split of 0.17kh asked the right question and paid off in one round. For the 15 rows that are
`code_sim >= 0.95` and OEP-wrong, probing **the true EP address** (VA = base + the original's EP RVA) divides them:

    executes the true EP (claim is later)          : 7   petite_7za, petite_HDDScan, petite_Hasher, petite_md5summer,
                                                        petite_Everything, neolite_HDDScan, jdpack_PEview
    never executes it (the stub dies first)        : 8   jdpack_7z, jdpack_7za, jdpack_MxdwGc, petite_HashCalc,
                                                        petite_DarkNamer, petite_PEViewer, winupack_PEview,
                                                        aspack_adwcleaner_7.2.4.0

The first group is exactly the shape of the reference's **payload-internal traffic guard** (which taote only armed for
UPX/NSPack/Molebox/JDPack): a later hop is the payload's own runtime writes reclaiming a range around the executing flow,
so it must not replace the entry hop. Armed for PEtite behind `TAOTE_HOPGUARD_EXTRA` and measured:

    PEtite family, 73 rows, 4 workers, 85 s budget:
        arm   all-three  oep_exact  imports
        off   61         65         66
        on    65         72         66         (+4 all-three: 7za, HDDScan, Hasher, md5summer; +7 OEP; 0 losses)
    Neolite, 93 rows, same arm:  92 -> 73 all-three (-19)   -> REJECTED

Neolite is why the guard cannot be generic: its `.text` is demand-paged, so a re-hop inside the range is legitimate and
dropping it destroys the claim (eight rows fall back to 0x401000). PEtite only.

**Corpus r112** (2678 rows, 85 s, 4 workers, launched 03:21, ALL RUNS COMPLETE 04:56):

    valid PE 2677   oep_exact 2305   imports 2250   all-three 2178 (raw)
    r111 raw: 2677 / 2299 / 2253 / 2177

4 gains - exactly the four PEtite rows above - and 3 raw losses, all three of them the documented **dur-86 wall flake** in
untouched families (mew_Procmon recall 0.912 at dur 86, nspack_ADInsight 0.311 at 86, nspack_Everything 0.9281 at 86);
re-run solo they all grade all-three with recall 1.0 (claims 0x4755cb, 0x434dac, 0x545f0d). The two habitual flakes
(nspack_Bginfo 0.0314, rlpack_geek 0.0521, dur 86/87) failed again in both rounds. So:

    refereed r111 = 2177 + 2 = 2179      refereed r112 = 2178 + 5 = 2183      -> +4, 0 real losses

Suite 609/609, 0 failed. The OEP-exact count also climbs 2299 -> 2305 raw, and the 15-row pool shrinks to 11.

#### 0.17kj The guard avenue is exhausted (PECompact neutral) - and the 9 "executes the true EP but claims elsewhere" rows share one shape

Extended the 0.17kh/0.17ki probe split from the `code_sim >= 0.95` pool to **every** `code_sim >= 0.8` OEP-wrong row
(18 rows), probing the true EP address (VA = base + the original's EP RVA) in each:

    executes the true EP : 9   PECompact 4 (md5summer, Hasher, Everything, Bginfo), RLPack 1 (geek),
                               Neolite 1 (HDDScan), NSPack 1 (Everything), MPRESS 1 (Bginfo), JDPack 1 (PEview)
    never executes it    : 9   WinUpack 1, RLPack 1, PEtite 1, MPRESS 1, JDPack 3, BeRo 1, ASPack 1

**Arming the payload-internal traffic guard for PECompact is a measured no-op.** 97-row family, 4 workers, 85 s:

    arm   all-three  oep_exact  imports   rows changed
    off   92         92         95        -
    on    92         92         95        0

So PEtite remains the *only* family that responded to that guard (+4). NSPack and JDPack are already armed and still get 3
of these rows wrong, which says the guard is not what decides them.

**What the 9 rows actually share** (meta reasons: section_hop 7, ladder_passc 2) is that the *claim sits inside the
packer's own stub section* while the payload's true entry executes:

    jdpack_PEview  ledger hop 0x41502e -> claim 0x4155f9   truth 0x401000   (0x4150xx is .jdpack, the stub)
    neolite_HDDScan   claim 0x7bb11e   truth 0x883d20
    mpress_Bginfo     claim 0x5ea681   truth 0x5b5d42
    pecompact_Bginfo  claim 0x401000   truth 0x5b5d42   (an EARLIER claim - the section start, i.e. a fallback)

i.e. the accepted hop is into the stub's own written section, and the payload's first execution never becomes a candidate.
The next hypothesis is mechanical and checkable: the claim ledger tracks `written_ranges_`, and those ranges can **span the
stub and the payload** (the packer decodes .text while its own section is also dirty); a hop that matches such a range
**erases the range** (unpack.cpp:1587-1591), which removes the payload's range too, so its first execution has nothing to
match. The experiment is to erase only the matching range's intersection with the hop's own section (or not to erase a
range that spans more than one section), gated, and A/B on PECompact (97) plus JDPack (100) - both families hold 4 and 4
of these rows and both are cheap to measure.

**Measured: the erase hypothesis is wrong too (not kept).** Built behind `TAOTE_HOP_ERASE_SPLIT` (do not erase a matched
range that spans more than one section) and A/B'd on both families that hold these rows:

    PECompact 97 rows:  all-three 92 -> 90   (-2: pecompact_AccessEnum 0x407a98 -> 0x403a53, pecompact_Diskmon
                                              0x40b4b8 -> 0x406a90, both OEP-exact before and OEP-wrong after)
    JDPack 100 rows:    all-three 95 -> 95   (0 rows changed - jdpack_PEview keeps 0x4155f9)

So a spanning range's erase is not what hides the payload's entry; keeping the range only lets an *earlier, worse* hop
win. Reverted.

Two negatives in a row on this pool (guard-for-PECompact neutral, erase-split -2) after one clean win (PEtite +4) is the
signal to stop hypothesising about the ledger and instead instrument it: the next attempt should print, for one of the 9
rows, every candidate (addr, matched range, prev_exec, accept/reject reason) at the moment the payload's true entry
executes - i.e. prove *why* that address is not a candidate before touching the mechanism again.

#### 0.17kk The instrument found it: JDPack's payload is IN THE CLEAR, so the written-range rule can never see the hand-off - corpus 2183 -> 2184 refereed

Per 0.17kj's decision I stopped hypothesising about the ledger and instrumented it (`TAOTE_HOP_TRACE=<addr>`, printed
*inside* `on_section_exec` **before** any early return, with the matched range, `prev_exec`, `stages_` and the early-return
state). One run on `jdpack_PEview`, tracing the true entry:

    [hoptrace] addr=0x401000 prev=0x415402 stages=0 dumped=0 ranges=2 matched=0 range=[0x0,0x0)
               in_written=0 inplace=0 ep_dist=0x14000

So the payload's first execution has `in_written=0` - no claimed range covers it - and the function returns before the hop
logic ever runs. The next instrument answered *why*: `TAOTE_UNPACK_DEBUG` shows the claims on that row are `.jdpack`,
`.rsrc`, `.idata` and `data`, and **never `code` (.text)**, and a corrected-syntax range census
(`TAOTE_WATCH_RANGE=0x401000-0x409110`) shows **not one write ever lands in `.text`** - so `code_sim 1.0` on this row is
trivial: the packed file already holds the payload's plaintext and the stub only redirects execution. The family is the
**in-clear class**, and no written-range rule can ever accept its hand-off.

Also worth recording: the packed file zeroes every section's Characteristics (`exec=0` on all six sections here, like
TELock), so `any_exec_watched` is false, the JDPack-class fallback watches `vsize > raw` sections, and the secondary watch
set ends up covering all six - which is why the exec hook *does* fire at 0x401000 but the write side never claims it.

**The mechanism** (`TAOTE_HOP_CLEAR`, unpack.cpp on_section_exec): when `in_written` is false, still accept a hand-off if
the transfer comes **out of the packer's own (packed-EP) section into a different image section** - the in-clear class.
Measured:

    JDPack 100 rows:  all-three 95 -> 96, oep_exact 96 -> 97, imports 99 -> 99, exactly ONE row changed
                      (jdpack_PEview 0x4155f9 -> 0x401000 = its true EP), zero collateral
    corpus r113 with the rule for EVERY family: +jdpack_PEview but -upx_FastHash_kr (0x41dffa -> 0x41bf46,
                      deterministic) - UPX decompresses INTO the destination section, so its transfers do have writes
                      and the fallback mis-fires
    corpus r114 with the rule scoped to JDPack: all-three 2182 raw (r112: 2178), oep 2307, imports 2253,
                      4 gains (jdpack_PEview plus the three recovered dur-86 flakes), ZERO losses

Refereed: r112 2178 + 5 flakes = 2183 -> r114 2182 + 2 flakes = **2184** (+1, exactly the designed row). The two habitual
flakes (nspack_Bginfo, rlpack_geek) failed in both rounds at dur 86.

`TAOTE_HOP_CLEAR` = unset -> JDPack only, `1` -> every family, `0` -> off.

#### 0.17kl Making the in-clear rule generic: a WEAK claim that only fills a gap or displaces stub-section junk (corpus-neutral, UPX regression removed)

0.17kk's rule lost one UPX row when enabled for every family. The cause was found with the same instrument: my clear hop
set `last_hop_imp_`/`have_hop_`, so the payload's *real* hop that followed on `upx_FastHash_kr` was rejected as
"import-quiet" (imports had not grown since) and the claim stayed at the wrong 0x41bf46. Two refinements fix the class:

1. **weak claim** - the clear candidate is emitted without touching `have_hop_`/`last_hop_imp_`, so a later written-range
   hop is judged as a first hop;
2. **gap-fill + stub-junk override** - it is emitted only when there is no claim yet, **or** when the existing claim sits
   *inside the packed-EP section* (junk by construction - `dump_module` already refuses the mirror case, a new candidate
   in the stub section never replacing an outside claim). Without (2) nothing is emitted at all on jdpack_PEview, whose
   `meta_oep_` is already 0x41502e in `.jdpack` when the real 0x401000 executes - measured directly with
   `TAOTE_HOP_TRACE` (`... in_written=0 ... meta_oep=0x41502e`).

Both rows are then correct: `upx_FastHash_kr` -> 0x41dffa (its truth) and `jdpack_PEview` -> 0x401000 (its truth).

Measured with the rule enabled for **every** family:

    UPX     108 rows: all-three 108 -> 108, 0 rows changed   (the r113 regression is gone)
    JDPack  100 rows: all-three  96 ->  96, 0 rows changed
    corpus r115 (global rule): 2178... 2182 raw / oep 2307 / imports 2253 - IDENTICAL to r114 (JDPack-scoped):
              0 gains, 0 losses, so the generic form buys nothing beyond jdpack_PEview and the shipped default stays
              JDPack-scoped (least blast radius). `TAOTE_HOP_CLEAR=1` now means "every family, safely".

So this round keeps no capability change (2184 refereed either way) but removes a deterministic regression from the
generic path and documents exactly why the two conditions are needed.

#### 0.17km The in-clear rule must NOT extend into in-place sections (PECompact 92 -> 51 all-three, measured, reverted)

The r115 meta pass showed the remaining `code_sim >= 0.8` OEP-wrong rows split by where the claim sits: mostly inside the
payload's own section but *earlier* than the truth, and the traces of two of them (both PECompact) show the killer is a
different early return than jdpack's:

    pecompact_md5summer, truth 0x49ec68: in_written=0 inplace=1 meta_oep=0x401016
    pecompact_Hasher,     truth 0x482628: in_written=0 inplace=1 meta_oep=0x401016

i.e. those transfers die at `if (inside_inplace(addr) && !in_written) return 0;` — the in-place guard, not the
written-range guard. So the natural experiment was to let the in-clear fallback run from that early return too
(hoisted into a `clear_hop_from_stub` lambda reachable from both). Measured on the 97-row PECompact family with
`TAOTE_HOP_CLEAR=1`:

    default (clear rule JDPack-only) :  all-three 92, oep 92, imports 95
    with the in-place path widened   :  all-three 51, oep 51, imports 95   (-41, 46 rows changed)

e.g. pecompact_AccessEnum 0x407a98 -> 0x42c564, Cacheset 0x4024a2 -> 0x4270dc, Diskmon 0x40b4b8 -> 0x43cde0 — every one
of them was OEP-exact and becomes wrong. The reason is the one Neolite already showed at family level: PECompact's `.text`
is written **later** (JIT), so the early stub->.text transfers are *internal* traffic, and answering them as hand-offs
destroys the claim. The in-place early return is load-bearing exactly as written.

Reverted; the clear rule stays gated to the `!in_written` path and to JDPack by default (r114/r115 = 2184 refereed).
This is the third measured negative in this area (PECompact guard -0, erase-split -2, in-place widening -41), so the
pool's remaining rows need a discriminator aimed at *which transfer is the entry*, not at widening the acceptance path.

#### 0.17kn Why every section-based rule failed on this pool: PECompact's stub lives INSIDE the payload's section

Auditing the picker before designing another rule produced the structural fact that explains the last three negatives.
`pecompact_md5summer` has **two sections and nothing else**:

    CODE    0x401000-0x4e3000  vs=0xe2000 raw=0x4fc00 exec=1 inplace
    .rsrc   0x4e3000-0x4ec000  vs=0x9000  raw=0x8c00  exec=1 inplace

with `packed_ep_va_ = 0x401000`. So the "packer's own section" IS the payload's section: the stub, the decoder and the
payload all live in one 0xe2000-byte `CODE` region, and the two transfers that were recorded by a stub-origin test
(0x4ebaec@0, 0x4ebb0f@3) sat in the same section as their targets. Every rule that asked "did the transfer leave the
packer's section" is therefore structurally inapplicable here:

    recorded truth 0x49ec68: prev=0x4ebba6 -> same section as the target -> not a cross-section transfer
    the pick then keeps 0x49a786 while the ledger holds only 0x4ebaec / 0x401016 / 0x4ebb0f

That is also why widening the in-clear path scored -41: an in-section rule degenerates into "accept every transfer" for a
single-section layout. Ledger-only recording (accept the transfer into `hop_ledger_` without claiming, so the finalize
pick can score it) was built behind `TAOTE_HOP_LEDGER_ONLY` and measured: it adds three candidates to the ledger on this
row and changes nothing (0x49a786 stays), because the discriminator has to be *content* (which of the transfers is an
entry) rather than geometry. Reverted.

The picker audit did show taote already carries a partial port of the reference's `pick_and_emit_oep`: a ledger, a
junk-latch rule (write ordinal >= 32), a `shape_at` prologue vote and an incumbent-strength rule (aspack_Cacheset,
molebox_AccessEnum, bero_Autologon are the measured cases). What it does NOT carry is the reference's V2/V3/V4 terms and,
more importantly, the reference's habit of *ledgering every candidate during the run and emitting once at pick time* -
taote claims at hop time, which is why the pool's earlier-than-truth claims are already fixed before any pick can reorder
them. The next unit is therefore to record (not claim) the in-section, stub-origin transfers and let the existing
`shape_at` pick choose - a content discriminator, which is the only kind this layout admits.

#### 0.17ko Content-gated in-section recording reaches the right candidate - the PICK still isn't the decider (and the legacy ledger is far worse)

Two more measurements in the same area, both reverted:

**1. The legacy ledger path is not the answer.** `TAOTE_CLAIM_LEDGER=0` (ledger every first-exec in a written section, no
claim consumption) on the families holding these rows:

    PECompact  97 rows: all-three 92 -> 90   (-2)
    Neolite    93 rows: all-three 73 -> 20   (-53)

Recording everything is far worse than the claim ledger, as the code comments already claimed - now re-measured on this
pool.

**2. Content-gated in-section recording works, but the pick never sees it.** Built behind `TAOTE_INPLACE_LEDGER`: on the
in-place early return, record (do not claim) a transfer whose target opens like an entry (`55 8b ec` / `6a ?? 68` /
`68 ?? e8` / `e8 ?? e5`). On pecompact_md5summer the ledger then holds **24** entries and the second one is the truth:

    [unpack] hop ledger (24): 0x401016@3 0x49ec68@924007 0x403f0c@924022 ...
    [unpack] pick OEP 0x49a786 (was 0x401016)

- the truth is recorded with a large write ordinal (924007), and the finalize printout then shows the settled ledger.
So the recording half of the reference's design is achievable; what is missing is that **the pick is not the decider** -
it returns a ladder address (0x49a786) that is not even in the ledger, i.e. the pick runs before/independently of these
late entries, and the claim (`meta_oep_`) is already fixed at hop time. Making this work needs the claim deferred to
finalize for the in-place class, which is a structural change to the emission path (dump_module writes the artifact at
claim time), not another accept/reject predicate.

Recorded state of the pool: 4 measured negatives (guard +/-0, erase-split -2, in-place widening -41, legacy ledger
-2/-53) and one positive (the in-clear JDPack hand-off, +1). Every one of the negatives is explained by PECompact keeping
stub + decoder + payload in a single section (0.17kn), so the only remaining lever there is content-based, and it needs
the deferral above.

#### 0.17kp The deferral works mechanically, but a FAMILY rule returns before the ledger vote - and that rule is what makes three other rows pass

Followed 0.17ko's plan: since the artifact is written **only in finalize** from `res.oep` (unpack.cpp:4391-4412), deferring
the claim is cheap - record the in-place, entry-shaped transfers and let `pick_oep` decide. Two pieces were built:

1. **record without claiming** (`TAOTE_INPLACE_LEDGER`): on the in-place early return, if the target opens like an entry
   (`55 8b ec` / `6a ?? 68` / `68 ?? e8` / `e8 ?? e5`), push it to `hop_ledger_`+`hop_write_seq_` and emit nothing.
   Measured: the ledger then holds the truth (0x49ec68@924007 on pecompact_md5summer, second entry after the junk latch).
2. **first-entry pick** in that mode: take the FIRST ledger candidate with `seq >= 32 && shape_at >= 2` instead of the
   last, because the in-place class appends the payload's own transfers *after* the entry.

Both work in isolation and neither changes the answer, and the reason is now located precisely: `pick_oep` has a
**PECompact-specific rule ahead of the incumbent vote** (unpack.cpp:3130-3170) -

    if (ladder != 0 && ladder != pep && ladder_is_startup_frame) -> return ladder   // "pecompact epfix"

which fires for these rows (the PassC ladder's 0x49a786 *is* a `55 8b ec 6a ff 68` startup frame) and returns before the
ledger vote is ever consulted. That rule is not removable: its own measurements are pecompact_{DarkNamer,Hash,rm}, which
it flips to exact and which currently pass. So on this family the two failing rows (md5summer, Hasher) trade directly
against three passing ones - a lottery, not a mechanism.

Reverted both pieces. This is the FIFTH measured negative in this pool (guard +/-, erase-split -2, in-place widening -41,
legacy ledger -2/-53, deferral + family rule = no change), and the conclusion is now firm: the 16 rows that are decoded
but OEP-wrong cannot be moved by any section predicate, ledger ordering, or acceptance change, because the only
available discriminator is a prologue shape that the family rule already uses for a *different* set of rows. Further work
there needs either a stronger content model (the reference's V3 quiescence term depends on an instruction timeline taote
does not record) or per-family knowledge of the kind the reference keeps in `v5_family` priors.

#### 0.17kq 616 rows run as family "unknown" - and the reference's EP-head signatures fix 245 of them (FSG 117, Exe32pack 128), with zero behaviour change

A corpus-wide census of the r115 logs found **616 of 2677 rows report `family=unknown`**, and they are whole families:

    Eronana 151/151   Exe32pack 124/124   BeRoEXEPacker 107/107   FSG 97/97
    Yoda-Crypter 92    Amber 41           Molebox 3               MPRESS 1

`opts_.family` comes from `guess_family()` (tools/taote.cpp:103) when the CLI passes none - i.e. from
`packer_detector.cpp` - and that detector keys these families on **section names** (`"fsg"`, `"$win8"`, `".bero"`,
`".eronana"`, `".yp"`). Those are exactly the families that blank or wipe their section names, so the marker can never
match. Every name-keyed seam in the runner is therefore silently inert on 23% of the corpus.

The reference hit the same wall and fixed it with **EP-head signatures** (its `ep_sigs()` map plus a 24-byte FSG stub-head
rule whose comment says every FSG row "was reported unknown -- which also left the name-keyed early-stop policy unable to
reach them"). Ported the two that are structurally censused, in the same idiom taote already uses for PECompact/TELock:

    FSG        BB ?? ?? ?? ??  BF ?? ?? ?? ??  BE ?? ?? ?? ??  53 E8 0A 00 00 00
    Exe32pack  3b c0 74 02 81

Selectivity measured over the **whole packed corpus** (3001 files, EP file offset computed from each file's own section
table):

    FSG signature:        117 hits, 117 in the FSG directory,    0 elsewhere
    Exe32pack signature:  128 hits, 128 in the Exe32pack directory, 0 elsewhere

which reproduces the reference's own census (117 of 119 FSG, 0 of 2,961). Behaviour measured on both families before and
after: **FSG all-three 96 -> 96, Exe32pack 92 -> 92, zero rows changed** - the labels are truthful now but nothing was
keyed on them, so this is a prerequisite, not a win. (Blast radius is fully enumerated, not inferred: the census above
proves no other row can be relabelled.)

**Also measured and rejected in the same area**: porting the reference's Exe32pack *stale second hop* rule
(Exe32packUnpacker::family_pre_dump_accept: "once an OEP is latched, a later section_hop is definitionally stale") as a
`dump_module` veto is catastrophic - **all-three 92 -> 17** (-75, 89 claims changed, e.g. exe32pack_AddInProcess
0x40681e -> 0x40c0eb) - because Exe32pack's stub legitimately hops again in taote's run; the reference applies that rule
at its own pre-dump seam with context taote does not have. Reverted.

The remaining 371 unknown rows (Eronana 151, BeRo 107, Yoda-Crypter 92, Amber 41, ...) need their own EP signatures
before any family-scoped mechanism can reach them.

#### 0.17kr Labelling the remaining unknown families is truthful but NOT behaviour-neutral: a label routes to a different seam

Censused and built the three remaining signatures (0.17kq's next unit), all measured over the packed corpus:

    BeRoEXEPacker  has("bero")       110 hits, all 110 BeRo, 0 elsewhere
                   (taote tested ".bero" WITH a dot; the names are "packerBY"/"bero^fr", so all
                    107 rows ran as "unknown" - the reference's table is the bare {"bero"})
    YodaCrypter    has("yc")         113 hits: 112 Yoda-Crypter + 1 Amber (the reference carries
                   the same signature and the same exposure)
    Eronana        EP {0x60,0x68}    260 hits on its own - 151 Eronana AND 109 BeRo - so it is
                   only safe AFTER the section rules: BeRo's "bero" claims its 109 first and
                   exactly the 151 Eronana rows reach the EP test

Family arms (4 workers, 85 s), before -> after:

    BeRoEXEPacker   103/107 -> 102/107     ONE regression
    Eronana Packer  137/151 -> 137/151     neutral
    Yoda-Crypter     92/92  ->  92/92      neutral

The BeRo regression is instructive: `bero_geek.exe` is OEP-exact at 0x559760 without the label and claims 0x6c25a2 with
it, i.e. **the label routes the row to a different seam** (a family packer instead of the generic one) whose pick differs.
So a truthful detection is a prerequisite only when the seam it selects has been audited; the FSG and Exe32pack labels of
0.17kq were exactly neutral because those seams happen to behave like the generic path (measured: zero rows changed in
both families), while BeRo's does not.

All three were reverted (a change that is neutral-or-worse on its own arms has no business shipping). The workable
sequence for the remaining 371 unknown rows is therefore: signature -> **seam audit** (run the family arm with and
without the label and diff every claim, as was done here for `bero_geek`) -> only then keep it.

#### 0.17ks The BeRo label ships as a genuine no-op; the "regression" that blocked 0.17kr was budget-cap noise

0.17kr reverted three detector signatures because BeRoEXEPacker's arm read 103 -> 102 with `bero_geek.exe` moving
0x559760 -> 0x6c25a2. That diagnosis was wrong, and the way it was wrong is the useful part:

    two arms of the SAME binary       102 vs 103, and exactly the same three rows moved with the same claims
    3 rows solo at 85 s               bero_geek 0x559760 / bero_HDDScan 0x7bb11e / bero_adwcleaner 0x566dbf (stable)
    the same 3 at 600 s, label OFF    geek 0x559760 / HDDScan 0x883d20 / adwcleaner 0x566dbf
    the same 3 at 600 s, label ON     geek 0x559760 / HDDScan 0x883d20 / adwcleaner 0x566dbf   <- IDENTICAL

So the label changes nothing on these rows; they are **cap-flaky**: `dur` is 86-87 in every 85 s arm (wall-capped) and
their claim depends on how much of the ladder scan finished. Any family arm containing such rows has a +/-1 noise floor,
and a one-row delta on a 100-row family is not evidence unless the row is re-run deterministically.

Census of the three: 110 corpus hits for `has("bero")`, all BeRoEXEPacker, 0 elsewhere (the reference's bare `{"bero"}`;
taote tested ".bero" WITH a dot, which the real `packerBY` / `bero^fr` names never match, hence 107 rows as "unknown").

SHIPPED: the BeRo signature only. The ladder shaping that the label newly unlocks (packer.hpp opts WinUpack/BeRo/NSPack/
RLPack into `ladder_skip_boundary` + `ladder_first_c3` from a round-50 measurement) was kept: at 600 s it is neutral on
all three flagged rows apart from bero_adwcleaner landing on 0x5468ca instead of 0x566dbf, both wrong against the truth
0xcfb5d8 (code_sim 0.40 - that row is decode-bound, not claim-bound).

BY-PRODUCT, and the more interesting lead: **bero_HDDScan.exe reaches its TRUE entry 0x883d20 at 600 s** while every
85 s arm claims 0x74dbe7/0x427ebc/0x7bb11e. That row is not claim-bound and not decode-bound - it is BUDGET-bound: the
ladder scan simply does not finish inside 85 s. Same truth as rlpack/mpress/neolite HDDScan (0x883d20), and neolite's
copy was closed earlier as "meta_oep_ already held 0xadaa70". Worth a census: how many of the corpus's misses have
`dur >= 84` and turn exact when given 600 s - that population is the honest target for a *faster* scan, not a bigger budget.

#### 0.17kt The corpus budget is NOT the binding constraint (23 capped failing rows, 0 gains at 7x), and Exe32pack's decode dies on a value, not a mapping

**Budget census.** 90 of 2678 rows finish at `dur >= 84` (the 85 s cap); 23 of those fail all-three. Re-ran all 23
through the same harness with `--unpack-timeout 600` (7x the budget): **0 all-three gains, 0 OEP gains**. So the cap costs
essentially nothing on this corpus and "make the scan faster" is not a lever - the one row that does benefit solo
(bero_HDDScan reaches its true 0x883d20 at 600 s single-threaded) does not survive 4-way wall-clock sharing, which is the
condition the corpus is graded in.

**Decoded-miss census (r115, 496 misses) by class:**

    A oep ungraded (managed/odd)      81      E import near-miss (recall>=0.85)  22
    C decode-bound OEP-wrong         272      F import-bound, decode low        94
    D decoded OEP-wrong               18      G import-bound, decoded             9
    C breakdown: Themida 122 + Yoda-Protector 100 (both also fail for the reference) + Amber 15 + Exe32pack 15 +
                 TELock 8 + NSPack 5 + WinUpack 2 + Alienyze 1. So the non-parity decode pool is only ~46 rows.

**Exe32pack, 15 rows, exact oracle available.** The reference decodes exe32pack_bzip2.exe to the ORIGINAL .text byte for
byte (19456/19456 equal), while taote's artifact .text is entirely zero - nothing is ever written there. The packed file
has a wiped section table (every raw size/pointer is 0 except .tls and .k; the payload+headers live in `.k` at ptr 0x600,
raw 0x4e0e, vsize 0x7302) and EP 0x1100c sits INSIDE `.k`, whose bytes are a self-modifying delta decoder
(`3b c0 74 02 81 83 55 ... call $+5 / pop ebp / sub ebp, 0x403aec`). taote runs 7727 writes inside `.k`, reaches
pc 0x4178a0, then dies on a **write to 0x54** - a store through a small uninitialised pointer, immediately after the stub's
`GetModuleHandleA("KERNEL32")` (the pointer 0x411190 really does hold "KERNEL32\0" in `.k`).

Two mechanisms measured and rejected for it (both reverted):

    TAOTE_NULLWRITE=1   mirror of the read-side null-page tolerance on WRITE faults: the run then dies on a FETCH
                        (UC_ERR_FETCH_UNMAPPED) instead - the pointer is computed from a value, so surviving the store
                        only moves the crash.
    TAOTE_STUB_CASE=Exe32pack  the export-name case-aware surface (the hashed-lookup hypothesis): bzip2, DriveCleanup and
                        touch all keep their exact claims and import counts.

KEPT: the write-unmapped diagnostic under TAOTE_SEHDBG (`[sehc] write unmapped addr=0x...`), which is what identified the
0x54 store as a value problem rather than a missing mapping.

NEXT UNIT for Exe32pack: the stub parses the module returned by GetModuleHandleA and stores a field from it; find what it
expects of that module (taote hands it a synthetic stub image at 0x10020000) and diff it against what the reference's
loader exposes. Alternative target with the same shape and fewer unknowns: Amber's 15 decode-bound rows.

#### 0.17ku A widened detector read silently killed PECompact's label: -29 rows, caught only by the corpus arm

Round 287 widened the EP-prefix read from 10 bytes (for PECompact's `b8 <imm32> 50 64 ff 35`) to 24 (for FSG's stub
head) and updated the FSG guard to `gcount() == 24`, but **left PECompact's guard at `gcount() == 10`**. Since the read is
now 24 bytes, `gcount()` is 24 for every file with 24 bytes available, so the PECompact test could never fire again:

    family label      r115 (before 287)   r116 (after)
    PECompact rows    92 all-three        63 all-three    (29 rows changed claim, e.g.
                                                           pecompact_FileTypesMan 0x4109f0 -> 0x401000)

Those 29 rows kept their original section names, so no other rule caught them: they silently became `family="unknown"`,
which disables the engine's PECompact seams (the pecompact-epfix ladder rule among them). Round 287 measured only its own
two families (FSG 96 -> 96, Exe32pack 92 -> 92) and skipped the corpus arm, which is exactly the rule this violated.

Fix: `gcount() >= 9` for PECompact and `gcount() >= 21` for FSG (the bytes each pattern actually needs, so a head that
ends near EOF cannot fall through). Measured: PECompact 92 -> 92 with **0 claims changed**, FSG 96 -> 96 with 0 claims
changed, and corpus r117 = valid PE 2677 / OEP 2306 / imports 2253 / all-three 2181 against r115's 2677/2307/2253/2182 -
the single difference being `bero_geek.exe`, the cap-flaky row whose 600 s claim is identical in both arms, so the
refereed baseline stays **2184** (r117 raw 2181 + the three habitual dur-86 flakes).

So the detector work of rounds 287-289 is now corpus-refereed and genuinely neutral, and the round's real yield is this
bug plus the rule-shaped lesson: **a family label is engine behaviour; any change to the detector needs the corpus arm,
not just the family it was designed for.**

Also in this round (see 0.17ks/0.17kt): the BeRo label ships as a measured no-op (with the ±1 family-arm noise floor
established), the 85 s budget is proved not to be the binding constraint (23 capped failing rows, 0 gains at 7x), and
Exe32pack's decode failure is localised to a value, not a mapping (a store to 0x54 through a stub-internal `self`
pointer that arrives as 0x40).

#### 0.17kv The real roadmap: 232 of taote's 497 misses are rows the REFERENCE solves (tools/ref_parity.py)

Until now "parity" was a corpus-level comparison (taote 2184 vs the reference's 1996), which says nothing about any single
row. `tools/ref_parity.py` (new) runs pegasus over every row taote fails and compares its `oep_rva` with the original EP
RVA - a per-row oracle, 497 rows in ~10 minutes at 6-way parallelism. Result on r117:

    family             taote misses the reference SOLVES
    TELock             116 of 116
    Exe32pack           30 of  32
    Amber               26 of  38
    WinUpack            14 of  16
    Eronana Packer      13 of  14
    Alienyze             7 of   8
    NSPack               7 of   7
    JDPack / MEW         4 of   4 each
    PECompact            4 of   5
    PEtite               3 of   8
    ASPack / BeRo / MPRESS  1 each
    TOTAL              232 of 232 -> solved

    both engines fail: Themida 122, Yoda-Protector 100, Amber 12, RLPack 9, PEtite 5, BeRo 4, Exe32pack 2, MPRESS 2,
    WinUpack 2, Alienyze 1, EXpressor 1, Eronana 1, FSG 1.

So the headroom is **232 portable rows, not ~135**, and 114 of them are TELock - a family this session had written off as
"decode-blocked" because taote's own artifacts never decode it. That conclusion was about *taote's* run, not about the
packer: the reference gets TELock's entry on all 116 rows and its artifact .text equals the original byte for byte.

**TELock diagnosis (the subject of the next rounds).** telock_7z.exe, taote vs the reference:

    reference   .text 65536/65536 bytes equal to not-packed/7z.exe's .text, OEP RVA 0xebc5 (exact)
    taote       .text  5133/65536 equal (packed entropy), OEP 0x40ebc5 via the ported telock_oep_table rule (exact)

So the OEP seam is already right; the *decode* is what differs. Three capture points measured, all garbage:

    first-write shadow (TAOTE_UNPACK_SHADOW_ALL=1)   48796 bytes restored, .text unchanged -> the shadow holds the
                                                     stub's own earlier writes, not the decryptor's output
    executed-page view (default)                     "exec-page overlay: 1 pages" - the payload executes one page
    hand-off whole-image snapshot (new, next para)   "handoff snapshot at 0x40ebc5 (110592 bytes)", .text unchanged

The last one is decisive: at the instant execution first leaves the stub section (the true EP), taote's image ALREADY
holds packed bytes. So the decryptor's output is not what taote's run ever holds, and the reference's own comment is the
explanation: "in TELock's at-OEP state the live memory already holds the fully unpacked image" - its run reaches the OEP
with a decoded image, taote's reaches the OEP with a re-encrypted one. That is a difference in the emulated *path* (the
stub's 59K SEH-ladder dispatches, the corrupt small pointers at 0x419128 that taote survives by mapping zero pages),
not in the dump.

New instrument kept (env-gated, default off, so the corpus is byte-identical): `TAOTE_HANDOFF_SNAP=1` snapshots the whole
image at the first fetch outside the packed-EP section and overlays it at finalize, logging
`[unpack] handoff snapshot at 0x... (N bytes)` / `[unpack] handoff overlay N bytes`.

#### 0.17kw TELock's decode diverges on ONE register: the second pass's rolling key (bl), not the code path

The reference's write log is the discriminator: `SE_TELOCK_WRLOG=<file> SE_TELOCK_WRLOG_FULL=1` prints
`addr value size pc` for every write (capped at 200k lines). Run on telock_7z.exe it shows BOTH engines walk the same
three-pass decryptor, with identical pcs:

    0x418da8  35328 writes   pass 1: copy the packed stream into .text   (byte-identical in both engines,
                                                                          verified at both ends of the span:
                                                                          0x401000..7 = 16 9a af e6 9b 52 bd ef,
                                                                          0x4099f0..f7 = 1c 6f 2c af 80 5e f0 de)
    0x418faa  loop start, writes each byte TWICE:
              0x418fc2  intermediate value   (both engines: 0x0c at 0x401000)
              0x418fe0  final value          REFERENCE 0x33 = the truth   TAOTE 0xda = the ciphertext
    0x4190ba / 0x419128  partial passes (43 / 223 writes in taote, 9434 in the reference at 0x419128)

Register-level comparison at the same pcs (`TAOTE_PROBE` vs the reference's `SE_TELOCK_STUBTRACE`):

    pc        engine      eax       ecx     edx         esi       edi        ebp
    0x418faa  taote       0x418faa  0       0x8f398597  0x409a00  0x409a00   0xc95e      (entry to the loop)
    0x418fab  both        0x1000    0x8a00  0xfd62f97a  0x3       0xc95e    0xc95e
    0x418fbe  taote       0x1043 ... IDENTICAL ...
    0x418fc2  both        0x100c    -       -           -         -          -           store 0x0c
    0x418fc8  reference   0x1033    ...     -           -         -          -           <- diverges here
    0x418fc8  taote       0x10da    ...     -           -         -          -

The loop body explains it exactly. At 0x418fbe `sub al,0x37` turns 0x43 into 0x0c; at 0x418fc4 `ror al,cl` (cl=0) is a
no-op; at 0x418fc6 `xor al,bl` mixes the rolling key. So `final = 0x0c ^ bl`:
**the reference's bl is 0x3f, taote's is 0xd6** (0x0c ^ 0xd6 = 0xda, exactly what taote stores). Every other register and
every other write in the stream matches, so this is NOT a code-path, mapping or decode-loop difference - it is one piece
of key state.

`ebx` is seeded before 0x418faa and is not touched by the copy pass (whose output is byte-identical), so the seed itself is
what differs between the two engines. Nearest suspects, in order: the stack address (taote esp=0x121ffc0, the reference
0x15fffc0 - TELock is an anti-emulation packer and a stack/PEB-derived key would explain a divergence that survives an
identical code path), a value read from a stub data slot the stub filled earlier, or an API return the two loaders answer
differently.

NEXT UNIT: find the ebx seed. Probe backward from 0x418faa at 4-byte steps (the loop entry is 0x418fab, so the seed is set
in the ~0x40 bytes before it) and compare `ebx` with the reference's, remembering that the reference's trace does NOT print
ebx - so the comparison has to be made through its write log (`final == intermediate ^ bl`) or by adding ebx to the
comparison via a probe of the reference's [stub] trace format.

#### 0.17kx TELock's wrong key has a cause: the reference decrypts its OWN STUB first (6481 bytes), taote skips it after 64

The reference's write log orders TELock's work unambiguously (line numbers in /tmp/wl.txt, 200k-write cap):

    1      .. 6481   pc=0x418030  writes 0x418041 .. 0x419991  - the stub decrypting ITSELF, byte at a time
    6482   .. 81657  pc=0x4199cb/0x4199cf/0x4199d2/0x4199d6    - a 4-instruction loop, 6474 writes (a copy)
    81658  ..        pc=0x418da8                                - the .text copy pass
    116986 ..        pc=0x418fc2 / 0x418fe0                     - the .text transform passes

taote's equivalent, measured with `TAOTE_WATCH_RANGE=0x418000-0x41b000` and a pc census:

    pc=0x418030   64 writes      (the reference: 6481)
    pc=0x4199xx   NONE           (the reference: 6474 x4)

and the first six writes are byte-identical in both engines (0x418041 = e8, 0x418042 = 7e, 0x418043 = 1b,
0x418044 = 00, 0x418045 = 00, 0x418046 = c3). So the ladder code is right and taote simply LEAVES it after 64 bytes,
then goes on to the .text passes - which is exactly why its rolling key byte differs (0.17kw) and its .text never decodes.

This also matches the reference's own comment in TELockUnpacker::family_terminal_fill: "the stage 1 dump (taken early,
before the 59K+ SEH ladder dispatches)" - the ladder is ~59K SEH dispatches, each decrypting a byte of the stub.

taote's SEH activity on this row, counted with `TAOTE_SEHDBG=1`: 5 null reads, 2 sentinel fetches, 2 `ret`, 2 `exhausted`.
It is not running a ladder at all.

Knobs measured, all unchanged (64 bytes and .text 5133/65536): TAOTE_TF_TRAPS=200000 (the TF single-step budget, default
4096 and raised to 40000 only for PEtite), TAOTE_NO_SEH_SEED=1, TAOTE_PROT_ENFORCE=1, TAOTE_SEH_FETCHPROT=1. The TF path in
README/0.17ja only fires when `emu_start` returns CLEANLY with eflags.TF set; TELock's run ends in a fault, so that branch
is never reached - which is the first thing to instrument next.

NEXT UNIT: find why the ladder exits after 64 bytes. The exit is between two identical write sequences, so it is a branch
whose condition reads memory/stack (the engines' esp differ: 0x121ffc0 vs 0x15fffc0). Instrument by probing the pcs around
the ladder's loop end (the reference's ladder pc is 0x418030; its callers/handlers live at 0x4186xx-0x4199xx) and by making
the TF single-step path reachable for TELock. Success is a single number: ladder writes 64 -> ~6481, then .text equal
5133 -> 65536 on telock_7z, then the 116-row TELock family via tools/ref_parity.py.

#### 0.17ky The ladder is single-step driven: taote delivers 2 exception dispatches where the reference delivers ~59K

Instrumented the invalid-instruction handler (debug-only) and measured telock_7z.exe end to end. The ladder's own code is
visible in live memory at its entry (`TAOTE_PROBE=0x418030` -> `30 06 46 5a eb 01 e9 ...` = `xor [esi],al; inc esi; ...`,
an overlapping-instruction stream), and its state at entry is CORRECT:

    ecx = 0x1951 = 6481      <- exactly the reference's write count, so the loop bound is right
    eax = 0x7efc             <- the XOR key
    esi = 0x418041           <- the first decrypted byte, which both engines write as 0xe8

and then the ladder STOPS after exactly 64 bytes (0x418041..0x418080), immediately followed by two CPU-exception
dispatches, in this order:

    0x419a08  b=0xf1  (ICEBP)  fs0=0x121ffb0  esp=0x121ffb0
    0x4186a8  b=0x8d  (#UD)    fs0=0x121ffb8  esp=0x121ffb8  -> handled=1, retarget=0x41868a

Both the guest's SEH chain (fs:[0] = 0x121ffb8, installed by the stub's own store at pc 0x4186a0 - 22 writes to the TEB,
same install/restore shape as the reference's `fs0 0x0 -> 0x15fffa0 at eip=0x4186a8`) and the handler address are RIGHT:
the reference dispatches to `eip=0x41868a` too. After the handler runs, the reference continues the ladder and taote goes
straight to the `.text` copy pass at 0x418da8 - which is why its rolling key never advances and its `.text` stays packed.

The counts make the missing mechanism unambiguous: the reference logs 5 `[insn-inv]` events but ~59K SEH dispatches
(its own comment: "the stage 1 dump, taken early, before the 59K+ SEH ladder dispatches"). taote logs 2 dispatch-worthy
events in total. taote's TF single-step delivery (qiling/os/windows/windows.cpp:1090-1112) only fires when `emu_start`
returns CLEANLY with eflags.TF set - measured: **zero clean returns on this row** (every exit is an exception), so that
branch is dead code here and the guest never sees a per-instruction #DB.

So the ladder is a single-step decryptor: execute one instruction, the #DB handler decrypts the next byte(s), repeat ~6481
times. Nothing about TELock's ladder code, its bounds, its key, its SEH chain or its handler differs between the engines -
only the *trap delivery* does.

NEXT UNIT: deliver #DB per instruction while eflags.TF is set. Either make `emu_start` return per instruction for TF runs
(the existing path) or add an instruction-level hook that stages `seh_dispatch_cpu(0x80000004)` when TF is set. Measure with
one number: ladder writes at pc 0x418030, 64 -> ~6481 (TAOTE_WATCH_RANGE=0x418041-0x418130 | grep -c 'pc=0x418030'), then
telock_7z `.text` equality 5133 -> 65536, then the TELock family, then the corpus. Cost control: TELock's ladder is ~59K
instructions, but the hook must not slow the other 2500 rows - gate it to TF-set windows only.

##### Correction to 0.17ky: the ladder is NOT TF/single-step driven - that inference is measured wrong

0.17ky concluded "the ladder is a single-step decryptor" from the reference's comment about "59K+ SEH ladder dispatches".
Tested the mechanism directly and it is wrong:

    TAOTE_TF_STEP=1   an instruction-level hook confined to the packed-EP section that calls emu_stop() whenever
                      eflags.TF is set (so the run loop's existing clean-return trap branch delivers the #DB), plus
                      set_tf_trap_cap(200000) for the ladder's ~6481 iterations.
    result            ladder writes at pc=0x418030: 64 -> 64.  .text equality unchanged.

So taote never observes TF set during this run at all (which is also why `TAOTE_RUNDBG` reports zero "emu_start returned
cleanly" lines - the two facts are the same fact). TELock arms TF at 0x418ad5, which is *after* the ladder region, so the
ladder cannot be TF-driven in the first place; the 64-byte exit is caused by the two exception dispatches that follow it
(0x419a08 ICEBP, 0x4186a8 #UD -> handler 0x41868a) and by whatever that handler does or returns to.

The prototype was reverted (measured and not kept). What 0.17ky still establishes, and what the next unit should use:

  * the ladder's state at entry is correct: ecx=6481 (the reference's exact write count), eax=0x7efc (the key),
    esi=0x418041 (its first decrypted byte, 0xe8 in both engines);
  * taote stops after exactly 64 decrypted bytes, then dispatches two CPU exceptions whose chain (fs:[0]=0x121ffb8,
    installed by the stub's own store at pc 0x4186a0) and handler address (0x41868a) both match the reference's;
  * after that handler the reference continues the ladder and taote jumps to the .text copy pass at 0x418da8.

NEXT UNIT, corrected: instrument the handler at 0x41868a - its first instructions, its `iret`/`ret` target, and the
registers/flags it restores into the interrupted context - because THAT is where the ladder is abandoned. A useful
single-number probe: does the reference return from that handler into the ladder region (a pc in [0x418030, 0x4180a0)) while
taote returns to 0x418da8? Compare with `TAOTE_PROBE` on both sides.

#### 0.17kz CORRECTION + the TELock divergence is now two precise facts: a flags-fidelity bug and a module-base-dependent key seed

**Correction first (my 0.17kx/0.17ky numbers were instrument artifacts).** `TAOTE_WATCH_RANGE` takes an optional `[:max]`
line cap, and I measured "the ladder writes 64 bytes" without it. With `TAOTE_WATCH_RANGE=0x418000-0x41b000:400000` taote's
census is IDENTICAL to the reference's write log:

    6481 pc=0x418030 (the stub self-decrypt)   6474 x4 pc=0x4199cb/0x4199cf/0x4199d2/0x4199d6 (copy loop)
    4823 pc=0x418432   4788 pc=0x4186d8   4754 pc=0x4186f9   4724 pc=0x418719  ...

and the ladder's written values match at both ends (0x418041=0xe8 .. 0x419991=0xfb, identical to the reference's log).
So the ladder, its bounds, its key and its output are all correct: 0.17ky's "taote stops after 64 bytes" is withdrawn.
Lesson (same family as the hop-trace placement mistake): check the diagnostic's own limits before drawing a conclusion.

**Fact 1 - the guest runs with IF=0, the reference with IF=1.** At the decrypt loop both engines hold eax/ecx/edx/esi/edi/
ebp/ebx identically, and the flags differ in exactly one bit: taote `eflags=0x47` (CF|PF|ZF), the reference `efl=0x247`
(same plus **IF**). A ring-3 Windows thread runs with IF=1 and cannot clear it (CLI faults with #GP, POPF ignores IF), while
unicorn executes CLI silently, so taote's stub reads back "interrupts disabled" and takes the emulator-detection branch.
Prototype `TAOTE_IF_USER=1` (re-assert IF at every basic block, env-gated, default off) makes taote's flags read 0x247 and
makes it execute the seed block at 0x418fb1..0x418fbc that it previously jumped over. It changes no grade yet, because of
fact 2.

**Fact 2 - the key seed is a stub data slot whose input is the MODULE BASE.** The seed instruction is
`mov ebx,[ebp+0x40d376]` = the dword at **0x419cd4**, and:

    reference   [0x419cd4] = 0x12cdd33f   (written at pc 0x41882b)
    taote       [0x419cd4] = 0x6d8fd7d6   (written at pc 0x41882b - same pc, different value)

The upstream input is one slot away: pc 0x41840c writes a module base to 0x419da0 -

    reference   0x419da0 = 0x77000000
    taote       0x419da0 = 0x10020000   (taote's synthetic stub-DLL base)

So TELock's decrypt key is derived from a module base, and the two loaders place that module differently. That is a LAYOUT
difference, not a decode mechanism, and it is the last thing between taote and a byte-exact TELock decode.

NEXT UNIT (one experiment decides the family): relocate taote's stub-DLL base for the TELock run to 0x77000000 and re-measure
`[0x419cd4]`, the key byte (bl at 0x418fbe; reference 0x12cdd33f) and telock_7z `.text` equality (5133 -> 65536). If the
decode becomes exact, the fix is a loader-layout one (matching the reference's module placement for this family) and it
should be measured corpus-wide; if not, the derivation is base-dependent in a way that needs the stub's hash function read.
Then also decide on `TAOTE_IF_USER` as a DEFAULT-ON fidelity fix (ring-3 IF is real Windows semantics), measured on the
corpus as its own unit.

#### 0.17la The 0.17kz "module base" hypothesis is measured wrong; what survives is the IF-fidelity fix tool

0.17kz ended on "TELock's key seed is derived from a module base (taote 0x10020000 vs the reference 0x77000000)". Tested
by teaching the stub-dll synthesizer to place the whole stub surface at a chosen base:

    TAOTE_STUB_IMAGEBASE=0x77000000   the stub records 0x77020000 at 0x419da0 (base+0x20000, so the synthesizer's own
                                      section offset lands on top) - and [0x419cd4] stayed 0x6d8fd7d6
    TAOTE_STUB_IMAGEBASE=0x76fe0000   chosen so the *mapped* base would be 0x77000000 - [0x419cd4] still 0x6d8fd7d6

So the decrypt key is NOT derived from that module base; 0x419da0 and 0x419cd4 are two independent stub fields that a
common routine happens to fill (both at pc 0x41882b's neighbourhood, 0x41840c for the first). The base override was
reverted, as was a redundant `TAOTE_IF_ALWAYS` prototype (it set IF once per run-loop iteration, which the guest's own CLI
immediately undid - superseded by the per-block TAOTE_IF_USER below).

KEPT (env-gated, default off) as the working tool for the next unit: **TAOTE_IF_USER=1** re-asserts IF at every basic block,
which is real ring-3 semantics (CLI faults with #GP; POPF ignores IF). With it, taote's flags at the decrypt loop read
0x247 exactly like the reference's, and taote executes the seed block at 0x418fb1..0x418fbc that it otherwise skips. It
changes no grade yet, and it is the strongest candidate for a DEFAULT-ON fidelity fix - to be evaluated as its own unit on
the corpus (it touches every family's flag state, so it needs the 2678-row arm before it ships).

WHAT IS STILL UNKNOWN, and the corrected next unit: with IF fixed, taote and the reference now walk the same seed block, yet
[0x419cd4] still differs (taote 0x6d8fd7d6, reference 0x12cdd33f) and that value is written at the SAME pc (0x41882b) in
both engines. So the input to that computation is something other than the two candidate fields tried so far. Next: read the
code at 0x41882b itself (TAOTE_PROBE=0x41882b dumps 40 live bytes plus the register file) and walk back to whatever feeds it,
comparing against the reference's trace with its new `ebx=` and `efl=` columns (both were added to the reference's stub trace
this round: it now prints ebx and eflags, which is what made the byte-level comparison possible at all).

#### 0.17lb BREAKTHROUGH: TELock's decrypt key is a fold over the stub's RESOLVED EXPORT TABLE, and forcing the right value decodes .text to 93%

Working from the reference's ebx/efl-bearing trace, TELock's key field is now fully mapped:

    0x41880f/0x418811  fold loop:   edx = (edx >> 8) ^ eax      (verified arithmetically on the reference's own
                                                                 sequence: 0x00926809 ^ 0x7472f296 = 0x74e09a9f)
                       seed:        0x92680909
                       eax:         a per-entry hash, one iteration per entry of the stub dll's export table
                                    (taote's counter runs from 0x1992 = 6546 down)
    0x418824           xor dx, word [ebp+0x1b55]  ->  the word at 0x419bd4 = 0xf900 in BOTH engines
    0x41882b           mov [ebp+0x1c55], edx       ->  the field at 0x419cd4, i.e. the key
    reference 0x12cdd33f   taote 0x6d8fd7d6

And the decisive experiment: with `TAOTE_TLOCK_KEY=<hex>` (new, env-gated, per-instruction hook that forces edx at
0x41882b - a per-BLOCK hook never sees that pc, it is mid-block, which is why the first attempt silently did nothing):

    TAOTE_TLOCK_KEY=0x12cdd33f  ->  telock_7z .text equals not-packed/7z.exe's .text for **61037 of 65536 bytes**
                                    (93.2%), against 5133 in every arm before it

So the key field is THE blocker: everything else about taote's TELock decode - the ladder, the copy pass, the intermediate
transform, the round-trip key 0xf900, the OEP - is already exact. The 4499 remaining bytes are a second-order difference
(most likely a second keyed field or the tail of the span).

Why the two engines disagree: the fold covers the stub dll's export table, and taote's surface (its own api_db SDK table) is
not the reference's (sdk_exports.inc, 24,291 names). One entry that differs, or a different ordering, changes the whole fold.
Measured and rejected as the cause already: export-name CASE (TAOTE_STUB_CASE=TELock / =all leave edx unchanged) and the
module base (0.17la).

NEXT UNIT, now concrete: align the TELock stub-dll export surface with the reference's sdk_exports.inc (same names, same
sorted order) and re-measure edx at 0x418824 against 0x12cd2a3f. If the fold matches, the decode is exact without any forced
value, and the whole 116-row family follows - measure the TELock family, then the corpus. If the fold still differs, dump the
per-entry eax hashes on both sides (TAOTE_PROBE=0x418811 with PROBE_N) and find the first entry whose hash differs, which
names are involved, and whether that name is in api_db at all. The fold's arithmetic is simple enough to reimplement
host-side, so an alternative (and possibly better) lever is to compute the key from the *packed* stub's own export
references rather than from taote's surface.

#### 0.17lc TELock's key fold diverges at export entry 280 because the two stub-DLL SURFACES differ (1584 vs 1651 names)

Following 0.17lb: the fold (`edx = (edx >> 8) ^ eax` at 0x41880f/0x418811) runs 6546 iterations in BOTH engines, and the
first iterations are IDENTICAL -

    idx      reference                        taote
    0        ebx=0x1992 eax=0x677845db  edx=0x6787ba24   identical
    ...      identical                      identical
    279      ebx=0x187b eax=0xe257a0dd  edx=0xe20028bb   identical
    280      ebx=0x187a eax=0x3e36130d  edx=0x3ed41325   eax=0x470317ee  <- FIRST DIVERGENCE
    281      ebx=0x1879 eax=0x9625524b  edx=0x961b8658   eax=0x0feb6709

One entry differs and, because the table is walked in sorted order, everything after it is shifted. The cause is the surface
itself:

    taote      qiling/unpack/api_db.inc (mingw-w64 import libs)  kernel32: 1584 names
    reference  src/windows/sdk_exports.inc (mingw-w64, own filter) kernel32: 1651 names
    73 names only in taote's list (BaseAttachCompleteThunk, ConvertToGlobalHandle, CreateSocketHandle, ...),
    140 only in the reference's (BaseCleanupAppcompatCacheSupportWorker, BaseProcessStart, BaseThreadStart, ...),
    and the sorted orders diverge already at index 44 (BaseAttachCompleteThunk vs BaseCheckAppcompatCache).

So TELock's decrypt key is a hash fold over the *actual export-name list of the module it resolves against*, and taote's
synthesised surface is a different list. Nothing about taote's decode machinery is wrong - with the reference's key value
forced, .text is 61037/65536 exact (0.17lb). taote simply computes the key from a different name list, exactly the way a
different Windows build would.

NEXT UNIT: port the reference's sdk_exports.inc surface into taote's stub-DLL writer (same names, same sorted order, per
module) - the reference added that file for this reason ("seed the stub export surface from the SDK") - then re-measure edx at
0x418824 against 0x12cd2a3f on telock_7z, then the TELock family (116 rows, all reference-solved per tools/ref_parity.py),
then the corpus. Note the size: the fold covers 6546 entries while kernel32 alone has ~1600 names, so the walked table spans
more than one DLL - the port has to preserve the *whole* per-module table, not just kernel32. If the exact reference list
cannot be reproduced, the fallback lever is to compute the key host-side from the packed stub's own references (the fold's
arithmetic is 3 instructions) and to take the *expected* value from wherever the stub's own check stores it.
