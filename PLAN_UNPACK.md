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
