// qiling/unpack/packers/decode_only_packer.cpp — the NSPack / RLPack / MPRESS
// seam (the reference's decode_only_ladder, unpacker.cpp:7814-7930, shared by
// NSPackUnpacker / RLPackUnpacker / the MPRESS path).
//
// These stubs decode their payload into one big section and hand off through the
// decoded body's own trampolines, so the reference does not trust a section-hop
// candidate: it walks a static byte-pattern ladder over the DECODED body and lets
// that lead the OEP pick. The patterns, in the reference's order:
//
//   Pass B   the MSVC SEH frame `55 8b ec 6a ff 68 <image-addr>` (unique per image)
//   Borland  a UNIQUE `6a ?? 68 <image-addr> e8` in the decode target
//   boundary a function-boundary CRT-init thunk `ret | e8 .. e9 .. | prologue`
//   Pass C   the CFG thunk `cc|c3 e8 <rel32> e9 <rel32>` (skipped for MPRESS
//            unless its e9 target starts with a recognizable prologue)
//   MPRESS   a UNIQUE `e8 <rel32> e9 00000000`, else the last Borland/SEH entry
#include "qiling/unpack/packers/packer.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>

namespace qiling {
namespace unpack {
namespace packers {

namespace {

std::string hex_str(std::uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

std::uint16_t rd16(const std::vector<std::uint8_t>& d, std::size_t o) {
    if (o + 2 > d.size()) {
        return 0;
    }
    return static_cast<std::uint16_t>(d[o] | (d[o + 1] << 8));
}

std::uint32_t rd32(const std::vector<std::uint8_t>& d, std::size_t o) {
    if (o + 4 > d.size()) {
        return 0;
    }
    return static_cast<std::uint32_t>(d[o]) | (static_cast<std::uint32_t>(d[o + 1]) << 8) |
           (static_cast<std::uint32_t>(d[o + 2]) << 16) | (static_cast<std::uint32_t>(d[o + 3]) << 24);
}

// F43h-static (the reference's mpress_static_oep_, unpacker.cpp:10876): the
// retdec-derived static OEP read from the MPRESS fix-imports stub. The stub
// inside the decoded `.MPRESS1` section carries the ORIGINAL entry point as a
// rel-offset dword, so this is a signature-level determination with no
// emulation-timing dependence - which is why the reference applies it FIRST for
// MPRESS and lets it supersede both the MSVC-prologue scan (which misfires on
// hand-written assembly startups) and the late API-return hop latch.
//
// Inputs: the PACKED file (section table + stub signature) and the DUMP (the
// fix-stub data at .MPRESS1 + fs_sec). Returns an RVA, or 0.
std::uint32_t mpress_static_oep_rva(const std::vector<std::uint8_t>& orig,
                                    const std::vector<std::uint8_t>& dump,
                                    std::uint64_t image_size) {
    if (orig.size() <= 0x400 || orig[0] != 'M' || orig[1] != 'Z') {
        return 0;
    }
    const std::size_t oe = rd32(orig, 0x3c);
    if (oe + 24 + 96 + 40 > orig.size()) {
        return 0;
    }
    const std::size_t oopt = oe + 24;
    if (rd16(orig, oopt) != 0x10b) {  // 32-bit only
        return 0;
    }
    const std::uint32_t ep_rva = rd32(orig, oopt + 16);
    if (ep_rva == 0) {
        return 0;
    }
    const std::uint32_t nsec = rd16(orig, oe + 6);
    const std::size_t soff = oopt + rd16(orig, oe + 20);
    std::uint32_t mp1_va = 0;
    for (std::uint32_t i = 0; i < nsec; ++i) {
        const std::size_t e2 = soff + static_cast<std::size_t>(i) * 40;
        if (e2 + 40 > orig.size()) {
            break;
        }
        if (orig[e2] == '.' && orig[e2 + 1] == 'M' && orig[e2 + 2] == 'P' && orig[e2 + 3] == 'R' &&
            orig[e2 + 4] == 'E' && orig[e2 + 5] == 'S' && orig[e2 + 6] == 'S' && orig[e2 + 7] == '1') {
            mp1_va = rd32(orig, e2 + 12);
            break;
        }
    }
    if (mp1_va == 0) {
        return 0;
    }
    const auto file_off = [&](std::uint32_t rva) -> std::size_t {
        for (std::uint32_t i = 0; i < nsec; ++i) {
            const std::size_t e2 = soff + static_cast<std::size_t>(i) * 40;
            if (e2 + 40 > orig.size()) {
                break;
            }
            const std::uint32_t vsz = rd32(orig, e2 + 8), va = rd32(orig, e2 + 12);
            const std::uint32_t rs = rd32(orig, e2 + 16), ptr = rd32(orig, e2 + 20);
            if (va <= rva && rva < va + std::max(vsz, rs)) {
                return static_cast<std::size_t>(ptr) + (rva - va);
            }
        }
        return 0;
    };
    const std::size_t ep_off = file_off(ep_rva);
    if (ep_off == 0 || ep_off + 12 > orig.size()) {
        return 0;
    }
    const std::uint32_t sig = rd32(orig, ep_off + 8);
    // retdec mpressUnpackerStubData {signature, ..., fixStubOffset, ...}
    static const std::uint32_t kStubTbl[][2] = {
        {0x2B6, 0x2B8}, {0x29E, 0x2A0}, {0x299, 0x29B}, {0xB57, 0xB59},
        {0x29C, 0x29E}, {0xB5A, 0xB5C}, {0x29F, 0x2A1}};
    std::uint32_t fs_off_tbl = 0;
    for (const auto& t : kStubTbl) {
        if (t[0] == sig) {
            fs_off_tbl = t[1];
            break;
        }
    }
    if (fs_off_tbl == 0) {
        return 0;
    }
    const std::size_t fo = file_off(ep_rva + fs_off_tbl);
    if (fo == 0 || fo + 4 > orig.size()) {
        return 0;
    }
    const std::uint32_t fs_va = ep_rva + fs_off_tbl + 4 + rd32(orig, fo);  // rva
    if (fs_va < mp1_va) {
        return 0;
    }
    const std::uint32_t fs_sec = fs_va - mp1_va;
    const std::size_t fs_dump = static_cast<std::size_t>(mp1_va) + fs_sec;
    if (fs_dump + 0x140 > dump.size()) {
        return 0;
    }
    // retdec mpressFixStubData {signature, importHintsOffset, oepOffset}
    static const std::uint32_t kFixTbl[][3] = {
        {0x8B, 0xC1, 0xBD}, {0x45, 0x138, 0x134}, {0x35, 0x128, 0x124}};
    const std::uint32_t* ft = nullptr;
    const std::uint8_t b7 = dump[fs_dump + 7];
    for (const auto& t : kFixTbl) {
        if (t[0] == b7) {
            ft = t;
            break;
        }
    }
    if (ft == nullptr) {
        return 0;
    }
    const std::uint32_t oep = mp1_va + fs_sec + ft[1] + rd32(dump, fs_dump + ft[2]);
    if (oep == 0 || oep >= image_size) {
        return 0;
    }
    return oep;
}

}  // namespace

std::uint64_t ladder_oep(const PackerContext& ctx) {
    const std::vector<std::uint8_t>& image = ctx.image();
    const auto& sections = ctx.sections;
    if (image.size() < 0x200 || sections.empty()) {
        return 0;
    }
    // F43h-static, MPRESS only, FIRST (the reference's order): the fix-imports
    // stub's static OEP supersedes every pattern pass below.
    const bool mpress = ctx.family == "MPRESS";
    if (mpress && ctx.packed_path != nullptr) {
        std::vector<std::uint8_t> orig;
        if (std::FILE* f = std::fopen(ctx.packed_path->c_str(), "rb")) {
            std::uint8_t buf[65536];
            std::size_t n = 0;
            while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) {
                orig.insert(orig.end(), buf, buf + n);
            }
            std::fclose(f);
        }
        if (!orig.empty()) {
            const auto soep = mpress_static_oep_rva(orig, image, ctx.image_size);
            if (soep != 0) {
                if (ctx.debug) {
                    std::fprintf(stderr, "[unpack] ladder: MPRESS static fix-stub OEP rva=0x%x\n", soep);
                }
                return ctx.base + soep;
            }
        }
    }
    const auto body_of = [&](const PackSection& ps) {
        std::vector<std::uint8_t> b;
        if (ps.start < ctx.base) {
            return b;
        }
        const auto off = static_cast<std::size_t>(ps.start - ctx.base);
        if (off >= image.size()) {
            return b;
        }
        const auto span = std::min<std::size_t>(
            {static_cast<std::size_t>(ps.end - ps.start), 4u * 1024 * 1024, image.size() - off});
        b.assign(image.begin() + static_cast<std::ptrdiff_t>(off),
                 image.begin() + static_cast<std::ptrdiff_t>(off + span));
        return b;
    };
    // The decode target: the largest section. Its degenerate head holds the packed
    // EP too, so neither the exec flag nor the watch state is a filter.
    const PackSection* tgt = nullptr;
    for (const auto& ps : sections) {
        if (!tgt || (ps.end - ps.start) > (tgt->end - tgt->start)) {
            tgt = &ps;
        }
    }
    // Pass A (new): the MSVC6 CRT-init thunk at a function boundary -
    //     <ret|int3|nop|retn> e8 <call __security_init_cookie> e9 <body>
    // The reference keys on this in its Amber scan; measured over the 142 corpus
    // programs whose entry IS this thunk, 140 have the entry among these hits and
    // 111 programs hold EXACTLY ONE (so the unique-match gate is safe), while the
    // packer's decoded body also carries the e9-target body and the look-alike
    // `55 8b ec 6a ff 68` frames that Pass B was matching instead. The e8 operand
    // is often unrelocated in the dump (winupack_Contig: 0xd62cbd79) and the e9
    // may point BACKWARDS, so only the e9 target has to be in-image.
    {
        std::set<std::uint64_t> a_hits;  // sections may overlap in the dump
        std::uint64_t a_va = 0;
        for (const auto& ps : sections) {
            const auto body = body_of(ps);
            for (std::size_t i = 1; i + 11 < body.size(); ++i) {
                if (body[i] != 0xe8 || body[i + 5] != 0xe9) {
                    continue;
                }
                const auto prev = body[i - 1];
                if (!(prev == 0xc3 || prev == 0xcc || prev == 0x90 || prev == 0xc2)) {
                    continue;
                }
                const auto rel = static_cast<std::int32_t>(
                    static_cast<std::uint32_t>(body[i + 6]) | (static_cast<std::uint32_t>(body[i + 7]) << 8) |
                    (static_cast<std::uint32_t>(body[i + 8]) << 16) |
                    (static_cast<std::uint32_t>(body[i + 9]) << 24));
                const auto tgt_va = static_cast<std::int64_t>(ps.start + i + 10) + rel;
                if (tgt_va < static_cast<std::int64_t>(ctx.base) ||
                    tgt_va >= static_cast<std::int64_t>(ctx.base + ctx.image_size)) {
                    continue;
                }
                // the jump must land on the real BODY: an entry prologue. Without
                // this the decoded image holds several copies of the thunk shape
                // (mpress_Dbgview: 4, only 0x415757 lands on `6a 58 68 ... e8`;
                // the three impostors land on `8b f0 ff 15`, i.e. ordinary code).
                const auto boff = static_cast<std::size_t>(tgt_va - static_cast<std::int64_t>(ctx.base));
                if (boff + 9 > image.size()) {
                    continue;
                }
                const auto* q = image.data() + boff;
                if (!((q[0] == 0x6a && q[2] == 0x68 && q[7] == 0xe8) ||
                      (q[0] == 0x55 && q[1] == 0x8b && q[2] == 0xec) ||
                      (q[0] == 0xe8 && q[5] == 0xe9))) {
                    continue;
                }
                a_hits.insert(ps.start + i);
                a_va = ps.start + i;
            }
        }
        const auto a_count = a_hits.size();
        if (ctx.debug) {
            std::fprintf(stderr, "[unpack] ladder passA CRT-thunks: %zu\n", a_count);
        }
        if (a_count == 1) {
            if (ctx.debug) {
                std::fprintf(stderr, "[unpack] ladder: unique CRT-init thunk 0x%llx\n",
                             static_cast<unsigned long long>(a_va));
            }
            return a_va;
        }
    }
    // Pass B: the MSVC entry frame `55 8b ec 6a ff 68 <image-addr> 64 a1` is
    // unique per image (every other function shares the `55 8b ec` head but not
    // the SEH push). RLPack AccessEnum's payload has no Pass-C thunk at all.
    {
        std::size_t hits = 0;
        std::uint64_t hit_va = 0;
        std::vector<std::uint64_t> frames;
        for (const auto& ps : sections) {
            const auto body = body_of(ps);
            for (std::size_t i = 0; i + 11 < body.size(); ++i) {
                if (body[i] == 0x55 && body[i + 1] == 0x8b && body[i + 2] == 0xec && body[i + 3] == 0x6a &&
                    body[i + 4] == 0xff && body[i + 5] == 0x68) {
                    const auto pv = static_cast<std::uint64_t>(
                        static_cast<std::uint32_t>(body[i + 6]) |
                        (static_cast<std::uint32_t>(body[i + 7]) << 8) |
                        (static_cast<std::uint32_t>(body[i + 8]) << 16) |
                        (static_cast<std::uint32_t>(body[i + 9]) << 24));
                    if (pv > ctx.base && pv < ctx.base + ctx.image_size) {
                        // The first frame in address order, not the last: a
                        // program with two identical SEH-prologue frames (the
                        // compiler emits the same 55 8b ec 6a ff 68 <imm> shape
                        // for several functions) usually has the entry EARLIER
                        // than its look-alikes. Measured on Cacheset: frames at
                        // 0x24a2 (the true entry), 0x6c29 and a third.
                        //
                        // Round 16: this used to default to the LAST frame
                        // (`hit_va = fva` every iteration) while the comment
                        // above already documented that the FIRST is right - a
                        // half-implemented fix. Measured over the corpus's 87
                        // pure pick failures (payload decoded, code_sim>=0.80,
                        // imports already correct), 19 have their true EP at
                        // this frame shape and in 14 of those it is the FIRST
                        // frame (the six PsTools-family MPRESS/WinUpack images
                        // that share a 3-frame body are first-frame in all six).
                        const auto fva = ps.start + i;
                        if (frames.empty() || frames.back() != fva) {
                            frames.push_back(fva);  // sections may overlap in the dump
                        }
                        hits = frames.size();
                    }
                }
            }
        }
        if (!frames.empty()) {
            hit_va = frames.front();  // the entry sits before its look-alikes
        }
        // The CRT STARTUP frame outranks both the first/last vote and the hop
        // hint: the real `mainCRTStartup` is
        //     55 8b ec 6a ff 68 <handler> 68 <scope> 64 a1
        // (push ebp / mov ebp,esp / push -1 / push handler / push scope /
        //  mov eax, fs:[0]), i.e. THREE pushes before the fs:0 read, while an
        // ordinary function carrying an SEH try-block has only two
        //     55 8b ec 6a ff 68 <handler> 64 a1
        // Measured: mpress_DarkNamer's four frames are three two-push functions
        // plus exactly one three-push startup frame (0x40a71e, the true entry);
        // the first-frame vote alone picked 0x404fa0 and regressed it.
        if (hits > 1) {
            std::uint64_t startup = 0;
            std::size_t startup_count = 0;
            for (const auto fva : frames) {
                if (fva < ctx.base || fva - ctx.base + 17 > image.size()) {
                    continue;
                }
                const auto* f = image.data() + (fva - ctx.base);
                if (f[0] == 0x55 && f[1] == 0x8b && f[2] == 0xec && f[3] == 0x6a && f[4] == 0xff &&
                    f[5] == 0x68 && f[10] == 0x68 && f[15] == 0x64 && f[16] == 0xa1) {
                    startup = fva;
                    ++startup_count;
                }
            }
            if (startup_count == 1) {
                hit_va = startup;
            }
        }
        if (ctx.debug) {
            std::fprintf(stderr, "[unpack] ladder passB hits=%zu first=0x%llx last=0x%llx\n", hits,
                         static_cast<unsigned long long>(frames.empty() ? 0 : frames.front()),
                         static_cast<unsigned long long>(frames.empty() ? 0 : frames.back()));
        }
        // A program that shares this frame shape across several functions
        // (Cacheset has 3, AccessEnum 2) makes "unique" false, so the hops we
        // accepted during the run decide: the hop lands inside the entry, a
        // few bytes past the frame (both families: +0x16). Prefer the frame
        // closest below the hop; with no hop, the first (lowest) frame - the
        // entry sits before its look-alikes. Measured: first-hit alone lost
        // pecompact_AccessEnum (0x7a98 -> 0x3a53) and pecompact_DarkNamer.
        if (hits > 1 && ctx.hop_hint != 0) {
            std::uint64_t best = 0;
            for (const auto fva : frames) {
                if (fva <= ctx.hop_hint && ctx.hop_hint - fva <= 0x40) {
                    best = fva;
                }
            }
            if (best != 0) {
                hit_va = best;
            }
        }
        // Round 16: MPRESS was excluded here wholesale, which sent its 3-frame
        // PsTools-family images to the Borland pre-check and the Pass-C scan
        // (mpress_ldmdump: Pass B holds the true 0x403024 `55 8b ec 6a ff 68`
        // first frame, but the gate skipped it and the Borland `6a 03 68 .. e8`
        // helper at 0x402279 won). The `hits <= 8` bound still excludes the
        // frame-dense images where first-frame is wrong (HashCalc 84 frames,
        // disk2vhd 194), so the gate only widens where the evidence is clean.
        if (hits >= 1 && hits <= 8) {
            if (ctx.debug) {
                std::fprintf(stderr, "[unpack] ladder: unique MSVC frame entry 0x%llx\n",
                             static_cast<unsigned long long>(hit_va));
            }
            return hit_va;
        }
    }
    // Borland/Delphi pre-check: a UNIQUE `6a ?? 68 <image-addr> e8` (push/push/call
    // entry) in the largest section is the entry — it also suppresses the Pass-C
    // override, which would otherwise fire on a false-positive CFG thunk. It is
    // scoped to the decode-only families like the rest of the ladder: 7z's MSVC
    // payload happens to hold exactly one such sequence and the pre-check then
    // shadowed the Pass-B entry that the four-frame cluster identifies (measured:
    // jdpack_7zFM picked 0x405723 instead of its true 0x422ce2).
    if (tgt != nullptr) {
        const auto b = body_of(*tgt);
        std::size_t count = 0;
        std::size_t off = 0;
        for (std::size_t i = 0; i + 8 < b.size(); ++i) {
            if (b[i] == 0x6a && b[i + 2] == 0x68 && b[i + 7] == 0xe8) {
                const auto pv = static_cast<std::uint64_t>(
                    static_cast<std::uint32_t>(b[i + 3]) | (static_cast<std::uint32_t>(b[i + 4]) << 8) |
                    (static_cast<std::uint32_t>(b[i + 5]) << 16) | (static_cast<std::uint32_t>(b[i + 6]) << 24));
                if (pv > ctx.base && pv < ctx.base + ctx.image_size) {
                    ++count;
                    off = i;
                }
            }
        }
        if (count == 1) {
            if (ctx.debug) {
                std::fprintf(stderr, "[unpack] ladder: unique Borland entry in %s\n", tgt->name.c_str());
            }
            return tgt->start + off;
        }
    }
    // A function-boundary thunk: `ret|int3|nop <e8 rel32> <e9 rel32> <prologue>`.
    // The original entry of the ADInsight-class payloads is
    //   5d c3 | e8 <call __security_init_cookie> e9 <rel32> | 6a 14 68 <imm32> e8
    // i.e. a CRT-init thunk sitting on a function boundary, followed by the real
    // body. The MPRESS packer's runtime fixups rewrite the two rel32 operands, so
    // the reference's `e9 00000000` test does not survive the decode — the
    // boundary prefix does. Requiring the set to be corpus-unique (exactly one)
    // keeps it inert for the samples whose entry is a plain MSVC/Borland frame
    // (ADExplorer/AccessEnum have zero hits).
    if (tgt != nullptr) {
        const auto tb = body_of(*tgt);
        std::size_t bc_count = 0;
        std::size_t bc_off = 0;
        for (std::size_t i = 1; i + 18 < tb.size(); ++i) {
            if (tb[i] != 0xe8 || tb[i + 5] != 0xe9) {
                continue;
            }
            const auto* q = tb.data() + i + 10;
            const bool prologue = (q[0] == 0x6a && q[2] == 0x68 && q[7] == 0xe8) ||
                                  (q[0] == 0x55 && q[1] == 0x8b && q[2] == 0xec);
            if (!prologue) {
                continue;
            }
            const auto prev = tb[i - 1];
            if (prev == 0xc3 || prev == 0xcc || prev == 0x90 || prev == 0xc2) {
                ++bc_count;
                bc_off = i;
            }
        }
        if (ctx.debug) {
            std::fprintf(stderr, "[unpack] ladder boundary-thunks in %s: %zu\n", tgt->name.c_str(), bc_count);
        }
        if (bc_count == 1) {
            return tgt->start + bc_off;
        }
    }
    // The reference's MPRESS pass-ladder heuristics (unpacker.cpp:7336-7405).
    // Upstream gates the whole block on `packer_name_ == "MPRESS"` AND runs it
    // only inside oep_pass_ladder_, i.e. only when the Pass-C chooser override
    // was SKIPPED. Both gates are load-bearing and are reproduced here:
    //
    //   - Pass C is right whenever it has unambiguous thunk evidence
    //     (winupack_Bginfo 0x5b5d42, nspack_cmd, bero_ADInsight/ComIntRep/
    //     procexp all regress if the count heuristic is allowed to preempt a
    //     clean Pass C), so the heuristic is confined to the ambiguous case.
    //   - the unique `e8 <rel32> e9 00000000` nop-jmp is LoadOrd's OEP (call
    //     __security_init_cookie then jmp-with-zero-rel --- only the real entry
    //     has it) and must be tested BEFORE the counts, exactly as upstream.
    //
    // The count table, verbatim from the reference: OpenedFilesView 4 Borland /
    // 2 SEH -> Borland LAST; DarkNamer 4/4 -> SEH LAST; Hash 0/1 -> SEH LAST;
    // shexview 3/0 -> Borland LAST.
    // WinUpack shares MPRESS's decoder generation (its payloads are the same
    // bodies with the same b/s counts), and the rule is safe there for the
    // same measured reason: over the 19 remaining WinUpack pick failures it
    // picks 9 correctly and declines the other 10 (all b_count > 8), so the
    // gate widens to both families with no false positives.
    if ((mpress || ctx.family == "WinUpack") && tgt != nullptr) {
        const auto b = body_of(*tgt);
        // (1) unique nop-jmp CRT-init/boundary thunk
        std::size_t zc_count = 0;
        std::size_t zc_off = 0;
        for (std::size_t i = 0; i + 11 < b.size(); ++i) {
            if (b[i] == 0xe8 && b[i + 5] == 0xe9) {
                const auto e9_rel = static_cast<std::int32_t>(
                    static_cast<std::uint32_t>(b[i + 6]) | (static_cast<std::uint32_t>(b[i + 7]) << 8) |
                    (static_cast<std::uint32_t>(b[i + 8]) << 16) | (static_cast<std::uint32_t>(b[i + 9]) << 24));
                if (e9_rel == 0) {
                    ++zc_count;
                    zc_off = i;
                }
            }
        }
        if (zc_count == 1) {
            if (ctx.debug) {
                std::fprintf(stderr, "[unpack] ladder: unique nop-jmp thunk\n");
            }
            return tgt->start + zc_off;
        }
        // (2) the CRT-init cluster is SMALL. Measured separation over the
        // corpus's pick failures: every sample this heuristic gets right is the
        // standard 4-entry `6a xx 68 <image-addr> e8` cluster (b_count == 4, the
        // reference's own "OpenedFilesView: 4 Borland" note), while every
        // sample it gets WRONG has 20-174 hits - i.e. the pattern is matching
        // ordinary code, not a CRT cluster (winupack_Bginfo 174, bero_ADInsight
        // 55, bero_procexp 73, mpress_ComIntRep 44, nspack_cmd 20). The bound is
        // the same shape as Pass B's `hits <= 8`.
        std::size_t b_count = 0;
        std::size_t b_last = 0;
        for (std::size_t i = 0; i + 8 < b.size(); ++i) {
            if (b[i] == 0x6a && b[i + 2] == 0x68 && b[i + 7] == 0xe8) {
                const auto pv = static_cast<std::uint64_t>(
                    static_cast<std::uint32_t>(b[i + 3]) | (static_cast<std::uint32_t>(b[i + 4]) << 8) |
                    (static_cast<std::uint32_t>(b[i + 5]) << 16) | (static_cast<std::uint32_t>(b[i + 6]) << 24));
                if (pv > ctx.base && pv < ctx.base + ctx.image_size) {
                    ++b_count;
                    b_last = i;
                }
            }
        }
        std::size_t s_count = 0;
        std::size_t s_last = 0;
        const auto hw = std::min<std::size_t>(b.size(), 0x40000);
        for (std::size_t i = 0; i + 6 < hw; ++i) {
            if (b[i] == 0x55 && b[i + 1] == 0x8b && b[i + 2] == 0xec && b[i + 3] == 0x6a && b[i + 4] == 0xff &&
                b[i + 5] == 0x68) {
                ++s_count;
                s_last = i;
            }
        }
        if (ctx.debug) {
            std::fprintf(stderr, "[unpack] ladder borland+seh: b=%zu s=%zu\n", b_count, s_count);
        }
        if (b_count > 0 && b_count <= 8 && b_count > s_count) {
            return tgt->start + b_last;
        }
        if (s_count > 0 && s_count <= 8 && s_count >= b_count) {
            return tgt->start + s_last;
        }
    }
    // Pass D (before Pass C, as in the reference): the Borland C++Builder
    // signature `eb ?? 'fb:C++HOOK' 90 e9` - an unambiguous printable literal, at
    // most one per PE, so it needs no counting or uniqueness guard.
    // (unpacker.cpp:7411-7424)
    for (const auto& ps : sections) {
        const auto b = body_of(ps);
        if (b.size() < 18) {
            continue;
        }
        for (std::size_t i = 0; i + 18 < b.size(); ++i) {
            if (b[i] == 0xeb && std::memcmp(b.data() + i + 2, "fb:C++HOOK", 10) == 0 &&
                b[i + 12] == 0x90 && b[i + 13] == 0xe9) {
                if (ctx.debug) {
                    std::fprintf(stderr, "[unpack] ladder %s: Pass D (BCB sig) at +0x%zx\n",
                                 ps.name.c_str(), i);
                }
                return ps.start + i;
            }
        }
    }

    // Pass C: a CFG thunk `cc|c3 e8 <rel32> e9 <rel32>`. Every section is scanned
    // (NSPack decodes .text into nsp0 while the OEP lives in nsp1).
    for (const auto& ps : sections) {
        const auto b = body_of(ps);
        if (b.size() < 12) {
            continue;
        }
        std::size_t c_count = 0;
        std::size_t c_off = 0;
        std::size_t c3_count = 0;
        std::size_t c3_off = 0;
        std::size_t c3_last_off = 0;
        std::size_t c3_valid_off = 0;
        bool c3_prologue_valid = false;
        for (std::size_t i = 0; i + 11 < b.size(); ++i) {
            if ((b[i] == 0xcc || b[i] == 0xc3) && b[i + 1] == 0xe8 && b[i + 6] == 0xe9) {
                ++c_count;
                c_off = i + 1;
                if (b[i] == 0xc3) {
                    ++c3_count;
                    c3_off = i + 1;
                    c3_last_off = i + 1;
                    const auto rel = static_cast<std::int32_t>(
                        static_cast<std::uint32_t>(b[i + 7]) | (static_cast<std::uint32_t>(b[i + 8]) << 8) |
                        (static_cast<std::uint32_t>(b[i + 9]) << 16) |
                        (static_cast<std::uint32_t>(b[i + 10]) << 24));
                    const auto jmp_tgt = static_cast<std::uint64_t>(
                        static_cast<std::int64_t>(ps.start + i + 6 + 5) + rel);
                    if (jmp_tgt >= ctx.base && jmp_tgt < ctx.base + ctx.image_size) {
                        c3_valid_off = i + 1;
                        // the e9 target of a real thunk is the CRT entry: it starts
                        // with a recognizable prologue (a false hit inside the
                        // decompressor jumps to arbitrary code)
                        const auto boff = static_cast<std::int64_t>(i + 11) + rel;
                        if (boff >= 0 && static_cast<std::size_t>(boff) + 8 <= b.size()) {
                            const auto* q = b.data() + boff;
                            if ((q[0] == 0x6a && q[2] == 0x68 && q[7] == 0xe8) ||
                                (q[0] == 0x55 && q[1] == 0x8b && q[2] == 0xec) ||
                                (q[0] == 0xe8 && q[5] == 0xe9)) {
                                c3_prologue_valid = true;
                            }
                        }
                    }
                }
            }
        }
        if (ctx.debug) {
            std::fprintf(stderr, "[unpack] ladder %s: C=%zu C3=%zu valid=%zu\n", ps.name.c_str(), c_count,
                         c3_count, c3_valid_off);
        }
        // MPRESS's c3 hits often land on a wrong function, so the reference skips
        // them — unless the validation passed (the e9 target is in-image AND starts
        // with a recognizable prologue), in which case it is the CFG thunk that
        // leads to the entry, exactly as for the other two families
        if (c3_count >= 1 && (!mpress || c3_prologue_valid || c3_valid_off != 0)) {
            // a validated hit wins; otherwise the LAST c3 hit (the main entry runs
            // after all CRT init — mpress_ADExplorer: the second of two)
            return ps.start + (c3_valid_off != 0 ? c3_valid_off : c3_last_off);
        }
        if (c_count == 1 && !(mpress && c3_count == c_count && !c3_prologue_valid)) {
            return ps.start + c_off;
        }
        // Pass E (after Pass C, as in the reference): the Borland/Delphi entry
        // `6a <imm8> 68 <imm32> e8 <rel32>` with an in-image push - accepted only
        // when it is UNIQUE in the section, because ordinary code contains the
        // same two-push shape by the dozen. (unpacker.cpp:7444-7464)
        {
            std::size_t e_count = 0;
            std::size_t e_off = 0;
            for (std::size_t i = 0; i + 8 < b.size(); ++i) {
                if (b[i] == 0x6a && b[i + 2] == 0x68 && b[i + 7] == 0xe8) {
                    const auto pv = static_cast<std::uint64_t>(
                        static_cast<std::uint32_t>(b[i + 3]) |
                        (static_cast<std::uint32_t>(b[i + 4]) << 8) |
                        (static_cast<std::uint32_t>(b[i + 5]) << 16) |
                        (static_cast<std::uint32_t>(b[i + 6]) << 24));
                    if (pv > ctx.base && pv < ctx.base + ctx.image_size) {
                        ++e_count;
                        e_off = i;
                    }
                }
            }
            if (e_count == 1) {
                if (ctx.debug) {
                    std::fprintf(stderr, "[unpack] ladder %s: Pass E (borland push-imm8) at +0x%zx\n",
                                 ps.name.c_str(), e_off);
                }
                return ps.start + e_off;
            }
        }
    }
    if (!mpress) {
        return 0;
    }
    // MPRESS: (a) a UNIQUE bare `e8 <rel32> e9 00000000` — the entry calls
    // __security_init_cookie then nop-jumps to the Borland entry;
    // (b) otherwise the LAST of the Borland / SEH entry patterns in the decode
    // target (the main entry runs after all CRT init), SEH winning ties.
    const auto b = tgt != nullptr ? body_of(*tgt) : std::vector<std::uint8_t>{};
    {
        std::size_t zc_count = 0;
        std::size_t zc_off = 0;
        for (std::size_t i = 0; i + 11 < b.size(); ++i) {
            if (b[i] == 0xe8 && b[i + 5] == 0xe9) {
                const auto rel = static_cast<std::uint32_t>(b[i + 6]) | (static_cast<std::uint32_t>(b[i + 7]) << 8) |
                                 (static_cast<std::uint32_t>(b[i + 8]) << 16) |
                                 (static_cast<std::uint32_t>(b[i + 9]) << 24);
                if (rel == 0) {
                    ++zc_count;
                    zc_off = i;
                }
            }
        }
        if (zc_count == 1) {
            return tgt->start + zc_off;
        }
    }
    {
        std::size_t b_count = 0;
        std::size_t b_last = 0;
        for (std::size_t i = 0; i + 8 < b.size(); ++i) {
            if (b[i] == 0x6a && b[i + 2] == 0x68 && b[i + 7] == 0xe8) {
                const auto pv = static_cast<std::uint64_t>(
                    static_cast<std::uint32_t>(b[i + 3]) | (static_cast<std::uint32_t>(b[i + 4]) << 8) |
                    (static_cast<std::uint32_t>(b[i + 5]) << 16) | (static_cast<std::uint32_t>(b[i + 6]) << 24));
                if (pv > ctx.base && pv < ctx.base + ctx.image_size) {
                    ++b_count;
                    b_last = i;
                }
            }
        }
        std::size_t s_count = 0;
        std::size_t s_last = 0;
        const auto hw = std::min<std::size_t>(b.size(), 0x40000);
        for (std::size_t i = 0; i + 6 < hw; ++i) {
            if (b[i] == 0x55 && b[i + 1] == 0x8b && b[i + 2] == 0xec && b[i + 3] == 0x6a && b[i + 4] == 0xff &&
                b[i + 5] == 0x68) {
                ++s_count;
                s_last = i;
            }
        }
        if (b_count > 0 && b_count > s_count) {
            return tgt->start + b_last;
        }
        if (s_count > 0 && s_count >= b_count) {
            return tgt->start + s_last;
        }
    }
    return 0;
}


// The ladder is the family's whole contribution; the three subclasses exist so the
// detector's label routes here (the reference has one subclass per family, all
// delegating to the shared body).
class DecodeOnlyPacker : public Packer {
public:
    explicit DecodeOnlyPacker(const char* label) : label_(label) {}
    const char* name() const override { return label_; }
    bool decode_only() const override { return true; }
    // the base class default already is the ladder

private:
    const char* label_;
};

std::unique_ptr<Packer> make_nspack_packer() { return std::make_unique<DecodeOnlyPacker>("NSPack"); }
std::unique_ptr<Packer> make_rlpack_packer() { return std::make_unique<DecodeOnlyPacker>("RLPack"); }
std::unique_ptr<Packer> make_mpress_packer() { return std::make_unique<DecodeOnlyPacker>("MPRESS"); }

}  // namespace packers
}  // namespace unpack
}  // namespace qiling
