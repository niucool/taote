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

namespace qiling {
namespace unpack {
namespace packers {

namespace {

std::string hex_str(std::uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

}  // namespace

std::uint64_t ladder_oep(const PackerContext& ctx) {
    const std::vector<std::uint8_t>& image = ctx.image();
    const auto& sections = ctx.sections;
    if (image.size() < 0x200 || sections.empty()) {
        return 0;
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
    const bool mpress = ctx.family == "MPRESS";
    // The decode target: the largest section. Its degenerate head holds the packed
    // EP too, so neither the exec flag nor the watch state is a filter.
    const PackSection* tgt = nullptr;
    for (const auto& ps : sections) {
        if (!tgt || (ps.end - ps.start) > (tgt->end - tgt->start)) {
            tgt = &ps;
        }
    }
    // Pass B: the MSVC entry frame `55 8b ec 6a ff 68 <image-addr> 64 a1` is
    // unique per image (every other function shares the `55 8b ec` head but not
    // the SEH push). RLPack AccessEnum's payload has no Pass-C thunk at all.
    {
        std::size_t hits = 0;
        std::uint64_t hit_va = 0;
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
                        ++hits;
                        hit_va = ps.start + i;
                    }
                }
            }
        }
        if (ctx.debug) {
            std::fprintf(stderr, "[unpack] ladder passB hits=%zu last=0x%llx\n", hits,
                         static_cast<unsigned long long>(hit_va));
        }
        if (!mpress && hits >= 1 && hits <= 8) {
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
