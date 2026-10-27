// qiling/unpack/packers/embedded_pe.cpp — the Amber / Alienyze seam
// (the reference's try_embedded_pe, unpacker.cpp:10430-10520, and AmberUnpacker).
//
// Amber-class stubs do not decode in place: they decompress the payload into a
// heap buffer, build a *file-layout* PE there and jump into it. The image dump is
// therefore the stub itself, and the payload is found by scanning every non-image
// map for a second PE image (MZ + a valid optional header) and adopting the
// largest one.
#include "qiling/unpack/packers/factories.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "qiling/core.hpp"

namespace qiling {
namespace unpack {
namespace packers {

bool adopt_embedded_pe(Qiling& ql, PackerContext& ctx, std::vector<std::uint8_t>& image) {
    std::uint64_t best = 0;
    std::uint64_t best_size = 0;
    try {
        // The heap is mapped in page chunks, so a payload written through a
        // VirtualAlloc buffer straddles several map entries (amber_nbtstat's
        // 0x11400-byte image starts at 0x50009ea inside a 0x1000-byte map whose
        // successors are separate entries). Treat a CONTIGUOUS run of maps as
        // one region, otherwise the `soi <= hi - cand_base` gate below can never
        // hold for a heap-resident image.
        const auto maps = ql.mem().get_mapinfo();
        const auto run_end = [&maps](std::uint64_t start) {
            std::uint64_t end = start;
            bool grew = true;
            while (grew) {
                grew = false;
                for (const auto& m : maps) {
                    const auto m_lo = std::get<0>(m);
                    const auto m_hi = std::get<1>(m);
                    if (m_lo == end && m_hi > m_lo) {
                        end = m_hi;
                        grew = true;
                    }
                }
            }
            return end;
        };
        for (const auto& mi : maps) {
            const auto lo = std::get<0>(mi);
            const auto hi = run_end(lo);
            if (hi <= lo || lo == ctx.base || hi - lo < 0x1000 || hi - lo > 0x8000000) {
                continue;
            }
            if (lo >= 0x10000000) {
                continue;  // the loaded dll tree
            }
            // The payload is not always at the region base: Amber copies its
            // image into a heap buffer and runs it at a nonzero offset inside the
            // allocation (measured: exec at 0x5426bfc inside a 0x5001000-0x5428000
            // region whose head is zeros), so look for the MZ signature at every
            // 0x1000 step as well.
            std::vector<std::uint64_t> bases{lo};
            {
                std::vector<std::uint8_t> whole;
                try {
                    whole = ql.mem().read(lo, std::min<std::uint64_t>(hi - lo, 0x2000000));
                } catch (...) {
                    whole.clear();
                }
                for (std::uint64_t o = 0x1000; o + 0x200 <= whole.size(); o += 0x1000) {
                    if (whole[o] == 'M' && whole[o + 1] == 'Z') {
                        bases.push_back(lo + o);
                    }
                }
                // ...and at ANY offset, because the buffer VirtualAlloc hands
                // back is a heap chunk, not a page boundary: the payload image can
                // start anywhere inside it (amber_nbtstat: 0x9ea past the map
                // base). Bounded so a garbage-heavy region cannot explode the
                // candidate list; the PE32 + EXECUTABLE_IMAGE + section-layout
                // gates below do the real filtering.
                {
                    std::size_t seen = 0;
                    for (std::uint64_t o = 0; o + 0x200 <= whole.size() && seen < 64; ++o) {
                        if (whole[o] == 'M' && whole[o + 1] == 'Z') {
                            bases.push_back(lo + o);
                            ++seen;
                        }
                    }
                }
            }
            for (const auto cand_base : bases) {
            std::vector<std::uint8_t> head;
            try {
                head = ql.mem().read(cand_base, std::min<std::uint64_t>(hi - cand_base, 0x1000));
            } catch (...) {
                continue;
            }
            static const bool dbg = std::getenv("TAOTE_EMBEDDBG") != nullptr;
            if (dbg) {
                std::fprintf(stderr, "[embed] map 0x%llx-0x%llx head=%02x%02x%02x%02x\n",
                             static_cast<unsigned long long>(lo), static_cast<unsigned long long>(hi),
                             head.empty() ? 0 : head[0], head.size() < 2 ? 0 : head[1],
                             head.size() < 3 ? 0 : head[2], head.size() < 4 ? 0 : head[3]);
            }
            if (head.size() < 0x200 || head[0] != 'M' || head[1] != 'Z') {
                continue;
            }
            const auto lfanew = static_cast<std::size_t>(head[0x3c]) | (static_cast<std::size_t>(head[0x3d]) << 8) |
                                (static_cast<std::size_t>(head[0x3e]) << 16) |
                                (static_cast<std::size_t>(head[0x3f]) << 24);
            if (lfanew + 0x40 > head.size() || head[lfanew] != 'P' || head[lfanew + 1] != 'E') {
                if (dbg) std::fprintf(stderr, "[embed] reject noPE at 0x%llx lfanew=0x%zx\n",
                                      (unsigned long long)cand_base, lfanew);
                continue;
            }
            const auto opt = lfanew + 24;
            const auto magic = static_cast<std::uint32_t>(head[opt]) | (static_cast<std::uint32_t>(head[opt + 1]) << 8);
            if (magic != 0x10b && magic != 0x20b) {
                if (dbg) std::fprintf(stderr, "[embed] reject magic=0x%x at 0x%llx\n", magic,
                                      (unsigned long long)cand_base);
                continue;
            }
            const auto soi = static_cast<std::uint64_t>(head[opt + 0x38]) |
                             (static_cast<std::uint64_t>(head[opt + 0x39]) << 8) |
                             (static_cast<std::uint64_t>(head[opt + 0x3a]) << 16) |
                             (static_cast<std::uint64_t>(head[opt + 0x3b]) << 24);
            if (soi < 0x1000 || soi > hi - cand_base) {
                if (dbg) std::fprintf(stderr, "[embed] reject soi=0x%llx (room 0x%llx) at 0x%llx\n",
                                      (unsigned long long)soi, (unsigned long long)(hi - cand_base),
                                      (unsigned long long)cand_base);
                continue;
            }
            // Stricter acceptance (the reference requires EXECUTABLE_IMAGE and a
            // real section layout): scanning every 0x1000 step finds heap garbage
            // that merely starts with MZ, and adopting it replaces the image
            // (measured: Molebox Hasher/puttytel lost their decode this way).
            // Characteristics lives in the COFF header at lfanew+22, NOT in the
            // optional header: the old `opt + 0x46` read (lfanew+0x5E) is the high
            // half of NumberOfRvaAndSizes, so the EXECUTABLE_IMAGE gate below was
            // testing garbage and rejecting real payloads. amber_nbtstat's decoded
            // image at 0x5011dea reads 0x8140 there (no 0x0002) while its COFF
            // Characteristics is 0x0102. The reference reads
            // `rd16(head, coff + 18)` (unpacker.cpp:10583).
            const auto chars = static_cast<std::uint32_t>(head[lfanew + 22]) |
                               (static_cast<std::uint32_t>(head[lfanew + 23]) << 8);
            const auto ep_rva = static_cast<std::uint64_t>(head[opt + 0x10]) |
                                (static_cast<std::uint64_t>(head[opt + 0x11]) << 8) |
                                (static_cast<std::uint64_t>(head[opt + 0x12]) << 16) |
                                (static_cast<std::uint64_t>(head[opt + 0x13]) << 24);
            if ((chars & 0x0002) == 0 || ep_rva == 0 || ep_rva >= soi) {
                if (dbg) std::fprintf(stderr, "[embed] reject chars=0x%x ep=0x%llx soi=0x%llx at 0x%llx\n",
                                      chars, (unsigned long long)ep_rva, (unsigned long long)soi,
                                      (unsigned long long)cand_base);
                continue;
            }
            const auto use_base = cand_base;
            if (dbg) {
                std::fprintf(stderr, "[embed] candidate MZ+PE at 0x%llx sizeimg 0x%llx (map 0x%llx)\n",
                             static_cast<unsigned long long>(use_base),
                             static_cast<unsigned long long>(soi),
                             static_cast<unsigned long long>(lo));
            }
            if (soi > best_size) {
                best = use_base;
                best_size = soi;
            }
            }
        }
    } catch (...) {
        return false;
    }
    if (best == 0) {
        return false;
    }
    std::vector<std::uint8_t> embedded;
    try {
        embedded = ql.mem().read(best, best_size);
    } catch (...) {
        return false;
    }
    if (embedded.size() < 0x200) {
        return false;
    }
    // adopt: the payload image replaces the stub's. The engine re-derives its own
    // section table from the adopted image (it owns the watch set), so this module
    // only reports the new base/size and the sections it parsed.
    const auto old_base = ctx.base;
    image = embedded;
    ctx.adopted_base = best;
    ctx.adopted_size = best_size;
    ctx.adopted_sections.clear();
    const auto rd = [&embedded](std::size_t o) -> std::uint32_t {
        if (o + 4 > embedded.size()) {
            return 0;
        }
        return static_cast<std::uint32_t>(embedded[o]) | (static_cast<std::uint32_t>(embedded[o + 1]) << 8) |
               (static_cast<std::uint32_t>(embedded[o + 2]) << 16) |
               (static_cast<std::uint32_t>(embedded[o + 3]) << 24);
    };
    const auto rd16 = [&embedded](std::size_t o) -> std::uint32_t {
        if (o + 2 > embedded.size()) {
            return 0;
        }
        return static_cast<std::uint32_t>(embedded[o]) | (static_cast<std::uint32_t>(embedded[o + 1]) << 8);
    };
    const auto e_lfanew = static_cast<std::size_t>(rd(0x3c));
    const auto n_sec = rd16(e_lfanew + 6);
    const auto opt_size = rd16(e_lfanew + 20);
    const auto sec_table = e_lfanew + 24 + static_cast<std::size_t>(opt_size);
    for (std::size_t i = 0; i < n_sec && i < 96; ++i) {
        const auto o = sec_table + i * 40;
        PackSection ps;
        for (std::size_t k = 0; k < 8 && embedded[o + k] != 0; ++k) {
            ps.name.push_back(static_cast<char>(embedded[o + k]));
        }
        ps.vsize = rd(o + 8);
        ps.start = best + rd(o + 12);
        ps.end = ps.start + (ps.vsize ? ps.vsize : 1);
        ps.raw = rd(o + 16);
        const auto ch = rd(o + 36);
        ps.is_exec = (ch & 0x20000000u) != 0;
        ctx.adopted_sections.push_back(ps);
    }
    if (ctx.debug) {
        std::fprintf(stderr, "[unpack] embedded PE at 0x%llx size 0x%llx (stub at 0x%llx)\n",
                     static_cast<unsigned long long>(best), static_cast<unsigned long long>(best_size),
                     static_cast<unsigned long long>(old_base));
    }
    return true;
}


// The base class default: the reference's packer-agnostic try_embedded_pe. Any
// family can build its payload in a heap buffer, so the recovery must not be
// gated on the label.
bool Packer::adopt_embedded_pe(PackerContext& ctx) {
    if (ctx.ql == nullptr || ctx.image_ptr == nullptr) {
        return false;
    }
    // adopt_embedded_pe fills ctx.adopted; the scan itself works on a copy so the
    // caller's image is untouched until it accepts the payload
    std::vector<std::uint8_t> probe = *ctx.image_ptr;
    return packers::adopt_embedded_pe(*ctx.ql, ctx, probe);
}

class AmberPacker : public Packer {
public:
    const char* name() const override { return "Amber"; }
    bool adopt_embedded_pe(PackerContext& ctx) override {
        if (ctx.ql == nullptr) {
            return false;
        }
        std::vector<std::uint8_t> adopted = ctx.image();
        if (!packers::adopt_embedded_pe(*ctx.ql, ctx, adopted)) {
            return false;
        }
        ctx.adopted = std::move(adopted);
        return true;
    }
};

// Alienyze is Amber-class: the stub builds the payload elsewhere too, so the same
// adoption applies (the reference's AlienyzeUnpacker adds the per-sample XOR
// recovery on top, see PLAN_UNPACK §0.5.3d row 6).
// ---- Alienyze: single-byte XOR image recovery ---------------------------
//
// Ported from the reference's src/unpacker/alienyze.cpp. The stub decrypts the
// original image on demand through guard pages the emulation never trips, so the
// dump still holds the XOR'd body and the stub itself exits immediately
// (measured: alienyze_* finish in dur=0 with stages=0, imports 0/126). The
// reference therefore recovers statically:
//
//   1. al_score_window / al_recover_key: score x86-code likelihood over 14
//      windows spread from the first section VA for all 256 keys, take the best.
//   2. al_recover_key_store: fallback when the code score fails - every name in
//      the `.alien` store ends in ".dll", so the pattern '.','d','l','l' ^ k must
//      appear at least twice there.
//   3. XOR mem[first_sec_va..end) with the key.
//   4. Restore the original IMAGE BODY, which the stub stashes (same key) inside
//      `.alien` behind its import store at .alien+0x7e0, over the hollow
//      (rsize == 0) sections' RVAs - gated on the x86-code score so a layout
//      drift skips the copy instead of corrupting the image, and deferred until
//      after the import parse in the reference because the packer's FT/INT
//      tables live inside the hollow region this copy overwrites.
namespace alienyze {

// the reference's al_score_window: +8 per `55 8b|89 ec|e5` prologue, +4 per
// e8/e9 call/jmp with an in-image 4-aligned target, +5 per ff 15/25 or
// `8b|8d modrm==05` absolute reference into the image
int score_window(const std::uint8_t* p, std::size_t n, std::uint32_t img_off,
                 std::size_t image_size) {
    if (p == nullptr) {
        return 0;
    }
    const auto rd32 = [p](std::size_t i) -> std::uint32_t {
        return static_cast<std::uint32_t>(p[i]) | (static_cast<std::uint32_t>(p[i + 1]) << 8) |
               (static_cast<std::uint32_t>(p[i + 2]) << 16) |
               (static_cast<std::uint32_t>(p[i + 3]) << 24);
    };
    int s = 0;
    std::size_t i = 0;
    while (i + 6 < n) {
        const std::uint8_t b = p[i];
        if (b == 0x55 && (p[i + 1] == 0x8B || p[i + 1] == 0x89) &&
            (p[i + 2] == 0xEC || p[i + 2] == 0xE5)) {
            s += 8;
            i += 3;
            continue;
        }
        if (b == 0xE8 || b == 0xE9) {
            const auto rel = static_cast<std::int32_t>(rd32(i + 1));
            const std::int64_t addr = static_cast<std::int64_t>(img_off) +
                                      static_cast<std::int64_t>(i) + 5 + rel;
            if (addr >= 0x1000 && addr < static_cast<std::int64_t>(image_size) && (addr & 3) == 0) {
                s += 4;
                i += 5;
                continue;
            }
        }
        if (b == 0xFF && (p[i + 1] == 0x15 || p[i + 1] == 0x25)) {
            const auto v = rd32(i + 2);
            if (v >= 0x1000 && v < image_size && (v & 3) == 0) {
                s += 5;
                i += 6;
                continue;
            }
        }
        if ((b == 0x8B || b == 0x8D) && (p[i + 1] & 0xC7) == 0x05) {
            const auto v = rd32(i + 2);
            if (v >= 0x1000 && v < image_size && (v & 3) == 0) {
                s += 5;
                i += 6;
                continue;
            }
        }
        i++;
    }
    return s;
}

int recover_key(const std::vector<std::uint8_t>& mem, std::uint32_t first_sec_va) {
    std::vector<std::uint32_t> offs;
    const std::size_t start = first_sec_va ? first_sec_va : 0x1000;
    const std::size_t span = mem.size() > start ? mem.size() - start : 0;
    for (std::size_t f = 0; f < 14; ++f) {
        const std::size_t o = start + (span * f) / 16;
        if (o + 0x180 <= mem.size()) {
            offs.push_back(static_cast<std::uint32_t>(o));
        }
    }
    int best_key = -1;
    int best_score = -1;
    std::vector<std::uint8_t> xbuf(0x180);
    for (int k = 0; k < 256; ++k) {
        int tot = 0;
        for (const std::uint32_t o : offs) {
            for (std::size_t i = 0; i < 0x180; ++i) {
                xbuf[i] = mem[o + i] ^ static_cast<std::uint8_t>(k);
            }
            tot += score_window(xbuf.data(), 0x180, o, mem.size());
        }
        if (tot > best_score) {
            best_score = tot;
            best_key = k;
        }
    }
    return best_score <= 0 ? -1 : best_key;
}

// al_recover_key_store: the known-plaintext ".dll" suffix scan in `.alien`
int recover_key_store(const std::vector<std::uint8_t>& mem, std::size_t a_lo, std::size_t a_hi) {
    if (a_hi > mem.size()) {
        a_hi = mem.size();
    }
    int best_k = -1;
    std::size_t best_n = 0;
    for (int k = 1; k < 256; ++k) {
        const auto p0 = static_cast<std::uint8_t>('.' ^ k);
        const auto p1 = static_cast<std::uint8_t>('d' ^ k);
        const auto p2 = static_cast<std::uint8_t>('l' ^ k);
        std::size_t n = 0;
        for (std::size_t i = a_lo; i + 4 <= a_hi; ++i) {
            if (mem[i] == p0 && mem[i + 1] == p1 && mem[i + 2] == p2 && mem[i + 3] == p2) {
                ++n;
            }
        }
        if (n > best_n) {
            best_n = n;
            best_k = k;
        }
    }
    return best_n >= 2 ? best_k : -1;
}

struct Sec {
    std::string name;
    std::uint32_t vsize = 0, va = 0, rsize = 0;
};

// al_stub_sections: the packed image's own section table
std::vector<Sec> stub_sections(const std::vector<std::uint8_t>& raw) {
    std::vector<Sec> out;
    const auto rd32 = [&raw](std::size_t o) -> std::uint32_t {
        if (o + 4 > raw.size()) {
            return 0;
        }
        return static_cast<std::uint32_t>(raw[o]) | (static_cast<std::uint32_t>(raw[o + 1]) << 8) |
               (static_cast<std::uint32_t>(raw[o + 2]) << 16) |
               (static_cast<std::uint32_t>(raw[o + 3]) << 24);
    };
    const auto rd16 = [&raw](std::size_t o) -> std::uint32_t {
        if (o + 2 > raw.size()) {
            return 0;
        }
        return static_cast<std::uint32_t>(raw[o]) | (static_cast<std::uint32_t>(raw[o + 1]) << 8);
    };
    const std::size_t lfanew = rd32(0x3c);
    const auto n_sec = rd16(lfanew + 6);
    const auto opt_size = rd16(lfanew + 20);
    const std::size_t sec_tab = lfanew + 24 + opt_size;
    for (std::uint32_t i = 0; i < n_sec && i < 96; ++i) {
        const std::size_t o = sec_tab + i * 40;
        if (o + 40 > raw.size()) {
            break;
        }
        Sec s;
        for (std::size_t k = 0; k < 8 && raw[o + k] != 0; ++k) {
            s.name.push_back(static_cast<char>(raw[o + k]));
        }
        s.vsize = rd32(o + 8);
        s.va = rd32(o + 12);
        s.rsize = rd32(o + 16);
        out.push_back(s);
    }
    return out;
}

}  // namespace alienyze

class AlienyzePacker : public AmberPacker {
public:
    const char* name() const override { return "Alienyze"; }

    bool transform_image(PackerContext& ctx) override {
        if (ctx.image_mut == nullptr || ctx.image_mut->empty()) {
            return false;
        }
        auto& mem = *ctx.image_mut;
        const auto secs = alienyze::stub_sections(mem);
        if (secs.empty()) {
            return false;
        }

        std::uint32_t first_sec_va = 0;
        std::uint32_t a_lo = 0;
        std::uint32_t a_hi = 0;
        for (const auto& s : secs) {
            if (s.va != 0 && (first_sec_va == 0 || s.va < first_sec_va)) {
                first_sec_va = s.va;
            }
            if (s.name == ".alien") {
                a_lo = s.va;
                a_hi = s.va + s.vsize;
            }
        }
        if (a_lo == 0 || a_hi > mem.size()) {
            return false;
        }

        int key = alienyze::recover_key(mem, first_sec_va);
        if (key <= 0) {
            key = alienyze::recover_key_store(mem, a_lo, a_hi);
        }
        if (key <= 0) {
            if (ctx.debug) {
                std::fprintf(stderr, "[unpack] alienyze: key solve failed\n");
            }
            return false;
        }
        for (std::size_t i = first_sec_va; i < mem.size(); ++i) {
            mem[i] ^= static_cast<std::uint8_t>(key);
        }
        if (ctx.debug) {
            std::fprintf(stderr, "[unpack] alienyze: key=0x%02x decoded [0x%x..0x%zx)\n", key,
                         first_sec_va, mem.size());
        }

        // ---- the corpus-variant body relocation ----
        // The packed section table keeps the ORIGINAL layout but hollows the raw
        // data (rsize == 0); the original IMAGE BODY (RVA layout, same key) sits
        // in `.alien` behind the import store at .alien+0x7e0. Restore it over
        // the hollow RVAs, gated on the x86-code score so a layout drift skips
        // the copy instead of corrupting the image.
        const auto rd32 = [&mem](std::size_t o) -> std::uint32_t {
            if (o + 4 > mem.size()) {
                return 0;
            }
            return static_cast<std::uint32_t>(mem[o]) | (static_cast<std::uint32_t>(mem[o + 1]) << 8) |
                   (static_cast<std::uint32_t>(mem[o + 2]) << 16) |
                   (static_cast<std::uint32_t>(mem[o + 3]) << 24);
        };
        const std::size_t packed_lfanew = rd32(0x3c);
        const std::uint32_t packed_ep_rva =
            packed_lfanew + 24 + 40 <= mem.size() ? rd32(packed_lfanew + 24 + 16) : 0;

        std::uint32_t hollow_start = 0;
        std::uint32_t hollow_end = 0;
        bool has_hollow = false;
        for (const auto& s : secs) {
            if (s.name == ".alien" || s.va == 0 || s.vsize == 0) {
                continue;
            }
            if (s.rsize == 0) {
                if (hollow_start == 0) {
                    hollow_start = s.va;
                }
                if (s.va + s.vsize > hollow_end) {
                    hollow_end = s.va + s.vsize;
                }
                has_hollow = true;
            }
        }

        constexpr std::uint32_t kPayloadOff = 0x7e0;  // .alien+0x7e0, every corpus sample
        const std::size_t psrc = static_cast<std::size_t>(a_lo) + kPayloadOff;
        if (has_hollow && psrc + 0x180 < mem.size() && hollow_end > hollow_start &&
            hollow_end <= mem.size()) {
            const int score = alienyze::score_window(mem.data() + psrc, 0x180,
                                                     static_cast<std::uint32_t>(psrc),
                                                     static_cast<std::uint32_t>(mem.size()));
            std::size_t avail = mem.size() - psrc;
            if (packed_ep_rva > psrc) {
                avail = std::min<std::size_t>(avail, static_cast<std::size_t>(packed_ep_rva - psrc));
            }
            const std::size_t n =
                std::min<std::size_t>(avail, static_cast<std::size_t>(hollow_end - hollow_start));
            if (score >= 20 && psrc >= hollow_end && n > 0x1000) {
                std::copy_n(mem.begin() + static_cast<std::ptrdiff_t>(psrc),
                            static_cast<std::ptrdiff_t>(n),
                            mem.begin() + static_cast<std::ptrdiff_t>(hollow_start));
                if (ctx.debug) {
                    std::fprintf(stderr,
                                 "[unpack] alienyze: body copy [0x%x..0x%llx) <- .alien+0x%x "
                                 "(%zu bytes, score=%d)\n",
                                 hollow_start,
                                 static_cast<unsigned long long>(hollow_start + n), kPayloadOff, n,
                                 score);
                }
            } else if (ctx.debug) {
                std::fprintf(stderr,
                             "[unpack] alienyze: body copy skipped (score=%d n=%zu psrc=0x%zx "
                             "hollow_end=0x%x)\n",
                             score, n, psrc, hollow_end);
            }
        }

        // report the geometry from the (now decoded) image; the engine re-derives
        // its watch set from these
        ctx.adopted_base = 0;  // same base: the payload was restored in place
        ctx.adopted_sections.clear();
        for (const auto& s : secs) {
            if (s.va == 0 || s.vsize == 0) {
                continue;
            }
            PackSection ps;
            ps.name = s.name;
            ps.vsize = s.vsize;
            ps.start = ctx.base + s.va;
            ps.end = ps.start + s.vsize;
            ps.raw = s.rsize;
            ps.is_exec = (s.name == ".text" || s.name == ".alien");
            ctx.adopted_sections.push_back(ps);
        }
        return true;
    }
};

std::unique_ptr<Packer> make_amber_packer() { return std::make_unique<AmberPacker>(); }
std::unique_ptr<Packer> make_alienyze_packer() { return std::make_unique<AlienyzePacker>(); }

}  // namespace packers
}  // namespace unpack
}  // namespace qiling
