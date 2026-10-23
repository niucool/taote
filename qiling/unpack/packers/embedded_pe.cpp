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
        for (const auto& mi : ql.mem().get_mapinfo()) {
            const auto lo = std::get<0>(mi);
            const auto hi = std::get<1>(mi);
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
                continue;
            }
            const auto opt = lfanew + 24;
            const auto magic = static_cast<std::uint32_t>(head[opt]) | (static_cast<std::uint32_t>(head[opt + 1]) << 8);
            if (magic != 0x10b && magic != 0x20b) {
                continue;
            }
            const auto soi = static_cast<std::uint64_t>(head[opt + 0x38]) |
                             (static_cast<std::uint64_t>(head[opt + 0x39]) << 8) |
                             (static_cast<std::uint64_t>(head[opt + 0x3a]) << 16) |
                             (static_cast<std::uint64_t>(head[opt + 0x3b]) << 24);
            if (soi < 0x1000 || soi > hi - cand_base) {
                continue;
            }
            // Stricter acceptance (the reference requires EXECUTABLE_IMAGE and a
            // real section layout): scanning every 0x1000 step finds heap garbage
            // that merely starts with MZ, and adopting it replaces the image
            // (measured: Molebox Hasher/puttytel lost their decode this way).
            const auto chars = static_cast<std::uint32_t>(head[opt + 0x46]) |
                               (static_cast<std::uint32_t>(head[opt + 0x47]) << 8);
            const auto ep_rva = static_cast<std::uint64_t>(head[opt + 0x10]) |
                                (static_cast<std::uint64_t>(head[opt + 0x11]) << 8) |
                                (static_cast<std::uint64_t>(head[opt + 0x12]) << 16) |
                                (static_cast<std::uint64_t>(head[opt + 0x13]) << 24);
            if ((chars & 0x0002) == 0 || ep_rva == 0 || ep_rva >= soi) {
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
class AlienyzePacker : public AmberPacker {
public:
    const char* name() const override { return "Alienyze"; }
};

std::unique_ptr<Packer> make_amber_packer() { return std::make_unique<AmberPacker>(); }
std::unique_ptr<Packer> make_alienyze_packer() { return std::make_unique<AlienyzePacker>(); }

}  // namespace packers
}  // namespace unpack
}  // namespace qiling
