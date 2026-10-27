// qiling/unpack/packers/neolite_packer.cpp — Neolite's terminal OEP fill.
//
// Ported from the reference's NeoliteUnpacker::family_terminal_fill
// (../pegasus/src/unpacker/packers/neolite_unpacker.cpp:501-622).
//
// Neolite decodes the payload IN PLACE, so the original program's CRT entry
// frame survives byte-identical in the dump. What fails is the PICK: the stub's
// hand-off is a plausible-looking first byte (0x8b/0xe8/...) at a place that is
// not the entry, so neither the accepted-hop rule nor the decode-only ladder can
// tell it from the real one. The reference's answer is a last-resort scan for
// the compiler's CRT entry frames, applied AFTER the pick and gated on the pick
// being demonstrably not entry-shaped.
//
// Three signatures, all measured across the family corpus by the reference:
//   P1e  VS2010 CRT main entry (the SEH-init chain)  - high precision
//   P2   VS2005/08 CRT entry (frame + call [IAT])    - high precision
//   P3   linker entry thunk (call; jmp; int3 pad)    - loose, rescue only
#include "qiling/unpack/packers/factories.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <vector>

namespace qiling {
namespace unpack {
namespace packers {

namespace {

bool match_at(const std::vector<std::uint8_t>& img, std::size_t i, const char* pat,
              std::size_t plen) {
    // '?' in the pattern is a wildcard byte; every other byte must match. The
    // reference spells the same three patterns as escaped C strings.
    if (i + plen > img.size()) {
        return false;
    }
    for (std::size_t j = 0; j < plen; ++j) {
        const char c = static_cast<char>(img[i + j]);
        if (pat[j] != '?' && pat[j] != c) {
            return false;
        }
    }
    return true;
}

// P1e: e8 ???? 6a ? 68 ???? e8 ???? 33 db 89 5d fc 64 a1 18 00 00 00
const char kP1e[] = "\xe8????\x6a?\x68????\xe8????"
                    "\x33\xdb\x89\x5d\xfc\x64\xa1\x18\x00\x00\x00";
constexpr std::size_t kP1eLen = 28;
// P3: e8 ???? e9 ???? cc cc cc cc
const char kP3[] = "\xe8????\xe9????\xcc\xcc\xcc\xcc";
constexpr std::size_t kP3Len = 14;
// P2 head: 55 8b ec 83 ec ?  then {53|56|57} ff 15
const char kP2[] = "\x55\x8b\xec\x83\xec?";

}  // namespace

class NeolitePacker : public Packer {
public:
    const char* name() const override { return "Neolite"; }

    bool family_fill(PackerContext& ctx) override {
        if (ctx.oep_mut == nullptr || ctx.base == 0) {
            return false;
        }
        const auto& img = ctx.image();
        if (img.size() < 64) {
            return false;
        }
        const std::uint64_t oep = *ctx.oep_mut;

        std::set<std::uint32_t> cands;     // every CRT-entry candidate (rva)
        std::set<std::uint32_t> high;      // P1e + P2 only (corpus-unique)
        for (std::size_t i = 0; i + 32 < img.size(); ++i) {
            if (match_at(img, i, kP1e, kP1eLen)) {
                cands.insert(static_cast<std::uint32_t>(i));
                high.insert(static_cast<std::uint32_t>(i));
            }
            if (match_at(img, i, kP3, kP3Len)) {
                cands.insert(static_cast<std::uint32_t>(i));
            }
            if (match_at(img, i, kP2, 6) && (img[i + 6] == 0x53 || img[i + 6] == 0x56 ||
                                             img[i + 6] == 0x57) &&
                img[i + 7] == 0xff && img[i + 8] == 0x15) {
                cands.insert(static_cast<std::uint32_t>(i));
                high.insert(static_cast<std::uint32_t>(i));
            }
        }

        // A VS CRT entry begins 55/e8/e9/eb/6a/68. Any other first byte is
        // mid-function junk, which is the only case this fill may override -
        // rows with a genuinely shaped pick must keep it (the reference's
        // cur_plausible gate: psping's e8/e9 trampoline pick must not be
        // replaced by a decoy P3 hit elsewhere in its image).
        bool cur_plausible = false;
        if (oep >= ctx.base && oep - ctx.base < img.size()) {
            const auto b = img[static_cast<std::size_t>(oep - ctx.base)];
            cur_plausible = b == 0x55 || b == 0xe8 || b == 0xe9 || b == 0xeb || b == 0x6a ||
                            b == 0x68;
        }
        const auto cur_rva = oep >= ctx.base ? static_cast<std::uint32_t>(oep - ctx.base)
                                            : 0xffffffffu;

        const std::set<std::uint32_t>* use = nullptr;
        if (high.size() == 1 && !high.count(cur_rva) && !cur_plausible) {
            use = &high;   // the corpus-unique VS2010/VS2005 entry overrides
        } else if (cands.size() == 1 && (oep == 0 || !cur_plausible)) {
            use = &cands;  // the loose thunk only rescues an unusable pick
        }
        if (use == nullptr) {
            return false;
        }

        const auto rva = *use->begin();
        if (ctx.debug) {
            std::fprintf(stderr, "[unpack] neolite: CRT entry frame at rva 0x%x (cands=%zu high=%zu)\n",
                         rva, cands.size(), high.size());
        }
        *ctx.oep_mut = ctx.base + rva;
        return true;
    }
};

std::unique_ptr<Packer> make_neolite_packer() { return std::make_unique<NeolitePacker>(); }

}  // namespace packers
}  // namespace unpack
}  // namespace qiling
