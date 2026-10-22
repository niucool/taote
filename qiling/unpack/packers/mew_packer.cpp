// qiling/unpack/packers/mew_packer.cpp — the MEW seam
// (../pegasus/src/unpacker/packers/mew_unpacker.cpp).
//
// MEW parses its own OEP out of a header table at install time:
//
//   packed EP  e9 <rel32>        -> the stub
//   stub       be <imm32>        mov esi, <table>
//   table+4    <imm32>           the original OEP (a VA)
//
// and it memsets the decoded image right before handing off, so the terminal dump
// is zeroed where the payload lives: the dump must come from the first-write
// shadow image (the reference keeps the full overlay for this family alone,
// unpacker.cpp:178-200).
#include "qiling/unpack/packers/factories.hpp"

#include <cstdint>
#include <cstdio>
#include <vector>

#include "qiling/core.hpp"

namespace qiling {
namespace unpack {
namespace packers {

namespace {

std::uint32_t rd32(const std::vector<std::uint8_t>& v, std::size_t o) {
    if (o + 4 > v.size()) {
        return 0;
    }
    return static_cast<std::uint32_t>(v[o]) | (static_cast<std::uint32_t>(v[o + 1]) << 8) |
           (static_cast<std::uint32_t>(v[o + 2]) << 16) | (static_cast<std::uint32_t>(v[o + 3]) << 24);
}

}  // namespace

// The header-table parse (mew_unpacker.cpp:28-64). Returns 0 when the shape does
// not match or the recorded entry is outside the image.
std::uint64_t mew_parse_static_oep(Qiling& ql, std::uint64_t packed_ep_va, std::uint64_t base,
                                   std::uint64_t image_size) {
    try {
        const auto ep = ql.mem().read(packed_ep_va, 5);
        if (ep.size() != 5 || ep[0] != 0xe9) {
            return 0;
        }
        const auto rel = static_cast<std::int32_t>(rd32(ep, 1));
        const auto stub_va = static_cast<std::uint64_t>(static_cast<std::int64_t>(packed_ep_va + 5) + rel);
        const auto st = ql.mem().read(stub_va, 5);
        if (st.size() != 5 || st[0] != 0xbe) {
            return 0;  // mov esi, imm32
        }
        const auto table = rd32(st, 1);
        const auto ov = ql.mem().read(table + 4, 4);
        if (ov.size() != 4) {
            return 0;
        }
        const auto va = static_cast<std::uint64_t>(rd32(ov, 0));
        if (va < base || va >= base + image_size) {
            return 0;
        }
        return va;
    } catch (...) {
        return 0;
    }
}

class MewPacker : public Packer {
public:
    const char* name() const override { return "MEW"; }
    ShadowPolicy shadow_policy() const override { return ShadowPolicy::first_write; }

    std::uint64_t static_oep(const PackerContext& ctx) const override {
        if (ctx.ql == nullptr) {
            return 0;
        }
        const auto oep = mew_parse_static_oep(*ctx.ql, ctx.packed_ep_va, ctx.base, ctx.image_size);
        if (oep != 0 && ctx.debug) {
            std::fprintf(stderr, "[unpack] mew static OEP 0x%llx\n", static_cast<unsigned long long>(oep));
        }
        return oep;
    }
};

std::unique_ptr<Packer> make_mew_packer() { return std::make_unique<MewPacker>(); }

}  // namespace packers
}  // namespace unpack
}  // namespace qiling
