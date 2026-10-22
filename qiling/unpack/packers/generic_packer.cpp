// qiling/unpack/packers/generic_packer.cpp — the default packer and the factory
// (the reference's GenericUnpacker + PackerDetector::create_unpacker).
//
// GenericUnpacker is a deliberate no-op in the reference too
// (src/unpacker/packers/generic_unpacker.cpp:1-8): every family without a
// dedicated seam runs the base engine unchanged.
#include "qiling/unpack/packers/factories.hpp"

#include <cctype>
#include <string>

namespace qiling {
namespace unpack {
namespace packers {

namespace {

class GenericPacker : public Packer {
public:
    const char* name() const override { return "generic"; }
};

std::string lower_ascii(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

}  // namespace

// The detection label -> subclass map (the reference's create_unpacker,
// src/unpacker/packer_detector.cpp:357-386). Anything not listed runs generic.
std::unique_ptr<Packer> make_packer(const std::string& family) {
    const auto f = lower_ascii(family);
    if (f == "mew") return make_mew_packer();
    if (f == "pecompact") return make_pecompact_packer();
    if (f == "nspack") return make_nspack_packer();
    if (f == "rlpack") return make_rlpack_packer();
    if (f == "mpress") return make_mpress_packer();
    if (f == "amber") return make_amber_packer();
    if (f == "alienyze") return make_alienyze_packer();
    if (f == "petite") return make_petite_packer();
    if (f == "telock") return make_telock_packer();
    if (f == "neolite") return make_neolite_packer();
    if (f == "molebox") return make_molebox_packer();
    if (f == "winupack") return make_winupack_packer();
    if (f == "enigmavb") return make_enigma_vb_packer();
    if (f == "exe32pack") return make_exe32pack_packer();
    return std::make_unique<GenericPacker>();
}

}  // namespace packers
}  // namespace unpack
}  // namespace qiling
