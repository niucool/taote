// qiling/unpack/packers/factories.hpp — the per-family factories.
//
// One declaration per packer module so the engine's factory (generic_packer.cpp)
// stays a pure dispatch table, exactly as the reference's
// PackerDetector::create_unpacker (src/unpacker/packer_detector.cpp:357-386)
// maps a detected name to a subclass.
#ifndef QILING_UNPACK_PACKERS_FACTORIES_HPP
#define QILING_UNPACK_PACKERS_FACTORIES_HPP

#include <memory>

#include "qiling/unpack/packers/packer.hpp"

namespace qiling {
namespace unpack {
namespace packers {

std::unique_ptr<Packer> make_mew_packer();
std::unique_ptr<Packer> make_pecompact_packer();
std::unique_ptr<Packer> make_nspack_packer();
std::unique_ptr<Packer> make_rlpack_packer();
std::unique_ptr<Packer> make_mpress_packer();
std::unique_ptr<Packer> make_amber_packer();
std::unique_ptr<Packer> make_alienyze_packer();
std::unique_ptr<Packer> make_petite_packer();
std::unique_ptr<Packer> make_telock_packer();
std::unique_ptr<Packer> make_neolite_packer();
std::unique_ptr<Packer> make_molebox_packer();
std::unique_ptr<Packer> make_winupack_packer();
std::unique_ptr<Packer> make_enigma_vb_packer();
std::unique_ptr<Packer> make_exe32pack_packer();

}  // namespace packers
}  // namespace unpack
}  // namespace qiling

#endif  // QILING_UNPACK_PACKERS_FACTORIES_HPP
