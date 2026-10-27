// qiling/unpack/packers/family_packers.cpp — the families whose seam is empty
// *today* (they run on the generic engine), one class each so the port has the
// reference's file-per-family shape and a place for the next seam.
//
// The reference has ../pegasus/src/unpacker/packers/<family>_unpacker.{h,cpp} for
// all of them. A family moves out of this file into its own module the moment it
// needs real code (mew_packer.cpp, pecompact_packer.cpp, decode_only_packer.cpp,
// embedded_pe.cpp are the ones that already do). Keeping the empty ones here
// records *which* families are still generic without 15 identical 20-line files.
#include "qiling/unpack/packers/factories.hpp"

namespace qiling {
namespace unpack {
namespace packers {

namespace {

// A family with no seam of its own: the generic engine already unpacks it
// (measured 3/3 at S75 for UPX, ASPack, FSG, EXpressor, Eronana, Exe32pack,
// JDPack, Packman, EnigmaVB, Molebox, Yoda-Crypter).
class FamilyPacker : public Packer {
public:
    explicit FamilyPacker(const char* label) : label_(label) {}
    const char* name() const override { return label_; }

private:
    const char* label_;
};

}  // namespace

std::unique_ptr<Packer> make_petite_packer() { return std::make_unique<FamilyPacker>("PEtite"); }
std::unique_ptr<Packer> make_telock_packer() { return std::make_unique<FamilyPacker>("TELock"); }
std::unique_ptr<Packer> make_molebox_packer() { return std::make_unique<FamilyPacker>("Molebox"); }
std::unique_ptr<Packer> make_winupack_packer() { return std::make_unique<FamilyPacker>("WinUpack"); }
std::unique_ptr<Packer> make_enigma_vb_packer() { return std::make_unique<FamilyPacker>("EnigmaVB"); }
std::unique_ptr<Packer> make_exe32pack_packer() { return std::make_unique<FamilyPacker>("Exe32pack"); }

}  // namespace packers
}  // namespace unpack
}  // namespace qiling
