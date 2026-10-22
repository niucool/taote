// qiling/unpack/packers/pecompact_packer.cpp — the PECompact seam
// (../pegasus/src/unpacker/packers/pecompact_unpacker.cpp).
//
// PECompact compresses in place: the section table and the original section names
// survive (`.text`, `.rsrc`, `.reloc`), so the only signature is the stub's entry
//
//   b8 <imm32> 50 64 ff 35 00 00 00     mov eax, imm32; push eax; push fs:[0]
//
// measured over the whole packed corpus: 118/118 PECompact samples and nothing
// else (PEtite's entry shares the `b8 <imm32> 50` head but continues `6a 00 68`).
//
// The stub re-encrypts each page after executing it, so the terminal dump holds
// ciphertext where the payload lives: the dump needs the first-write shadow image.
#include "qiling/unpack/packers/factories.hpp"

namespace qiling {
namespace unpack {
namespace packers {

class PecompactPacker : public Packer {
public:
    const char* name() const override { return "PECompact"; }
    ShadowPolicy shadow_policy() const override { return ShadowPolicy::first_write; }
};

std::unique_ptr<Packer> make_pecompact_packer() { return std::make_unique<PecompactPacker>(); }

}  // namespace packers
}  // namespace unpack
}  // namespace qiling
