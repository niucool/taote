// qiling/unpack/packers/packer.hpp — the packer seam (the reference's
// UniversalUnpacker family seams, ../pegasus/src/unpacker/unpacker.h:133-520).
//
// The engine (unpack.cpp) owns the generic unpack: section classification, the
// write-claim / section-hop OEP mechanism, the candidate ledger and the dump.
// A packer subclass owns only what is *family specific*, one seam at a time,
// mirroring the reference's layout:
//
//   src/unpacker/unpacker.cpp        the engine + ~35 virtual seams
//   src/unpacker/packers/mew_unpacker.cpp
//   src/unpacker/packers/petite_unpacker.cpp
//   ...
//
// A seam is added here only when a family needs it (the reference accumulated
// them the same way); `GenericPacker` reproduces the historical behaviour for
// every family without one.
#ifndef QILING_UNPACK_PACKERS_PACKER_HPP
#define QILING_UNPACK_PACKERS_PACKER_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "qiling/unpack/unpack.hpp"

namespace qiling {

class Qiling;

namespace unpack {

namespace packers {

// What a seam may look at. Deliberately a plain struct (not the Unpacker): the
// family code must not reach into the engine's private state, and the tests can
// drive a packer without an emulator.
struct PackerContext {
    Qiling* ql = nullptr;            // the run (guest memory, at install time)
    const std::vector<std::uint8_t>* image_ptr = nullptr;  // the dump (read-mostly)
    // The same image, writable, for transform_image() only (a family that has to
    // decrypt the body in place). Kept separate so every other seam stays
    // read-only by construction.
    std::vector<std::uint8_t>* image_mut = nullptr;
    std::vector<std::uint8_t> adopted;                     // a seam's replacement image
    std::uint64_t adopted_base = 0;                        // ... and its base/size/sections
    std::uint64_t adopted_size = 0;
    std::vector<PackSection> adopted_sections;
    std::uint64_t base = 0;
    std::uint64_t image_size = 0;
    std::uint64_t packed_ep_va = 0;
    // The run's strongest section-hop candidate (the claim ledger's last
    // non-junk entry). A ladder pass may use it as a hint: the accepted hop
    // lands a few bytes INSIDE the payload entry (measured: exactly +0x16 on
    // PECompact/NSPack Cacheset and AccessEnum), so the frame just below the
    // hop is the entry when one exists.
    std::uint64_t hop_hint = 0;
    bool is_64 = false;
    bool debug = false;
    std::string family;
    // the PACKED file on disk: the static OEP readers that work from the
    // packer's own stub data (the MPRESS fix-imports stub) read it, exactly as
    // the reference's mpress_static_oep_ opens packed_path_
    const std::string* packed_path = nullptr;
    std::vector<PackSection> sections;

    const std::vector<std::uint8_t>& image() const {
        static const std::vector<std::uint8_t> empty;
        return image_ptr != nullptr ? *image_ptr : empty;
    }
};

// Which decode view the dump needs (the reference keeps the first-write shadow
// image; §0.5.3b measured that it helps the re-encrypting decoders and hurts the
// JIT ones).
enum class ShadowPolicy {
    none,         // terminal memory wins
    first_write,  // the first write per byte (MEW, PECompact)
};

// The shared decode-only ladder (the reference's decode_only_ladder, shared by
// NSPack/RLPack/MPRESS and used as the engine's static fallback for any family):
// the byte-pattern walk over the DECODED body that finds the payload entry when
// the stub hands off through its own trampolines.
std::uint64_t ladder_oep(const PackerContext& ctx);

class Packer {
public:
    virtual ~Packer() = default;

    // the detector's label ("MEW", "PECompact", ...)
    virtual const char* name() const = 0;

    // The decode-only families (NSPack/RLPack/MPRESS) hand off through the
    // decoded body's own trampolines, so the static ladder outranks the ledger.
    virtual bool decode_only() const { return false; }

    // A statically parsed OEP, read at install() (before the stub runs).
    virtual std::uint64_t static_oep(const PackerContext& /*ctx*/) const { return 0; }

    // A statically parsed OEP, read from the DUMP at finalize time. The default
    // is the shared decode-only ladder, which the engine also uses as its static
    // fallback for every family (measured: it is what corrects a junk first hop
    // for PECompact/FSG/JDPack/Packman as well).
    virtual std::uint64_t static_oep_from_image(const PackerContext& ctx) const { return ladder_oep(ctx); }

    virtual ShadowPolicy shadow_policy() const { return ShadowPolicy::none; }

    // Transform the terminal image IN PLACE before the OEP pick. Families whose
    // payload is present but still encrypted at rest use this; the reference
    // spells the same step out as recover_alienyze() (src/unpacker/alienyze.cpp)
    // and family_transform_dump_image(). A true return means the image was
    // rewritten (ctx.image_ptr contents), so downstream parses must re-read it.
    virtual bool transform_image(PackerContext& /*ctx*/) { return false; }

    // Adopt a payload PE that the stub built outside the image (Amber/Alienyze).
    // A true return means `ctx.adopted` holds the replacement image.
    // The reference's try_embedded_pe is PACKER-AGNOSTIC (it lives in the base
    // class: a payload built in a heap buffer is recovered the same way whatever
    // the label). Families with their own recovery override this.
    virtual bool adopt_embedded_pe(PackerContext& ctx);
};

// The family factory: `family` is the detector's label (see packer_detector.hpp).
// Never returns null — an unknown label yields the generic packer.
std::unique_ptr<Packer> make_packer(const std::string& family);

}  // namespace packers
}  // namespace unpack
}  // namespace qiling

#endif  // QILING_UNPACK_PACKERS_PACKER_HPP
