// qiling/unpack/packer_detector.hpp — the packer detector
// (../pegasus/src/unpacker/packer_detector.cpp).
//
// The reference's detector tries, in order:
//   1. section-name substrings           (.aspack/.adata, upx0/upx1, .mpress1/2,
//                                         mew, nsp0/nsp1, petite, .packed/.rlpack,
//                                         .neolit, .alien, .yp, $win8, fsg, .upack,
//                                         .bero, .eronana, .ex_cod/.ex_dat,
//                                         .enigma1/2, .themida, .jdpack, .packman, yc)
//   2. a UPX PackHeader probe            (`UPX!` in the first 0x800 bytes)
//   3. Molebox                           (every section name is one digit)
//   4. Amber                             (>=9 sections, last name `.` + 7 alnum)
//   5. EP-prefix signatures              (PECompact b8..50 64 ff 35, Eronana 60 68,
//                                         Exe32pack 3b c0 74 02 81, TELock e9,
//                                         WinUpack be)
//   6. a content probe for the archives  (SFX)
//
// taote ports 1, 3 and the EP-prefix signatures that measured clean, and keeps the
// MEASURED authoring choice from the plan (§3 Phase 2): the detector's job here is
// to *route* to a packer seam, so it must never claim a family it cannot back —
// an "unknown" label on a family without a seam is strictly better than a wrong
// one, because the seam is what changes behaviour.
#ifndef QILING_UNPACK_PACKER_DETECTOR_HPP
#define QILING_UNPACK_PACKER_DETECTOR_HPP

#include <string>

namespace qiling {
namespace unpack {

struct Detection {
    std::string name = "unknown";  // the family label ("UPX", "PECompact", ...)
    std::string sig_kind;          // "section" | "ep-prefix" | "molebox" | "-"
    std::string detail;            // the matched name/signature, for the logs
};

// Detect the packer family of a PE file. Reads at most the headers plus the
// section each entry point lives in; never throws (a malformed file detects as
// "unknown", which routes to the generic packer).
Detection detect_from_file(const std::string& path);

}  // namespace unpack
}  // namespace qiling

#endif  // QILING_UNPACK_PACKER_DETECTOR_HPP
