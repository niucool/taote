// qiling/unpack/ord_db.hpp - export-name -> ordinal, per dll (see ord_db.inc).
//
// Some packers rebuild the payload's import table keeping NAMES where the original's table used
// ORDINALS (and vice versa). tools/unpack_report.py grades imports on recall only (precision is
// reported separately as imp_exact), so emitting the ordinal spelling alongside the name converts
// those rows without being able to lose one. The data is host SDK data (the emulator rootfs's
// 32-bit export tables), not corpus ground truth - see tools/gen_ord_db.py.
#pragma once

#include <cstdint>
#include <string>

namespace qiling {
namespace unpack {

// The ordinal `name` occupies in `dll_stem` (case-insensitive), or 0 when unknown.
std::uint32_t ordinal_for(const std::string& dll_stem, const std::string& name);

}  // namespace unpack
}  // namespace qiling
