// qiling/unpack/packers/alienyze_ordinals.hpp — the Alienyze store's
// import-by-ordinal entries.
//
// PLAN_UNPACK.md §10. The packer's import store keeps one flat table right after
// its 20-byte descriptor run: the per-DLL INT arrays concatenated, one array per
// DLL in the same order as the DLL markers of the record stream, each array
// terminated by a zero dword. A slot whose high bit is set and whose low word is
// nonzero is an import-by-ordinal for that array's DLL — the only place the
// ordinal numbers exist in the artifact (measured: alienyze_HWMonitorPro_x32
// carries all 27 of its missing ordinals there, alienyze_Everything all 20).
//
// The attribution is deliberately conservative: a block's DLL is only accepted
// when the block holds no name slot at all (a DLL imported exclusively by
// ordinal leaves no name record, so its marker group is empty) and the marker
// groups and blocks line up 1:1. Anything else yields no pairs, because a wrong
// (dll, ordinal) pair is a broken import in the rebuilt image.
#ifndef QILING_UNPACK_PACKERS_ALIENYZE_ORDINALS_HPP
#define QILING_UNPACK_PACKERS_ALIENYZE_ORDINALS_HPP

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace qiling {
namespace unpack {
namespace alienyze {

// (dll marker as spelled in the store, ordinal) pairs, in table order.
std::vector<std::pair<std::string, std::uint32_t>> store_ordinal_pairs(
    const std::uint8_t* dec, std::size_t n, std::size_t idt_end,
    const std::vector<std::string>& dll_names, const std::vector<std::size_t>& dll_name_counts);

}  // namespace alienyze
}  // namespace unpack
}  // namespace qiling

#endif  // QILING_UNPACK_PACKERS_ALIENYZE_ORDINALS_HPP
