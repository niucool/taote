// qiling/unpack/iat/import_rebuilder.hpp — the import-directory rebuilder
// (Scylla's ImportRebuilder, ../pegasus/src/scylla_wrapper/ImportRebuilder.cpp).
//
// Scylla's rebuild walks an import tree and writes a fresh section that holds the
// descriptor array, per-dll INT/IAT thunk arrays and the hint/name strings, then
// patches the file's import directory at that section. This is that step, with
// the file layout left to the PE writer (unpack.cpp's rebuild_pe): the module
// owns the *content* of the import section, which is the part the reference
// needed Scylla for.
#ifndef QILING_UNPACK_IAT_IMPORT_REBUILDER_HPP
#define QILING_UNPACK_IAT_IMPORT_REBUILDER_HPP

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace qiling {
namespace unpack {
namespace iat {

// One dll's import list, in first-seen order with duplicates removed.
struct ImportGroup {
    std::string dll;                 // lowercased
    std::vector<std::string> names;  // function names (or "ordinal_N")
};

// Groups a flat (dll, name) list the way Scylla's tree does: first-seen dll order,
// de-duplicated names inside a dll.
std::vector<ImportGroup> group_imports(const std::vector<std::pair<std::string, std::string>>& imports);

// The image of the new import section, relative to its own RVA.
struct ImportSection {
    std::vector<std::uint8_t> blob;
    std::uint32_t iat_rva = 0;        // relative to the section RVA
    std::uint32_t iat_size = 0;
    std::size_t descriptors_off = 0;  // offset of the descriptor array in `blob`
    std::size_t descriptors_size = 0;
};

// Scylla's ImportRebuilder::createImportSection: descriptor array, then per dll
// the INT, the IAT and the hint/name strings.
//   layout: [descriptors][ (INT, IAT, names) per group ]
ImportSection build_import_section(const std::vector<ImportGroup>& groups, std::uint32_t section_rva);

}  // namespace iat
}  // namespace unpack
}  // namespace qiling

#endif  // QILING_UNPACK_IAT_IMPORT_REBUILDER_HPP
