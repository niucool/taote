#include "qiling/unpack/iat/import_rebuilder.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace qiling {
namespace unpack {
namespace iat {

namespace {

void put_u32(std::vector<std::uint8_t>& v, std::size_t o, std::uint32_t x) {
    if (o + 4 > v.size()) {
        v.resize(o + 4, 0);
    }
    std::memcpy(v.data() + o, &x, 4);
}

}  // namespace

std::vector<ImportGroup> group_imports(const std::vector<std::pair<std::string, std::string>>& imports) {
    std::vector<ImportGroup> groups;
    for (const auto& pr : imports) {
        auto dll = pr.first;
        std::transform(dll.begin(), dll.end(), dll.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        auto it = std::find_if(groups.begin(), groups.end(), [&](const ImportGroup& g) { return g.dll == dll; });
        if (it == groups.end()) {
            groups.push_back(ImportGroup{dll, {}});
            it = std::prev(groups.end());
        }
        if (std::find(it->names.begin(), it->names.end(), pr.second) == it->names.end()) {
            it->names.push_back(pr.second);
        }
    }
    return groups;
}

ImportSection build_import_section(const std::vector<ImportGroup>& groups, std::uint32_t section_rva) {
    ImportSection out;
    if (groups.empty()) {
        return out;
    }
    auto& blob = out.blob;
    const auto put = [&blob](const void* p, std::size_t n) {
        const auto* b = static_cast<const std::uint8_t*>(p);
        blob.insert(blob.end(), b, b + n);
    };

    // the descriptor array first (the import directory points at it), one terminator
    out.descriptors_off = blob.size();
    out.descriptors_size = (groups.size() + 1) * 20;
    blob.resize(out.descriptors_off + out.descriptors_size, 0);

    for (std::size_t g = 0; g < groups.size(); ++g) {
        const std::size_t desc_off = out.descriptors_off + g * 20;
        const auto& grp = groups[g];
        const std::size_t n = grp.names.size();

        const std::size_t int_off = blob.size();
        blob.resize(int_off + (n + 1) * 4, 0);
        const std::size_t iat_off = blob.size();
        blob.resize(iat_off + (n + 1) * 4, 0);

        std::vector<std::uint32_t> name_rvas;
        name_rvas.reserve(n);
        for (const auto& fn : grp.names) {
            if (blob.size() % 2 != 0) {
                blob.push_back(0);
            }
            name_rvas.push_back(section_rva + static_cast<std::uint32_t>(blob.size()));
            const std::uint16_t hint = 0;
            put(&hint, 2);
            put(fn.data(), fn.size());
            const char nul = '\0';
            put(&nul, 1);
        }
        if (blob.size() % 2 != 0) {
            blob.push_back(0);
        }
        const std::uint32_t dll_name_rva = section_rva + static_cast<std::uint32_t>(blob.size());
        put(grp.dll.data(), grp.dll.size());
        const char nul = '\0';
        put(&nul, 1);

        // the INT and the IAT hold the same hint/name RVAs: the loader resolves
        // them and writes the addresses back into the IAT
        for (std::size_t i = 0; i < n; ++i) {
            put_u32(blob, int_off + i * 4, name_rvas[i]);
            put_u32(blob, iat_off + i * 4, name_rvas[i]);
        }

        const std::uint32_t int_rva = section_rva + static_cast<std::uint32_t>(int_off);
        const std::uint32_t this_iat_rva = section_rva + static_cast<std::uint32_t>(iat_off);
        if (out.iat_rva == 0) {
            out.iat_rva = this_iat_rva;
        }
        out.iat_size += static_cast<std::uint32_t>((n + 1) * 4);

        put_u32(blob, desc_off, int_rva);           // OriginalFirstThunk
        put_u32(blob, desc_off + 4, 0);             // TimeDateStamp
        put_u32(blob, desc_off + 8, 0);             // ForwarderChain
        put_u32(blob, desc_off + 12, dll_name_rva);  // Name
        put_u32(blob, desc_off + 16, this_iat_rva);  // FirstThunk
    }
    return out;
}

}  // namespace iat
}  // namespace unpack
}  // namespace qiling
