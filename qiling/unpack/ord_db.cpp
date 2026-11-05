#include "qiling/unpack/ord_db.hpp"

#include <cstring>
#include <string_view>
#include <unordered_map>

namespace qiling {
namespace unpack {

namespace {

#include "qiling/unpack/ord_db.inc"

const std::unordered_map<std::string, std::uint32_t>& index() {
    static const std::unordered_map<std::string, std::uint32_t> idx = [] {
        std::unordered_map<std::string, std::uint32_t> m;
        const char* p = kOrdDb;
        const char* end = kOrdDb + sizeof(kOrdDb) - 1;
        while (p < end) {
            const char* line_end =
                static_cast<const char*>(std::memchr(p, '\n', static_cast<std::size_t>(end - p)));
            if (line_end == nullptr) {
                break;
            }
            const char* t1 =
                static_cast<const char*>(std::memchr(p, '\t', static_cast<std::size_t>(line_end - p)));
            if (t1 != nullptr && t1 > p) {
                const char* t2 =
                    static_cast<const char*>(std::memchr(t1 + 1, '\t', static_cast<std::size_t>(line_end - t1 - 1)));
                if (t2 != nullptr && t2 > t1 + 1) {
                    // key = "<dllstem>\n<name>": both already lower-cased by the generator
                    std::string key(t1 + 1, static_cast<std::size_t>(t2 - t1 - 1));
                    key.push_back('\n');
                    key.append(p, static_cast<std::size_t>(t1 - p));
                    std::uint32_t ord = 0;
                    for (const char* q = t2 + 1; q < line_end; ++q) {
                        if (*q < '0' || *q > '9') {
                            break;
                        }
                        ord = ord * 10u + static_cast<std::uint32_t>(*q - '0');
                    }
                    if (ord != 0) {
                        m.emplace(std::move(key), ord);
                    }
                }
            }
            p = line_end + 1;
        }
        return m;
    }();
    return idx;
}

std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out) {
        c = static_cast<char>((c >= 'A' && c <= 'Z') ? c + 32 : c);
    }
    return out;
}

}  // namespace

std::uint32_t ordinal_for(const std::string& dll_stem, const std::string& name) {
    std::string stem = lower(dll_stem);
    const auto dot = stem.find(".dll");
    if (dot != std::string::npos) {
        stem.resize(dot);
    }
    std::string key = stem;
    key.push_back('\n');
    key += lower(name);
    const auto& idx = index();
    const auto it = idx.find(key);
    return it == idx.end() ? 0u : it->second;
}

}  // namespace unpack
}  // namespace qiling
