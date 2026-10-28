// qiling/unpack/api_db.cpp — see api_db.hpp.
#include "qiling/unpack/api_db.hpp"

#include <cstring>
#include <string_view>
#include <unordered_map>

namespace qiling {
namespace unpack {

namespace {

#include "qiling/unpack/api_db.inc"

// The blob is "name\tdll\n" per line, sorted by name. Parsed once into a map:
// 32k lines is a few hundred microseconds and saves a perfect-hash generator.
const std::unordered_map<std::string_view, std::string_view>& table() {
    static const std::unordered_map<std::string_view, std::string_view> t = [] {
        std::unordered_map<std::string_view, std::string_view> m;
        const char* p = kApiDb;
        const char* end = kApiDb + sizeof(kApiDb) - 1;
        while (p < end) {
            const char* line_end = static_cast<const char*>(std::memchr(p, '\n', static_cast<std::size_t>(end - p)));
            if (line_end == nullptr) {
                break;
            }
            const char* tab = static_cast<const char*>(std::memchr(p, '\t', static_cast<std::size_t>(line_end - p)));
            if (tab != nullptr && tab > p) {
                m.emplace(std::string_view(p, static_cast<std::size_t>(tab - p)),
                          std::string_view(tab + 1, static_cast<std::size_t>(line_end - tab - 1)));
            }
            p = line_end + 1;
        }
        return m;
    }();
    return t;
}

}  // namespace

const char* api_owner(const std::string& name) {
    if (name.empty() || name.size() > 128) {
        return nullptr;
    }
    char low[128];
    for (std::size_t i = 0; i < name.size(); ++i) {
        const auto c = static_cast<unsigned char>(name[i]);
        low[i] = static_cast<char>((c >= 'A' && c <= 'Z') ? c + 32 : c);
    }
    const auto& t = table();
    const auto it = t.find(std::string_view(low, name.size()));
    if (it == t.end()) {
        return nullptr;
    }
    // the blob outlives the process: hand back a NUL-terminated copy built once
    static std::unordered_map<std::string, std::string> cache;
    static const std::string* unused = nullptr;
    (void)unused;
    const std::string key(it->second);
    const auto c = cache.find(key);
    if (c != cache.end()) {
        return c->second.c_str();
    }
    return cache.emplace(key, key).first->second.c_str();
}

}  // namespace unpack
}  // namespace qiling
