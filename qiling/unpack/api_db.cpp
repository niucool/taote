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

namespace {

const std::string_view* lookup(const std::string& name) {
    if (name.empty() || name.size() > 128) {
        return nullptr;
    }
    static char low[128];
    for (std::size_t i = 0; i < name.size(); ++i) {
        const auto c = static_cast<unsigned char>(name[i]);
        low[i] = static_cast<char>((c >= 'A' && c <= 'Z') ? c + 32 : c);
    }
    const auto& t = table();
    const auto it = t.find(std::string_view(low, name.size()));
    return it == t.end() ? nullptr : &it->second;
}

}  // namespace

std::vector<std::string> api_owners(const std::string& name) {
    std::vector<std::string> out;
    const auto* v = lookup(name);
    if (v == nullptr) {
        return out;
    }
    std::size_t start = 0;
    while (start <= v->size()) {
        const auto comma = v->find(',', start);
        const auto end = comma == std::string_view::npos ? v->size() : comma;
        if (end > start) {
            out.emplace_back(std::string(v->substr(start, end - start)));
        }
        if (comma == std::string_view::npos) {
            break;
        }
        start = comma + 1;
    }
    return out;
}

namespace {

// The host SDK files the C-runtime surface under ucrt/ucrtbase/crtdll and gives
// msvcrt (and the versioned msvcr*'s) NO names at all, so a stub msvcrt was
// created with only the handful of handlers taote implements - while a packer
// resolving CRT imports the way the loader does walks the module's own export
// name table and finds nothing. Treat the whole CRT as one family: all of these
// dlls really do export (nearly) the same names.
bool is_crt_family(std::string_view n) {
    if (n == "crtdll" || n == "ucrt" || n == "ucrtbase" || n == "msvcrt" || n == "msvcr") {
        return true;
    }
    if (n.rfind("msvcr", 0) == 0) {  // msvcr70/71/80/90/100/110/120...
        return true;
    }
    if (n.rfind("api-ms-win-crt", 0) == 0) {
        return true;
    }
    return false;
}

}  // namespace

std::vector<std::string> api_names_for(const std::string& dll) {
    std::string want = dll;
    for (auto& c : want) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (const auto dot = want.rfind('.'); dot != std::string::npos) {
        want.resize(dot);
    }
    const bool want_crt = is_crt_family(want);
    std::vector<std::string> out;
    for (const auto& [name, owners] : table()) {
        std::size_t start = 0;
        while (start <= owners.size()) {
            const auto comma = owners.find(',', start);
            const auto end = comma == std::string_view::npos ? owners.size() : comma;
            std::string owned(owners.substr(start, end - start));
            for (auto& c : owned) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if (!owned.empty() && (owned == want || (want_crt && is_crt_family(owned)))) {
                out.emplace_back(name);
                break;
            }
            if (comma == std::string_view::npos) {
                break;
            }
            start = comma + 1;
        }
    }
    return out;
}

const char* api_owner(const std::string& name) {
    const auto* v = lookup(name);
    if (v == nullptr) {
        return nullptr;
    }
    const auto comma = v->find(',');
    const std::string first(v->substr(0, comma == std::string_view::npos ? v->size() : comma));
    // the blob outlives the process: hand back a NUL-terminated copy built once
    static std::unordered_map<std::string, std::string> cache;
    const auto it = cache.find(first);
    if (it != cache.end()) {
        return it->second.c_str();
    }
    return cache.emplace(first, first).first->second.c_str();
}

}  // namespace unpack
}  // namespace qiling
