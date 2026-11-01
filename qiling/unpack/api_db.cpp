// qiling/unpack/api_db.cpp — see api_db.hpp.
#include "qiling/unpack/api_db.hpp"

#include <cstring>
#include <string_view>
#include <unordered_map>

namespace qiling {
namespace unpack {

namespace {

#include "qiling/unpack/api_db.inc"

struct ApiRow {
    std::string name;    // the DLL's own spelling - PE export names are case-sensitive
    std::string owners;  // comma-separated owning dll stems, best first
};

// The blob is "<name>\t<dlls>\n" per line, sorted by name. Parsed once into a
// vector plus a lower-cased index: lookups are case-insensitive, but the *name
// returned to callers keeps the DLL's spelling. That case is load-bearing - a
// stub dll seeded with `createcompatiblebitmap` cannot satisfy a packer that
// hashes the real `CreateCompatibleBitmap` (PLAN_UNPACK 0.17gv).
const std::vector<ApiRow>& rows() {
    static const std::vector<ApiRow> v = [] {
        std::vector<ApiRow> out;
        const char* p = kApiDb;
        const char* end = kApiDb + sizeof(kApiDb) - 1;
        while (p < end) {
            const char* line_end = static_cast<const char*>(std::memchr(p, '\n', static_cast<std::size_t>(end - p)));
            if (line_end == nullptr) {
                break;
            }
            const char* tab = static_cast<const char*>(std::memchr(p, '\t', static_cast<std::size_t>(line_end - p)));
            if (tab != nullptr && tab > p) {
                out.push_back({std::string(p, static_cast<std::size_t>(tab - p)),
                               std::string(tab + 1, static_cast<std::size_t>(line_end - tab - 1))});
            }
            p = line_end + 1;
        }
        return out;
    }();
    return v;
}

std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out) {
        c = static_cast<char>((c >= 'A' && c <= 'Z') ? c + 32 : c);
    }
    return out;
}

const std::unordered_map<std::string, std::size_t>& index() {
    static const std::unordered_map<std::string, std::size_t> idx = [] {
        std::unordered_map<std::string, std::size_t> m;
        const auto& r = rows();
        m.reserve(r.size() * 2);
        for (std::size_t i = 0; i < r.size(); ++i) {
            m.emplace(lower(r[i].name), i);
        }
        return m;
    }();
    return idx;
}

}  // namespace

namespace {

const ApiRow* lookup(const std::string& name) {
    if (name.empty() || name.size() > 128) {
        return nullptr;
    }
    const auto& idx = index();
    const auto it = idx.find(lower(name));
    return it == idx.end() ? nullptr : &rows()[it->second];
}

}  // namespace

std::vector<std::string> api_owners(const std::string& name) {
    std::vector<std::string> out;
    const auto* row = lookup(name);
    if (row == nullptr) {
        return out;
    }
    const auto* v = &row->owners;
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
    for (const auto& row : rows()) {
        const auto& owners = row.owners;
        std::size_t start = 0;
        while (start <= owners.size()) {
            const auto comma = owners.find(',', start);
            const auto end = comma == std::string::npos ? owners.size() : comma;
            std::string owned(owners.substr(start, end - start));
            for (auto& c : owned) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            if (!owned.empty() && (owned == want || (want_crt && is_crt_family(owned)))) {
                out.emplace_back(row.name);
                break;
            }
            if (comma == std::string::npos) {
                break;
            }
            start = comma + 1;
        }
    }
    return out;
}

const char* api_owner(const std::string& name) {
    const auto* row = lookup(name);
    if (row == nullptr) {
        return nullptr;
    }
    const auto* v = &row->owners;
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
