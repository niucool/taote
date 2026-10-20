// tools/gap_census.cpp — the API-surface census for a PE corpus (PLAN_PARITY.md
// Phase 0).
//
// For every PE file under the given directories, parse the import table with
// LIEF and ask the ApiRegistry whether the imported name resolves. The report
// ranks the unresolved names by how many binaries import them, so the handler
// backlog is data-driven instead of guesswork.
//
//   gap_census <dir-or-file> [more...]
//
// GNU-style `--top N` limits the per-dll listing (default 40).
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include <LIEF/PE.hpp>

#include "qiling/os/windows/dlls/dlls.hpp"
#include "qiling/os/windows/fncc.hpp"

namespace fs = std::filesystem;

namespace {

std::string lower(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

bool looks_like_pe(const fs::path& p) {
    static const char* kExts[] = {".exe", ".dll", ".sys", ".exe_", ".dll_", ".sys_"};
    const auto name = lower(p.filename().string());
    for (const auto* ext : kExts) {
        if (name.size() >= std::strlen(ext) && name.compare(name.size() - std::strlen(ext), std::strlen(ext), ext) == 0) {
            return true;
        }
    }
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<fs::path> inputs;
    std::size_t top = 40;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--top") == 0 && i + 1 < argc) {
            top = static_cast<std::size_t>(std::strtoul(argv[++i], nullptr, 0));
            continue;
        }
        inputs.emplace_back(argv[i]);
    }
    if (inputs.empty()) {
        std::fprintf(stderr, "usage: gap_census <dir-or-file> [...] [--top N]\n");
        return 2;
    }

    qiling::os::register_dlls();

    std::size_t files = 0;
    std::size_t parsed = 0;
    std::map<std::string, std::map<std::string, std::size_t>> missing;  // dll -> name -> binaries
    std::map<std::string, std::size_t> per_dll_total;

    for (const auto& in : inputs) {
        std::error_code ec;
        std::vector<fs::path> candidates;
        if (fs::is_directory(in, ec)) {
            for (const auto& e : fs::recursive_directory_iterator(in, ec)) {
                if (e.is_regular_file(ec) && looks_like_pe(e.path())) {
                    candidates.push_back(e.path());
                }
            }
            std::sort(candidates.begin(), candidates.end());
        } else {
            candidates.push_back(in);
        }

        for (const auto& path : candidates) {
            ++files;
            auto bin = LIEF::PE::Parser::parse(path.string());
            if (bin == nullptr) {
                continue;
            }
            ++parsed;
            for (const auto& imp : bin->imports()) {
                const auto dll = lower(imp.name());
                for (const auto& entry : imp.entries()) {
                    if (entry.name().empty()) {
                        continue;
                    }
                    ++per_dll_total[dll];
                    if (qiling::os::ApiRegistry::instance().find(entry.name()) == nullptr) {
                        ++missing[dll][entry.name()];
                    }
                }
            }
        }
    }

    std::printf("scanned %zu PE files (%zu parsed)\n\n", files, parsed);
    for (const auto& [dll, names] : missing) {
        std::printf("== %s (%zu unresolved imports, %zu import slots)\n", dll.c_str(), names.size(),
                    per_dll_total[dll]);
        std::vector<std::pair<std::string, std::size_t>> ranked(names.begin(), names.end());
        std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
            if (a.second != b.second) {
                return a.second > b.second;
            }
            return a.first < b.first;
        });
        for (std::size_t i = 0; i < ranked.size() && i < top; ++i) {
            std::printf("  %4zu x %s\n", ranked[i].second, ranked[i].first.c_str());
        }
        if (ranked.size() > top) {
            std::printf("  ... %zu more\n", ranked.size() - top);
        }
    }
    return 0;
}
