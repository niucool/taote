#include "qiling/os/stats.hpp"

#include <cstdio>

namespace qiling {

void QlOsStats::clear() {
    syscalls_.clear();
    strings_.clear();
    position_ = 0;
}

std::vector<std::string> QlOsStats::summary() const {
    std::vector<std::string> out;

    const auto banner = [](const char* caption) {
        return std::vector<std::string>{"", caption, std::string(24, '-')};
    };

    auto append = [&out](std::vector<std::string> lines) {
        out.insert(out.end(), lines.begin(), lines.end());
    };

    append(banner("syscalls called"));
    for (const auto& [name, calls] : syscalls_) {
        out.push_back(name + ":");
        for (const auto& call : calls) {
            char line[160];
            std::snprintf(line, sizeof(line), "  retval=%s%#llx address=%#llx retaddr=%#llx",
                          call.retval_present ? "" : "n/a ",
                          static_cast<unsigned long long>(call.retval),
                          static_cast<unsigned long long>(call.address),
                          static_cast<unsigned long long>(call.retaddr));
            out.push_back(line);
        }
    }

    append(banner("strings ocurrences"));
    for (const auto& [token, positions] : strings_) {
        std::string line = token + ":";
        for (const auto pos : positions) {
            line += ' ' + std::to_string(pos);
        }
        out.push_back(line);
    }

    return out;
}

void QlOsStats::log_api_call(std::uint64_t address, std::string_view name,
                             std::uint64_t retval, bool retval_present,
                             std::uint64_t retaddr) {
    // stats.py: the 'hook_' prefix marks hook-installed APIs and is stripped
    std::string key{name};
    if (key.rfind("hook_", 0) == 0) {
        key.erase(0, 5);
    }

    syscalls_[key].push_back(ApiCallRecord{address, key, retval, retval_present, retaddr, position_});
    ++position_;
}

void QlOsStats::log_string(std::string_view s) {
    std::string_view rest = s;
    while (!rest.empty()) {
        const auto space = rest.find(' ');
        const auto token = rest.substr(0, space);
        if (!token.empty()) {
            strings_[std::string(token)].insert(position_);
        }
        rest = (space == std::string_view::npos) ? std::string_view{} : rest.substr(space + 1);
    }
}

}  // namespace qiling
