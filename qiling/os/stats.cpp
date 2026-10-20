#include "qiling/os/stats.hpp"

#include <cstdio>

namespace qiling {

void QlOsStats::clear() {
    syscalls_.clear();
    strings_.clear();
    indicators_.clear();
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
    ++api_count_;
    // stats.py: the 'hook_' prefix marks hook-installed APIs and is stripped
    std::string key{name};
    if (key.rfind("hook_", 0) == 0) {
        key.erase(0, 5);
    }

    syscalls_[key].push_back(ApiCallRecord{address, key, {}, {}, retval, retval_present, retaddr, position_});
    ++position_;
}

void QlOsStats::log_api_call(std::uint64_t address, std::string_view name, std::string_view dll,
                             std::vector<std::string> params, std::uint64_t retval, bool retval_present,
                             std::uint64_t retaddr) {
    ++api_count_;
    std::string key{name};
    if (key.rfind("hook_", 0) == 0) {
        key.erase(0, 5);
    }

    syscalls_[key].push_back(ApiCallRecord{address, key, std::string(dll), std::move(params), retval,
                                           retval_present, retaddr, position_});
    ++position_;
}

void QlOsStats::log_indicator(std::string_view kind, std::string_view target) {
    if (target.empty()) {
        return;
    }
    indicators_[std::string(kind)].push_back(IndicatorEvent{std::string(kind), std::string(target), position_});
}

void QlOsStats::log_unsupported_api(std::string_view name) {
    unsupported_apis_.insert(std::string(name));
    ++api_count_;
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

// os/stats.py QlWinStats — the registry access log + the summary extension

void QlWinStats::clear() {
    QlOsStats::clear();
    registry_.clear();
}

void QlWinStats::log_reg_access(std::string_view key, std::optional<std::string> item,
                                std::optional<int> type, std::optional<std::string> value) {
    registry_[std::string(key)].push_back(RegAccessRecord{
        item.value_or(std::string()), std::move(type), std::move(value), position()});
    advance_position();
}

std::vector<std::string> QlWinStats::summary() const {
    auto out = QlOsStats::summary();

    out.push_back("");
    out.push_back("registry keys accessed");
    out.push_back(std::string(24, '-'));
    for (const auto& [key, values] : registry_) {
        out.push_back(key + ":");
        for (const auto& rec : values) {
            std::string line = "  item=" + rec.item;
            if (rec.type) {
                line += " type=" + std::to_string(*rec.type);
            }
            if (rec.value) {
                line += " value=" + *rec.value;
            }
            out.push_back(line);
        }
    }

    return out;
}

}  // namespace qiling
