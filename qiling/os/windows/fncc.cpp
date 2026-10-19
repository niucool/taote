#include "qiling/os/windows/fncc.hpp"

#include "qiling/os/os.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/exception.hpp"

namespace qiling {
namespace os {

// the resolved-params accessors (the posix kernel_api.cpp shapes): the
// placeholder-typed entries carry the strings, the plain-int entries the raw
// values; the string fallback reads the guest cstring at the raw address
// (the direct-invocation path)
std::string api_get_string(Qiling& ql, const std::pair<std::string, FcallValue>& p) {
    if (const auto* s = std::get_if<std::string>(&p.second)) {
        return *s;
    }
    return QlOsUtils::read_cstring(ql, std::get<std::uint64_t>(p.second));
}

std::uint64_t api_get_int(const std::pair<std::string, FcallValue>& p) {
    if (const auto* v = std::get_if<std::uint64_t>(&p.second)) {
        return *v;
    }
    return 0;
}

const std::pair<std::string, FcallValue>& get_param(const ResolvedParams& params, std::string_view name) {
    for (const auto& p : params) {
        if (p.first == name) {
            return p;
        }
    }
    throw QlErrorBase(std::string("api param not found: ") + std::string(name));
}

ApiRegistry& ApiRegistry::instance() {
    static ApiRegistry registry;
    return registry;
}

void ApiRegistry::register_api(ApiEntry entry) {
    entries_[entry.name] = std::move(entry);
}

const ApiEntry* ApiRegistry::find(const std::string& api_name) const {
    const auto it = entries_.find(api_name);
    return it == entries_.end() ? nullptr : &it->second;
}

std::vector<std::string> ApiRegistry::names() const {
    std::vector<std::string> out;
    out.reserve(entries_.size());
    for (const auto& [name, _] : entries_) {
        out.push_back(name);
    }
    return out;
}

void ApiRegistry::clear() {
    entries_.clear();
}

// ---- the @winsdkapi builder ----

WinsdkApi::WinsdkApi(std::string name, WinCc cc, ApiParams params, bool passthru) {
    entry_.name = std::move(name);
    entry_.cc = cc;
    entry_.params = std::move(params);
    entry_.passthru = passthru;
}

void WinsdkApi::operator=(ApiHandler handler) {
    entry_.handler = std::move(handler);
    ApiRegistry::instance().register_api(entry_);
}

}  // namespace os
}  // namespace qiling
