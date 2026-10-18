#include "qiling/os/windows/fncc.hpp"

#include "qiling/os/os.hpp"

namespace qiling {
namespace os {

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
