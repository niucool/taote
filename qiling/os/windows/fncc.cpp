#include "qiling/os/windows/fncc.hpp"

#include "qiling/core.hpp"
#include "qiling/os/windows/windows.hpp"
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
    // the NULL string args ride the empty string (the windows contract: the
    // NULL lpValueName means the default-value probe; the raw pointer stays
    // reachable through api_get_int for the callers that need the
    // distinction)
    const auto addr = std::get<std::uint64_t>(p.second);
    if (addr == 0) {
        return "";
    }
    return QlOsUtils::read_cstring(ql, addr);
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

std::optional<std::uint64_t> call_api(Qiling& ql, std::uint64_t pc, const std::string& api_name,
                                      const ApiParams& params, WinCc cc, const ApiHandler& handler,
                                      bool passthru) {
    auto& os = ql.os<windows::QlOsWindows>();
    os.set_fcall_ptr(os.fcall_select(cc));

    const auto* onenter = os.find_api_enter(api_name);
    const auto* onexit = os.find_api_exit(api_name);

    return os.call(
        pc, api_name,
        [&ql, &os, params, handler, onenter, onexit](std::uint64_t use_pc,
                                                     const QlFunctionCall::Params& raw)
            -> std::optional<std::uint64_t> {
            std::vector<std::uint64_t> rawvals;
            rawvals.reserve(raw.size());
            for (const auto& [name, value] : raw) {
                (void)name;
                rawvals.push_back(value);
            }
            auto resolved = os.resolve_named_params(params, rawvals);
            if (onenter != nullptr) {
                if (const auto new_pc = (*onenter)(ql, resolved); new_pc.has_value()) {
                    use_pc = *new_pc;
                }
            }
            auto retval = handler(ql, use_pc, resolved);
            if (onexit != nullptr) {
                // the upstream passes the *same* dict to onenter, func and
                // onexit, so a rewrite the func makes is visible on exit. The
                // C++ handlers take const params (they cannot rewrite the
                // dict), so the exit hook re-resolves the guest memory instead:
                // a handler that rewrote the string in place is observed the
                // same way
                resolved = os.resolve_named_params(params, rawvals);
                if (const auto override_ret = (*onexit)(ql, resolved, retval); override_ret.has_value()) {
                    retval = *override_ret;
                }
            }
            return retval;
        },
        params, nullptr, nullptr, passthru);
}

// ---- the @winsdkapi builder ----

WinsdkApi::WinsdkApi(std::string name, WinCc cc, ApiParams params, bool passthru,
                     std::function<bool(Qiling&)> guard) {
    entry_.name = std::move(name);
    entry_.cc = cc;
    entry_.params = std::move(params);
    entry_.passthru = passthru;
    entry_.guard = std::move(guard);
}

void WinsdkApi::operator=(ApiHandler handler) {
    entry_.handler = std::move(handler);
    ApiRegistry::instance().register_api(entry_);
}

}  // namespace os
}  // namespace qiling
