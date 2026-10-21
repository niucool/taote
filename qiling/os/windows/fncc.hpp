// Ported from qiling/os/windows/fncc.py — the calling-convention ids and the
// API registration engine. Python decorates functions with `@winsdkapi(cc=..,
// params=..)` and dispatches dynamically via `getattr(dlls, f'hook_{name}')`;
// the C++ port replaces the dynamic lookup with a static registration table
// (PORT_PLAN.md §5.2, D16): each API handler registers its name, calling
// convention and parameter types through the ApiRegistry, and the
// `hook_winapi` dispatcher resolves by name.
#ifndef QILING_OS_WINDOWS_FNCC_HPP
#define QILING_OS_WINDOWS_FNCC_HPP

#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "qiling/os/os.hpp"

namespace qiling {

class Qiling;

namespace os {

// fncc.py: the calling conventions
enum class WinCc : int { Stdcall = 1, Cdecl = 2, Ms64 = 3 };

// the api.py type-alias surface: (name, type) pairs per API signature
using ApiParams = std::vector<std::pair<std::string, int>>;

// the resolved-params shape the handlers read: the placeholder-typed entries
// (the STRING/WSTRING families) arrive as the decoded strings, the plain-int
// entries the raw values (the posix kernel_api ResolvedParams shape)
using ResolvedParams = std::vector<std::pair<std::string, FcallValue>>;

// the api handler signature: (ql, pc, resolved params) — the params resolve
// through the os.call orchestration before the handler runs
using ApiHandler = std::function<std::optional<std::uint64_t>(Qiling& ql, std::uint64_t pc,
                                                              const ResolvedParams& params)>;

// the resolved-params accessors (the posix kernel_api.cpp shapes, shared with
// the dll modules): the string fallback reads the guest cstring at the raw
// address; the int fallback answers 0 for the string-typed entries
std::string api_get_string(Qiling& ql, const std::pair<std::string, FcallValue>& p);
std::uint64_t api_get_int(const std::pair<std::string, FcallValue>& p);

// the named lookup over the resolved params (the python params["name"] shape)
const std::pair<std::string, FcallValue>& get_param(const ResolvedParams& params, std::string_view name);

// one registered API implementation
struct ApiEntry {
    std::string name;
    WinCc cc;
    ApiParams params;
    bool passthru = false;
    ApiHandler handler;
};

// the static registration table (the `@winsdkapi` decorator analogue). DLL
// modules register their handlers at static-init time; `hook_winapi` resolves
// by api name.
class ApiRegistry {
public:
    static ApiRegistry& instance();

    // registers (or replaces) an api implementation
    void register_api(ApiEntry entry);

    // the getattr(dlls, f'hook_{api_name}') analogue
    const ApiEntry* find(const std::string& api_name) const;

    // the registered api names (the winsdkapi coverage surface)
    std::vector<std::string> names() const;

    // drops every registration (test isolation)
    void clear();

private:
    ApiRegistry() = default;
    std::map<std::string, ApiEntry> entries_;
};

// fncc.py `winsdkapi.wrapper`: run `handler` as the implementation of
// `api_name` — the ENTER/EXIT intercepts fire around it with the *resolved*
// params, the return value is written back and the frame is unwound. A user
// CALL-intercept replacement (os.set_api with QL_INTERCEPT::CALL) is a
// winsdkapi-decorated function upstream, i.e. exactly this call, so the
// replacement can reuse it to keep the ENTER/EXIT chain working.
std::optional<std::uint64_t> call_api(Qiling& ql, std::uint64_t pc, const std::string& api_name,
                                      const ApiParams& params, WinCc cc, const ApiHandler& handler,
                                      bool passthru = false);

// the `@winsdkapi(cc=..., params=..., passthru=...)` decorator analogue: a
// fluent builder used by the dll modules at static-init time
class WinsdkApi {
public:
    WinsdkApi(std::string name, WinCc cc, ApiParams params = {}, bool passthru = false);

    // completes the registration with the handler body
    void operator=(ApiHandler handler);

private:
    ApiEntry entry_;
};

}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_WINDOWS_FNCC_HPP
