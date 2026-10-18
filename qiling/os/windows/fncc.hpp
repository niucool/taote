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
#include <vector>

#include "qiling/const.hpp"

namespace qiling {

class Qiling;

namespace os {

// fncc.py: the calling conventions
enum class WinCc : int { Stdcall = 1, Cdecl = 2, Ms64 = 3 };

// the api.py type-alias surface: (name, type) pairs per API signature
using ApiParams = std::vector<std::pair<std::string, int>>;

// the api handler signature: (ql, pc, params-as-read) — the resolved values
// arrive through the os.call orchestration
class ApiRegistry;

using ApiHandler = std::function<std::optional<std::uint64_t>(Qiling& ql, std::uint64_t pc)>;

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
