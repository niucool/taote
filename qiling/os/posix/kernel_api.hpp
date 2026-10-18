// Ported from qiling/os/linux/kernel_api/{kernel_api,hook}.py — the Linux
// kernel API surface the ET_REL driver path calls into (the `@linux_kernel_api`
// decorator + the getattr dispatch map onto a static registry, following the
// windows fncc precedent).
//
//   @linux_kernel_api(params={...})  -> KernelApi(name, params) = handler
//   getattr(api, f'hook_{name}')     -> KernelApiRegistry::find(name)
//   hook_kernel_api (hook.py)        -> QlOsPosix::hook_kernel_api
#ifndef QILING_OS_POSIX_KERNEL_API_HPP
#define QILING_OS_POSIX_KERNEL_API_HPP

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace qiling {

class Qiling;

namespace os {
namespace posix {

// os/const.hpp: UINT=PARAM_INT32, STRING=PARAM_PTRX+1, SIZE_T=PARAM_INTN,
// POINTER=PARAM_INTN — the windows.h-colliding aliases are spelled out here
inline constexpr int K_UINT = 3;          // PARAM_INT32
inline constexpr int K_SIZE_T = 5;        // PARAM_INTN
inline constexpr int K_POINTER = 5;       // PARAM_INTN
inline constexpr int K_STRING = 129;      // PARAM_PTRX + 1

// kernel_api.py: the handler receives (ql, pc, params) with the resolved
// parameter values; the optional return lands in the arch return register
using KernelApiHandler = std::function<std::optional<std::uint64_t>(
    Qiling& ql, std::uint64_t pc, const std::vector<std::pair<std::string, std::uint64_t>>& params)>;

// the name→(type) pairs per api signature (the decorator's params mapping)
using KernelApiParams = std::vector<std::pair<std::string, int>>;

// one registered kernel api implementation
struct KernelApiEntry {
    std::string name;
    KernelApiParams params;
    bool passthru = false;
    KernelApiHandler handler;
};

// the static registration table (the kernel_api.py module namespace analogue:
// the Python dispatches through getattr(api, f'hook_{name}'); the port keeps
// an explicit registry)
class KernelApiRegistry {
public:
    static KernelApiRegistry& instance();

    void register_api(KernelApiEntry entry);

    // the getattr(api, f'hook_{api_name}') analogue
    const KernelApiEntry* find(const std::string& name) const;

    // drops every registration (test isolation)
    void clear();

private:
    KernelApiRegistry() = default;
    std::map<std::string, KernelApiEntry> entries_;
};

// the @linux_kernel_api(params={...}, passthru=...) builder: a fluent wrapper
// used by the builtin handlers at static-init time
class KernelApi {
public:
    KernelApi(std::string name, KernelApiParams params = {}, bool passthru = false);

    void operator=(KernelApiHandler handler);

private:
    KernelApiEntry entry_;
};

}  // namespace posix
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_POSIX_KERNEL_API_HPP
