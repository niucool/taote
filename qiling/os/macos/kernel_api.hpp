// Ported from qiling/os/macos/kernel_api/{kernel_api,hook,fncc}.py — the
// XNU kernel-function surface the kext path calls into (the `@macos_kernel_api`
// decorator + the hook_kernel_api getattr dispatch), mirroring the posix
// kernel_api slice's structure (the registry, the fluent builder, the STRING
// resolution riding the os resolvers).
//
//   @macos_kernel_api(params={...}, passthru=...) -> KernelApi(name, params,
//                                                    passthru) = handler
//   getattr(api, f'hook_{name}')                  -> KernelApiRegistry::find
//   hook_kernel_api (hook.py)                     -> QlOsMacos::hook_kernel_api
//   fncc.py macos_kernel_api wrapper              -> the call() with the
//                                                    passthru + the onenter/
//                                                    onexit user hooks
//
// The loader-side import_symbols come from the Mach-O kernel loader (the
// loader/macho.py slice) — the hook stays inert until that lands (the
// dispatch is loader-gated, mirroring the posix ET_REL gate).
#ifndef QILING_OS_MACOS_KERNEL_API_HPP
#define QILING_OS_MACOS_KERNEL_API_HPP

#include "qiling/os/posix/kernel_api.hpp"
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace qiling {
namespace os {
namespace macos {

// the fncc param-type aliases: the upstream macos decorators use os/const.py
// spellings — INT/UINT/BOOL ride PARAM_INT32, POINTER/SIZE_T ride PARAM_INTN,
// STRING rides PARAM_PTRX+1 (the _WIN32 spellings per the posix slice; the
// posix K_* spellings pull through — the same registry entry shape)
using posix::K_UINT;
using posix::K_SIZE_T;
using posix::K_POINTER;
using posix::K_STRING;
inline constexpr int K_BOOL = 3;  // PARAM_INT32 (the upstream BOOL)
inline constexpr int K_ULONGLONG = 4;  // PARAM_INT64

using KernelApiEntry = posix::KernelApiEntry;
using KernelApiParams = posix::KernelApiParams;
using KernelApiHandler = posix::KernelApiHandler;
using ResolvedParams = posix::ResolvedParams;

// the static registration table (the kernel_api.py module namespace analogue;
// the macos module carries its own namespace — the names overlap the linux
// ones but the registries stay separate)
class KernelApiRegistry {
public:
    static KernelApiRegistry& instance();

    void register_api(KernelApiEntry entry);
    const KernelApiEntry* find(const std::string& name) const;
    void clear();

private:
    KernelApiRegistry() = default;
    std::map<std::string, KernelApiEntry> entries_;
};

// the @macos_kernel_api builder (the fncc.py decorator wrapper shape)
class KernelApi {
public:
    KernelApi(std::string name, KernelApiParams params = {}, bool passthru = false);

    void operator=(KernelApiHandler handler);

private:
    KernelApiEntry entry_;
};

}  // namespace macos
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_MACOS_KERNEL_API_HPP
