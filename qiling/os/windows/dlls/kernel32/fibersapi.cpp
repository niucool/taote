// Ported from qiling/os/windows/dlls/kernel32/fibersapi.py — the fiber-local
// storage family (the Fls* cycle over the fiber.py FiberManager). The
// @winsdkapi decorators map onto register_fibersapi_family(); the bodies
// ride the verbatim upstream walks (the free's callback-invocation stays
// skipped per the fiber.py <SKIP> note). The family self-registers at
// static-init and can be re-seeded after ApiRegistry::clear() (the test
// isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

namespace qiling {
namespace os {
namespace win {

void register_fibersapi_family() {
    using namespace qiling::os::api;

    // DWORD FlsFree(
    //  DWORD dwFlsIndex
    // );
    WinsdkApi("FlsFree", WinCc::Stdcall, {
        {"dwFlsIndex", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dw_fls_index = api_get_int(get_param(params, "dwFlsIndex"));
        return static_cast<std::uint64_t>(w(ql).fiber_manager().free(dw_fls_index));
    };

    // LPVOID FlsGetValue(
    //  DWORD dwFlsIndex
    // );
    WinsdkApi("FlsGetValue", WinCc::Stdcall, {
        {"dwFlsIndex", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dw_fls_index = api_get_int(get_param(params, "dwFlsIndex"));
        return w(ql).fiber_manager().get(dw_fls_index);
    };

    // LPVOID FlsGetValue2(
    //  DWORD dwFlsIndex
    // );
    WinsdkApi("FlsGetValue2", WinCc::Stdcall, {
        {"dwFlsIndex", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dw_fls_index = api_get_int(get_param(params, "dwFlsIndex"));
        return w(ql).fiber_manager().get_noerr(dw_fls_index);
    };

    // BOOL FlsSetValue(
    //  DWORD dwFlsIndex
    //  PVOID lpFlsData
    // );
    WinsdkApi("FlsSetValue", WinCc::Stdcall, {
        {"dwFlsIndex", DWORD_},
        {"lpFlsData", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto dw_fls_index = api_get_int(get_param(params, "dwFlsIndex"));
        const auto lp_fls_data = api_get_int(get_param(params, "lpFlsData"));
        return static_cast<std::uint64_t>(w(ql).fiber_manager().set(dw_fls_index, lp_fls_data));
    };

    // DWORD FlsAlloc(
    //  PFLS_CALLBACK_FUNCTION lpCallback
    // );
    WinsdkApi("FlsAlloc", WinCc::Stdcall, {
        {"lpCallback", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto cb = api_get_int(get_param(params, "lpCallback"));
        // the verbatim `cb or None`: the 0 callback rides the no-callback alloc
        return w(ql).fiber_manager().alloc(cb != 0 ? std::optional<std::uint64_t>(cb) : std::nullopt);
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kFibersapiRegistered = [] {
    register_fibersapi_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
