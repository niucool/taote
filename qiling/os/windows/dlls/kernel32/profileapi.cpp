// Ported from qiling/os/windows/dlls/kernel32/profileapi.py — the profiling
// family (the QueryPerformance pair). The @winsdkapi decorators map onto
// register_profileapi_family(); the bodies ride the verbatim upstream walks
// (the counter's no-write quirk included). The family self-registers at
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

void register_profileapi_family() {
    using namespace qiling::os::api;

    // BOOL QueryPerformanceCounter(
    //   LARGE_INTEGER *lpPerformanceCount
    // );
    WinsdkApi("QueryPerformanceCounter", WinCc::Stdcall, {
        {"lpPerformanceCount", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // the verbatim quirk: the 0 return with NO write into the caller's
        // LARGE_INTEGER
        return 0;
    };

    // BOOL QueryPerformanceFrequency(
    //  LARGE_INTEGER *lpFrequency
    // );
    WinsdkApi("QueryPerformanceFrequency", WinCc::Stdcall, {
        {"lpFrequency", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lp_frequency = api_get_int(get_param(params, "lpFrequency"));

        ql.mem().write_ptr(lp_frequency, 10000000, 8);

        return 1;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kProfileapiRegistered = [] {
    register_profileapi_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
