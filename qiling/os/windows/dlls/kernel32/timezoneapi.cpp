// Ported from qiling/os/windows/dlls/kernel32/timezoneapi.py — the timezone
// family (GetTimeZoneInformation). The @winsdkapi decorators map onto
// register_timezoneapi_family(); the bodies ride the verbatim upstream walks
// (the fail-for-now INVALID return included). The family self-registers at
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

void register_timezoneapi_family() {
    using namespace qiling::os::api;

    // DWORD GetTimeZoneInformation(
    //   [out] LPTIME_ZONE_INFORMATION lpTimeZoneInformation
    // );
    WinsdkApi("GetTimeZoneInformation", WinCc::Stdcall, {
        {"lpTimeZoneInformation", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // TODO: implement this later. fail for now  (verbatim)
        // the python const rides -1 (the DWORD return truncates to the
        // 0xffffffff TIME_ZONE_ID_INVALID); the port returns the raw
        // 0xffffffff shape the guest sees
        return 0xFFFFFFFFull;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kTimezoneapiRegistered = [] {
    register_timezoneapi_family();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
